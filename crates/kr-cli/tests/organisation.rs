//! `kr organisation` against a real control daemon on the network.
//!
//! The daemon is the `kr-controller` executable the workspace builds beside this test, copied to the
//! internal disk and put on the network on loopback alone, with no relay and no discovery. It has
//! no owner when it starts, so what this tests is the command's own part of an enrolment: it reads
//! a chain file, asks the host, reports what the host holds, and stops where only an owner device
//! can go on. The confirmation by an owner device and the enrolment it spends are the daemon's, and
//! its own suite drives them.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::SigningTranscript;
use kr_ipc::client::LocalClient;
use kr_protocol::account::{
    BackupPolicy, ExternalProviderPolicy, MembershipLeasePayload, ORGANISATION_POLICY_DOMAIN,
    OrganisationPolicy, OrganisationPolicyPayload, POLICY_AUTHORITY_DOMAIN,
    POLICY_AUTHORITY_HEAD_DOMAIN, PolicyAuthority, PolicyAuthorityHead, PolicyAuthorityHeadPayload,
    PolicyAuthorityLink, PolicyAuthorityLinkPayload,
};
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::{
    AuthorityRevision, BuildId, OrganisationId, OrganisationPolicyRevision, PluginId,
    PolicyKeyRevision,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::scalars::{CanonicalSet, Nullable, Signature64, TimestampMs, U64, Uuid};
use serde_json::Value;

mod support;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Returns an executable the workspace builds beside this test, when it has been built.
fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A host tree with a running daemon on the network, and the `kr` that talks to it.
struct Host {
    daemon: Option<std::process::Child>,
    temp: kr_ipc::testing::TempHost,
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }
}

impl Host {
    async fn start() -> Self {
        Self::start_with(|_| ()).await
    }

    /// Starts a host whose registry already records an enrolment in the organisation `authority`
    /// names: what an owner device's confirmation and `organisation.enrol` leave, written before
    /// the daemon starts, since the confirmation is the daemon suite's.
    async fn start_enrolled(authority: &PolicyAuthority) -> Self {
        Self::start_with(|temp| {
            let database = temp.environment().registry_database();
            std::fs::create_dir_all(database.parent().expect("a directory")).expect("created");
            let grants = kr_controller::grants::GrantDirectory::open(&database)
                .expect("the host's authority store");
            let mut policy = kr_controller::grants::HostPolicy::personal(AuthorityRevision::new(0));
            let reading = kr_controller::service::net::devices::ObservedUtc {
                now: TimestampMs::new(kr_ipc::now_ms().get()),
                behind_ms: 0,
            };
            let verified = policy
                .verify_enrolment(authority, Some(&reading))
                .expect("the published chain verifies");
            policy
                .enrol(verified, AuthorityRevision::new(0))
                .expect("the host enrols");
            grants
                .store_policy(&policy.snapshot())
                .expect("the host's policy is written");
        })
        .await
    }

    async fn start_with(seed: impl FnOnce(&kr_ipc::testing::TempHost)) -> Self {
        let controller = beside_this_test("kr-controller").unwrap_or_else(|| {
            panic!(
                "the kr-controller executable is not built beside this test, so this check cannot \
                 run; a workspace test run builds it, and so does `cargo build -p kr-controller`"
            )
        });
        let temp = kr_ipc::testing::TempHost::create();
        let mut document = ConfigurationDocument::empty();
        document.revision = 1;
        document.network.enabled = Nullable::some(true);
        document.network.bind_address = Nullable::some("127.0.0.1:0".to_owned());
        let path = kr_worker::config::document_path(&temp.environment());
        std::fs::create_dir_all(path.parent().expect("the document has a directory"))
            .expect("the state directory");
        kr_ipc::paths::write_owner_only_file(
            &path,
            kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
        )
        .expect("the configuration document");
        seed(&temp);
        let bin = temp.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a directory for the executable");
        let destination = bin.join(controller.file_name().expect("the executable has a name"));
        kr_ipc::testing::place_program(&controller, &destination);
        let log = std::fs::File::create(temp.root().join("daemon.log")).expect("the daemon's log");
        let child = std::process::Command::new(&destination)
            .current_dir(temp.root())
            .arg("--runtime-dir")
            .arg(temp.root().join("r"))
            .arg("--state-dir")
            .arg(temp.root().join("s"))
            .arg("--secret-store")
            .arg("file")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("the daemon starts");
        let host = Self {
            daemon: Some(child),
            temp,
        };
        let endpoint = host
            .temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let started = Instant::now();
        while LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err()
        {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the daemon did not answer; its log says: {}",
                host.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        host
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.temp.root().join("daemon.log")).unwrap_or_default()
    }

    /// Runs `kr` on plain pipes, with this host's directories and nothing of this test's own.
    fn kr(&self, arguments: &[&str]) -> std::process::Output {
        std::process::Command::new(kr())
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("KR_RUNTIME_DIR", self.temp.paths().runtime_root())
            .env("KR_STATE_DIR", self.temp.paths().state_root())
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("runs kr")
    }

    /// Runs `kr` and reads what it printed as JSON.
    fn kr_json(&self, arguments: &[&str]) -> Value {
        let output = self.kr(arguments);
        assert!(
            output.status.success(),
            "kr {}: {}\n{}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr),
            self.log()
        );
        serde_json::from_slice(&output.stdout).expect("kr printed JSON")
    }
}

/// An organisation that signs with real keys: its published chain, written as JSON where a member
/// exported it, and the key of its second revision, which signs a policy.
struct Exported {
    authority: PolicyAuthority,
    chain: PathBuf,
    signing: AuthorisationKeyPair,
}

/// An organisation's chain of two keys and a head by the second, signed with real keys, as the
/// organisation's service publishes it, written as JSON where a member exported it.
fn export_chain(directory: &Path) -> PathBuf {
    exported_organisation(directory).chain
}

/// A policy the organisation signs under the key of its second revision, written as JSON where a
/// member exported it.
fn export_policy(
    directory: &Path,
    organisation: &Exported,
    name: &str,
    policy_revision: u64,
    adapters: Option<&[&str]>,
) -> PathBuf {
    let payload = OrganisationPolicyPayload {
        organisation_id: organisation.authority.organisation_id,
        policy_revision: OrganisationPolicyRevision::new(policy_revision),
        adapter_allowlist: Nullable(adapters.map(|names| {
            names
                .iter()
                .map(|name| PluginId::new(*name).expect("a plugin identifier"))
                .collect::<CanonicalSet<PluginId>>()
        })),
        minimum_client_version: Nullable::null(),
        maximum_grant_lifetime_ms: Nullable::null(),
        external_providers: ExternalProviderPolicy::OrganisationOnly,
        backup: BackupPolicy {
            required: false,
            recovery_recipient: Nullable::null(),
        },
        audit_retention_days: U64::new(365),
        issued_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
        key_revision: PolicyKeyRevision::new(2),
    };
    let transcript = SigningTranscript::from_canonical_bytes(
        ORGANISATION_POLICY_DOMAIN,
        payload.signing_input().expect("encodes"),
    )
    .expect("a transcript");
    let policy = OrganisationPolicy {
        signature: kr_crypto::sign::sign(&organisation.signing, &transcript).expect("a signature"),
        payload,
    };
    let path = directory.join(name);
    std::fs::write(&path, serde_json::to_vec(&policy).expect("encodes")).expect("writes");
    path
}

fn exported_organisation(directory: &Path) -> Exported {
    exported_organisation_as(directory, 0x21, "chain.json")
}

/// An organisation named by `byte` that signs with real keys, whose chain is written to `file`.
fn exported_organisation_as(directory: &Path, byte: u8, file: &str) -> Exported {
    let now = kr_ipc::now_ms().get();
    let sign = |key: &AuthorisationKeyPair, domain: &str, input: Vec<u8>| -> Signature64 {
        let transcript =
            SigningTranscript::from_canonical_bytes(domain, input).expect("a transcript");
        kr_crypto::sign::sign(key, &transcript).expect("a signature")
    };
    let organisation_id = OrganisationId::new(Uuid::from_bytes([byte; 16]));
    let first = AuthorisationKeyPair::generate().expect("a key");
    let second = AuthorisationKeyPair::generate().expect("a key");
    let first_payload = PolicyAuthorityLinkPayload {
        organisation_id,
        key_revision: PolicyKeyRevision::new(1),
        previous_key_revision: Nullable::null(),
        public_key: *first.public(),
        not_before_ms: TimestampMs::new(now - 2 * 86_400_000),
    };
    let second_payload = PolicyAuthorityLinkPayload {
        organisation_id,
        key_revision: PolicyKeyRevision::new(2),
        previous_key_revision: Nullable::some(PolicyKeyRevision::new(1)),
        public_key: *second.public(),
        not_before_ms: TimestampMs::new(now - 86_400_000),
    };
    let head_payload = PolicyAuthorityHeadPayload {
        organisation_id,
        key_revision: PolicyKeyRevision::new(2),
        issued_at_ms: TimestampMs::new(now - 1_000),
        expires_at_ms: TimestampMs::new(now - 1_000 + 15 * 60_000),
    };
    let authority = PolicyAuthority {
        organisation_id,
        chain: vec![
            PolicyAuthorityLink {
                signature: sign(
                    &first,
                    POLICY_AUTHORITY_DOMAIN,
                    first_payload.signing_input().expect("encodes"),
                ),
                payload: first_payload,
            },
            PolicyAuthorityLink {
                signature: sign(
                    &first,
                    POLICY_AUTHORITY_DOMAIN,
                    second_payload.signing_input().expect("encodes"),
                ),
                payload: second_payload,
            },
        ],
        head: PolicyAuthorityHead {
            signature: sign(
                &second,
                POLICY_AUTHORITY_HEAD_DOMAIN,
                head_payload.signing_input().expect("encodes"),
            ),
            payload: head_payload,
        },
    };
    let path = directory.join(file);
    std::fs::write(&path, serde_json::to_vec(&authority).expect("encodes")).expect("writes");
    Exported {
        authority,
        chain: path,
        signing: second,
    }
}

/// KR-REQ-17.53: a host enrolled in nothing says so, in words and in JSON, and the list is what the
/// owner reads before and after an enrolment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_enrolled_in_nothing_says_so() {
    let host = Host::start().await;
    let output = host.kr(&["organisation", "list"]);
    let printed = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stderr),
        host.log()
    );
    assert!(printed.contains("enrolled in no organisation"), "{printed}");
    assert!(printed.contains("Exclusive management is off"), "{printed}");
    assert!(
        printed.contains("signed for device"),
        "the list says what a lease for the host's own local owner is signed for: {printed}"
    );
    let listed = host.kr_json(&["organisation", "list", "--json"]);
    assert_eq!(listed["enrolments"], serde_json::json!([]), "{listed}");
    assert_eq!(listed["exclusive"], false, "{listed}");
    assert_eq!(listed["clock_trusted"], true, "{listed}");
    assert!(listed["host_device"]["device_id"].is_string(), "{listed}");
    assert!(
        listed["host_device"]["authorisation_key_id"].is_string(),
        "{listed}"
    );
    assert_eq!(
        listed["workers_without_local_enforcement"],
        serde_json::json!([]),
        "{listed}"
    );
}

/// KR-REQ-17.54: a file that is not a membership lease, or is larger than one, is the person's
/// mistake and is said before the host is asked; a lease the host has no enrolment for reaches the
/// host at its own socket and is refused there, with nothing installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn presenting_a_lease_is_refused_before_the_host_is_asked_or_by_the_host_that_holds_no_enrolment()
 {
    let host = Host::start().await;
    let directory = host.temp.root().join("exports");
    std::fs::create_dir_all(&directory).expect("a directory");

    let not_a_lease = directory.join("not-a-lease.json");
    std::fs::write(&not_a_lease, b"{\"hello\": 1}").expect("writes");
    let output = host.kr(&[
        "organisation",
        "present",
        not_a_lease.to_str().expect("a path"),
    ]);
    assert!(!output.status.success());
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("not a membership lease"), "{said}");

    let too_large = directory.join("too-large.json");
    std::fs::File::create(&too_large)
        .expect("creates")
        .set_len(2 * 1024 * 1024)
        .expect("a sparse file");
    let output = host.kr(&[
        "organisation",
        "present",
        too_large.to_str().expect("a path"),
    ]);
    assert!(!output.status.success());
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("larger than any lease"), "{said}");

    let key = AuthorisationKeyPair::generate().expect("a key");
    let payload = MembershipLeasePayload {
        organisation_id: OrganisationId::new(Uuid::from_bytes([0x21; 16])),
        account_id: kr_protocol::ids::AccountId::new("account:ada").expect("an account"),
        device_key: *key.public(),
        role: kr_protocol::account::TeamRole::Controller,
        maximum_grants: kr_protocol::scalars::CanonicalSet::new(),
        issued_at_ms: TimestampMs::new(kr_ipc::now_ms().get()),
        expires_at_ms: TimestampMs::new(kr_ipc::now_ms().get() + 60_000),
        key_revision: PolicyKeyRevision::new(1),
    };
    let signature = kr_crypto::sign::sign(
        &key,
        &SigningTranscript::from_canonical_bytes(
            kr_protocol::account::MEMBERSHIP_LEASE_DOMAIN,
            payload.signing_input().expect("encodes"),
        )
        .expect("a transcript"),
    )
    .expect("a signature");
    let lease = directory.join("lease.json");
    std::fs::write(
        &lease,
        serde_json::to_vec(&kr_protocol::account::MembershipLease { payload, signature })
            .expect("encodes"),
    )
    .expect("writes");
    let output = host.kr(&["organisation", "present", lease.to_str().expect("a path")]);
    assert!(
        !output.status.success(),
        "a host enrolled in nothing takes no lease: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("PERMISSION_DENIED") || said.contains("enrol"),
        "the host's own refusal, not a want of the method at its socket: {said}\n{}",
        host.log()
    );
}

/// KR-REQ-17.53: a file that is not an organisation's chain is a mistake of the person's, said
/// before the host is asked, and a chain that verifies but finds no owner device to confirm it is
/// refused with nothing changed, naming how a host gets its first owner device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolment_stops_where_only_an_owner_device_can_go_on() {
    let host = Host::start().await;
    let directory = host.temp.root().join("exports");
    std::fs::create_dir_all(&directory).expect("a directory");

    let not_a_chain = directory.join("not-a-chain.json");
    std::fs::write(&not_a_chain, b"{\"hello\": 1}").expect("writes");
    let output = host.kr(&[
        "organisation",
        "enrol",
        not_a_chain.to_str().expect("a path"),
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not an organisation's published"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let missing = directory.join("missing.json");
    let output = host.kr(&["organisation", "enrol", missing.to_str().expect("a path")]);
    assert!(!output.status.success());

    let chain = export_chain(&directory);
    let output = host.kr(&["organisation", "enrol", chain.to_str().expect("a path")]);
    assert!(!output.status.success(), "no owner device can confirm this");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("kr pair invite --owner"),
        "{said}\n{}",
        host.log()
    );
    let listed = host.kr_json(&["organisation", "list", "--json"]);
    assert_eq!(
        listed["enrolments"],
        serde_json::json!([]),
        "nothing was enrolled"
    );
}

/// KR-REQ-17.53: an invitation that requires an organisation names the enrolment the host holds,
/// so a host enrolled in no such organisation has none to name: `kr pair invite --organisation` is
/// refused before anybody is asked to confirm anything, saying how a host gets enrolled, and a
/// file that is larger than any chain a control frame carries is refused before it is read whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invitation_for_an_organisation_the_host_is_not_enrolled_in_is_refused() {
    let host = Host::start().await;
    let organisation = OrganisationId::new(Uuid::from_bytes([0x21; 16])).to_string();
    let output = host.kr(&["pair", "invite", "--guest", "--organisation", &organisation]);
    assert!(!output.status.success(), "nothing to name");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("not enrolled in that organisation"),
        "{said}\n{}",
        host.log()
    );
    assert!(said.contains("kr organisation enrol"), "{said}");
    let output = host.kr(&[
        "pair",
        "invite",
        "--guest",
        "--organisation",
        "not-an-identifier",
    ]);
    assert!(!output.status.success(), "an identifier is a UUID");

    let directory = host.temp.root().join("exports");
    std::fs::create_dir_all(&directory).expect("a directory");
    let too_large = directory.join("too-large.json");
    let file = std::fs::File::create(&too_large).expect("creates");
    file.set_len(2 * 1024 * 1024).expect("a sparse file");
    let output = host.kr(&["organisation", "enrol", too_large.to_str().expect("a path")]);
    assert!(!output.status.success());
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("larger than any chain"), "{said}");
}

/// KR-REQ-17.54: a withdrawal names an organisation by its identifier, and the host leaves none it
/// is not enrolled in: a mistake in the identifier is the person's, said before the host is asked,
/// and an organisation the host holds nothing of is refused by the host with nothing fenced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_from_an_organisation_the_host_is_not_enrolled_in_is_refused() {
    let host = Host::start().await;
    let output = host.kr(&["organisation", "withdraw", "not-an-identifier"]);
    assert!(!output.status.success());
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("not an organisation identifier"), "{said}");

    let organisation = OrganisationId::new(Uuid::from_bytes([0x21; 16])).to_string();
    let output = host.kr(&["organisation", "withdraw", &organisation]);
    assert!(!output.status.success(), "the host holds nothing of it");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("not enrolled in that organisation"),
        "{said}\n{}",
        host.log()
    );
}

/// KR-REQ-17.54: exclusive management is put to nobody for confirmation while the host would
/// refuse it: a host enrolled in nothing has no organisation to manage it, and one that is not
/// exclusive has nothing to end. Both are the host's refusal, with nothing changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn exclusive_management_is_refused_where_the_host_would_refuse_it() {
    let host = Host::start().await;
    let output = host.kr(&["organisation", "exclusive", "on"]);
    assert!(!output.status.success());
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("enrolled in no organisation"),
        "{said}\n{}",
        host.log()
    );
    let output = host.kr(&["organisation", "exclusive", "off"]);
    assert!(!output.status.success());
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("not exclusively organisation-managed"),
        "{said}\n{}",
        host.log()
    );
    let listed = host.kr_json(&["organisation", "list", "--json"]);
    assert_eq!(listed["exclusive"], false, "{listed}");
}

/// `kr organisation policy` applies the policy an organisation signed to a host enrolled in it, and
/// the list shows the revision and the adapters it allows and the adapters the policies allow
/// together. The same policy again is a repeat, a chain that is another organisation's is sent
/// beside it and refused by the host, and an older policy is refused by its rule.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_policy_is_applied_listed_and_not_applied_again_when_older() {
    let directory = tempfile::tempdir().expect("a directory");
    let organisation = exported_organisation(directory.path());
    let host = Host::start_enrolled(&organisation.authority).await;
    let adapters = ["kalareach/claude-code", "kalareach/codex"];
    let policy = export_policy(
        directory.path(),
        &organisation,
        "policy-3.json",
        3,
        Some(&adapters),
    );
    let file = policy.to_str().expect("a path");

    let applied = host.kr_json(&["organisation", "policy", file, "--json"]);
    assert_eq!(applied["ok"], true, "{applied}");
    assert_eq!(
        applied["adapter_allowlist"],
        serde_json::json!(adapters),
        "{applied}"
    );
    assert_eq!(
        applied["effective_adapter_allowlist"],
        serde_json::json!(adapters),
        "{applied}"
    );

    let listed = host.kr_json(&["organisation", "list", "--json"]);
    assert_eq!(
        listed["effective_adapter_allowlist"],
        serde_json::json!(adapters),
        "{listed}"
    );
    assert_eq!(
        listed["enrolments"][0]["adapter_allowlist"],
        serde_json::json!(adapters),
        "{listed}"
    );
    assert_eq!(
        listed["enrolments"][0]["organisation_policy_revision"],
        applied["organisation_policy_revision"],
        "{listed}"
    );
    let words = host.kr(&["organisation", "list"]);
    let printed = String::from_utf8_lossy(&words.stdout);
    assert!(printed.contains("kalareach/codex"), "{printed}");

    let again = host.kr_json(&["organisation", "policy", file, "--json"]);
    assert_eq!(again, applied, "the same policy again is a repeat");

    // A chain that belongs to another organisation is read from its file, sent beside the policy
    // and refused by the host before the policy is looked at.
    let other = exported_organisation_as(directory.path(), 0x22, "other-chain.json");
    let output = host.kr(&[
        "organisation",
        "policy",
        file,
        "--chain",
        other.chain.to_str().expect("a path"),
    ]);
    assert!(
        !output.status.success(),
        "another organisation's chain is refused"
    );
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("(foreign_chain)"), "{said}\n{}", host.log());

    let older = export_policy(directory.path(), &organisation, "policy-2.json", 2, None);
    let output = host.kr(&["organisation", "policy", older.to_str().expect("a path")]);
    assert!(!output.status.success(), "an older revision is refused");
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("(not_newer)"), "{said}\n{}", host.log());
}

/// A policy file that is not a policy is the person's mistake and is said before the
/// host is asked, and a policy for an organisation the host is not enrolled in is refused by the
/// host, by its rule, with nothing applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_policy_that_is_not_one_or_is_for_another_organisation_is_refused() {
    let host = Host::start().await;
    let directory = host.temp.root().join("exports");
    std::fs::create_dir_all(&directory).expect("a directory");

    let not_a_policy = directory.join("not-a-policy.json");
    std::fs::write(&not_a_policy, b"{\"hello\": 1}").expect("writes");
    let output = host.kr(&[
        "organisation",
        "policy",
        not_a_policy.to_str().expect("a path"),
    ]);
    assert!(!output.status.success());
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("not a policy"), "{said}");

    let organisation = exported_organisation(&directory);
    let policy = export_policy(
        &directory,
        &organisation,
        "policy.json",
        1,
        Some(&["kalareach/codex"]),
    );
    let output = host.kr(&["organisation", "policy", policy.to_str().expect("a path")]);
    assert!(
        !output.status.success(),
        "the host holds nothing of the organisation"
    );
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("(not_enrolled)"), "{said}\n{}", host.log());
    let listed = host.kr_json(&["organisation", "list", "--json"]);
    assert_eq!(
        listed["effective_adapter_allowlist"],
        serde_json::Value::Null,
        "{listed}"
    );
}
