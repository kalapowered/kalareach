//! An organisation's signed policy applied on a host: the adapters it allows decide which adapters
//! the host admits.
//!
//! Everything here goes through the owner's local socket, on a real daemon enrolled in an
//! organisation the way a person enrols it, with a policy the organisation's own keys signed. The
//! catalogue is the daemon's own: the example package is installed in it, and `plugin.list` says
//! whether the admissions in force let a new binding use it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-18.06 | the cases named `kr_req_18_06_` |

#![cfg(unix)]

mod fence_support;
mod net_support;
mod organisation_fixture;
mod organisation_support;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_plugin_catalogue::RepositoryKind;
use kr_plugin_catalogue::{CapabilityCeiling, Enrolment, InstallationGrant, RepositoryId};
use kr_protocol::account::{OrganisationPolicy, PolicyAuthority};
use kr_protocol::catalogue as wire;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, OrganisationPolicyRevision, PluginId};
use kr_protocol::method::Method;
use kr_protocol::organisation::{OrganisationPolicyApplyParams, OrganisationPolicyApplyResult};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use net_support::pairing as calls;
use organisation_fixture::*;
use organisation_support::{MINUTE_MS, Organisation};

const EXAMPLE: &str = "kalareach/example-declarative";
const CODEX: &str = "kalareach/codex";
const CLAUDE_CODE: &str = "kalareach/claude-code";

fn example() -> PluginId {
    PluginId::new(EXAMPLE).expect("a plugin identifier")
}

fn allowed(names: &[&str]) -> Nullable<CanonicalSet<PluginId>> {
    Nullable::some(
        names
            .iter()
            .map(|name| PluginId::new(*name).expect("a plugin identifier"))
            .collect(),
    )
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a destination");
    let mut stack = vec![from.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).expect("readable").flatten() {
            let source = entry.path();
            if source.is_dir() {
                stack.push(source);
                continue;
            }
            let relative = source.strip_prefix(from).expect("inside the tree");
            let destination = to.join(relative);
            std::fs::create_dir_all(destination.parent().expect("a parent")).expect("writable");
            std::fs::copy(&source, &destination).expect("copyable");
        }
    }
}

fn directory_url(path: &Path) -> url::Url {
    let absolute = std::fs::canonicalize(path).expect("an existing directory");
    url::Url::from_directory_path(absolute).expect("an absolute path")
}

/// Installs and enables the example package in the daemon's own catalogue, from a copy of the
/// published development generation. The copy lives as long as the returned directory.
async fn install_the_example(fixture: &Fixture) -> tempfile::TempDir {
    let repository = tempfile::tempdir().expect("a directory on the internal disk");
    let published = repository.path().join("development");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/catalogue/development"),
        &published,
    );
    let environment_id = fixture.host.environment_id;
    let module = fixture.host.controller().catalogue().catalogue();
    let mut catalogue = module.lock().await;
    let id = RepositoryId::new("development").expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                directory_url(&published.join("metadata")),
                directory_url(&published.join("targets")),
                std::fs::read(published.join("root.json")).expect("a trust root"),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let version = kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version");
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&example(), &version)
        .expect("the example package")
        .manifest_digest;
    catalogue
        .install(
            &id,
            environment_id,
            &example(),
            &version,
            digest,
            InstallationGrant::none(),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(environment_id, &example(), true)
        .await
        .expect("enabled");
    repository
}

/// What `plugin.list` says of the example package's admission now.
async fn admission(fixture: &Fixture) -> wire::PluginAdmission {
    let mut client = fixture.host.client().await;
    let listed: wire::PluginListResult = calls::read(
        &mut client,
        Method::PluginList,
        &wire::PluginListParams {
            environment_id: fixture.host.environment_id,
        },
    )
    .await
    .expect("the owner reads the list");
    listed
        .plugins
        .into_iter()
        .find(|summary| summary.plugin_id == example())
        .expect("the example package is installed")
        .admission
        .0
        .expect("the admissions say where the package stands")
}

fn is_admitted(admission: &wire::PluginAdmission) -> bool {
    matches!(admission, wire::PluginAdmission::Admitted)
}

fn is_left_out_by_the_allowlist(admission: &wire::PluginAdmission) -> bool {
    matches!(
        admission,
        wire::PluginAdmission::LeftOut {
            reason: wire::PluginLeftOutReason::NotAllowed,
            ..
        }
    )
}

/// Waits until `wanted` holds of the example package's admission. It fails when it never does.
async fn until_admission(fixture: &Fixture, wanted: fn(&wire::PluginAdmission) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let now = admission(fixture).await;
        if wanted(&now) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the admissions never came to hold: {now:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Applies `policy`, with `authority` beside it, on the owner's socket under a new action.
async fn apply(
    fixture: &Fixture,
    policy: OrganisationPolicy,
    authority: Option<PolicyAuthority>,
) -> Result<OrganisationPolicyApplyResult, ProtocolError> {
    let mut client = fixture.host.client().await;
    calls::mutate_as(
        fixture.host.environment_id,
        &mut client,
        ActionId::new(kr_ipc::new_uuid()),
        Method::OrganisationPolicyApply,
        &OrganisationPolicyApplyParams {
            policy,
            authority: Nullable(authority),
        },
    )
    .await
}

/// That the host refused with a bad argument that names `rule`.
fn refused_as(
    outcome: Result<OrganisationPolicyApplyResult, ProtocolError>,
    rule: &str,
) -> ProtocolError {
    let error = outcome.expect_err("the host refuses the policy");
    assert_eq!(error.code, ErrorCode::InvalidArgument, "{error:?}");
    assert!(
        error.message.contains(&format!("({rule})")),
        "the refusal names {rule}: {error:?}"
    );
    error
}

/// KR-REQ-18.06: a policy the organisation signed under the key the host pinned decides which
/// adapters the host admits. Before it, the package is admitted; a policy that names another
/// adapter leaves it out, and one that names it admits it again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_an_applied_policy_leaves_a_package_outside_its_allowlist_out() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    assert!(
        is_admitted(&admission(&fixture).await),
        "with no policy applied every adapter is admitted"
    );

    let applied = apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 1, Some(&[CODEX]), fixture.now()),
        None,
    )
    .await
    .expect("the host applies the organisation's policy");
    assert_eq!(
        applied.organisation_policy_revision,
        OrganisationPolicyRevision::new(1)
    );
    assert_eq!(applied.adapter_allowlist, allowed(&[CODEX]));
    assert_eq!(applied.effective_adapter_allowlist, allowed(&[CODEX]));
    assert!(
        is_left_out_by_the_allowlist(&admission(&fixture).await),
        "a package the policy does not name is left out"
    );

    let listed = fixture.listed().await;
    assert_eq!(listed.effective_adapter_allowlist, allowed(&[CODEX]));
    assert_eq!(
        listed.enrolments[0].organisation_policy_revision,
        Nullable::some(OrganisationPolicyRevision::new(1))
    );
    assert_eq!(listed.enrolments[0].adapter_allowlist, allowed(&[CODEX]));

    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 2, Some(&[CODEX, EXAMPLE]), fixture.now()),
        None,
    )
    .await
    .expect("a later revision that names the package");
    assert!(
        is_admitted(&admission(&fixture).await),
        "a package the policy names is admitted"
    );
    fixture.host.stop().await;
}

/// KR-REQ-18.06: the policy a host applied is still in force after the host restarts, and so is
/// the floor under it: the same revision with another list, and a lower revision, are refused
/// by name, the same revision with the same list is a repeat that succeeds, and a higher one
/// applies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_a_restart_keeps_the_applied_policy_and_its_floor() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 5, Some(&[CODEX]), fixture.now()),
        None,
    )
    .await
    .expect("the host applies the policy");

    let fixture = fixture.restart().await;
    assert!(
        is_left_out_by_the_allowlist(&admission(&fixture).await),
        "the restarted host holds the list"
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::some(OrganisationPolicyRevision::new(5))
    );

    let same = |names: &[&str]| {
        fixture
            .organisation
            .policy(2, 5, Some(names), fixture.now())
    };
    apply(&fixture, same(&[CODEX]), None)
        .await
        .expect("the same revision with the same list is a repeat");
    refused_as(
        apply(&fixture, same(&[CODEX, EXAMPLE]), None).await,
        "not_newer",
    );
    refused_as(
        apply(
            &fixture,
            fixture
                .organisation
                .policy(2, 4, Some(&[CODEX, EXAMPLE]), fixture.now()),
            None,
        )
        .await,
        "not_newer",
    );
    assert!(
        is_left_out_by_the_allowlist(&admission(&fixture).await),
        "what was refused changed nothing"
    );

    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 6, Some(&[EXAMPLE]), fixture.now()),
        None,
    )
    .await
    .expect("a higher revision applies after the restart");
    assert!(is_admitted(&admission(&fixture).await));
    fixture.host.stop().await;
}

/// KR-REQ-18.06: a policy the host cannot verify under the key its chain ends with is refused, by
/// the rule that refuses it, and nothing the host admits changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_a_policy_that_does_not_verify_changes_nothing() {
    let mut fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let now = fixture.now();
    let organisation = &fixture.organisation;

    // Signed by a key the host did not pin: the first revision's, under the second's name.
    let forged =
        organisation.signed_policy(1, organisation.policy_payload(2, 1, Some(&[CODEX]), now));
    refused_as(apply(&fixture, forged, None).await, "bad_signature");

    // A payload altered after it was signed.
    let mut tampered = organisation.policy(2, 1, Some(&[CODEX]), now);
    tampered.payload.adapter_allowlist = allowed(&[CODEX, EXAMPLE]);
    refused_as(apply(&fixture, tampered, None).await, "bad_signature");

    // Another organisation's policy, signed with its own keys.
    let other = Organisation::new(0x22, now - 2 * 24 * 60 * MINUTE_MS);
    refused_as(
        apply(&fixture, other.policy(1, 1, Some(&[CODEX]), now), None).await,
        "not_enrolled",
    );

    // A policy that breaks a rule of its own: it names no adapter at all.
    refused_as(
        apply(&fixture, organisation.policy(2, 1, Some(&[]), now), None).await,
        "structure",
    );

    // Issued before the key that signs it took over: the second revision took over a day ago.
    refused_as(
        apply(
            &fixture,
            organisation.policy(2, 1, Some(&[CODEX]), now - 2 * 24 * 60 * MINUTE_MS),
            None,
        )
        .await,
        "issued_before_activation",
    );

    // An earlier key revision, properly signed: only the key the chain ends with signs a policy.
    refused_as(
        apply(
            &fixture,
            organisation.policy(1, 1, Some(&[CODEX]), now),
            None,
        )
        .await,
        "earlier_revision",
    );

    // A key revision the host does not hold: without a chain, with a chain that is not newer, with
    // a chain that does not verify, and with another organisation's chain.
    fixture.organisation.rotate(now - 1_000);
    let organisation = &fixture.organisation;
    let later = organisation.policy(3, 1, Some(&[CODEX]), now);
    refused_as(apply(&fixture, later.clone(), None).await, "later_revision");
    refused_as(
        apply(
            &fixture,
            later.clone(),
            Some(organisation.authority_at(2, now)),
        )
        .await,
        "later_revision",
    );
    let mut broken = organisation.authority(now);
    broken.head.signature = kr_protocol::scalars::Signature64::from_bytes([0x61; 64]);
    refused_as(apply(&fixture, later.clone(), Some(broken)).await, "chain");
    let elsewhere = Organisation::new(0x22, now - 2 * 24 * 60 * MINUTE_MS).authority(now);
    refused_as(
        apply(&fixture, later, Some(elsewhere)).await,
        "foreign_chain",
    );

    assert!(
        is_admitted(&admission(&fixture).await),
        "nothing that was refused changed what the host admits"
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::null()
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].accepted_head.get(),
        2,
        "a chain that was refused with its policy is not kept"
    );
    fixture.host.stop().await;
}

/// KR-REQ-18.06: after the organisation rotates its key, a policy under the new key applies with
/// the chain beside it, and a policy under the old key, issued before the rotation, does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_after_a_rotation_only_the_new_key_signs_a_policy() {
    let mut fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let now = fixture.now();
    fixture.organisation.rotate(now - 1_000);
    let organisation = &fixture.organisation;

    apply(
        &fixture,
        organisation.policy(3, 1, Some(&[CODEX]), now),
        Some(organisation.authority(now)),
    )
    .await
    .expect("the policy under the new key applies with the chain beside it");
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 3);

    refused_as(
        apply(
            &fixture,
            organisation.policy(2, 2, Some(&[CODEX, EXAMPLE]), now - 2_000),
            None,
        )
        .await,
        "earlier_revision",
    );
    apply(
        &fixture,
        organisation.policy(3, 2, Some(&[CODEX, EXAMPLE]), now),
        None,
    )
    .await
    .expect("the new key signs the next revision with no chain beside it");
    assert!(is_admitted(&admission(&fixture).await));
    fixture.host.stop().await;
}

/// KR-REQ-18.06: a chain that shows an installed lease was signed after its key was succeeded is
/// refused with its policy, and nothing is kept: dropping the lease owes a fence that presenting
/// the chain with a lease raises, and the lease stays in force until then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chain_that_would_drop_an_installed_lease_is_refused_with_its_policy() {
    let mut fixture = Fixture::start().await;
    let ada = fixture.member("ada", SERVED).await;
    let raw = ada.connect(&fixture).await;
    ada.present(&fixture, &raw, fixture.lease(2, &ada, SERVED), None)
        .await
        .expect("the lease");
    read_host_info(&raw).await.expect("served under the lease");

    // The organisation's key was succeeded a minute before the host's lease was issued, and the
    // host has not heard of it.
    let now = fixture.now();
    fixture.organisation.rotate(now - MINUTE_MS);
    let organisation = &fixture.organisation;
    refused_as(
        apply(
            &fixture,
            organisation.policy(3, 1, Some(&[CODEX]), now),
            Some(organisation.authority(now)),
        )
        .await,
        "chain_drops_leases",
    );
    assert_eq!(fixture.listed().await.enrolments[0].accepted_head.get(), 2);
    read_host_info(&raw)
        .await
        .expect("the lease is still in force");
    raw.close();
    fixture.host.stop().await;
}

/// KR-REQ-18.06: the host stops applying an organisation's list when it leaves the organisation,
/// and a new enrolment holds no policy until one is applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_withdrawing_from_the_organisation_lifts_its_list() {
    let mut fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let organisation_id = fixture.organisation.organisation_id;
    apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 1, Some(&[CODEX]), fixture.now()),
        None,
    )
    .await
    .expect("the host applies the policy");
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));

    let mut client = fixture.host.client().await;
    fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            organisation_id,
        )
        .await
        .expect("the owner withdraws the host");
    drop(client);
    assert!(
        is_admitted(&admission(&fixture).await),
        "the list went with the enrolment"
    );
    assert_eq!(
        fixture.listed().await.effective_adapter_allowlist,
        Nullable::null()
    );

    fixture.enrol().await;
    assert!(
        is_admitted(&admission(&fixture).await),
        "a new enrolment holds no policy"
    );
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::null()
    );
    fixture.host.stop().await;
}

/// KR-REQ-18.06: what the host admits is the intersection of the lists of every organisation it
/// is enrolled in that states one. An organisation with no list adds no constraint, lists that
/// share nothing admit nothing, and leaving an organisation widens what is left.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_the_effective_list_is_the_intersection_of_the_organisations_lists() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let now = fixture.now();
    let second = Organisation::new(0x22, now - 2 * 24 * 60 * MINUTE_MS);
    fixture.enrol_in(&second).await;

    // One organisation states a list, the other none.
    let first = apply(
        &fixture,
        fixture
            .organisation
            .policy(2, 1, Some(&[CLAUDE_CODE, CODEX]), now),
        None,
    )
    .await
    .expect("the first organisation's policy");
    assert_eq!(
        first.effective_adapter_allowlist,
        allowed(&[CLAUDE_CODE, CODEX])
    );
    let unlisted = apply(&fixture, second.policy(1, 1, None, now), None)
        .await
        .expect("the second organisation's policy, with no list");
    assert_eq!(
        unlisted.effective_adapter_allowlist,
        allowed(&[CLAUDE_CODE, CODEX]),
        "no list adds no constraint"
    );

    // Both state one.
    let both = apply(
        &fixture,
        second.policy(1, 2, Some(&[CODEX, EXAMPLE]), now),
        None,
    )
    .await
    .expect("a list from the second organisation");
    assert_eq!(both.effective_adapter_allowlist, allowed(&[CODEX]));
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));

    // Lists that share nothing.
    let nothing = apply(&fixture, second.policy(1, 3, Some(&[EXAMPLE]), now), None)
        .await
        .expect("a list that shares nothing with the first");
    assert_eq!(nothing.effective_adapter_allowlist, allowed(&[]));
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));

    // Leaving the first organisation leaves the second's list alone.
    let mut client = fixture.host.client().await;
    fixture
        .withdraw(
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            fixture.organisation.organisation_id,
        )
        .await
        .expect("the owner withdraws the host from the first organisation");
    drop(client);
    assert_eq!(
        fixture.listed().await.effective_adapter_allowlist,
        allowed(&[EXAMPLE])
    );
    assert!(is_admitted(&admission(&fixture).await));
    fixture.host.stop().await;
}

/// KR-REQ-18.06: a policy whose list cannot be put in force is recorded and told so, and the host
/// never reports it as applied while it is not in force. The catalogue is held here as a
/// synchronisation holds it. The action that was told so is answered once the list is in force; a
/// policy applied again, as the owner's tooling does, completes it; and the host's own pass puts
/// the list in force when nobody asks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_18_06_a_list_that_could_not_be_put_in_force_is_told_and_then_put_in_force() {
    let fixture = Fixture::start().await;
    let _repository = install_the_example(&fixture).await;
    let environment_id = fixture.host.environment_id;
    let controller = Arc::clone(fixture.host.controller());

    // The catalogue is busy: the apply says so and the list is not in force.
    let policy = fixture
        .organisation
        .policy(2, 1, Some(&[CODEX]), fixture.now());
    let mut client = fixture.host.client().await;
    let request = client
        .compose(
            Method::OrganisationPolicyApply,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            &OrganisationPolicyApplyParams {
                policy,
                authority: Nullable::null(),
            },
        )
        .await
        .expect("the request");
    {
        let held = controller.catalogue().catalogue().lock().await;
        // Every time the owner asks, and every time the same action is repeated, the catalogue is
        // still held and the answer says so: a recorded success is not given while the list is not
        // in force.
        for _ in 0..2 {
            let refused = client
                .repeat(&request)
                .await
                .expect("the daemon answers")
                .expect_err("the list could not be put in force");
            assert_eq!(refused.code, ErrorCode::ResourceUnavailable, "{refused:?}");
        }
        let installation = held
            .installation(environment_id, &example())
            .expect("readable")
            .expect("installed");
        assert_eq!(
            held.standing(&installation, None),
            None,
            "the list is not in force"
        );
    }
    assert_eq!(
        fixture.listed().await.enrolments[0].organisation_policy_revision,
        Nullable::some(OrganisationPolicyRevision::new(1)),
        "the policy is recorded"
    );

    // The same action again is answered once the list is in force.
    let answered: OrganisationPolicyApplyResult = client
        .repeat(&request)
        .await
        .expect("the daemon answers")
        .expect("the recorded answer, with the list in force")
        .to_typed()
        .expect("an answer");
    assert_eq!(answered.adapter_allowlist, allowed(&[CODEX]));
    assert!(is_left_out_by_the_allowlist(&admission(&fixture).await));
    drop(client);

    // A later policy fails the same way, and the next pass puts its list in force.
    let next = fixture
        .organisation
        .policy(2, 2, Some(&[EXAMPLE]), fixture.now());
    {
        let _held = controller.catalogue().catalogue().lock().await;
        let refused = apply(&fixture, next, None)
            .await
            .expect_err("the list could not be put in force");
        assert_eq!(refused.code, ErrorCode::ResourceUnavailable, "{refused:?}");
    }
    controller.ask_for_admissions_pass();
    until_admission(&fixture, is_admitted).await;
    fixture.host.stop().await;
}

/// KR-REQ-18.06: a registry an earlier build wrote, whose enrolment has no policy, is read as it
/// is written. The enrolment row of a host that applied no policy has the bytes an earlier build
/// gave it, so a host that restarts on such a registry keeps its enrolment and no stored policy is
/// invented. (A row that carried a null where the policy is absent would not read back, and the
/// daemon would not start.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_enrolment_with_no_applied_policy_is_stored_as_an_earlier_build_stored_it() {
    use kr_protocol::account::PolicyAuthorityLink;
    use kr_protocol::ids::{AuthorityRevision, OrganisationId, PolicyKeyRevision};
    use kr_protocol::scalars::TimestampMs;
    use serde::{Deserialize, Serialize};

    /// The policy row as the build before an applied policy was kept wrote it.
    #[derive(Serialize, Deserialize)]
    struct EarlierPolicy {
        accepted_floor: AuthorityRevision,
        utc_floor_ms: TimestampMs,
        exclusively_managed: bool,
        offline: Nullable<kr_protocol::sharing::OfflineValidityPolicy>,
        enrolments: Vec<EarlierEnrolment>,
        lease_records: Vec<u8>,
    }

    #[derive(Serialize, Deserialize)]
    struct EarlierEnrolment {
        organisation_id: OrganisationId,
        root: PolicyAuthorityLink,
        links: Vec<PolicyAuthorityLink>,
        accepted_head: PolicyKeyRevision,
        enrolment_revision: AuthorityRevision,
        members: Vec<u8>,
    }

    let fixture = Fixture::start().await;
    let held = {
        let database = rusqlite::Connection::open(fixture.host.registry_database())
            .expect("opens the registry");
        database
            .query_row(
                "SELECT value FROM host_authority WHERE key = 'policy'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .expect("the host's policy row")
    };
    let earlier: EarlierPolicy = kr_cbor::from_canonical_slice(&held, &kr_cbor::Limits::DEFAULT)
        .expect("the row is the shape the earlier build wrote");
    assert_eq!(earlier.enrolments.len(), 1);
    assert_eq!(
        kr_cbor::to_canonical_vec(&earlier).expect("encodes"),
        held,
        "and it is the same bytes"
    );

    let fixture = fixture.restart().await;
    let listed = fixture.listed().await;
    assert_eq!(listed.enrolments.len(), 1, "the host kept its enrolment");
    assert_eq!(
        listed.enrolments[0].organisation_policy_revision,
        Nullable::null()
    );
    fixture.host.stop().await;
}
