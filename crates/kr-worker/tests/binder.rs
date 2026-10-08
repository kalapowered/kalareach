//! The binder: every binding is made from the admissions this worker holds, and every snapshot it
//! applies brings each live binding to the state of the release it holds.
//!
//! The admissions arrive as the control daemon hands them over, applied by the worker's own
//! admissions, and the broker's ledger is on the internal disk beside a real receipt journal, so a
//! row is read back through a connection of its own and a store that fails is the store's own
//! refusal.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.13 | a binding is made only from the admissions held, at their frame, for a package they admit, and carries its release, origin, frame, program and version, which stays; a binding stays on its hash across an upgrade and new bindings take the new one; an instance no package recognised is bound once one that recognises it is admitted, and only a matching, admitted package binds; a disabled or removed package's bindings end at the next snapshot; a write that fails leaves no binding; a launch given back takes its binding and its row, the row as soon as the store takes writes again or at the next process's open; a native exit removes the rows; the actions a package declares that cannot be registered are reported by name |
//! | KR-REQ-27.09 | an executable no signed build names has no version: the package that recognises it is still admitted and bound, its bridge channel is not served for that program, and the channel of a build a record names opens |
//! | KR-REQ-11.24 | the grants are the installation's effective capabilities through the runtime's map; a confirmed widening reaches a binding on the installed hash with its actions and its fault state kept, and never a retired release's; a withdrawal reaches every release of the package, a skipped revision's too |
//! | KR-REQ-11.25 | the decoding trust is the admitted connector's, with the answer right only beside the decoding right |
//! | KR-REQ-25.22 | a revoked release's binding is warned about once and served under the policy that only warns, refused every rich admission under the policy that disables at the next admission until the revocation is lifted, and ended under the policy that disables at once as soon as the request it admitted completes; the release's state is found by its origin, so a revocation reaches a binding on a release from another repository |

use std::path::Path;
use std::sync::Arc;

use kr_plugin_sdk::capability::PluginCapability;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::matching::MatchConfidence;
use kr_plugin_sdk::package::MANIFEST_FILE;
use kr_protocol::admission::{
    AdmissionRevocation, AdmittedPackage, FrameId, LiveRelease, ReleaseOrigin, ReleaseState,
    RevocationPolicy,
};
use kr_protocol::attention::AdapterTransition;
use kr_protocol::broker::{
    ActionName, ActionProvenance, AuthenticationState, BinaryIdentity, BrokerGrant, BrokerGrants,
    InstanceCapabilityIdentity, InstanceCapabilityRecord, InstanceCapabilityState,
    InstanceEvidenceSource, InstanceInvalidation, IntegrationMode, LaunchProfile,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, BrokerBindingId, CapabilityId,
    CapabilityRevision, EnvironmentId, GatewayConnectionId, LaunchProfileId, SessionId,
    UpstreamRequestId,
};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_worker::broker::binder::{AdapterNotice, MatchedExecutable};
use kr_worker::broker::bridge::BridgeProcess;
use kr_worker::broker::catalogue::Admissions;
use kr_worker::broker::catalogue::testing::{self, Snapshot};
use kr_worker::broker::connectors::{
    ConnectorSource, ConnectorSources, InstalledConnector, QualifiedExecutable, decoding_trust,
    fixture,
};
use kr_worker::broker::ledger::{BindingRecord, BoundExecutable};
use kr_worker::broker::{
    Broker, BrokerError, BrokerTransport, Caller, Credential, ForegroundMark, InstanceEnding,
    Invocation, Ledger, ManagedProcess, PendingTransmission, TransportHandle, UpstreamArrival,
    UpstreamBody, UpstreamDispatch, UpstreamOutcome, UpstreamRequest,
};
use kr_worker::persistence::JournalHealth;

mod common;

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn instance(number: u8) -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([number; 16]))
}

fn binding(number: u8) -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([100 + number; 16]))
}

/// The program every binding here is made for: Claude Code, at the build its signed record names.
fn program() -> MatchedExecutable {
    MatchedExecutable {
        path: "/usr/local/bin/claude".to_owned(),
        digest: Digest256::from_bytes(fixture::QUALIFIED_DIGEST),
    }
}

/// The signed record for [`program`]'s build, naming `version`.
fn build_named(version: &str) -> QualifiedExecutable {
    QualifiedExecutable {
        digest: Digest256::from_bytes(fixture::QUALIFIED_DIGEST),
        version: version.to_owned(),
    }
}

fn copy_tree(from: &Path, to: &Path) {
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

/// Writes another release of the package `source` names: every file alike, its manifest naming
/// `version`, so its hash differs. Returns what an installation hands over for it.
fn another_release(source: &ConnectorSource, version: &str) -> ConnectorSource {
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(source.package_dir.join(MANIFEST_FILE)).expect("the manifest reads"),
    )
    .expect("the manifest is JSON");
    manifest["version"] = serde_json::json!(version);
    let written = serde_json::to_string_pretty(&manifest).expect("the manifest encodes");
    let digest = PayloadDigest::of(written.as_bytes());
    let directory = source
        .package_dir
        .parent()
        .expect("the store's packages")
        .join(digest.to_string());
    copy_tree(&source.package_dir, &directory);
    std::fs::write(directory.join(MANIFEST_FILE), written).expect("the manifest is written");
    ConnectorSource {
        package_digest: Digest256::from_bytes(*digest.as_bytes()),
        package_dir: directory,
        ..source.clone()
    }
}

/// The digest the verified manifest names for a package's connector table.
fn connector_digest(source: &ConnectorSource) -> Digest256 {
    let table = std::fs::read(source.package_dir.join("connector.json")).expect("the table reads");
    Digest256::from_bytes(*PayloadDigest::of(&table).as_bytes())
}

/// The same release, revoked by its repository.
fn revoked(state: ReleaseState) -> ReleaseState {
    ReleaseState {
        revocation: Nullable::some(AdmissionRevocation {
            reason: "compromised".to_owned(),
            revoked_at: TimestampMs::new(5),
            statement: "Do not run this release.".to_owned(),
        }),
        ..state
    }
}

/// The same release, capped at `grants`.
fn capped(state: ReleaseState, grants: &[PluginCapability]) -> ReleaseState {
    ReleaseState {
        grant_cap: grants
            .iter()
            .map(|grant| grant.as_str().to_owned())
            .collect(),
        ..state
    }
}

/// A worker's broker on a session's store, and the admissions and connector sources it holds.
struct Worker {
    broker: Broker,
    store: common::SharedStore,
    packages: tempfile::TempDir,
    admissions: Admissions,
    sources: ConnectorSources,
}

impl Worker {
    fn open() -> Self {
        let store = common::SharedStore::open();
        let broker =
            Broker::open(Some(&store.path), session(), store.health()).expect("the broker opens");
        Self {
            broker,
            store,
            packages: tempfile::tempdir().expect("a directory on the internal disk"),
            admissions: Admissions::new(),
            sources: ConnectorSources::new(),
        }
    }

    /// Writes a package of `shape` in this worker's store, with every capability it declares
    /// granted.
    fn package(&self, shape: &fixture::Shape) -> ConnectorSource {
        fixture::package(self.packages.path(), Path::new(fixture::FORWARDER), shape)
            .expect("the package is written")
    }

    fn claude_code(&self) -> ConnectorSource {
        self.package(&fixture::Shape::claude_code())
    }

    fn hand_over(&self, snapshot: Snapshot) -> FrameId {
        testing::hand_over(&self.admissions, &self.sources, &self.broker, snapshot)
    }

    fn admit(&self, round: u64, packages: Vec<AdmittedPackage>) -> FrameId {
        self.hand_over(Snapshot::admitting(round, packages))
    }

    fn register(&self, number: u8) {
        self.broker
            .register_instance(instance(number), IntegrationMode::NativeBridge, None, None)
            .expect("the instance is registered");
    }

    fn bind(
        &self,
        number: u8,
        instance_number: u8,
        package_digest: Digest256,
        frame: FrameId,
    ) -> Result<Vec<BrokerError>, BrokerError> {
        self.broker.bind(
            binding(number),
            instance(instance_number),
            package_digest,
            frame,
            program(),
            kr_ipc::now_ms(),
        )
    }

    /// The row the ledger holds for one binding, read through a connection of its own.
    fn row(&self, number: u8) -> Option<BindingRecord> {
        Ledger::open(Some(&self.store.path), JournalHealth::shared())
            .expect("the ledger opens")
            .binding(binding(number))
            .expect("the ledger reads")
    }

    fn grants(&self, number: u8) -> BrokerGrants {
        self.broker
            .binding_record(binding(number))
            .expect("the binding is live")
            .grants
    }

    /// Asks for one rich admission through a binding: an action token for its instance.
    fn rich_admission(&self, number: u8, instance_number: u8) -> Result<(), BrokerError> {
        self.broker
            .issue_token(
                binding(number),
                &Invocation {
                    actor_id: ActorId::new("device-1").expect("valid"),
                    grant: BrokerGrant::UpstreamAction,
                    grant_id: None,
                    application_instance_id: instance(instance_number),
                    binding_revision: AgentBindingRevision::new(1),
                    action: ActionName::new("prompt.send").expect("valid"),
                    draft_id: None,
                    capability: None,
                    parameters: b"{\"text\":\"hello\"}".to_vec(),
                },
                kr_ipc::now_ms(),
            )
            .map(|_| ())
    }
}

// ---------------------------------------------------------------------------------------------
// Where a binding comes from
// ---------------------------------------------------------------------------------------------

/// One bind a test expects refused: the package, the frame, the instance, why, and the refusal
/// it is.
type Refusal = (
    Digest256,
    FrameId,
    u8,
    &'static str,
    fn(&BrokerError) -> bool,
);

/// KR-REQ-11.13: a binding is made only from the admissions this worker holds, at the frame they
/// are at, for a package they admit; nothing a caller describes is bound. The binding and its row
/// carry the release it holds and where that came from, the frame, the program it was made for
/// with the version the signed record names for its build, and the digest of the connector table.
#[test]
fn kr_req_11_13_a_binding_is_made_only_from_the_admissions_held_at_their_frame() {
    let worker = Worker::open();
    let mut source = worker.claude_code();
    source.qualified = vec![build_named(fixture::QUALIFIED_VERSION)];
    let package = testing::admitted(&source);
    worker.register(2);

    let before = worker
        .bind(
            1,
            2,
            package.package_digest,
            Snapshot::admitting(1, Vec::new()).frame(),
        )
        .expect_err("a worker that holds no admissions binds nothing");
    assert!(
        matches!(before, BrokerError::PreconditionFailed { .. }),
        "{before}"
    );

    let held = worker.admit(1, vec![package.clone()]);
    let stale = FrameId {
        round: U64::new(2),
        ..held
    };
    let refusals: [Refusal; 3] = [
        (
            package.package_digest,
            stale,
            2,
            "a frame other than the one held",
            |refused| matches!(refused, BrokerError::PreconditionFailed { .. }),
        ),
        (
            Digest256::from_bytes([7; 32]),
            held,
            2,
            "a package the admissions do not admit",
            |refused| matches!(refused, BrokerError::PermissionDenied { .. }),
        ),
        (
            package.package_digest,
            held,
            9,
            "an instance not registered",
            |refused| matches!(refused, BrokerError::UnknownSubject { .. }),
        ),
    ];
    for (digest, frame, instance_number, why, expected) in refusals {
        let refused = worker
            .bind(1, instance_number, digest, frame)
            .expect_err(why);
        assert!(expected(&refused), "{why}: {refused}");
        assert!(worker.broker.binding_record(binding(1)).is_none(), "{why}");
        assert!(worker.row(1).is_none(), "{why}: no row either");
    }

    let refused_actions = worker
        .bind(1, 2, package.package_digest, held)
        .expect("the admitted package binds at the frame held");
    assert!(
        refused_actions.is_empty(),
        "every declared action registers"
    );
    let release = LiveRelease {
        plugin_id: package.plugin_id.clone(),
        publisher_id: package.publisher_id.clone(),
        version: package.version.clone(),
        package_digest: package.package_digest,
        origin: package.origin.clone(),
    };
    let executable = BoundExecutable {
        path: program().path,
        digest: program().digest,
        version: Some(fixture::QUALIFIED_VERSION.to_owned()),
    };
    let bound = worker
        .broker
        .binding_record(binding(1))
        .expect("the binding is live");
    assert_eq!(bound.application_instance_id, instance(2));
    assert_eq!(bound.plugin_id, package.plugin_id);
    assert_eq!(bound.package_digest, package.package_digest);
    assert_eq!(bound.release.as_ref(), Some(&release));
    assert_eq!(bound.frame, Some(held));
    assert_eq!(bound.executable.as_ref(), Some(&executable));
    assert_eq!(bound.connector_digest, Some(connector_digest(&source)));
    for action in ["prompt.send", "approval.answer"] {
        assert!(
            bound
                .actions
                .contains_key(&ActionName::new(action).expect("valid")),
            "{action} is registered from the verified manifest"
        );
    }
    let row = worker.row(1).expect("the record was written");
    assert_eq!(row.application_instance_id, instance(2));
    assert_eq!(row.release, Some(release.clone()));
    assert_eq!(row.frame, Some(held));
    assert_eq!(row.executable, Some(executable));
    assert_eq!(row.connector_digest, Some(connector_digest(&source)));
    assert_eq!(row.grants, bound.grants);
    assert_eq!(row.trust, bound.trust);
    let live = worker.broker.live_bindings();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].binding_id, binding(1));
    assert_eq!(live[0].release, release);
    assert!(!live[0].ending);
}

/// KR-REQ-11.13: a live binding keeps the version its build's signed record named when it was
/// bound. A later synchronisation that names another version for the same build changes the
/// version a new binding takes, and not the live one's, in memory or in its row.
#[test]
fn kr_req_11_13_a_binding_keeps_the_version_it_was_bound_with() {
    let worker = Worker::open();
    let mut source = worker.claude_code();
    source.qualified = vec![build_named("2.1.278")];
    let first = worker.admit(1, vec![testing::admitted(&source)]);
    worker.register(2);
    worker.register(3);
    worker
        .bind(1, 2, source.package_digest, first)
        .expect("binds");

    source.qualified = vec![build_named("2.1.300")];
    let second = worker.admit(2, vec![testing::admitted(&source)]);
    worker
        .bind(2, 3, source.package_digest, second)
        .expect("a new binding at the new frame");

    let version = |number: u8| {
        worker
            .broker
            .binding_record(binding(number))
            .and_then(|bound| bound.executable)
            .and_then(|executable| executable.version)
    };
    assert_eq!(
        version(1).as_deref(),
        Some("2.1.278"),
        "the live binding's stays"
    );
    assert_eq!(
        version(2).as_deref(),
        Some("2.1.300"),
        "a new binding takes the new"
    );
    assert_eq!(
        worker
            .row(1)
            .and_then(|row| row.executable)
            .and_then(|executable| executable.version)
            .as_deref(),
        Some("2.1.278"),
        "and so does its row"
    );
}

/// KR-REQ-27.09: an executable no signed build names has no version, so the package that
/// recognises it keeps the terminal as its route and no typed action is advertised through it.
/// The package is still admitted and a binding is still made for the program, with no version;
/// the connector's table is qualified against a version, so its channel is not served for that
/// program, and the same package's channel opens for the build a signed record names. A typed
/// action here is one of the connector's table, which only a served channel carries; the package's
/// own declared actions are registered at bind whatever the version.
#[test]
fn kr_req_27_09_an_executable_no_signed_build_names_keeps_the_terminal_route_and_no_typed_action() {
    let worker = Worker::open();
    let mut source = worker.claude_code();
    source.qualified = vec![build_named(fixture::QUALIFIED_VERSION)];
    let frame = worker.admit(1, vec![testing::admitted(&source)]);
    worker
        .broker
        .register_instance(
            instance(2),
            IntegrationMode::NativeBridge,
            None,
            Some(managed(2)),
        )
        .expect("the launched instance is registered");
    worker.register(3);

    let matched = worker
        .broker
        .admitted_match(&program().path)
        .expect("the admitted package recognises the program");
    let named = program().digest;
    let unnamed = Digest256::from_bytes([0x5a; 32]);
    assert_eq!(matched.version_of(&named), Some(fixture::QUALIFIED_VERSION));
    assert_eq!(
        matched.version_of(&unnamed),
        None,
        "a build no signed record names has no version"
    );

    // The program is still bound to the package that recognises it, with no version.
    worker
        .broker
        .bind(
            binding(3),
            instance(3),
            source.package_digest,
            frame,
            MatchedExecutable {
                path: program().path,
                digest: unnamed,
            },
            kr_ipc::now_ms(),
        )
        .expect("an unnamed build is still bound to the package that recognises it");
    let bound = worker
        .broker
        .binding_record(binding(3))
        .and_then(|record| record.executable)
        .expect("the binding carries its program");
    assert_eq!(bound.version, None);

    // Its channel is not served, so no typed action of the connector's table is offered through
    // it. The version the channel is opened with is the one the connector's own signed builds
    // give, which is the version the admitted match gives.
    let connector = worker
        .sources
        .for_command(fixture::COMMAND)
        .expect("the admitted connector");
    let bridge = BridgeProcess {
        identity: ProcessStartIdentity::new(2_002, ProcessStartSource::MacosProcBsdInfo, 901),
        starter: Some(launched()),
        started: None,
    };
    assert_eq!(connector.qualified_version(&unnamed), None);
    assert_eq!(
        connector.qualified_version(&named),
        matched.version_of(&named)
    );
    let refusal = worker
        .broker
        .open_bridge_channel(
            instance(2),
            &bridge,
            &connector,
            connector.qualified_version(&unnamed),
        )
        .expect_err("no channel for a build no record names");
    assert!(
        matches!(&refusal, BrokerError::UnsupportedCapability { detail }
            if detail.contains("no signed qualification record names the executable")),
        "{refusal:?}"
    );

    // Control: the same package, the same instance and bridge, for the build a record names.
    worker
        .broker
        .open_bridge_channel(
            instance(2),
            &bridge,
            &connector,
            connector.qualified_version(&named),
        )
        .expect("the channel opens for the build a signed record names");
}

/// KR-REQ-11.24 and KR-REQ-11.25: `bind` derives a binding's grants from the installation's
/// effective capabilities through the plugin runtime's map, never from what the package asks for,
/// and its decoding trust from the admitted connector, with the right to answer only where
/// `approval.respond` is granted beside `approval.decode`. A package with no connector table has
/// no trust.
#[test]
fn kr_req_11_24_bind_derives_the_grants_from_the_installation_and_the_trust_from_its_connector() {
    let worker = Worker::open();
    // Claude Code: observing and decoding granted, acting upstream and answering not, though the
    // package asks for both.
    let mut claude = worker.claude_code();
    for withheld in [
        PluginCapability::UpstreamAction,
        PluginCapability::ApprovalRespond,
    ] {
        claude.granted.remove(&withheld);
    }
    // Gemini CLI: everything it asks for.
    let gemini = worker.package(&fixture::Shape::gemini_cli(&["--flag"]));
    // Qoder CLI: answering granted without decoding.
    let mut qoder = worker.package(&fixture::Shape::qoder_cli());
    qoder.granted.remove(&PluginCapability::ApprovalDecode);
    let declarative = declarative(worker.packages.path());
    let frame = worker.admit(
        1,
        [&claude, &gemini, &qoder, &declarative]
            .into_iter()
            .map(testing::admitted)
            .collect(),
    );
    for (number, source) in [(1, &claude), (2, &gemini), (3, &qoder), (4, &declarative)] {
        worker.register(number);
        worker
            .bind(number, number, source.package_digest, frame)
            .expect("binds");
    }

    let bound = |number: u8| {
        worker
            .broker
            .binding_record(binding(number))
            .expect("the binding is live")
    };
    let expected = |source: &ConnectorSource| {
        decoding_trust(
            &InstalledConnector::read(source.clone()).expect("the connector reads"),
            TimestampMs::new(0),
        )
    };
    let same = |held: Option<kr_protocol::broker::DecodingTrust>,
                wanted: Option<kr_protocol::broker::DecodingTrust>| {
        assert_eq!(
            held.map(|trust| kr_protocol::broker::DecodingTrust {
                granted_at: TimestampMs::new(0),
                ..trust
            }),
            wanted
        );
    };

    let first = bound(1);
    assert_eq!(
        first.grants,
        BrokerGrants::granted([BrokerGrant::Observation, BrokerGrant::ApprovalInterpreter]),
        "what the installation granted, not what the package asked for"
    );
    let trust = first.trust.clone().expect("decoding is granted");
    assert!(!trust.may_encode_response, "answering is not granted");
    same(first.trust, expected(&claude));

    let second = bound(2);
    assert_eq!(
        second.grants,
        BrokerGrants::granted([
            BrokerGrant::Observation,
            BrokerGrant::UpstreamAction,
            BrokerGrant::ApprovalInterpreter,
        ])
    );
    assert!(
        second
            .trust
            .as_ref()
            .is_some_and(|trust| trust.may_encode_response),
        "answering is granted beside decoding"
    );
    same(second.trust, expected(&gemini));

    let third = bound(3);
    assert!(
        !third.grants.holds(BrokerGrant::ApprovalInterpreter),
        "no interpreter without decoding"
    );
    assert!(
        third.trust.is_none(),
        "and no trust: answering alone decodes nothing"
    );

    let fourth = bound(4);
    assert_eq!(
        fourth.grants,
        BrokerGrants::granted([BrokerGrant::Observation])
    );
    assert!(
        fourth.trust.is_none(),
        "a package with no connector table has no trust"
    );
    assert!(fourth.connector_digest.is_none());
}

/// The example declarative package, which has no connector table, as an installation granting the
/// three capabilities it asks for hands it over.
fn declarative(root: &Path) -> ConnectorSource {
    fixture::declarative_package(
        root,
        "example-declarative",
        "example-agent",
        MatchConfidence::Exact,
    )
    .expect("the package is written")
}

// ---------------------------------------------------------------------------------------------
// What each snapshot does to a live binding
// ---------------------------------------------------------------------------------------------

/// KR-REQ-11.24: a confirmed widening reaches a live binding on the installed hash, derived again
/// with its actions and its fault state kept, and never a binding on a release the admissions no
/// longer admit, even when that release's cap says it could. `regrant` refuses such a binding.
#[test]
fn kr_req_11_24_a_confirmed_widening_reaches_only_the_installed_hash_and_keeps_what_it_holds() {
    let worker = Worker::open();
    let mut old = worker.claude_code();
    old.granted.remove(&PluginCapability::UpstreamAction);
    let mut new = another_release(&old, "0.4.0");
    new.granted.remove(&PluginCapability::UpstreamAction);
    let old_package = testing::admitted(&old);
    let first = worker.admit(1, vec![old_package.clone()]);
    worker.register(1);
    worker.register(2);
    worker
        .bind(1, 1, old.package_digest, first)
        .expect("the old release binds");

    // An upgrade: the new release is installed and the old one retired at its cap.
    let new_package = testing::admitted(&new);
    let second = worker.hand_over(Snapshot {
        releases: vec![
            testing::release_of(&new_package),
            testing::release_of(&old_package),
        ],
        ..Snapshot::admitting(2, vec![new_package.clone()])
    });
    worker
        .bind(2, 2, new.package_digest, second)
        .expect("the new release binds");
    worker
        .broker
        .disable_rich(binding(2), "the component faulted");
    assert!(!worker.grants(2).holds(BrokerGrant::UpstreamAction));

    // The owner confirms `upstream.action` for the installation; the old release's cap says the
    // same, and a retired release is still never widened.
    new.granted.insert(PluginCapability::UpstreamAction);
    old.granted.insert(PluginCapability::UpstreamAction);
    let widened = testing::admitted(&new);
    let third = worker.hand_over(Snapshot {
        releases: vec![
            testing::release_of(&widened),
            testing::release_of(&testing::admitted(&old)),
        ],
        ..Snapshot::admitting(3, vec![widened])
    });

    assert!(
        worker.grants(2).holds(BrokerGrant::UpstreamAction),
        "the installed hash's binding is widened"
    );
    let kept = worker
        .broker
        .binding_record(binding(2))
        .expect("the binding is live");
    assert!(
        kept.actions
            .contains_key(&ActionName::new("prompt.send").expect("valid")),
        "its actions are kept"
    );
    assert_eq!(
        kept.rich_disabled.as_deref(),
        Some("the component faulted"),
        "and its fault state"
    );
    assert_eq!(
        kept.frame,
        Some(third),
        "the change is recorded at its frame"
    );
    assert!(
        worker
            .row(2)
            .is_some_and(|row| row.grants.holds(BrokerGrant::UpstreamAction)),
        "the row first"
    );
    assert!(
        !worker.grants(1).holds(BrokerGrant::UpstreamAction),
        "the retired release's binding is not widened"
    );
    let refused = worker
        .broker
        .regrant(binding(1), third, kr_ipc::now_ms())
        .expect_err("a retired release is never widened");
    assert!(
        matches!(refused, BrokerError::PermissionDenied { .. }),
        "{refused}"
    );
    worker
        .broker
        .regrant(binding(2), third, kr_ipc::now_ms())
        .expect("the installed hash's binding is derived again, with nothing to change");
    let stale = worker
        .broker
        .regrant(binding(2), second, kr_ipc::now_ms())
        .expect_err("a regrant decided at a frame no longer held");
    assert!(
        matches!(stale, BrokerError::PreconditionFailed { .. }),
        "{stale}"
    );
}

/// KR-REQ-11.24: a withdrawn grant reaches every live binding of the package, on the installed
/// hash and on a retired release alike, and the next action that needs it is refused. A worker
/// sent a later revision first, which restores the grant to the installation with the owner's
/// confirmation, still narrows the retired release's binding, from the cap the snapshot carries.
#[test]
fn kr_req_11_24_a_withdrawn_grant_reaches_every_release_of_the_package() {
    let worker = Worker::open();
    let old = worker.claude_code();
    let new = another_release(&old, "0.4.0");
    let old_package = testing::admitted(&old);
    let first = worker.admit(1, vec![old_package.clone()]);
    worker.register(1);
    worker.register(2);
    worker
        .bind(1, 1, old.package_digest, first)
        .expect("the old release binds");
    let new_package = testing::admitted(&new);
    let second = worker.hand_over(Snapshot {
        releases: vec![
            testing::release_of(&new_package),
            testing::release_of(&old_package),
        ],
        ..Snapshot::admitting(2, vec![new_package.clone()])
    });
    worker
        .bind(2, 2, new.package_digest, second)
        .expect("the new release binds");
    worker
        .rich_admission(1, 1)
        .expect("acting upstream is granted on the old release");
    worker.rich_admission(2, 2).expect("and on the new one");

    // The revision that withdraws `upstream.action` never reaches this worker; the next one,
    // which restores it to the installation, does. The retired release's cap is narrowed for
    // good.
    let without: Vec<PluginCapability> = old
        .granted
        .iter()
        .copied()
        .filter(|grant| *grant != PluginCapability::UpstreamAction)
        .collect();
    worker.hand_over(Snapshot {
        releases: vec![
            testing::release_of(&new_package),
            capped(testing::release_of(&old_package), &without),
        ],
        ..Snapshot::admitting(4, vec![new_package.clone()])
    });
    assert!(
        !worker.grants(1).holds(BrokerGrant::UpstreamAction),
        "the retired release's binding loses the grant"
    );
    let refused = worker
        .rich_admission(1, 1)
        .expect_err("its next action that needs it is refused");
    assert!(matches!(refused, BrokerError::Grant(_)), "{refused}");
    assert!(
        worker
            .row(1)
            .is_some_and(|row| !row.grants.holds(BrokerGrant::UpstreamAction)),
        "in its row too"
    );
    assert!(
        worker.grants(2).holds(BrokerGrant::UpstreamAction),
        "the installed hash keeps what the installation grants"
    );

    // Withdrawn from the installation too: the installed hash's binding loses it as well.
    let mut narrowed = new.clone();
    narrowed.granted.remove(&PluginCapability::UpstreamAction);
    let narrowed = testing::admitted(&narrowed);
    worker.hand_over(Snapshot {
        releases: vec![
            testing::release_of(&narrowed),
            capped(testing::release_of(&old_package), &without),
        ],
        ..Snapshot::admitting(5, vec![narrowed])
    });
    assert!(!worker.grants(2).holds(BrokerGrant::UpstreamAction));
    let refused = worker
        .rich_admission(2, 2)
        .expect_err("the installed hash's next action is refused");
    assert!(matches!(refused, BrokerError::Grant(_)), "{refused}");
}

/// Brings the store back, as the host's maintenance does: the journal writes its own gap, and the
/// broker commits its gap and finishes its recovery, with nothing handed over meanwhile.
fn recover(worker: &mut Worker) {
    worker
        .broker
        .refuse_ledger_writes(false)
        .expect("the store takes writes again");
    let now = kr_ipc::now_ms().get();
    worker.store.recover_journal(now);
    worker
        .broker
        .recover(TimestampMs::new(now))
        .expect("the gap is committed");
    worker.broker.reconcile_connected(TimestampMs::new(now));
}

/// KR-REQ-11.24: a withdrawal the store cannot record takes effect at once, and its record is owed
/// and written when the store's recovery finishes, with no snapshot after it; the next action that
/// needs the withdrawn grant is refused then too. A widening the store cannot record is not used
/// until its record is written, which the recovery's end does as well.
#[test]
fn kr_req_11_24_a_grant_change_the_store_cannot_record_is_owed_and_never_widens_first() {
    let mut worker = Worker::open();
    let source = worker.claude_code();
    let first = worker.admit(1, vec![testing::admitted(&source)]);
    worker.register(1);
    worker
        .bind(1, 1, source.package_digest, first)
        .expect("binds");
    let mut narrowed = source.clone();
    narrowed.granted.remove(&PluginCapability::UpstreamAction);

    worker
        .broker
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    worker.admit(2, vec![testing::admitted(&narrowed)]);
    assert!(
        !worker.grants(1).holds(BrokerGrant::UpstreamAction),
        "the withdrawal takes effect whatever the store says"
    );
    assert!(
        worker
            .row(1)
            .is_some_and(|row| row.grants.holds(BrokerGrant::UpstreamAction)),
        "its record is not written yet"
    );

    recover(&mut worker);
    assert!(
        worker
            .row(1)
            .is_some_and(|row| !row.grants.holds(BrokerGrant::UpstreamAction)),
        "the owed record is written once the recovery finishes"
    );
    let refused = worker
        .rich_admission(1, 1)
        .expect_err("the withdrawn grant stays withdrawn");
    assert!(matches!(refused, BrokerError::Grant(_)), "{refused}");

    // A widening the store refuses is not used until it is recorded.
    worker
        .broker
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    worker.admit(3, vec![testing::admitted(&source)]);
    assert!(
        !worker.grants(1).holds(BrokerGrant::UpstreamAction),
        "a widening with no record is not in force"
    );
    recover(&mut worker);
    assert!(
        worker.grants(1).holds(BrokerGrant::UpstreamAction),
        "the recovery's end brings the binding to the admissions it holds"
    );
    assert!(
        worker
            .row(1)
            .is_some_and(|row| row.grants.holds(BrokerGrant::UpstreamAction)),
        "record first"
    );
    worker
        .rich_admission(1, 1)
        .expect("the confirmed grant is in force once recorded");
}

/// KR-REQ-11.13: a binding stays on its hash across an upgrade, reporting the release it holds;
/// a new binding takes the new hash, and the old one is not admitted for new bindings any more.
#[test]
fn kr_req_11_13_a_binding_stays_on_its_hash_across_an_upgrade() {
    let worker = Worker::open();
    let old = worker.claude_code();
    let new = another_release(&old, "0.4.0");
    let old_package = testing::admitted(&old);
    let first = worker.admit(1, vec![old_package.clone()]);
    for number in 1..=3 {
        worker.register(number);
    }
    worker.bind(1, 1, old.package_digest, first).expect("binds");

    let new_package = testing::admitted(&new);
    let second = worker.hand_over(Snapshot {
        releases: vec![
            testing::release_of(&new_package),
            testing::release_of(&old_package),
        ],
        ..Snapshot::admitting(2, vec![new_package])
    });
    let kept = worker
        .broker
        .binding_record(binding(1))
        .expect("the binding is live");
    assert_eq!(
        kept.package_digest, old.package_digest,
        "it stays on its hash"
    );
    assert_eq!(
        kept.release.map(|release| release.package_digest),
        Some(old.package_digest)
    );
    worker
        .bind(2, 2, new.package_digest, second)
        .expect("a new binding takes the new hash");
    let refused = worker
        .bind(3, 3, old.package_digest, second)
        .expect_err("the old hash is not admitted any more");
    assert!(
        matches!(refused, BrokerError::PermissionDenied { .. }),
        "{refused}"
    );
    let mut held: Vec<Digest256> = worker
        .broker
        .live_bindings()
        .iter()
        .map(|live| live.release.package_digest)
        .collect();
    held.sort();
    let mut wanted = vec![old.package_digest, new.package_digest];
    wanted.sort();
    assert_eq!(held, wanted, "each binding reports the release it holds");
}

/// A launch profile for an instance running the program at `path`.
fn profile(number: u8, path: &str) -> LaunchProfile {
    LaunchProfile {
        profile_id: LaunchProfileId::new(format!("lp-{number}")).expect("valid"),
        environment_id: EnvironmentId::new(Uuid::from_bytes([1; 16])),
        binary: BinaryIdentity {
            resolved_path: path.to_owned(),
            digest: Digest256::from_bytes(fixture::QUALIFIED_DIGEST),
            version: "unknown".to_owned(),
            distribution: "adopted".to_owned(),
        },
        arguments: vec![path.to_owned()],
        authentication: AuthenticationState::Authenticated,
        mode: IntegrationMode::NativeTerminal,
        ownership: kr_protocol::broker::AgentOwnership::Full,
        vendor_mode: kr_protocol::scalars::Nullable::null(),
        resolved_at: TimestampMs::new(10),
    }
}

/// KR-REQ-11.13: an instance running with no binding is bound once a package that recognises its
/// program is admitted, as an enable after its launch; only a package that matches it and is
/// admitted binds it, and an instance whose program nothing recognises stays unbound.
#[test]
fn kr_req_11_13_an_instance_is_bound_once_an_admitted_package_recognises_it() {
    let worker = Worker::open();
    let claude = worker.claude_code();
    let gemini = worker.package(&fixture::Shape::gemini_cli(&[]));
    worker
        .broker
        .adopt_instance(
            profile(1, "/usr/local/bin/claude"),
            instance(1),
            ProcessStartIdentity::new(1_101, ProcessStartSource::MacosProcBsdInfo, 900),
            None,
        )
        .expect("a program found running");
    worker
        .broker
        .adopt_instance(
            profile(2, "/usr/local/bin/vim"),
            instance(2),
            ProcessStartIdentity::new(1_102, ProcessStartSource::MacosProcBsdInfo, 900),
            None,
        )
        .expect("another program found running");
    let bound_to = |number: u8| {
        worker
            .broker
            .live_bindings()
            .into_iter()
            .find(|live| live.application_instance_id == instance(number))
            .map(|live| live.release.package_digest)
    };

    // Admitted, and recognising neither.
    worker.admit(1, vec![testing::admitted(&gemini)]);
    assert_eq!(
        bound_to(1),
        None,
        "a package that does not match binds nothing"
    );
    assert_eq!(bound_to(2), None);

    // Enabled: the package that recognises the program is admitted.
    worker.admit(
        2,
        vec![testing::admitted(&gemini), testing::admitted(&claude)],
    );
    assert_eq!(
        bound_to(1),
        Some(claude.package_digest),
        "the enabled package binds the running instance"
    );
    assert_eq!(
        bound_to(2),
        None,
        "a program nothing recognises stays unbound"
    );
    let bound = worker
        .broker
        .live_bindings()
        .into_iter()
        .find(|live| live.application_instance_id == instance(1))
        .expect("bound");
    assert_eq!(
        worker
            .broker
            .binding_record(bound.binding_id)
            .and_then(|record| record.executable)
            .map(|executable| executable.path)
            .as_deref(),
        Some("/usr/local/bin/claude"),
        "for the program it was found running"
    );
}

/// KR-REQ-11.13: a binding of a package the owner disabled or removed ends at the next snapshot,
/// its row with it, and a binding of another package stays.
#[test]
fn kr_req_11_13_a_disabled_or_removed_package_s_bindings_end_at_the_next_snapshot() {
    let worker = Worker::open();
    let claude = worker.claude_code();
    let gemini = worker.package(&fixture::Shape::gemini_cli(&[]));
    let claude_package = testing::admitted(&claude);
    let gemini_package = testing::admitted(&gemini);
    let first = worker.admit(1, vec![claude_package.clone(), gemini_package.clone()]);
    worker.register(1);
    worker.register(2);
    worker
        .bind(1, 1, claude.package_digest, first)
        .expect("binds");
    worker
        .bind(2, 2, gemini.package_digest, first)
        .expect("binds");

    worker.hand_over(Snapshot {
        releases: vec![
            ReleaseState {
                ends_at_next_boundary: true,
                ..testing::release_of(&claude_package)
            },
            testing::release_of(&gemini_package),
        ],
        ..Snapshot::admitting(2, vec![gemini_package])
    });
    assert!(
        worker.broker.binding_record(binding(1)).is_none(),
        "the disabled package's binding ended"
    );
    assert!(worker.row(1).is_none(), "and its row went with it");
    assert!(worker.broker.binding_record(binding(2)).is_some());
    assert!(worker.row(2).is_some());
    assert!(
        worker.broker.take_notices().is_empty(),
        "an ending that is not a revocation warns about nothing"
    );
}

// ---------------------------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------------------------

/// What a person reads about a revoked release of `package`.
fn warning_about(package: &AdmittedPackage) -> String {
    format!(
        "{} {} was revoked by its repository (compromised): Do not run this release.",
        package.plugin_id, package.version
    )
}

/// KR-REQ-25.22: under the policy that only warns, a binding on a revoked release keeps serving,
/// and the session is told once, with the warning a person reads; once the revocation no longer
/// stands, it is told that too.
#[test]
fn kr_req_25_22_warn_only_keeps_a_revoked_binding_serving_and_says_so_once() {
    let worker = Worker::open();
    let source = worker.claude_code();
    let package = testing::admitted(&source);
    let first = worker.admit(1, vec![package.clone()]);
    worker.register(1);
    worker
        .bind(1, 1, source.package_digest, first)
        .expect("binds");

    for round in [2, 3] {
        worker.hand_over(Snapshot {
            policy: RevocationPolicy::WarnOnly,
            releases: vec![revoked(testing::release_of(&package))],
            ..Snapshot::admitting(round, Vec::new())
        });
    }
    assert_eq!(
        worker.broker.take_notices(),
        vec![AdapterNotice {
            plugin_id: package.plugin_id.clone(),
            transition: AdapterTransition::Revoked,
            text: warning_about(&package),
        }],
        "told once, however many snapshots say so"
    );
    let serving = worker
        .broker
        .binding_record(binding(1))
        .expect("the binding is live");
    assert!(serving.rich_disabled.is_none());
    assert!(!serving.ending);
    worker
        .rich_admission(1, 1)
        .expect("it keeps serving rich admissions");

    // The administrator moves to the policy that disables at the next admission, and back.
    worker.hand_over(Snapshot {
        policy: RevocationPolicy::DisableAtNextAdmission,
        releases: vec![revoked(testing::release_of(&package))],
        ..Snapshot::admitting(4, Vec::new())
    });
    assert!(worker.rich_admission(1, 1).is_err());
    worker.hand_over(Snapshot {
        policy: RevocationPolicy::WarnOnly,
        releases: vec![revoked(testing::release_of(&package))],
        ..Snapshot::admitting(5, Vec::new())
    });
    worker
        .rich_admission(1, 1)
        .expect("under the policy that only warns it serves again");
    assert!(
        worker.broker.take_notices().is_empty(),
        "the same revocation is not told again"
    );

    worker.admit(6, vec![package.clone()]);
    assert_eq!(
        worker.broker.take_notices(),
        vec![AdapterNotice {
            plugin_id: package.plugin_id.clone(),
            transition: AdapterTransition::Cleared,
            text: format!(
                "this session holds no binding on a revoked release of {} any more",
                package.plugin_id
            ),
        }]
    );
}

/// KR-REQ-25.22: under the policy that disables at the next admission, a binding on a revoked
/// release keeps observing and every rich admission through it is refused, with the revocation as
/// the reason, until the revocation no longer stands. What a component fault disabled stays
/// disabled whatever the revocation does.
#[test]
fn kr_req_25_22_disable_at_next_admission_refuses_rich_admissions_until_the_revocation_is_lifted() {
    let worker = Worker::open();
    let source = worker.claude_code();
    let package = testing::admitted(&source);
    let first = worker.admit(1, vec![package.clone()]);
    worker.register(1);
    worker
        .bind(1, 1, source.package_digest, first)
        .expect("binds");
    let revoke = |round: u64| {
        worker.hand_over(Snapshot {
            policy: RevocationPolicy::DisableAtNextAdmission,
            releases: vec![revoked(testing::release_of(&package))],
            ..Snapshot::admitting(round, Vec::new())
        })
    };

    revoke(2);
    let disabled = worker
        .broker
        .binding_record(binding(1))
        .expect("the binding stays");
    assert!(
        disabled.grants.holds(BrokerGrant::Observation),
        "it keeps observing"
    );
    assert!(!disabled.ending, "and is not ended");
    let refused = worker
        .rich_admission(1, 1)
        .expect_err("a rich admission is refused");
    assert!(
        matches!(&refused, BrokerError::UnsupportedCapability { detail } if detail.contains("revoked by its repository")),
        "{refused}"
    );
    assert_eq!(
        worker
            .broker
            .take_notices()
            .into_iter()
            .map(|notice| notice.transition)
            .collect::<Vec<_>>(),
        vec![AdapterTransition::Revoked]
    );

    worker.admit(3, vec![package.clone()]);
    worker
        .rich_admission(1, 1)
        .expect("a revocation that no longer stands lifts what it did");
    assert_eq!(
        worker
            .broker
            .take_notices()
            .into_iter()
            .map(|notice| notice.transition)
            .collect::<Vec<_>>(),
        vec![AdapterTransition::Cleared]
    );

    worker
        .broker
        .disable_rich(binding(1), "the component faulted");
    revoke(4);
    worker.admit(5, vec![package.clone()]);
    assert_eq!(
        worker.broker.rich_disabled(binding(1)).as_deref(),
        Some("the component faulted"),
        "a fault's disabling is not a revocation's to lift"
    );

    // The other order: revoked and disabled for it, then a fault, then the revocation lifted, and
    // then the policy that only warns. The fault stays.
    let worker = Worker::open();
    let source = worker.claude_code();
    let package = testing::admitted(&source);
    let first = worker.admit(1, vec![package.clone()]);
    worker.register(1);
    worker
        .bind(1, 1, source.package_digest, first)
        .expect("binds");
    worker.hand_over(Snapshot {
        policy: RevocationPolicy::DisableAtNextAdmission,
        releases: vec![revoked(testing::release_of(&package))],
        ..Snapshot::admitting(2, Vec::new())
    });
    worker
        .broker
        .disable_rich(binding(1), "the component faulted");
    worker.hand_over(Snapshot {
        policy: RevocationPolicy::WarnOnly,
        releases: vec![revoked(testing::release_of(&package))],
        ..Snapshot::admitting(3, Vec::new())
    });
    assert_eq!(
        worker.broker.rich_disabled(binding(1)).as_deref(),
        Some("the component faulted"),
        "the policy that only warns lifts no fault"
    );
    worker.admit(4, vec![package]);
    assert_eq!(
        worker.broker.rich_disabled(binding(1)).as_deref(),
        Some("the component faulted"),
        "and nor does the revocation's end"
    );
}

/// KR-REQ-25.22: a revocation reaches a binding by the release it holds, found by where that came
/// from: a binding on a release from one repository is warned and disabled when that repository
/// revokes it, though the package now installed came from another repository and is not revoked.
#[test]
fn kr_req_25_22_a_revocation_reaches_a_binding_on_a_release_from_another_repository() {
    let worker = Worker::open();
    let old = worker.claude_code();
    let new = another_release(&old, "0.4.0");
    let old_package = testing::admitted(&old);
    let first = worker.admit(1, vec![old_package.clone()]);
    worker.register(1);
    worker.bind(1, 1, old.package_digest, first).expect("binds");

    // The package moves to another repository; the one it came from revokes the old release.
    let moved = AdmittedPackage {
        origin: ReleaseOrigin {
            repository_id: "mirror".to_owned(),
            enrolment_key: "fedcba9876543210fedcba9876543210".to_owned(),
        },
        ..testing::admitted(&new)
    };
    let second = worker.hand_over(Snapshot {
        policy: RevocationPolicy::DisableAtNextAdmission,
        releases: vec![
            testing::release_of(&moved),
            revoked(testing::release_of(&old_package)),
        ],
        ..Snapshot::admitting(2, vec![moved.clone()])
    });
    assert_eq!(
        worker.broker.take_notices(),
        vec![AdapterNotice {
            plugin_id: old_package.plugin_id.clone(),
            transition: AdapterTransition::Revoked,
            text: warning_about(&old_package),
        }]
    );
    assert!(
        worker.rich_admission(1, 1).is_err(),
        "the policy reaches the old release's binding"
    );
    worker.register(2);
    worker
        .bind(2, 2, moved.package_digest, second)
        .expect("the release now installed binds");
    worker.rich_admission(2, 2).expect("and is not revoked");
}

/// A transport that records what it carries and answers at once.
#[derive(Debug, Default)]
struct RecordingUpstream {
    submitted: std::sync::Mutex<Vec<UpstreamRequest>>,
}

impl UpstreamDispatch for RecordingUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        self.submitted
            .lock()
            .expect("the record is not poisoned")
            .push(request.clone());
        let upstream_request_id = match &request.body {
            UpstreamBody::Approval {
                upstream_request_id,
                ..
            } => upstream_request_id.clone(),
            _ => UpstreamRequestId::new("upstream-1").expect("valid"),
        };
        Ok(PendingTransmission::settled(Ok(UpstreamOutcome {
            upstream_request_id: Some(upstream_request_id),
            turn_id: request.turn_id.clone(),
            provenance: ActionProvenance::UpstreamTypedRpc,
        })))
    }
}

/// The application a launch registered for an instance.
fn launched() -> ProcessStartIdentity {
    ProcessStartIdentity::new(1_002, ProcessStartSource::MacosProcBsdInfo, 900)
}

fn managed(number: u8) -> ManagedProcess {
    ManagedProcess::new(
        instance(number),
        launched(),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id: instance(number),
            executable_digest: Digest256::from_bytes([3; 32]),
            process: launched(),
        },
        Credential::from_bytes([9; 32]),
        false,
        TimestampMs::new(1),
    )
}

/// Opens instance 2's channel for `connector`, relays one tool approval on it, has the channel's
/// package interpret it, and equips the instance to answer it: the evidence the answer is checked
/// against and the transport it goes out on. Returns the resource and the transport.
fn relayed_approval(
    broker: &Broker,
    connector: &InstalledConnector,
) -> (
    kr_protocol::gateway::PendingResource,
    Arc<RecordingUpstream>,
) {
    let connection = broker
        .open_bridge_channel(
            instance(2),
            &BridgeProcess {
                identity: ProcessStartIdentity::new(
                    2_002,
                    ProcessStartSource::MacosProcBsdInfo,
                    901,
                ),
                starter: Some(launched()),
                started: None,
            },
            connector,
            Some(fixture::QUALIFIED_VERSION),
        )
        .expect("the application's own channel is opened");
    let frame = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/claude/channel/permission_request",
        "params": {
            "request_id": "abcde",
            "tool_name": "Bash",
            "description": "List the files here",
            "input_preview": "ls -la",
        },
    })
    .to_string();
    let Ok(UpstreamArrival::Forward {
        resource: Some(relayed),
        ..
    }) = broker.receive_upstream(
        connection,
        frame.as_bytes(),
        EnvironmentId::new(Uuid::from_bytes([7; 16])),
        "person",
        kr_ipc::now_ms(),
    )
    else {
        panic!("the relayed approval is recorded");
    };
    broker
        .interpret_declared(relayed.resource_id, kr_ipc::now_ms())
        .expect("interpreted")
        .expect("by the channel's own package's binding");
    broker
        .record_capability(InstanceCapabilityRecord {
            capability_id: CapabilityId::new("agent.approval").expect("valid"),
            capability_version: "1".to_owned(),
            application_instance_id: instance(2),
            identity: InstanceCapabilityIdentity {
                binary_digest: Nullable::some(Digest256::from_bytes([3; 32])),
                ..InstanceCapabilityIdentity::default()
            },
            revision: CapabilityRevision::new(1),
            state: InstanceCapabilityState::QualifiedAvailable,
            source: InstanceEvidenceSource::HostProbe,
            invalidated_by: [InstanceInvalidation::BindingChanged].into_iter().collect(),
            disabled_reason: Nullable::null(),
            observed_at: TimestampMs::new(1),
        })
        .expect("the evidence is recorded");
    let upstream = Arc::new(RecordingUpstream::default());
    broker.bind_connection_dispatch(connection, Arc::clone(&upstream) as _);
    let _: GatewayConnectionId = connection;
    (relayed, upstream)
}

/// KR-REQ-25.22: under the policy that disables at once, a binding on a revoked release admits
/// nothing more from the next snapshot on, and a request it admitted before completes: the
/// binding is reported ending while that request is open, and closes, with its row, at the first
/// snapshot after it completes. A binding on the same release with nothing open closes at once.
#[tokio::test]
async fn kr_req_25_22_disable_at_once_ends_a_revoked_binding_once_its_admitted_request_completes() {
    let worker = Worker::open();
    let source = worker.claude_code();
    let package = testing::admitted(&source);
    let first = worker.admit(1, vec![package.clone()]);
    worker
        .broker
        .register_instance(
            instance(2),
            IntegrationMode::NativeBridge,
            None,
            Some(managed(2)),
        )
        .expect("the launched instance is registered");
    worker.register(3);
    worker
        .bind(1, 2, source.package_digest, first)
        .expect("binds");
    worker
        .bind(2, 3, source.package_digest, first)
        .expect("binds");
    let connector = worker
        .sources
        .for_command(fixture::COMMAND)
        .expect("the admitted connector");
    let (resource, upstream) = relayed_approval(&worker.broker, &connector);
    let caller = Caller {
        actor_id: ActorId::new("device-1").expect("valid"),
        grant_id: None,
    };
    let answer = kr_protocol::agent::AgentApprovalRespondParams {
        target: kr_protocol::agent::AgentMutationTarget {
            subject: kr_worker::broker::subject(session(), instance(2)),
            binding_revision: AgentBindingRevision::new(1),
        },
        resource_id: resource.resource_id,
        option_id: "allow".to_owned(),
    };
    let admitted = worker
        .broker
        .admit_approval(&caller, &answer, kr_ipc::now_ms())
        .expect("the answer is admitted before the revocation arrives");

    let revoke = |round: u64| {
        worker.hand_over(Snapshot {
            policy: RevocationPolicy::DisableAtOnce,
            releases: vec![revoked(testing::release_of(&package))],
            ..Snapshot::admitting(round, Vec::new())
        })
    };
    revoke(2);
    assert!(
        worker.broker.binding_record(binding(2)).is_none(),
        "a binding with nothing open closes at once"
    );
    assert!(worker.row(2).is_none());
    let ending = worker
        .broker
        .binding_record(binding(1))
        .expect("the binding whose request is open stays until it completes");
    assert!(ending.ending);
    assert!(
        worker
            .broker
            .live_bindings()
            .iter()
            .any(|live| live.binding_id == binding(1) && live.ending),
        "and is reported ending"
    );
    assert!(
        worker.rich_admission(1, 2).is_err(),
        "it admits nothing more"
    );

    worker
        .broker
        .record_approval(&admitted, kr_ipc::now_ms())
        .expect("the admitted answer goes")
        .settled(kr_ipc::now_ms())
        .await
        .expect("and completes");
    assert_eq!(
        upstream
            .submitted
            .lock()
            .expect("the record is not poisoned")
            .len(),
        1,
        "the answer reached the application"
    );
    assert!(
        worker.broker.binding_record(binding(1)).is_some(),
        "nothing closes it between snapshots"
    );

    revoke(3);
    assert!(
        worker.broker.binding_record(binding(1)).is_none(),
        "it closes at the first snapshot after its request completed"
    );
    assert!(worker.row(1).is_none());
    assert_eq!(
        worker
            .broker
            .take_notices()
            .into_iter()
            .map(|notice| notice.transition)
            .collect::<Vec<_>>(),
        vec![
            AdapterTransition::Revoked,
            AdapterTransition::Revoked,
            AdapterTransition::Cleared
        ],
        "each binding on the revoked release is warned about, and the session is told when none \
         is left"
    );
}

/// KR-REQ-18.06: a binding on a package the organisation's allowlist no longer names ends at its
/// next admission boundary, as a disabled or removed package's does: it admits nothing more while
/// a request it admitted is open, and says the allowlist may be why, not only that the package was
/// disabled or removed.
#[tokio::test]
async fn kr_req_18_06_a_binding_ended_by_the_allowlist_admits_nothing_and_says_why() {
    let worker = Worker::open();
    let source = worker.claude_code();
    let package = testing::admitted(&source);
    let first = worker.admit(1, vec![package.clone()]);
    worker
        .broker
        .register_instance(
            instance(2),
            IntegrationMode::NativeBridge,
            None,
            Some(managed(2)),
        )
        .expect("the launched instance is registered");
    worker
        .bind(1, 2, source.package_digest, first)
        .expect("binds");
    let connector = worker
        .sources
        .for_command(fixture::COMMAND)
        .expect("the admitted connector");
    let (resource, _upstream) = relayed_approval(&worker.broker, &connector);
    let caller = Caller {
        actor_id: ActorId::new("device-1").expect("valid"),
        grant_id: None,
    };
    let answer = kr_protocol::agent::AgentApprovalRespondParams {
        target: kr_protocol::agent::AgentMutationTarget {
            subject: kr_worker::broker::subject(session(), instance(2)),
            binding_revision: AgentBindingRevision::new(1),
        },
        resource_id: resource.resource_id,
        option_id: "allow".to_owned(),
    };
    worker
        .broker
        .admit_approval(&caller, &answer, kr_ipc::now_ms())
        .expect("the answer is admitted before the allowlist changes");
    worker.rich_admission(1, 2).expect("admitted before");

    worker.hand_over(Snapshot {
        releases: vec![ReleaseState {
            ends_at_next_boundary: true,
            ..testing::release_of(&package)
        }],
        ..Snapshot::admitting(2, Vec::new())
    });
    assert!(
        worker
            .broker
            .live_bindings()
            .iter()
            .any(|live| live.binding_id == binding(1) && live.ending),
        "the binding whose request is open is reported ending"
    );
    let refusal = worker
        .rich_admission(1, 2)
        .expect_err("it admits nothing more")
        .to_string();
    assert!(refusal.contains("allowlist"), "{refusal}");
}

// ---------------------------------------------------------------------------------------------
// The record, and what ends it
// ---------------------------------------------------------------------------------------------

/// KR-REQ-11.13: a binding whose record the store refuses is not made: nothing is bound in memory,
/// and nothing is reported.
#[test]
fn kr_req_11_13_a_binding_whose_record_cannot_be_written_is_not_made() {
    let worker = Worker::open();
    let source = worker.claude_code();
    let frame = worker.admit(1, vec![testing::admitted(&source)]);
    worker.register(1);
    worker
        .broker
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    let refused = worker
        .bind(1, 1, source.package_digest, frame)
        .expect_err("the store refuses the record");
    assert!(
        matches!(refused, BrokerError::StoreFault { .. }),
        "{refused}"
    );
    assert!(worker.broker.binding_record(binding(1)).is_none());
    assert!(worker.broker.live_bindings().is_empty());
}

/// Launches instance 1 as a command backend's launch does, up to its registration.
fn registered_launch(broker: &Broker) -> kr_worker::broker::profiles::RegisteredLaunch<'_> {
    let intent = broker
        .prepare_launch(
            profile(1, "/usr/local/bin/claude"),
            ForegroundMark::idle(4),
            None,
        )
        .expect("the launch is prepared");
    broker
        .execute_launch(&intent, &ForegroundMark::idle(4), instance(1))
        .expect("the launch runs")
        .register(IntegrationMode::NativeBridge, Some(managed(1)))
        .expect("the instance is registered")
}

/// KR-REQ-11.13: a launch given back after its instance was bound takes the binding with it, from
/// memory and from the ledger. With the store refusing the row's removal, the binding still goes
/// from memory at once, and its row goes once the store's recovery finishes.
#[test]
fn kr_req_11_13_a_launch_given_back_after_its_bind_leaves_no_binding_or_row() {
    let mut worker = Worker::open();
    let source = worker.claude_code();
    let frame = worker.admit(1, vec![testing::admitted(&source)]);

    let launch = registered_launch(&worker.broker);
    worker
        .bind(1, 1, source.package_digest, frame)
        .expect("binds");
    assert!(worker.row(1).is_some());
    launch.abandon();
    assert!(worker.broker.binding_record(binding(1)).is_none());
    assert!(worker.row(1).is_none(), "the row goes with it");

    let launch = registered_launch(&worker.broker);
    worker
        .bind(1, 1, source.package_digest, frame)
        .expect("binds again");
    worker
        .broker
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    launch.abandon();
    assert!(
        worker.broker.binding_record(binding(1)).is_none(),
        "the binding goes from memory at once"
    );
    assert!(worker.broker.live_bindings().is_empty());
    assert!(
        worker.row(1).is_some(),
        "the row the store would not remove is still there"
    );
    assert_eq!(
        worker.broker.owed_rows().into_iter().collect::<Vec<_>>(),
        vec![binding(1)],
        "and owed"
    );

    worker
        .broker
        .refuse_ledger_writes(false)
        .expect("the store takes writes again");
    let now = kr_ipc::now_ms().get();
    worker.store.recover_journal(now);
    worker
        .broker
        .recover(TimestampMs::new(now))
        .expect("the gap is committed");
    worker.broker.reconcile_connected(TimestampMs::new(now));
    assert!(
        worker.row(1).is_none(),
        "the owed row is removed once the recovery finishes"
    );
    assert!(worker.broker.owed_rows().is_empty());
}

/// KR-REQ-11.13: a row a process could not remove before it ended is removed by the next process
/// that opens the session's ledger, which never takes an earlier process's bindings back; and an
/// instance's native exit removes its bindings' rows.
#[test]
fn kr_req_11_13_rows_go_with_the_process_that_held_them_and_with_a_native_exit() {
    let worker = Worker::open();
    let source = worker.claude_code();
    let frame = worker.admit(1, vec![testing::admitted(&source)]);
    worker.register(1);
    worker.register(2);
    worker
        .bind(1, 1, source.package_digest, frame)
        .expect("binds");
    worker
        .bind(2, 2, source.package_digest, frame)
        .expect("binds");

    let ended = worker.broker.end(instance(2), InstanceEnding::NativeExit);
    assert!(ended.instance_ended);
    assert!(worker.broker.binding_record(binding(2)).is_none());
    assert!(worker.row(2).is_none(), "a native exit removes its rows");

    let Worker {
        broker,
        store,
        packages,
        ..
    } = worker;
    drop(broker);
    assert!(
        Ledger::open(Some(&store.path), JournalHealth::shared())
            .expect("the ledger opens")
            .binding(binding(1))
            .expect("the ledger reads")
            .is_some(),
        "the ended process left its row"
    );
    let next = Broker::open(Some(&store.path), session(), store.health())
        .expect("the next process opens the ledger");
    assert!(
        Ledger::open(Some(&store.path), JournalHealth::shared())
            .expect("the ledger opens")
            .binding(binding(1))
            .expect("the ledger reads")
            .is_none(),
        "the next process removes it before anything is decided"
    );
    assert!(next.live_bindings().is_empty());
    drop(packages);
}

/// Section 5: a package that ships a component binds for its declarative parts, whose actions it
/// registers and whose rich admissions it makes, and the worker's report on its admissions says
/// what this host does with the component, and what it does not. The same package with no
/// component is reported for nothing.
#[test]
fn kr_req_11_13_a_package_with_a_component_binds_its_declarative_parts_and_reports_what_is_done_with_the_component()
 {
    let reported = |worker: &Worker, package: Digest256| {
        worker
            .admissions
            .report(
                session(),
                worker.broker.live_bindings(),
                &worker.broker.action_refusals(),
            )
            .expect("a report")
            .iter()
            .flat_map(|part| part.refusals.iter())
            .filter(|refusal| refusal.package_digest == package)
            .map(|refusal| refusal.detail.clone())
            .collect::<Vec<_>>()
    };

    let worker = Worker::open();
    let source = worker.package(&fixture::Shape {
        component: true,
        ..fixture::Shape::claude_code()
    });
    let frame = worker.admit(1, vec![testing::admitted(&source)]);
    worker.register(1);
    let refused = worker
        .bind(1, 1, source.package_digest, frame)
        .expect("the package binds for its declarative parts");
    assert!(refused.is_empty(), "{refused:?}");
    for action in ["prompt.send", "approval.answer"] {
        assert!(
            worker
                .broker
                .registered_action(binding(1), &ActionName::new(action).expect("valid"))
                .expect("the binding is held")
                .is_some(),
            "{action} is registered"
        );
    }
    worker
        .rich_admission(1, 1)
        .expect("a declared action is admitted");
    let details = reported(&worker, source.package_digest);
    assert_eq!(details.len(), 1, "{details:?}");
    assert!(
        details[0].contains("beyond registering it for a binding and preparing an action"),
        "{}",
        details[0]
    );

    let worker = Worker::open();
    let source = worker.claude_code();
    let frame = worker.admit(1, vec![testing::admitted(&source)]);
    worker.register(1);
    worker
        .bind(1, 1, source.package_digest, frame)
        .expect("the package binds");
    assert!(reported(&worker, source.package_digest).is_empty());
}

/// KR-REQ-11.13: a package's declared actions that this host cannot register are refused by name
/// when it is bound, and the worker's report on its admissions names them against the package.
#[test]
fn kr_req_11_13_actions_a_package_declares_that_cannot_register_are_reported() {
    let worker = Worker::open();
    let source = declarative(worker.packages.path());
    // The same package declaring its action as text typed into the terminal, which the software
    // development kit's check accepts from a package that asks for `terminal.input` and this host
    // leaves to the input lease alone.
    let mut manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(source.package_dir.join(MANIFEST_FILE)).expect("reads"),
    )
    .expect("JSON");
    manifest["actions"][0]["effect"] = serde_json::json!("terminal.input");
    manifest["actions"][0]["implementation"] = serde_json::json!({
        "type": "terminal_text",
        "template": [
            { "type": "literal", "text": "status " },
            { "type": "parameter", "parameter": "detail" }
        ]
    });
    manifest["capabilities"]
        .as_array_mut()
        .expect("a list")
        .push(serde_json::json!({
            "capability": "terminal.input",
            "reason": "Type the status command"
        }));
    let written = serde_json::to_string_pretty(&manifest).expect("encodes");
    let digest = PayloadDigest::of(written.as_bytes());
    let directory = worker
        .packages
        .path()
        .join("packages")
        .join(digest.to_string());
    copy_tree(&source.package_dir, &directory);
    std::fs::write(directory.join(MANIFEST_FILE), written).expect("written");
    let refusing = ConnectorSource {
        package_digest: Digest256::from_bytes(*digest.as_bytes()),
        package_dir: directory,
        ..source
    };
    let frame = worker.admit(1, vec![testing::admitted(&refusing)]);
    worker.register(1);
    let refused = worker
        .bind(1, 1, refusing.package_digest, frame)
        .expect("the package binds");
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(
        refused[0].to_string().contains("status.refresh"),
        "{}",
        refused[0]
    );
    let report = worker
        .admissions
        .report(
            session(),
            worker.broker.live_bindings(),
            &worker.broker.action_refusals(),
        )
        .expect("a report");
    let named: Vec<_> = report
        .iter()
        .flat_map(|part| part.refusals.iter())
        .filter(|refusal| refusal.package_digest == refusing.package_digest)
        .collect();
    assert_eq!(named.len(), 1);
    assert!(
        named[0].detail.contains("status.refresh"),
        "{}",
        named[0].detail
    );
}
