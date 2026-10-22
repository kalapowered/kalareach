//! A qualification update reaches what is made after it and never changes what is live.
//!
//! Qualification data arrives as a signed record the control daemon folds into the next snapshot of
//! admissions it hands a worker. Section 11 says updating that data cannot turn an old live binding
//! into a different version, and section 29 says qualification updates are signed data and not an
//! excuse to hot-change live bindings. Each case hands a real worker's broker a first snapshot,
//! makes what a session makes of it (a binding for a running program, a table pinned for an
//! application's native connection), hands it a second snapshot that no longer names the build, and
//! reads what the live instance holds. The second snapshot is shown to have reached what is made
//! after it, so a case could not pass because the update changed nothing.

use kr_protocol::broker::IntegrationMode;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId, SessionId};
use kr_protocol::scalars::{Digest256, Uuid};
use kr_worker::broker::binder::MatchedExecutable;
use kr_worker::broker::catalogue::Admissions;
use kr_worker::broker::catalogue::testing;
use kr_worker::broker::connectors::{
    ConnectorSource, ConnectorSources, QualifiedExecutable, fixture,
};
use kr_worker::broker::{Broker, BrokerTransport, Credential, ManagedProcess, TransportHandle};
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

/// A worker's broker with the admissions and connector sources it applies snapshots to.
struct Worker {
    broker: Broker,
    admissions: Admissions,
    sources: ConnectorSources,
    packages: tempfile::TempDir,
}

impl Worker {
    fn open(store: Option<&std::path::Path>, health: std::sync::Arc<JournalHealth>) -> Self {
        Self {
            broker: Broker::open(store, session(), health).expect("the broker opens"),
            admissions: Admissions::new(),
            sources: ConnectorSources::new(),
            packages: tempfile::tempdir().expect("a directory on the internal disk"),
        }
    }

    fn package(
        &self,
        shape: &fixture::Shape,
        qualified: &[QualifiedExecutable],
    ) -> ConnectorSource {
        let mut source = fixture::package(
            self.packages.path(),
            std::path::Path::new(fixture::FORWARDER),
            shape,
        )
        .expect("the package is written");
        source.qualified = qualified.to_vec();
        source
    }

    /// Hands the worker a snapshot of `round` admitting `source` as it now stands.
    fn hand_over(&self, round: u64, source: &ConnectorSource) -> kr_protocol::admission::FrameId {
        testing::admit(
            &self.admissions,
            &self.sources,
            &self.broker,
            vec![testing::admitted(source)],
            round,
        )
    }
}

/// The program a live Claude Code binding is made for, at the build the first snapshot names.
fn claude() -> MatchedExecutable {
    MatchedExecutable {
        path: "/usr/local/bin/claude".to_owned(),
        digest: Digest256::from_bytes(fixture::QUALIFIED_DIGEST),
    }
}

fn claude_build() -> QualifiedExecutable {
    QualifiedExecutable {
        digest: Digest256::from_bytes(fixture::QUALIFIED_DIGEST),
        version: fixture::QUALIFIED_VERSION.to_owned(),
    }
}

/// KR-REQ-29.04: a snapshot that no longer names a live binding's build leaves the binding on the
/// program and version it was made for, in memory and in its row, and a binding made after it for
/// the same program has no version.
///
/// This is the withdrawal, which `kr_req_11_13_a_binding_keeps_the_executable_it_was_bound_with`
/// does not make: there a later record names another version, and here it names none.
#[test]
fn a_snapshot_that_no_longer_names_the_build_leaves_a_live_binding_as_it_was_made() {
    let store = common::SharedStore::open();
    let worker = Worker::open(Some(&store.path), store.health());
    let source = worker.package(&fixture::Shape::claude_code(), &[claude_build()]);
    let first = worker.hand_over(1, &source);
    for number in 2..=3 {
        worker
            .broker
            .register_instance(instance(number), IntegrationMode::NativeBridge, None, None)
            .expect("the instance is registered");
    }
    worker
        .broker
        .bind(
            binding(1),
            instance(2),
            source.package_digest,
            first,
            claude(),
            kr_ipc::now_ms(),
        )
        .expect("a binding for the build the record names");
    let live = |broker: &Broker, number: u8| {
        broker
            .binding_record(binding(number))
            .and_then(|record| record.executable)
            .map(|executable| (executable.path, executable.digest, executable.version))
    };
    let made = live(&worker.broker, 1);
    assert_eq!(
        made.as_ref().and_then(|bound| bound.2.as_deref()),
        Some(fixture::QUALIFIED_VERSION)
    );

    // The update withdraws the record: the next snapshot admits the same package, naming no build.
    let withdrawn = ConnectorSource {
        qualified: Vec::new(),
        ..source.clone()
    };
    let second = worker.hand_over(2, &withdrawn);

    // It reached what is made after it: the same program is bound again with no version.
    worker
        .broker
        .bind(
            binding(2),
            instance(3),
            withdrawn.package_digest,
            second,
            claude(),
            kr_ipc::now_ms(),
        )
        .expect("the package still recognises the program");
    assert_eq!(
        live(&worker.broker, 2).and_then(|bound| bound.2),
        None,
        "a binding made after the withdrawal has no version to take"
    );

    // And left alone what was live: the version in memory, and the row the ledger holds.
    assert_eq!(live(&worker.broker, 1), made, "the live binding is as made");
    let row = kr_worker::broker::Ledger::open(Some(&store.path), JournalHealth::shared())
        .expect("the ledger opens")
        .binding(binding(1))
        .expect("the ledger reads")
        .and_then(|row| row.executable)
        .map(|executable| (executable.path, executable.digest, executable.version));
    assert_eq!(row, made, "and so is its row");
}

/// The executable digest the Codex-shaped package's record names.
fn executable() -> Digest256 {
    Digest256::from_bytes([7; 32])
}

fn codex_build() -> QualifiedExecutable {
    QualifiedExecutable {
        digest: executable(),
        version: fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
    }
}

/// The process a managed application instance runs as, and the credential its launch presented.
fn managed(instance: ApplicationInstanceId) -> (ProcessStartIdentity, ManagedProcess) {
    let process = ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900);
    (
        process.clone(),
        ManagedProcess::new(
            instance,
            process.clone(),
            TransportHandle {
                transport: BrokerTransport::PrivateSocket,
                application_instance_id: instance,
                executable_digest: executable(),
                process,
            },
            Credential::from_bytes([9; 32]),
            kr_protocol::scalars::TimestampMs::new(1),
        ),
    )
}

/// KR-REQ-29.04: the tables pinned for a running application's native connection are those of the
/// record that stood when they were pinned. A snapshot that withdraws the record afterwards leaves
/// the live instance on them, and its connection opens again on them, while an application started
/// after the withdrawal gets no table.
#[test]
fn a_record_withdrawn_after_the_tables_were_pinned_leaves_the_live_instance_on_them() {
    let worker = Worker::open(None, JournalHealth::shared());
    let source = worker.package(&fixture::Shape::codex_backend(), &[codex_build()]);
    worker.hand_over(1, &source);
    let connector = worker
        .sources
        .for_command("codex")
        .expect("the admitted connector");

    let live = instance(2);
    let (process, launched) = managed(live);
    worker
        .broker
        .register_instance(live, IntegrationMode::Gateway, None, Some(launched))
        .expect("the live instance is registered");
    let tables = worker
        .broker
        .pin_compiled(live, &connector, &executable())
        .expect("the table the record qualifies is pinned");
    let pinned = worker
        .broker
        .pinned_table(live, &connector.plugin_id())
        .expect("the live instance holds its tables");

    // The update withdraws the record.
    let withdrawn = ConnectorSource {
        qualified: Vec::new(),
        ..source.clone()
    };
    worker.hand_over(2, &withdrawn);
    let after = worker
        .sources
        .for_command("codex")
        .expect("the connector is still admitted");

    // It reached what is made after it: nothing is pinned for an application started now.
    let (_, launched) = managed(instance(3));
    worker
        .broker
        .register_instance(instance(3), IntegrationMode::Gateway, None, Some(launched))
        .expect("the new instance is registered");
    worker
        .broker
        .pin_compiled(instance(3), &after, &executable())
        .expect_err("no record names the executable now, so nothing is pinned for it");

    // And left alone what was live: the tables, and a connection over them.
    assert_eq!(
        worker.broker.pinned_table(live, &connector.plugin_id()),
        Some(pinned),
        "the live instance keeps the tables it was pinned"
    );
    worker
        .broker
        .open_native_connection(
            live,
            &[9; 32],
            &process,
            &connector.plugin_id(),
            &tables.protocol_version,
        )
        .expect("a native connection still opens on the tables pinned before the update");
}
