//! Section 24 at the worker: the durability contract, the outbox, retention, the journal-fault
//! seam, local state and forward-only migration.
//!
//! Every test here names the row it closes. Where the contract is about the *store* the test
//! drives the journal directly, because that is where the durability order lives. Where it is
//! about what a caller is told, the test goes through the real endpoint, the real handshake and
//! the real signatures, because a rule that only holds when called directly is not a rule.
//!
//! The journal and every runtime path a test opens live on the internal disk, under the temporary
//! host this harness creates. Nothing here reaches the workspace, and nothing here touches the
//! operating system's credential store.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{ActionId, ActorId, BuildId, ControllerGeneration, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::ReceiptState;
use kr_protocol::recovery::HistoryGapCause;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, Durability, ShellMode};
use kr_worker::history::SpoolLayout;
use kr_worker::journal::{Journal, RETENTION_MS, Submission};
use kr_worker::persistence::contract::{CommitPoint, FlushPolicy, WriteKind, flush_policy};
use kr_worker::persistence::fault::{FaultKind, WorkClass};
use kr_worker::persistence::migration::{self, MigrationError};
use kr_worker::persistence::outbox::{Fanout, MAX_OUTBOX_PAGE, REMEMBERED_EVENT_IDS};
use kr_worker::persistence::retention::{OutputRetention, RetentionLimit};
use kr_worker::persistence::stores;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

mod common;

#[cfg(unix)]
use common::{LIVENESS_DEADLINE, carried_times, carries, produced, retained};

// ---------------------------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------------------------

struct Host {
    _temp: kr_ipc::testing::TempHost,
    #[cfg_attr(not(unix), allow(dead_code))]
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    journal_path: std::path::PathBuf,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Starts a worker whose journal already holds whatever `prepare` writes into it, running `script`.
async fn host_prepared(prepare: impl FnOnce(&std::path::Path), script: &str) -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    // The secret-store seam: the daemon's keys live in a file store under this temporary
    // environment's own secrets directory, so nothing test-driven reaches the operating system's
    // credential store.
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let journal_path = environment.journal_database(session_id);
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    prepare(&journal_path);
    let config = session_config(&environment, session_id, script);
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal_path.clone()),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        service,
        runtime,
        session_id,
        journal_path,
        endpoint,
        environment_id,
    }
}

async fn host() -> Host {
    host_prepared(|_| {}, "sleep 30").await
}

/// Starts a worker whose root program is `script`, for a test that watches what reaches it.
#[cfg(unix)]
async fn host_running(script: &str) -> Host {
    host_prepared(|_| {}, script).await
}

fn session_config(
    environment: &kr_ipc::paths::EnvironmentPaths,
    session_id: SessionId,
    script: &str,
) -> SessionConfig {
    SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: environment.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: root_shell(script),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        worker_endpoint: None,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
    }
}

/// Builds the command that runs one script as a session's root shell on this platform.
///
/// The scripts here are POSIX, so on Unix this is `/bin/sh`. On Windows it is PowerShell 7, the
/// shell this product launches there, with the platform's own working directory and search path
/// rather than a `/bin/sh` the platform has not got; a test whose script is POSIX-only says so and
/// runs on Unix alone.
#[cfg(unix)]
fn root_shell(script: &str) -> ShellCommand {
    kr_worker::testing::posix_script(script)
}

/// Builds the command that runs one script as a session's root shell on this platform.
#[cfg(windows)]
fn root_shell(script: &str) -> ShellCommand {
    kr_worker::testing::powershell_command(script)
}

async fn cli(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects")
}

fn target(host: &Host) -> ActionTarget {
    ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(host.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

async fn close(client: &mut LocalClient, host: &Host) -> kr_protocol::session::SessionCloseResult {
    let outcome = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            target(host),
            &kr_protocol::session::SessionCloseParams {
                session_id: host.session_id,
            },
        )
        .await
        .expect("the call reaches the worker");
    outcome
        .map(|value| value.to_typed().expect("decodes"))
        .unwrap_or_else(|error| panic!("the authorised stop was refused: {error}"))
}

fn actor() -> ActorId {
    ActorId::new("test:persistence").expect("an actor")
}

/// A submission under a distinct identifier, for a test that needs more than a byte's worth.
fn numbered_submission(index: u16) -> Submission {
    let mut identifier = [0_u8; 16];
    identifier[0] = (index >> 8) as u8;
    identifier[1] = index as u8;
    Submission {
        action_id: kr_worker::journal::action_id_from(identifier),
        ..submission(1, 1)
    }
}

fn attach_params(session_id: SessionId) -> kr_protocol::attachment::SessionAttachParams {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    // The native terminal exception is about raw input under the live lease, so the attachment
    // this suite uses asks for input as well as for output.
    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
    kr_protocol::attachment::SessionAttachParams {
        session_id,
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    }
}

fn submission(action: u8, digest: u8) -> Submission {
    Submission {
        actor_id: actor(),
        action_id: kr_worker::journal::action_id_from([action; 16]),
        method: Method::AgentApprovalRespond.into(),
        method_version: MethodVersion::V1,
        payload_digest: Digest256::from_bytes([digest; 32]),
        subject_digest: Digest256::from_bytes([digest; 32]),
        intent: vec![0xa0],
        accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
        now_ms: kr_ipc::now_ms(),
    }
}

/// Stops the journal growing and then fills the space it has left, so the next durable write is
/// refused by the store itself rather than by anything this test arranged.
///
/// It returns the refusal the store gave, so a caller can say what kind it was.
fn fill_the_store(journal: &mut Journal) -> kr_worker::WorkerError {
    journal.cap_at_current_size().expect("caps the store");
    let mut action = 100_u8;
    loop {
        match journal.accept(&submission(action, action)) {
            Ok(_) => {
                action = action
                    .checked_add(1)
                    .expect("the bounded store never filled");
            }
            Err(error) => return error,
        }
    }
}

/// A journal path on the internal disk, named so two tests never share one.
fn journal_path(name: &str) -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!("kr-persist-{name}-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("the journal directory");
    directory.join("journal.sqlite3")
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.02, 24.03: the commit order, and what never waits for a flush
// ---------------------------------------------------------------------------------------------

/// KR-REQ-02.04: a worker's receipt journal is a SQLite database in write-ahead mode with full
/// synchronisation.
#[test]
fn the_store_is_write_ahead_logged_with_full_synchronisation() {
    // KR-REQ-04.06: the receipt journal is an SQLite database, opened in-process.
    // KR-REQ-24.02. Section 24 permits WAL plus full durability and forbids weakening it to meet
    // a latency number, so the settings are asserted rather than assumed.
    let path = journal_path("pragmas");
    let journal = Journal::open(&path).expect("opens");
    let mode = journal.pragma_string("journal_mode").expect("the mode");
    assert_eq!(mode.to_lowercase(), "wal");
    let synchronous = journal.pragma_i64("synchronous").expect("the setting");
    assert_eq!(synchronous, 2, "2 is FULL");
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn the_intent_is_committed_before_the_caller_could_have_been_answered() {
    // KR-REQ-04.06: an action receipt is a row in that SQLite journal, which a second connection
    // reads back.
    // KR-REQ-24.02, first half: acceptance is *committed* before the acknowledgement returns. A
    // second connection to the same file sees the row while the accepting journal is still open,
    // which is true only of a committed transaction. What the store then does with a committed
    // transaction is the store's contract, and the settings test above is what holds it to it:
    // this test proves the commit point, not the fsync.
    let path = journal_path("accept-durable");
    let mut journal = Journal::open(&path).expect("opens");
    journal.accept(&submission(1, 1)).expect("accepts");
    let reader = Journal::open_read_only(&path).expect("opens read-only");
    let receipt = reader
        .read(actor(), kr_worker::journal::action_id_from([1; 16]))
        .expect("reads")
        .expect("the intent is already on disk");
    assert_eq!(receipt.state, ReceiptState::Accepted);
    drop(reader);
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn the_dispatch_marker_is_committed_before_the_effect_could_have_left() {
    // KR-REQ-24.02, second half: the marker is committed before dispatch, which is what makes a
    // lost outcome recoverable rather than repeatable. Committed, on the same evidence as above.
    let path = journal_path("marker-durable");
    let mut journal = Journal::open(&path).expect("opens");
    journal.accept(&submission(2, 2)).expect("accepts");
    journal
        .mark_dispatching(
            actor(),
            kr_worker::journal::action_id_from([2; 16]),
            TimestampMs::new(1_100),
        )
        .expect("marks");
    let reader = Journal::open_read_only(&path).expect("opens read-only");
    let receipt = reader
        .read(actor(), kr_worker::journal::action_id_from([2; 16]))
        .expect("reads")
        .expect("the marker is already on disk");
    assert_eq!(receipt.state, ReceiptState::Dispatching);
    drop(reader);
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[tokio::test]
async fn output_bytes_write_no_row_to_the_journal_at_all() {
    // KR-REQ-24.03, first half. The live parser is in worker memory and the retained output is a
    // bounded indexed spool, so a session producing output leaves the journal exactly as it found
    // it. What is counted is rows written on this connection, which is what "waits for an fsync"
    // reduces to here: a write that never happens never flushes. The spool's own files are a
    // separate store, declared `BestEffortFile`, and they are what output does reach.
    let host = host().await;
    let before = host
        .runtime
        .session()
        .journal()
        .expect("a journal")
        .total_changes();
    {
        let mut session = host.runtime.session();
        for _ in 0..64 {
            session.ingest_output(b"hello world\r\n");
        }
    }
    let after = host
        .runtime
        .session()
        .journal()
        .expect("a journal")
        .total_changes();
    assert_eq!(
        before, after,
        "output must not write a durable row, let alone flush one"
    );
}

#[test]
fn no_commit_point_shares_a_flush_and_the_writes_that_may_are_named() {
    // KR-REQ-24.03, second half, as a policy: grouped commits share a flush without moving the
    // dispatch boundary ahead of durability, which means a commit point is never grouped.
    for point in CommitPoint::ALL {
        assert_eq!(
            flush_policy(WriteKind::Commit(*point)),
            FlushPolicy::Immediate
        );
    }
    assert_eq!(flush_policy(WriteKind::Keystroke), FlushPolicy::NotDurable);
    assert_eq!(flush_policy(WriteKind::OutputByte), FlushPolicy::NotDurable);
    assert_eq!(
        flush_policy(WriteKind::PromptTelemetry),
        FlushPolicy::Grouped
    );
}

#[test]
fn a_transition_its_event_and_its_outbox_row_go_back_together_when_one_fails() {
    // KR-REQ-24.20's "same local transaction", proved by failure rather than by success: the
    // outbox insert is the last write of the transaction, and a store that refuses it leaves the
    // receipt where it was and the event unwritten. What that establishes is the transaction
    // boundary, which is what lets the three rows share one commit; it does not count flushes,
    // and the store's own settings are what the pragma test above holds it to.
    let path = journal_path("one-transaction");
    let mut journal = Journal::open(&path).expect("opens");
    journal.accept(&submission(4, 4)).expect("accepts");
    let before = journal
        .read(actor(), kr_worker::journal::action_id_from([4; 16]))
        .expect("reads")
        .expect("a receipt");
    let events_before = journal.events_after(0, 64).expect("reads").len();

    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch(
            "CREATE TRIGGER refuse_outbox BEFORE INSERT ON outbox
             BEGIN SELECT RAISE(ABORT, 'this store refused the outbox row'); END;",
        )
        .expect("the store will refuse the outbox row");
    let refused = journal.mark_dispatching(
        actor(),
        kr_worker::journal::action_id_from([4; 16]),
        TimestampMs::new(2_000),
    );
    assert!(refused.is_err(), "the transition could not be recorded");

    let after = journal
        .read(actor(), kr_worker::journal::action_id_from([4; 16]))
        .expect("reads")
        .expect("a receipt");
    assert_eq!(after.state, before.state, "the receipt went back with it");
    assert_eq!(after.revision, before.revision);
    assert_eq!(
        journal.events_after(0, 64).expect("reads").len(),
        events_before,
        "the event went back with it"
    );

    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch("DROP TRIGGER refuse_outbox;")
        .expect("the store will take it now");
    journal
        .mark_dispatching(
            actor(),
            kr_worker::journal::action_id_from([4; 16]),
            TimestampMs::new(2_100),
        )
        .expect("marks");
    assert_eq!(
        journal.events_after(0, 64).expect("reads").len(),
        events_before + 1
    );
    assert_eq!(journal.outbox_after(0, 64).expect("reads").len(), 2);
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.20, 24.21: the outbox, its fan-out, and what never reaches the control log
// ---------------------------------------------------------------------------------------------

#[test]
fn every_transition_leaves_one_outbox_row_in_this_journals_own_order() {
    // KR-REQ-24.20, first half, for the happy path: each transition leaves exactly one outbox
    // row, visible to a second connection the moment the transition is. That the two are one
    // transaction rather than two in a row is what the rollback test below establishes.
    let path = journal_path("outbox-transaction");
    let mut journal = Journal::open(&path).expect("opens");
    journal.accept(&submission(3, 3)).expect("accepts");
    let reader = Journal::open_read_only(&path).expect("opens read-only");
    let after_accept = reader.outbox_after(0, 64).expect("reads the outbox");
    assert_eq!(after_accept.len(), 1);
    assert_eq!(after_accept[0].event.detail, "accepted");
    assert_eq!(
        after_accept[0].event.actor_id.as_ref().map(ActorId::as_str),
        Some("test:persistence")
    );

    journal
        .mark_dispatching(
            actor(),
            kr_worker::journal::action_id_from([3; 16]),
            TimestampMs::new(1_100),
        )
        .expect("marks");
    journal
        .settle(
            actor(),
            kr_worker::journal::action_id_from([3; 16]),
            ReceiptState::Applied,
            Some(b"result"),
            None,
            TimestampMs::new(1_200),
        )
        .expect("settles");
    let records = reader.outbox_after(0, 64).expect("reads the outbox");
    let states: Vec<&str> = records
        .iter()
        .map(|record| record.event.detail.as_str())
        .collect();
    assert_eq!(states, vec!["accepted", "dispatching", "applied"]);
    // The cursor orders this journal's own events and nothing else.
    let cursors: Vec<u64> = records.iter().map(|record| record.cursor).collect();
    assert!(cursors.windows(2).all(|pair| pair[0] < pair[1]));
    drop(reader);
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn a_page_asked_for_again_before_its_cursor_is_recorded_is_applied_once() {
    // KR-REQ-24.20, second half: fan-out is at-least-once and idempotent. The durable half is the
    // consumer's cursor, which bounds what a redelivery replays; the in-process half is the
    // de-duplication window, which covers the interval between applying a record and recording
    // the cursor past it.
    let path = journal_path("outbox-fanout");
    let mut journal = Journal::open(&path).expect("opens");
    for action in 1..=3 {
        journal
            .accept(&submission(action, action))
            .expect("accepts");
    }
    let mut consumer = Fanout::new();
    let cursor = journal.outbox_cursor("attention").expect("a cursor");
    assert_eq!(cursor.cursor, 0);
    let page = journal.outbox_after(cursor.cursor, 64).expect("a page");
    // The consumer applies each record and says so, which is the order that matters: a record
    // remembered before its effect ran would be suppressed after that effect failed.
    let fresh: Vec<_> = consumer.fresh(&page).into_iter().cloned().collect();
    assert_eq!(fresh.len(), 3);
    for record in &fresh {
        consumer.note_applied(record);
    }
    // The cursor is not recorded here, so the same page is asked for again inside this process
    // and the window is what suppresses it. What this stages is the omission rather than a write
    // that failed: to the consumer they are the same thing, which is being handed a page it has
    // not recorded as taken.
    let again = journal.outbox_after(0, 64).expect("a page");
    assert!(consumer.fresh(&again).is_empty());
    assert_eq!(consumer.applied(), 3);
    assert_eq!(consumer.suppressed(), 3);

    let last = page.last().expect("a record").cursor;
    journal
        .note_outbox_consumed("attention", last, 3)
        .expect("records the cursor");
    let recorded = journal.outbox_cursor("attention").expect("a cursor");
    assert_eq!(recorded.cursor, last);
    assert_eq!(recorded.delivered, 3);
    assert!(
        journal
            .outbox_after(recorded.cursor, 64)
            .expect("a page")
            .is_empty()
    );

    // A consumer that restarted remembers nothing, and the recorded cursor is what stops it
    // replaying the journal: it is handed what it has not recorded as taken, and nothing before
    // it. A record applied but not recorded before the restart would be applied again, which is
    // the consumer's own to close rather than this journal's.
    let mut restarted = Fanout::new();
    let resumed = journal.outbox_after(recorded.cursor, 64).expect("a page");
    assert!(restarted.fresh(&resumed).is_empty());
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn a_page_of_the_outbox_never_outruns_the_window_that_covers_it() {
    // The de-duplication window is what makes a replayed page idempotent, so a page larger than
    // the window could displace an identifier the same page still needs. The journal bounds it.
    let path = journal_path("outbox-page-bound");
    let mut journal = Journal::open(&path).expect("opens");
    for index in 0..u16::try_from(MAX_OUTBOX_PAGE + 4).expect("fits") {
        journal
            .accept(&numbered_submission(index))
            .expect("accepts");
    }
    let page = journal.outbox_after(0, u64::MAX).expect("a page");
    assert_eq!(page.len() as u64, MAX_OUTBOX_PAGE);
    assert!(MAX_OUTBOX_PAGE as usize <= REMEMBERED_EVENT_IDS);
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn collecting_receipts_never_takes_an_event_a_consumer_still_owes() {
    // KR-REQ-24.20 again, and the failure it guards against: a receipt written thirty days ago
    // can have produced its outcome event this minute, and a consumer that has recorded no
    // cursor past it has never been offered it.
    let path = journal_path("outbox-collection");
    let mut journal = Journal::open(&path).expect("opens");
    journal.accept(&submission(1, 1)).expect("accepts");
    journal
        .note_outbox_consumed("attention", 0, 0)
        .expect("a consumer registers");
    // Long past the retention period, so the receipt itself is collectable.
    let later = TimestampMs::new(kr_ipc::now_ms().get() + RETENTION_MS + 60_000);
    journal.prune(later).expect("prunes");
    let owed = journal.outbox_after(0, 64).expect("a page");
    assert_eq!(owed.len(), 1, "the registered consumer is still owed it");

    // Once it has taken it, collection may have it.
    journal
        .note_outbox_consumed("attention", owed[0].cursor, 1)
        .expect("records the cursor");
    journal.prune(later).expect("prunes");
    assert!(journal.outbox_after(0, 64).expect("a page").is_empty());
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[tokio::test]
async fn no_terminal_body_and_no_provider_key_reaches_the_control_log() {
    // KR-REQ-24.21. The check is a search of the journal's own bytes after a session has produced
    // output carrying a recognisable provider key, and after the acceptance and dispatch commit
    // points have been driven: none of the terminal's body is in the durable control record. The
    // key and the command line are supplied as output rather than typed, because output is the
    // path section 24 names and the one this suite can drive without an application to type at.
    const SECRET: &str = "sk-provider-key-4d2f8a1b";
    const TYPED: &str = "export ANTHROPIC_API_KEY=sk-provider-key-4d2f8a1b";
    let host = host().await;
    {
        let mut session = host.runtime.session();
        session.ingest_output(TYPED.as_bytes());
        session.ingest_output(b"\r\n");
        // And a host event, which is the one thing an application can put into the journal: with
        // nothing holding the input lease, a notification becomes a durable record of its own.
        let effect = kr_term::sideeffect::SideEffect {
            kind: kr_term::sideeffect::SideEffectKind::Notification {
                title: Some("a notification title".to_owned()),
                body: "a notification body".to_owned(),
                id: None,
                urgency: kr_term::sideeffect::NotificationUrgency::Normal,
                display: kr_term::sideeffect::NotificationDisplay::Always,
            },
            destination: kr_term::sideeffect::SideEffectDestination::HostEvent,
            at: 0,
        };
        session
            .journal_mut()
            .expect("a journal")
            .record_host_event(&effect, TimestampMs::new(1_500))
            .expect("records the host event");
    }
    // The acceptance and dispatch commit points, so the search covers the mutation path as well
    // as the output one. The checkpoint moves the write-ahead log into the file, so what is
    // searched is everything this session has written rather than what has been merged.
    {
        let mut session = host.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        journal.accept(&submission(9, 9)).expect("accepts");
        journal
            .mark_dispatching(
                actor(),
                kr_worker::journal::action_id_from([9; 16]),
                TimestampMs::new(2_000),
            )
            .expect("marks");
        journal.checkpoint().expect("checkpoints the log");
    }
    let bytes = std::fs::read(&host.journal_path).expect("reads the journal");
    assert!(
        !contains(&bytes, SECRET.as_bytes()),
        "a provider key reached the durable control log"
    );
    assert!(
        !contains(&bytes, TYPED.as_bytes()),
        "a keystroke line reached the durable control log"
    );
    // What the journal does keep is the application's own notice, which section 25 retains and
    // which this store declares as exactly that rather than as metadata.
    assert!(contains(&bytes, b"a notification body"));
    assert_eq!(
        stores::store("host_events").expect("a declaration").content,
        stores::ContentClass::ApplicationNotice
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.22, 24.23: the per-store declaration, and a full store before dispatch
// ---------------------------------------------------------------------------------------------

#[test]
fn every_store_declares_its_durability_retention_cleanup_and_reconciliation() {
    // KR-REQ-24.22, first half. Every table the journal creates is declared, and every
    // declaration is one a reader can act on rather than a name.
    let path = journal_path("store-declarations");
    let journal = Journal::open(&path).expect("opens");
    let tables = journal.table_names().expect("reads the schema");
    for table in &tables {
        if table == "schema_version" || table.starts_with("sqlite_") {
            continue;
        }
        assert!(
            stores::store(table).is_some(),
            "{table} is a store with no declaration"
        );
    }
    for store in stores::STORES {
        assert!(!store.holds.is_empty(), "{} says nothing", store.name);
    }
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn authority_and_dispatch_data_is_never_evicted_under_a_history_cap() {
    // KR-REQ-24.22, second half, and KR-REQ-20.21's "history pressure cannot silently delete a
    // live dispatch barrier or deduplication record".
    for name in ["receipts", "outbox", "fence_evidence", "host_time"] {
        let store = stores::store(name).expect("a declaration");
        assert!(!store.evictable_under_history_cap);
    }
    let evictable: Vec<&str> = stores::evictable_under_history_cap()
        .map(|store| store.name)
        .collect();
    assert_eq!(
        evictable,
        vec!["host_events", "output spool", "resident history"]
    );
}

#[tokio::test]
async fn a_full_durable_store_refuses_a_new_mutation_before_anything_is_dispatched() {
    // KR-REQ-24.23. The store is made full for real, with the page bound SQLite enforces itself,
    // so what refuses the mutation is the store rather than a flag this test set.
    let host = host().await;
    {
        let mut session = host.runtime.session();
        let refusal = fill_the_store(session.journal_mut().expect("a journal"));
        assert!(refusal.to_string().contains("full"), "{refusal}");
    }
    let mut client = cli(&host).await;
    // A mutation that is not an authorised stop. A geometry resize is a write this worker serves
    // and it needs a durable receipt, so a full store refuses it before anything is dispatched.
    let outcome = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &attach_params(host.session_id),
        )
        .await
        .expect("the call reaches the worker");
    let failure = outcome.expect_err("a full store refuses the mutation");
    assert_eq!(failure.code, ErrorCode::StorageUnavailable);
    // And the seam says why, classified from the store's own result code.
    let condition = host.runtime.session().health().condition();
    assert_eq!(
        condition.fault().map(|fault| fault.kind),
        Some(FaultKind::Full)
    );
    assert!(
        !host
            .runtime
            .session()
            .durability_posture()
            .admits(WorkClass::RichMutation)
    );
}

/// KR-REQ-07.57: a full journal does not stop an authorised close, whose answer says its
/// durability is volatile.
#[tokio::test]
async fn a_full_store_still_admits_the_authorised_stop_and_says_its_durability_is_volatile() {
    // KR-REQ-24.23's exceptions, which are exactly two and are stated in sections 7 and 11 rather
    // than invented here. This is the section 7 one.
    let host = host().await;
    {
        let mut session = host.runtime.session();
        let refusal = fill_the_store(session.journal_mut().expect("a journal"));
        assert!(refusal.to_string().contains("full"), "{refusal}");
    }
    let mut client = cli(&host).await;
    let result = close(&mut client, &host).await;
    assert_eq!(result.durability, Durability::Volatile);
}

// ---------------------------------------------------------------------------------------------
// The journal-fault and recovery seam
// ---------------------------------------------------------------------------------------------

#[test]
fn a_fault_fences_rich_work_and_recovery_writes_the_interval_down_before_it_clears() {
    let path = journal_path("fault-and-recovery");
    let mut journal = Journal::open(&path).expect("opens");
    journal.accept(&submission(5, 5)).expect("accepts");
    assert!(journal.health().condition().is_healthy());

    let failure = fill_the_store(&mut journal);
    assert!(failure.to_string().contains("full"), "{failure}");
    let condition = journal.health().condition();
    let fault = condition.fault().expect("the seam holds the fault");
    assert_eq!(fault.kind, FaultKind::Full);
    assert!(
        fault.durable_through > 0,
        "the mark is the last sequence this host really wrote"
    );
    let posture = journal.health().posture();
    assert!(!posture.admits(WorkClass::RichMutation));
    assert!(posture.admits(WorkClass::AuthorisedStop));
    assert!(posture.admits(WorkClass::NativeTerminal));

    // The gap is committed before the condition is cleared. A store that refuses the gap is a
    // store this host may not call recovered, because the record would then read as continuous
    // over an interval it knows it did not write.
    journal.release_size_cap().expect("releases the cap");
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch(
            "CREATE TRIGGER refuse_gap BEFORE INSERT ON journal_gaps
             BEGIN SELECT RAISE(ABORT, 'this store refused the gap'); END;",
        )
        .expect("the store will refuse the gap");
    assert!(journal.recover(TimestampMs::new(9_000)).is_err());
    assert!(!journal.health().condition().is_healthy());
    assert!(journal.recovery_gaps().expect("reads the gaps").is_empty());

    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute_batch("DROP TRIGGER refuse_gap;")
        .expect("the store will take the gap now");
    let gap = journal
        .recover(TimestampMs::new(9_100))
        .expect("recovers")
        .expect("a fault was open");
    assert_eq!(gap.kind, FaultKind::Full);
    assert_eq!(gap.recovered_at_ms.get(), 9_100);
    assert!(journal.health().condition().is_healthy());
    let recorded = journal.recovery_gaps().expect("reads the gaps");
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].durable_through, gap.durable_through);
    // A second recovery has nothing to record.
    assert!(
        journal
            .recover(TimestampMs::new(9_200))
            .expect("recovers")
            .is_none()
    );
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn the_mark_a_gap_starts_from_survives_receipt_collection() {
    // Collection removes events. A mark taken from what the journal still holds would go
    // backwards every time it ran, and a gap would then claim an interval that reached back
    // before work this host had certainly written.
    let path = journal_path("mark-survives-collection");
    let mut journal = Journal::open(&path).expect("opens");
    for action in 1..=3 {
        journal
            .accept(&submission(action, action))
            .expect("accepts");
    }
    // A record of an earlier boot needs no window guard, which is what lets a live journal
    // collect it at all: retention keeps a record of *this* boot while a window could still admit
    // its action.
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute("UPDATE receipts SET created_boot = NULL", [])
        .expect("marks the records as an earlier boot's");
    let later = TimestampMs::new(kr_ipc::now_ms().get() + RETENTION_MS + 60_000);
    assert!(journal.prune(later).expect("prunes") > 0);
    assert_eq!(
        journal.event_high_water().expect("reads"),
        0,
        "collection took every event"
    );
    // Reopening over the collected store still starts the mark where the store got to.
    drop(journal);
    let mut journal = Journal::open(&path).expect("reopens");
    let failure = fill_the_store(&mut journal);
    assert!(failure.to_string().contains("full"), "{failure}");
    let condition = journal.health().condition();
    let fault = condition.fault().expect("a fault");
    assert!(
        fault.durable_through >= 3,
        "the mark is what the store allocated, not what it still holds: {}",
        fault.durable_through
    );
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn a_stored_value_this_build_cannot_read_leaves_the_store_faulted() {
    // Section 24: a lost or corrupt journal produces an explicit incomplete archive rather than
    // an invented success. A write that happens to succeed says nothing about a row this build
    // could not decode, and neither does a structural check: nothing here repairs such a row, so
    // the fault stays rather than being cleared over a reader that still cannot read it.
    let path = journal_path("corrupt-stays-faulted");
    let mut journal = Journal::open(&path).expect("opens");
    journal.accept(&submission(1, 1)).expect("accepts");
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute(
            "UPDATE outbox SET stream = 'a stream no build writes' WHERE cursor = 1",
            [],
        )
        .expect("writes an undecodable row");
    let refused = journal.outbox_after(0, 64);
    assert!(refused.is_err(), "the row cannot be decoded");
    assert_eq!(
        journal.health().condition().fault().map(|fault| fault.kind),
        Some(FaultKind::Corrupt)
    );

    // The store's pages are sound - what this build cannot read is a value rather than a page -
    // and recovery still refuses, because a sound page says nothing about an unreadable value.
    assert!(
        journal
            .recover(TimestampMs::new(7_000))
            .expect("recovery answers")
            .is_none(),
        "a value this build cannot read is not recovered from"
    );
    assert_eq!(
        journal.health().condition().fault().map(|fault| fault.kind),
        Some(FaultKind::Corrupt)
    );
    assert!(journal.recovery_gaps().expect("reads the gaps").is_empty());
    assert!(
        !journal.health().posture().admits(WorkClass::RichMutation),
        "rich work stays fenced while the store holds a value nothing can read"
    );
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn a_boundary_this_host_cannot_publish_stops_the_eviction_it_describes() {
    // A full disk can refuse the boundary write and still allow the deletions after it. A spool
    // that deleted its segments over an unpublished boundary would come back from a restart with
    // no record of where its output had reached, so nothing is deleted until it is published.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-unwritable-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 1 << 20))
            .expect("a spool");
    for _ in 0..4 {
        history.append(&[b'x'; 8]);
    }
    let retained = history.oldest_retained_cursor();
    // A directory whose boundary cannot be written: a directory of that name is in the way.
    std::fs::create_dir(directory.join("boundary")).expect("blocks the boundary file");
    let taken = history.apply_retention(
        OutputRetention::new(std::time::Duration::from_secs(7 * 24 * 60 * 60), 1 << 30, 0),
        32,
        kr_ipc::now_ms(),
        true,
    );
    assert!(
        taken.is_empty(),
        "nothing is deleted while the boundary is unpublished"
    );
    assert!(
        history
            .left_behind()
            .is_some_and(|why| why.contains("boundary")),
        "and the pass says why it removed nothing: {:?}",
        history.left_behind()
    );
    assert_eq!(history.oldest_retained_cursor(), retained);
    assert_eq!(
        history.page(0, 64).expect("a page").bytes.len(),
        28,
        "the retained output is still there"
    );
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_recovery_gap_survives_reopening_the_journal() {
    let path = journal_path("gap-survives");
    {
        let mut journal = Journal::open(&path).expect("opens");
        fill_the_store(&mut journal);
        journal.release_size_cap().expect("releases the cap");
        journal.recover(TimestampMs::new(5_000)).expect("recovers");
    }
    let journal = Journal::open(&path).expect("reopens");
    let gaps = journal.recovery_gaps().expect("reads the gaps");
    assert_eq!(gaps.len(), 1);
    assert_eq!(gaps[0].kind, FaultKind::Full);
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.30: forward-only migration, one current schema, an explicit importer
// ---------------------------------------------------------------------------------------------

#[test]
fn a_version_one_journal_is_refused_in_place_and_names_the_importer() {
    // KR-REQ-24.30. Version 1 is older than the ladder, so no host brings it forward on its own:
    // it is refused by name, with the command that imports it, rather than read in its old shape
    // or migrated behind the person's back.
    let path = journal_path("version-one-refused");
    write_version_one_fixture(&path);
    let error = Journal::open(&path).expect_err("a version 1 journal is not opened in place");
    assert!(
        error.to_string().contains(migration::IMPORTER),
        "the refusal names the importer: {error}"
    );
    assert!(migration::IMPORTER.contains("kr host import-journals"));
    assert_eq!(
        Journal::recorded_schema_version(&path).expect("reads the version"),
        1,
        "the refusal changed nothing"
    );
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn a_version_two_journal_is_brought_forward_in_place_and_keeps_its_rows() {
    // The control: version 2 is inside the ladder, so opening it brings it forward through every
    // later step, each one transaction, and keeps what it held.
    let path = journal_path("version-two-migrates");
    write_version_two_fixture(&path);
    let journal = Journal::open(&path).expect("migrates and opens");
    assert_eq!(
        journal.schema_version().expect("a version"),
        migration::CURRENT
    );
    let receipt = journal
        .read(actor(), kr_worker::journal::action_id_from([7; 16]))
        .expect("reads")
        .expect("the earlier build's receipt survived");
    assert_eq!(receipt.state, ReceiptState::Accepted);
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn the_importer_brings_a_version_one_journal_to_the_current_version_once() {
    // KR-REQ-24.30's explicit importer, for both shapes a build recording version 1 wrote: the
    // receipt table alone, and the receipt table with results and a closure. One import, one
    // transaction, the current version at the end, every row kept; a second run finds nothing to
    // import.
    use kr_worker::persistence::import::{Imported, import_journal};
    for with_results in [false, true] {
        let path = journal_path("version-one-imported");
        write_version_one_fixture(&path);
        if with_results {
            add_version_one_results_and_closure(&path);
        }
        // An error this build names is kept, and read back as this build reads it.
        rusqlite::Connection::open(&path)
            .expect("opens the fixture")
            .execute(
                "UPDATE receipts SET error_code = ?1, error_message = 'it was refused'",
                [ErrorCode::PermissionDenied.as_str()],
            )
            .expect("records an error");
        assert_eq!(
            import_journal(&path).expect("imports"),
            Imported::Imported {
                from: 1,
                to: migration::CURRENT,
                receipts: 1,
            }
        );
        let journal = Journal::open_existing(&path).expect("a current journal");
        assert_eq!(
            journal.schema_version().expect("a version"),
            migration::CURRENT
        );
        let mut tables = journal.table_names().expect("reads the schema");
        tables.retain(|name| !name.starts_with("sqlite_"));
        tables.sort();
        let mut current: Vec<String> = migration::tables_at(migration::CURRENT)
            .iter()
            .map(|name| (*name).to_owned())
            .collect();
        current.sort();
        assert_eq!(
            tables, current,
            "the imported journal is the current schema"
        );
        let receipt = journal
            .read(actor(), kr_worker::journal::action_id_from([7; 16]))
            .expect("reads")
            .expect("the receipt survived");
        assert_eq!(receipt.state, ReceiptState::Accepted);
        assert_eq!(
            receipt.error.as_ref().map(|error| error.code),
            Some(ErrorCode::PermissionDenied),
            "its error came with it"
        );
        if with_results {
            assert_eq!(
                journal
                    .read_result(&actor(), kr_worker::journal::action_id_from([7; 16]))
                    .expect("reads")
                    .as_deref(),
                Some([0xf6_u8].as_slice()),
                "the result survived"
            );
            assert!(
                journal
                    .read_closure(fixture_session())
                    .expect("reads")
                    .is_some(),
                "the closure survived"
            );
        }
        drop(journal);
        assert_eq!(
            import_journal(&path).expect("answers"),
            Imported::NothingToImport {
                version: migration::CURRENT
            },
            "an imported journal is never read in its old shape again"
        );
        std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
    }
}

#[test]
fn a_journal_the_importer_cannot_read_is_refused_by_name_and_left_as_it_was() {
    // "Refuses what it cannot read by name": a version it does not read, an object no version 1
    // build made, and a row the current build cannot decode are each named, and the file is left
    // exactly as it was, because the refusal comes before anything is committed.
    use kr_worker::persistence::import::import_journal;
    let refused = |name: &str, spoil: &dyn Fn(&rusqlite::Connection), named: &str| {
        let path = journal_path(name);
        write_version_one_fixture(&path);
        add_version_one_results_and_closure(&path);
        spoil(&rusqlite::Connection::open(&path).expect("opens the fixture"));
        let before = std::fs::read(&path).expect("reads the fixture");
        let error = import_journal(&path).expect_err("refused");
        assert!(
            error.to_string().contains(named),
            "the refusal names {named}: {error}"
        );
        assert_eq!(
            std::fs::read(&path).expect("reads the store again"),
            before,
            "a refused import leaves the file as it was"
        );
        std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
    };
    refused(
        "import-version-zero",
        &|connection| {
            connection
                .execute("UPDATE schema_version SET version = 0", [])
                .expect("records version 0");
        },
        "version 0",
    );
    refused(
        "import-unknown-table",
        &|connection| {
            connection
                .execute_batch("CREATE TABLE notes (body TEXT);")
                .expect("adds a table no build made");
        },
        "notes",
    );
    refused(
        "import-unreadable-closure",
        &|connection| {
            connection
                .execute("UPDATE closure SET record = x'ff00'", [])
                .expect("spoils the closure record");
        },
        "closure",
    );
    // Every field a receipt keeps is read as the running host reads it, the error included.
    refused(
        "import-unknown-error-code",
        &|connection| {
            connection
                .execute(
                    "UPDATE receipts SET error_code = 'NOT_A_CODE', error_message = 'it failed'",
                    [],
                )
                .expect("records an error no build names");
        },
        "error code",
    );
}

#[test]
fn an_import_that_fails_after_its_changes_leaves_the_journal_as_it_was() {
    // Every refusal above comes before the import changes anything. This one comes after all of
    // it - the columns added, the current objects made, the privacy record written, the version
    // set - and before the commit, and it goes back with the transaction: the file is the version 1
    // journal it was, byte for byte, and the next import brings it forward.
    use kr_worker::persistence::import::{
        Imported, import_journal, stop_the_next_import_before_its_commit,
    };
    for with_results in [false, true] {
        let path = journal_path("import-stopped");
        write_version_one_fixture(&path);
        if with_results {
            add_version_one_results_and_closure(&path);
        }
        let before = std::fs::read(&path).expect("reads the fixture");
        let statements = schema_statements(&path);
        stop_the_next_import_before_its_commit();
        import_journal(&path).expect_err("the import stops before its commit");
        assert_eq!(
            std::fs::read(&path).expect("reads the store again"),
            before,
            "the file is as it was"
        );
        assert_eq!(schema_statements(&path), statements);
        assert_eq!(
            Journal::recorded_schema_version(&path).expect("reads the version"),
            1
        );
        assert_eq!(
            import_journal(&path).expect("imports"),
            Imported::Imported {
                from: 1,
                to: migration::CURRENT,
                receipts: 1,
            }
        );
        std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
    }
}

/// Every object a store holds, with the statement that made it.
fn schema_statements(path: &std::path::Path) -> Vec<(String, String, Option<String>)> {
    let connection = rusqlite::Connection::open(path).expect("opens the store");
    let mut statement = connection
        .prepare("SELECT type, name, sql FROM sqlite_master ORDER BY type, name")
        .expect("reads the schema");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("reads the schema")
        .collect::<rusqlite::Result<_>>()
        .expect("reads the schema")
}

#[test]
fn a_journal_whose_statements_no_version_one_build_ran_is_refused_and_left_as_it_was() {
    // The two shapes are the statements two builds ran, and a table with a constraint neither
    // made, or an index on another column, is not one of them: the constraint would come forward
    // into the current schema and refuse actions the host takes. Each is refused naming the
    // object, before anything is changed.
    use kr_worker::persistence::import::import_journal;
    let unique = VERSION_ONE_RECEIPTS.replace(
        "PRIMARY KEY (actor_id, action_id)",
        "PRIMARY KEY (actor_id, action_id), UNIQUE (payload_digest)",
    );
    let checked = VERSION_ONE_RECEIPTS.replace(
        "revision             INTEGER NOT NULL,",
        "revision             INTEGER NOT NULL CHECK (revision >= 0),",
    );
    let elsewhere = VERSION_ONE_INDEX.replace("(created_at_ms)", "(updated_at_ms)");
    for (name, receipts, index, named) in [
        (
            "import-unique-digest",
            unique.as_str(),
            VERSION_ONE_INDEX,
            "receipts",
        ),
        (
            "import-checked-revision",
            checked.as_str(),
            VERSION_ONE_INDEX,
            "receipts",
        ),
        (
            "import-index-elsewhere",
            VERSION_ONE_RECEIPTS,
            elsewhere.as_str(),
            "receipts_created_at",
        ),
    ] {
        let path = journal_path(name);
        write_version_one_fixture_as(&path, receipts, index);
        let before = std::fs::read(&path).expect("reads the fixture");
        let error = import_journal(&path).expect_err("refused");
        assert!(
            error.to_string().contains(named),
            "{name}: the refusal names {named}: {error}"
        );
        assert_eq!(
            std::fs::read(&path).expect("reads the store again"),
            before,
            "{name}: a refused import leaves the file as it was"
        );
        std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
    }
}

/// The session the version 1 fixture's closure belongs to.
fn fixture_session() -> SessionId {
    SessionId::new(Uuid::from_bytes([9; 16]))
}

/// Adds what the second build recording version 1 made beside the receipts: a result for the
/// fixture's receipt and a closure record.
fn add_version_one_results_and_closure(path: &std::path::Path) {
    let closure = kr_protocol::session::ClosureRecord {
        session_id: fixture_session(),
        session_epoch: SessionEpoch::V1,
        reason: kr_protocol::session::ClosureReason::CloseRequested,
        root_exit_code: Nullable::null(),
        root_signal: Nullable::null(),
        terminated: Vec::new(),
        surviving: Vec::new(),
        ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
        durability: Durability::Durable,
        closed_at_ms: TimestampMs::new(2_000),
    };
    let connection = rusqlite::Connection::open(path).expect("opens the fixture");
    connection
        .execute_batch(
            "CREATE TABLE results (
                 actor_id  TEXT NOT NULL,
                 action_id BLOB NOT NULL,
                 result    BLOB NOT NULL,
                 PRIMARY KEY (actor_id, action_id)
             );
             CREATE TABLE closure (
                 session_id BLOB PRIMARY KEY,
                 record     BLOB NOT NULL
             );",
        )
        .expect("the second version 1 shape");
    connection
        .execute(
            "INSERT INTO results (actor_id, action_id, result) VALUES (?1, ?2, x'f6')",
            rusqlite::params![
                "test:persistence",
                Uuid::from_bytes([7; 16]).as_bytes().as_slice()
            ],
        )
        .expect("the earlier build's result");
    connection
        .execute(
            "INSERT INTO closure (session_id, record) VALUES (?1, ?2)",
            rusqlite::params![
                fixture_session().get().as_bytes().as_slice(),
                kr_cbor::to_canonical_vec(&closure).expect("encodes the closure"),
            ],
        )
        .expect("the earlier build's closure");
}

/// Writes the journal the first build recording version 2 wrote, with one receipt.
fn write_version_two_fixture(path: &std::path::Path) {
    let connection = rusqlite::Connection::open(path).expect("creates the fixture");
    connection
        .execute_batch(
            "CREATE TABLE schema_version (version INTEGER NOT NULL);
             CREATE TABLE receipts (
                 actor_id             TEXT    NOT NULL,
                 action_id            BLOB    NOT NULL,
                 method               TEXT    NOT NULL,
                 method_version       INTEGER NOT NULL,
                 revision             INTEGER NOT NULL,
                 state                TEXT    NOT NULL,
                 reason               TEXT,
                 payload_digest       BLOB    NOT NULL,
                 intent               BLOB    NOT NULL,
                 accepted_deadline_ms INTEGER,
                 error_code           TEXT,
                 error_message        TEXT,
                 created_at_ms        INTEGER NOT NULL,
                 updated_at_ms        INTEGER NOT NULL,
                 PRIMARY KEY (actor_id, action_id)
             );
             CREATE INDEX receipts_created_at ON receipts (created_at_ms);
             CREATE TABLE results (
                 actor_id  TEXT NOT NULL,
                 action_id BLOB NOT NULL,
                 result    BLOB NOT NULL,
                 PRIMARY KEY (actor_id, action_id),
                 FOREIGN KEY (actor_id, action_id)
                     REFERENCES receipts (actor_id, action_id) ON DELETE CASCADE
             );
             CREATE TABLE receipt_events (
                 sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                 actor_id       TEXT    NOT NULL,
                 action_id      BLOB    NOT NULL,
                 revision       INTEGER NOT NULL,
                 state          TEXT    NOT NULL,
                 recorded_at_ms INTEGER NOT NULL,
                 FOREIGN KEY (actor_id, action_id)
                     REFERENCES receipts (actor_id, action_id) ON DELETE CASCADE
             );
             CREATE TABLE closure (
                 session_id BLOB PRIMARY KEY,
                 record     BLOB NOT NULL
             );
             INSERT INTO schema_version (version) VALUES (2);",
        )
        .expect("the version 2 schema");
    connection
        .execute(
            "INSERT INTO receipts (
                 actor_id, action_id, method, method_version, revision, state,
                 payload_digest, intent, accepted_deadline_ms, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, 1, 1, 'accepted', ?4, x'a0', 10000, 1000, 1000)",
            rusqlite::params![
                "test:persistence",
                Uuid::from_bytes([7; 16]).as_bytes().as_slice(),
                Method::SessionClose.as_str(),
                [7_u8; 32].as_slice(),
            ],
        )
        .expect("the earlier build's receipt");
}

#[test]
fn a_database_a_newer_build_wrote_is_refused_rather_than_read() {
    let path = journal_path("migration-future");
    write_version_one_fixture(&path);
    let connection = rusqlite::Connection::open(&path).expect("opens");
    connection
        .execute(
            "UPDATE schema_version SET version = ?1",
            rusqlite::params![migration::CURRENT + 1],
        )
        .expect("records a newer version");
    drop(connection);
    let error = Journal::open(&path).expect_err("a newer store is refused");
    assert!(error.to_string().contains("newer store is not read"));
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn a_store_that_has_lost_any_table_of_its_own_version_is_refused_rather_than_refilled() {
    // KR-REQ-24.30 and the incomplete archive of 24.21. Migration creates what is absent, so a
    // store that lost a table would come back with an empty one and the loss would never be
    // reported. Every table the current schema holds is checked, one at a time, because the one
    // that is missed is the one whose loss goes unseen: a lost `results` or `receipt_events`
    // loses outcomes and event history exactly as a lost `receipts` loses receipts.
    let path = journal_path("lost-table");
    {
        let journal = Journal::open(&path).expect("a current store");
        drop(journal);
    }
    let all = migration::tables_at(migration::CURRENT);
    assert!(
        all.contains(&"results") && all.contains(&"receipt_events") && all.contains(&"closure"),
        "the current version's list is the whole schema: {all:?}"
    );
    let original = std::fs::read(&path).expect("reads the store");
    for table in all {
        if *table == "schema_version" {
            // Its loss is a store with no version at all, which the version probe reports.
            continue;
        }
        std::fs::write(&path, &original).expect("puts the store back");
        let connection = rusqlite::Connection::open(&path).expect("opens");
        connection
            .execute_batch(&format!("DROP TABLE {table};"))
            .expect("drops one table");
        drop(connection);
        let error = Journal::open_existing(&path)
            .expect_err("a store missing one of its own tables is not opened");
        assert!(
            error.to_string().contains(table),
            "the refusal names what is lost: {error}"
        );
        let connection = rusqlite::Connection::open(&path).expect("reopens");
        let present: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                rusqlite::params![table],
                |row| row.get(0),
            )
            .expect("reads the schema");
        assert_eq!(present, 0, "{table} was not recreated empty");
    }
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
}

#[test]
fn a_database_older_than_the_ladder_names_the_importer_rather_than_restoring_in_part() {
    for older in [0, 1] {
        let error = migration::plan(older).expect_err("older than the ladder");
        assert_eq!(
            error,
            MigrationError::Unsupported {
                found: older,
                oldest: migration::OLDEST_MIGRATABLE,
                importer: migration::IMPORTER,
            }
        );
    }
    assert_eq!(migration::OLDEST_MIGRATABLE, 2);
}

#[test]
fn every_migration_path_ends_at_the_one_version_this_build_reads() {
    // KR-REQ-24.30's "code reads one current schema after migration". The ladder is contiguous
    // and every step ends at the one version `Journal::open` will then read, which is what leaves
    // no older shape for a second reader to be written against.
    assert_eq!(kr_worker::journal::SCHEMA_VERSION, migration::CURRENT);
    let steps = migration::plan(migration::OLDEST_MIGRATABLE).expect("a plan");
    assert_eq!(steps.last().expect("a last step").to, migration::CURRENT);
    assert!(
        migration::plan(migration::CURRENT)
            .expect("a plan")
            .is_empty()
    );
}

/// Writes the journal the first build of this schema wrote: version 1, with one receipt.
///
/// The shape is `927ecc84`'s exactly - the receipt table and its one index, and nothing else -
/// because a fixture that already had the later tables would not exercise what the ladder does.
fn write_version_one_fixture(path: &std::path::Path) {
    write_version_one_fixture_as(path, VERSION_ONE_RECEIPTS, VERSION_ONE_INDEX);
}

/// The receipt table the builds recording version 1 made, as their statement spelled it.
const VERSION_ONE_RECEIPTS: &str = "CREATE TABLE IF NOT EXISTS receipts (
                 actor_id             TEXT    NOT NULL,
                 action_id            BLOB    NOT NULL,
                 method               TEXT    NOT NULL,
                 method_version       INTEGER NOT NULL,
                 revision             INTEGER NOT NULL,
                 state                TEXT    NOT NULL,
                 reason               TEXT,
                 payload_digest       BLOB    NOT NULL,
                 accepted_deadline_ms INTEGER,
                 error_code           TEXT,
                 error_message        TEXT,
                 created_at_ms        INTEGER NOT NULL,
                 updated_at_ms        INTEGER NOT NULL,
                 PRIMARY KEY (actor_id, action_id)
             );";

/// The receipt index the builds recording version 1 made.
const VERSION_ONE_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS receipts_created_at ON receipts (created_at_ms);";

/// Writes the version 1 fixture with the receipt table and index given, and one receipt.
fn write_version_one_fixture_as(path: &std::path::Path, receipts: &str, index: &str) {
    let connection = rusqlite::Connection::open(path).expect("creates the fixture");
    connection
        .execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
             {receipts}
             {index}
             INSERT INTO schema_version (version) VALUES (1);"
        ))
        .expect("the version 1 schema");
    connection
        .execute(
            "INSERT INTO receipts (
                 actor_id, action_id, method, method_version, revision, state,
                 payload_digest, accepted_deadline_ms, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, 1, 1, 'accepted', ?4, 10000, 1000, 1000)",
            rusqlite::params![
                "test:persistence",
                Uuid::from_bytes([7; 16]).as_bytes().as_slice(),
                Method::SessionClose.as_str(),
                [7_u8; 32].as_slice(),
            ],
        )
        .expect("the earlier build's receipt");
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.20, 20.21: seven days, the two caps, and the gap cursors eviction leaves
// ---------------------------------------------------------------------------------------------

#[test]
fn the_retention_figures_are_the_ones_section_twenty_states() {
    // KR-REQ-20.20.
    let retention = OutputRetention::DEFAULT;
    assert_eq!(retention.max_age.as_secs(), 7 * 24 * 60 * 60);
    assert_eq!(retention.host_cap_bytes, 1024 * 1024 * 1024);
    assert_eq!(retention.session_cap_bytes, 128 * 1024 * 1024);
    // KR-REQ-20.21's separate budget: receipts are a period, not a byte cap.
    assert_eq!(RETENTION_MS, 30 * 24 * 60 * 60 * 1000);
    assert_eq!(stores::RECEIPT_RETENTION.as_millis() as u64, RETENTION_MS);
}

#[test]
fn the_stores_kept_for_a_period_name_the_archive_as_their_collector_once_the_session_closes() {
    // KR-REQ-20.21. A closed session has no maintenance tick of its own, so what it keeps for a
    // period - its output for seven days, its receipts and what goes with them for thirty - is
    // collected by the archive once it has closed, and each declaration says so.
    for name in [
        "receipts",
        "results",
        "receipt_events",
        "outbox",
        "observations",
        "output spool",
    ] {
        let store = stores::store(name).expect("a declaration");
        assert_eq!(store.cleanup, stores::Cleanup::WorkerThenArchive, "{name}");
    }
}

#[tokio::test]
async fn a_live_session_applies_output_retention_and_leaves_a_gap_a_reader_is_told_about() {
    // KR-REQ-20.20 and 20.21 through the session, rather than through the history alone: the
    // maintenance path is what a running host uses, and the gap it leaves carries the bound.
    let host = host().await;
    let evicted = {
        let mut session = host.runtime.session();
        for _ in 0..32 {
            session.ingest_output(&[b'x'; 8192]);
        }
        let before = session.retained_output_bytes();
        assert!(before > 0);
        // A session cap this session is already over, with the host figure taken from the spool.
        session.apply_output_retention(
            OutputRetention::new(
                std::time::Duration::from_secs(7 * 24 * 60 * 60),
                1024 * 1024 * 1024,
                1024,
            ),
            before,
            kr_ipc::now_ms(),
            true,
        )
    };
    assert!(!evicted.is_empty(), "the session cap took something");
    assert_eq!(evicted[0].limit, RetentionLimit::SessionCap);
    let session = host.runtime.session();
    assert_eq!(
        session.history_gap_cause(0),
        Some(HistoryGapCause::SessionCapacity)
    );
    let page = session.history_page(0, 4096).expect("a page");
    let gap = page.gap.0.expect("the evicted range is reported");
    assert_eq!(gap.from_cursor.get(), 0);
    assert!(gap.to_cursor.get() > 0);
}

#[test]
fn a_spool_that_retention_emptied_still_says_where_its_output_got_to() {
    // KR-REQ-20.21. An eviction that took every segment leaves a directory with no segments in
    // it, and a session reopened over that must not start its cursor again at nought: a client
    // asking for what it missed would be served the new output as though it were the old, and
    // the archive would have nothing to report a gap from.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-boundary-{}", kr_ipc::new_uuid()));
    // A cap of nothing, so the pass takes every segment and the directory is left empty.
    let retention = OutputRetention::new(std::time::Duration::from_secs(1), 1024 * 1024, 0);
    let before = {
        let mut history =
            kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 4096))
                .expect("a spool");
        for _ in 0..4 {
            history.append(&[b'x'; 8]);
        }
        let taken = history.apply_retention(retention, 32, kr_ipc::now_ms(), true);
        assert!(!taken.is_empty());
        history.next_cursor()
    };
    assert_eq!(before, 32);
    // The session restarts over the emptied directory.
    let reopened =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 4096))
            .expect("reopens the spool");
    assert_eq!(
        reopened.next_cursor(),
        before,
        "the cursor continues rather than starting again"
    );
    assert_eq!(reopened.oldest_retained_cursor(), before);
    let page = reopened.page(0, 64).expect("a page");
    let gap = page.gap.0.expect("everything before the boundary is a gap");
    assert_eq!(gap.from_cursor.get(), 0);
    assert_eq!(gap.to_cursor.get(), before);
    std::fs::remove_dir_all(&directory).ok();
}

/// The file one spool segment is kept in, named by the cursor it starts at.
fn segment_file(directory: &std::path::Path, start: u64) -> std::path::PathBuf {
    directory.join(format!("{start:020}.out"))
}

/// Writes four eight-byte segments, `a` to `d`, covering cursors 0 to 32.
fn four_segments(directory: &std::path::Path) -> kr_worker::history::OutputHistory {
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, directory, SpoolLayout::new(8, 1 << 20))
            .expect("a spool");
    for byte in *b"abcd" {
        history.append(&[byte; 8]);
    }
    history
}

#[test]
fn a_missing_middle_segment_reads_as_a_gap_and_the_page_goes_on_to_the_next() {
    // KR-REQ-24.19 and 20.21. A segment inside the retained range that has gone is a range this
    // host cannot account for. A reader asking for it is told so, with a cause, and is given what
    // comes after it, rather than an empty page at the same cursor that it would ask for again.
    let directory = std::env::temp_dir().join(format!("kr-persist-hole-{}", kr_ipc::new_uuid()));
    drop(four_segments(&directory));
    std::fs::remove_file(segment_file(&directory, 8)).expect("removes the middle segment");

    let reopened = kr_worker::history::OutputHistory::read_spool(&directory, SpoolLayout::DEFAULT)
        .expect("reads what is left");
    // A page that starts before the hole stops at it.
    let before = reopened.page(0, 64).expect("a page");
    assert_eq!(before.bytes.as_slice(), &[b'a'; 8]);
    assert_eq!(before.next_cursor.get(), 8);
    assert!(!before.gap.is_present());
    // A page at the hole reports it and goes on to the next segment this host holds.
    let at = reopened.page(8, 64).expect("a page");
    let gap = at
        .gap
        .0
        .unwrap_or_else(|| panic!("the missing range is a gap: {at:?}"));
    assert_eq!((gap.from_cursor.get(), gap.to_cursor.get()), (8, 16));
    assert_eq!(gap.cause, Some(HistoryGapCause::ArchiveIncomplete));
    assert_eq!(at.from_cursor.get(), 16);
    assert_eq!(
        at.bytes.as_slice(),
        [[b'c'; 8], [b'd'; 8]].concat().as_slice()
    );
    assert_eq!(at.next_cursor.get(), 32);
    // What this host retains is what it holds, not the distance from the oldest cursor.
    assert_eq!(reopened.retained_bytes(), 24);
    assert_eq!(reopened.holes(), vec![(8, 16)]);
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_segment_that_goes_under_an_open_index_reads_as_a_gap_rather_than_an_error() {
    // The same hole, made while the session still has its spool open: the index names the
    // segment, and the file behind it has gone.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-hole-open-{}", kr_ipc::new_uuid()));
    let mut history = four_segments(&directory);
    std::fs::remove_file(segment_file(&directory, 8)).expect("removes the middle segment");
    let at = history.page(8, 64).expect("a page rather than an error");
    let gap = at
        .gap
        .0
        .unwrap_or_else(|| panic!("the missing range is a gap: {at:?}"));
    assert_eq!((gap.from_cursor.get(), gap.to_cursor.get()), (8, 16));
    assert_eq!(gap.cause, Some(HistoryGapCause::ArchiveIncomplete));
    assert_eq!(at.from_cursor.get(), 16);
    assert_eq!(&at.bytes.as_slice()[..8], &[b'c'; 8]);
    // The next retention pass forgets the segment, so the session is no longer counted as holding
    // it and the account names the range.
    assert_eq!(history.retained_bytes(), 32, "the index still names it");
    let taken = history.apply_retention(OutputRetention::DEFAULT, 32, kr_ipc::now_ms(), true);
    assert!(taken.is_empty(), "nothing was over any bound");
    assert_eq!(history.retained_bytes(), 24);
    assert_eq!(history.holes(), vec![(8, 16)]);
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_missing_newest_segment_reads_as_a_gap_up_to_the_recorded_boundary() {
    // A hole at the end is visible only against the boundary the spool recorded, which an
    // eviction writes before it deletes anything.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-hole-end-{}", kr_ipc::new_uuid()));
    {
        let mut history = four_segments(&directory);
        let taken = history.apply_retention(
            OutputRetention::new(
                std::time::Duration::from_secs(7 * 24 * 60 * 60),
                1 << 30,
                24,
            ),
            32,
            kr_ipc::now_ms(),
            true,
        );
        assert_eq!(
            taken.len(),
            1,
            "the oldest segment went and the boundary was written"
        );
    }
    std::fs::remove_file(segment_file(&directory, 24)).expect("removes the newest segment");
    let reopened = kr_worker::history::OutputHistory::read_spool(&directory, SpoolLayout::DEFAULT)
        .expect("reads what is left");
    assert_eq!(
        reopened.next_cursor(),
        32,
        "the boundary says where the output reached"
    );
    let page = reopened.page(24, 64).expect("a page");
    let gap = page
        .gap
        .0
        .unwrap_or_else(|| panic!("the missing range is a gap: {page:?}"));
    assert_eq!((gap.from_cursor.get(), gap.to_cursor.get()), (24, 32));
    assert!(page.bytes.is_empty());
    assert_eq!(page.next_cursor.get(), 32);
    assert_eq!(reopened.holes(), vec![(24, 32)]);
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_contiguous_spool_pages_from_end_to_end_with_no_gap() {
    // The control for the three above: nothing is missing, so nothing is reported missing.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-contiguous-{}", kr_ipc::new_uuid()));
    drop(four_segments(&directory));
    let reopened = kr_worker::history::OutputHistory::read_spool(&directory, SpoolLayout::DEFAULT)
        .expect("reads the spool");
    let mut cursor = 0;
    let mut read = Vec::new();
    while cursor < reopened.next_cursor() {
        let page = reopened.page(cursor, 12).expect("a page");
        assert!(!page.gap.is_present(), "no gap at {cursor}");
        assert_eq!(page.from_cursor.get(), cursor);
        read.extend_from_slice(page.bytes.as_slice());
        cursor = page.next_cursor.get();
    }
    assert_eq!(read.len(), 32);
    assert_eq!(reopened.retained_bytes(), 32);
    assert!(reopened.holes().is_empty());
    std::fs::remove_dir_all(&directory).ok();
}

/// What the spool's segment files hold on the disk, counted from the directory itself.
fn segment_bytes_on_disk(directory: &std::path::Path) -> u64 {
    // Each size is read through the file, not from `DirEntry::metadata`: NTFS keeps a size in the
    // directory entry that it does not bring up to date while the spool holds the file open.
    std::fs::read_dir(directory)
        .expect("reads the spool")
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "out"))
        .filter_map(|entry| std::fs::metadata(entry.path()).ok())
        .filter(std::fs::Metadata::is_file)
        .map(|metadata| metadata.len())
        .sum()
}

/// Pages a history from `from` to its end, and returns the first gap it is told about and every
/// byte it is given. A page stops where the resident window starts, so a whole read takes more
/// than one.
fn read_to_end(
    history: &kr_worker::history::OutputHistory,
    from: u64,
) -> (Option<kr_protocol::recovery::HistoryGap>, Vec<u8>) {
    let mut cursor = from;
    let mut first_gap = None;
    let mut bytes = Vec::new();
    for _ in 0..64 {
        let page = history.page(cursor, 64).expect("a page");
        if first_gap.is_none() {
            first_gap = page.gap.0;
        }
        bytes.extend_from_slice(page.bytes.as_slice());
        if page.next_cursor.get() >= history.next_cursor() {
            return (first_gap, bytes);
        }
        cursor = page.next_cursor.get();
    }
    panic!("paging from {from} never reached the end");
}

#[test]
fn an_append_larger_than_the_room_left_makes_room_first_and_names_the_session_cap() {
    // KR-REQ-20.20, the session cap held before the write. An append that would take the session
    // past its cap gives up the oldest output first, so no append stands over the bound, and the
    // range it gave up is a gap that names the bound that took it.
    let directory = std::env::temp_dir().join(format!("kr-persist-cap-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 32))
            .expect("a spool");
    history.append(&[b'a'; 24]);
    // Eight bytes of room are left, and one append asks for sixteen.
    history.append(&[b'b'; 16]);
    assert_eq!(
        history.retained_bytes(),
        32,
        "at the cap rather than over it"
    );
    assert!(
        history.spool_peak_bytes() <= 32,
        "the room was made before the write, not after it: {}",
        history.spool_peak_bytes()
    );
    assert!(segment_bytes_on_disk(&directory) <= 32);
    assert_eq!(history.oldest_retained_cursor(), 8);
    let (gap, bytes) = read_to_end(&history, 0);
    let gap = gap.expect("the range the append made room with is a gap");
    assert_eq!((gap.from_cursor.get(), gap.to_cursor.get()), (0, 8));
    assert_eq!(
        gap.cause,
        Some(HistoryGapCause::SessionCapacity),
        "the reader is told which bound took it"
    );
    assert_eq!(bytes, [[b'a'; 16], [b'b'; 16]].concat());

    // One append larger than the whole cap keeps its newest bytes, and never more than the cap.
    // Room is made a segment at a time, so what is kept is within one segment of the cap.
    history.append(&[b'c'; 100]);
    let retained = history.retained_bytes();
    assert!(retained <= 32 && retained > 32 - 8, "{retained}");
    assert!(
        history.spool_peak_bytes() <= 32,
        "no piece of it was written before its room was made: {}",
        history.spool_peak_bytes()
    );
    assert!(segment_bytes_on_disk(&directory) <= 32);
    assert_eq!(history.oldest_retained_cursor(), 140 - retained);
    let (gap, bytes) = read_to_end(&history, 0);
    assert_eq!(
        gap.and_then(|gap| gap.cause),
        Some(HistoryGapCause::SessionCapacity)
    );
    assert_eq!(bytes, vec![b'c'; usize::try_from(retained).expect("small")]);
    assert!(history.suspended().is_none(), "nothing stopped the spool");
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn appends_under_the_session_cap_keep_everything_and_leave_no_gap() {
    // The control for the test above: with room to spare nothing is given up.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-under-cap-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 64))
            .expect("a spool");
    history.append(&[b'a'; 24]);
    history.append(&[b'b'; 16]);
    assert_eq!(history.retained_bytes(), 40);
    assert_eq!(segment_bytes_on_disk(&directory), 40);
    let (gap, bytes) = read_to_end(&history, 0);
    assert!(gap.is_none());
    assert_eq!(
        bytes,
        [[b'a'; 24].as_slice(), [b'b'; 16].as_slice()].concat()
    );
    assert!(history.evictions().is_empty());
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_segment_that_cannot_be_removed_stops_the_spool_rather_than_standing_over_the_cap() {
    // KR-REQ-20.20. Making room can fail: the oldest segment is there and cannot be removed. The
    // write that needed the room is not made, so the cap still holds; the segment that did not go
    // is still counted, still served and still tried by every later pass; and a reader past the
    // point the spool stopped is told why.
    let directory = std::env::temp_dir().join(format!("kr-persist-stuck-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 32))
            .expect("a spool");
    history.append(&[b'a'; 24]);
    // A directory stands where the oldest segment's file was, so no platform removes it as one.
    let oldest = segment_file(&directory, 0);
    std::fs::remove_file(&oldest).expect("removes the oldest segment's file");
    std::fs::create_dir(&oldest).expect("puts a directory in its place");
    std::fs::write(oldest.join("in-the-way"), b"x").expect("and something in it");

    history.append(&[b'b'; 16]);
    assert_eq!(
        history.retained_bytes(),
        32,
        "nothing was written past the cap, and the segment that could not go is still counted"
    );
    let (stopped_at, why) = history
        .suspended()
        .expect("the spool stopped taking output");
    assert_eq!(stopped_at, 32);
    assert!(why.contains("could not be removed"), "{why}");
    // What the spool still holds is still served.
    let held = history.page(8, 64).expect("a page");
    assert!(!held.gap.is_present());
    assert_eq!(
        held.bytes.as_slice(),
        [&[b'a'; 16][..], &[b'b'; 8][..]].concat().as_slice()
    );
    // A reader past the point the spool stopped is told why the range is not there.
    let past = history.page(32, 64).expect("a page");
    let gap = past
        .gap
        .0
        .unwrap_or_else(|| panic!("the range past the stop is a gap: {past:?}"));
    assert_eq!(gap.from_cursor.get(), 32);
    assert_eq!(gap.cause, Some(HistoryGapCause::SpoolUnavailable));

    // The next pass tries again and says what it could not remove.
    let over = OutputRetention::new(
        std::time::Duration::from_secs(7 * 24 * 60 * 60),
        1 << 30,
        24,
    );
    assert!(
        history
            .apply_retention(over, 32, kr_ipc::now_ms(), true)
            .is_empty()
    );
    assert!(
        history
            .left_behind()
            .is_some_and(|why| why.contains("could not be removed")),
        "{:?}",
        history.left_behind()
    );
    assert_eq!(
        history.suspended().map(|(at, _)| at),
        Some(32),
        "a spool that still cannot make room stays stopped where it stopped"
    );
    // Once the obstacle is gone the next pass no longer counts the segment, leaves nothing behind
    // and lets the spool take output again. The range it could not take stays a gap that says why.
    std::fs::remove_dir_all(&oldest).expect("clears the way");
    history.apply_retention(over, 32, kr_ipc::now_ms(), true);
    assert!(
        history.left_behind().is_none(),
        "{:?}",
        history.left_behind()
    );
    assert!(
        history.suspended().is_none(),
        "the spool takes output again"
    );
    history.append(&[b'c'; 8]);
    assert!(history.retained_bytes() <= 32);
    let (gap, bytes) = read_to_end(&history, 32);
    let gap = gap.expect("the range the spool could not take is a gap");
    assert_eq!((gap.from_cursor.get(), gap.to_cursor.get()), (32, 40));
    assert_eq!(gap.cause, Some(HistoryGapCause::SpoolUnavailable));
    assert_eq!(bytes, [b'c'; 8]);
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
#[cfg(unix)]
fn a_stopped_spool_writes_what_the_window_kept_when_it_takes_output_again() {
    // A spool that stopped because it could not open a segment still has room, so the resident
    // window keeps what arrives meanwhile. The next pass that finds the spool can write again
    // writes that first, so a reader of the directory alone finds nothing missing.
    use std::os::unix::fs::PermissionsExt as _;
    let directory = std::env::temp_dir().join(format!("kr-persist-resume-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(16, &directory, SpoolLayout::new(8, 1 << 20))
            .expect("a spool");
    history.append(&[b'a'; 8]);
    let mode = std::fs::metadata(&directory).expect("reads").permissions();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
        .expect("makes the directory unwritable");
    history.append(&[b'b'; 8]);
    std::fs::set_permissions(&directory, mode).expect("puts the permissions back");
    assert_eq!(history.suspended().map(|(at, _)| at), Some(8));

    history.apply_retention(OutputRetention::DEFAULT, 16, kr_ipc::now_ms(), true);
    assert!(
        history.suspended().is_none(),
        "the spool takes output again"
    );
    let reopened = kr_worker::history::OutputHistory::read_spool(&directory, SpoolLayout::DEFAULT)
        .expect("reads the directory alone");
    let (gap, bytes) = read_to_end(&reopened, 0);
    assert!(gap.is_none(), "nothing is missing: {gap:?}");
    assert_eq!(bytes, [[b'a'; 8], [b'b'; 8]].concat());
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
#[cfg(unix)]
fn a_resume_that_stops_again_part_way_keeps_what_it_wrote_and_writes_nothing_twice() {
    // A resume writes from the point the spool stopped. If it stops again part way, what it wrote
    // stays written and the next attempt starts after it: a file is never given the same cursors
    // twice.
    use std::os::unix::fs::PermissionsExt as _;
    let directory =
        std::env::temp_dir().join(format!("kr-persist-resume-part-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(32, &directory, SpoolLayout::new(8, 1 << 20))
            .expect("a spool");
    history.append(&[b'a'; 8]);
    let mode = std::fs::metadata(&directory).expect("reads").permissions();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
        .expect("makes the directory unwritable");
    history.append(&[b'b'; 16]);
    std::fs::set_permissions(&directory, mode).expect("puts the permissions back");
    assert_eq!(history.suspended().map(|(at, _)| at), Some(8));
    // Something stands where the second resumed segment's file would go.
    let obstacle = segment_file(&directory, 16);
    std::fs::create_dir(&obstacle).expect("puts a directory in its place");
    std::fs::write(obstacle.join("in-the-way"), b"x").expect("and something in it");

    history.apply_retention(OutputRetention::DEFAULT, 24, kr_ipc::now_ms(), true);
    assert_eq!(
        history.suspended().map(|(at, _)| at),
        Some(16),
        "it wrote one segment and stopped again past it"
    );
    history.apply_retention(OutputRetention::DEFAULT, 24, kr_ipc::now_ms(), true);
    assert_eq!(
        history.suspended().map(|(at, _)| at),
        Some(16),
        "a second attempt starts where the first stopped, not before it"
    );
    std::fs::remove_dir_all(&obstacle).expect("clears the way");
    history.apply_retention(OutputRetention::DEFAULT, 24, kr_ipc::now_ms(), true);
    assert!(history.suspended().is_none());

    for start in [0, 8, 16] {
        assert_eq!(
            std::fs::metadata(segment_file(&directory, start))
                .expect("the segment is there")
                .len(),
            8,
            "the segment at {start} holds its eight bytes once"
        );
    }
    let reopened = kr_worker::history::OutputHistory::read_spool(&directory, SpoolLayout::DEFAULT)
        .expect("reads the directory alone");
    let (gap, bytes) = read_to_end(&reopened, 0);
    assert!(gap.is_none(), "{gap:?}");
    assert_eq!(bytes, [[b'a'; 8], [b'b'; 8], [b'b'; 8]].concat());
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn what_an_append_removed_before_an_unlink_failed_still_names_the_session_cap() {
    // Making room can remove one segment and fail on the next. The range that did go is the
    // session cap's and is recorded as that; the range past the stop is the spool's.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-part-evict-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 16))
            .expect("a spool");
    // Segments of four, four and eight bytes: output that is not retained between them starts a
    // new segment each time.
    history.append(&[b'a'; 4]);
    history.stop_retaining();
    history.append(&[b'-'; 4]);
    history.resume_retaining();
    history.append(&[b'b'; 4]);
    history.stop_retaining();
    history.append(&[b'-'; 4]);
    history.resume_retaining();
    history.append(&[b'c'; 8]);
    assert_eq!(history.retained_bytes(), 16);
    // The second segment cannot be removed.
    let second = segment_file(&directory, 8);
    std::fs::remove_file(&second).expect("removes the second segment's file");
    std::fs::create_dir(&second).expect("puts a directory in its place");
    std::fs::write(second.join("in-the-way"), b"x").expect("and something in it");

    // Eight more bytes need both four-byte segments to go.
    history.append(&[b'd'; 8]);
    assert_eq!(history.suspended().map(|(at, _)| at), Some(24));
    let evictions = history.evictions();
    assert!(
        evictions
            .iter()
            .any(|eviction| eviction.limit == RetentionLimit::SessionCap
                && eviction.from_cursor == 0
                && eviction.bytes == 4),
        "the segment that went is recorded as the session cap's: {evictions:?}"
    );
    let past = history.page(24, 64).expect("a page");
    assert_eq!(
        past.gap.0.and_then(|gap| gap.cause),
        Some(HistoryGapCause::SpoolUnavailable)
    );
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_newest_segment_that_goes_under_an_open_index_is_forgotten_and_the_next_byte_starts_a_new_one()
{
    // A handle open on a file that has gone writes to nothing any reader can reach. The next pass
    // forgets the segment and drops the handle, so the session is counted as what it holds and
    // the next output goes to a new file.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-newest-gone-{}", kr_ipc::new_uuid()));
    let mut history = four_segments(&directory);
    std::fs::remove_file(segment_file(&directory, 24)).expect("removes the newest segment");
    history.apply_retention(OutputRetention::DEFAULT, 32, kr_ipc::now_ms(), true);
    assert_eq!(
        history.retained_bytes(),
        28,
        "the surviving files and the resident window hold 28 bytes"
    );
    assert_eq!(history.holes(), vec![(24, 28)]);
    history.append(&[b'e'; 8]);
    assert!(
        segment_file(&directory, 32).exists(),
        "the next output went to a new file"
    );
    let reopened = kr_worker::history::OutputHistory::read_spool(&directory, SpoolLayout::DEFAULT)
        .expect("reads the directory alone");
    let page = reopened.page(24, 64).expect("a page");
    let gap = page.gap.0.expect("the range that went is a gap");
    assert_eq!((gap.from_cursor.get(), gap.to_cursor.get()), (24, 32));
    assert_eq!(page.bytes.as_slice(), &[b'e'; 8]);
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_segment_that_goes_between_two_writes_is_not_made_again_and_what_followed_it_is_kept() {
    // A pass lets go of the handle the newest segment is written through, so the next write opens
    // the segment again. One whose file has gone in between is not made again: an empty file at
    // its name would put the next bytes where the index says earlier ones are. The spool stops at
    // that cursor instead, and the next pass forgets the segment and writes what the resident
    // window kept into a new one.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-reopened-{}", kr_ipc::new_uuid()));
    let mut history = kr_worker::history::OutputHistory::with_spool(
        64,
        &directory,
        SpoolLayout::new(64, 1 << 20),
    )
    .expect("a spool");
    history.append(b"aaaa");
    history.apply_retention(
        OutputRetention::DEFAULT,
        history.retained_bytes(),
        kr_ipc::now_ms(),
        true,
    );
    std::fs::remove_file(segment_file(&directory, 0)).expect("removes the segment");
    history.append(b"bbbb");
    assert!(
        !segment_file(&directory, 0).exists(),
        "the segment that went was not made again"
    );
    let (at, reason) = history
        .suspended()
        .expect("the spool stopped where the segment went");
    assert_eq!(at, 4);
    assert!(reason.contains("could not be opened"), "{reason}");

    history.apply_retention(
        OutputRetention::DEFAULT,
        history.retained_bytes(),
        kr_ipc::now_ms(),
        true,
    );
    assert!(
        history.suspended().is_none(),
        "the next pass took output again"
    );
    let reopened = kr_worker::history::OutputHistory::read_spool(&directory, SpoolLayout::DEFAULT)
        .expect("reads the directory alone");
    assert_eq!(
        reopened.page(4, 64).expect("a page").bytes.as_slice(),
        b"bbbb",
        "what followed the segment that went is kept"
    );
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_position_past_output_the_spool_did_not_take_is_written_down_by_the_next_pass() {
    // Privacy mode's output is not retained, and the cursor still moves past it. A spool reopened
    // over the directory has to continue from there rather than reuse those cursors, so the next
    // pass writes the position down.
    let directory = std::env::temp_dir().join(format!(
        "kr-persist-privacy-boundary-{}",
        kr_ipc::new_uuid()
    ));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 1 << 20))
            .expect("a spool");
    history.append(&[b'a'; 8]);
    history.stop_retaining();
    assert!(history.discard_retained().left_behind.is_none());
    history.append(&[b'p'; 8]);
    history.apply_retention(OutputRetention::DEFAULT, 0, kr_ipc::now_ms(), true);
    let reopened = kr_worker::history::OutputHistory::read_spool(&directory, SpoolLayout::DEFAULT)
        .expect("reads the directory alone");
    assert_eq!(
        reopened.next_cursor(),
        16,
        "the cursor continues past the output that was not kept"
    );
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_clock_this_host_cannot_prove_stops_the_age_bound_and_not_the_caps() {
    // KR-REQ-20.20 against section 9's collection rule: removing output because it is seven days
    // old is expiry-based collection, and a host that cannot prove its wall clock does not do
    // that. The caps are about bytes rather than about time, so they still apply.
    let directory =
        std::env::temp_dir().join(format!("kr-persist-unproved-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 1 << 20))
            .expect("a spool");
    for _ in 0..4 {
        history.append(&[b'x'; 8]);
    }
    let expired = TimestampMs::new(kr_ipc::now_ms().get() + 8 * 24 * 60 * 60 * 1000);
    let age_only = OutputRetention::new(
        std::time::Duration::from_secs(7 * 24 * 60 * 60),
        1024 * 1024 * 1024,
        1024 * 1024,
    );
    assert!(
        history
            .apply_retention(age_only, 32, expired, false)
            .is_empty(),
        "a clock this host cannot prove collects nothing by age"
    );
    let capped = OutputRetention::new(
        std::time::Duration::from_secs(7 * 24 * 60 * 60),
        1024 * 1024 * 1024,
        8,
    );
    let taken = history.apply_retention(capped, 32, expired, false);
    assert_eq!(taken.len(), 1, "the cap does not depend on a clock");
    assert_eq!(taken[0].limit, RetentionLimit::SessionCap);
    // And with the clock proved, the age bound applies as well.
    let taken = history.apply_retention(age_only, 32, expired, true);
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].limit, RetentionLimit::Age);
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn the_resident_window_is_collected_by_age_as_well_as_the_spool() {
    // KR-REQ-20.20. The window is what a session serves when its spool has nothing left, so
    // output past the retention period is not something a host may keep serving because it
    // happens to be the newest it has.
    let mut history = kr_worker::history::OutputHistory::in_memory(4096);
    history.append(&[b'x'; 64]);
    let expired = TimestampMs::new(kr_ipc::now_ms().get() + 8 * 24 * 60 * 60 * 1000);
    let taken = history.apply_retention(OutputRetention::DEFAULT, 64, expired, true);
    assert_eq!(taken.len(), 1, "the window's own output expired");
    assert_eq!(taken[0].limit, RetentionLimit::Age);
    assert_eq!(taken[0].bytes, 64);
    assert_eq!(history.oldest_retained_cursor(), history.next_cursor());
    let page = history.page(0, 64).expect("a page");
    assert!(page.bytes.is_empty());
    assert_eq!(
        page.gap.0.expect("a gap").cause,
        Some(HistoryGapCause::Retention)
    );
}

#[test]
fn a_window_whose_newest_byte_is_not_expired_keeps_the_whole_interval() {
    // The marks say when the *newest* byte in each interval arrived, so a range goes only when
    // this host can say every byte in it had expired. Output written a moment ago is kept even
    // when the interval it belongs to began before the deadline.
    let mut history = kr_worker::history::OutputHistory::in_memory(4096);
    // The reading is taken *before* the output arrives, so the deadline it produces is at or
    // before the instant the interval's newest byte was stamped with. Taking it afterwards would
    // make the test a race: a clock tick between the append and the reading is enough to put the
    // byte on the wrong side of a one-millisecond window, and a loaded machine ticks.
    let before_the_output = kr_ipc::now_ms();
    history.append(&[b'x'; 32]);
    let taken = history.apply_retention(
        OutputRetention::new(std::time::Duration::from_millis(1), 1 << 30, 1 << 30),
        32,
        before_the_output,
        true,
    );
    assert!(
        taken.is_empty(),
        "the interval's newest byte is younger than the deadline"
    );
    assert_eq!(history.oldest_retained_cursor(), 0);
}

#[test]
fn the_spool_writes_its_boundary_before_it_deletes_what_supports_it() {
    // A crash between the delete and the write would put the spool back in the condition the
    // boundary exists to prevent, so the file is on disk first. A reader of the directory after
    // an eviction therefore finds a boundary that already covers what went.
    let directory = std::env::temp_dir().join(format!("kr-persist-order-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 1 << 20))
            .expect("a spool");
    for _ in 0..4 {
        history.append(&[b'x'; 8]);
    }
    let retention =
        OutputRetention::new(std::time::Duration::from_secs(7 * 24 * 60 * 60), 1 << 30, 0);
    let taken = history.apply_retention(retention, 32, kr_ipc::now_ms(), true);
    assert!(!taken.is_empty());
    let recorded: u64 = std::fs::read_to_string(directory.join("boundary"))
        .expect("the boundary is on disk")
        .trim()
        .parse()
        .expect("a number");
    assert_eq!(recorded, 32, "it covers everything the spool was given");
    assert!(
        !directory.join("boundary.writing").exists(),
        "the staging file does not survive the rename"
    );
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
#[cfg(unix)]
fn a_spool_that_stops_taking_output_keeps_what_it_wrote_counted_served_and_purgeable() {
    // A spool that cannot open a segment stops taking output rather than being dropped, so what it
    // wrote before that stays in its account: counted against the cap, served to a reader,
    // collected by retention and removed by a purge. A privacy purge that answered "nothing to
    // remove" because the spool had gone would be reporting a removal it never made, and the
    // archive could still be served those segments afterwards.
    use std::os::unix::fs::PermissionsExt as _;
    let directory = std::env::temp_dir().join(format!("kr-persist-lost-{}", kr_ipc::new_uuid()));
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(64, 1 << 20))
            .expect("a spool");
    for _ in 0..8 {
        history.append(&[b'x'; 64]);
    }
    let before = std::fs::read_dir(&directory)
        .expect("reads the spool")
        .count();
    assert!(before > 1, "the spool wrote segments: {before}");

    // The directory stops taking new files, which is what a rotation needs.
    let mode = std::fs::metadata(&directory).expect("reads").permissions();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
        .expect("makes the directory unwritable");
    for _ in 0..8 {
        history.append(&[b'y'; 64]);
    }
    std::fs::set_permissions(&directory, mode).expect("puts the permissions back");
    let (stopped_at, why) = history
        .suspended()
        .expect("the spool stopped taking output");
    assert_eq!(stopped_at, 8 * 64);
    assert!(why.contains("could not be opened"), "{why}");
    assert_eq!(
        history.retained_bytes(),
        8 * 64 + 4,
        "what it wrote is still counted, beside the resident window"
    );
    let held = history.page(0, 1024).expect("a page");
    assert!(!held.gap.is_present(), "what it wrote is still served");
    assert_eq!(held.bytes.as_slice(), &[b'x'; 8 * 64]);
    let past = history.page(8 * 64, 1024).expect("a page");
    assert_eq!(
        past.gap.as_ref().and_then(|gap| gap.cause),
        Some(HistoryGapCause::SpoolUnavailable),
        "the range the spool could not take is its storage's rather than a bound's"
    );

    let discarded = history.discard_retained();
    assert!(
        discarded.left_behind.is_none(),
        "the purge finished: {:?}",
        discarded.left_behind
    );
    assert!(discarded.segments > 0, "it removed the segments it found");
    let left: Vec<_> = std::fs::read_dir(&directory)
        .expect("reads the spool")
        .flatten()
        .map(|entry| entry.file_name())
        .filter(|name| name != "boundary")
        .collect();
    assert!(
        left.is_empty(),
        "a stopped spool's segments are gone after the purge: {left:?}"
    );
    // The boundary stays on the disk, because it is where this session's output got to rather
    // than content. A reader that comes to the directory afterwards - the archive does exactly
    // this - is told the range that went rather than that the session started at nought, and only
    // the file can tell it that: the history that did the purge still has the cursor in memory.
    let reopened = kr_worker::history::OutputHistory::read_spool(&directory, SpoolLayout::DEFAULT)
        .expect("the archive reads what is left");
    assert_eq!(
        reopened.oldest_retained_cursor(),
        history.next_cursor(),
        "the boundary the purge wrote is where the output got to"
    );
    assert!(reopened.next_cursor() > 0, "and it is not nought");
    let page = reopened.page(0, 1024).expect("a page");
    let gap = page
        .gap
        .as_ref()
        .expect("the range that went reads as a gap");
    assert_eq!(gap.to_cursor.get(), history.next_cursor());
    std::fs::remove_dir_all(&directory).ok();
}

#[test]
fn a_boundary_this_host_cannot_read_is_reported_rather_than_guessed_at() {
    let directory =
        std::env::temp_dir().join(format!("kr-persist-unreadable-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("the directory");
    std::fs::write(directory.join("boundary"), "not a cursor").expect("an unreadable boundary");
    let mut history =
        kr_worker::history::OutputHistory::with_spool(4, &directory, SpoolLayout::new(8, 1 << 20))
            .expect("a spool");
    history.append(&[b'x'; 16]);
    // A host that recorded where its output got to and cannot read it back does not know what it
    // is missing, so every page says so rather than reporting the silence as completeness.
    let page = history.page(0, 64).expect("a page");
    assert_eq!(
        page.gap.0.and_then(|gap| gap.cause),
        Some(HistoryGapCause::SpoolUnavailable),
        "this host cannot say what came before what it holds"
    );
    assert!(
        !page.bytes.is_empty(),
        "what it does hold is still served, a page at a time"
    );
    // And after an eviction the answer is the same one, for the same reason.
    let taken = history.apply_retention(
        OutputRetention::new(std::time::Duration::from_secs(7 * 24 * 60 * 60), 1 << 30, 0),
        16,
        kr_ipc::now_ms(),
        true,
    );
    assert!(!taken.is_empty());
    assert_eq!(
        history
            .page(0, 64)
            .expect("a page")
            .gap
            .0
            .and_then(|gap| gap.cause),
        Some(HistoryGapCause::SpoolUnavailable)
    );
    std::fs::remove_dir_all(&directory).ok();
}

#[cfg(unix)]
#[tokio::test]
async fn the_output_spool_is_owner_only_like_every_other_state_directory() {
    // KR-REQ-24.26. The spool holds the terminal's own output, so its mode is not a decision this
    // host leaves to the process umask.
    use std::os::unix::fs::PermissionsExt as _;

    let host = host().await;
    {
        let mut session = host.runtime.session();
        session.ingest_output(b"hello\r\n");
    }
    let spool = host
        .journal_path
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the environment state directory")
        .join("spool");
    let entries: Vec<std::path::PathBuf> = std::fs::read_dir(&spool)
        .expect("the spool directory exists")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    assert!(!entries.is_empty(), "this session has a spool of its own");
    for entry in entries {
        let mode = std::fs::metadata(&entry)
            .expect("the directory exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "{} is {mode:o}", entry.display());
    }
}

// ---------------------------------------------------------------------------------------------
// The wire shape of a history gap
// ---------------------------------------------------------------------------------------------

#[test]
fn a_gap_with_no_recorded_cause_is_byte_for_byte_what_an_earlier_build_wrote() {
    // The cause is absent from the wire when the host has no reason recorded, so a gap this build
    // reports to a client built before causes existed decodes there unchanged.
    let gap = kr_protocol::recovery::HistoryGap {
        from_cursor: kr_protocol::scalars::U64::new(0),
        to_cursor: kr_protocol::scalars::U64::new(4096),
        cause: None,
    };
    let encoded = kr_cbor::to_canonical_vec(&gap).expect("encodes");
    let older: EarlierHistoryGap =
        kr_cbor::from_canonical_slice(&encoded, &kr_cbor::Limits::default())
            .expect("an earlier build decodes");
    assert_eq!(older.from_cursor.get(), 0);
    assert_eq!(older.to_cursor.get(), 4096);
    // And a gap an earlier build wrote decodes here, with no cause.
    let round: kr_protocol::recovery::HistoryGap = kr_cbor::from_canonical_slice(
        &kr_cbor::to_canonical_vec(&older).expect("encodes"),
        &kr_cbor::Limits::default(),
    )
    .expect("decodes");
    assert_eq!(round.cause, None);
}

#[test]
fn a_gap_that_carries_a_cause_is_refused_by_a_decoder_built_before_it() {
    // The boundary, stated rather than hidden: `HistoryGap` denies unknown fields, so a client
    // built before this field refuses a gap that carries one. This host only ever sends a cause
    // it has recorded, so the case arises for a gap eviction produced and not for any other.
    let gap = kr_protocol::recovery::HistoryGap {
        from_cursor: kr_protocol::scalars::U64::new(0),
        to_cursor: kr_protocol::scalars::U64::new(4096),
        cause: Some(HistoryGapCause::HostCapacity),
    };
    let encoded = kr_cbor::to_canonical_vec(&gap).expect("encodes");
    assert!(
        kr_cbor::from_canonical_slice::<EarlierHistoryGap>(&encoded, &kr_cbor::Limits::default())
            .is_err(),
        "a decoder built before the field refuses it"
    );
}

/// `HistoryGap` as a build before the cause existed declares it.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct EarlierHistoryGap {
    from_cursor: kr_protocol::scalars::U64,
    to_cursor: kr_protocol::scalars::U64,
}

// ---------------------------------------------------------------------------------------------
// KR-ACC-028: a full journal during native traffic
// ---------------------------------------------------------------------------------------------

/// The application these tests drive: it answers each line it reads with `kr-got:` and the line,
/// and says `kr-interrupted.` when the interrupt reaches it.
///
/// It empties its field separator once, for the whole script, and not for each `read` with
/// `IFS= read`. macOS's `/bin/sh` is bash 3.2, which runs the trap for a signal that reaches it
/// while `read` waits inside that `read`, and frees the `read`'s temporary assignment when the
/// trap's command ends. The `read` then splits the next line it is given on memory it no longer
/// owns, and drops the line's last character when that memory holds it and holds no character
/// before it in the line. An assignment for the whole script is not freed by the trap.
#[cfg(unix)]
const READING_APPLICATION: &str = "stty -echo; IFS=; trap 'printf \"kr-interrupted.\\n\"' INT; \
     printf 'kr-ready.\\n'; \
     while :; do if read -r line; then printf 'kr-got:%s\\n' \"$line\"; fi; done";

/// KR-REQ-07.57: with the journal full, raw input and the interrupt under the live lease keep
/// working, while a typed mutation and an approval are refused with `STORAGE_UNAVAILABLE` before
/// anything is dispatched, leaving nothing behind to be retried.
///
/// Unix only: its root program is a POSIX script that turns off echo, traps the interrupt signal and
/// reads a line at a time, none of which PowerShell expresses the same way, and the interrupt it
/// drives is a POSIX signal to a process group. The store-side halves of this contract - a full
/// store refusing a rich mutation and still taking the interrupt and the close - are covered on
/// Windows by [`a_full_durable_store_refuses_a_new_mutation_before_anything_is_dispatched`] and
/// [`a_store_that_cannot_be_read_still_takes_the_interrupt_and_the_close`], whose root shell is only
/// a keep-alive; the worker's own `tests/windows.rs` drives a real console and PowerShell.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_journal_fences_a_rich_mutation_while_raw_input_keeps_flowing() {
    // KR-ACC-028: the journal is filled while the input lease is live and an application is
    // reading from the terminal and answering it; the bytes the person types still reach it and
    // the interrupt still interrupts it, while a rich mutation and the answer to a pending
    // decision are refused before anything is dispatched, and nothing is left behind for a replay
    // to find. Then the store is given room again and recovers, and nothing the fence refused is
    // dispatched afterwards: what was refused stays refused until it is asked for again.
    let host = host_running(READING_APPLICATION).await;
    produced(&host.runtime, b"kr-ready.").await;
    let mut client = cli(&host).await;
    // A decision is pending, asked by an agent in this session while the store was working.
    let asker = kr_worker::questions::binding::VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("kr-test-agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: true,
        connection_id: kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid()),
    };
    let now = || kr_worker::questions::Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    };
    let (asked, _) = host
        .service
        .questions()
        .create(
            &asker,
            &kr_protocol::question::QuestionCreateParams {
                session_id: host.session_id,
                request_id: "push-anyway".to_owned(),
                kind: kr_protocol::question::QuestionKind::Confirm,
                context: "Two tests are failing.".to_owned(),
                question: "Push the branch anyway?".to_owned(),
                choices: Vec::new(),
                agent_name: Nullable::some("kr-test-agent".to_owned()),
                requested_expiry_ms: Nullable::some(kr_protocol::scalars::DurationMs::new(600_000)),
                wait_ms: Nullable::null(),
            },
            now(),
        )
        .expect("the agent asks while the store is working");

    // An attachment and the input lease, taken while the store is still working.
    let attachment: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &attach_params(host.session_id),
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("attaches");
    let lease: kr_protocol::input::InputAcquireResult = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::input::InputAcquireParams {
                session_id: host.session_id,
                attachment_id: attachment.attachment.attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("acquires the lease");

    {
        let mut session = host.runtime.session();
        let refusal = fill_the_store(session.journal_mut().expect("a journal"));
        assert!(refusal.to_string().contains("full"), "{refusal}");
    }

    // The terminal keeps working. Raw input under the live lease is section 11's exception, and a
    // keystroke never waited for a durable write in the first place.
    for sequence in 0..4 {
        let written: kr_protocol::input::InputWriteResult = client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: host.session_id,
                    attachment_id: attachment.attachment.attachment_id,
                    epoch: lease.lease.epoch,
                    sequence: kr_protocol::ids::InputSequence::new(sequence),
                    bytes: kr_protocol::scalars::Bytes::new(
                        format!("kr-typed-{sequence}\n").into_bytes(),
                    ),
                },
            )
            .await
            .expect("reaches the worker")
            .map(|value| value.to_typed().expect("decodes"))
            .expect("the terminal still takes input with a full store");
        assert_eq!(written.sequence.get(), sequence);
    }
    // And the application reads every line of it.
    produced(&host.runtime, b"kr-got:kr-typed-3").await;
    let seen = retained(&host.runtime);
    for sequence in 0..4 {
        assert!(
            carries(&seen, format!("kr-got:kr-typed-{sequence}").as_bytes()),
            "line {sequence} reached the application"
        );
    }

    // Rich work is fenced, and the refusal is a refusal rather than an uncertain outcome.
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let refused = client
        .mutate(
            Method::SessionAttach,
            action_id,
            target(&host),
            &attach_params(host.session_id),
        )
        .await
        .expect("reaches the worker")
        .expect_err("a full store fences rich work");
    assert_eq!(refused.code, ErrorCode::StorageUnavailable);
    // An approval is rich work too. Answering the pending decision is refused at the same point,
    // before anything is dispatched, and the decision is still waiting afterwards: nothing was
    // decided that this host could not record.
    let approval = client
        .mutate(
            Method::QuestionAnswer,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::question::QuestionAnswerParams {
                session_id: host.session_id,
                question_id: asked.question.question_id,
                expected_revision: asked.question.revision,
                answer: kr_protocol::question::QuestionAnswer::Decision { decided: true },
            },
        )
        .await
        .expect("reaches the worker")
        .expect_err("a full store fences an approval");
    assert_eq!(approval.code, ErrorCode::StorageUnavailable);
    let (still, _) = host
        .service
        .questions()
        .read_own(
            &asker,
            &kr_protocol::question::QuestionReadOwnParams {
                session_id: host.session_id,
                question_id: asked.question.question_id,
                caller_token: asked.caller_token.clone(),
                wait_ms: Nullable::null(),
            },
            now(),
        )
        .expect("the agent reads its question");
    assert_eq!(
        still.question.state,
        kr_protocol::question::QuestionState::Pending,
        "the refused answer decided nothing"
    );

    // Section 7's other exception, through the same admission path the refusal above took: the
    // interrupt is the one way a person has of stopping a running command on a host whose store
    // has failed, so a full journal must not take it away. This is a mutation, so it passes the
    // posture check, the duplicate-suppression read and the outstanding read, each of which the
    // full store can refuse.
    // Each interrupt the application has not said it took is sent again, and each one is accepted
    // by the full store: an interrupt that reaches a shell just before it waits is taken late.
    let interrupted = interrupt_until_said(&host, &mut client, &attachment, &lease).await;
    assert_eq!(interrupted.lease.epoch, lease.lease.epoch);

    // And nothing can replay it: the store holds no record of the action at all, so there is no
    // dispatch marker for a recovery to turn into an uncertain outcome.
    {
        let mut session = host.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        let caller = ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
            .expect("the local caller");
        assert!(
            journal.read(caller, action_id).expect("reads").is_none(),
            "a fenced mutation leaves nothing to replay"
        );
        assert!(!session.durability_posture().admits(WorkClass::RichMutation));
        assert!(
            session
                .durability_posture()
                .admits(WorkClass::NativeTerminal)
        );
    }

    // The store is given room again, as a disk that was cleared is, and the next maintenance pass
    // recovers it: the interval durable writing was lost is written down first, and rich work is
    // admitted again.
    {
        let mut session = host.runtime.session();
        session
            .journal_mut()
            .expect("a journal")
            .release_size_cap()
            .expect("the store can grow again");
    }
    host.service.recover_storage_now();
    {
        let session = host.runtime.session();
        assert!(
            session.durability_posture().admits(WorkClass::RichMutation),
            "the store recovered"
        );
        assert!(
            !session
                .journal()
                .expect("a journal")
                .recovery_gaps()
                .expect("reads the gaps")
                .is_empty(),
            "the interval durable writing was lost is written down"
        );
    }

    // Nothing the fence refused is dispatched now that the store could take it. The refused
    // attach has no receipt and made no attachment, and the refused answer decided nothing:
    // KR-ACC-028's "never replay volatile requests" holds across the recovery, not only during
    // the fault.
    {
        let mut session = host.runtime.session();
        assert_eq!(
            session.attachments().len(),
            1,
            "the refused attach made no attachment"
        );
        let caller = ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
            .expect("the local caller");
        assert!(
            session
                .journal_mut()
                .expect("a journal")
                .read(caller, action_id)
                .expect("reads")
                .is_none(),
            "the refused mutation was not replayed into the recovered store"
        );
    }
    let (after, _) = host
        .service
        .questions()
        .read_own(
            &asker,
            &kr_protocol::question::QuestionReadOwnParams {
                session_id: host.session_id,
                question_id: asked.question.question_id,
                caller_token: asked.caller_token.clone(),
                wait_ms: Nullable::null(),
            },
            now(),
        )
        .expect("the agent reads its question");
    assert_eq!(
        after.question.state,
        kr_protocol::question::QuestionState::Pending,
        "the refused answer was not replayed either"
    );

    // Work asked for again is admitted as new work, which is the only way it reaches the host.
    let admitted: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &attach_params(host.session_id),
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("the recovered store takes rich work again");
    assert_ne!(
        admitted.attachment.attachment_id,
        attachment.attachment.attachment_id
    );
    // And the application still answers what is typed.
    let written: kr_protocol::input::InputWriteResult = client
        .request(
            Method::InputWrite,
            &kr_protocol::input::InputWriteParams {
                session_id: host.session_id,
                attachment_id: attachment.attachment.attachment_id,
                epoch: lease.lease.epoch,
                sequence: kr_protocol::ids::InputSequence::new(4),
                bytes: kr_protocol::scalars::Bytes::new(b"kr-typed-4\n".to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("the terminal takes input after the recovery");
    assert_eq!(written.sequence.get(), 4);
    produced(&host.runtime, b"kr-got:kr-typed-4").await;
}

/// The application the test above drives, which KR-REQ-07.57's raw input and interrupt are shown
/// on, answers a line typed right after an interrupt whole, whatever printable character ends it.
///
/// Each printable ASCII character but the space ends one such line. The last character of a line is
/// the one an application that splits its input on the wrong set of characters drops, so the one
/// line the test above types finds a lost character only now and then, and these look for it at the
/// end of ninety-four lines.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_character_typed_after_an_interrupt_reaches_the_application() {
    let host = host_running(READING_APPLICATION).await;
    produced(&host.runtime, b"kr-ready.").await;
    let mut client = cli(&host).await;
    let attachment: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &attach_params(host.session_id),
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("attaches");
    let lease: kr_protocol::input::InputAcquireResult = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::input::InputAcquireParams {
                session_id: host.session_id,
                attachment_id: attachment.attachment.attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("acquires the lease");

    for (index, character) in (b'!'..=b'~').enumerate() {
        // The interrupt has reached the application, which is what the next line is typed after.
        interrupt_until_said(&host, &mut client, &attachment, &lease).await;
        let line = format!("L{index:02}{}", char::from(character));
        let _: kr_protocol::input::InputWriteResult = client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: host.session_id,
                    attachment_id: attachment.attachment.attachment_id,
                    epoch: lease.lease.epoch,
                    sequence: kr_protocol::ids::InputSequence::new(index as u64),
                    bytes: kr_protocol::scalars::Bytes::new(format!("{line}\n").into_bytes()),
                },
            )
            .await
            .expect("reaches the worker")
            .map(|value| value.to_typed().expect("decodes"))
            .expect("the terminal takes input after an interrupt");
        assert_eq!(
            answer_beginning(&host.runtime, &format!("kr-got:L{index:02}")).await,
            format!("kr-got:{line}"),
            "the application got the line typed after interrupt {index} whole"
        );
    }
}

/// Interrupts the application until it has said it took the interrupt, and returns the lease the
/// last interrupt was accepted under.
///
/// A shell runs a trap for a signal that reaches it while it waits for input. A signal that reaches
/// it just before it starts to wait is held until something wakes the wait: the next line, or
/// another signal. So an interrupt the application has not said it took within half a second is
/// sent again. What the application had said before the first interrupt is counted first, so only
/// what it says after that counts: the count only has to rise by one. The caller has waited for the
/// answer to the line it typed after the previous interrupt, and a shell runs a trap for a signal
/// sent before a line arrives before it answers that line, so no reply to an earlier interrupt is
/// counted here.
#[cfg(unix)]
async fn interrupt_until_said(
    host: &Host,
    client: &mut LocalClient,
    attachment: &kr_protocol::attachment::SessionAttachResult,
    lease: &kr_protocol::input::InputAcquireResult,
) -> kr_protocol::input::InputLeaseResult {
    let said = carried_times(&retained(&host.runtime), b"kr-interrupted.") + 1;
    let started = tokio::time::Instant::now();
    loop {
        let sent: kr_protocol::input::InputLeaseResult = client
            .mutate(
                Method::InputInterrupt,
                ActionId::new(kr_ipc::new_uuid()),
                target(host),
                &kr_protocol::input::InputInterruptParams {
                    session_id: host.session_id,
                    attachment_id: attachment.attachment.attachment_id,
                    epoch: lease.lease.epoch,
                    action: kr_protocol::input::InterruptAction::NativeInterrupt,
                },
            )
            .await
            .expect("reaches the worker")
            .map(|value| value.to_typed().expect("decodes"))
            .expect("the worker takes the interrupt");
        for _ in 0..25 {
            if carried_times(&retained(&host.runtime), b"kr-interrupted.") >= said {
                return sent;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for the application to say it took an interrupt",
            started.elapsed()
        );
    }
}

/// Waits until the session's retained output carries a whole line that begins with `prefix`, and
/// returns that line without its ending.
#[cfg(unix)]
async fn answer_beginning(runtime: &SessionRuntime, prefix: &str) -> String {
    let started = tokio::time::Instant::now();
    loop {
        let seen = retained(runtime);
        let text = String::from_utf8_lossy(&seen);
        if let Some(start) = text.find(prefix)
            && let Some(length) = text[start..].find("\r\n")
        {
            return text[start..start + length].to_owned();
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for a line beginning {prefix:?} in the session's retained output",
            started.elapsed()
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// KR-REQ-07.57: with the journal unreadable, the interrupt and the close still work, the close
/// says its durability is volatile, and a second close is answered against the session itself
/// rather than against a receipt the store could not keep.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_store_that_cannot_be_read_still_takes_the_interrupt_and_the_close() {
    // KR-ACC-028 and section 7's two exceptions, against a store that fails its *reads* rather
    // than its writes. Admission asks the journal twice before anything is dispatched, for the
    // action that may supersede this one and for how many the caller already has outstanding.
    // Those reads protect a new rich action. An authorised stop and a native interrupt are
    // neither, so a store that cannot answer them must not take away the one way a person has of
    // stopping a running command, nor the way they end the session.
    let host = host().await;
    let mut client = cli(&host).await;
    let attachment: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &attach_params(host.session_id),
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("attaches");
    let lease: kr_protocol::input::InputAcquireResult = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::input::InputAcquireParams {
                session_id: host.session_id,
                attachment_id: attachment.attachment.attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("acquires the lease");

    // The receipt table goes, which is what both admission reads read. This is the shape of a
    // store whose file a person or another program has damaged under a running host.
    {
        let connection = rusqlite::Connection::open(&host.journal_path).expect("opens the store");
        connection
            .execute_batch("DROP TABLE receipts;")
            .expect("takes the receipt table away");
    }

    // Rich work is refused, because the reads that protect it cannot answer.
    let refused = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &attach_params(host.session_id),
        )
        .await
        .expect("reaches the worker")
        .expect_err("a store that cannot be read fences rich work");
    assert_eq!(refused.code, ErrorCode::StorageUnavailable);

    // The interrupt passes the same gates.
    let interrupted: kr_protocol::input::InputLeaseResult = client
        .mutate(
            Method::InputInterrupt,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::input::InputInterruptParams {
                session_id: host.session_id,
                attachment_id: attachment.attachment.attachment_id,
                epoch: lease.lease.epoch,
                action: kr_protocol::input::InterruptAction::NativeInterrupt,
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("an unreadable store does not take the interrupt away");
    assert_eq!(interrupted.lease.epoch, lease.lease.epoch);

    // And so does the authorised stop, whose receipt is what it loses rather than its effect.
    let closed: kr_protocol::session::SessionCloseResult = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::session::SessionCloseParams {
                session_id: host.session_id,
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("an unreadable store does not take the stop away");
    assert_eq!(
        closed.durability,
        kr_protocol::session::Durability::Volatile,
        "the close says what it lost rather than claiming a receipt it could not write"
    );
    assert_eq!(closed.session_id, host.session_id);
    // The same stop asked for again, under a new action identifier. There is no receipt to
    // de-duplicate it against, so it is answered from the session: the closure already under way,
    // not a second one.
    let again: kr_protocol::session::SessionCloseResult = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &kr_protocol::session::SessionCloseParams {
                session_id: host.session_id,
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("a repeated stop is answered rather than refused");
    assert_eq!(again.session_id, host.session_id);
    assert_ne!(
        again.state,
        kr_protocol::session::SessionState::Live,
        "the repeat joins the closure rather than finding a live session"
    );
    assert_eq!(again.durability, kr_protocol::session::Durability::Volatile);
}

/// KR-REQ-07.57: a condition the store has already reported fences typed mutations before the
/// next write, and the authorised stop still goes through with volatile durability.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_condition_the_store_already_reported_fences_rich_work_before_the_next_write() {
    // KR-REQ-24.23 and the seam together. A store that has told this host it cannot be trusted
    // does not have to refuse the *next* statement for the work that statement is part of to be
    // work this host must not start: a value nothing can decode leaves the rows around it
    // perfectly writable, and a mutation admitted over that would be a mutation this host had
    // already said it could not account for.
    let host = host().await;
    {
        // A stored value this build cannot read, which is the condition that does not repeat
        // itself on the next write.
        let mut session = host.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        journal.accept(&submission(7, 7)).expect("accepts");
        journal.checkpoint().expect("checkpoints");
    }
    let path = host.journal_path.clone();
    rusqlite::Connection::open(&path)
        .expect("the same database")
        .execute(
            "UPDATE outbox SET stream = 'a stream no build writes' WHERE cursor = 1",
            [],
        )
        .expect("writes an undecodable row");
    {
        let session = host.runtime.session();
        let journal = session.journal().expect("a journal");
        assert!(
            journal.outbox_after(0, 64).is_err(),
            "the row is unreadable"
        );
    }
    assert_eq!(
        host.runtime
            .session()
            .health()
            .condition()
            .fault()
            .map(|fault| fault.kind),
        Some(FaultKind::Corrupt)
    );

    // The next write would succeed on its own, and the mutation is refused anyway.
    let mut client = cli(&host).await;
    let outcome = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(&host),
            &attach_params(host.session_id),
        )
        .await
        .expect("the call reaches the worker");
    let failure = outcome.expect_err("rich work is fenced by the condition already reported");
    assert_eq!(failure.code, ErrorCode::StorageUnavailable);
    assert!(failure.message.contains("read back"), "{}", failure.message);

    // And the authorised stop is not: section 7's exception survives the condition.
    let result = close(&mut client, &host).await;
    assert_eq!(result.durability, Durability::Volatile);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.48: state-recovery reads bounded by cursor, range and authority
// ---------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_history_page_is_bounded_by_the_cursor_and_the_range_it_names() {
    // KR-REQ-23.48 for `history.page`'s cursor and range. The row's other reads -
    // `events.subscribe`, `events.snapshot` and `action.read` - and present view authority over
    // their subject are proved in `tests/recovery_reads.rs`.
    let host = host().await;
    let mut client = cli(&host).await;
    {
        let mut session = host.runtime.session();
        for _ in 0..8 {
            session.ingest_output(&[b'x'; 1024]);
        }
    }
    // The cursor bounds where it starts.
    let page: kr_protocol::recovery::HistoryPageResult = client
        .request(
            Method::HistoryPage,
            &kr_protocol::recovery::HistoryPageParams {
                session_id: host.session_id,
                from_cursor: U64::new(2048),
                max_bytes: U64::new(512),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("a page");
    assert_eq!(page.from_cursor.get(), 2048);
    // And the range bounds how much it carries.
    assert_eq!(page.bytes.len(), 512);
    assert_eq!(page.next_cursor.get(), 2048 + 512);
    // A page asked for beyond every bound is still bounded.
    let bounded: kr_protocol::recovery::HistoryPageResult = client
        .request(
            Method::HistoryPage,
            &kr_protocol::recovery::HistoryPageParams {
                session_id: host.session_id,
                from_cursor: U64::new(0),
                max_bytes: U64::new(u64::MAX),
            },
        )
        .await
        .expect("reaches the worker")
        .map(|value| value.to_typed().expect("decodes"))
        .expect("a page");
    assert!(
        bounded.bytes.len() as u64 <= kr_protocol::recovery::MAX_HISTORY_PAGE_BYTES,
        "a page never carries more than the protocol's bound"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-07.68: what the persistence contract covers
// ---------------------------------------------------------------------------------------------

#[test]
fn the_store_declarations_say_what_survives_a_daemon_restart_and_what_a_crash_ends() {
    // Section 7: *the persistence contract covers network loss and control-daemon restart. A
    // worker crash or host reboot ends the affected live process execution.* The store
    // declarations are where that is decidable: what survives a daemon restart is what the
    // worker's own journal holds, and what a worker crash ends is the live execution, which is
    // why a crash's closure is recorded by the controller rather than resumed.
    use kr_worker::persistence::stores;

    for name in ["receipts", "results", "closure", "session", "journal_gaps"] {
        let store = stores::store(name).expect("a declaration");
        assert_eq!(
            store.durability,
            stores::Durability::CrashDurable,
            "{name} survives a daemon restart"
        );
    }
    // The live parser and the session's own memory do not survive the process that holds them,
    // which is what "a worker crash ends the live execution" means in this host.
    let resident = stores::store("resident history").expect("a declaration");
    assert_eq!(resident.durability, stores::Durability::ProcessMemory);
    assert_eq!(resident.reconciliation, stores::Reconciliation::NotRestored);
    // And a crashed session's record is the archive's to serve rather than a worker's to resume.
    let closure = stores::store("closure").expect("a declaration");
    assert!(closure.served_by_archive);
    assert_eq!(closure.cleanup, stores::Cleanup::ArchiveService);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-24.26: owner-only local state
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_state_directories_this_host_creates_are_owner_only() {
    // KR-REQ-24.26 on this machine. The headless Linux limitation is documented in
    // docs/host/README.md and is about key storage rather than about these directories.
    let host = host().await;
    let mut directory = host.journal_path.parent().expect("a parent").to_path_buf();
    // Every directory from the journal up to the environment's state root is owner-only.
    for _ in 0..3 {
        assert_owner_only(&directory);
        let Some(parent) = directory.parent() else {
            break;
        };
        directory = parent.to_path_buf();
    }
}

#[cfg(unix)]
fn assert_owner_only(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let mode = std::fs::metadata(path)
        .expect("the directory exists")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700, "{} is {mode:o}", path.display());
}

/// Reads a directory's access-control list, and returns why it is not owner-only, or `None`.
///
/// Windows has no mode bits, so the question the Unix check asks of `0700` is asked of the list,
/// read from a handle on the directory: it belongs to this account and grants no account the machine
/// does not already trust.
#[cfg(windows)]
fn not_owner_only(path: &std::path::Path) -> Option<String> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsHandle as _;

    // The flag that lets a program open a directory at all.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

    let handle = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
    {
        Ok(handle) => handle,
        Err(error) => return Some(format!("{} could not be opened: {error}", path.display())),
    };
    match kr_ipc::paths::check_access_list(handle.as_handle(), &path.display().to_string(), false) {
        Ok(()) => None,
        Err(refusal) => Some(format!("{refusal:?}")),
    }
}

#[cfg(windows)]
fn assert_owner_only(path: &std::path::Path) {
    if let Some(reason) = not_owner_only(path) {
        panic!("{} is not owner-only: {reason}", path.display());
    }
}

/// KR-REQ-24.26: the owner-only check reads the access-control list, so a directory whose list has
/// been widened is refused. Today's check, that the directory merely exists, passes a widened one;
/// this is the case that fails against it.
#[cfg(windows)]
#[test]
fn a_widened_state_directory_is_not_owner_only() {
    let root = tempfile::tempdir().expect("a directory");
    let owned = root.path().join("owned");
    kr_ipc::paths::create_private_directory(&owned).expect("an owner-only directory");
    // The negative control: as created, it is owner-only.
    assert!(
        not_owner_only(&owned).is_none(),
        "a directory this host created is owner-only"
    );

    // Widened to grant Everyone, which the check must refuse.
    let output = std::process::Command::new("icacls.exe")
        .args([owned.as_os_str(), "/grant".as_ref(), "*S-1-1-0:F".as_ref()])
        .output()
        .expect("icacls runs");
    assert!(
        output.status.success(),
        "icacls: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        not_owner_only(&owned).is_some(),
        "a directory that grants Everyone is not owner-only"
    );
}
