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

// ---------------------------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------------------------

struct Host {
    _temp: kr_ipc::testing::TempHost,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    journal_path: std::path::PathBuf,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Starts a worker whose journal already holds whatever `prepare` writes into it.
async fn host_prepared(prepare: impl FnOnce(&std::path::Path)) -> Host {
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
    // The T-002g seam: the daemon's keys live in a file store under this temporary environment's
    // own secrets directory, so nothing test-driven reaches the operating system's credential
    // store.
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
    let config = session_config(&environment, session_id);
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
        runtime,
        session_id,
        journal_path,
        endpoint,
        environment_id,
    }
}

async fn host() -> Host {
    host_prepared(|_| {}).await
}

fn session_config(
    environment: &kr_ipc::paths::EnvironmentPaths,
    session_id: SessionId,
) -> SessionConfig {
    SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: environment.environment_id(),
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "sleep 30".to_owned()],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
    }
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

#[test]
fn the_store_is_write_ahead_logged_with_full_synchronisation() {
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
    // the consumer's own to close and is named in this task's handoff.
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
fn a_database_an_earlier_build_wrote_is_brought_forward_and_keeps_its_rows() {
    // KR-REQ-24.30. The fixture is a version 1 journal with one receipt, written by hand exactly
    // as the first build of this schema wrote it, and the migration has to reach it through every
    // step of the ladder without losing it.
    let path = journal_path("migration-fixture");
    write_version_one_fixture(&path);
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
    // Every object of the current schema is there afterwards, including the ones the last step
    // added.
    let tables = journal.table_names().expect("reads the schema");
    for expected in ["outbox", "outbox_cursors", "journal_gaps"] {
        assert!(tables.iter().any(|name| name == expected), "{expected}");
    }
    drop(journal);
    std::fs::remove_dir_all(path.parent().expect("a parent")).ok();
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
fn a_database_older_than_the_ladder_names_the_importer_rather_than_restoring_in_part() {
    let error = migration::plan(0).expect_err("version 0 is not migratable");
    assert_eq!(
        error,
        MigrationError::Unsupported {
            found: 0,
            oldest: migration::OLDEST_MIGRATABLE,
            importer: migration::IMPORTER,
        }
    );
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
    let connection = rusqlite::Connection::open(path).expect("creates the fixture");
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS receipts (
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
             );
             CREATE INDEX IF NOT EXISTS receipts_created_at ON receipts (created_at_ms);
             INSERT INTO schema_version (version) VALUES (1);",
        )
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
    history.append(&[b'x'; 32]);
    let cutoff_just_past = TimestampMs::new(kr_ipc::now_ms().get() + 1);
    let taken = history.apply_retention(
        OutputRetention::new(std::time::Duration::from_millis(1), 1 << 30, 1 << 30),
        32,
        cutoff_just_past,
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
        "a decoder built before the field refuses it, which is what the handoff records"
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_full_journal_fences_a_rich_mutation_while_raw_input_keeps_flowing() {
    // KR-ACC-028, for the parts this suite can drive: the journal is filled while the input lease
    // is live, raw input keeps being accepted, a rich mutation is refused before anything is
    // dispatched, and nothing is left behind for a replay to find. What it does not drive is an
    // approval, which needs the question ledger, or a native terminal application responding to
    // the bytes; the fixture's root shell is a `sleep`. Those are named in this task's handoff.
    let host = host().await;
    let mut client = cli(&host).await;

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
                    bytes: kr_protocol::scalars::Bytes::new(b"echo hello\n".to_vec()),
                },
            )
            .await
            .expect("reaches the worker")
            .map(|value| value.to_typed().expect("decodes"))
            .expect("the terminal still takes input with a full store");
        assert_eq!(written.sequence.get(), sequence);
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
}

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
    // KR-REQ-23.48 for `history.page`. The row also covers `events.subscribe`,
    // `events.snapshot` and `action.read`, and present view authority over the subject; those are
    // this host's own suites and are named in this task's handoff rather than claimed here.
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

#[cfg(not(unix))]
fn assert_owner_only(path: &std::path::Path) {
    assert!(std::fs::metadata(path).is_ok(), "{}", path.display());
}
