//! How long the host's answer to the application's question may wait, on the clock the session is
//! given.
//!
//! A reply the host owes the application waits behind a bracketed paste the person has open, so it
//! never lands inside what they are typing, and is dropped once it has waited two seconds: an
//! application that asked and has not been answered in that time has given up or moved on. Section 9
//! puts such a window on the continuous clock, the one a suspension moves and a set wall clock does
//! not, and the session is handed that clock with the rest of its time sources. These tests move it
//! by hand, in a session of this process, so nothing here waits for time to pass.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::clock::ManualSharedClock;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    AttachmentId, ConnectionId, EnvironmentId, InputLeaseEpoch, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::root::{
    CwdRevision, EditorBufferRevision, EditorKeymap, EditorLeaveReason, EditorState,
    PendingReaderInput, PromptGeneration, ReaderContext, ReaderRevision, RootEditorEnterParams,
    RootEditorLeaveParams,
};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_shell_integration::contract::events::{BridgeEvent, HooksActivated};
use kr_shell_integration::contract::fence::LeaseView;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_worker::action::time::{ManualWallClock, TimeSources};
use kr_worker::fence::FenceDriver;
use kr_worker::session::{InputBatch, Session, SessionConfig};

/// The person's bracketed paste, begun and not ended.
const PASTE_OPEN: &[u8] = b"\x1b[200~pasted";

/// The end of that paste.
const PASTE_CLOSE: &[u8] = b"\x1b[201~";

/// The application asks where the cursor is.
const QUESTION: &[u8] = b"\x1b[6n";

/// A session that waits, whose person holds the input lease.
struct Fixture {
    session: Session,
    session_id: SessionId,
    holder: AttachmentId,
    epoch: u64,
    sequence: u64,
    _host: kr_ipc::testing::TempHost,
}

impl Fixture {
    fn new(time: TimeSources) -> Self {
        Self::built(time, None)
    }

    /// A managed session whose root integration is registered and qualified as `kind`, with no
    /// bridge behind it: the fence machine is driven by the events the case sends it.
    fn managed(time: TimeSources, kind: ShellKind) -> Self {
        Self::built(time, Some(kind))
    }

    fn built(time: TimeSources, root: Option<ShellKind>) -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            display_number: DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script("sleep 120"),
            shell_mode: if root.is_some() {
                ShellMode::Managed
            } else {
                ShellMode::NativeCompat
            },
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: Some(host.environment().journal_database(session_id)),
            spool_directory: Some(host.environment().session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 8 * 1024 * 1024,
            resident_bytes: 1024 * 1024,
            time,
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut session = Session::open(config).expect("opens");
        session.launch().expect("launches");
        if let Some(kind) = root {
            session.install_fence(FenceDriver::new(
                session_id,
                LeaseView::unheld(InputLeaseEpoch::new(0)),
                Arc::new(kr_transport::clock::ManualClock::new()),
            ));
            let mut driver = session.fence_mut().expect("a driver");
            assert!(driver.registered(kind, "psreadline-2.3"));
            let _ = driver.bridge_event(
                RequestId::new(1),
                &BridgeEvent::HooksActivated(HooksActivated {
                    session_id,
                    prompt_generation: PromptGeneration::new(1),
                    modules: Vec::new(),
                }),
            );
            assert!(driver.phase().reports_ready());
        }
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let params = SessionAttachParams {
            session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        };
        let holder = AttachmentId::new(kr_ipc::new_uuid());
        session
            .attach(&params, params.requested.clone(), holder)
            .expect("attaches");
        let epoch = session
            .acquire_input(holder, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("the lease is granted")
            .lease
            .epoch
            .get();
        Self {
            session,
            session_id,
            holder,
            epoch,
            sequence: 0,
            _host: host,
        }
    }

    /// The person types.
    fn type_bytes(&mut self, bytes: &[u8]) {
        self.session
            .write_input(
                self.holder,
                self.epoch,
                self.sequence,
                bytes,
                None,
                Instant::now(),
            )
            .expect("the input is accepted");
        self.sequence += 1;
    }

    /// A second attachment takes the input lease from the person, and is told what the takeover
    /// discarded.
    fn seized_by_another(&mut self) -> u64 {
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let params = SessionAttachParams {
            session_id: self.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        };
        let next = AttachmentId::new(kr_ipc::new_uuid());
        self.session
            .attach(&params, params.requested.clone(), next)
            .expect("attaches");
        self.session
            .acquire_input(next, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("the lease is taken")
            .discarded_bytes
            .get()
    }

    /// The replies queued for the application since the last call.
    fn replies(&mut self) -> Vec<Vec<u8>> {
        self.session
            .take_pending_input()
            .into_iter()
            .filter_map(|batch| match batch {
                InputBatch::Reply { bytes, .. } => Some(bytes),
                _ => None,
            })
            .collect()
    }

    /// The application asks while the person has a paste open, and the person ends it once `waited`
    /// has passed on `clock`. Returns the replies the application is written, at the question and
    /// after the paste ends.
    fn asks_behind_a_paste(
        &mut self,
        clock: &ManualSharedClock,
        waited: Duration,
    ) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let _ = self.session.ingest_output(b"\x1b[?2004h");
        self.type_bytes(PASTE_OPEN);
        let _ = self.replies();
        let _ = self.session.ingest_output(QUESTION);
        let at_the_question = self.replies();
        clock.advance(waited);
        self.type_bytes(PASTE_CLOSE);
        self.session.pump_replies();
        (at_the_question, self.replies())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.session.force_close();
    }
}

fn manual() -> (ManualSharedClock, TimeSources) {
    let clock = ManualSharedClock::new();
    let mut time = TimeSources::system();
    time.continuous = Arc::new(clock.clone());
    (clock, time)
}

/// KR-REQ-08.48, KR-REQ-08.49: a reply held behind the person's open paste is written once the
/// paste ends, when it has waited less than two seconds of continuous time.
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_that_waited_under_two_seconds_is_written_when_the_paste_ends() {
    let (clock, time) = manual();
    let mut fixture = Fixture::new(time);
    let (at_the_question, after) =
        fixture.asks_behind_a_paste(&clock, Duration::from_millis(1_900));
    assert!(
        at_the_question.is_empty(),
        "the reply does not land inside the paste: {at_the_question:?}"
    );
    assert_eq!(after, vec![b"\x1b[1;1R".to_vec()]);
}

/// KR-REQ-08.48, KR-REQ-08.49, section 9: a reply that waited more than two seconds of continuous
/// time is dropped, not written into a conversation that has moved on. The wall clock does not
/// move in this test, and the session's decision follows the clock it was given.
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_that_waited_over_two_seconds_is_dropped_when_the_paste_ends() {
    let (clock, time) = manual();
    let mut fixture = Fixture::new(time);
    let (at_the_question, after) =
        fixture.asks_behind_a_paste(&clock, Duration::from_millis(2_100));
    assert!(at_the_question.is_empty());
    assert!(after.is_empty(), "the reply expired: {after:?}");
}

/// Section 9: a wall clock stepped an hour forward while a reply waits does not drop it. The reply
/// has waited half a second of continuous time, and a lane that measured the wait on the wall clock
/// would read an hour and drop it.
#[tokio::test(flavor = "multi_thread")]
async fn a_wall_clock_stepped_forward_does_not_drop_a_reply_that_has_waited_half_a_second() {
    let (clock, mut time) = manual();
    let wall = ManualWallClock::new(1_790_000_000_000);
    time.wall = Arc::new(wall.clone());
    let mut fixture = Fixture::new(time);
    let _ = fixture.session.ingest_output(b"\x1b[?2004h");
    fixture.type_bytes(PASTE_OPEN);
    let _ = fixture.replies();
    let _ = fixture.session.ingest_output(QUESTION);
    wall.set(1_790_000_000_000 + 3_600_000);
    clock.advance(Duration::from_millis(500));
    fixture.type_bytes(PASTE_CLOSE);
    fixture.session.pump_replies();
    assert_eq!(fixture.replies(), vec![b"\x1b[1;1R".to_vec()]);
}

/// Section 9: and a wall clock stepped an hour back does not keep a reply past its two seconds.
/// The reply has waited 2.1 seconds of continuous time, and a lane that measured the wait on the
/// wall clock would read a negative wait and keep it.
#[tokio::test(flavor = "multi_thread")]
async fn a_wall_clock_stepped_back_does_not_keep_a_reply_that_has_waited_over_two_seconds() {
    let (clock, mut time) = manual();
    let wall = ManualWallClock::new(1_790_000_000_000);
    time.wall = Arc::new(wall.clone());
    let mut fixture = Fixture::new(time);
    let _ = fixture.session.ingest_output(b"\x1b[?2004h");
    fixture.type_bytes(PASTE_OPEN);
    let _ = fixture.replies();
    let _ = fixture.session.ingest_output(QUESTION);
    wall.set(1_790_000_000_000 - 3_600_000);
    clock.advance(Duration::from_millis(2_100));
    fixture.type_bytes(PASTE_CLOSE);
    fixture.session.pump_replies();
    assert!(fixture.replies().is_empty(), "the reply expired");
}

/// KR-REQ-08.48: a takeover discards the previous holder's keystrokes that were not written and
/// reports how many; the host's own answer waiting beside them is not the holder's, so it is not in
/// that count and it is not discarded: the application still gets what it asked for.
#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_counts_the_holders_keystrokes_and_leaves_the_hosts_answer_alone() {
    let (_clock, time) = manual();
    let mut fixture = Fixture::new(time);
    fixture.type_bytes(b"abc");
    let _ = fixture.session.ingest_output(QUESTION);

    let discarded = fixture.seized_by_another();

    assert_eq!(
        discarded, 3,
        "the three keystrokes, and none of the six bytes of the answer"
    );
    assert_eq!(
        fixture.replies(),
        vec![b"\x1b[1;1R".to_vec()],
        "the answer is still queued for the application"
    );
}

// --------------------------------------------------------------------------------------------
// The root editor's cursor question.
// --------------------------------------------------------------------------------------------

/// The application asks for its primary device attributes.
const DEVICE_ATTRIBUTES: &[u8] = b"\x1b[c";

/// And for its secondary ones.
const SECONDARY_ATTRIBUTES: &[u8] = b"\x1b[>c";

/// The host's answer to the first, and to the second.
const DEVICE_ATTRIBUTES_REPLY: &[u8] = b"\x1b[?62;22c";
const SECONDARY_ATTRIBUTES_REPLY: &[u8] = b"\x1b[>41;1;0c";

/// The host's answer to a question about the cursor of a screen nothing has drawn on.
const CURSOR_REPORT: &[u8] = b"\x1b[1;1R";

fn editor_state() -> EditorState {
    EditorState {
        buffer_empty: true,
        buffer_revision: EditorBufferRevision::new(1),
        keymap: EditorKeymap::Emacs,
        pending: PendingReaderInput::NONE,
    }
}

impl Fixture {
    /// The root editor reports one of its events, and the session carries out what comes of it.
    fn editor_reports(&mut self, event: BridgeEvent) {
        let _ = self
            .session
            .stimulate_fence(|driver| driver.bridge_event(RequestId::new(2), &event))
            .expect("a driver");
    }

    /// The root editor starts a read.
    fn editor_enters(&mut self) {
        self.editor_reports(BridgeEvent::EditorEnter(RootEditorEnterParams {
            session_id: self.session_id,
            root_process: kr_ipc::identity::current_process_start_identity().expect("this process"),
            prompt_generation: PromptGeneration::new(1),
            reader_revision: ReaderRevision::new(1),
            reader_context: ReaderContext::Primary,
            editor: editor_state(),
            cwd_revision: CwdRevision::new(1),
        }));
    }

    /// The root editor reports itself idle, which it does once it is reading keys.
    #[cfg(not(windows))]
    fn editor_idles(&mut self) {
        use kr_protocol::root::KeyQueueSnapshot;
        use kr_shell_integration::contract::events::ReaderIdle;

        self.editor_reports(BridgeEvent::ReaderIdle(ReaderIdle {
            session_id: self.session_id,
            prompt_generation: PromptGeneration::new(1),
            reader_revision: ReaderRevision::new(1),
            reader_context: ReaderContext::Primary,
            snapshot: KeyQueueSnapshot::drained(),
            editor: editor_state(),
            cwd_revision: CwdRevision::new(1),
        }));
    }

    /// The root editor returns a line.
    fn editor_leaves(&mut self) {
        self.editor_reports(BridgeEvent::EditorLeave(RootEditorLeaveParams {
            session_id: self.session_id,
            prompt_generation: PromptGeneration::new(1),
            reader_revision: ReaderRevision::new(1),
            reason: EditorLeaveReason::CommandAccepted,
        }));
    }

    /// The application writes `output`, which asks the questions in it.
    fn application_writes(&mut self, output: &[u8]) {
        let _ = self.session.ingest_output(output);
    }

    /// Everything queued for the terminal since the last call, in the order it is written: what the
    /// host answers and what the person typed.
    #[cfg(not(windows))]
    fn queued(&mut self) -> Vec<(&'static str, Vec<u8>)> {
        self.session
            .take_pending_input()
            .into_iter()
            .filter_map(|batch| match batch {
                InputBatch::Reply { bytes, .. } => Some(("reply", bytes)),
                InputBatch::Lease { bytes, .. } => Some(("keys", bytes)),
                InputBatch::LeaseChanged => None,
            })
            .collect()
    }
}

/// A fixture with a root PowerShell editor at a prompt, on a clock the case moves.
fn at_a_powershell_prompt() -> (ManualSharedClock, Fixture) {
    let (clock, time) = manual();
    let mut fixture = Fixture::managed(time, ShellKind::PowerShell);
    fixture.editor_enters();
    (clock, fixture)
}

/// KR-REQ-08.48, KR-REQ-08.49: the PowerShell editor reads the reply to its question about the
/// cursor from the same input as every other byte, and joins into it any byte that comes ahead of
/// it. So when answers to earlier questions are waiting with the cursor report, the cursor report is
/// written first and the others follow it, in the order of their questions. A program that asks
/// nothing of the kind sees no change: once the report is written the order is the questions'.
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn a_cursor_report_is_written_ahead_of_the_answers_to_the_questions_before_it() {
    let (_clock, mut fixture) = at_a_powershell_prompt();
    fixture.application_writes(&[DEVICE_ATTRIBUTES, SECONDARY_ATTRIBUTES, b"\x1b[6n"].concat());
    assert_eq!(
        fixture.replies(),
        vec![
            CURSOR_REPORT.to_vec(),
            DEVICE_ATTRIBUTES_REPLY.to_vec(),
            SECONDARY_ATTRIBUTES_REPLY.to_vec()
        ]
    );

    fixture.application_writes(&[DEVICE_ATTRIBUTES, b"\x1b[6n"].concat());
    assert_eq!(
        fixture.replies(),
        vec![DEVICE_ATTRIBUTES_REPLY.to_vec(), CURSOR_REPORT.to_vec()],
        "the editor has its report, and the answers keep the order of their questions again"
    );
}

/// KR-REQ-08.48, KR-REQ-08.49: an answer the host owes after the editor began its read waits for the
/// editor's cursor report however long that takes, and is then written, not dropped.
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_produced_before_the_cursor_question_waits_for_its_report() {
    let (clock, mut fixture) = at_a_powershell_prompt();
    fixture.application_writes(DEVICE_ATTRIBUTES);
    assert!(
        fixture.replies().is_empty(),
        "the answer would land ahead of the report the editor is waiting for"
    );
    assert_eq!(
        fixture
            .session
            .fence()
            .expect("a driver")
            .host_reply_bytes(),
        0
    );

    // The editor's question is asked long after, as it is on a machine that is busy.
    clock.advance(Duration::from_secs(10));
    fixture.application_writes(b"\x1b[6n");
    assert_eq!(
        fixture.replies(),
        vec![CURSOR_REPORT.to_vec(), DEVICE_ATTRIBUTES_REPLY.to_vec()],
        "the report first, and the answer it kept behind it, which did not age while it waited"
    );
}

/// KR-REQ-08.49: a hold that ends because the editor is reading keys, or has left, writes what it
/// kept; and what it kept has not been given the time it waited back, so an answer that is by then
/// older than the lane's limit is dropped, as one is behind a paste: it would reach a program that
/// did not ask.
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn a_hold_that_ends_without_the_cursor_report_writes_what_is_young_and_drops_what_is_old() {
    let (_clock, mut fixture) = at_a_powershell_prompt();
    fixture.application_writes(DEVICE_ATTRIBUTES);
    assert!(fixture.replies().is_empty());
    fixture.editor_idles();
    assert_eq!(
        fixture.replies(),
        vec![DEVICE_ATTRIBUTES_REPLY.to_vec()],
        "the editor is reading keys, so nothing is owed a report any more"
    );

    let (_clock, mut fixture) = at_a_powershell_prompt();
    fixture.application_writes(DEVICE_ATTRIBUTES);
    assert!(fixture.replies().is_empty());
    fixture.editor_leaves();
    assert_eq!(fixture.replies(), vec![DEVICE_ATTRIBUTES_REPLY.to_vec()]);

    let (clock, mut fixture) = at_a_powershell_prompt();
    fixture.application_writes(DEVICE_ATTRIBUTES);
    assert!(fixture.replies().is_empty());
    clock.advance(Duration::from_millis(2_100));
    fixture.editor_idles();
    assert!(
        fixture.replies().is_empty(),
        "an answer that old is not handed to whatever reads next"
    );
}

/// KR-REQ-08.48: the cursor report is also written ahead of an answer that already left the lane
/// and waits at the end of the queue for the terminal's writer. A key the person typed behind that
/// answer keeps the report behind both (the next case).
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn a_cursor_report_is_written_ahead_of_an_answer_still_waiting_for_the_writer() {
    let (_clock, time) = manual();
    let mut fixture = Fixture::managed(time, ShellKind::PowerShell);
    // Asked before the editor began its read, and queued for the writer, which has not taken it.
    fixture.application_writes(DEVICE_ATTRIBUTES);
    fixture.editor_enters();
    fixture.application_writes(b"\x1b[6n");
    assert_eq!(
        fixture.replies(),
        vec![CURSOR_REPORT.to_vec(), DEVICE_ATTRIBUTES_REPLY.to_vec()]
    );
}

/// KR-REQ-08.48: the cursor report passes the answers that wait at the end of the queue for the
/// writer, and no further: a key the person typed behind a waiting answer keeps its place ahead of
/// the report, which a key does not harm (the runtime gives bytes before an escape back as keys).
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn a_cursor_report_stays_behind_the_keys_that_were_queued_after_a_waiting_answer() {
    let (_clock, time) = manual();
    let mut fixture = Fixture::managed(time, ShellKind::PowerShell);
    // Asked before the editor began its read, and queued for the writer, which has not taken it,
    // with a key of the person's behind it.
    fixture.application_writes(DEVICE_ATTRIBUTES);
    fixture.type_bytes(b"x");
    fixture.editor_enters();
    fixture.application_writes(b"\x1b[6n");
    assert_eq!(
        fixture.queued(),
        vec![
            ("reply", DEVICE_ATTRIBUTES_REPLY.to_vec()),
            ("keys", b"x".to_vec()),
            ("reply", CURSOR_REPORT.to_vec())
        ]
    );
}

/// KR-REQ-08.49: a hold that ended while the gate was shut is over. The editor is owed a report again
/// at its next read, and the time between the two reads is not time the report gives back to the
/// answer the first hold kept: that answer has waited past its deadline by then, and is dropped
/// instead of reaching the next reader.
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_kept_for_one_read_is_not_given_the_time_before_the_next_to_reach_it() {
    let (clock, mut fixture) = at_a_powershell_prompt();
    fixture.application_writes(b"\x1b[?2004h");
    fixture.application_writes(DEVICE_ATTRIBUTES);
    assert!(fixture.replies().is_empty(), "kept for the cursor report");

    // The person's paste shuts the gate, the editor leaves, and the next read begins; the paste ends.
    fixture.type_bytes(PASTE_OPEN);
    let _ = fixture.replies();
    clock.advance(Duration::from_millis(2_500));
    fixture.editor_leaves();
    fixture.editor_enters();
    fixture.type_bytes(PASTE_CLOSE);
    fixture.session.pump_replies();
    fixture.application_writes(b"\x1b[6n");
    assert_eq!(
        fixture.replies(),
        vec![CURSOR_REPORT.to_vec()],
        "the answer is not handed to the second read"
    );
}

/// KR-REQ-08.48: two cursor reports asked in one write keep their order, and both stay behind a key
/// and ahead of an answer that waits at the end of the queue.
#[cfg(not(windows))]
#[tokio::test(flavor = "multi_thread")]
async fn two_cursor_reports_keep_their_order_behind_a_key_and_ahead_of_the_answers_after_it() {
    let (_clock, time) = manual();
    let mut fixture = Fixture::managed(time, ShellKind::PowerShell);
    // A waiting answer, the person's key behind it, and another waiting answer behind that.
    fixture.application_writes(DEVICE_ATTRIBUTES);
    fixture.type_bytes(b"x");
    fixture.application_writes(SECONDARY_ATTRIBUTES);
    fixture.editor_enters();
    // Two questions about the cursor, with the cursor moved between them.
    fixture.application_writes(b"\x1b[6n\x1b[2;5H\x1b[6n");
    assert_eq!(
        fixture.queued(),
        vec![
            ("reply", DEVICE_ATTRIBUTES_REPLY.to_vec()),
            ("keys", b"x".to_vec()),
            ("reply", CURSOR_REPORT.to_vec()),
            ("reply", b"\x1b[2;5R".to_vec()),
            ("reply", SECONDARY_ATTRIBUTES_REPLY.to_vec())
        ]
    );
}

/// The rule is the PowerShell editor's alone. A Zsh or Bash editor asks the terminal nothing about
/// the cursor, and an answer it is sent is read as keys whenever it arrives; Fish asks, with two
/// other questions in one write, and reads the three answers in the order of the questions. So
/// nothing is held for any of them; and no session holds an answer while no editor reads.
#[tokio::test(flavor = "multi_thread")]
async fn answers_keep_the_order_of_their_questions_wherever_no_cursor_report_is_owed() {
    let (_clock, time) = manual();
    let mut zsh = Fixture::managed(time, ShellKind::Zsh);
    zsh.editor_enters();
    zsh.application_writes(&[DEVICE_ATTRIBUTES, b"\x1b[6n"].concat());
    assert_eq!(
        zsh.replies(),
        vec![DEVICE_ATTRIBUTES_REPLY.to_vec(), CURSOR_REPORT.to_vec()]
    );

    let (_clock, time) = manual();
    let mut powershell = Fixture::managed(time, ShellKind::PowerShell);
    powershell.application_writes(&[DEVICE_ATTRIBUTES, b"\x1b[6n"].concat());
    assert_eq!(
        powershell.replies(),
        vec![DEVICE_ATTRIBUTES_REPLY.to_vec(), CURSOR_REPORT.to_vec()],
        "no editor reads, so a program that asks both is answered in order"
    );

    powershell.editor_enters();
    powershell.editor_leaves();
    powershell.application_writes(&[SECONDARY_ATTRIBUTES, b"\x1b[6n"].concat());
    assert_eq!(
        powershell.replies(),
        vec![SECONDARY_ATTRIBUTES_REPLY.to_vec(), CURSOR_REPORT.to_vec()],
        "the editor has left, so a program the line started is answered in order"
    );
}

/// The Windows console has no cursor question in its input, so a PowerShell root there holds
/// nothing.
#[cfg(windows)]
#[tokio::test(flavor = "multi_thread")]
async fn a_powershell_root_on_windows_holds_no_answer_for_a_cursor_report() {
    let (_clock, mut fixture) = at_a_powershell_prompt();
    fixture.application_writes(&[DEVICE_ATTRIBUTES, b"\x1b[6n"].concat());
    assert_eq!(
        fixture.replies(),
        vec![DEVICE_ATTRIBUTES_REPLY.to_vec(), CURSOR_REPORT.to_vec()]
    );
}
