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
use kr_protocol::ids::{AttachmentId, ConnectionId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::action::time::{ManualWallClock, TimeSources};
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
    holder: AttachmentId,
    epoch: u64,
    sequence: u64,
    _host: kr_ipc::testing::TempHost,
}

impl Fixture {
    fn new(time: TimeSources) -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            display_number: DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script("sleep 120"),
            shell_mode: ShellMode::NativeCompat,
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
