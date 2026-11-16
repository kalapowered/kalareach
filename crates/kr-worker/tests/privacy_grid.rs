//! Privacy mode and the rows of the canonical grid above the live screen.
//!
//! The host's own terminal scrolls above the live page and is served those rows from the grid. Under
//! privacy mode the grid holds none of them: it gives up what it held when privacy mode went on,
//! keeps none while it is on, and gives up each row that was on the screen when it went off as that
//! row leaves. The live screen is left alone, and a paired device, which is shown the live screen
//! and nothing above it, is told the same before and after.
//!
//! Every case runs a session of this process with a shell that only waits, so the output is what a
//! case gives it and no step waits for anything: a scroll is answered when it is asked for.

use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, TerminalPresentationMode,
    ViewportPosition,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{AttachmentId, SessionEpoch, SessionId};
use kr_protocol::projection::{ProjectedBuffer, ProjectionEvent};
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::output::{OutputDelivery, OutputStream};
use kr_worker::privacy::PrivacyGeneration;
use kr_worker::pty::ShellCommand;
use kr_worker::session::{Session, SessionConfig};

/// The lines a run prints, and the rows of the screen they scroll over.
const LINES: usize = 60;
const ROWS: u64 = 24;

/// The first line of a run that is still on the live screen when the run has ended: the screen
/// holds the last lines and the blank row the cursor is on.
const ON_SCREEN: usize = LINES - (ROWS as usize - 1);

const ENTER_ALTERNATE: &str = "\x1b[?1049h";
const LEAVE_ALTERNATE: &str = "\x1b[?1049l";

/// The same buffer switch without a saved cursor: a screen that the host can restore completely, so
/// the host's own terminal is served the raw stream while the program shows.
const ENTER_ALTERNATE_PLAIN: &str = "\x1b[?1047h";
const LEAVE_ALTERNATE_PLAIN: &str = "\x1b[?1047l";

/// The session's own size.
fn dimensions() -> Dimensions {
    Dimensions::new(80, ROWS)
}

/// The window both terminals look through: a projection of the bottom of the live screen, which
/// moves above the live page when it is asked to.
const WINDOW_ROWS: u64 = 10;

fn window() -> Dimensions {
    Dimensions::new(40, WINDOW_ROWS)
}

/// The window that shows the last rows of the live screen.
fn bottom() -> Option<ViewportPosition> {
    Some(ViewportPosition::Line(U64::new(ROWS - WINDOW_ROWS)))
}

fn config(temp: &kr_ipc::testing::TempHost, session_id: SessionId) -> SessionConfig {
    let environment = temp.environment();
    let journal = environment.journal_database(session_id);
    std::fs::create_dir_all(journal.parent().expect("a parent")).expect("the journal directory");
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
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        worker_endpoint: None,
        desktop: DesktopBinding::none(),
        dimensions: dimensions(),
        journal_path: Some(journal),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
    }
}

/// The lines `word 0` to `word 59`, each ended as a terminal ends it.
fn run(word: &str) -> String {
    (0..LINES)
        .map(|line| format!("{word} {line}\r\n"))
        .collect()
}

/// A session, the host's own terminal and a paired device beside it.
///
/// The device is shown the live screen and nothing above it, as a forwarded caller is.
struct Rig {
    session: Session,
    host: AttachmentId,
    host_stream: OutputStream,
    device: AttachmentId,
    device_stream: OutputStream,
    session_id: SessionId,
    // Declared last: the directory is removed after every field above has let go of its files.
    temp: kr_ipc::testing::TempHost,
}

impl Rig {
    fn open() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let session = Session::open(config(&temp, session_id)).expect("opens the session");
        Self::around(temp, session_id, session)
    }

    /// The same session, opened again over the stores it left.
    fn reopened(self) -> Self {
        let Self {
            session,
            temp,
            session_id,
            ..
        } = self;
        drop(session);
        let session = Session::open(config(&temp, session_id)).expect("opens the session again");
        Self::around(temp, session_id, session)
    }

    fn around(
        temp: kr_ipc::testing::TempHost,
        session_id: SessionId,
        mut session: Session,
    ) -> Self {
        let (host, mut host_stream) = attach(&mut session, session_id);
        let (device, mut device_stream) = attach(&mut session, session_id);
        session.narrow_content(device, kr_worker::render::Scope::LiveScreen);
        // Both start at the bottom of the live screen, so that a window that is put on the top of
        // it is a window that moved and is installed.
        for (attachment, stream) in [(host, &mut host_stream), (device, &mut device_stream)] {
            session
                .viewport(attachment, window(), bottom(), 0)
                .expect("the bottom of the live screen");
            drain(stream);
        }
        Self {
            session,
            host,
            host_stream,
            device,
            device_stream,
            temp,
            session_id,
        }
    }

    fn print(&mut self, bytes: &str) {
        let _ = self.session.ingest_output(bytes.as_bytes());
    }

    fn enable(&mut self) {
        self.session
            .enable_privacy(PrivacyGeneration::new(1), &mut [])
            .expect("privacy mode goes on");
        assert!(self.session.privacy().is_enabled());
    }

    fn disable(&mut self) {
        self.session
            .disable_privacy(PrivacyGeneration::new(2))
            .expect("privacy mode goes off")
            .expect("it was on");
        assert!(!self.session.privacy().is_enabled());
    }

    /// What the host's own terminal is shown when it scrolls `rows` above the live page, and is
    /// then back on the bottom of the live screen. The device is refused the same scroll.
    fn scrolled(&mut self, rows: u64) -> Vec<String> {
        drain(&mut self.host_stream);
        self.session
            .viewport(
                self.host,
                window(),
                Some(ViewportPosition::Above(U64::new(rows))),
                0,
            )
            .expect("the host's terminal may look above the live page");
        let installed = installed_rows(drain(&mut self.host_stream));
        self.session
            .viewport(self.host, window(), bottom(), 0)
            .expect("and may come back");
        drain(&mut self.host_stream);

        let refused = self
            .session
            .viewportable(
                self.device,
                window(),
                Some(ViewportPosition::Above(U64::new(rows))),
            )
            .expect_err("a device shown the live screen cannot look above it");
        assert_eq!(refused.code(), ErrorCode::UnsupportedCapability);
        installed
    }

    /// What the host's terminal and the device are each drawn of the bottom of the live screen.
    fn live_screens(&mut self) -> (Vec<String>, Vec<String>) {
        let mut seen = Vec::new();
        for (attachment, stream) in [
            (self.host, &mut self.host_stream),
            (self.device, &mut self.device_stream),
        ] {
            self.session
                .viewport(attachment, window(), bottom(), 0)
                .expect("the bottom of the live screen");
            drain(stream);
            self.session
                .install_projection(attachment)
                .expect("the screen is installed");
            let rows = installed_rows(drain(stream));
            assert!(!rows.is_empty(), "the live screen is drawn");
            seen.push(rows);
        }
        let device = seen.pop().expect("the device's rows");
        let host = seen.pop().expect("the host's rows");
        (host, device)
    }
}

fn attach(session: &mut Session, session_id: SessionId) -> (AttachmentId, OutputStream) {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let params = SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(window()),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    };
    let id = AttachmentId::new(kr_ipc::new_uuid());
    session
        .attach(&params, params.requested.clone(), id)
        .expect("attaches");
    session.join(id).expect("joins");
    let stream = session.subscribe(id).expect("subscribes");
    session.install_projection(id).expect("installs");
    (id, stream)
}

/// Everything queued on a stream, as the events of a projection and nothing else.
fn drain(stream: &mut OutputStream) -> Vec<ProjectionEvent> {
    let mut events = Vec::new();
    while let Some(delivery) = stream.try_recv() {
        stream.written(delivery.len());
        if let OutputDelivery::Projection { event, .. } = delivery {
            events.push(*event);
        }
    }
    events
}

/// The text of every primary-buffer row of the last screen the events installed, oldest first.
fn installed_rows(events: Vec<ProjectionEvent>) -> Vec<String> {
    let mut rows: Vec<(u64, String)> = Vec::new();
    for event in events {
        match event {
            ProjectionEvent::Snapshot(_) | ProjectionEvent::Reset(_) => rows.clear(),
            ProjectionEvent::Rows(page) if page.buffer == ProjectedBuffer::Primary => {
                for row in page.rows {
                    let text = row.runs.iter().map(|run| run.text.as_str()).collect();
                    rows.push((row.row.get(), text));
                }
            }
            _ => {}
        }
    }
    rows.sort_by_key(|(id, _)| *id);
    rows.dedup_by_key(|(id, _)| *id);
    rows.into_iter().map(|(_, text)| text).collect()
}

/// The numbers of the rows that read `word <number>`.
fn numbers(rows: &[String], word: &str) -> Vec<usize> {
    rows.iter()
        .filter_map(|row| row.trim().strip_prefix(word)?.trim().parse().ok())
        .collect()
}

/// Whether a scroll shows nothing of `word` but rows that were on the live screen when the run
/// ended, which privacy mode leaves where they are.
fn shows_only_the_screen(rows: &[String], word: &str) -> bool {
    numbers(rows, word)
        .iter()
        .all(|number| *number >= ON_SCREEN)
}

/// The control of every case: without privacy mode the same scroll reaches the first row.
fn reaches_the_first_row(rows: &[String], word: &str) -> bool {
    numbers(rows, word).contains(&0)
}

#[test]
fn rows_printed_before_privacy_mode_are_not_scrolled_to_after_it_goes_on() {
    let mut rig = Rig::open();
    rig.print(&run("before"));
    let live = rig.live_screens();
    assert!(
        reaches_the_first_row(&rig.scrolled(1000), "before"),
        "without privacy mode a scroll reaches the oldest row"
    );

    rig.enable();

    let scrolled = rig.scrolled(1000);
    assert!(
        !numbers(&scrolled, "before").is_empty(),
        "the live screen is still there to be scrolled over"
    );
    assert!(
        shows_only_the_screen(&scrolled, "before"),
        "a scroll shows no row from above the live page: {scrolled:?}"
    );
    assert_eq!(
        rig.live_screens(),
        live,
        "the host's screen and the device's are drawn by the same bytes as before"
    );
}

#[test]
fn rows_printed_while_privacy_mode_is_on_are_not_scrolled_to() {
    let mut rig = Rig::open();
    rig.print(&run("before"));
    rig.enable();
    rig.print(&run("while"));

    let scrolled = rig.scrolled(1000);
    assert!(
        !numbers(&scrolled, "while").is_empty(),
        "the scroll is answered with the live screen"
    );
    assert!(
        numbers(&scrolled, "before").is_empty(),
        "the rows that were on the screen have left it and are not kept: {scrolled:?}"
    );
    assert!(
        shows_only_the_screen(&scrolled, "while"),
        "no row printed while privacy mode is on is above the live page: {scrolled:?}"
    );
    assert_eq!(rig.session.retained_output_bytes(), 0);
}

#[test]
fn nothing_comes_back_when_privacy_mode_goes_off_and_new_rows_are_kept() {
    let mut rig = Rig::open();
    rig.print(&run("before"));
    rig.enable();
    rig.print(&run("while"));
    rig.disable();

    let scrolled = rig.scrolled(1000);
    assert!(!numbers(&scrolled, "while").is_empty(), "{scrolled:?}");
    assert!(numbers(&scrolled, "before").is_empty(), "{scrolled:?}");
    assert!(shows_only_the_screen(&scrolled, "while"), "{scrolled:?}");

    rig.print(&run("after"));
    let scrolled = rig.scrolled(1000);
    assert!(
        numbers(&scrolled, "before").is_empty() && numbers(&scrolled, "while").is_empty(),
        "the rows that were on the screen when privacy mode went off are not kept: {scrolled:?}"
    );
    let scrolled = rig.scrolled(30);
    assert!(
        numbers(&scrolled, "after")
            .iter()
            .any(|number| *number < ON_SCREEN),
        "rows printed afterwards are kept and can be scrolled to: {scrolled:?}"
    );
}

#[test]
fn a_session_opened_under_privacy_mode_keeps_no_rows() {
    let mut rig = Rig::open();
    rig.enable();
    let mut rig = rig.reopened();
    assert!(rig.session.privacy().is_enabled());

    rig.print(&run("while"));

    let scrolled = rig.scrolled(1000);
    assert!(!numbers(&scrolled, "while").is_empty());
    assert!(shows_only_the_screen(&scrolled, "while"), "{scrolled:?}");

    // Privacy mode goes off: the rows of the interval that were on the screen are given up as they
    // leave it, and rows after them are kept.
    rig.disable();
    rig.print(&run("after"));
    let scrolled = rig.scrolled(1000);
    assert!(
        numbers(&scrolled, "while").is_empty(),
        "no earlier row is kept: {scrolled:?}"
    );
    assert!(
        numbers(&rig.scrolled(30), "after")
            .iter()
            .any(|number| *number < ON_SCREEN),
        "rows printed after it are kept"
    );
}

#[test]
fn a_session_that_cannot_read_its_state_keeps_no_rows_until_it_reads_off() {
    let rig = Rig::open();
    let (temp, session_id) = (rig.temp, rig.session_id);
    drop(rig.session);
    let journal = temp.environment().journal_database(session_id);
    rusqlite::Connection::open(&journal)
        .expect("the journal")
        .execute(
            "UPDATE privacy SET generation = 'unreadable' WHERE id = 1",
            [],
        )
        .expect("the record is made unreadable");
    let session = Session::open(config(&temp, session_id)).expect("opens again");
    let mut rig = Rig::around(temp, session_id, session);

    rig.print(&run("unknown"));
    let scrolled = rig.scrolled(1000);
    assert!(!numbers(&scrolled, "unknown").is_empty());
    assert!(
        shows_only_the_screen(&scrolled, "unknown"),
        "a session that cannot say keeps none: {scrolled:?}"
    );

    // The record is put right and reads as off: rows are kept again from that moment.
    rusqlite::Connection::open(&journal)
        .expect("the journal")
        .execute(
            "UPDATE privacy SET generation = 0, enabled = 0 WHERE id = 1",
            [],
        )
        .expect("the record is put right");
    rig.session.collect_expired();
    rig.print(&run("known"));
    let scrolled = rig.scrolled(30);
    assert!(
        numbers(&scrolled, "known")
            .iter()
            .any(|number| *number < ON_SCREEN),
        "rows printed after it reads off are kept: {scrolled:?}"
    );
    assert!(
        numbers(&rig.scrolled(1000), "unknown").is_empty(),
        "no row printed while it could not say comes back"
    );
}

#[test]
fn a_session_that_cannot_read_its_state_keeps_none_when_the_retry_reads_it_on() {
    let rig = Rig::open();
    let (temp, session_id) = (rig.temp, rig.session_id);
    drop(rig.session);
    let journal = temp.environment().journal_database(session_id);
    rusqlite::Connection::open(&journal)
        .expect("the journal")
        .execute(
            "UPDATE privacy SET generation = 'unreadable' WHERE id = 1",
            [],
        )
        .expect("the record is made unreadable");
    let session = Session::open(config(&temp, session_id)).expect("opens again");
    let mut rig = Rig::around(temp, session_id, session);
    rig.print(&run("unknown"));

    // The record reads as on: the rows stay out of the grid.
    rusqlite::Connection::open(&journal)
        .expect("the journal")
        .execute(
            "UPDATE privacy SET generation = 1, enabled = 1 WHERE id = 1",
            [],
        )
        .expect("the record is put right");
    rig.session.collect_expired();
    rig.print(&run("known"));

    let scrolled = rig.scrolled(1000);
    assert!(!numbers(&scrolled, "known").is_empty(), "{scrolled:?}");
    assert!(
        numbers(&scrolled, "unknown").is_empty(),
        "no earlier row is kept: {scrolled:?}"
    );
    assert!(shows_only_the_screen(&scrolled, "known"), "{scrolled:?}");
}

#[test]
fn rows_given_up_while_a_full_screen_program_runs_are_gone_when_it_leaves() {
    let mut rig = Rig::open();
    rig.print(&run("before"));
    rig.print(ENTER_ALTERNATE);
    rig.enable();
    rig.print(&format!("{LEAVE_ALTERNATE}{}", run("while")));

    let scrolled = rig.scrolled(1000);
    assert!(
        !numbers(&scrolled, "while").is_empty(),
        "the scroll is answered with the live screen"
    );
    assert!(
        numbers(&scrolled, "before").is_empty(),
        "no row from before privacy mode went on is above the live page: {scrolled:?}"
    );
    assert!(shows_only_the_screen(&scrolled, "while"), "{scrolled:?}");
}

#[test]
fn privacy_mode_going_off_inside_a_full_screen_program_keeps_no_earlier_row() {
    let mut rig = Rig::open();
    rig.print(&run("before"));
    rig.print(ENTER_ALTERNATE);
    rig.enable();
    rig.disable();
    rig.print(&format!("{LEAVE_ALTERNATE}{}", run("after")));

    let scrolled = rig.scrolled(1000);
    assert!(
        numbers(&scrolled, "before").is_empty(),
        "no row from before comes back, those on the screen included: {scrolled:?}"
    );
    assert!(!numbers(&scrolled, "after").is_empty(), "{scrolled:?}");
    let scrolled = rig.scrolled(30);
    assert!(
        numbers(&scrolled, "after")
            .iter()
            .any(|number| *number < ON_SCREEN),
        "rows printed afterwards are kept: {scrolled:?}"
    );
}

#[test]
fn a_window_above_the_live_page_when_privacy_mode_goes_on_is_installed_again() {
    let mut rig = Rig::open();
    rig.print(&run("before"));
    drain(&mut rig.host_stream);
    rig.session
        .viewport(
            rig.host,
            window(),
            Some(ViewportPosition::Above(U64::new(30))),
            0,
        )
        .expect("the host's terminal looks above the live page");
    let held = installed_rows(drain(&mut rig.host_stream));
    assert!(
        numbers(&held, "before")
            .iter()
            .any(|number| *number < ON_SCREEN),
        "the window is above the live page: {held:?}"
    );

    rig.enable();
    rig.print("next\r\n");

    let events = drain(&mut rig.host_stream);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, ProjectionEvent::Snapshot(_))),
        "the window is installed again"
    );
    let installed = installed_rows(events);
    assert!(!numbers(&installed, "before").is_empty(), "{installed:?}");
    assert!(
        shows_only_the_screen(&installed, "before"),
        "and what it holds is the live screen: {installed:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// A resize while a full-screen program shows the alternate buffer.
//
// After `Session::resize` the host's own terminal is told what it needs to draw the screen from the
// session in one of two ways. A terminal that is served the raw stream (the owner of the size, of
// exactly the screen's size, with a qualified profile) is told to resynchronise and asks for its
// screen, which is `Session::restoration`: the bytes that put its terminal into the current screen,
// with the rows of the primary buffer that the program has covered. Any other terminal is
// installed again in band, with a snapshot and its pages. Neither is handed a row from above the
// screen, but the primary buffer's own screen can hold rows that a taller resize pulls in from
// above it, so both are read right after the resize and again when the program has left.
// ---------------------------------------------------------------------------------------------

/// What a stream was sent: its projection events, how many times it was told to resynchronise, and
/// how many deliveries were bytes or a rendered screen.
struct Sent {
    events: Vec<ProjectionEvent>,
    resyncs: usize,
    stream_deliveries: usize,
}

fn sent(stream: &mut OutputStream) -> Sent {
    let mut sent = Sent {
        events: Vec::new(),
        resyncs: 0,
        stream_deliveries: 0,
    };
    while let Some(delivery) = stream.try_recv() {
        stream.written(delivery.len());
        match delivery {
            OutputDelivery::Projection { event, .. } => sent.events.push(*event),
            OutputDelivery::Resync(_) => sent.resyncs += 1,
            OutputDelivery::Bytes { .. } | OutputDelivery::Screen { .. } => {
                sent.stream_deliveries += 1;
            }
            _ => {}
        }
    }
    sent
}

/// The numbers that follow `word` in the bytes that put a terminal into a screen.
fn numbers_in(bytes: &[u8], word: &str) -> Vec<usize> {
    let text = String::from_utf8_lossy(bytes);
    let mut rest = text.as_ref();
    let mut found = Vec::new();
    while let Some(at) = rest.find(word) {
        rest = &rest[at + word.len()..];
        let digits: String = rest
            .trim_start_matches(' ')
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        if let Ok(number) = digits.parse() {
            found.push(number);
        }
    }
    found.sort_unstable();
    found.dedup();
    found
}

/// The screen is this tall after the taller resize, and this tall after the shorter one.
const TALLER: u64 = ROWS + 8;
const SHORTER: u64 = ROWS - 6;

/// The window the second terminal looks through: as wide and as tall as the taller screen, from
/// the top of the live page, so that every row of the primary buffer's screen is in it.
fn whole_page() -> Dimensions {
    Dimensions::new(80, TALLER)
}

/// A session whose host's own terminal owns the size and is exactly that size, with a qualified
/// profile: the session serves it the raw stream. A second terminal declares a profile that this
/// build has not qualified, so it is served a projection of the same screen.
struct Owned {
    session: Session,
    host: AttachmentId,
    host_stream: OutputStream,
    viewer: AttachmentId,
    viewer_stream: OutputStream,
    // Declared last: the directory is removed after every field above has let go of its files.
    _temp: kr_ipc::testing::TempHost,
}

impl Owned {
    fn open() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let mut session = Session::open(config(&temp, session_id)).expect("opens the session");

        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Geometry);
        let params = SessionAttachParams {
            session_id,
            mode: AttachMode::Terminal,
            claim_geometry: true,
            dimensions: Nullable::some(dimensions()),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        };
        let host = AttachmentId::new(kr_ipc::new_uuid());
        session
            .attach(&params, params.requested.clone(), host)
            .expect("the host attaches and owns the size");
        session.join(host).expect("joins");
        let host_stream = session.subscribe(host).expect("subscribes");

        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        let params = SessionAttachParams {
            session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(whole_page()),
            terminal_profile_id: Nullable::some("vt100".to_owned()),
            requested,
        };
        let viewer = AttachmentId::new(kr_ipc::new_uuid());
        session
            .attach(&params, params.requested.clone(), viewer)
            .expect("the second terminal attaches");
        session.join(viewer).expect("joins");
        let viewer_stream = session.subscribe(viewer).expect("subscribes");
        session
            .viewport(
                viewer,
                whole_page(),
                Some(ViewportPosition::Line(U64::new(0))),
                0,
            )
            .expect("the top of the live page");
        session.install_projection(viewer).expect("installs");

        let mut owned = Self {
            session,
            host,
            host_stream,
            viewer,
            viewer_stream,
            _temp: temp,
        };
        // The host's terminal asks for its screen when it attaches, as a terminal does.
        owned.session.restoration(host).expect("the first screen");
        owned.settle();
        owned
    }

    fn print(&mut self, bytes: &str) {
        let _ = self.session.ingest_output(bytes.as_bytes());
    }

    fn enable(&mut self) {
        self.session
            .enable_privacy(PrivacyGeneration::new(1), &mut [])
            .expect("privacy mode goes on");
        assert!(self.session.privacy().is_enabled());
    }

    fn disable(&mut self) {
        self.session
            .disable_privacy(PrivacyGeneration::new(2))
            .expect("privacy mode goes off")
            .expect("it was on");
        assert!(!self.session.privacy().is_enabled());
    }

    /// Reads what both streams were sent so far, so that the next read is only what follows.
    fn settle(&mut self) -> (Sent, Sent) {
        (sent(&mut self.host_stream), sent(&mut self.viewer_stream))
    }

    /// The owner resizes the session, as the host's own terminal does when its window changes.
    fn resize(&mut self, rows: u64) {
        let epoch = self.session.geometry().epoch.get();
        self.session
            .resize(self.host, Dimensions::new(80, rows), epoch)
            .expect("the owner resizes the session");
    }

    /// What a host's terminal does when it is told to resynchronise: it subscribes again, which is
    /// what lets the session tell it a second time, and asks for its screen.
    fn host_asks_for_its_screen(&mut self) {
        self.host_stream = self.session.subscribe(self.host).expect("subscribes again");
        self.host_restoration();
        self.settle();
    }

    /// How the session serves the host's terminal now.
    fn host_presentation(&mut self) -> TerminalPresentationMode {
        self.session
            .viewport(self.host, dimensions(), None, 0)
            .expect("the host's own report")
            .presentation
    }

    /// The bytes that put the host's terminal into the screen as it is now.
    fn host_restoration(&mut self) -> Vec<u8> {
        self.session
            .restoration(self.host)
            .expect("the restoration")
            .1
    }
}

/// The text of every primary-buffer row that a terminal is installed with in band, after checking
/// that it was installed over its stream and not told to ask for a screen.
fn installed_in_band(sent: Sent) -> Vec<String> {
    assert!(
        sent.events
            .iter()
            .any(|event| matches!(event, ProjectionEvent::Snapshot(_))),
        "the terminal is installed again over its stream"
    );
    assert_eq!(sent.resyncs, 0, "and it is not told to ask for a screen");
    installed_rows(sent.events)
}

/// One order of events: rows above the screen, a full-screen program, privacy
/// mode on while it shows.
fn before_the_program_then_the_enabling(enter: &str) -> Owned {
    let mut rig = Owned::open();
    rig.print(&run("before"));
    rig.print(enter);
    rig.enable();
    rig
}

#[test]
fn a_host_served_the_raw_stream_is_handed_no_earlier_row_when_a_resize_comes_under_a_full_screen_program()
 {
    // The control: without privacy mode the same resize pulls rows of the primary buffer in from
    // above its screen, and the host is handed them, so the reading below can see a row.
    let mut control = Owned::open();
    control.print(&run("before"));
    control.print(ENTER_ALTERNATE_PLAIN);
    control.resize(TALLER);
    let pulled_in = numbers_in(&control.host_restoration(), "before");
    assert!(
        pulled_in.iter().any(|number| *number < ON_SCREEN),
        "without privacy mode the screen the host is handed holds earlier rows: {pulled_in:?}"
    );

    let mut rig = before_the_program_then_the_enabling(ENTER_ALTERNATE_PLAIN);
    rig.host_asks_for_its_screen();
    assert_eq!(
        rig.host_presentation(),
        TerminalPresentationMode::Direct,
        "the host's terminal is served the raw stream"
    );
    rig.resize(TALLER);
    let (host, _) = rig.settle();
    assert_eq!(host.resyncs, 1, "the host is told to ask for its screen");
    assert!(
        host.events.is_empty() && host.stream_deliveries == 0,
        "and it is installed with nothing in band"
    );

    let handed = numbers_in(&rig.host_restoration(), "before");
    assert!(
        !handed.is_empty(),
        "the rows that were on the screen at the enabling are still the screen's: {handed:?}"
    );
    assert!(
        handed.iter().all(|number| *number >= ON_SCREEN),
        "no row from above the screen at the enabling is handed to the host: {handed:?}"
    );

    rig.print(LEAVE_ALTERNATE_PLAIN);
    let handed = numbers_in(&rig.host_restoration(), "before");
    assert!(
        handed.iter().all(|number| *number >= ON_SCREEN),
        "nor when the program has left: {handed:?}"
    );
    rig.disable();
    let handed = numbers_in(&rig.host_restoration(), "before");
    assert!(
        handed.iter().all(|number| *number >= ON_SCREEN),
        "nor when privacy mode has gone off: {handed:?}"
    );
}

#[test]
fn a_terminal_installed_in_band_is_given_no_earlier_row_when_a_resize_comes_under_a_full_screen_program()
 {
    let mut control = Owned::open();
    control.print(&run("before"));
    control.print(ENTER_ALTERNATE);
    control.settle();
    control.resize(TALLER);
    let (_, viewer) = control.settle();
    let installed = installed_in_band(viewer);
    assert!(
        numbers(&installed, "before")
            .iter()
            .any(|number| *number < ON_SCREEN),
        "without privacy mode the install holds earlier rows: {installed:?}"
    );

    let mut rig = before_the_program_then_the_enabling(ENTER_ALTERNATE);
    rig.host_asks_for_its_screen();
    rig.resize(TALLER);
    let (host, viewer) = rig.settle();
    // A program that saves the cursor as it starts leaves the host's own terminal on a projection
    // too, because a restoration cannot carry the saved cursor of the other buffer.
    for (who, sent) in [
        ("the second terminal", viewer),
        ("the host's terminal", host),
    ] {
        let installed = installed_in_band(sent);
        assert!(
            !numbers(&installed, "before").is_empty(),
            "{who}: the rows that were on the screen at the enabling are still the screen's: {installed:?}"
        );
        assert!(
            shows_only_the_screen(&installed, "before"),
            "{who}: no row from above the screen at the enabling is in the install: {installed:?}"
        );
    }

    rig.print(LEAVE_ALTERNATE);
    rig.session
        .install_projection(rig.viewer)
        .expect("installs again");
    let installed = installed_rows(sent(&mut rig.viewer_stream).events);
    assert!(!numbers(&installed, "before").is_empty(), "{installed:?}");
    assert!(
        shows_only_the_screen(&installed, "before"),
        "nor when the program has left: {installed:?}"
    );
}

#[test]
fn rows_a_shorter_resize_pushed_above_the_screen_are_not_handed_back_by_a_taller_one() {
    let mut rig = Owned::open();
    rig.print(&run("before"));
    rig.enable();
    rig.print(&run("while"));
    rig.print(ENTER_ALTERNATE);
    rig.settle();

    rig.resize(SHORTER);
    rig.resize(TALLER);

    // A shorter screen moved the top rows of the primary buffer above it, and they are rows of the
    // private interval: a taller one must not bring them back.
    let first_kept = ON_SCREEN + (ROWS - SHORTER) as usize;
    let handed = numbers_in(&rig.host_restoration(), "while");
    assert!(
        !handed.is_empty(),
        "the rows still on the screen are handed: {handed:?}"
    );
    assert!(
        handed.iter().all(|number| *number >= first_kept),
        "no row that the shorter screen pushed above it is handed back: {handed:?}"
    );
    assert!(numbers_in(&rig.host_restoration(), "before").is_empty());
    let (_, viewer) = rig.settle();
    let installed = installed_in_band(viewer);
    assert!(
        numbers(&installed, "while")
            .iter()
            .all(|number| *number >= first_kept),
        "nor is the second terminal installed with one: {installed:?}"
    );
    assert!(numbers(&installed, "before").is_empty(), "{installed:?}");

    rig.print(LEAVE_ALTERNATE);
    let handed = numbers_in(&rig.host_restoration(), "while");
    assert!(
        handed.iter().all(|number| *number >= first_kept),
        "nor when the program has left: {handed:?}"
    );
}
