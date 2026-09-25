//! tmux: the pane it draws against the grid the worker holds, a click between panes, focus
//! passing through it, a key in xterm's `modifyOtherKeys` protocol, and an overlong control string
//! and a broken character passed through it.

use std::path::Path;
use std::process::Command;

use kr_protocol::projection::ProjectedBuffer;

use crate::harness::{Launch, Screen, Session, application, ascii_suffix_column, utf8_locale};
use crate::queries;

/// The configuration every case runs tmux with: no status line, so its one window is the whole
/// screen, every event passed on at once, passthrough allowed, the mouse and focus on.
const CONFIGURATION: &str = "\
set -g status off
set -g escape-time 0
set -g allow-passthrough on
set -g mouse on
set -g focus-events on
set -g default-terminal screen-256color
";

/// A tmux server of the case's own, on a socket in the case's own directory.
struct Tmux {
    program: std::path::PathBuf,
    socket: std::path::PathBuf,
}

impl Tmux {
    fn new(directory: &Path) -> Self {
        Self::with(directory, "")
    }

    /// A server whose configuration adds `more` to the one every case runs with.
    fn with(directory: &Path, more: &str) -> Self {
        let tmux = application("tmux");
        std::fs::write(
            directory.join("tmux.conf"),
            format!("{CONFIGURATION}{more}"),
        )
        .expect("writes the configuration");
        Self {
            program: tmux.executable,
            socket: directory.join("tmux.sock"),
        }
    }

    /// Starts tmux in the session with `command` as its one pane's program.
    fn launch(&self, directory: &Path, command: &str) -> Launch {
        Launch::new(&self.program)
            .arguments(["-S".to_owned(), self.socket.to_string_lossy().into_owned()])
            .arguments([
                "-f".to_owned(),
                directory.join("tmux.conf").to_string_lossy().into_owned(),
            ])
            .arguments(["-u", "new-session", command])
    }

    /// Asks the server something, as a second client outside the session.
    fn ask(&self, arguments: &[&str]) -> String {
        let output = Command::new(&self.program)
            .arg("-S")
            .arg(&self.socket)
            .args(arguments)
            .env("LC_ALL", utf8_locale())
            .output()
            .expect("tmux runs");
        assert!(
            output.status.success(),
            "tmux {arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    /// What tmux itself holds as its pane's screen.
    fn pane(&self) -> Vec<String> {
        self.ask(&["capture-pane", "-p"])
            .lines()
            .map(|line| line.trim_end().to_owned())
            .collect()
    }

    /// How wide tmux takes `text` to be.
    fn width(&self, text: &str) -> u64 {
        self.ask(&["display", "-p", &format!("#{{w:#{{l:{text}}}}}")])
            .trim()
            .parse()
            .expect("a width")
    }
}

impl Drop for Tmux {
    fn drop(&mut self) {
        let _ = Command::new(&self.program)
            .arg("-S")
            .arg(&self.socket)
            .arg("kill-server")
            .output();
    }
}

async fn no_query_reached_the_terminal(session: &Session) {
    let asked = queries::find(&session.written());
    assert!(
        !asked.is_empty(),
        "tmux asked its terminal nothing, so this case shows nothing about queries"
    );
    let reached = queries::find(&session.received().await);
    assert!(
        reached.is_empty(),
        "the queries tmux asked reached the attached terminal: {}",
        reached
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// The rows of the worker's snapshot, trimmed as tmux trims its own.
fn rows(screen: &Screen) -> Vec<String> {
    (0..screen.rows.len()).map(|row| screen.line(row)).collect()
}

/// The samples the pane prints, each followed by a marker.
const SAMPLES: &[(&str, &str)] = &[
    ("CJK", "中文テキスト"),
    ("combining marks", "e\u{301}galite\u{301} n\u{303}"),
    ("Hebrew", "שלום עולם"),
    ("an emoji", "\u{1f600}"),
    ("a flag", "\u{1f1ff}\u{1f1e6}"),
    ("a skin tone", "\u{1f44b}\u{1f3fd}"),
    ("a joined sequence", "\u{1f469}\u{200d}\u{1f4bb}"),
];

/// KR-ACC-004, KR-REQ-27.04: tmux draws its pane on the alternate screen, and every row the grid
/// holds is the row tmux holds, CJK, combining marks, bidirectional text and emoji sequences
/// included: each sample's marker is at the column tmux's own width puts it at. No query tmux
/// asked reached the attached terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn the_pane_tmux_holds_is_the_grid_the_worker_holds() {
    let directory = tempfile::tempdir().expect("a directory");
    let tmux = Tmux::new(directory.path());
    let lines: Vec<String> = SAMPLES
        .iter()
        .map(|(_, sample)| format!("{sample}|end"))
        .collect();
    let script = format!(
        "printf '%s\\n' {}; printf 'kr-drawn\\n'; exec cat",
        lines
            .iter()
            .map(|line| format!("'{line}'"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let session = Session::start(tmux.launch(directory.path(), &script)).await;
    let screen = session
        .wait_for("tmux to draw the pane", |screen| screen.shows("kr-drawn"))
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Alternate, "{screen}");
    let pane = tmux.pane();
    let grid = rows(&screen);
    assert_eq!(
        grid[..pane.len().min(grid.len())],
        pane[..pane.len().min(grid.len())],
        "tmux's pane and the grid"
    );
    let mut disagreements = Vec::new();
    for (row, (script, sample)) in SAMPLES.iter().enumerate() {
        let expected = tmux.width(sample);
        let grid_column = ascii_suffix_column(&screen, row, "|end");
        if grid_column != Some(expected) {
            disagreements.push(format!(
                "{script} ({}): tmux puts the marker at column {expected}, the grid at {grid_column:?}",
                sample.escape_unicode()
            ));
        }
    }
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
    no_query_reached_the_terminal(&session).await;
}

/// KR-ACC-004, KR-REQ-27.04: with the mouse on, tmux turns on SGR mouse reporting, and a click in
/// the other pane makes it the active one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_click_in_the_other_pane_makes_it_the_active_one() {
    let directory = tempfile::tempdir().expect("a directory");
    let tmux = Tmux::new(directory.path());
    let mut session =
        Session::start(tmux.launch(directory.path(), "printf 'kr-left\\n'; exec cat")).await;
    session
        .wait_for("tmux to draw the pane", |screen| screen.shows("kr-left"))
        .await;
    tmux.ask(&["split-window", "-h", "printf 'kr-right\\n'; exec cat"]);
    let screen = session
        .wait_for("the second pane", |screen| screen.shows("kr-right"))
        .await;
    assert!(screen.mode(1006), "the SGR form: {}", screen.modes);
    assert_eq!(
        tmux.ask(&["display", "-p", "#{pane_index}"]).trim(),
        "1",
        "the new pane is the active one"
    );
    // Press and release the first button in the left pane, at its third column and row.
    session.type_bytes(b"\x1b[<0;3;3M\x1b[<0;3;3m");
    let started = tokio::time::Instant::now();
    while tmux.ask(&["display", "-p", "#{pane_index}"]).trim() != "0" {
        assert!(
            started.elapsed() < crate::harness::LIVENESS,
            "the click never made the left pane active"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    no_query_reached_the_terminal(&session).await;
}

/// KR-ACC-004, KR-REQ-27.04: tmux asks its terminal for focus events, and a focus report typed
/// through the session reaches the program in the pane that asked for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_focus_report_reaches_the_program_in_the_pane_that_asked_for_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let tmux = Tmux::new(directory.path());
    // The pane's program asks for focus reports and shows what it reads, a line at a time, with an
    // escape written as `^[`.
    let mut session = Session::start(tmux.launch(
        directory.path(),
        "printf '\\033[?1004hkr-focus\\n'; stty -icanon -echo; exec cat -v",
    ))
    .await;
    let screen = session
        .wait_for("the pane's program", |screen| screen.shows("kr-focus"))
        .await;
    assert!(screen.mode(1004), "focus events: {}", screen.modes);
    session.type_bytes(b"\x1b[O\x1b[I");
    // Enter ends the line, which is when the program writes it.
    session.type_bytes(b"\r");
    let screen = session
        .wait_for("the focus reports in the pane", |screen| {
            screen.shows("^[[O^[[I")
        })
        .await;
    assert!(screen.shows("^[[O^[[I"), "{screen}");
    no_query_reached_the_terminal(&session).await;
}

/// KR-ACC-004, KR-REQ-27.04: with extended keys on, tmux asks its terminal for xterm's
/// `modifyOtherKeys` at level 2, and the session's snapshot records that level. A control-Enter
/// typed in that protocol reaches the program in the pane, which asked for the same protocol, as
/// that key rather than as a plain Enter.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_key_in_the_modify_other_keys_protocol_reaches_the_pane_that_asked_for_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let tmux = Tmux::with(
        directory.path(),
        "set -g extended-keys on\n\
         set -g extended-keys-format xterm\n\
         set -as terminal-features 'xterm*:extkeys'\n",
    );
    // The pane's program asks for modifyOtherKeys at level 2 and shows what it reads, a line at a
    // time, with an escape written as `^[`.
    let mut session = Session::start(tmux.launch(
        directory.path(),
        "printf '\\033[>4;2mkr-keys\\n'; stty -icanon -echo; exec cat -v",
    ))
    .await;
    let screen = session
        .wait_for("the pane's program", |screen| screen.shows("kr-keys"))
        .await;
    assert!(
        screen.keyboard.contains("modify_other_keys: U64(2)"),
        "tmux asked the session for modifyOtherKeys at level 2: {}",
        screen.keyboard
    );
    // Control-Enter, as xterm writes it at that level: `CSI 27 ; 5 ; 13 ~`.
    session.type_bytes(b"\x1b[27;5;13~");
    // Enter ends the line, which is when the program writes it.
    session.type_bytes(b"\r");
    let key = "^[[27;5;13~";
    let screen = session
        .wait_for("control-Enter in the pane", |screen| screen.shows(key))
        .await;
    assert!(screen.shows(key), "{screen}");
    no_query_reached_the_terminal(&session).await;
}

/// KR-ACC-004, KR-REQ-27.04: an operating-system command longer than the profile's control-string
/// bound, passed through tmux to its terminal, is dropped whole: the text after it is drawn where
/// tmux draws it and none of it becomes text. A character whose UTF-8 is cut short is drawn as
/// tmux draws it, and the grid matches tmux's pane throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn an_overlong_control_string_and_a_broken_character_through_tmux_leave_its_pane_intact() {
    let directory = tempfile::tempdir().expect("a directory");
    let tmux = Tmux::new(directory.path());
    // Seventy thousand bytes of link target, past the profile's 65,536-byte bound, wrapped for
    // tmux to pass through; then a character with its last byte missing.
    let script = "\
        target=$(printf '%070000d' 0 | tr 0 a); \
        printf '\\033Ptmux;\\033\\033]8;;https://example.com/%s\\007\\033\\\\' \"$target\"; \
        printf 'kr-after-the-string\\n'; \
        printf 'broken \\342\\202 end\\n'; \
        printf 'kr-drawn\\n'; exec cat";
    let session = Session::start(tmux.launch(directory.path(), script)).await;
    let screen = session
        .wait_for("tmux to draw the pane", |screen| screen.shows("kr-drawn"))
        .await;
    assert!(screen.shows("kr-after-the-string"), "{screen}");
    assert!(
        !screen.shows("aaaaaaaa"),
        "the link target became text:\n{screen}"
    );
    let pane = tmux.pane();
    let grid = rows(&screen);
    assert_eq!(
        grid[..pane.len().min(grid.len())],
        pane[..pane.len().min(grid.len())],
        "tmux's pane and the grid"
    );
    no_query_reached_the_terminal(&session).await;
}
