//! GNU screen: its window against the grid the worker holds, and a character cut short.

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_protocol::projection::ProjectedBuffer;

use crate::harness::{Launch, Screen, Session, application, utf8_locale};
use crate::queries;

/// A screen session of the case's own: its socket directory, which screen requires to be the
/// owner's alone, and a configuration with no startup message or status line.
struct Gnu {
    program: PathBuf,
    sockets: PathBuf,
    configuration: PathBuf,
}

impl Gnu {
    fn new(directory: &Path) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let screen = application("screen");
        let sockets = directory.join("sockets");
        std::fs::create_dir(&sockets).expect("a socket directory");
        std::fs::set_permissions(&sockets, std::fs::Permissions::from_mode(0o700))
            .expect("the owner's alone");
        let configuration = directory.join("screenrc");
        std::fs::write(
            &configuration,
            "startup_message off\naltscreen on\ndefflow off\n",
        )
        .expect("writes the configuration");
        Self {
            program: screen.executable,
            sockets,
            configuration,
        }
    }

    fn launch(&self, command: &str) -> Launch {
        Launch::new(&self.program)
            .variable("SCREENDIR", self.sockets.to_string_lossy())
            .arguments(["-U", "-S", "kr", "-c"])
            .arguments([self.configuration.to_string_lossy().into_owned()])
            .arguments(["/bin/sh", "-c", command])
    }

    /// What screen itself holds as its window, as it copies it out.
    fn window(&self, directory: &Path) -> Vec<String> {
        let copy = directory.join("hardcopy");
        let _ = std::fs::remove_file(&copy);
        let status = Command::new(&self.program)
            .args(["-S", "kr", "-X", "hardcopy"])
            .arg(&copy)
            .env("SCREENDIR", &self.sockets)
            .env("LC_ALL", utf8_locale())
            .status()
            .expect("screen runs");
        assert!(status.success(), "screen's hardcopy");
        let started = std::time::Instant::now();
        while !copy.is_file() {
            assert!(
                started.elapsed() < crate::harness::LIVENESS,
                "screen wrote no hardcopy"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        String::from_utf8_lossy(&std::fs::read(&copy).expect("the hardcopy"))
            .lines()
            .map(|line| line.trim_end().to_owned())
            .collect()
    }
}

impl Drop for Gnu {
    fn drop(&mut self) {
        let _ = Command::new(&self.program)
            .args(["-S", "kr", "-X", "quit"])
            .env("SCREENDIR", &self.sockets)
            .output();
    }
}

fn rows(screen: &Screen) -> Vec<String> {
    (0..screen.rows.len()).map(|row| screen.line(row)).collect()
}

async fn no_query_reached_the_terminal(session: &Session) {
    let reached = queries::find(&session.received().await);
    assert!(
        reached.is_empty(),
        "a query reached the attached terminal: {}",
        reached
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// KR-ACC-004, KR-REQ-27.04: GNU screen draws its window on the alternate screen, and the grid
/// holds the rows screen holds, CJK, combining marks and bidirectional text included; a character
/// whose UTF-8 is cut short is drawn as screen draws it. No query reached the attached terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn the_window_screen_holds_is_the_grid_the_worker_holds() {
    let directory = tempfile::tempdir().expect("a directory");
    let gnu = Gnu::new(directory.path());
    let script = "printf '%s\\n' 'plain line' '中文テキスト|end' 'e\u{301}galite\u{301}|end' 'שלום עולם|end'; \
                  printf 'broken \\342\\202 end\\n'; printf 'kr-drawn\\n'; exec cat";
    let session = Session::start(gnu.launch(script)).await;
    let screen = session
        .wait_for("screen to draw its window", |screen| {
            screen.shows("kr-drawn")
        })
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Alternate, "{screen}");
    let window = gnu.window(directory.path());
    let grid = rows(&screen);
    let shared = window.len().min(grid.len());
    assert_eq!(
        grid[..shared],
        window[..shared],
        "screen's window and the grid"
    );
    assert_eq!(
        crate::harness::ascii_suffix_column(&screen, 1, "|end"),
        Some(12),
        "{screen}"
    );
    no_query_reached_the_terminal(&session).await;
}
