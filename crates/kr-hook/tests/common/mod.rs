//! What every `kr-hook` test needs: a copy of the forwarder on the internal disk, started with an
//! environment that names exactly what the test means it to name.

#![allow(dead_code)]

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Everything the forwarder reads from its environment, removed from every child a test starts.
///
/// A test run inside a KalaReach session inherits that session's variables, and a forwarder that
/// found them would reach for a worker the test never started.
pub const FORWARDER_VARIABLES: &[&str] = &["KR_REGISTRATION", "KR_CREDENTIAL", "KR_SESSION"];

/// How long a test waits for something that should happen promptly, before it calls it a failure.
///
/// It is a liveness bound for a loaded machine, not a measurement: what a test measures, it
/// measures separately.
pub const LIVENESS: Duration = Duration::from_secs(60);

/// A host tree of its own, with the forwarder copied into it.
pub struct Placed {
    /// The tree, removed when this is dropped.
    pub host: kr_ipc::testing::TempHost,
    /// The copy of the forwarder a test starts.
    pub forwarder: PathBuf,
}

impl Placed {
    /// Copies the forwarder the build produced into a fresh tree on the internal disk.
    #[must_use]
    pub fn new() -> Self {
        let host = kr_ipc::testing::TempHost::create();
        let directory = host.root().join("bin");
        std::fs::create_dir_all(&directory).expect("a directory for the forwarder");
        let forwarder = directory.join(if cfg!(windows) {
            "kr-hook.exe"
        } else {
            "kr-hook"
        });
        kr_ipc::testing::place_program(Path::new(env!("CARGO_BIN_EXE_kr-hook")), &forwarder);
        let placed = Self { host, forwarder };
        // The first start of a program at a new path is the one the operating system checks, and
        // on macOS that check can take seconds. It is taken here, once, so a test that measures how
        // promptly the forwarder answers measures the forwarder.
        let warmed = run_with_input(placed.command(&["--version"]), b"");
        assert_eq!(
            warmed.code,
            Some(0),
            "the placed forwarder runs: {}",
            warmed.stderr
        );
        placed
    }

    /// The forwarder with these arguments and a clean environment, run from the tree's root.
    #[must_use]
    pub fn command(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(&self.forwarder);
        command.args(arguments).current_dir(self.host.root());
        for variable in FORWARDER_VARIABLES {
            command.env_remove(variable);
        }
        command
    }
}

/// What one run of the forwarder produced.
#[derive(Debug)]
pub struct Ran {
    /// Its exit code, where it exited with one.
    pub code: Option<i32>,
    /// Everything it wrote to standard output.
    pub stdout: Vec<u8>,
    /// Everything it wrote to standard error.
    pub stderr: String,
    /// How long it took from start to exit.
    pub took: Duration,
}

/// Runs a command to its end with `input` on standard input, which is then closed.
///
/// # Panics
///
/// Panics when the process does not end within [`LIVENESS`].
#[must_use]
pub fn run_with_input(command: Command, input: &[u8]) -> Ran {
    run(command, input, false)
}

/// Runs a command to its end with `input` on standard input, which is held open until it ends.
///
/// An application that never closes a hook's input must not be able to hold the hook open.
///
/// # Panics
///
/// Panics when the process does not end within [`LIVENESS`].
#[must_use]
pub fn run_holding_input(command: Command, input: &[u8]) -> Ran {
    run(command, input, true)
}

fn run(mut command: Command, input: &[u8], hold: bool) -> Ran {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = command.spawn().expect("the forwarder starts");
    let mut stdin = child.stdin.take().expect("its input");
    let input = input.to_vec();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let writing = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        let _ = stdin.flush();
        if hold {
            // Held until the process has ended, then closed.
            let _ = released.recv();
        }
        drop(stdin);
    });
    let mut stdout = child.stdout.take().expect("its output");
    let mut stderr = child.stderr.take().expect("its diagnostics");
    let reading = std::thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        out
    });
    let diagnosing = std::thread::spawn(move || {
        let mut err = String::new();
        let _ = stderr.read_to_string(&mut err);
        err
    });
    let status = loop {
        if let Some(status) = child.try_wait().expect("the forwarder can be waited on") {
            break status;
        }
        if started.elapsed() > LIVENESS {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the forwarder did not end within {LIVENESS:?}");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let took = started.elapsed();
    drop(release);
    let _ = writing.join();
    Ran {
        code: status.code(),
        stdout: reading.join().expect("the output is read"),
        stderr: diagnosing.join().expect("the diagnostics are read"),
        took,
    }
}
