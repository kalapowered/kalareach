//! What every `kr-hook` test needs: a copy of the forwarder on the internal disk, started with an
//! environment that names exactly what the test means it to name.

#![allow(dead_code)]

pub mod launched;

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Everything the forwarder reads from its environment, removed from every child a test starts.
///
/// A test run inside a KalaReach session inherits that session's variables, and a forwarder that
/// found them would reach for a worker the test never started.
///
/// A credential variable is removed too: the forwarder finds its credential through the
/// registration, and a test that passes proves it did not need one.
pub const FORWARDER_VARIABLES: &[&str] = &["KR_REGISTRATION", "KR_CREDENTIAL", "KR_SESSION"];

/// How long a test waits for something that should happen promptly, before it calls it a failure.
///
/// It is a liveness bound for a loaded machine, not a measurement: what a test measures, it
/// measures separately.
pub const LIVENESS: Duration = Duration::from_secs(60);

/// How long the first start of a placed program may take.
///
/// On macOS the operating system checks a program at a new path the first time it starts, and on
/// a loaded machine that check alone has taken longer than [`LIVENESS`]. Nothing is measured here.
pub const FIRST_START_WITHIN: Duration = Duration::from_secs(300);

/// Whether a test of this binary holds its placed programs, which on Windows is one at a time.
///
/// The first start of a fresh executable there is read by the system before it runs, which takes
/// about half a second for the forwarder's debug build, and that read delays every other process
/// creation on the machine while it lasts. Tests that place a program each and then time how
/// promptly it answers, run in parallel, time each other's first starts. A test waits here until
/// no other holds a placed program, and nothing is measured against a delay: the wait ends when
/// the other test has ended.
#[cfg(windows)]
static HOLDING: (std::sync::Mutex<bool>, std::sync::Condvar) =
    (std::sync::Mutex::new(false), std::sync::Condvar::new());

/// The hold on [`HOLDING`] one [`Placed`] keeps for its life. It is nothing where programs placed
/// in parallel delay nobody.
pub struct Hold {
    #[cfg(windows)]
    _private: (),
}

impl Hold {
    #[cfg(windows)]
    fn take() -> Self {
        let (held, released) = &HOLDING;
        let mut held = held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *held {
            held = released
                .wait(held)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *held = true;
        Self { _private: () }
    }

    #[cfg(not(windows))]
    const fn take() -> Self {
        Self {}
    }
}

#[cfg(windows)]
impl Drop for Hold {
    fn drop(&mut self) {
        let (held, released) = &HOLDING;
        *held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        released.notify_one();
    }
}

/// A host tree of its own, with the forwarder copied into it.
pub struct Placed {
    /// The tree, removed when this is dropped.
    pub host: kr_ipc::testing::TempHost,
    /// The copy of the forwarder a test starts.
    pub forwarder: PathBuf,
    /// Where a program placed and run one at a time is held to that; ended after the tree.
    _hold: Option<Hold>,
}

impl Placed {
    /// Copies the forwarder the build produced into a fresh tree on the internal disk.
    #[must_use]
    pub fn new() -> Self {
        let hold = Hold::take();
        let host = kr_ipc::testing::TempHost::create();
        let directory = host.root().join("bin");
        std::fs::create_dir_all(&directory).expect("a directory for the forwarder");
        let forwarder = directory.join(if cfg!(windows) {
            "kr-hook.exe"
        } else {
            "kr-hook"
        });
        kr_ipc::testing::place_program(Path::new(env!("CARGO_BIN_EXE_kr-hook")), &forwarder);
        let placed = Self {
            host,
            forwarder,
            _hold: Some(hold),
        };
        // The first start of a program at a new path is the one the operating system checks, and
        // on macOS that check can take seconds. It is taken here, once, so a test that measures how
        // promptly the forwarder answers measures the forwarder.
        let warmed = run(
            placed.command(&["--version"]),
            b"",
            false,
            FIRST_START_WITHIN,
        );
        assert_eq!(
            warmed.code,
            Some(0),
            "the placed forwarder runs: {}",
            warmed.stderr
        );
        placed
    }

    /// A program placed by a case beside the one it already holds, which is the only one it runs: it
    /// takes no hold of its own, so it never waits for itself.
    #[must_use]
    pub const fn beside(host: kr_ipc::testing::TempHost, forwarder: PathBuf) -> Self {
        Self {
            host,
            forwarder,
            _hold: None,
        }
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

/// A listener standing in for the worker's own, on the private endpoint this platform gives a
/// launch: a socket inside an owner-only directory on Unix, a named pipe on Windows.
///
/// It is kr-ipc's own listener, the one the worker binds on Windows and the same kind of socket the
/// worker binds on Unix, so the forwarder connects to it as it connects to the worker's. `accept`
/// gives the process the system names on the connection, which a test compares with the process the
/// forwarder presents.
pub struct StandIn {
    /// The bound listener.
    pub listener: kr_ipc::endpoint::Listener,
    /// What a registration's `endpoint=` line says: the socket's path, or the pipe's full name.
    pub address: String,
}

impl StandIn {
    /// Binds a listener, with its socket in `directory` on Unix and a pipe name that carries `name` on
    /// Windows.
    ///
    /// # Panics
    ///
    /// Panics when the endpoint cannot be made or bound.
    #[must_use]
    pub fn bind(directory: &Path, name: &str) -> Self {
        let fresh: String = kr_ipc::new_uuid()
            .to_string()
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect();
        let (address, endpoint) = if cfg!(windows) {
            let pipe = format!("kr-hook-{name}-{fresh}");
            (
                format!(r"\\.\pipe\{pipe}"),
                kr_ipc::paths::Endpoint::from_name(pipe),
            )
        } else {
            let path = directory.join(format!("{}.sock", &fresh[..12]));
            (
                path.to_string_lossy().into_owned(),
                kr_ipc::paths::Endpoint::from_path(path),
            )
        };
        let endpoint = endpoint.expect("a usable endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("the listener binds");
        Self { listener, address }
    }
}

/// Connects to the private endpoint a launch publishes, which a registration names as `address`: the
/// socket's path on Unix and the pipe's full name on Windows.
///
/// # Panics
///
/// Panics when the endpoint cannot be named or reached.
pub async fn connect(address: &str) -> kr_ipc::endpoint::Connection {
    let endpoint = if cfg!(windows) {
        let name = address
            .strip_prefix(r"\\.\pipe\")
            .expect("a pipe's full name");
        kr_ipc::paths::Endpoint::from_name(name.to_owned())
    } else {
        kr_ipc::paths::Endpoint::from_path(PathBuf::from(address))
    }
    .expect("a usable endpoint");
    kr_ipc::endpoint::Connection::connect(&endpoint)
        .await
        .expect("the endpoint is reachable")
}

/// Reads one line from a connection, without its newline, and the end of the stream as its end.
///
/// # Panics
///
/// Panics when the read fails or takes longer than [`LIVENESS`].
pub async fn read_line(stream: &mut kr_ipc::endpoint::Connection) -> Vec<u8> {
    use tokio::io::AsyncReadExt as _;

    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = tokio::time::timeout(LIVENESS, stream.read(&mut byte))
            .await
            .expect("a bounded read")
            .expect("the line is read");
        if read == 0 || byte[0] == b'\n' {
            return line;
        }
        line.push(byte[0]);
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
    run(command, input, false, LIVENESS)
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
    run(command, input, true, LIVENESS)
}

fn run(mut command: Command, input: &[u8], hold: bool, within: Duration) -> Ran {
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
        if started.elapsed() > within {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the forwarder did not end within {within:?}");
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

/// Sets whether a write to a pipe waits for room: it does, or it writes nothing and says so.
///
/// The calls have no safe form; the handle is the pipe's own and open for each of them.
///
/// # Panics
///
/// Panics when the system refuses the mode.
#[cfg(windows)]
#[allow(
    unsafe_code,
    reason = "setting a pipe's mode is a call with no safe form"
)]
pub fn pipe_waits(pipe: &std::io::PipeWriter, waits: bool) {
    use std::os::windows::io::AsRawHandle as _;

    use windows_sys::Win32::System::Pipes::{PIPE_NOWAIT, PIPE_WAIT, SetNamedPipeHandleState};

    let mode = if waits { PIPE_WAIT } else { PIPE_NOWAIT };
    // SAFETY: the handle is the pipe's own and open; the mode is a local that outlives the call, and
    // the two limits are not changed.
    let set = unsafe {
        SetNamedPipeHandleState(
            pipe.as_raw_handle().cast(),
            &raw const mode,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_ne!(
        set,
        0,
        "the pipe's mode is set: {}",
        std::io::Error::last_os_error()
    );
}
