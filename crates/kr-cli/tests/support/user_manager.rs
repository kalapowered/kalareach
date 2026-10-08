//! A user service manager of a test's own, and the bounded commands a test's teardown runs.
//!
//! Included by the suites that have a daemon started through the user's service manager. Each of
//! them has the `teardown` module of the controller's tests at its root, which this uses.

// Each suite compiles this module on its own and uses the part of it that it needs, so a helper
// the other suite uses is dead code from this one's point of view.
#![allow(dead_code)]

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Child;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

/// How long the streams of a command that has ended are given to reach their end, and how long a
/// daemon is given to end once its lifeline has closed.
pub const STREAMS_DEADLINE: Duration = Duration::from_secs(10);

/// How long one call to a service manager in a test's teardown may take.
pub const TEARDOWN_BOUND: Duration = Duration::from_secs(60);

/// Set where the service-start tests must run: a host with no user service manager then fails
/// them, rather than saying why they did not run.
pub const REQUIRE_SERVICE_MANAGER: &str = "KR_REQUIRE_SERVICE_MANAGER";

/// Says why a service-start test did not run, or fails it where it has to run.
pub fn not_tested_here(why: &str) {
    assert!(
        std::env::var_os(REQUIRE_SERVICE_MANAGER).is_none(),
        "{REQUIRE_SERVICE_MANAGER} is set and the service start cannot be tested here: {why}"
    );
    eprintln!("the service start is not tested here: {why}");
}

/// How long a user manager of a test's own is given to come up.
#[cfg(target_os = "linux")]
const COMES_UP: Duration = Duration::from_secs(120);

/// Starts one process at a time.
///
/// A pipe is made and only then marked to close when a program is started, and on macOS those are
/// two steps. A process another test's thread starts in between inherits both ends, and a `kr`
/// that inherits them hands them on to the daemon it starts, which outlives it: the pipe then
/// never reaches its end, and the command that made it looks as if it had left something holding
/// its output. Starting one process at a time closes that window for every pipe made through it.
pub fn spawning<T>(start: impl FnOnce() -> T) -> T {
    static SPAWNING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one_at_a_time = SPAWNING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    start()
}

/// Reads a stream to its end on a thread of its own, and sends what it read.
pub fn read_aside(mut stream: impl std::io::Read + Send + 'static) -> Receiver<Vec<u8>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    receiver
}

/// Runs a command to its end within `bound`, ending and collecting it when it has not ended.
///
/// For teardown, which must not panic: every failure is returned as what it was.
pub fn bounded(mut command: Command, bound: Duration) -> Result<Output, String> {
    let what = format!("{command:?}");
    let mut child = spawning(|| {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    })
    .map_err(|error| format!("{what} could not be started: {error}"))?;
    let stdout = child.stdout.take().map(read_aside);
    let stderr = child.stderr.take().map(read_aside);
    let begun = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if begun.elapsed() < bound => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => {
                // This test's own child, not collected yet, so the number is still its.
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{what} did not end within {bound:?}"));
            }
        }
    };
    let collect = |stream: Option<Receiver<Vec<u8>>>| {
        stream
            .and_then(|stream| stream.recv_timeout(STREAMS_DEADLINE).ok())
            .unwrap_or_default()
    };
    Ok(Output {
        status,
        stdout: collect(stdout),
        stderr: collect(stderr),
    })
}

/// A user service manager of a test's own: a second `systemd --user`, run in a scope of the user
/// manager of whoever runs the tests, with that scope's cgroup delegated to it.
///
/// Its home is the test's own, so it reads unit files from there, and its runtime directory is its
/// own, so `systemctl --user` reaches it through `XDG_RUNTIME_DIR` and nothing else. It starts
/// nothing by itself: its default target has no dependencies. Ending the scope ends every process
/// in it, the manager and whatever the manager started, workers included, which is how a test's
/// teardown ends it. Where that cannot be established, the test's tree and the manager's runtime
/// directory are both kept.
#[cfg(target_os = "linux")]
pub struct UserManager {
    /// The scope it runs in.
    scope: String,
    /// The manager, which `systemd-run` became: this test process's own child.
    process: Option<Child>,
    /// Its runtime directory, outside the test's tree.
    pub runtime: PathBuf,
    /// What keeps the test's tree when this manager's scope cannot be established as ended.
    holder: crate::teardown::Holder,
}

#[cfg(target_os = "linux")]
impl UserManager {
    /// Starts a manager whose home is `home`, or says why none can be started here.
    pub fn start(home: &Path, holder: crate::teardown::Holder) -> Result<Self, String> {
        use std::os::unix::fs::PermissionsExt as _;

        let program = ["/usr/lib/systemd/systemd", "/lib/systemd/systemd"]
            .into_iter()
            .map(PathBuf::from)
            .find(|candidate| candidate.is_file())
            .ok_or("this host has no systemd to run a user manager with")?;
        let mut asked = Command::new("systemctl");
        asked.args(["--user", "show", "--property=Version", "--value"]);
        let answered = bounded(asked, STREAMS_DEADLINE)?;
        if !answered.status.success() {
            return Err(format!(
                "no user manager answers for whoever runs these tests, so there is no scope to run \
                 a manager of the test's own in: {}",
                String::from_utf8_lossy(&answered.stderr).trim()
            ));
        }
        let units = home.join(".config/systemd/user");
        std::fs::create_dir_all(&units).map_err(|error| error.to_string())?;
        std::fs::write(
            units.join("kr-test-idle.target"),
            "[Unit]\nDescription=Nothing, so that this manager starts only what a test asks for\n\
             DefaultDependencies=no\n",
        )
        .map_err(|error| error.to_string())?;
        let runtime =
            std::env::temp_dir().join(format!("krm-{}", &kr_ipc::new_uuid().to_string()[..8]));
        std::fs::create_dir(&runtime).map_err(|error| error.to_string())?;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| error.to_string())?;
        let log = std::fs::File::create(runtime.join("manager.log"))
            .map_err(|error| error.to_string())?;
        let scope = format!("kr-test-manager-{}.scope", kr_ipc::new_uuid());
        let process = spawning(|| {
            let mut command = Command::new("systemd-run");
            command
                .args(["--user", "--scope", "--quiet", "--property=Delegate=yes"])
                .arg(format!("--unit={scope}"))
                .args(["--", "env", "-i"])
                .arg(format!("HOME={}", home.display()))
                .arg(format!("XDG_RUNTIME_DIR={}", runtime.display()))
                .arg("PATH=/usr/bin:/bin");
            command
                .arg(&program)
                .args([
                    "--user",
                    "--unit=kr-test-idle.target",
                    "--log-target=console",
                ])
                .stdin(Stdio::null())
                .stdout(log.try_clone().expect("the log twice"))
                .stderr(log)
                .spawn()
        })
        .map_err(|error| format!("systemd-run could not be started: {error}"))?;
        let mut manager = Self {
            scope,
            process: Some(process),
            runtime,
            holder,
        };
        let begun = Instant::now();
        loop {
            let mut asked = manager.systemctl(&["show", "--property=Version", "--value"]);
            asked.env_remove("DBUS_SESSION_BUS_ADDRESS");
            if bounded(asked, STREAMS_DEADLINE).is_ok_and(|answer| answer.status.success()) {
                return Ok(manager);
            }
            let ended = manager
                .process
                .as_mut()
                .is_some_and(|process| matches!(process.try_wait(), Ok(Some(_))));
            if ended || begun.elapsed() > COMES_UP {
                return Err(format!(
                    "the test's user manager did not come up: {}",
                    std::fs::read_to_string(manager.runtime.join("manager.log"))
                        .unwrap_or_default()
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// `systemctl --user` pointed at this manager and at nothing else: with no session bus named,
    /// a manager that did not answer on its own socket is not replaced by the user's own.
    pub fn systemctl(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new("systemctl");
        command
            .arg("--user")
            .args(arguments)
            .env("XDG_RUNTIME_DIR", &self.runtime)
            .env_remove("DBUS_SESSION_BUS_ADDRESS");
        command
    }

    /// The manager's own process.
    pub fn pid(&self) -> u32 {
        self.process.as_ref().expect("the manager is running").id()
    }
}

#[cfg(target_os = "linux")]
impl Drop for UserManager {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;

        // The scope belongs to the user manager of whoever runs the tests, so it is asked there.
        let mut stop = Command::new("systemctl");
        stop.args(["--user", "stop", &self.scope]);
        let stopped = bounded(stop, TEARDOWN_BOUND);
        if !stopped.as_ref().is_ok_and(|answer| answer.status.success()) {
            eprintln!("stopping {}: {stopped:?}", self.scope);
            let mut kill = Command::new("systemctl");
            kill.args(["--user", "kill", "--signal=SIGKILL", &self.scope]);
            let killed = bounded(kill, TEARDOWN_BOUND);
            eprintln!("killing what is in {}: {killed:?}", self.scope);
        }
        if let Some(mut process) = self.process.take() {
            let begun = Instant::now();
            while matches!(process.try_wait(), Ok(None)) && begun.elapsed() < STREAMS_DEADLINE {
                std::thread::sleep(Duration::from_millis(20));
            }
            // This test's own child, not collected yet, so the number is still its.
            let _ = process.kill();
            let _ = process.wait();
        }
        // Whether the scope is gone is asked of the manager that held it: a scope with nothing
        // left in it goes by itself, and the manager then describes it as inactive. Only an answer
        // that says so counts; a question that failed establishes nothing.
        let mut shown = Command::new("systemctl");
        shown.args([
            "--user",
            "show",
            "--property=ActiveState",
            "--value",
            &self.scope,
        ]);
        let state = bounded(shown, STREAMS_DEADLINE).and_then(|answer| {
            if answer.status.success() {
                Ok(String::from_utf8_lossy(&answer.stdout).trim().to_owned())
            } else {
                Err(format!(
                    "systemctl --user show answered {:?}: {}",
                    answer.status.code(),
                    String::from_utf8_lossy(&answer.stderr).trim()
                ))
            }
        });
        if !matches!(state.as_deref(), Ok("inactive" | "failed")) {
            // Both are kept: something may still be running in them.
            self.holder.hold(format!(
                "the scope {} of the test's user manager could not be established as ended ({state:?}); \
                 its runtime directory is kept at {}",
                self.scope,
                self.runtime.display()
            ));
            return;
        }
        // The manager makes directories nobody may write in its runtime directory, which could not
        // be removed otherwise.
        let mut waiting = vec![self.runtime.clone()];
        while let Some(directory) = waiting.pop() {
            let _ = std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700));
            for entry in std::fs::read_dir(&directory)
                .into_iter()
                .flatten()
                .flatten()
            {
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    waiting.push(entry.path());
                }
            }
        }
        if let Err(error) = std::fs::remove_dir_all(&self.runtime) {
            eprintln!(
                "the test's user manager left {}: {error}",
                self.runtime.display()
            );
        }
    }
}
