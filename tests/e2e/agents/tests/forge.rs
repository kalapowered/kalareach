//! The forging launcher's own guards: where it reads, what it presents, and what it leaves to the
//! real launcher. The backend is a listener of the test's own; the real launcher is a stand-in
//! script that says what it was run with.

#![cfg(unix)]

use std::io::{BufRead as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use kr_ipc::testing::PrivateTempDir;

/// What a test stands on: a run's directory with a launch directory, a launch record, a socket the
/// backend listens on, the forging launcher at `b/kr-hook` and a stand-in for the real launcher at
/// `b/h/kr-hook`.
struct Scene {
    root: PathBuf,
    listener: UnixListener,
    _directory: PrivateTempDir,
}

fn write_private(path: &Path, text: &str) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("a file");
    file.write_all(text.as_bytes()).expect("written");
}

impl Scene {
    fn new(gateway: bool) -> Self {
        let directory = PrivateTempDir::create();
        let root = std::fs::canonicalize(directory.path()).expect("the directory");
        let launch = root.join("launch");
        std::fs::create_dir(&launch).expect("the launch directory");
        std::fs::create_dir_all(root.join("b/h")).expect("the launcher directories");
        let listener = UnixListener::bind(launch.join("sock")).expect("the backend's socket");
        listener.set_nonblocking(false).expect("blocking");
        write_private(&launch.join("credential"), &"ab".repeat(32));
        write_private(&launch.join("registration"), "");
        let record = serde_json::json!({
            "endpoint": launch.join("sock"),
            "credential": launch.join("credential"),
            "variables": [],
            "gateway": gateway.then_some("ws://127.0.0.1:1/"),
        });
        write_private(&launch.join("launch"), &record.to_string());
        std::fs::copy(env!("CARGO_BIN_EXE_kr-e2e-forge"), root.join("b/kr-hook"))
            .expect("the forging launcher placed");
        let real = root.join("b/h/kr-hook");
        std::fs::write(&real, "#!/bin/sh\necho \"real:$*\"\n").expect("the stand-in launcher");
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).expect("mode");
        Self {
            root,
            listener,
            _directory: directory,
        }
    }

    /// Runs the forging launcher with `arguments`, where `registration` names the launch.
    fn run(&self, registration: &Path, arguments: &[&str]) -> (i32, String, String) {
        let output = Command::new(self.root.join("b/kr-hook"))
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("KALAREACH_E2E_FORGE_ROOT", &self.root)
            .env("KR_REGISTRATION", registration)
            .output()
            .expect("the forging launcher runs");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn registration(&self) -> PathBuf {
        self.root.join("launch/registration")
    }

    /// Whether anything connected to the listener: asked after the launcher has ended.
    fn nothing_connected(&self) -> bool {
        self.listener.set_nonblocking(true).expect("nonblocking");
        matches!(
            self.listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        )
    }
}

const LAUNCH: [&str; 5] = ["launch", "--", "/bin/true", "true", "--flag"];

/// A registration outside the root names no launch the helper may read: nothing is presented and
/// nothing runs.
#[test]
fn a_registration_outside_the_root_is_not_presented() {
    let scene = Scene::new(true);
    let (code, _, error) = scene.run(Path::new("/tmp/elsewhere/registration"), &LAUNCH);
    assert_eq!(code, 1);
    assert!(error.contains("nothing presented"), "{error}");
    assert!(scene.nothing_connected());
}

/// A link at a parent component of the launch directory is not walked.
#[test]
fn a_link_at_a_parent_component_of_the_launch_directory_is_not_walked() {
    let scene = Scene::new(true);
    let elsewhere = scene.root.join("elsewhere");
    std::fs::rename(scene.root.join("launch"), &elsewhere).expect("moved");
    std::os::unix::fs::symlink(&elsewhere, scene.root.join("launch")).expect("a link");
    let (code, _, error) = scene.run(&scene.registration(), &LAUNCH);
    assert_eq!(code, 1);
    assert!(error.contains("nothing presented"), "{error}");
}

/// A link at the endpoint's last component is not connected through: a connect would follow it.
#[test]
fn a_link_at_the_endpoints_last_component_is_not_connected_through() {
    let scene = Scene::new(true);
    let real = scene.root.join("real.sock");
    let listener = UnixListener::bind(&real).expect("another socket");
    std::fs::remove_file(scene.root.join("launch/sock")).expect("the socket's name removed");
    std::os::unix::fs::symlink(&real, scene.root.join("launch/sock")).expect("a link");
    let (code, _, error) = scene.run(&scene.registration(), &LAUNCH);
    assert_eq!(code, 1);
    assert!(error.contains("nothing presented"), "{error}");
    listener.set_nonblocking(true).expect("nonblocking");
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "the helper connected through the link"
    );
}

/// An invocation that is not a launch runs the real launcher unchanged, and presents nothing.
#[test]
fn an_invocation_that_is_not_a_launch_runs_the_real_launcher_unchanged() {
    let scene = Scene::new(true);
    let (code, out, _) = scene.run(&scene.registration(), &["--version"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "real:--version");
    assert!(scene.nothing_connected());
}

/// A launch is presented once with a well-formed credential that is not the file's, in the frame
/// the real launcher writes (with the environment where the record names a gateway); a backend
/// that closes the stream with no line is a refusal, and the real launcher runs after it with the
/// arguments the helper was given.
#[test]
fn a_launch_is_presented_once_with_a_forged_credential_and_then_the_real_launcher_runs() {
    let scene = Scene::new(true);
    let listener = scene.listener.try_clone().expect("the listener");
    let backend = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("a presentation");
        let mut line = String::new();
        std::io::BufReader::new(&stream)
            .read_line(&mut line)
            .expect("the frame");
        line
    });
    let (code, out, error) = scene.run(&scene.registration(), &LAUNCH);
    let line = backend.join().expect("the backend");
    assert_eq!(code, 0, "{error}");
    assert!(error.contains("forged presentation refused"), "{error}");
    assert_eq!(out.trim(), "real:launch -- /bin/true true --flag");
    let frame: serde_json::Value = serde_json::from_str(line.trim()).expect("one JSON frame");
    let launch = &frame["kr_launch"];
    let credential = launch["credential"].as_str().expect("a credential");
    assert_eq!(credential.len(), 64);
    assert!(credential.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(
        credential,
        "ab".repeat(32),
        "the credential is not the file's"
    );
    assert_eq!(launch["executable"], "/bin/true");
    assert_eq!(launch["arguments"], serde_json::json!(["true", "--flag"]));
    assert!(launch["pid"].is_u64() && launch["start"].is_u64());
    assert!(
        launch["environment"].is_object(),
        "a record with a gateway is presented the environment"
    );
}

/// A backend that accepts and never answers is waited for within the helper's bound, and the real
/// launcher runs all the same.
#[test]
fn a_backend_that_never_answers_is_bounded_and_the_real_launcher_runs() {
    let scene = Scene::new(false);
    let listener = scene.listener.try_clone().expect("the listener");
    let (release, held) = std::sync::mpsc::channel::<()>();
    let backend = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("a presentation");
        let _ = held.recv();
        drop(stream);
    });
    let (code, out, error) = scene.run(&scene.registration(), &LAUNCH);
    release.send(()).expect("released");
    backend.join().expect("the backend");
    assert_eq!(code, 0, "{error}");
    assert!(error.contains("no answer"), "{error}");
    assert_eq!(out.trim(), "real:launch -- /bin/true true --flag");
}

impl Scene {
    /// [`Scene::run`] where the helper must end within `limit`: it is ended at the limit, and none is
    /// returned, where it has not.
    fn run_within(
        &self,
        registration: &Path,
        arguments: &[&str],
        limit: std::time::Duration,
    ) -> Option<(i32, String, String)> {
        let mut child = Command::new(self.root.join("b/kr-hook"))
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("KALAREACH_E2E_FORGE_ROOT", &self.root)
            .env("KR_REGISTRATION", registration)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the forging launcher runs");
        let started = std::time::Instant::now();
        while child.try_wait().expect("the helper's state").is_none() {
            if started.elapsed() >= limit {
                child.kill().expect("the helper ended");
                child.wait().expect("the helper reaped");
                return None;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let output = child.wait_with_output().expect("the helper's output");
        Some((
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        ))
    }
}

/// The longest the helper may take over a presentation that does not complete: its own bound, five
/// seconds, and the time the real launcher takes to start.
const WITHIN: std::time::Duration = std::time::Duration::from_secs(9);

/// A backend that answers one byte at a time, never a whole line, cannot hold the launch past the
/// helper's bound for the whole answer: the bound is not renewed by each byte.
#[test]
fn a_backend_that_answers_a_byte_at_a_time_is_bounded_as_a_whole_and_the_real_launcher_runs() {
    let scene = Scene::new(false);
    let listener = scene.listener.try_clone().expect("the listener");
    let backend = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a presentation");
        let mut sent = 0;
        // One byte every half second, for as long as the helper reads: far past its bound.
        while sent < 60 && stream.write_all(b"x").is_ok() {
            sent += 1;
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        sent
    });
    let ran = scene.run_within(&scene.registration(), &LAUNCH, WITHIN);
    assert!(
        ran.is_some(),
        "the helper ended within {WITHIN:?} of a backend that answers a byte at a time"
    );
    let (code, out, error) = ran.expect("asserted above");
    assert_eq!(code, 0, "{error}");
    assert!(error.contains("no answer"), "{error}");
    assert_eq!(out.trim(), "real:launch -- /bin/true true --flag");
    let sent = backend.join().expect("the backend");
    assert!(
        sent < 60,
        "the helper stopped reading: {sent} bytes were taken"
    );
}

/// An endpoint whose queue of connections is full is waited for within the helper's bound, and the
/// real launcher runs all the same: a connection that waits without end does not hold the launch.
/// The queue is made as short as the system allows and filled by one connection that nothing
/// accepts: on Linux the next connection then waits, which the case shows with a connection that
/// does not wait before it runs the helper; macOS refuses it at once, so there the case shows only
/// that the launcher runs.
#[test]
fn an_endpoint_whose_queue_is_full_is_bounded_and_the_real_launcher_runs() {
    let scene = Scene::new(false);
    let socket = scene.root.join("launch/sock");
    rustix::net::listen(&scene.listener, 0).expect("the queue is made short");
    let held = std::os::unix::net::UnixStream::connect(&socket).expect("the first connection");
    #[cfg(target_os = "linux")]
    {
        use rustix::net::{AddressFamily, SocketAddrUnix, SocketFlags, SocketType};
        let control = rustix::net::socket_with(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
            None,
        )
        .expect("a socket");
        let address = SocketAddrUnix::new(&socket).expect("the endpoint's address");
        assert_eq!(
            rustix::net::connect(&control, &address),
            Err(rustix::io::Errno::AGAIN),
            "a second connection to the endpoint waits: its queue is full"
        );
    }
    let ran = scene.run_within(&scene.registration(), &LAUNCH, WITHIN);
    assert!(
        ran.is_some(),
        "the helper ended within {WITHIN:?} of an endpoint whose queue is full"
    );
    let (code, out, error) = ran.expect("asserted above");
    assert_eq!(code, 0, "{error}");
    assert!(error.contains("no answer"), "{error}");
    assert_eq!(out.trim(), "real:launch -- /bin/true true --flag");
    drop(held);
}

/// The directory this test program's own build put its programs in, the real launcher among them.
fn built_directory() -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test program");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    directory
}

/// The frame the forging launcher presents for a launch is the frame the real launcher presents for
/// the same launch, member for member: they differ in the credential, which is the point, and in the
/// pid and the start of the process that presents each, which are the processes'.
#[test]
fn a_frame_the_forging_launcher_presents_equals_the_real_launchers_but_for_the_credential_and_its_own_identity()
 {
    let real = built_directory().join("kr-hook");
    assert!(
        real.is_file(),
        "the real launcher is not built at {}; build it with `cargo build -p kr-hook --bins`",
        real.display()
    );
    let scene = Scene::new(true);
    // The real launcher takes where the added flags stand from the registration's name, and
    // refuses one that does not say: this launch has none added.
    let registration = scene.root.join("launch/registration.0.0");
    write_private(&registration, "");
    let listener = scene.listener.try_clone().expect("the listener");
    listener.set_nonblocking(true).expect("nonblocking");
    let backend = std::thread::spawn(move || {
        let mut lines = Vec::new();
        let began = std::time::Instant::now();
        while lines.len() < 2 && began.elapsed() < std::time::Duration::from_secs(30) {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking");
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                        .expect("a bound");
                    let mut line = String::new();
                    std::io::BufReader::new(&stream)
                        .read_line(&mut line)
                        .expect("the frame");
                    lines.push(line);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("the listener: {error}"),
            }
        }
        lines
    });
    // The real launcher presents first, then the forging one, each in the same environment.
    let _ = Command::new(&real)
        .args(LAUNCH)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("KALAREACH_E2E_FORGE_ROOT", &scene.root)
        .env("KR_REGISTRATION", &registration)
        .output()
        .expect("the real launcher runs");
    let _ = scene.run(&registration, &LAUNCH);
    let lines = backend.join().expect("the backend");
    assert_eq!(
        lines.len(),
        2,
        "both launchers presented a frame: {lines:?}"
    );
    let frame = |line: &str| -> serde_json::Map<String, serde_json::Value> {
        let parsed: serde_json::Value = serde_json::from_str(line.trim()).expect("one JSON frame");
        parsed["kr_launch"]
            .as_object()
            .cloned()
            .expect("a launch frame")
    };
    let (real_frame, forged_frame) = (frame(&lines[0]), frame(&lines[1]));
    let keys = |frame: &serde_json::Map<String, serde_json::Value>| {
        frame.keys().cloned().collect::<Vec<_>>()
    };
    assert_eq!(keys(&real_frame), keys(&forged_frame));
    assert!(
        real_frame.contains_key("environment"),
        "a record with a gateway is presented the environment: {real_frame:?}"
    );
    for (key, value) in &real_frame {
        if matches!(key.as_str(), "credential" | "pid" | "start") {
            continue;
        }
        assert_eq!(
            Some(value),
            forged_frame.get(key),
            "the member {key} of the two frames"
        );
    }
    assert_eq!(real_frame["credential"], "ab".repeat(32));
    let forged = forged_frame["credential"].as_str().expect("a credential");
    assert!(forged.len() == 64 && forged.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_ne!(forged, "ab".repeat(32));
    for frame in [&real_frame, &forged_frame] {
        assert!(frame["pid"].is_u64() && frame["start"].is_u64());
    }
    assert_ne!(real_frame["pid"], forged_frame["pid"]);
}
