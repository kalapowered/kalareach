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
    _directory: PrivateTempDir,
    root: PathBuf,
    listener: UnixListener,
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
            _directory: directory,
            root,
            listener,
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
