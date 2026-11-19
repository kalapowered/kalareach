//! `kr voice credential`, run the way a person runs it, against a real control daemon.
//!
//! The daemon is this test's own: the real `kr-controller` service, started in this process on a
//! host tree of the test's own, with its real endpoint, handshake and admission and its real secret
//! store, and a supervisor that starts no worker. `kr` is the real binary, copied to the internal
//! disk and run with that tree's directories, on plain pipes and on a real pseudo-terminal. No
//! provider is contacted and no real key is used: the key is a sentinel no provider issued.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::ids::BuildId;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde_json::Value;

mod support;

/// A value no real key has, so finding any part of it in what a command printed is a leak.
const SENTINEL: &str = "kr-test-voice-key-0123456789abcdef";

/// The longest wait for anything a command does.
const DEADLINE: Duration = Duration::from_secs(60);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A supervisor that starts nothing. None of these commands needs a worker.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// A host tree and its running daemon.
struct Host {
    clients: tokio::task::JoinHandle<kr_controller::error::Result<()>>,
    // Declared last: the directory is removed after every field above has let go of its files.
    temp: kr_ipc::testing::TempHost,
}

impl Drop for Host {
    fn drop(&mut self) {
        self.clients.abort();
    }
}

impl Host {
    async fn start() -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = open_store_in(&secrets).expect("a secret store in the test tree");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(NoWorkers),
            worker_program: PathBuf::from("/nonexistent/kr-worker"),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let clients = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
        Self { temp, clients }
    }

    /// `kr` with this tree's directories, from the root directory, on no terminal.
    fn command(&self, line: &[&str]) -> Command {
        let mut command = Command::new(support::kr());
        command
            .args(line)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", self.temp.root())
            .env("KR_RUNTIME_DIR", self.temp.paths().runtime_root())
            .env("KR_STATE_DIR", self.temp.paths().state_root())
            .current_dir("/");
        command
    }

    /// Runs `kr` with nothing on standard input.
    fn kr(&self, line: &[&str]) -> Output {
        self.command(line)
            .stdin(Stdio::null())
            .output()
            .expect("kr runs")
    }

    /// Runs `kr` with `input` on a pipe as its standard input.
    fn piped(&self, line: &[&str], input: &[u8]) -> Output {
        let mut child = self
            .command(line)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("kr runs");
        child
            .stdin
            .take()
            .expect("a pipe")
            .write_all(input)
            .expect("the input is written");
        child.wait_with_output().expect("kr ends")
    }

    /// Runs `kr` with `--json` and reads the one document it printed, and how it exited.
    fn json(&self, line: &[&str]) -> (Option<i32>, Value) {
        let mut asked = line.to_vec();
        asked.push("--json");
        let output = self.kr(&asked);
        let document = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "kr {} printed no JSON ({error}): {}{}",
                asked.join(" "),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), document)
    }

    /// What `kr doctor` says of the voice key.
    fn voice_check(&self) -> Value {
        let (_, report) = self.json(&["doctor"]);
        report["doctor"]["checks"]
            .as_array()
            .and_then(|checks| {
                checks
                    .iter()
                    .find(|check| check["id"] == "voice-credential")
            })
            .cloned()
            .unwrap_or_else(|| panic!("kr doctor reports the voice key: {report}"))
    }

    /// The files under the secret store's folder, with their bytes.
    fn secret_files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut found = Vec::new();
        let mut pending = vec![self.temp.environment().secrets_dir()];
        while let Some(folder) = pending.pop() {
            for entry in std::fs::read_dir(&folder).into_iter().flatten().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else if let Ok(bytes) = std::fs::read(&path) {
                    found.push((path, bytes));
                }
            }
        }
        found
    }
}

/// Every text a finished command left, for a search for the key.
fn everything(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_no_key(text: &str, what: &str) {
    for window in [
        SENTINEL,
        &SENTINEL[..8],
        &SENTINEL[12..20],
        &SENTINEL[SENTINEL.len() - 8..],
    ] {
        assert!(!text.contains(window), "{what} carries {window:?}: {text}");
    }
}

/// What a pseudo-terminal showed, collected as it arrives.
struct Shown {
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Shown {
    fn collect(mut reader: Box<dyn Read + Send>) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut chunk = [0_u8; 1024];
            while let Ok(taken) = reader.read(&mut chunk) {
                if taken == 0 {
                    break;
                }
                into.lock()
                    .expect("not poisoned")
                    .extend_from_slice(&chunk[..taken]);
            }
        });
        Self { seen }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().expect("not poisoned")).into_owned()
    }

    fn wait_for(&self, marker: &str, what: &str) {
        let started = Instant::now();
        while !self.text().contains(marker) {
            assert!(
                started.elapsed() < DEADLINE,
                "{what}: waited for {marker:?} in {:?}",
                self.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// The modes of the terminal a pair holds, read through the slave's own device.
fn modes(tty: &Path) -> rustix::termios::Termios {
    let slave = std::fs::File::open(tty).expect("opens the terminal's device");
    rustix::termios::tcgetattr(&slave).expect("reads the terminal's modes")
}

fn shows_what_is_typed(modes: &rustix::termios::Termios) -> bool {
    modes
        .local_modes
        .contains(rustix::termios::LocalModes::ECHO)
}

/// What one run of a program on a pseudo-terminal did.
struct Typed {
    shown: String,
    status: u32,
    during: rustix::termios::Termios,
    before: rustix::termios::Termios,
    after: rustix::termios::Termios,
}

/// Starts `builder` on a new pseudo-terminal, waits for `marker` to be shown, reads the terminal's
/// modes, types `keys`, and waits for the program to end.
fn type_at(builder: CommandBuilder, marker: &str, keys: &[u8]) -> Typed {
    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("opens a terminal");
    let tty = pty.master.tty_name().expect("the terminal has a device");
    let before = modes(&tty);
    let shown = Shown::collect(pty.master.try_clone_reader().expect("a reader"));
    let mut writer = pty.master.take_writer().expect("a writer");
    let mut child = pty
        .slave
        .spawn_command(builder)
        .expect("starts the program");
    shown.wait_for(marker, "the program asked for its input");
    let during = modes(&tty);
    writer.write_all(keys).expect("types");
    writer.flush().expect("types");
    let status = child.wait().expect("the program ends").exit_code();
    // The reader drains what is left once the program has ended.
    std::thread::sleep(Duration::from_millis(200));
    let after = modes(&tty);
    Typed {
        shown: shown.text(),
        status,
        during,
        before,
        after,
    }
}

impl Host {
    fn on_a_terminal(&self, line: &[&str]) -> CommandBuilder {
        let mut builder = CommandBuilder::new(support::kr());
        for argument in line {
            builder.arg(argument);
        }
        builder.env_clear();
        builder.env("PATH", "/usr/bin:/bin");
        builder.env("HOME", self.temp.root());
        builder.env("KR_RUNTIME_DIR", self.temp.paths().runtime_root());
        builder.env("KR_STATE_DIR", self.temp.paths().state_root());
        builder.cwd("/");
        builder
    }
}

const SET: &[&str] = &["voice", "credential", "set", "--provider", "openai-live"];
const REMOVE: &[&str] = &["voice", "credential", "remove", "--provider", "openai-live"];

/// A key given as an argument is refused with the usage code and a sentence that does not repeat
/// it, and a key in the environment is not read; a pipe sets the key, and the host holds it only
/// after the pipe.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_voice_credential_set_reads_a_pipe_or_a_silent_terminal_and_refuses_an_argument() {
    let host = Host::start().await;
    assert_eq!(
        host.voice_check()["detail"],
        "none",
        "the host starts with no key"
    );

    // An argument is refused before anything is read or sent, with the usage code, and the
    // refusal repeats nothing of it.
    let joined = format!("--key={SENTINEL}");
    let lines: Vec<Vec<&str>> = vec![
        [SET, &[SENTINEL]].concat(),
        [SET, &["--", SENTINEL]].concat(),
        [SET, &["--key", SENTINEL]].concat(),
        [SET, &[joined.as_str()]].concat(),
        [&SET[..3], &["--provider", SENTINEL]].concat(),
    ];
    for line in lines {
        let output = host.piped(&line, b"");
        assert_eq!(
            output.status.code(),
            Some(2),
            "{line:?}: {}",
            everything(&output)
        );
        assert_no_key(&everything(&output), "the refusal of an argument");
    }
    // The environment is not a place a key is read from: with nothing on the input the command
    // asks for nothing and changes nothing.
    let output = host
        .command(SET)
        .env("KR_VOICE_KEY", SENTINEL)
        .env("OPENAI_API_KEY", SENTINEL)
        .stdin(Stdio::null())
        .output()
        .expect("kr runs");
    assert_eq!(output.status.code(), Some(2), "{}", everything(&output));
    assert!(everything(&output).contains("no key was entered"));
    assert_no_key(
        &everything(&output),
        "a command given the key in its environment",
    );
    assert_eq!(
        host.voice_check()["detail"],
        "none",
        "nothing was held after the refusals"
    );

    // A pipe sets the key. Nothing the command printed carries it, and the host holds it.
    let output = host.piped(SET, format!("{SENTINEL}\n").as_bytes());
    assert_eq!(output.status.code(), Some(0), "{}", everything(&output));
    assert!(everything(&output).contains("This host holds the OpenAI key now."));
    assert_no_key(&everything(&output), "a command that set the key");
    let held = host.voice_check();
    assert_eq!(held["detail"], "held for openai-live", "{held}");
    assert_eq!(held["status"], "ok", "{held}");

    // The same command with `--json` prints one document that names the provider and no key.
    let output = host.piped(
        &[SET, &["--json"][..]].concat(),
        format!("{SENTINEL}\r\n").as_bytes(),
    );
    assert_eq!(output.status.code(), Some(0), "{}", everything(&output));
    let document: Value = serde_json::from_slice(&output.stdout).expect("one document");
    assert_eq!(document["kind"], "openai_live", "{document}");
    assert_eq!(document["in_force"], Value::Bool(true), "{document}");
    assert_no_key(&everything(&output), "the document of a set");

    // A key the host refuses is refused with the host's own sentence, and the one held stays.
    let output = host.piped(SET, b"too short\n");
    assert_ne!(output.status.code(), Some(0), "{}", everything(&output));
    assert_no_key(
        &everything(&output),
        "the refusal of a key of the wrong shape",
    );
    assert_eq!(host.voice_check()["detail"], "held for openai-live");

    // Removing the key says so, and removing it again says there was none.
    let output = host.kr(REMOVE);
    assert!(
        everything(&output).contains("This host deleted the OpenAI key."),
        "{}",
        everything(&output)
    );
    assert_eq!(host.voice_check()["detail"], "none");
    let output = host.kr(REMOVE);
    assert!(
        everything(&output).contains("This host held no OpenAI key."),
        "{}",
        everything(&output)
    );
}

/// A terminal shows nothing of what is typed, the key is taken and the terminal's modes are back
/// when the command ends; Ctrl+C ends the read with nothing changed and the modes back. The control
/// is a program that leaves echo on: the same harness shows what it was typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_typed_at_a_terminal_is_not_shown_and_the_terminal_comes_back() {
    let host = Host::start().await;
    let prompt = "Nothing you type is shown.";

    // The control: a program that does not turn echo off shows the typed bytes to the harness.
    let mut control = CommandBuilder::new("/bin/sh");
    control.arg("-c");
    control.arg("printf 'ready\\n'; read line; printf 'done\\n'");
    control.env_clear();
    control.env("PATH", "/usr/bin:/bin");
    let echoed = type_at(control, "ready", format!("{SENTINEL}\r").as_bytes());
    assert!(
        echoed.shown.contains(SENTINEL),
        "the harness sees an echoed key: {:?}",
        echoed.shown
    );
    assert!(
        shows_what_is_typed(&echoed.during),
        "the control's terminal echoes"
    );

    // The key is typed, with a typing mistake corrected, and taken.
    let typed = type_at(
        host.on_a_terminal(SET),
        prompt,
        format!("{SENTINEL}x\x7f\r").as_bytes(),
    );
    assert_eq!(typed.status, 0, "{:?}", typed.shown);
    assert!(typed.shown.contains(prompt), "{:?}", typed.shown);
    assert_no_key(&typed.shown, "what the terminal showed");
    assert!(
        !shows_what_is_typed(&typed.during),
        "the terminal shows nothing while the key is read"
    );
    assert_eq!(
        shows_what_is_typed(&typed.after),
        shows_what_is_typed(&typed.before),
        "the terminal shows what is typed again after the key"
    );
    assert_eq!(typed.after.local_modes, typed.before.local_modes);
    assert_eq!(typed.after.input_modes, typed.before.input_modes);
    assert_eq!(host.voice_check()["detail"], "held for openai-live");
    host.kr(REMOVE);

    // Ctrl+C ends the read: nothing is changed, the modes are back and the key is not shown.
    let cancelled = type_at(
        host.on_a_terminal(SET),
        prompt,
        format!("{SENTINEL}\x03").as_bytes(),
    );
    assert_ne!(cancelled.status, 0, "{:?}", cancelled.shown);
    assert!(
        cancelled.shown.contains("cancelled"),
        "{:?}",
        cancelled.shown
    );
    assert_no_key(&cancelled.shown, "what the terminal showed after Ctrl+C");
    assert_eq!(cancelled.after.local_modes, cancelled.before.local_modes);
    assert_eq!(cancelled.after.input_modes, cancelled.before.input_modes);
    assert_eq!(
        host.voice_check()["detail"],
        "none",
        "a cancelled entry holds nothing"
    );
}

/// KR-REQ-26.42: a host with no account adds and removes a voice key, needs no account to do
/// either, and still names each managed integration it does without as one it does not need.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_with_no_account_adds_and_removes_a_voice_credential_and_needs_no_account() {
    let host = Host::start().await;
    let output = host.piped(SET, format!("{SENTINEL}\n").as_bytes());
    assert_eq!(output.status.code(), Some(0), "{}", everything(&output));
    assert_eq!(host.voice_check()["detail"], "held for openai-live");
    let output = host.kr(REMOVE);
    assert_eq!(output.status.code(), Some(0), "{}", everything(&output));
    assert_eq!(host.voice_check()["detail"], "none");

    let (_, account) = host.json(&["account", "show"]);
    assert_eq!(account["state"], "signed_out", "{account}");
    let (_, report) = host.json(&["doctor"]);
    support::the_managed_integrations_are_named_as_ones_the_host_does_without(&report);
}

/// P1-8: `kr doctor` tells a held key, none and an unreadable store apart, and a store that cannot
/// be read is never reported as none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_doctor_tells_held_none_and_unreadable_apart() {
    let host = Host::start().await;
    let none = host.voice_check();
    assert_eq!(none["detail"], "none", "{none}");
    assert_eq!(none["status"], "not_applicable", "{none}");

    let before: Vec<PathBuf> = host
        .secret_files()
        .into_iter()
        .map(|(path, _)| path)
        .collect();
    let output = host.piped(SET, format!("{SENTINEL}\n").as_bytes());
    assert_eq!(output.status.code(), Some(0), "{}", everything(&output));
    let held = host.voice_check();
    assert_eq!(held["detail"], "held for openai-live", "{held}");
    assert_eq!(held["status"], "ok", "{held}");

    // The item is the one file the store gained. It is replaced by bytes the host cannot read.
    let gained: Vec<PathBuf> = host
        .secret_files()
        .into_iter()
        .map(|(path, _)| path)
        .filter(|path| !before.contains(path))
        .collect();
    assert_eq!(gained.len(), 1, "the store gained one item: {gained:?}");
    std::fs::write(&gained[0], b"not an item").expect("the item is replaced");
    let unreadable = host.voice_check();
    assert_eq!(
        unreadable["detail"], "unreadable (the secret store refused)",
        "{unreadable}"
    );
    assert_eq!(unreadable["status"], "warning", "{unreadable}");
    assert_no_key(&unreadable.to_string(), "the doctor's report");
}
