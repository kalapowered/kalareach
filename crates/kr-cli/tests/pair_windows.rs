//! `kr pair` for a host's first owner, against a real control daemon on Windows.
//!
//! The Unix twin of these cases is `crates/kr-cli/tests/pair.rs`. This one exists because the first
//! owner's confirmation rests on things this platform does its own way: whether a standard stream is
//! a console, and whether this process is inside a KalaReach session, whose membership a session's
//! worker answers over its own named pipe. The daemon is the `kr-controller` executable the
//! workspace builds beside this test, put on the network on loopback alone and serving its local
//! control endpoint; it has no owner when it starts.
//!
//! What the daemon's network listener does on this platform is the first thing these tests
//! establish: [`Host::start`] does not return until the daemon answers its local endpoint, and it
//! cannot answer that until it has bound the listener the configuration asks for.

#![cfg(windows)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::scalars::Nullable;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

use support::kr;

/// How long a wait for the daemon is given before the test calls it a failure.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// How long a process this test told to stop is given to go before the test moves on without it.
const STOP_DEADLINE: Duration = Duration::from_secs(10);

/// Stops a process this test started and waits a bounded time for it to go, so a process that
/// will not stop is never waited on for good. Returns what happened, for a failure message.
fn stop(child: &mut std::process::Child) -> String {
    let killed = child.kill();
    let asked = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return format!("it stopped ({status})"),
            Ok(None) if asked.elapsed() < STOP_DEADLINE => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                return format!(
                    "it was still running {STOP_DEADLINE:?} after it was told to stop ({killed:?})"
                );
            }
            Err(error) => {
                return format!("its state could not be read after it was told to stop: {error}");
            }
        }
    }
}

/// The build identity `kr` and this test present to the daemon.
fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Returns an executable the workspace builds beside this test, when it has been built.
fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

/// Copies an executable where a launched process may run it from, and returns its new path.
fn copy_into(source: &Path, directory: &Path) -> PathBuf {
    let destination = directory.join(source.file_name().expect("the executable has a name"));
    kr_ipc::testing::place_program(source, &destination);
    destination
}

/// A host tree with a running daemon on loopback, and the `kr` that talks to it over its local
/// control endpoint.
struct Host {
    daemon: Option<std::process::Child>,
    temp: kr_ipc::testing::TempHost,
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            stop(&mut daemon);
        }
    }
}

impl Host {
    async fn start() -> Self {
        let controller = beside_this_test("kr-controller").unwrap_or_else(|| {
            panic!(
                "the kr-controller executable is not built beside this test, so this check cannot \
                 run; build it with `cargo build -p kr-controller` first"
            )
        });
        let temp = kr_ipc::testing::TempHost::create();
        // The configuration document puts the host on the network: loopback alone, no relay and no
        // discovery. Binding this listener on this platform is what these tests first establish.
        let mut document = ConfigurationDocument::empty();
        document.revision = 1;
        document.network.enabled = Nullable::some(true);
        document.network.bind_address = Nullable::some("127.0.0.1:0".to_owned());
        let path = kr_worker::config::document_path(&temp.environment());
        std::fs::create_dir_all(path.parent().expect("the document has a directory"))
            .expect("the state directory");
        kr_ipc::paths::write_owner_only_file(
            &path,
            kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
        )
        .expect("the configuration document");
        let bin = temp.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a directory for the executable");
        let controller = copy_into(&controller, &bin);
        let log = std::fs::File::create(temp.root().join("daemon.log")).expect("the daemon's log");
        let child = std::process::Command::new(&controller)
            .current_dir(temp.root())
            .arg("--runtime-dir")
            .arg(temp.root().join("r"))
            .arg("--state-dir")
            .arg(temp.root().join("s"))
            .arg("--secret-store")
            .arg("file")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("duplicates the log"))
            .stderr(log)
            .spawn()
            .expect("the daemon starts");
        let host = Self {
            daemon: Some(child),
            temp,
        };
        let endpoint = host
            .temp
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let started = Instant::now();
        while LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .is_err()
        {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the daemon did not answer its local endpoint; its log says: {}",
                host.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        host
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.temp.root().join("daemon.log")).unwrap_or_default()
    }

    /// The environment `kr` runs with: this host's directories on top of the platform's own, and
    /// never a session or attachment identifier of this test's own.
    fn environment(&self) -> Vec<(String, String)> {
        let mut environment: Vec<(String, String)> = std::env::vars()
            .filter(|(name, _)| name != "KR_SESSION" && name != "KR_ATTACHMENT")
            .collect();
        environment.push((
            "KR_RUNTIME_DIR".to_owned(),
            self.temp.paths().runtime_root().display().to_string(),
        ));
        environment.push((
            "KR_STATE_DIR".to_owned(),
            self.temp.paths().state_root().display().to_string(),
        ));
        environment
    }

    /// The root of the system drive, which exists, is readable, and is not the build tree.
    fn system_drive_root(&self) -> std::ffi::OsString {
        std::env::var_os("SystemDrive").map_or_else(
            || std::ffi::OsString::from(r"C:\"),
            |drive| {
                let mut root = drive;
                root.push(r"\");
                root
            },
        )
    }

    /// Runs `kr` on a pseudo-console of its own, which is its controlling terminal, with `extra` set
    /// on top of the host environment.
    fn on_console(&self, arguments: &[&str], extra: &[(&str, &str)]) -> OnConsole {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 40,
                cols: 200,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a console");
        let mut command = CommandBuilder::new(kr());
        command.args(arguments);
        command.env_clear();
        for (name, value) in self.environment() {
            command.env(name, value);
        }
        command.env("TERM", "xterm-256color");
        for (name, value) in extra {
            command.env(name, value);
        }
        command.cwd(self.system_drive_root());
        let child = pty.slave.spawn_command(command).expect("starts kr");
        drop(pty.slave);
        let writer: Arc<Mutex<Box<dyn Write + Send>>> =
            Arc::new(Mutex::new(pty.master.take_writer().expect("a writer")));
        let output = ConsoleOutput::collect(
            pty.master.try_clone_reader().expect("a reader"),
            Arc::clone(&writer),
        );
        OnConsole {
            child,
            output,
            writer,
            _master: pty.master,
        }
    }

    /// Writes an unreadable file where a session descriptor would be, so a guard that reads the
    /// sessions cannot establish whether this process is inside one.
    fn unreadable_descriptor(&self) {
        let directory = self.temp.environment().descriptors_dir();
        std::fs::create_dir_all(&directory).expect("the descriptors directory");
        std::fs::write(
            directory.join("00000000-0000-4000-8000-000000000002.kr"),
            b"not a descriptor",
        )
        .expect("an unreadable descriptor");
    }

    /// Runs `kr` on plain pipes, with `extra` set on top of the host environment. It keeps this
    /// process's console, as a command piped to another at a console does, so a guard that let it
    /// through could leave it waiting there for someone to type: past the deadline it is stopped
    /// and the test fails rather than waiting for good.
    fn kr(&self, arguments: &[&str], extra: &[(&str, &str)]) -> std::process::Output {
        let cwd = self.system_drive_root();
        let mut command = std::process::Command::new(kr());
        command.args(arguments).env_clear().envs(self.environment());
        for (name, value) in extra {
            command.env(name, value);
        }
        let mut child = command
            .current_dir(&cwd)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("runs kr");
        let stdout = Drained::collect(child.stdout.take().expect("kr's standard output"));
        let stderr = Drained::collect(child.stderr.take().expect("kr's standard error"));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("kr's state") {
                break status;
            }
            if started.elapsed() >= LIVENESS_DEADLINE {
                let stopped = stop(&mut child);
                panic!(
                    "kr did not finish within {LIVENESS_DEADLINE:?} and was told to stop, and \
                     {stopped}; its standard error says: {}",
                    String::from_utf8_lossy(&stderr.so_far())
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        std::process::Output {
            status,
            stdout: stdout.finish(),
            stderr: stderr.finish(),
        }
    }
}

/// Everything a pipe from `kr` has carried, read on a thread of its own so a full pipe never holds
/// `kr` up.
struct Drained {
    seen: Arc<Mutex<Vec<u8>>>,
    reader: std::thread::JoinHandle<std::io::Result<()>>,
}

impl Drained {
    fn collect(mut pipe: impl Read + Send + 'static) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        let reader = std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            loop {
                match pipe.read(&mut buffer) {
                    Ok(0) => return Ok(()),
                    Ok(read) => {
                        if let Ok(mut seen) = collected.lock() {
                            seen.extend_from_slice(&buffer[..read]);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => return Err(error),
                }
            }
        });
        Self { seen, reader }
    }

    fn so_far(&self) -> Vec<u8> {
        self.seen
            .lock()
            .map(|seen| seen.to_vec())
            .unwrap_or_default()
    }

    /// Everything the pipe carried, once it has closed, which it does when `kr` has ended. A read
    /// that failed fails the test rather than passing part of the output off as all of it.
    fn finish(self) -> Vec<u8> {
        let started = Instant::now();
        while !self.reader.is_finished() {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "a pipe from kr stayed open after kr ended"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let Self { seen, reader } = self;
        reader
            .join()
            .expect("the thread reading kr's pipe")
            .expect("kr's pipe is read to its end");
        seen.lock().expect("kr's output is not poisoned").to_vec()
    }
}

/// KR-REQ-10.53: the first owner is not confirmed where there is no terminal. With standard input
/// and output on pipes, `kr` refuses before asking anything, and nothing is issued. This also
/// establishes that the daemon's network listener came up on this platform: `kr` reached the daemon
/// for the challenge that precedes the terminal check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_without_a_terminal() {
    let host = Host::start().await;
    let output = host.kr(&["pair", "invite", "--owner", "--direct"], &[]);
    assert_eq!(
        output.status.code(),
        Some(6),
        "stderr: {}\ndaemon: {}",
        String::from_utf8_lossy(&output.stderr),
        host.log()
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("needs a terminal"),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `kr` running on a pseudo-console of its own.
struct OnConsole {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    output: ConsoleOutput,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl OnConsole {
    /// Types some bytes at the console.
    fn type_in(&mut self, bytes: &[u8]) {
        let mut writer = self
            .writer
            .lock()
            .expect("the console writer is not poisoned");
        writer.write_all(bytes).expect("typed");
        writer.flush().expect("flushed");
    }

    /// Waits for the command to end, and returns whether it succeeded and what it printed.
    fn finish(mut self) -> (bool, String) {
        let started = Instant::now();
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("the command's state") {
                break status;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "kr did not finish; it printed: {}",
                self.output.text()
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        std::thread::sleep(Duration::from_millis(200));
        (status.success(), self.output.text())
    }
}

/// Everything a console has printed so far, read on a thread of its own.
struct ConsoleOutput {
    seen: Arc<Mutex<Vec<u8>>>,
}

impl ConsoleOutput {
    fn collect(
        mut reader: Box<dyn Read + Send>,
        writer: Arc<Mutex<Box<dyn Write + Send>>>,
    ) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        std::thread::spawn(move || {
            // The pseudo-console asks this terminal where its cursor is. portable-pty creates it with
            // PSEUDOCONSOLE_INHERIT_CURSOR, and with that flag the console host writes a cursor-position
            // report request (`ESC[6n`) when it starts and serves nothing to the process attached to it
            // until the terminal answers (`ESC[row;colR`). A real terminal answers at once; one that
            // never does holds `kr` before its first console call returns, so it never gets as far as
            // refusing or asking. This stand-in answers a fixed position, which is all the console host
            // needs.
            const QUERY: &[u8] = b"\x1b[6n";
            const REPLY: &[u8] = b"\x1b[1;1R";
            let mut answered = 0_usize;
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let asked = match collected.lock() {
                    Ok(mut seen) => {
                        seen.extend_from_slice(&buffer[..read]);
                        seen.windows(QUERY.len())
                            .filter(|window| *window == QUERY)
                            .count()
                    }
                    Err(_) => answered,
                };
                while answered < asked {
                    if let Ok(mut writer) = writer.lock() {
                        let _ = writer.write_all(REPLY);
                        let _ = writer.flush();
                    }
                    answered += 1;
                }
            }
        });
        Self { seen }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(
            &self
                .seen
                .lock()
                .expect("the console output is not poisoned"),
        )
        .into_owned()
    }

    /// Waits until the console shows `marker`, failing when it never does.
    fn expect(&self, marker: &str, what: &str) {
        let started = Instant::now();
        while !self.text().contains(marker) {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for {marker:?}; the console shows: {}",
                started.elapsed(),
                self.text()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// KR-REQ-10.53: a host with no owner has its first owner's invitation confirmed at a console
/// outside every session. `kr` asks the person to type `pair`, and on that it issues the invitation
/// a new device confirms.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_owner_invitation_is_confirmed_at_a_console() {
    let host = Host::start().await;
    let mut console = host.on_console(&["pair", "invite", "--owner", "--direct"], &[]);
    console
        .output
        .expect("Type pair to issue the invitation", "kr asks the person");
    console.type_in(b"pair\r");
    let (succeeded, printed) = console.finish();
    assert!(succeeded, "kr pair invite: {printed}\n{}", host.log());
    assert!(
        printed.contains("kr pair confirm "),
        "kr issues the invitation: {printed}"
    );
}

/// KR-REQ-10.53: a console inside a KalaReach session is not where the first owner is confirmed.
/// With `KR_SESSION` or `KR_ATTACHMENT` set, `kr` refuses on a real console and asks nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_inside_a_session() {
    let host = Host::start().await;
    for variable in ["KR_SESSION", "KR_ATTACHMENT"] {
        let console = host.on_console(
            &["pair", "invite", "--owner", "--direct"],
            &[(variable, "00000000-0000-4000-8000-000000000001")],
        );
        let (succeeded, printed) = console.finish();
        assert!(!succeeded, "{printed}");
        assert!(printed.contains(&format!("{variable} is set")), "{printed}");
        assert!(
            !printed.contains("Type pair"),
            "nothing was asked: {printed}"
        );
    }
}

/// KR-REQ-10.53: where it cannot be established whether this process is inside a session, because a
/// session descriptor cannot be read, the first owner is not confirmed even at a console.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_where_membership_is_unknown() {
    let host = Host::start().await;
    host.unreadable_descriptor();
    let console = host.on_console(&["pair", "invite", "--owner", "--direct"], &[]);
    let (succeeded, printed) = console.finish();
    assert!(!succeeded, "{printed}");
    assert!(printed.contains("cannot be established"), "{printed}");
    assert!(
        !printed.contains("Type pair"),
        "nothing was asked: {printed}"
    );
}

/// A terminal attached to a real worker's session, holding its keys: what it types reaches the
/// session's root shell, and what the session writes reaches it.
struct WorkerTerminal {
    client: LocalClient,
    session_id: kr_protocol::ids::SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
    seen: String,
}

impl WorkerTerminal {
    /// Attaches to the session's worker through its own descriptor and endpoint, at the session's
    /// own size, takes the keys and subscribes to what the session writes.
    ///
    /// At the session's size the worker streams the session's output as it is written. A terminal
    /// of another size that holds no geometry of its own is drawn a projection of the screen
    /// instead, which carries none of the session's output events.
    async fn attach(
        environment: &kr_ipc::paths::EnvironmentPaths,
        session_id: kr_protocol::ids::SessionId,
        dimensions: kr_protocol::session::Dimensions,
    ) -> Self {
        use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
        use kr_protocol::envelope::ActionTarget;
        use kr_protocol::ids::ActionId;
        use kr_protocol::method::Method;
        use kr_protocol::scalars::CanonicalSet;

        let descriptor = kr_ipc::descriptor::read_all(environment)
            .expect("reads the runtime directory")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("the session's descriptor is published");
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the worker");
        client
            .verify_worker(&descriptor)
            .await
            .expect("the worker answers the descriptor's challenge");
        let target = ActionTarget {
            environment_id: descriptor.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        };
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(dimensions),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker attaches the terminal")
            .to_typed()
            .expect("decodes");
        let attachment_id = attached.attachment.attachment_id;
        let lease: kr_protocol::input::InputAcquireResult = client
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &kr_protocol::input::InputAcquireParams {
                    session_id,
                    attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker hands this terminal the keys")
            .to_typed()
            .expect("decodes");
        let mut streams = CanonicalSet::new();
        streams.insert(kr_protocol::recovery::EventStream::Output);
        // The subscription is the last call: a client drops what arrives while it waits for an
        // answer of its own, and the screen it is drawn is queued the moment it subscribes.
        client
            .request(
                Method::EventsSubscribe,
                &kr_protocol::recovery::EventsSubscribeParams {
                    session_id,
                    attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker subscribes the terminal");
        Self {
            client,
            session_id,
            attachment_id,
            epoch: lease.lease.epoch,
            sequence: 0,
            seen: String::new(),
        }
    }

    /// Types one line into the session's root shell.
    async fn type_line(&mut self, line: &str) {
        let _: kr_protocol::input::InputWriteResult = self
            .client
            .request(
                kr_protocol::method::Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    epoch: self.epoch,
                    sequence: kr_protocol::ids::InputSequence::new(self.sequence),
                    bytes: kr_protocol::scalars::Bytes::new(format!("{line}\n").into_bytes()),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker takes the line")
            .to_typed()
            .expect("decodes");
        self.sequence += 1;
    }

    /// What the session has written so far, with its control sequences and line breaks taken out,
    /// so text the console wrapped or redrew reads as one run.
    fn text(&self) -> String {
        let mut plain = String::new();
        let mut characters = self.seen.chars().peekable();
        while let Some(character) = characters.next() {
            match character {
                '\u{1b}' => {
                    // A control sequence: ESC, then `[` and parameters up to a final letter, or `]`
                    // up to BEL or ST, or one character.
                    match characters.next() {
                        Some('[') => {
                            for next in characters.by_ref() {
                                if next.is_ascii_alphabetic() || next == '~' {
                                    break;
                                }
                            }
                        }
                        Some(']') => {
                            while let Some(next) = characters.next() {
                                if next == '\u{7}' {
                                    break;
                                }
                                if next == '\u{1b}' && characters.peek() == Some(&'\\') {
                                    characters.next();
                                    break;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                '\r' | '\n' => {}
                other if other.is_control() => {}
                other => plain.push(other),
            }
        }
        plain
    }

    /// Waits until the session has written `pattern`, as [`Self::text`] reads it, and returns it all.
    async fn shown(&mut self, pattern: &str, what: &str) -> String {
        let started = tokio::time::Instant::now();
        let deadline = started + LIVENESS_DEADLINE;
        while !self.text().contains(pattern) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.client.recv()).await {
                Ok(Ok(kr_protocol::envelope::ControlFrame::Notification(notification)))
                    if notification.event_type.as_str() == "session.output" =>
                {
                    if let Ok(event) = notification
                        .payload
                        .to_typed::<kr_protocol::recovery::OutputEvent>()
                    {
                        self.seen
                            .push_str(&String::from_utf8_lossy(event.bytes.as_slice()));
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => panic!(
                    "{what}: waited {:?} for {pattern:?} and the connection ended ({error}): {}",
                    started.elapsed(),
                    self.text()
                ),
                Err(_) => panic!(
                    "{what}: waited {:?} for {pattern:?}; the session wrote {} bytes: {:?}",
                    started.elapsed(),
                    self.seen.len(),
                    self.seen
                ),
            }
        }
        self.text()
    }
}

/// A daemon this test hosts for its own tree, on loopback as [`Host`]'s is, starting each worker
/// through the environment's scheduled task: the task's starter creates the worker, so a session's
/// worker is a process of its own outside this test's job.
struct WorkerHost {
    tree: teardown::Tree,
    _task: kr_controller::supervision::windows::testing::TestTask,
    controller: Option<std::sync::Arc<kr_controller::service::Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
}

impl WorkerHost {
    async fn start() -> Self {
        use kr_controller::service::{Controller, ControllerSetup};
        use kr_controller::supervision::windows::testing::{TestTask, built_binary};

        let tree = teardown::Tree::create();
        let environment = tree.environment();
        let mut document = ConfigurationDocument::empty();
        document.revision = 1;
        document.network.enabled = Nullable::some(true);
        document.network.bind_address = Nullable::some("127.0.0.1:0".to_owned());
        let path = kr_worker::config::document_path(&environment);
        std::fs::create_dir_all(path.parent().expect("the document has a directory"))
            .expect("the state directory");
        kr_ipc::paths::write_owner_only_file(
            &path,
            kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
        )
        .expect("the configuration document");
        let starter = built_binary("kr-controller").unwrap_or_else(|missing| panic!("{missing}"));
        let task = TestTask::register(&environment, &starter)
            .unwrap_or_else(|failure| panic!("the environment's task: {failure}"));
        let worker = tree.root().join("kr-worker.exe");
        kr_ipc::testing::place_and_start_once(
            &built_binary("kr-worker").unwrap_or_else(|missing| panic!("{missing}")),
            &worker,
            &["--version"],
        );
        let environment_id = environment.environment_id();
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = kr_crypto::store::open_store_in(&secrets).expect("a secret store");
                Ok(kr_ipc::verify::ControllerIdentity::open(
                    store.store.as_ref(),
                    environment_id,
                    false,
                )
                .expect("an identity"))
            }),
            secret_store: kr_crypto::store::StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: tree.supervisor(Box::new(task.supervisor(&environment))),
            worker_program: worker,
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let rendezvous = kr_ipc::endpoint::Listener::bind(
            &environment.rendezvous_endpoint().expect("an endpoint"),
        )
        .expect("binds the rendezvous");
        let clients = kr_ipc::endpoint::Listener::bind(
            &environment.controller_endpoint().expect("an endpoint"),
        )
        .expect("binds the client endpoint");
        let serving = vec![
            tokio::spawn(std::sync::Arc::clone(&controller).serve_rendezvous(rendezvous)),
            tokio::spawn(std::sync::Arc::clone(&controller).serve_clients(clients)),
        ];
        Self {
            tree,
            _task: task,
            controller: Some(controller),
            serving,
        }
    }

    /// Creates a session whose root shell is the POSIX shell Git for Windows installs, as the host
    /// tests' sessions have, through this host's daemon, and returns it with its size.
    async fn session(
        &self,
    ) -> (
        kr_protocol::ids::SessionId,
        kr_protocol::session::Dimensions,
    ) {
        let runtime_root = self.tree.paths().runtime_root().to_path_buf();
        let state_root = self.tree.paths().state_root().to_path_buf();
        let cwd = self.tree.root().display().to_string();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(kr())
                .args([
                    "--json",
                    "new",
                    "--invisible",
                    "--headless",
                    "--cwd",
                    &cwd,
                    "--shell",
                    &kr_worker::testing::posix_shell(),
                ])
                .env("KR_RUNTIME_DIR", runtime_root)
                .env("KR_STATE_DIR", state_root)
                .stdin(std::process::Stdio::null())
                .output()
                .expect("kr new runs")
        })
        .await
        .expect("kr new is waited for");
        let created: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("kr new's document");
        assert!(output.status.success(), "kr new: {created}");
        let size = |axis: &str| {
            created["dimensions"][axis]
                .as_u64()
                .unwrap_or_else(|| panic!("the session's {axis}: {created}"))
        };
        (
            created["session_id"]
                .as_str()
                .expect("a session identifier")
                .parse()
                .expect("parses"),
            kr_protocol::session::Dimensions::new(size("columns"), size("rows")),
        )
    }
}

impl Drop for WorkerHost {
    fn drop(&mut self) {
        for task in &self.serving {
            task.abort();
        }
        drop(self.controller.take());
    }
}

/// KR-REQ-10.53: a console inside a real worker's session is not where the first owner is
/// confirmed, even with `KR_SESSION` and `KR_ATTACHMENT` removed from it. `kr` asks every live
/// session's worker whether it is one of its own, and the worker, which put the session's shell in
/// its job before the shell ran, answers that it is. The worker is a process of its own, which the
/// environment's scheduled task started outside this test's job; `kr` runs from the session's root
/// shell on the worker's pseudo-console. With the variables left in place the refusal is theirs,
/// which shows they were there to remove.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_owner_is_not_confirmed_in_a_real_workers_session_without_its_variables() {
    let host = WorkerHost::start().await;
    let (session_id, dimensions) = host.session().await;
    let environment = host.tree.environment();
    let mut terminal = WorkerTerminal::attach(&environment, session_id, dimensions).await;
    let kr_path = kr();
    let roots = format!(
        "export KR_RUNTIME_DIR='{}' KR_STATE_DIR='{}'",
        host.tree.paths().runtime_root().display(),
        host.tree.paths().state_root().display()
    );
    // Each marker is put together by the shell, so the line as typed, which the terminal echoes,
    // does not hold it: only the shell's answer does, once `kr` has ended.
    terminal
        .type_line(&format!(
            "{roots}; unset KR_SESSION KR_ATTACHMENT; '{}' pair invite --owner --direct; \
             printf 'KR-%s-%s\\n' exit \"$?\"",
            kr_path.display()
        ))
        .await;
    let seen = terminal
        .shown(
            "KR-exit-",
            "kr runs in the session with its variables removed",
        )
        .await;
    assert!(
        seen.contains(&format!("this process is inside session {session_id}")),
        "the session's worker recognised kr as its own: {seen}"
    );
    assert!(!seen.contains("Type pair"), "nothing was asked: {seen}");
    assert!(!seen.contains("KR-exit-0"), "and kr refused: {seen}");

    terminal
        .type_line(&format!(
            "KR_SESSION='{session_id}' '{}' pair invite --owner --direct; \
             printf 'KR-%s-%s\\n' control \"$?\"",
            kr_path.display()
        ))
        .await;
    let seen = terminal
        .shown("KR-control-", "the control, with the variable in place")
        .await;
    assert!(
        seen.contains("KR_SESSION is set"),
        "with the variable in place the refusal is its: {seen}"
    );
    drop(terminal);
    let closed = tokio::task::spawn_blocking({
        let runtime_root = host.tree.paths().runtime_root().to_path_buf();
        let state_root = host.tree.paths().state_root().to_path_buf();
        move || {
            std::process::Command::new(kr())
                .args(["--json", "close", &session_id.to_string()])
                .env("KR_RUNTIME_DIR", runtime_root)
                .env("KR_STATE_DIR", state_root)
                .output()
                .expect("kr close runs")
        }
    })
    .await
    .expect("kr close is waited for");
    assert!(
        closed.status.success(),
        "{}",
        String::from_utf8_lossy(&closed.stdout)
    );
}
