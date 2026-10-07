//! `kr host clock --establish` against a real control daemon, and a host's owner confirming at a
//! real terminal that its clock is right.
//!
//! The daemon is the `kr-controller` executable the workspace builds beside this test, copied to
//! the internal disk and left off the network, which is how a host is configured by default. It
//! starts over the record an earlier build's attention store kept of a wall clock it had found
//! going backwards, so it distrusts its clock from its first moment, and the only way out is its
//! owner's word. `kr` runs on a real pseudo-terminal where the confirmation needs one, and on plain
//! pipes where what is tested is that it refuses. What the tests read is the host's own records:
//! the clock's, and the acceptance of the owner's confirmation.

#![cfg(unix)]

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use portable_pty::{CommandBuilder, PtySize, native_pty_system};

mod support;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// What an earlier build's attention store wrote of a clock it had found going backwards.
const EARLIER_BUILD_AFTER_A_ROLLBACK: &[u8] =
    include_bytes!("../../kr-controller/tests/fixtures/earlier-attention-clock/rolled_back.cbor");

/// Returns an executable the workspace builds beside this test, when it has been built.
fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A host tree with a running daemon off the network, and the `kr` that talks to it.
struct Host {
    daemon: Option<std::process::Child>,
    temp: kr_ipc::testing::TempHost,
}

impl Drop for Host {
    fn drop(&mut self) {
        if let Some(mut daemon) = self.daemon.take() {
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }
}

impl Host {
    /// Starts a daemon over the earlier build's record of a clock found going backwards.
    async fn start() -> Self {
        let controller = beside_this_test("kr-controller").unwrap_or_else(|| {
            panic!(
                "the kr-controller executable is not built beside this test, so this check cannot \
                 run; a workspace test run builds it, and so does `cargo build -p kr-controller`"
            )
        });
        let temp = kr_ipc::testing::TempHost::create();
        std::fs::create_dir_all(temp.environment().state_dir()).expect("the state directory");
        std::fs::write(
            temp.environment().state_dir().join("attention-time.cbor"),
            EARLIER_BUILD_AFTER_A_ROLLBACK,
        )
        .expect("the earlier build's record");
        let bin = temp.root().join("bin");
        std::fs::create_dir_all(&bin).expect("a directory for the executable");
        let destination = bin.join(controller.file_name().expect("the executable has a name"));
        kr_ipc::testing::place_program(&controller, &destination);
        let log = std::fs::File::create(temp.root().join("daemon.log")).expect("the daemon's log");
        let child = std::process::Command::new(&destination)
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
                "the daemon did not answer; its log says: {}",
                host.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        host
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.temp.root().join("daemon.log")).unwrap_or_default()
    }

    /// The environment `kr` runs with: this host's directories, and nothing of this test's own.
    fn environment(&self) -> Vec<(String, String)> {
        vec![
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            (
                "KR_RUNTIME_DIR".to_owned(),
                self.temp.paths().runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR".to_owned(),
                self.temp.paths().state_root().display().to_string(),
            ),
        ]
    }

    /// Runs `kr` on plain pipes.
    fn kr(&self, arguments: &[&str]) -> std::process::Output {
        std::process::Command::new(kr())
            .args(arguments)
            .env_clear()
            .envs(self.environment())
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .output()
            .expect("runs kr")
    }

    /// Runs `kr` on a pseudo-terminal of its own, which is its controlling terminal, with the
    /// variables in `extra` added to the environment.
    fn on_terminal(&self, arguments: &[&str], extra: &[(&str, &str)]) -> OnTerminal {
        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 80,
                cols: 240,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
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
        command.cwd("/");
        let child = pty.slave.spawn_command(command).expect("starts kr");
        drop(pty.slave);
        let output = TerminalOutput::collect(pty.master.try_clone_reader().expect("a reader"));
        let writer = pty.master.take_writer().expect("a writer");
        OnTerminal {
            child,
            output,
            writer,
            _master: pty.master,
        }
    }

    /// What the host's own record says of its clock: whether it distrusts it, and whether its owner
    /// has confirmed it.
    fn clock_record(&self) -> (bool, bool) {
        let registry = rusqlite::Connection::open_with_flags(
            self.temp.environment().registry_database(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("opens the registry");
        registry
            .busy_timeout(Duration::from_secs(10))
            .expect("waits for the daemon's own use");
        registry
            .query_row(
                "SELECT untrusted_at_ms IS NOT NULL, confirmed_at_ms IS NOT NULL
                   FROM network_clock WHERE id = 0",
                [],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
            )
            .expect("the clock record is readable")
    }

    /// The channel of each owner confirmation this host has spent, and what spent it.
    fn spent_confirmations(&self) -> Vec<(String, String)> {
        let registry = rusqlite::Connection::open_with_flags(
            self.temp.environment().registry_database(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("opens the registry");
        let mut statement = registry
            .prepare(
                "SELECT channel, consumed_by FROM owner_confirmations
                  WHERE consumed_at_ms IS NOT NULL",
            )
            .expect("prepares");
        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("queries")
            .collect::<Result<_, _>>()
            .expect("reads")
    }
}

/// `kr` running on a pseudo-terminal.
struct OnTerminal {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    output: TerminalOutput,
    writer: Box<dyn Write + Send>,
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl OnTerminal {
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
        // Whatever the command wrote before it ended is read before the reader is judged.
        std::thread::sleep(Duration::from_millis(200));
        (status.success(), self.output.text())
    }
}

/// Everything a pseudo-terminal's command has written, collected as it arrives.
#[derive(Clone)]
struct TerminalOutput {
    seen: Arc<Mutex<Vec<u8>>>,
}

impl TerminalOutput {
    fn collect(mut reader: Box<dyn Read + Send>) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                if let Ok(mut seen) = collected.lock() {
                    seen.extend_from_slice(&buffer[..read]);
                }
            }
        });
        Self { seen }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().expect("the output")).into_owned()
    }

    fn expect(&self, marker: &str, what: &str) {
        let started = Instant::now();
        while !self.text().contains(marker) {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "{what}: waited {:?} for {marker:?}; the terminal shows: {}",
                started.elapsed(),
                self.text()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// KR-REQ-09.19, KR-REQ-10.53: a host that distrusts its clock and has no owner has the clock
/// established by the person at its own terminal. `kr` tells the person the time the host reads,
/// asks for the word that confirms it, and the host's record says afterwards that it distrusts
/// nothing and that its owner confirmed it, on the terminal channel, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_owner_at_the_terminal_trusts_the_hosts_clock_again() {
    let host = Host::start().await;
    assert_eq!(
        host.clock_record(),
        (true, false),
        "the host starts distrusting its clock\n{}",
        host.log()
    );

    let mut terminal = host.on_terminal(&["host", "clock", "--establish"], &[]);
    terminal
        .output
        .expect("This host's clock reads", "kr shows the time");
    terminal.output.expect(
        "Type clock to trust this host's clock",
        "kr asks the person",
    );
    terminal.writer.write_all(b"clock\r").expect("typed");
    terminal.writer.flush().expect("flushed");
    let (succeeded, printed) = terminal.finish();
    assert!(
        succeeded,
        "kr host clock --establish: {printed}\n{}",
        host.log()
    );
    assert!(printed.contains("trusts its clock again"), "{printed}");

    assert_eq!(host.clock_record(), (false, true), "{}", host.log());
    assert_eq!(
        host.spent_confirmations(),
        vec![(
            "local_bootstrap_terminal".to_owned(),
            "establish this host's clock".to_owned()
        )]
    );
}

/// KR-REQ-10.53: the clock is not established where there is no terminal. With standard input and
/// output on pipes, `kr` refuses before asking anything, and the host still distrusts its clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_clock_is_not_established_without_a_terminal() {
    let host = Host::start().await;
    let output = host.kr(&["host", "clock", "--establish"]);
    assert_eq!(
        output.status.code(),
        Some(6),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(host.clock_record(), (true, false), "{}", host.log());
    assert!(host.spent_confirmations().is_empty());
}

/// KR-REQ-10.53: a terminal inside a KalaReach session is not where the clock is confirmed. With
/// `KR_SESSION` or `KR_ATTACHMENT` set, `kr` refuses on a real terminal before it asks anything,
/// and the host still distrusts its clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_clock_is_not_established_inside_a_session() {
    let host = Host::start().await;
    for variable in ["KR_SESSION", "KR_ATTACHMENT"] {
        let terminal = host.on_terminal(
            &["host", "clock", "--establish"],
            &[(variable, "00000000-0000-4000-8000-000000000001")],
        );
        let (succeeded, printed) = terminal.finish();
        assert!(!succeeded, "{variable}: {printed}");
        assert!(
            printed.contains(&format!("{variable} is set")),
            "{variable}: {printed}"
        );
        assert!(
            !printed.contains("Type clock"),
            "{variable}: nothing was asked: {printed}"
        );
        assert_eq!(host.clock_record(), (true, false), "{}", host.log());
        assert!(host.spent_confirmations().is_empty());
    }
}
