//! `kr new` starting this environment's control daemon: itself, under the standalone start, or
//! through the user's own service manager, under the service start.
//!
//! What these establish, with the real `kr`, `kr-controller` and `kr-worker` on a real environment
//! tree. With the standalone start selected and no daemon running, `kr new` starts one, detached
//! from itself: in a session and a process group of its own, with no controlling terminal and none
//! of the command's own streams, working in the environment's own directory. Then it goes on as it
//! would against a daemon that was already there. Three commands starting one at once leave one
//! daemon, at one generation, holding every session they created. A daemon that does not come up
//! within the bound ends the command with a failure of its own name and leaves no second daemon,
//! whether it cannot take the environment or is slow to start; a slow one is left to come up and is
//! then used. The start is selected by a command that needs no daemon, on a host where none has
//! ever run, and `kr doctor` reports it with the document it came from.
//!
//! With the start selected, neither the command that selects it nor the `kr new` that starts the
//! daemon runs a service-manager, lingering or privilege tool, and the daemon it starts runs, while
//! it starts, nothing but read-only queries of the service manager (and, when it is started inside
//! a service this host started, the one transient scope it moves itself into); once it serves, with
//! a manager to ask, it launches its workers as transient services. Nothing is written in the home
//! they are given.
//!
//! `kr status` on a session the started daemon holds reports each terminal attachment's
//! presentation and the reason for it.
//!
//! The installation is laid out the way a package lays it out: `kr`, its restoration guard, the
//! daemon and the worker side by side on the internal disk, where `kr` finds the daemon beside
//! itself. The daemon there is a short script, which is what `kr` starts. It hands over to a copy of
//! this test binary, which supervises the real daemon: it starts it with its keys in the
//! environment's own `secrets` directory, which is what every harness in this repository gives a
//! daemon so that nothing reaches the credential store of the person running the tests, and with
//! every other argument and the whole environment `kr` gave it. The supervisor records the daemon's
//! process number in the test's own tree and holds the daemon as a child it has not collected until
//! the test's lifeline closes, however the test ended; it then ends the daemon and collects it.
//! Only a process's own parent signals it, and only before collecting it, so no number is ever
//! signalled after it could have passed to something else, and the test process signals nothing.
//! Every runtime and state directory is inside the test's own temporary tree.
//!
//! The service start. `kr host startup --set service` writes the definition of a per-user service
//! in the home it is given, records it and has the service manager take it; three `kr new`
//! commands at once then converge on the one daemon the manager starts, whose parent is the
//! manager; `kr doctor` reports that the definition matches; `--clear` removes the definition and
//! its record and the daemon keeps serving; and a definition kr did not write, one changed since,
//! or one that has gone is named and never replaced. The installation for these has the real
//! daemon behind a script that hands over to it with `exec`, so the process the manager starts is
//! the daemon itself. On macOS the manager is launchd, and the definition, in the test's own home,
//! is loaded under a label that names the test's own environment. On Linux it is a user manager of
//! the test's own, run in a delegated scope with the test's home as its home, so it reads the
//! definition from there; ending the scope ends everything it started. A host with no user manager
//! says why these did not run, unless `KR_REQUIRE_SERVICE_MANAGER` is set. On macOS the manager is
//! the account's own launchd, which these cases load jobs into and remove them from, and which any
//! daemon in a graphical login session submits its sessions' workers to; so every case that starts
//! a daemon runs there only in a run that sets `KR_ALLOW_ACCOUNT_LAUNCHD=1`, as a hosted runner's
//! does. A person's own Mac says why they did not run and calls no `launchctl`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::identity::{ProcessQuery, ProcessState};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::ids::{ActionId, AttachmentId, BuildId, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, SessionListParams, SessionListResult};
use serde_json::Value;

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
#[path = "support/user_manager.rs"]
mod user_manager;

#[cfg(target_os = "linux")]
use user_manager::{REQUIRE_SERVICE_MANAGER, UserManager};
use user_manager::{STREAMS_DEADLINE, TEARDOWN_BOUND, bounded, read_aside, spawning};

/// How long a command, or anything a test waits for, is given. It fails when the thing never
/// happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// How long a case waits, once `kr` has said that the daemon it started did not answer within its
/// own 30 seconds, for that daemon to answer.
///
/// The command's sentence is true and stays: a machine under load can take longer than the
/// command's bound to bring a daemon up. The figure is the suite's long bound, the one every other
/// wait of this suite for a daemon is given (a daemon started by hand is waited for as long), so
/// that a start 30 seconds late is stood and a daemon that has still not answered 120 seconds
/// after the command's report, 150 seconds after it was started, is not taken for a slow one.
const SLOW_START_BOUND: Duration = LIVENESS_DEADLINE;

/// The name the real daemon is placed under, beside the script `kr` runs as the daemon.
const DAEMON_UNDER_TEST: &str = "kr-controller-under-test";

/// The name this test binary's copy is placed under, beside the script that hands over to it.
const SUPERVISOR_PROGRAM: &str = "startup-supervisor";

/// The test the supervisor runs as.
const SUPERVISOR_TEST: &str = "supervise_one_daemon_when_asked";

/// Set, to the real daemon's path, when this binary runs as a daemon's supervisor.
const SUPERVISE: &str = "KR_STARTUP_TEST_SUPERVISE";

/// The daemon's arguments, one to a line, when this binary runs as a daemon's supervisor.
const SUPERVISED_ARGUMENTS: &str = "KR_STARTUP_TEST_ARGUMENTS";

/// The file in a test's own tree that each daemon script records its daemon's process number in.
const LAUNCHED: &str = "launched-daemons";

/// The file in a test's own tree that each supervisor records its own process number in when it
/// starts.
const STARTS: &str = "daemon-starts";

/// The FIFO in a test's own tree that the test holds open for as long as it runs.
const LIFELINE: &str = "daemon-lifeline";

/// When present in a test's own tree, how many supervisors have to have started before any of them
/// starts its daemon, so that the daemons meet at the environment's lock.
const BARRIER: &str = "daemon-barrier";

/// When present in a test's own tree, how many seconds each supervisor waits before it starts its
/// daemon, which is what a daemon slow to come up looks like from outside.
const DELAY: &str = "daemon-delay";

/// The tools a service, lingering or a privilege would be obtained through.
const RECORDING_TOOLS: [&str; 8] = [
    "systemctl",
    "systemd-run",
    "loginctl",
    "launchctl",
    "sudo",
    "doas",
    "pkexec",
    "runuser",
];

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// Returns an executable the workspace builds beside this test, when it has been built.
fn beside_this_test(name: &str) -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    // `<target>/<profile>/deps/<this test>`: the executables are in `<target>/<profile>`.
    let profile = executable.parent()?.parent()?;
    let candidate = profile.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    candidate.is_file().then_some(candidate)
}

/// The installation these tests run, on the internal disk: `kr` and its guard, and beside them the
/// daemon script, the daemon it runs and the worker.
///
/// A build of this crate alone that has not built the daemon and the worker yet fails here and
/// says why, rather than passing without having tested anything.
fn installation() -> &'static Path {
    static PLACED: OnceLock<PathBuf> = OnceLock::new();
    PLACED.get_or_init(|| {
        let (Some(controller), Some(worker)) = (
            beside_this_test("kr-controller"),
            beside_this_test("kr-worker"),
        ) else {
            panic!(
                "the kr-controller and kr-worker executables are not built beside this test, so \
                 this check cannot run; a workspace test run builds them, and so does \
                 `cargo build -p kr-controller -p kr-worker`"
            );
        };
        let directory = support::command_binaries();
        // Each is started once where nothing is timed, so the operating system's check of a newly
        // written executable is paid here rather than inside the start `kr new` waits for.
        kr_ipc::testing::place_and_start_once(
            &worker,
            &directory.join("kr-worker"),
            &["--version"],
        );
        let daemon = directory.join(DAEMON_UNDER_TEST);
        kr_ipc::testing::place_and_start_once(&controller, &daemon, &["--version"]);
        let supervisor = directory.join(SUPERVISOR_PROGRAM);
        kr_ipc::testing::place_and_start_once(
            &std::env::current_exe().expect("this test binary"),
            &supervisor,
            &["--list"],
        );
        // Written under a name nothing runs, and placed under the one `kr` runs by a copy, like
        // every program these tests start: no descriptor this process holds is ever open on it.
        let source = directory.join("kr-controller.sh");
        std::fs::write(&source, daemon_script(&daemon, &supervisor))
            .expect("writes the daemon script");
        kr_ipc::testing::place_program(&source, &directory.join("kr-controller"));
        directory.to_path_buf()
    })
}

/// The daemon `kr` finds beside itself in these tests: a script that hands over, with everything
/// `kr` gave it, to this test binary's copy running as the daemon's supervisor.
fn daemon_script(daemon: &Path, supervisor: &Path) -> String {
    format!(
        "#!/bin/sh\n\
         exec /usr/bin/env {SUPERVISE}='{}' {SUPERVISED_ARGUMENTS}=\"$(printf '%s\\n' \"$@\")\" \
         '{}' {SUPERVISOR_TEST} --exact --quiet\n",
        daemon.display(),
        supervisor.display()
    )
}

/// Not a check of its own: the entry point the daemon script runs this binary's copy through, with
/// [`SUPERVISE`] set, to supervise one daemon. The test harness running it without that variable
/// finds nothing to supervise.
#[test]
fn supervise_one_daemon_when_asked() {
    if let Some(daemon) = std::env::var_os(SUPERVISE) {
        supervise(Path::new(&daemon));
    }
}

/// Supervises one daemon for a test.
///
/// It opens the test's lifeline, records itself, and waits at the test's barrier or out the test's
/// delay when the test asks for either. A lifeline that has closed by then means the test has
/// ended, and nothing is started. Otherwise it starts the real daemon as its child, with its keys
/// in the environment's own `secrets` directory and everything else `kr` gave the script, records
/// the daemon's process number, and waits for the lifeline to close. Only then does it end the
/// daemon and collect it. Rust collects a child only when asked, so a daemon that ended by itself in
/// the meantime is still this process's uncollected child, its number is still its own, and
/// signalling it reaches nothing else.
fn supervise(daemon: &Path) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let arguments: Vec<String> = std::env::var(SUPERVISED_ARGUMENTS)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    let state = arguments
        .windows(2)
        .find(|pair| pair[0] == "--state-dir")
        .map(|pair| PathBuf::from(&pair[1]))
        .expect("kr names the state tree");
    let tree = state
        .parent()
        .expect("the state tree is inside the test's own tree")
        .to_path_buf();
    // One write of the whole line: supervisors append to the same record at once, and a line
    // written in two pieces could be split by another's.
    let record = |name: &str, pid: u32| {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(tree.join(name))
            .expect("opens a record");
        file.write_all(record_line(pid).as_bytes())
            .expect("records a process");
    };
    // Read without waiting, so a closed lifeline is seen as its end rather than waited on.
    let lifeline = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(tree.join(LIFELINE))
        .expect("opens the lifeline");
    record(STARTS, std::process::id());
    let waited = Instant::now();
    if let Ok(wanted) = std::fs::read_to_string(tree.join(BARRIER)) {
        let wanted: usize = wanted.trim().parse().expect("a number of starts");
        while std::fs::read_to_string(tree.join(STARTS))
            .unwrap_or_default()
            .lines()
            .count()
            < wanted
            && waited.elapsed() < Duration::from_secs(30)
            && !closed(&lifeline)
        {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if let Ok(seconds) = std::fs::read_to_string(tree.join(DELAY)) {
        let delay = Duration::from_secs(seconds.trim().parse().expect("a number of seconds"));
        while waited.elapsed() < delay && !closed(&lifeline) {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    if closed(&lifeline) {
        return;
    }
    // Held from the moment it starts, so it is ended and collected however this supervisor's run
    // ends, a failure to record it included.
    let daemon = Supervised(
        Command::new(daemon)
            .arg("--secret-store")
            .arg("file")
            .args(&arguments)
            .env_remove(SUPERVISE)
            .env_remove(SUPERVISED_ARGUMENTS)
            .spawn()
            .expect("starts the daemon"),
    );
    record(LAUNCHED, daemon.0.id());
    while !closed(&lifeline) {
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(daemon);
}

/// The line a record names one process with: its number, and its start identity, so the test can
/// tell it from whatever holds the number later.
///
/// A daemon can end before it is recorded, as one that cannot take the environment does, and on
/// macOS the kernel stops describing a process once it has ended, collected or not. Such a process
/// is named as one that has ended rather than failing the record.
fn record_line(pid: u32) -> String {
    let identity = kr_ipc::identity::started_process_identity(pid).expect("the start identity");
    format!(
        "{pid}\t{}\n",
        serde_json::to_string(&identity).expect("encodes the identity")
    )
}

/// A daemon a supervisor started.
struct Supervised(Child);

impl Drop for Supervised {
    fn drop(&mut self) {
        // This process's own child, not collected yet, so the number is still its.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Whether nothing holds the lifeline open any more, which is how a supervisor learns the test has
/// ended.
fn closed(lifeline: &std::fs::File) -> bool {
    use std::io::Read as _;

    let mut byte = [0; 1];
    match (&*lifeline).read(&mut byte) {
        Ok(0) => true,
        Ok(_) => false,
        Err(error) => error.kind() != std::io::ErrorKind::WouldBlock,
    }
}

/// A host tree of a test's own, where the standalone start is tried.
///
/// However a test ends, each daemon `kr` started in the tree is ended before the tree goes, by the
/// supervisor that started it; every supervisor has ended; and then, through the tree, every worker
/// a daemon recorded.
struct Standalone {
    tree: teardown::Tree,
    home: PathBuf,
    /// The lifeline every supervisor in this tree waits on, held open for as long as the test runs.
    lifeline: Option<std::fs::File>,
}

impl Drop for Standalone {
    fn drop(&mut self) {
        for why in self.end_what_was_started() {
            self.tree.hold(why);
        }
    }
}

impl Standalone {
    /// Ends every supervisor this test's commands started, and with it every daemon, waits for them,
    /// and returns whatever could not be established as ended, which keeps the tree.
    ///
    /// The lifeline closes first, which is what closes admission: a supervisor that has not started
    /// its daemon by then starts none, and one that has ends it. Every supervisor records itself,
    /// with its start identity, before it can start anything, and ends only after its daemon has
    /// been ended and collected, so waiting for the recorded supervisors waits for every daemon too;
    /// the daemons' own records are waited for as well. Each process is named by its start
    /// identity, so a number given to something else is not mistaken for it.
    ///
    /// Two things are not waited for. A supervisor that records itself after the records are read
    /// finds the lifeline closed, starts nothing and ends by itself. A record that cannot be read,
    /// such as one cut off part way by a full disk, is returned as what it is, and every record that
    /// can be read is still waited for. Nothing here panics: this runs while a failing test unwinds,
    /// and a second panic there would end the whole suite.
    fn end_what_was_started(&mut self) -> Vec<String> {
        drop(self.lifeline.take());
        let (mut identities, mut unresolved) = self.identities(STARTS);
        let (launched, unreadable) = self.identities(LAUNCHED);
        identities.extend(launched);
        unresolved.extend(unreadable);
        let begun = Instant::now();
        for identity in identities {
            loop {
                match kr_ipc::identity::process_state(&identity) {
                    ProcessState::Ended => break,
                    // A process that is ending can read as unknown for a moment (the kernel's
                    // state of one that has exited and is not yet collected), so it is read again
                    // until the bound, as a running one is.
                    ProcessState::Running | ProcessState::Unknown { .. }
                        if begun.elapsed() < STREAMS_DEADLINE =>
                    {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    ProcessState::Running => {
                        unresolved.push(format!(
                            "the process {} this test started did not end once its lifeline \
                             closed",
                            identity.pid.get()
                        ));
                        break;
                    }
                    ProcessState::Unknown { detail } => {
                        unresolved.push(format!(
                            "whether the process {} this test started has ended cannot be \
                             established: {detail}",
                            identity.pid.get()
                        ));
                        break;
                    }
                }
            }
        }
        unresolved
    }

    /// The start identities one record in this tree names, in the order they were recorded, and a
    /// sentence for each line that does not name one.
    fn identities(
        &self,
        name: &str,
    ) -> (
        Vec<kr_protocol::identity::ProcessStartIdentity>,
        Vec<String>,
    ) {
        let mut identities = Vec::new();
        let mut unreadable = Vec::new();
        for line in std::fs::read_to_string(self.tree.root().join(name))
            .unwrap_or_default()
            .lines()
        {
            match line
                .split_once('\t')
                .map(|(_, identity)| serde_json::from_str(identity))
            {
                Some(Ok(identity)) => identities.push(identity),
                Some(Err(_)) | None => unreadable.push(format!(
                    "the record {name} holds a line that names no process: {line:?}"
                )),
            }
        }
        (identities, unreadable)
    }

    /// A tree for daemons started without a service manager of the test's own, or none where this
    /// run did not ask for the account's own launchd. On macOS a daemon in a graphical login
    /// session submits the worker of each session it makes to that launchd as a job, so these
    /// cases run there only where a run sets `KR_ALLOW_ACCOUNT_LAUNCHD`.
    fn create() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            let asked = std::env::var_os(ALLOW_ACCOUNT_LAUNCHD);
            if let Err(why) = account_launchd(asked.as_deref()) {
                eprintln!("the daemon start is not tested here: {why}");
                return None;
            }
        }
        Some(Self::make())
    }

    /// A tree that no daemon is started in, or that the caller has made sure may have one.
    fn make() -> Self {
        let tree = teardown::Tree::create();
        let home = tree.root().join("home");
        std::fs::create_dir_all(&home).expect("a home of this test's own");
        let fifo = tree.root().join(LIFELINE);
        let made = spawning(|| Command::new("mkfifo").arg(&fifo).status()).expect("runs mkfifo");
        assert!(made.success(), "makes the lifeline");
        // Open for reading and writing, which does not wait for a reader. This is the only end
        // that writes, so a script reading the lifeline reaches its end exactly when this closes.
        let lifeline = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .expect("holds the lifeline");
        Self {
            tree,
            home,
            lifeline: Some(lifeline),
        }
    }

    /// Selects the standalone start as `kr host startup --set standalone` records it: the first
    /// revision of a document that chooses it and nothing else.
    fn select_standalone(&self) {
        kr_ipc::paths::write_owner_only_file(
            &self.document(),
            br#"{"version": 1, "revision": 1, "startup": {"controller": "standalone"}}"#,
        )
        .expect("writes the configuration document");
    }

    /// Starts this environment's daemon as a person starts one by hand, which is the only start
    /// over a configuration document `kr` cannot use: `kr` starts no daemon then. The daemon is
    /// left running, supervised like every other this tree starts, writing to a log in the tree,
    /// and the call returns once it answers.
    fn start_a_daemon_by_hand(&self) {
        let paths = self.tree.paths();
        let log = self.tree.root().join("daemon-by-hand.log");
        let environment = self.tree.environment();
        let started = spawning(|| {
            Command::new("/bin/sh")
                .arg("-c")
                .arg("log=$1; shift; \"$@\" </dev/null >\"$log\" 2>&1 &")
                .arg("sh")
                .arg(&log)
                .arg(installation().join("kr-controller"))
                .arg("--runtime-dir")
                .arg(paths.runtime_root())
                .arg("--state-dir")
                .arg(paths.state_root())
                .arg("--own-session")
                .current_dir(environment.state_dir())
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &self.home)
                .status()
        })
        .expect("sh starts");
        assert!(started.success(), "sh puts the daemon in the background");
        let begun = Instant::now();
        while !answers(&environment) {
            assert!(
                begun.elapsed() < LIVENESS_DEADLINE,
                "the daemon started by hand did not answer; it said {}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Leaves in this tree what a host holds once a paired device has registered a delivery
    /// credential issued by `gateway`, for a daemon that has not started: the device's destination
    /// in the delivery journal, and the credential in the secret store the daemon opens. Nothing
    /// is sent to the gateway.
    fn hold_a_credential_issued_by(&self, gateway: &str) {
        use kr_delivery::destination::{
            DeliveryRule, Destination, DestinationId, DestinationRecord, PreviewKeys,
            PushDestination,
        };
        use kr_protocol::ids::{InstallationId, PushSenderRecordId};
        use kr_protocol::push::PushDeliveryCredential;
        use kr_protocol::scalars::{SecretBytes32, TimestampMs, Uuid};

        let environment = self.tree.environment();
        let sender_record_id = PushSenderRecordId::new(Uuid::from_bytes([3; 16]));
        let installation_id = InstallationId::new(Uuid::from_bytes([2; 16]));
        let store = kr_crypto::store::open_store_in(&environment.secrets_dir())
            .expect("the daemon's secret store");
        kr_controller::push::secrets::DestinationSecrets::new(
            std::sync::Arc::from(store.store),
            self.tree.environment_id(),
        )
        .put_push_credential(&PushDeliveryCredential {
            expires_at_ms: TimestampMs::new(u64::MAX / 4),
            gateway_origin: kr_protocol::service::GatewayOrigin::new(gateway).expect("an origin"),
            installation_id,
            issued_at_ms: TimestampMs::new(1_700_000_000_000),
            revision: kr_protocol::ids::PushSenderRevision::new(1),
            secret: SecretBytes32::from_bytes([9; 32]),
            sender_record_id,
        })
        .expect("the credential is kept");
        let mut journal = kr_delivery::journal::DeliveryJournal::open(
            &environment
                .state_dir()
                .join(kr_controller::push::DELIVERY_JOURNAL),
        )
        .expect("the delivery journal");
        journal
            .configure_destination(&DestinationRecord {
                // Not a paired device's identifier, so the watch over paired devices leaves it be.
                id: DestinationId::new("phone").expect("an identifier"),
                destination: Destination::Push(Box::new(PushDestination {
                    installation_id,
                    sender_record_id,
                    preview_keys: PreviewKeys::only(
                        *kr_crypto::keys::NotificationPreviewKeyPair::generate()
                            .expect("a keypair")
                            .public(),
                        1,
                    ),
                    previews_enabled: false,
                    mailbox_key: None,
                })),
                rule: Some(DeliveryRule {
                    name: "anything that wants a person".to_owned(),
                    grant_id: None,
                }),
                enabled: true,
                configured_at_ms: TimestampMs::new(1_700_000_000_000),
            })
            .expect("the destination is configured");
    }

    /// The delivery journal of this environment, opened beside the daemon that has it open.
    fn delivery_journal(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(
            self.tree
                .environment()
                .state_dir()
                .join(kr_controller::push::DELIVERY_JOURNAL),
        )
        .expect("the delivery journal")
    }

    /// Where this environment's configuration document is.
    ///
    /// Its state directory was chosen with `KR_STATE_DIR`, so the document is inside it on every
    /// platform.
    fn document(&self) -> PathBuf {
        self.tree.environment().state_dir().join("config.json")
    }

    /// Writes one of the files the daemon scripts read in this tree.
    fn ask_the_scripts(&self, name: &str, value: &str) {
        std::fs::write(self.tree.root().join(name), value).expect("writes the request");
    }

    /// `kr` from the installation, against this tree and nothing else, with nothing of this test's
    /// own environment but the temporary directory.
    fn kr(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(installation().join("kr"));
        command
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.tree.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.tree.paths().state_root(),
            )
            .current_dir(installation())
            .stdin(Stdio::null());
        if let Some(temporary) = std::env::var_os("TMPDIR") {
            command.env("TMPDIR", temporary);
        }
        command
    }

    /// `kr new` for an invisible, headless session of `/bin/sh` working in this tree.
    fn new_session(&self) -> Command {
        let cwd = self.tree.root().display().to_string();
        self.kr(&[
            "--json",
            "new",
            "--shell-mode",
            "native_compat",
            "--invisible",
            "--headless",
            "--cwd",
            &cwd,
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
        ])
    }

    /// `kr new` as above, naming no shell mode: the host's default decides.
    fn new_session_with_no_shell_mode(&self) -> Command {
        let cwd = self.tree.root().display().to_string();
        self.kr(&[
            "--json",
            "new",
            "--invisible",
            "--headless",
            "--cwd",
            &cwd,
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
        ])
    }

    /// Runs `command`, a `kr new` of this tree, to its end, for a case whose claim is not the start
    /// of the daemon: the daemon is how the case gets a session.
    ///
    /// Where `kr` says that the daemon it started did not answer within its start bound, having
    /// waited the whole of it, and the daemon is still coming up, this waits for it to answer, up
    /// to [`SLOW_START_BOUND`], and runs the command again, which finds the daemon and does what it
    /// was run for. The output of the command that ran last is returned. Any other outcome is
    /// returned as it is: the cases that claim something about the start itself do not call this.
    ///
    /// A daemon that is not running, or that does not answer within the bound, fails the case with
    /// what `kr` said and the end of the daemon's log.
    fn finish_through_a_slow_start(&self, what: &str, command: impl Fn() -> Command) -> Output {
        let began = Instant::now();
        let output = start(command()).finish(what);
        if !reports_the_start_was_slow(&output, began.elapsed()) {
            return output;
        }
        self.wait_for_the_started_daemon(what, &output);
        start(command()).finish(what)
    }

    /// Waits until the daemon `kr` started answers, for at most [`SLOW_START_BOUND`], and fails the
    /// case, with what `kr` said, as soon as nothing this tree started is running any more: every
    /// supervisor has ended, or every daemon the supervisors started has.
    ///
    /// A supervisor records itself before it can do anything else, so one that has not recorded
    /// itself by the time the stream deadline has passed is not there. One that is waiting out a
    /// delay has recorded itself and has no daemon yet, which is a daemon still to come.
    fn wait_for_the_started_daemon(&self, what: &str, said: &Output) {
        let ended = |identity: &kr_protocol::identity::ProcessStartIdentity| {
            kr_ipc::identity::process_state(identity) == ProcessState::Ended
        };
        let begun = Instant::now();
        loop {
            if self.answers() {
                return;
            }
            let (supervisors, _) = self.identities(STARTS);
            let (daemons, _) = self.identities(LAUNCHED);
            let reason = if supervisors.is_empty() && begun.elapsed() >= STREAMS_DEADLINE {
                Some("no process this command started has recorded itself".to_owned())
            } else if !supervisors.is_empty() && supervisors.iter().all(ended) {
                Some("every process this command started has ended".to_owned())
            } else if !daemons.is_empty()
                && daemons.len() >= supervisors.len()
                && daemons.iter().all(ended)
            {
                Some("every daemon this command started has ended".to_owned())
            } else if begun.elapsed() >= SLOW_START_BOUND {
                Some(format!(
                    "the daemon did not answer within {SLOW_START_BOUND:?} after the command said it was slow"
                ))
            } else {
                None
            };
            if let Some(reason) = reason {
                let log = std::fs::read_to_string(
                    self.tree
                        .environment()
                        .state_dir()
                        .join(kr_cli::startup::LOG_FILE),
                )
                .unwrap_or_default();
                let lines: Vec<&str> = log.lines().collect();
                let tail = lines[lines.len().saturating_sub(20)..].join("\n");
                panic!(
                    "{what}: {reason}; it said {}; the end of the daemon's log:\n{tail}",
                    String::from_utf8_lossy(&said.stdout)
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The row of `kr doctor`'s effective configuration that names `key`.
    fn doctor_row(&self, key: &str) -> Value {
        let output = start(self.kr(&["--json", "doctor"])).finish("kr doctor");
        let report = document(&output, "kr doctor");
        report["configuration"]["values"]
            .as_array()
            .and_then(|values| values.iter().find(|value| value["key"] == key).cloned())
            .unwrap_or_else(|| panic!("kr doctor reports {key}: {report}"))
    }

    /// Closes a session this test created, through the daemon that holds it.
    fn close(&self, created: &Value) {
        let session = created["session_id"]
            .as_str()
            .expect("a session identifier");
        let output = start(self.kr(&["--json", "close", session])).finish("kr close");
        let closed = document(&output, "kr close");
        assert!(output.status.success(), "{closed}");
    }

    /// The daemons `kr` started in this tree, by process number, in the order they started.
    fn launched(&self) -> Vec<u32> {
        self.recorded(LAUNCHED)
    }

    /// The processes one record in this tree names, in the order they were recorded.
    fn recorded(&self, name: &str) -> Vec<u32> {
        std::fs::read_to_string(self.tree.root().join(name))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split('\t').next()?.trim().parse().ok())
            .collect()
    }

    /// The daemons `kr` started in this tree that are running now.
    ///
    /// A daemon that could not take the environment ends by itself and waits for its supervisor to
    /// collect it, which counts as ended. Its number stays its own until then, so each number here
    /// names the daemon it was recorded for.
    fn running(&self) -> Vec<u32> {
        self.launched()
            .into_iter()
            .filter(|pid| match kr_ipc::identity::query_process(*pid) {
                ProcessQuery::Present(identity) => match kr_ipc::identity::process_state(&identity)
                {
                    ProcessState::Running => true,
                    ProcessState::Ended => false,
                    ProcessState::Unknown { detail } => {
                        panic!("whether daemon {pid} is running cannot be established: {detail}")
                    }
                },
                ProcessQuery::Gone => false,
                ProcessQuery::CannotEstablish(error) => {
                    panic!("whether daemon {pid} is running cannot be established: {error}")
                }
            })
            .collect()
    }

    /// Waits until exactly one daemon `kr` started here is running, and returns it.
    ///
    /// A daemon that lost the environment's lock ends moments after it tried, so the answer is
    /// waited for rather than read once.
    fn one_daemon(&self) -> u32 {
        let started = Instant::now();
        loop {
            let running = self.running();
            if running.len() == 1 {
                return running[0];
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "one daemon was to be left of those started, {:?}, and these are running: \
                 {running:?}",
                self.launched()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Whether anything answers on this environment's endpoint now.
    fn answers(&self) -> bool {
        answers(&self.tree.environment())
    }

    /// Asks this environment's daemon one question.
    fn ask<T: kr_protocol::wire::WireMessage>(
        &self,
        method: Method,
        params: &impl serde::Serialize,
    ) -> T {
        ask(&self.tree.environment(), method, params)
    }

    /// Establishes that a daemon is detached from whatever started it: it leads a session and a
    /// process group of its own, has no controlling terminal, and works in the environment's own
    /// directory.
    fn assert_detached(&self, pid: u32) {
        let process = rustix::process::Pid::from_raw(i32::try_from(pid).expect("a process number"))
            .expect("a process number");
        assert_eq!(
            rustix::process::getsid(Some(process)).expect("its session"),
            process,
            "the daemon leads a session of its own"
        );
        assert_eq!(
            rustix::process::getpgid(Some(process)).expect("its process group"),
            process,
            "and a process group of its own"
        );
        assert_eq!(
            kr_ipc::identity::controlling_terminal(pid).expect("its controlling terminal"),
            None,
            "and has no controlling terminal"
        );
        let environment = self.tree.environment();
        assert_eq!(
            working_directory(pid),
            std::fs::canonicalize(environment.state_dir()).expect("the state directory"),
            "and works in the environment's own directory"
        );
    }
}

/// Whether anything answers on an environment's endpoint now.
fn answers(environment: &kr_ipc::paths::EnvironmentPaths) -> bool {
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        tokio::time::timeout(
            STREAMS_DEADLINE,
            LocalClient::connect(&endpoint, LocalClientKind::Cli, build()),
        )
        .await
        .is_ok_and(|reached| reached.is_ok())
    })
}

/// Asks an environment's daemon one question.
fn ask<T: kr_protocol::wire::WireMessage>(
    environment: &kr_ipc::paths::EnvironmentPaths,
    method: Method,
    params: &impl serde::Serialize,
) -> T {
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the daemon");
        client
            .request(method, params)
            .await
            .expect("the call reaches the daemon")
            .expect("the daemon answers")
            .to_typed()
            .expect("decodes")
    })
}

/// The working directory of a process of this user's.
fn working_directory(pid: u32) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/cwd")).expect("reads its working directory")
    }
    #[cfg(not(target_os = "linux"))]
    {
        let listed = spawning(|| {
            Command::new("/usr/sbin/lsof")
                .args(["-a", "-d", "cwd", "-Fn", "-p", &pid.to_string()])
                .output()
        })
        .expect("lists its working directory");
        String::from_utf8_lossy(&listed.stdout)
            .lines()
            .find_map(|line| line.strip_prefix('n'))
            .map(PathBuf::from)
            .expect("its working directory is listed")
    }
}

/// A `kr` that has been started, and the threads reading what it prints.
///
/// One that a failing test leaves behind is waited for rather than left running, so nothing it
/// starts outlives the tree it was started in.
struct Running {
    child: Option<Child>,
    stdout: Receiver<Vec<u8>>,
    stderr: Receiver<Vec<u8>>,
}

impl Drop for Running {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let started = Instant::now();
        while matches!(child.try_wait(), Ok(None)) && started.elapsed() < LIVENESS_DEADLINE {
            std::thread::sleep(Duration::from_millis(20));
        }
        // This test's own child, not collected yet, so the number is still its.
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Starts `kr`, reading both its output streams on threads of their own.
fn start(mut command: Command) -> Running {
    let mut child = spawning(|| {
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    })
    .expect("kr starts");
    let stdout = read_aside(child.stdout.take().expect("its standard output"))
        .expect("a thread to read its standard output");
    let stderr = read_aside(child.stderr.take().expect("its standard error"))
        .expect("a thread to read its standard error");
    Running {
        child: Some(child),
        stdout,
        stderr,
    }
}

impl Running {
    /// Waits for `kr` to end, within the deadline, and for both of its streams to reach their end.
    ///
    /// A stream that stays open after `kr` has ended is held by something `kr` started, which is
    /// what a daemon given the command's own output would do, and that fails the test.
    fn finish(mut self, what: &str) -> Output {
        let mut child = self
            .child
            .take()
            .expect("a kr that has not been waited for");
        let started = Instant::now();
        let status = loop {
            match child.try_wait().expect("waits for kr") {
                Some(status) => break status,
                None if started.elapsed() < LIVENESS_DEADLINE => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                None => {
                    // This test's own child, not collected yet, so the number is still its.
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("{what} did not end within {LIVENESS_DEADLINE:?}");
                }
            }
        };
        let stdout = self.stdout.recv_timeout(STREAMS_DEADLINE).unwrap_or_else(|_| {
            panic!(
                "{what} ended and its standard output is still open: something it started holds it"
            )
        });
        let stderr = self.stderr.recv_timeout(STREAMS_DEADLINE).unwrap_or_else(|_| {
            panic!(
                "{what} ended and its standard error is still open: something it started holds it"
            )
        });
        Output {
            status,
            stdout,
            stderr,
        }
    }
}

/// Runs a command to its end and reads the one document it printed.
fn document(output: &Output, what: &str) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{what} printed no document ({error}): {}; it said {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

/// Whether a command's outcome is the one `kr` ends with when the daemon it started did not answer
/// within its start bound: exit 1 and the document of an unfinished command, code
/// `ENVIRONMENT_UNAVAILABLE`, after the command had run for the whole of the product's own start
/// bound. A command that reports the same at once has not waited and is not a slow start. Its
/// words are not read; the caller establishes that the daemon is still coming up from the
/// processes this test's tree started.
fn reports_the_start_was_slow(output: &Output, took: Duration) -> bool {
    let Ok(said) = serde_json::from_slice::<Value>(&output.stdout) else {
        return false;
    };
    took >= kr_cli::startup::START_BOUND
        && output.status.code() == Some(1)
        && said["ok"] == false
        && said["exit_code"] == 1
        && said["code"] == "ENVIRONMENT_UNAVAILABLE"
}

/// Every path under `root`, and the content of every file, in order.
fn every_path_under(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    let mut found = Vec::new();
    let mut waiting = vec![root.to_path_buf()];
    while let Some(directory) = waiting.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                waiting.push(path.clone());
                found.push((path, None));
            } else {
                let content = std::fs::read(&path).ok();
                found.push((path, content));
            }
        }
    }
    found.sort();
    found
}

/// One call a recording tool saw.
#[derive(Debug)]
struct Recorded {
    /// The process that made the call.
    caller: u32,
    /// The process that ran the tool. It is the caller's child, unless the caller replaced itself
    /// with the tool, which keeps its number.
    pid: u32,
    /// That process's name, as the listing of processes gives it.
    name: String,
    /// The tool.
    tool: String,
    /// Every argument, in order.
    arguments: Vec<String>,
}

/// Places the recording tools in `tools`: each records the call it was given and the process that
/// made it in `calls`. A tool fails the way a host with no service manager and no privilege tool
/// would, unless `passes` names the tools that go on to run the real one.
fn recording_tools(tools: &Path, calls: &Path, passes: &[&str]) {
    std::fs::create_dir_all(tools).expect("a directory for the recording tools");
    for tool in RECORDING_TOOLS {
        let ending = if passes.contains(&tool) {
            format!("exec /usr/bin/{tool} \"$@\"\n")
        } else {
            "exit 1\n".to_owned()
        };
        // Written aside as text and placed by a process of its own, so that no child another test
        // starts meanwhile holds a tool open for writing when the daemon starts it.
        let text = tools.join(format!("{tool}.text"));
        std::fs::write(
            &text,
            format!(
                "#!/bin/sh\n\
                 {{\n\
                 \x20 printf '%s\\t%s\\t%s\\t%s' \"$PPID\" \"$$\" \"$(ps -o comm= -p \"$PPID\" 2>/dev/null)\" '{tool}'\n\
                 \x20 for argument in \"$@\"; do printf '\\t%s' \"$argument\"; done\n\
                 \x20 printf '\\n'\n\
                 }} >> '{}'\n\
                 {ending}",
                calls.display()
            ),
        )
        .expect("writes a recording tool");
        kr_ipc::testing::place_program(&text, &tools.join(tool));
    }
}

/// The calls recorded in `calls`, in the order they were made.
fn recorded_calls(calls: &Path) -> Vec<Recorded> {
    std::fs::read_to_string(calls)
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let mut fields = line.split('\t');
            let mut number = |what: &str| -> u32 {
                fields
                    .next()
                    .and_then(|field| field.trim().parse().ok())
                    .unwrap_or_else(|| panic!("a recorded call names its {what}: {line}"))
            };
            let caller = number("caller");
            let pid = number("process");
            let name = fields.next().unwrap_or_default().trim().to_owned();
            let tool = fields.next().unwrap_or_default().to_owned();
            Recorded {
                caller,
                pid,
                name,
                tool,
                arguments: fields.map(str::to_owned).collect(),
            }
        })
        .collect()
}

/// What a daemon the standalone start ran may ask the service manager beyond the read-only
/// queries.
#[derive(Clone, Copy, Default)]
struct Allowance<'a> {
    /// The daemon's own program, when it was started inside a service this host started: it may
    /// move itself into one transient scope by running that program there.
    scope_for: Option<&'a Path>,
    /// Whether the scope's command line carries the flag that stops expansion of `$` in the
    /// arguments, which a systemd from 254 has and the daemon passes to it.
    no_expansion: bool,
    /// The worker program a daemon of this installation launches as a transient service, as one
    /// does where a service manager answers.
    workers: Option<&'a Path>,
}

/// Whether the `systemd-run` this host has takes the flag that stops expansion in a scope's
/// command line, which it does from systemd 254.
#[cfg(target_os = "linux")]
fn systemd_run_stops_expansion() -> bool {
    let output = Command::new("systemd-run")
        .arg("--version")
        .output()
        .expect("systemd-run reports its version");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .nth(1)
        .and_then(|version| version.parse::<u32>().ok())
        .expect("a version number")
        >= 254
}

/// Whether one recorded call is one the standalone start may make.
///
/// Only the daemon `kr` started may make one, whether it ran the tool as a child or replaced itself
/// with the tool, and only in one of the exact forms a daemon asks the platform's service manager
/// with: the read-only queries `systemctl --user show`, `systemd-run --version`, `loginctl
/// show-user` or `show-session`, and `launchctl print`; and, as `allowance` says, the daemon itself
/// running `systemd-run --user --scope --quiet --collect [--expand-environment=no]
/// --unit=kr-daemon-<id> -- <its program> <its arguments>`, which installs nothing, persists
/// nothing and takes no privilege, and the transient service of a worker of the one program a
/// session is started with. A call `kr` itself makes, a call from anything else, and every other
/// form of every tool is refused, with what it was.
fn allowed(call: &Recorded, daemons: &[u32], allowance: Allowance<'_>) -> Result<(), String> {
    if !daemons.contains(&call.caller) && !daemons.contains(&call.pid) {
        return Err(format!(
            "{} (process {}), which is not the daemon kr started, ran {} {:?}",
            call.name, call.caller, call.tool, call.arguments
        ));
    }
    let arguments: Vec<&str> = call.arguments.iter().map(String::as_str).collect();
    let query = matches!(
        (call.tool.as_str(), arguments.as_slice()),
        ("systemctl", ["--user", "show", ..])
            | ("systemd-run", ["--version"])
            | ("loginctl", ["show-user" | "show-session", ..])
            | ("launchctl", ["print", ..])
    );
    let own_scope = call.tool == "systemd-run"
        && daemons.contains(&call.pid)
        && allowance.scope_for.is_some_and(|program| {
            let ["--user", "--scope", "--quiet", "--collect", rest @ ..] = arguments.as_slice()
            else {
                return false;
            };
            let rest = match (rest, allowance.no_expansion) {
                (["--expand-environment=no", more @ ..], true) => more,
                (other, false) => other,
                _ => return false,
            };
            matches!(
                rest,
                [unit, "--", started, started_with @ ..]
                    if unit.starts_with("--unit=kr-daemon-")
                        && Path::new(started) == program
                        && started_with.contains(&"--own-session")
            )
        });
    // The forms the supervisor writes for a worker, in its order: the unit, the options it sets,
    // then the worker's program first and its reservation, the unit's own.
    let worker = call.tool == "systemd-run"
        && allowance.workers.is_some_and(|program| {
            let ["--user", unit, "--collect", rest @ ..] = arguments.as_slice() else {
                return false;
            };
            let Some(reservation) = unit.strip_prefix("--unit=kr-worker-") else {
                return false;
            };
            let mut rest = rest.iter();
            while let Some(argument) = rest.next() {
                let option = match *argument {
                    "-p" => rest.next().is_some_and(|value| {
                        value == &"Type=exec"
                            || value == &"Restart=no"
                            || value == &"Delegate=yes"
                            || value.starts_with("WorkingDirectory=")
                    }),
                    "--quiet" => true,
                    other => {
                        other.starts_with("--setenv=")
                            || other.starts_with("--property=UnsetEnvironment=")
                    }
                };
                if !option {
                    return Path::new(argument) == program
                        && rest.next() == Some(&"--reservation")
                        && rest.next() == Some(&reservation);
                }
            }
            false
        });
    if query || own_scope || worker {
        Ok(())
    } else {
        Err(format!(
            "the daemon ran {} {:?}, which is not among the calls it may make",
            call.tool, call.arguments
        ))
    }
}

/// KR-REQ-07.12: three first invocations at once converge on one control daemon.
///
/// Three `kr new` commands start together with the standalone start selected and no daemon
/// running, and each starts a daemon: the daemons are held until all three have been started, so
/// all three meet at the environment's singleton lock. Each command creates its session; one daemon
/// is left of the three, the environment's generation advanced once, and every session is in that
/// daemon's registry. The daemon leads a session and a process group of its own, has no controlling
/// terminal and works in the environment's own directory, and every command's own output ended with
/// the command.
#[test]
fn three_first_invocations_at_once_converge_on_one_daemon() {
    let Some(host) = Standalone::create() else {
        return;
    };
    host.select_standalone();
    host.ask_the_scripts(BARRIER, "3");

    let started: Vec<Running> = (0..3).map(|_| start(host.new_session())).collect();
    let mut sessions = Vec::new();
    let mut documents = Vec::new();
    for (index, running) in started.into_iter().enumerate() {
        let what = format!("kr new {index}");
        let output = running.finish(&what);
        let created = document(&output, &what);
        assert!(
            output.status.success(),
            "{what} created its session: {created}; it said {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(created["state"], "live", "{what}: {created}");
        let session_id: SessionId = created["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("parses");
        sessions.push(session_id);
        documents.push(created);
    }

    assert_eq!(
        host.launched().len(),
        3,
        "each command started a daemon, and the three met at the lock"
    );
    let daemon = host.one_daemon();
    let info: HostInfoResult = host.ask(Method::HostInfo, &());
    assert_eq!(info.environment_id, host.tree.environment_id());
    assert_eq!(
        info.generation.get(),
        1,
        "the environment's generation advanced once, for the one daemon that took it"
    );
    let listed: SessionListResult = host.ask(
        Method::SessionList,
        &SessionListParams {
            environment_id: Nullable::some(host.tree.environment_id()),
            include_closed: false,
        },
    );
    for session_id in &sessions {
        assert!(
            listed
                .sessions
                .iter()
                .any(|summary| summary.session_id == *session_id),
            "session {session_id} is in the one daemon's registry: {:?}",
            listed.sessions
        );
    }
    host.assert_detached(daemon);
    for created in &documents {
        host.close(created);
    }
}

/// KR-REQ-07.12: a daemon that cannot take the environment is named when the command gives up, and
/// no second daemon is left.
///
/// The environment is held by a daemon that has taken its singleton lock and never answers, which
/// is what a daemon stuck in its own start looks like from outside; this test holds the lock
/// itself. `kr new` starts a daemon, which cannot take the environment and ends, waits out its
/// bound for an answer, and fails with `ENVIRONMENT_UNAVAILABLE`, saying how long it waited and the
/// last line of the daemon's log. The daemon it started has ended, and nothing answers for the
/// environment.
#[test]
fn a_daemon_that_does_not_come_up_in_time_is_named_and_no_second_one_is_left() {
    let Some(host) = Standalone::create() else {
        return;
    };
    host.select_standalone();
    let environment = host.tree.environment();
    let held = kr_controller::singleton::SingletonLock::acquire(
        &environment.singleton_lock(),
        host.tree.environment_id(),
    )
    .expect("this test holds the environment");

    let output = start(host.new_session()).finish("kr new");
    let failure = document(&output, "kr new");
    assert_ne!(output.status.code(), Some(0), "nothing was created");
    assert_eq!(failure["ok"], false, "{failure}");
    assert_eq!(failure["code"], "ENVIRONMENT_UNAVAILABLE", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("did not answer within 30 seconds"),
        "the failure says how long it waited: {message}"
    );
    assert!(
        message.contains("another control daemon already owns environment"),
        "and what the daemon it started said: {message}"
    );

    let launched = host.launched();
    assert_eq!(launched.len(), 1, "the command started one daemon");
    let started = Instant::now();
    while !host.running().is_empty() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the daemon that could not take the environment ended: {launched:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let daemon =
        rustix::process::Pid::from_raw(i32::try_from(launched[0]).expect("a process number"))
            .expect("a process number");
    assert!(
        rustix::process::test_kill_process(daemon).is_ok(),
        "the daemon that ended by itself still holds its number, because its supervisor has not \
         collected it"
    );
    assert!(!host.answers(), "and nothing answers for the environment");
    drop(held);
}

/// KR-REQ-07.12: a daemon slow to come up is named when the command gives up, is left to come up,
/// and is then the environment's one daemon.
///
/// The daemon this `kr new` starts does not begin until after the command's bound, which is what a
/// daemon waiting on a slow machine or on a person looks like from outside. The command fails with
/// `ENVIRONMENT_UNAVAILABLE`, saying the process it started is still running. It is not ended: it
/// comes up, and the next `kr new` finds it answering, starts nothing, and creates its session
/// there.
#[test]
fn a_daemon_slow_to_come_up_is_named_left_to_come_up_and_then_used() {
    let Some(host) = Standalone::create() else {
        return;
    };
    host.select_standalone();
    host.ask_the_scripts(DELAY, "40");

    let output = start(host.new_session()).finish("the first kr new");
    let failure = document(&output, "the first kr new");
    assert_eq!(failure["code"], "ENVIRONMENT_UNAVAILABLE", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("did not answer within 30 seconds") && message.contains("still running"),
        "the failure says how long it waited and that what it started is still running: {message}"
    );

    let started = Instant::now();
    while !host.answers() {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the daemon that was slow to start came up"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    let output = start(host.new_session()).finish("the second kr new");
    let created = document(&output, "the second kr new");
    assert!(output.status.success(), "{created}");
    assert_eq!(
        host.launched().len(),
        1,
        "the second command found the daemon answering and started none"
    );
    let daemon = host.one_daemon();
    host.assert_detached(daemon);
    host.close(&created);
}

/// KR-REQ-07.13, KR-REQ-07.12: with the standalone start selected, nothing is installed and no
/// privilege is sought.
///
/// Each tool a service, lingering or a privilege would be obtained through is replaced on the
/// `PATH` both commands are given by one that records the call and the process that made it, and
/// fails the way it would on a host with no service manager. The daemon `kr new` starts inherits
/// that `PATH`, so it finds the same tools. Neither `kr host startup` nor `kr new` runs any of
/// them. The daemon runs nothing but the read-only queries the allow-list names, and on Linux it
/// does run one: `systemctl --user show`, asking whether there is a user manager. Nothing is
/// written, removed or changed in the home the commands were given, and nothing appears where a
/// per-user service definition would go.
#[test]
fn selecting_and_using_the_standalone_start_installs_nothing_and_seeks_no_privilege() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let calls = host.tree.root().join("tool-calls");
    let tools = host.tree.root().join("tools");
    recording_tools(&tools, &calls, &[]);
    let path = format!("{}:/usr/bin:/bin", tools.display());
    // The recording tools record: one run through the same `PATH` is found, and then forgotten.
    let checked = spawning(|| {
        Command::new("/bin/sh")
            .args(["-c", "loginctl enable-linger"])
            .env("PATH", &path)
            .status()
    })
    .expect("runs a recording tool");
    assert!(
        !checked.success(),
        "a recording tool fails as a missing one would"
    );
    let recorded = recorded_calls(&calls);
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    assert_eq!(
        (recorded[0].tool.as_str(), recorded[0].arguments.clone()),
        ("loginctl", vec!["enable-linger".to_owned()])
    );
    std::fs::remove_file(&calls).expect("forgets the check");
    let before = every_path_under(&host.home);

    let with_tools = |mut command: Command| {
        command
            .env("PATH", &path)
            .env("XDG_CONFIG_HOME", host.home.join(".config"));
        command
    };
    let selected = start(with_tools(host.kr(&[
        "--json",
        "host",
        "startup",
        "--set",
        "standalone",
    ])))
    .finish("kr host startup");
    let chosen = document(&selected, "kr host startup");
    assert!(selected.status.success(), "{chosen}");
    assert_eq!(chosen["startup"]["controller"], "standalone", "{chosen}");
    let output = start(with_tools(host.new_session())).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(created["state"], "live", "{created}");
    let daemon = host.one_daemon();
    host.assert_detached(daemon);
    // What the daemon asks when it is asked about itself, which is what `kr doctor` asks.
    let _: HostInfoResult = host.ask(Method::HostInfo, &());
    host.close(&created);
    assert!(
        !host
            .tree
            .paths()
            .state_root()
            .join("terminal-profiles.json")
            .exists(),
        "the standalone start records no terminal profile"
    );

    let daemons = host.launched();
    let recorded = recorded_calls(&calls);
    for call in &recorded {
        if let Err(refused) = allowed(call, &daemons, Allowance::default()) {
            panic!("{refused}; everything recorded: {recorded:?}");
        }
    }
    if cfg!(target_os = "linux") {
        assert!(
            recorded.iter().any(|call| {
                daemons.contains(&call.caller)
                    && call.tool == "systemctl"
                    && call.arguments == ["--user", "show", "--property=Version", "--value"]
            }),
            "the daemon's query of the user manager went through the recording tool, in exactly \
             the form it asks, so the tools it runs by name are the ones on the PATH it \
             inherited: {recorded:?}"
        );
    }
    assert!(
        every_path_under(&host.home) == before,
        "nothing was written, removed or changed in the home the commands were given"
    );
    for definitions in [".config/systemd", "Library/LaunchAgents"] {
        assert!(
            !host.home.join(definitions).exists(),
            "no service definition was written: {definitions}"
        );
    }
}

/// KR-REQ-07.13: the allow-list refuses every call that would install, enable, start or obtain
/// anything, from the daemon as from anybody else, and admits the read-only queries and, for a
/// daemon started inside a service this host started, the one transient scope it moves itself
/// into, and nothing more.
#[test]
fn the_allow_list_refuses_every_mutating_or_privileged_call() {
    let daemon = 4242;
    let call = |caller: u32, pid: u32, tool: &str, arguments: &[&str]| Recorded {
        caller,
        pid,
        name: "kr-controller".to_owned(),
        tool: tool.to_owned(),
        arguments: arguments
            .iter()
            .map(|argument| (*argument).to_owned())
            .collect(),
    };
    let program = Path::new("/opt/kr/kr-controller");
    let scope = |unit: &'static str, started: &'static str, last: &'static str| {
        [
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            unit,
            "--",
            started,
            "--secret-store",
            last,
        ]
    };
    let worker_program = Path::new("/opt/kr/kr-worker");
    let inside = Allowance {
        scope_for: Some(program),
        no_expansion: false,
        workers: None,
    };
    let expanding_off = Allowance {
        no_expansion: true,
        ..inside
    };
    let everything = Allowance {
        scope_for: Some(program),
        no_expansion: false,
        workers: Some(worker_program),
    };
    for allowance in [Allowance::default(), inside, everything] {
        for (tool, arguments) in [
            ("sudo", &["true"][..]),
            ("doas", &["true"][..]),
            ("pkexec", &["true"][..]),
            ("runuser", &["-u", "somebody", "true"][..]),
            ("systemctl", &["--user", "enable", "kalareach.service"][..]),
            (
                "systemctl",
                &["--user", "link", "/tmp/kalareach.service"][..],
            ),
            ("systemctl", &["--user", "start", "kalareach.service"][..]),
            ("systemctl", &["show", "--property=Version"][..]),
            (
                "systemd-run",
                &["--user", "--unit", "kalareach", "true"][..],
            ),
            ("systemd-run", &["--version", "--user"][..]),
            // A transient service, which the manager keeps, is not the scope the daemon asks for.
            (
                "systemd-run",
                &[
                    "--user",
                    "--collect",
                    "--unit=kr-daemon-0123",
                    "--",
                    "/opt/kr/kr-controller",
                ][..],
            ),
            ("loginctl", &["enable-linger"][..]),
            ("loginctl", &["enable-linger", "somebody"][..]),
            (
                "launchctl",
                &["bootstrap", "gui/501", "/tmp/kalareach.plist"][..],
            ),
            ("launchctl", &["load", "/tmp/kalareach.plist"][..]),
            ("launchctl", &["enable", "gui/501/kalareach"][..]),
        ] {
            assert!(
                allowed(&call(daemon, daemon, tool, arguments), &[daemon], allowance).is_err(),
                "{tool} {arguments:?} is refused"
            );
        }
    }
    for (tool, arguments) in [
        (
            "systemctl",
            &["--user", "show", "--property=Version", "--value"][..],
        ),
        ("loginctl", &["show-user", "501", "--property=Linger"][..]),
        ("loginctl", &["show-session", "3", "--property=Leader"][..]),
        ("launchctl", &["print", "gui/501"][..]),
    ] {
        assert_eq!(
            allowed(
                &call(daemon, daemon, tool, arguments),
                &[daemon],
                Allowance::default()
            ),
            Ok(()),
            "{tool} {arguments:?} is a read-only query"
        );
        assert!(
            allowed(
                &call(daemon + 1, daemon + 1, tool, arguments),
                &[daemon],
                Allowance::default()
            )
            .is_err(),
            "and made by anything but the daemon, it is refused: {tool} {arguments:?}"
        );
    }

    // The one scope: only by a daemon started inside a service, only by the daemon itself, only
    // for its own program with its own arguments, and only under a daemon's name.
    let mut good = scope(
        "--unit=kr-daemon-0123",
        "/opt/kr/kr-controller",
        "--own-session",
    )
    .map(str::to_owned)
    .to_vec();
    let own_scope = |caller: u32, pid: u32, arguments: &[String], allowance: Allowance<'_>| {
        let arguments: Vec<&str> = arguments.iter().map(String::as_str).collect();
        allowed(
            &call(caller, pid, "systemd-run", &arguments),
            &[daemon],
            allowance,
        )
    };
    assert!(
        own_scope(1, daemon, &good, Allowance::default()).is_err(),
        "a daemon started anywhere else asks for no scope"
    );
    assert_eq!(
        own_scope(1, daemon, &good, inside),
        Ok(()),
        "a daemon started inside a service moves itself into a scope of its own, having replaced \
         itself with the tool, so that the tool keeps its number"
    );
    assert!(
        own_scope(daemon, daemon + 1, &good, inside).is_err(),
        "and kr, or a child of the daemon, asks for none: the tool is not the daemon"
    );
    for (what, changed) in [
        (
            "another name",
            scope("--unit=other", "/opt/kr/kr-controller", "--own-session"),
        ),
        (
            "another program",
            scope("--unit=kr-daemon-0123", "/bin/sh", "--own-session"),
        ),
        (
            "no start of a daemon of its own",
            scope("--unit=kr-daemon-0123", "/opt/kr/kr-controller", "--other"),
        ),
    ] {
        assert!(
            own_scope(1, daemon, &changed.map(str::to_owned), inside).is_err(),
            "a scope under {what} is refused"
        );
    }
    good.truncate(6);
    assert!(
        own_scope(1, daemon, &good, inside).is_err(),
        "and a scope that runs nothing"
    );

    // The version it reads, and the flag that stops expansion, are the daemon's own; the flag is
    // only ever the one form.
    assert_eq!(
        allowed(
            &call(daemon + 1, daemon, "systemd-run", &["--version"]),
            &[daemon],
            Allowance::default()
        ),
        Ok(()),
        "the daemon reads the version of the tool it runs"
    );
    let mut expanding = scope(
        "--unit=kr-daemon-0123",
        "/opt/kr/kr-controller",
        "--own-session",
    )
    .map(str::to_owned)
    .to_vec();
    assert!(
        own_scope(1, daemon, &expanding, expanding_off).is_err(),
        "where the tool stops expansion the scope carries the flag that says so"
    );
    expanding.insert(4, "--expand-environment=no".to_owned());
    assert_eq!(
        own_scope(1, daemon, &expanding, expanding_off),
        Ok(()),
        "and with it the scope is the one call"
    );
    assert!(
        own_scope(1, daemon, &expanding, inside).is_err(),
        "where the tool has no such flag a scope that carries it is refused: it would not start"
    );
    expanding[4] = "--expand-environment=yes".to_owned();
    assert!(
        own_scope(1, daemon, &expanding, expanding_off).is_err(),
        "and no other form of the flag"
    );

    // A worker's transient service is the supervisor's, only where the daemon has a manager, and
    // only for the worker program a daemon of the installation launches.
    let worker = |options: &[&'static str], program: &'static str, reservation: &'static str| {
        let mut arguments = vec!["--user", "--unit=kr-worker-0123", "--collect"];
        arguments.extend(options);
        arguments.extend([program, "--reservation", reservation]);
        arguments
    };
    let written = [
        "-p",
        "Type=exec",
        "-p",
        "Restart=no",
        "-p",
        "Delegate=yes",
        "--quiet",
    ];
    let good = worker(&written, "/opt/kr/kr-worker", "0123");
    assert!(allowed(&call(1, daemon, "systemd-run", &good), &[daemon], inside).is_err());
    assert_eq!(
        allowed(
            &call(daemon, daemon + 1, "systemd-run", &good),
            &[daemon],
            everything
        ),
        Ok(())
    );
    for (what, arguments) in [
        ("another program", worker(&written, "/bin/sh", "0123")),
        (
            "another reservation",
            worker(&written, "/opt/kr/kr-worker", "4567"),
        ),
        (
            "a unit of the system manager",
            worker(&["--system"], "/opt/kr/kr-worker", "0123"),
        ),
        ("a scope", worker(&["--scope"], "/opt/kr/kr-worker", "0123")),
        (
            "a command before the worker's",
            vec![
                "--user",
                "--unit=kr-worker-0123",
                "--collect",
                "/bin/sh",
                "-c",
                "exit 0",
                "/opt/kr/kr-worker",
                "--reservation",
                "0123",
            ],
        ),
        (
            "a property that runs a command first",
            worker(
                &["-p", "ExecStartPre=/bin/true"],
                "/opt/kr/kr-worker",
                "0123",
            ),
        ),
    ] {
        assert!(
            allowed(
                &call(daemon, daemon, "systemd-run", &arguments),
                &[daemon],
                everything
            )
            .is_err(),
            "a service under a worker's name that is {what} is refused: {arguments:?}"
        );
    }
}

/// KR-REQ-07.12, KR-REQ-26.13: the start is selected with no daemon running, and `kr doctor`
/// reports it with the document it came from.
///
/// `kr host startup` shows that nothing is selected, refuses a way of starting this build does not
/// know with nothing written, and selects the standalone start as one validated edit at the next
/// revision, with no daemon asked and none started. `kr new` then starts one, and `kr doctor`
/// reports the selection with the document as its source and as applying at the next start.
/// Clearing it is an edit too, and the report goes back to the product default.
#[test]
fn the_start_is_selected_with_no_daemon_and_the_doctor_names_its_source() {
    let Some(host) = Standalone::create() else {
        return;
    };

    let shown = start(host.kr(&["--json", "host", "startup"])).finish("kr host startup");
    let unchosen = document(&shown, "kr host startup");
    assert!(shown.status.success(), "{unchosen}");
    assert_eq!(unchosen["startup"]["controller"], Value::Null, "{unchosen}");
    assert_eq!(unchosen["startup"]["source"], "default", "{unchosen}");

    let refused =
        start(host.kr(&["host", "startup", "--set", "elsewhere"])).finish("kr host startup");
    assert_eq!(refused.status.code(), Some(2), "a usage failure");
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        said.contains("standalone") && said.contains("service"),
        "the refusal names what can be chosen: {said}"
    );
    assert!(!host.document().exists(), "and nothing was written");

    let selected = start(host.kr(&["--json", "host", "startup", "--set", "standalone"]))
        .finish("kr host startup");
    let chosen = document(&selected, "kr host startup");
    assert!(selected.status.success(), "{chosen}");
    assert_eq!(chosen["startup"]["controller"], "standalone", "{chosen}");
    assert_eq!(
        chosen["startup"]["source"], "host_configuration",
        "{chosen}"
    );
    assert_eq!(chosen["startup"]["revision"], "1", "{chosen}");
    let written: Value =
        serde_json::from_slice(&std::fs::read(host.document()).expect("the document was written"))
            .expect("the document is JSON");
    assert_eq!(written["revision"], 1, "{written}");
    assert_eq!(written["startup"]["controller"], "standalone", "{written}");
    assert!(
        host.launched().is_empty(),
        "selecting the start starts nothing"
    );

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let reported = |what: &str| {
        // A diagnostic that did not pass makes the command's status a failure, and the document it
        // printed is still the whole report.
        let output = start(host.kr(&["--json", "doctor"])).finish(what);
        let report = document(&output, what);
        report["configuration"]["values"]
            .as_array()
            .and_then(|values| {
                values
                    .iter()
                    .find(|value| value["key"] == "startup.controller")
                    .cloned()
            })
            .unwrap_or_else(|| panic!("{what} reports the startup: {report}"))
    };
    let row = reported("kr doctor");
    assert_eq!(row["value"], "standalone", "{row}");
    assert_eq!(row["source"], "host_configuration", "{row}");
    assert_eq!(
        row["origin"],
        host.document().display().to_string(),
        "{row}"
    );
    assert_eq!(row["effect"], "next_start", "{row}");

    let cleared =
        start(host.kr(&["--json", "host", "startup", "--clear"])).finish("kr host startup");
    let none = document(&cleared, "kr host startup");
    assert!(cleared.status.success(), "{none}");
    assert_eq!(none["startup"]["controller"], Value::Null, "{none}");
    let row = reported("kr doctor after the clear");
    assert_eq!(row["value"], "none", "{row}");
    assert_eq!(row["source"], "default", "{row}");
    host.close(&created);
}

/// KR-REQ-07.12: the start is chosen and used on a host where no daemon has ever run.
///
/// Such a host has the environment's identity, which the first command of any kind allocates, and
/// none of the environment's directories. `kr host startup --set standalone` writes the choice
/// there with no daemon running, making the directories it needs as a daemon would, and `kr new`
/// then starts the daemon and creates its session.
#[test]
fn the_start_is_chosen_and_used_where_no_daemon_has_ever_run() {
    let Some(host) = Standalone::create() else {
        return;
    };
    std::fs::remove_dir_all(host.tree.paths().runtime_root()).expect("no runtime tree");
    std::fs::remove_dir_all(host.tree.paths().state_root().join("environments"))
        .expect("no environment directories");

    let selected = start(host.kr(&["--json", "host", "startup", "--set", "standalone"]))
        .finish("kr host startup");
    let chosen = document(&selected, "kr host startup");
    assert!(selected.status.success(), "{chosen}");
    assert_eq!(chosen["startup"]["controller"], "standalone", "{chosen}");
    assert!(host.document().is_file(), "the choice was written");

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(created["state"], "live", "{created}");
    host.assert_detached(host.one_daemon());
    host.close(&created);
}

/// Attaches a terminal to a session over its worker's own endpoint, and returns the connection the
/// attachment lives on with it. The attachment lasts as long as the connection does.
async fn terminal_attachment(
    host: &Standalone,
    session_id: SessionId,
    dimensions: Dimensions,
    profile: Option<&str>,
) -> (LocalClient, AttachmentId) {
    let descriptor = kr_ipc::descriptor::read_all(&host.tree.environment())
        .expect("reads the runtime directory")
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .find(|descriptor| descriptor.session_id == session_id)
        .expect("the session's descriptor is published");
    let endpoint = kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("reaches the worker");
    client
        .verify_worker(&descriptor)
        .await
        .expect("the worker answers its descriptor's challenge");
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let attached: SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id: descriptor.environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(dimensions),
                terminal_profile_id: Nullable(profile.map(str::to_owned)),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds")
        .to_typed()
        .expect("decodes");
    (client, attached.attachment.attachment_id)
}

/// KR-REQ-26.13: a session made with no shell mode takes the mode this host defaults to, in the
/// order section 26 gives an ordinary preference: the request, then the per-user host
/// configuration, then the product default, which is the managed shell.
///
/// `/bin/sh` is no qualified shell, so a session this host makes as a managed one is refused by
/// name, and one it makes as a stock shell is created: the outcome says which mode was chosen.
/// `kr doctor` reports the mode in force with the rung it came from.
#[test]
fn a_session_made_with_no_shell_mode_takes_the_hosts_default_in_the_order_section_26_gives() {
    let Some(host) = Standalone::create() else {
        return;
    };
    host.select_standalone();

    // Nothing chosen: the product default, a managed shell, which `/bin/sh` cannot be.
    let refused =
        host.finish_through_a_slow_start("kr new", || host.new_session_with_no_shell_mode());
    let failed = document(&refused, "kr new");
    assert!(!refused.status.success(), "{failed}");
    assert_eq!(failed["code"], "SHELL_INTEGRATION_UNSUPPORTED", "{failed}");
    let row = host.doctor_row("shell.mode");
    assert_eq!(row["value"], "managed", "{row}");
    assert_eq!(row["source"], "default", "{row}");
    assert_eq!(row["effect"], "new_sessions_only", "{row}");

    // The owner chose a stock shell in the host's configuration, a section of level 6.
    kr_ipc::paths::write_owner_only_file(
        &host.document(),
        br#"{"version": 3, "level": 6, "revision": 2, "startup": {"controller": "standalone"}, "shell": {"mode": "native_compat"}}"#,
    )
    .expect("writes the configuration document");
    let row = host.doctor_row("shell.mode");
    assert_eq!(row["value"], "native_compat", "{row}");
    assert_eq!(row["source"], "host_configuration", "{row}");
    assert_eq!(
        row["origin"],
        host.document().display().to_string(),
        "{row}"
    );
    let output =
        host.finish_through_a_slow_start("kr new", || host.new_session_with_no_shell_mode());
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    assert_eq!(created["shell_mode"], "native_compat", "{created}");

    // A request outranks the host's choice, in either direction.
    let cwd = host.tree.root().display().to_string();
    let output = start(host.kr(&[
        "--json",
        "new",
        "--invisible",
        "--headless",
        "--cwd",
        &cwd,
        "--shell",
        "/bin/sh",
        "--startup",
        "interactive",
        "--shell-mode",
        "managed",
    ]))
    .finish("kr new --shell-mode managed");
    let failed = document(&output, "kr new --shell-mode managed");
    assert_eq!(failed["code"], "SHELL_INTEGRATION_UNSUPPORTED", "{failed}");
    host.close(&created);
}

/// KR-REQ-26.13: `kr host shell-mode` shows, chooses and clears the mode a session is created in
/// when none is named, each choice one validated revision of the host's own configuration
/// document, and what is in force is the host's answer with the rung it came from.
#[test]
fn kr_host_shell_mode_chooses_and_clears_the_default_for_new_sessions() {
    let Some(host) = Standalone::create() else {
        return;
    };
    host.select_standalone();
    // The command asks the running daemon what is in force, so one is started the way a person's
    // first `kr new` starts it.
    let output = host.finish_through_a_slow_start("kr new", || host.new_session());
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let shell_mode = |arguments: &[&str]| {
        let mut command = vec!["--json", "host", "shell-mode"];
        command.extend_from_slice(arguments);
        let output = start(host.kr(&command)).finish("kr host shell-mode");
        let shown = document(&output, "kr host shell-mode");
        assert!(output.status.success(), "{shown}");
        shown["shell_mode"].clone()
    };

    let shown = shell_mode(&[]);
    assert_eq!(shown["mode"], "managed", "{shown}");
    assert_eq!(shown["source"], "default", "{shown}");

    let chosen = shell_mode(&["--set", "native_compat"]);
    assert_eq!(chosen["mode"], "native_compat", "{chosen}");
    assert_eq!(chosen["source"], "host_configuration", "{chosen}");
    let written: Value =
        serde_json::from_slice(&std::fs::read(host.document()).expect("the document was written"))
            .expect("the document is JSON");
    assert_eq!(written["shell"]["mode"], "native_compat", "{written}");
    assert_eq!(written["level"], 6, "{written}");
    assert_eq!(
        written["startup"]["controller"], "standalone",
        "an edit of the section leaves the others as they were: {written}"
    );
    let row = host.doctor_row("shell.mode");
    assert_eq!(row["value"], "native_compat", "{row}");
    assert_eq!(row["source"], "host_configuration", "{row}");

    let cleared = shell_mode(&["--clear"]);
    assert_eq!(cleared["mode"], "managed", "{cleared}");
    assert_eq!(cleared["source"], "default", "{cleared}");
    let written: Value =
        serde_json::from_slice(&std::fs::read(host.document()).expect("the document is there"))
            .expect("the document is JSON");
    assert!(written.get("shell").is_none(), "{written}");

    // A mode that is neither is refused and writes nothing.
    let output = start(host.kr(&["--json", "host", "shell-mode", "--set", "automatic"]))
        .finish("kr host shell-mode");
    let refused = document(&output, "kr host shell-mode");
    assert!(!output.status.success(), "{refused}");
    assert_eq!(refused["code"], "INVALID_ARGUMENT", "{refused}");
    host.close(&created);
}

/// KR-REQ-26.42: an ordinary user needs no account of any kind. On a host with no account that
/// selects no managed service, the first run starts the daemon and a session in it, the host's
/// configuration is chosen and read back, and `kr doctor` names each managed integration the host
/// does without as optional, never as a fault. `kr account sign-in`, which needs a managed service,
/// is refused by what is missing, and the session is live before and after.
#[test]
fn kr_req_26_42_an_ordinary_user_with_no_account_and_no_managed_service_runs_a_host_and_its_sessions()
 {
    let Some(host) = Standalone::create() else {
        return;
    };
    assert!(
        !host.document().exists(),
        "a first run: the host has no configuration"
    );

    // Setup chooses how the daemon starts, and names no service.
    let selected = start(host.kr(&["--json", "host", "startup", "--set", "standalone"]))
        .finish("kr host startup");
    let chosen = document(&selected, "kr host startup");
    assert!(selected.status.success(), "{chosen}");

    // The first session starts the daemon.
    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    assert_eq!(created["state"], "live", "{created}");
    let session = created["session_id"]
        .as_str()
        .expect("a session identifier");
    let live = |what: &str| {
        let output = start(host.kr(&["--json", "list"])).finish(what);
        let listed = document(&output, what);
        assert!(output.status.success(), "{listed}");
        assert!(listed.to_string().contains(session), "{what}: {listed}");
    };
    live("kr list");

    // The host's configuration is chosen as one validated edit and read back with its source.
    let output = start(host.kr(&["--json", "host", "shell-mode", "--set", "native_compat"]))
        .finish("kr host shell-mode");
    let mode = document(&output, "kr host shell-mode");
    assert!(output.status.success(), "{mode}");
    let row = host.doctor_row("shell.mode");
    assert_eq!(row["value"], "native_compat", "{row}");
    assert_eq!(row["source"], "host_configuration", "{row}");

    // The managed integrations are named, each as one the host does without.
    let output = start(host.kr(&["--json", "doctor"])).finish("kr doctor");
    let report = document(&output, "kr doctor");
    support::the_managed_integrations_are_named_as_ones_the_host_does_without(&report);

    // No account is signed in, and the host says it names no managed service.
    let output = start(host.kr(&["--json", "account", "show"])).finish("kr account show");
    let account = document(&output, "kr account show");
    assert!(output.status.success(), "{account}");
    assert_eq!(account["state"], "signed_out", "{account}");
    assert_eq!(account["unavailable"], "no_managed_service", "{account}");

    // An optional add that needs a service is refused by what is missing.
    let output = start(host.kr(&["--json", "account", "sign-in"])).finish("kr account sign-in");
    let refused = document(&output, "kr account sign-in");
    assert!(!output.status.success(), "{refused}");
    assert_eq!(refused["code"], "HOST_NOT_CONFIGURED", "{refused}");
    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|said| said.contains("names no managed service")),
        "the refusal says what is missing: {refused}"
    );

    // None of it touched the session.
    live("kr list after the refusal");
    host.close(&created);
}

/// KR-REQ-16.04: `kr host push-gateways` shows, lists and clears the gateways besides the official
/// one that a paired device's credential may name, each choice one validated revision of the host's
/// own configuration document that the daemon is asked about straight away, so that it is in force
/// when the command returns. An origin that is not one, and the official gateway, are refused by
/// the name of the setting, and write nothing.
#[test]
fn kr_host_push_gateways_lists_and_clears_the_gateways_a_credential_may_name() {
    let Some(host) = Standalone::create() else {
        return;
    };
    host.select_standalone();
    let output = host.finish_through_a_slow_start("kr new", || host.new_session());
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let push_gateways = |arguments: &[&str]| {
        let mut command = vec!["--json", "host", "push-gateways"];
        command.extend_from_slice(arguments);
        let output = start(host.kr(&command)).finish("kr host push-gateways");
        let shown = document(&output, "kr host push-gateways");
        (output.status.success(), shown)
    };

    let (ok, shown) = push_gateways(&[]);
    assert!(ok, "{shown}");
    assert_eq!(shown["push_gateways"], serde_json::json!([]), "{shown}");

    let (ok, shown) = push_gateways(&[
        "--set",
        "https://push.builder.example",
        "http://127.0.0.1:8788",
    ]);
    assert!(ok, "{shown}");
    assert_eq!(
        shown["push_gateways"],
        serde_json::json!(["https://push.builder.example", "http://127.0.0.1:8788"]),
        "{shown}"
    );
    let written: Value =
        serde_json::from_slice(&std::fs::read(host.document()).expect("the document was written"))
            .expect("the document is JSON");
    assert_eq!(written["level"], 7, "{written}");
    assert_eq!(
        written["push"]["gateways"],
        serde_json::json!(["https://push.builder.example", "http://127.0.0.1:8788"]),
        "{written}"
    );
    assert_eq!(
        written["startup"]["controller"], "standalone",
        "an edit of the section leaves the others as they were: {written}"
    );
    let row = host.doctor_row("push.gateways");
    assert!(
        row["value"]
            .as_str()
            .is_some_and(|value| value.contains("https://push.builder.example")),
        "{row}"
    );
    assert_eq!(row["effect"], "immediately", "{row}");

    // An origin that is not one, and the official gateway, are refused by name and write nothing.
    let before = std::fs::read(host.document()).expect("the document");
    for refused in ["push.builder.example", "https://reach.kala.to"] {
        let (ok, shown) = push_gateways(&["--set", refused]);
        assert!(!ok, "{refused}: {shown}");
        assert_eq!(shown["code"], "INVALID_ARGUMENT", "{shown}");
        assert!(
            shown["message"]
                .as_str()
                .is_some_and(|message| message.contains("push.gateways")),
            "{shown}"
        );
        assert_eq!(
            std::fs::read(host.document()).expect("the document"),
            before,
            "{refused}: nothing was written"
        );
    }

    let (ok, shown) = push_gateways(&["--clear"]);
    assert!(ok, "{shown}");
    assert_eq!(shown["push_gateways"], serde_json::json!([]), "{shown}");
    let written: Value =
        serde_json::from_slice(&std::fs::read(host.document()).expect("the document is there"))
            .expect("the document is JSON");
    assert!(written.get("push").is_none(), "{written}");
    host.close(&created);
}

/// A gateway of the test's own on a loopback port, which answers every request with a 503 and so
/// never revokes or refuses anything. Returns its origin.
fn a_gateway_that_is_unavailable() -> String {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let origin = format!("http://{}", listener.local_addr().expect("its address"));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut seen = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !seen.windows(4).any(|end| end == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => seen.extend_from_slice(&chunk[..read]),
                }
            }
            let _ = stream.write_all(
                b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            );
        }
    });
    origin
}

/// KR-REQ-16.04: `kr host push-gateways` with nothing to change fails, as a change does, when the
/// host says it has not finished putting its configuration document into force, and says both the
/// gateways in force and what the host has not finished. Here the host could not write down the
/// revocation it owes a gateway the document no longer lists. It moves the list before it retires
/// the gateway's credential, so the list it reports is the one it delivers through, and what is
/// unfinished is the retirement; a list shown on its own would suggest that the host has acted on
/// the whole document.
#[test]
fn kr_host_push_gateways_with_nothing_to_change_fails_when_the_host_did_not_put_the_document_into_force()
 {
    let gateway = a_gateway_that_is_unavailable();
    let gateway = gateway.as_str();
    let Some(host) = Standalone::create() else {
        return;
    };
    // The first revision of a document that chooses the standalone start and lists the gateway.
    kr_ipc::paths::write_owner_only_file(
        &host.document(),
        format!(
            r#"{{"version": 3, "level": 7, "revision": 1, "startup": {{"controller": "standalone"}}, "push": {{"gateways": ["{gateway}"]}}}}"#
        )
        .as_bytes(),
    )
    .expect("writes the configuration document");
    host.hold_a_credential_issued_by(gateway);
    let output = host.finish_through_a_slow_start("kr new", || host.new_session());
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let show = || {
        let output =
            start(host.kr(&["--json", "host", "push-gateways"])).finish("kr host push-gateways");
        (
            output.status.success(),
            document(&output, "kr host push-gateways"),
        )
    };
    let owed = || -> i64 {
        host.delivery_journal()
            .query_row("SELECT COUNT(*) FROM delivery_revocations", [], |row| {
                row.get(0)
            })
            .expect("the debts are counted")
    };

    // The control: while the gateway is listed the host delivers through it, and says so.
    let (ok, shown) = show();
    assert!(ok, "{shown}");
    assert_eq!(
        shown["push_gateways"],
        serde_json::json!([gateway]),
        "{shown}"
    );

    // The journal will not take a debt, and the owner takes the gateway out of the list by hand.
    host.delivery_journal()
        .execute_batch(
            "CREATE TRIGGER refuse_a_debt BEFORE INSERT ON delivery_revocations
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .expect("the trigger");
    kr_ipc::paths::write_owner_only_file(
        &host.document(),
        br#"{"version": 3, "revision": 2, "startup": {"controller": "standalone"}}"#,
    )
    .expect("writes the configuration document");
    let (ok, shown) = show();
    assert!(
        !ok,
        "the host did not finish putting the document into force: {shown}"
    );
    assert_eq!(shown["code"], "RESOURCE_UNAVAILABLE", "{shown}");
    assert!(
        shown["message"]
            .as_str()
            .is_some_and(|message| message.contains("were not let go of")),
        "it gives the retirement as the reason: {shown}"
    );
    assert!(
        shown["message"]
            .as_str()
            .is_some_and(|message| message.contains("the official gateway only")),
        "it says the list in use is the document's, which no longer lists the gateway: {shown}"
    );
    assert_eq!(owed(), 0, "and nothing was written down");

    // Once the journal takes it, the next question puts the document into force.
    host.delivery_journal()
        .execute_batch("DROP TRIGGER refuse_a_debt;")
        .expect("the trigger goes");
    let (ok, shown) = show();
    assert!(ok, "{shown}");
    assert_eq!(shown["push_gateways"], serde_json::json!([]), "{shown}");
    assert_eq!(owed(), 1, "the revocation the host owes is written down");
    host.close(&created);
}

/// KR-REQ-16.04: `kr host push-gateways` with nothing to change fails, and says why, on a host
/// that started over a configuration document it cannot use and still reads one it cannot use.
/// That host closes its routes, so it does not deliver through the official gateway or any other,
/// whatever list it reports.
#[test]
fn kr_host_push_gateways_with_nothing_to_change_fails_on_a_host_started_over_an_unusable_document()
{
    let show = |host: &Standalone| {
        let output =
            start(host.kr(&["--json", "host", "push-gateways"])).finish("kr host push-gateways");
        (
            output.status.success(),
            document(&output, "kr host push-gateways"),
        )
    };

    // The control: a daemon started by hand over a document the host can use shows its list.
    let Some(usable) = Standalone::create() else {
        return;
    };
    usable.select_standalone();
    usable.start_a_daemon_by_hand();
    let (ok, shown) = show(&usable);
    assert!(ok, "{shown}");
    assert_eq!(shown["push_gateways"], serde_json::json!([]), "{shown}");

    let Some(host) = Standalone::create() else {
        return;
    };
    kr_ipc::paths::write_owner_only_file(&host.document(), br#"{"version": 99}"#)
        .expect("writes a configuration document this build cannot use");
    host.start_a_daemon_by_hand();
    let (ok, shown) = show(&host);
    assert!(!ok, "the host cannot use its document: {shown}");
    assert_eq!(shown["code"], "RESOURCE_UNAVAILABLE", "{shown}");
    assert!(
        shown["message"]
            .as_str()
            .is_some_and(|message| message.contains("unknown_version")),
        "it says what the document turned out to be: {shown}"
    );
}

/// KR-REQ-16.04: a host started over a configuration document it could not use keeps its routes
/// closed after the document is put right, because it reads its routes once, when it starts. The
/// host reports the document as usable then, so `kr host push-gateways` shows its list and says on
/// standard error that a restart is needed, naming the doctor check that says why; its answer on
/// standard output is the one a host with open routes gives, and the exit is still success. In
/// text, the line it ends on names the gateways in force and does not say the host delivers through
/// them. An edit that only says what a document left unsaid (`network.enabled` absent, then
/// `false`) selects nothing new and gives no note on a host with open routes; a real change does.
#[test]
fn kr_host_push_gateways_says_a_restart_is_needed_on_a_host_started_over_a_document_put_right_since()
 {
    let show = |host: &Standalone| {
        let output =
            start(host.kr(&["--json", "host", "push-gateways"])).finish("kr host push-gateways");
        (
            output.status.success(),
            document(&output, "kr host push-gateways"),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let in_text = |host: &Standalone| {
        let output = start(host.kr(&["host", "push-gateways"])).finish("kr host push-gateways");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };

    // The control: a daemon started by hand over a document the host can use needs no restart.
    let Some(usable) = Standalone::create() else {
        return;
    };
    usable.select_standalone();
    usable.start_a_daemon_by_hand();
    let (ok, shown, said) = show(&usable);
    assert!(ok, "{shown}");
    assert!(
        said.is_empty(),
        "a host with open routes says nothing: {said}"
    );
    let members = |answer: &Value| {
        answer
            .as_object()
            .map(|members| members.keys().cloned().collect::<Vec<_>>())
    };
    let control_members = members(&shown);
    let (ok, line, said) = in_text(&usable);
    assert!(
        ok && line.contains("delivers notifications through the official gateway only"),
        "a host with open routes is said to deliver: {line}"
    );
    assert!(said.is_empty(), "{said}");

    // The document now says what it left unsaid, and nothing else: the host is still off the
    // network, so no route waits for a restart. A proxy is a real change.
    kr_ipc::paths::write_owner_only_file(
        &usable.document(),
        br#"{"version": 1, "revision": 2, "startup": {"controller": "standalone"}, "network": {"enabled": false}}"#,
    )
    .expect("writes the configuration document");
    let (ok, shown, said) = show(&usable);
    assert!(ok, "{shown}: {said}");
    assert!(
        said.is_empty(),
        "an edit that changes no selection needs no restart: {said}"
    );
    kr_ipc::paths::write_owner_only_file(
        &usable.document(),
        br#"{"version": 1, "revision": 3, "startup": {"controller": "standalone"}, "network": {"enabled": false, "proxy_url": "http://127.0.0.1:3128"}}"#,
    )
    .expect("writes the configuration document");
    let (ok, shown, said) = show(&usable);
    assert!(ok, "{shown}: {said}");
    assert!(
        said.contains("restart"),
        "a proxy the host did not start with needs one: {said}"
    );

    let Some(host) = Standalone::create() else {
        return;
    };
    kr_ipc::paths::write_owner_only_file(&host.document(), br#"{"version": 99}"#)
        .expect("writes a configuration document this build cannot use");
    host.start_a_daemon_by_hand();
    let (ok, shown, _) = show(&host);
    assert!(!ok, "the host cannot use its document: {shown}");

    // The owner puts the document right. The host reads it as usable, and its routes stay closed.
    host.select_standalone();
    let (ok, shown, said) = show(&host);
    assert!(ok, "the document is usable now: {shown}: {said}");
    assert_eq!(
        members(&shown),
        control_members,
        "the answer on standard output is the one a host with open routes gives: {shown}"
    );
    assert_eq!(shown["push_gateways"], serde_json::json!([]), "{shown}");
    assert!(
        said.contains("restart") && said.contains("configuration-network"),
        "it says a restart is needed, and where the host says why: {said}"
    );
    let (ok, line, _) = in_text(&host);
    assert!(
        ok && line.contains("in force") && !line.contains("deliver"),
        "the line it ends on does not say the host delivers: {line}"
    );
}

/// KR-REQ-16.04: a host started over a document it could not use, and then given one it can use
/// whose acceptance does not finish, fails the command with the host's reason, says the gateways in
/// force without saying that the host delivers through them, and still says that a restart is
/// needed: its routes are closed whatever it has accepted since. Here the document is put right and
/// no longer lists a gateway the host holds a credential for, and the journal will not take the
/// debt the retirement writes down.
#[test]
fn kr_host_push_gateways_says_a_restart_is_needed_when_the_document_put_right_is_not_all_in_force()
{
    let gateway = a_gateway_that_is_unavailable();
    let Some(host) = Standalone::create() else {
        return;
    };
    kr_ipc::paths::write_owner_only_file(&host.document(), br#"{"version": 99}"#)
        .expect("writes a configuration document this build cannot use");
    host.hold_a_credential_issued_by(&gateway);
    host.start_a_daemon_by_hand();
    let push_gateways = |arguments: &[&str]| {
        let mut command = vec!["--json", "host", "push-gateways"];
        command.extend_from_slice(arguments);
        let output = start(host.kr(&command)).finish("kr host push-gateways");
        (
            output.status.success(),
            document(&output, "kr host push-gateways"),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let show = || push_gateways(&[]);
    let (ok, shown, said) = show();
    assert!(!ok, "the host cannot use its document: {shown}");
    assert!(
        !said.contains("restart"),
        "a document the host cannot use gets no note about the routes: {said}"
    );

    // The journal will not take a debt, and the document is put right without the gateway.
    host.delivery_journal()
        .execute_batch(
            "CREATE TRIGGER refuse_a_debt BEFORE INSERT ON delivery_revocations
             BEGIN SELECT RAISE(ABORT, 'refused'); END;",
        )
        .expect("the trigger");
    host.select_standalone();
    let (ok, shown, said) = show();
    assert!(
        !ok,
        "the host did not finish putting the document into force: {shown}"
    );
    assert_eq!(shown["code"], "RESOURCE_UNAVAILABLE", "{shown}");
    let message = shown["message"].as_str().expect("a message");
    assert!(
        message.contains("were not let go of"),
        "it gives the retirement as the reason: {shown}"
    );
    assert!(
        message.contains("the official gateway only") && !message.contains("delivers"),
        "it says the list in force and does not say the host delivers through it: {shown}"
    );
    assert!(
        said.contains("restart") && said.contains("configuration-network"),
        "it still says a restart is needed, and where the host says why: {said}"
    );

    // A change fails the same way: the document is written, the acceptance does not finish, and the
    // note is written beside the failure. The credential is outside the new list too.
    let (ok, shown, said) = push_gateways(&["--set", "https://push.other.example"]);
    assert!(!ok, "the change is not all in force: {shown}");
    assert_eq!(shown["code"], "RESOURCE_UNAVAILABLE", "{shown}");
    assert!(
        shown["message"]
            .as_str()
            .is_some_and(|message| message.contains("were not let go of")),
        "it gives the host's reason: {shown}"
    );
    assert!(
        said.contains("restart") && said.contains("configuration-network"),
        "a failed change says a restart is needed too: {said}"
    );
}

/// KR-REQ-08.02: `kr status` reports each terminal attachment's presentation and the reason for it.
///
/// Two terminals attach to a session the started daemon holds: one at the session's own size that
/// declared no terminal profile, and one with a qualified profile at another size. Both are shown
/// a projection, each for a reason of its own, and `kr status` says which and why, in text and in
/// `--json`, as the session's own worker reports it. Neither reason passes with time, so what is
/// read does not depend on when it is read.
#[test]
fn status_reports_each_terminal_attachments_presentation_and_its_reason() {
    let Some(host) = Standalone::create() else {
        return;
    };
    host.select_standalone();
    let output = host.finish_through_a_slow_start("kr new", || host.new_session());
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let session_id: SessionId = created["session_id"]
        .as_str()
        .expect("a session identifier")
        .parse()
        .expect("parses");
    let display = created["display_number"].to_string();
    let canonical = Dimensions::new(
        created["dimensions"]["columns"].as_u64().expect("columns"),
        created["dimensions"]["rows"].as_u64().expect("rows"),
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime");
    let ((undeclared_client, undeclared), (smaller_client, smaller)) = runtime.block_on(async {
        (
            terminal_attachment(&host, session_id, canonical, None).await,
            terminal_attachment(
                &host,
                session_id,
                Dimensions::new(canonical.columns() - 20, canonical.rows() - 10),
                Some("xterm-256color"),
            )
            .await,
        )
    });

    let status = start(host.kr(&["--json", "status", &display])).finish("kr status");
    let report = document(&status, "kr status");
    assert!(status.status.success(), "{report}");
    let terminals = report["terminal_attachments"]
        .as_array()
        .unwrap_or_else(|| panic!("kr status lists the terminal attachments: {report}"));
    let reported = |attachment: AttachmentId| {
        terminals
            .iter()
            .find(|entry| entry["attachment_id"] == attachment.to_string())
            .unwrap_or_else(|| panic!("attachment {attachment} is listed: {report}"))
    };
    let entry = reported(undeclared);
    assert_eq!(entry["presentation"], "viewport", "{entry}");
    assert_eq!(
        entry["presentation_reason"], "no_terminal_profile",
        "{entry}"
    );
    let entry = reported(smaller);
    assert_eq!(entry["presentation"], "viewport", "{entry}");
    assert_eq!(entry["presentation_reason"], "size_mismatch", "{entry}");

    let shown = start(host.kr(&["status", &display])).finish("kr status");
    assert!(shown.status.success());
    let printed = String::from_utf8_lossy(&shown.stdout);
    for expected in [
        format!("attachment {undeclared}: viewport (no_terminal_profile)"),
        format!("attachment {smaller}: viewport (size_mismatch)"),
    ] {
        assert!(printed.contains(&expected), "{expected}: {printed}");
    }

    drop((undeclared_client, smaller_client));
    host.close(&created);
}

/// A worker of this test's own for `session_id`, which publishes its descriptor, proves itself as a
/// session's worker does and answers `session.read`, and never answers `events.snapshot`.
///
/// It runs on the runtime it is started from, for as long as that runtime runs.
async fn a_worker_that_withholds_its_attachments(host: &Standalone, session_id: SessionId) {
    use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};

    let environment = host.tree.environment();
    let environment_id = host.tree.environment_id();
    let display = kr_protocol::session::DisplayNumber::new(9);
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = kr_ipc::verify::WorkerIdentity::generate(
        session_id,
        SessionEpoch::V1,
        boot.clone(),
        process.clone(),
        kr_protocol::hello::PROTOCOL_VERSION,
    )
    .expect("a session key");
    let endpoint = environment.worker_endpoint(display).expect("an endpoint");
    let endpoint_text = endpoint.as_text();
    kr_ipc::descriptor::publish(
        &environment,
        &kr_protocol::worker::WorkerDescriptor {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: display,
            boot_identity: boot.clone(),
            process_start_identity: process,
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            endpoint: endpoint_text.clone(),
            worker_public_key: *identity.public_key(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            published_at_ms: kr_protocol::scalars::TimestampMs::new(0),
        },
    )
    .expect("publishes the descriptor");
    let read = kr_protocol::session::SessionReadResult {
        session: kr_protocol::session::SessionSummary {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: display,
            state: kr_protocol::session::SessionState::Live,
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            shell_path: "/bin/sh".to_owned(),
            cwd: "/".to_owned(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            created_at_ms: kr_protocol::scalars::TimestampMs::new(1),
            dimensions: Dimensions::new(120, 40),
            attachment_count: kr_protocol::scalars::U64::new(1),
            application_state: Nullable::null(),
            root_process: Nullable::null(),
            closure: Nullable::null(),
            environment_sources: None,
            root: None,
            application: None,
        },
        endpoint: Nullable::some(endpoint_text.clone()),
        launch_profile: Nullable::null(),
        last_command_block: Nullable::null(),
        outstanding_launches: Nullable::null(),
        metrics: None,
    };
    let boot_epoch = kr_ipc::identity::boot_epoch(&boot).expect("a boot epoch");
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(async move {
        while let Ok((connection, peer)) = listener.accept().await {
            let (mut reader, mut writer) =
                kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
            let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
            while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                let answer = match frame {
                    ControlFrame::Hello(_) => {
                        ControlFrame::HelloAck(Box::new(kr_protocol::local::LocalHelloAck {
                            selected_version: kr_protocol::hello::PROTOCOL_VERSION,
                            role: kr_protocol::local::LocalRole::Worker,
                            connection_id,
                            environment_id,
                            boot_identity: boot.clone(),
                            peer: peer.to_wire(),
                            action_window: kr_protocol::hello::ActionWindow {
                                action_window_id: kr_protocol::ids::ActionWindowId::new(
                                    "withholding-worker",
                                )
                                .expect("a window identifier"),
                                connection_id,
                                boot_epoch,
                                issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
                                valid_for_ms: kr_protocol::scalars::DurationMs::new(60_000),
                            },
                            capabilities: CanonicalSet::new(),
                            max_receive: kr_protocol::hello::ReceiveLimits::default(),
                            // A worker states the build it runs, and `kr status` reads only a worker
                            // of its own compatibility level.
                            build: Some(kr_protocol::local::LocalBuild {
                                build_id: BuildId::new("kr-worker/0.1.0")
                                    .expect("a build identifier"),
                                protocol_version: kr_protocol::hello::PACKAGE_VERSION,
                            }),
                        }))
                    }
                    ControlFrame::VerifyChallenge(challenge) => ControlFrame::VerifyProof(
                        identity
                            .answer(&challenge, &endpoint_text)
                            .expect("proves itself"),
                    ),
                    ControlFrame::Request(request)
                        if request.method.method() == Some(Method::SessionRead) =>
                    {
                        ControlFrame::Response(Response {
                            request_id: request.request_id,
                            outcome: Outcome::Ok(ParamsValue::from_typed(&read).expect("encodes")),
                        })
                    }
                    // `events.snapshot`, and anything else, is never answered.
                    _ => continue,
                };
                if writer.write_message(&answer).await.is_err() {
                    break;
                }
            }
        }
    });
}

/// KR-REQ-26.43: what a running session's terminal parser could not make sense of is in what
/// `kr doctor` reports of the host, which the daemon reads from the session's own worker.
///
/// A session's shell writes bytes that are not valid text and then waits, so nothing else is
/// written. The daemon, which never saw those bytes, is asked about the host until the worker's
/// count reaches it, and the document names the class of fault and how often it met one: no byte
/// of the output is in it.
#[test]
fn doctor_reports_the_faults_a_running_sessions_terminal_met() {
    let Some(host) = Standalone::create() else {
        return;
    };
    host.select_standalone();
    let shell = host.tree.root().join("faulty-shell.sh");
    kr_ipc::testing::place_script(
        &shell,
        "#!/bin/sh\nprintf 'ok\\355\\240\\200more'\nexec cat\n",
    );
    let cwd = host.tree.root().display().to_string();
    let output = host.finish_through_a_slow_start("kr new", || {
        host.kr(&[
            "--json",
            "new",
            "--invisible",
            "--headless",
            "--cwd",
            &cwd,
            "--shell",
            &shell.display().to_string(),
            "--shell-mode",
            "native_compat",
            "--startup",
            "interactive",
        ])
    });
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");

    let begun = Instant::now();
    let counted = loop {
        let output = start(host.kr(&["--json", "doctor"])).finish("kr doctor");
        let report = document(&output, "kr doctor");
        let found = report["doctor"]["metrics"]["terminal_parse_fault"]
            .as_array()
            .and_then(|series| {
                series
                    .iter()
                    .find(|series| series["fault"] == "invalid_encoding")
                    .cloned()
            });
        if let Some(found) = found {
            break (found, report);
        }
        assert!(
            begun.elapsed() < LIVENESS_DEADLINE,
            "the host reported no invalid text within {LIVENESS_DEADLINE:?}: {report}"
        );
        std::thread::sleep(Duration::from_millis(200));
    };
    let (series, report) = counted;
    assert!(
        series["count"].as_u64().is_some_and(|count| count >= 1),
        "{series}"
    );
    assert_eq!(series["environment"], "development", "{series}");
    assert!(
        !report["doctor"]["metrics"].to_string().contains("more"),
        "the report carries the class of fault and nothing the program wrote"
    );
    host.close(&created);
}

/// KR-REQ-08.02: a worker that answers the session read and never the question about its
/// attachments leaves `kr status` the session, and the attachments are reported as not read.
///
/// `kr status` waits its bound for the second answer, prints the session it has, and says why the
/// attachments are missing: `terminal_attachments` is null and `terminal_attachments_unread` names
/// the bound.
#[test]
fn status_reports_the_session_when_its_worker_withholds_the_attachments() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    let session_id = SessionId::new(kr_ipc::new_uuid());
    runtime.block_on(a_worker_that_withholds_its_attachments(&host, session_id));

    let started = Instant::now();
    let output = start(host.kr(&["--json", "status", &session_id.to_string()])).finish("kr status");
    let report = document(&output, "kr status");
    assert!(output.status.success(), "{report}");
    assert_eq!(report["session_id"], session_id.to_string(), "{report}");
    assert_eq!(report["state"], "live", "{report}");
    assert_eq!(report["terminal_attachments"], Value::Null, "{report}");
    let unread = report["terminal_attachments_unread"]
        .as_str()
        .unwrap_or_default();
    assert!(
        unread.contains("did not answer within 10 seconds"),
        "the status says why the attachments are missing: {report}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "and it waited its bound rather than for ever: {:?}",
        started.elapsed()
    );
    drop(runtime);
}

/// KR-REQ-07.12: a supervisor still waiting to start its daemon when its test ends starts nothing,
/// and the test's teardown waits for it.
///
/// The daemon is held back past the command's bound, and the test ends while it is held: what a
/// failing test's teardown does, run here on purpose. The supervisor sees the lifeline close, starts
/// no daemon and ends, and teardown has waited for it by the time it returns. The command then gives
/// up at its bound as it would with no daemon.
#[test]
fn a_supervisor_still_waiting_when_its_test_ends_starts_nothing() {
    let Some(mut host) = Standalone::create() else {
        return;
    };
    host.select_standalone();
    host.ask_the_scripts(DELAY, "40");
    let running = start(host.new_session());
    let begun = Instant::now();
    while host.identities(STARTS).0.is_empty() {
        assert!(
            begun.elapsed() < LIVENESS_DEADLINE,
            "the supervisor recorded itself"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let supervisor = host.identities(STARTS).0.remove(0);

    assert_eq!(host.end_what_was_started(), Vec::<String>::new());
    assert_eq!(
        kr_ipc::identity::process_state(&supervisor),
        ProcessState::Ended,
        "the supervisor ended with its test"
    );
    assert!(host.launched().is_empty(), "and started no daemon");

    let output = running.finish("kr new");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "ENVIRONMENT_UNAVAILABLE", "{failure}");
}

/// A record names a process that ended before it was recorded as one that has ended, rather than
/// failing: on macOS the kernel stops describing a process once it has ended, collected or not,
/// which is what a daemon that could not take the environment does.
#[test]
fn a_process_that_ended_before_it_was_recorded_is_recorded_as_ended() {
    let mut child = spawning(|| Command::new("/usr/bin/true").spawn()).expect("starts a process");
    let pid = child.id();
    let begun = Instant::now();
    // Ended, and not collected: this test has not waited for it yet.
    while match kr_ipc::identity::query_process(pid) {
        ProcessQuery::Gone => false,
        ProcessQuery::Present(identity) => {
            kr_ipc::identity::process_state(&identity) != ProcessState::Ended
        }
        ProcessQuery::CannotEstablish(error) => panic!("{error}"),
    } {
        assert!(begun.elapsed() < LIVENESS_DEADLINE, "the process ended");
        std::thread::sleep(Duration::from_millis(20));
    }
    let line = record_line(pid);
    let (number, identity) = line
        .trim_end()
        .split_once('\t')
        .expect("a number and an identity");
    assert_eq!(number, pid.to_string());
    let identity: kr_protocol::identity::ProcessStartIdentity =
        serde_json::from_str(identity).expect("an identity");
    assert_eq!(
        kr_ipc::identity::process_state(&identity),
        ProcessState::Ended,
        "{line}"
    );
    let _ = child.wait();
}

/// A record cut off part way is reported, and every record that can be read is still waited for.
#[test]
fn a_partial_record_is_reported_and_the_others_are_still_waited_for() {
    let Some(mut host) = Standalone::create() else {
        return;
    };
    let ended = serde_json::to_string(&kr_ipc::identity::ended_process_identity(4242))
        .expect("encodes an identity");
    let starts = host.tree.root().join(STARTS);
    std::fs::write(&starts, format!("4242\t{ended}\n4243\t{{\"pid\":\"42\n"))
        .expect("writes the records");

    let unresolved = host.end_what_was_started();
    assert_eq!(unresolved.len(), 1, "{unresolved:?}");
    assert!(unresolved[0].contains("names no process"), "{unresolved:?}");
    // Put right, so this test's own teardown finds nothing to keep the tree for.
    std::fs::write(&starts, format!("4242\t{ended}\n")).expect("writes the records");
}

/// A test that fails with a partial record keeps its tree and does not end the suite: the teardown
/// that runs while it unwinds reports the record rather than panicking a second time.
#[test]
fn a_failing_test_with_a_partial_record_keeps_its_tree_and_does_not_end_the_suite() {
    let root = std::sync::Mutex::new(None);
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // No daemon is started here, so this one needs no launchd.
        let host = Standalone::make();
        *root.lock().expect("the root") = Some(host.tree.root().to_path_buf());
        std::fs::write(host.tree.root().join(LAUNCHED), "4243\t{\"pid\":\"42\n")
            .expect("writes a partial record");
        panic!("a test that fails with a partial record");
    }));
    assert!(
        failed.is_err(),
        "the test failed, and this process is still here"
    );
    let root = root
        .lock()
        .expect("the root")
        .take()
        .expect("the tree was made");
    assert!(root.is_dir(), "the tree was kept for somebody to look at");
    // Nothing runs in it: the only record names no process. This test made it, so it removes it.
    std::fs::remove_dir_all(&root).expect("removes the kept tree");
}

// ------------------------------------------------------------------------------------------------
// The service start
// ------------------------------------------------------------------------------------------------

/// The installation the service-start tests run, on the internal disk: `kr` and its guard, the
/// worker, the real daemon, and beside them the `kr-controller` a definition names.
///
/// That `kr-controller` is a script that hands over, with `exec`, to the real daemon with its keys
/// in the environment's own `secrets` directory, so that nothing reaches the credential store of the
/// person running the tests. The handover replaces the script's process rather than starting a
/// child, so the process the service manager started is the daemon itself, and the manager is the
/// daemon's parent.
fn service_installation() -> &'static Path {
    static PLACED: OnceLock<PathBuf> = OnceLock::new();
    PLACED.get_or_init(|| {
        let (Some(controller), Some(worker)) = (
            beside_this_test("kr-controller"),
            beside_this_test("kr-worker"),
        ) else {
            panic!(
                "the kr-controller and kr-worker executables are not built beside this test, so \
                 this check cannot run; a workspace test run builds them, and so does \
                 `cargo build -p kr-controller -p kr-worker`"
            );
        };
        let directory = support::command_binaries().join("service");
        std::fs::create_dir(&directory).expect("a directory for the service installation");
        for source in [
            Path::new(env!("CARGO_BIN_EXE_kr")),
            Path::new(env!("CARGO_BIN_EXE_kr-attach-guard")),
        ] {
            let name = source.file_name().expect("the binary has a name");
            kr_ipc::testing::place_and_start_once(source, &directory.join(name), &["--version"]);
        }
        // The daemon and the worker are side by side, where a release keeps them, and the daemon is
        // under its own name: what the worker takes for the daemon of its installation is the file
        // beside it.
        let real = directory.join("daemon");
        std::fs::create_dir(&real).expect("a directory for the daemon and its worker");
        kr_ipc::testing::place_and_start_once(&worker, &real.join("kr-worker"), &["--version"]);
        let daemon = real.join("kr-controller");
        kr_ipc::testing::place_and_start_once(&controller, &daemon, &["--version"]);
        // What `kr` starts: a script that hands over, with `exec`, to the daemon. A test that sets
        // the hold variable has the daemon wait, as a process of the command that started it,
        // until the file `go` is in the directory it names; it records its number there first, and
        // the number stays the daemon's.
        let source = directory.join("kr-controller.sh");
        std::fs::write(
            &source,
            format!(
                "#!/bin/sh\n\
                 if [ -n \"$KR_TEST_HOLD_DIR\" ]; then\n\
                 \x20 echo $$ > \"$KR_TEST_HOLD_DIR/daemon.pid.tmp\"\n\
                 \x20 mv \"$KR_TEST_HOLD_DIR/daemon.pid.tmp\" \"$KR_TEST_HOLD_DIR/daemon.pid\"\n\
                 \x20 while [ ! -e \"$KR_TEST_HOLD_DIR/go\" ]; do sleep 0.05; done\n\
                 fi\n\
                 exec '{}' --secret-store file \"$@\"\n",
                daemon.display()
            ),
        )
        .expect("writes the daemon script");
        kr_ipc::testing::place_program(&source, &directory.join("kr-controller"));
        directory
    })
}

/// The parent of a process of this user's, and the parent's name.
fn parent_of(pid: u32) -> (u32, String) {
    let asked = |arguments: &[&str]| {
        let output =
            spawning(|| Command::new("/bin/ps").args(arguments).output()).expect("runs ps");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    };
    let parent: u32 = asked(&["-o", "ppid=", "-p", &pid.to_string()])
        .parse()
        .expect("ps names the parent");
    let name = asked(&["-o", "comm=", "-p", &parent.to_string()]);
    (parent, name)
}

/// A unit file's command line that creates `mark` and nothing else: each word quoted as systemd
/// reads it, with its specifier character doubled, and environment expansion off.
#[cfg(target_os = "linux")]
fn touching(mark: &Path) -> String {
    let word = |value: &str| {
        format!(
            "\"{}\"",
            value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('%', "%%")
        )
    };
    format!(
        "{} {} {}",
        word(":/usr/bin/touch"),
        word("--"),
        word(&mark.display().to_string())
    )
}

/// A D-Bus address for the socket at `path`: letters, digits and `-_/.` as they are, and every
/// other byte as `%` and its two hex digits, which every D-Bus library reads back.
#[cfg(target_os = "linux")]
fn bus_address(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt as _;

    let mut address = "unix:path=".to_owned();
    for byte in path.as_os_str().as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-_/.".contains(byte) {
            address.push(char::from(*byte));
        } else {
            address.push_str(&format!("%{byte:02x}"));
        }
    }
    address
}

/// Set to `1` by a run that has the service-start cases load jobs into the account's own launchd
/// on macOS: a hosted runner's account is for the run alone, and a person's own is not.
const ALLOW_ACCOUNT_LAUNCHD: &str = "KR_ALLOW_ACCOUNT_LAUNCHD";

/// Whether a run asked, by the value of [`ALLOW_ACCOUNT_LAUNCHD`], for the account's own launchd,
/// and where it did not, why the cases that need it do not run. Only `1` asks.
fn account_launchd(asked: Option<&std::ffi::OsStr>) -> Result<(), String> {
    if asked == Some(std::ffi::OsStr::new("1")) {
        Ok(())
    } else {
        Err(format!(
            "this run did not ask for the account's own launchd, which the daemons these cases start \
             load jobs into and remove them from; set {ALLOW_ACCOUNT_LAUNCHD}=1 where that account \
             is a test account or a hosted runner's"
        ))
    }
}

/// A host tree of a test's own where the service start is chosen: a home of the test's own that
/// the definition is written in, and the user service manager that starts the daemon.
///
/// On macOS that manager is launchd, and the definition is loaded into this user's own domain under
/// a label that names the tree's own environment, so no other test has it. A run loads into the
/// account's own launchd only where it sets [`ALLOW_ACCOUNT_LAUNCHD`]. On Linux the manager is a
/// [`UserManager`] of the test's own.
///
/// However a test ends, the daemon the manager started is ended through the manager first. On
/// Linux the test's own manager ends next, and with its scope everything it started, workers
/// included; on macOS the tree then ends every worker the daemon recorded. A tree in which that
/// cannot be established is kept.
struct ServiceHost {
    // Dropped first, while the tree is still there to be kept.
    #[cfg(target_os = "linux")]
    manager: UserManager,
    tree: teardown::Tree,
    home: PathBuf,
}

impl Drop for ServiceHost {
    fn drop(&mut self) {
        if let Err(why) = self.end_the_daemon() {
            self.tree.hold(why);
        }
    }
}

impl ServiceHost {
    /// A tree with a user service manager, or none where this host has no manager to test with,
    /// having said why; a host that sets `KR_REQUIRE_SERVICE_MANAGER` fails instead. On macOS the
    /// manager is the account's own launchd, which a run uses only where it sets
    /// `KR_ALLOW_ACCOUNT_LAUNCHD`.
    fn create() -> Option<Self> {
        #[cfg(target_os = "macos")]
        {
            let asked = std::env::var_os(ALLOW_ACCOUNT_LAUNCHD);
            match Self::in_launchd(asked.as_deref(), Path::new("/bin/launchctl")) {
                Ok(host) => Some(host),
                Err(why) => Self::not_here(&why),
            }
        }
        #[cfg(target_os = "linux")]
        {
            let (tree, home) = Self::tree_and_home();
            match UserManager::start(&home, tree.holder()) {
                Ok(manager) => Some(Self {
                    manager,
                    tree,
                    home,
                }),
                Err(why) => Self::not_here(&why),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            drop(Self::tree_and_home());
            Self::not_here("this platform has no service start")
        }
    }

    /// The tree of a test's own, with the home of its own that a definition is written in.
    fn tree_and_home() -> (teardown::Tree, PathBuf) {
        let tree = teardown::Tree::create();
        let home = tree.root().join("home");
        std::fs::create_dir_all(&home).expect("a home of this test's own");
        (tree, home)
    }

    /// A tree on the account's own launchd, which `launchctl` reaches, or why there is none. Where
    /// the run did not ask for that launchd, nothing is made and `launchctl` is not run, not even
    /// to read.
    #[cfg(target_os = "macos")]
    fn in_launchd(asked: Option<&std::ffi::OsStr>, launchctl: &Path) -> Result<Self, String> {
        account_launchd(asked)?;
        let (tree, home) = Self::tree_and_home();
        let domain = format!("user/{}", kr_ipc::paths::current_uid());
        let mut print = Command::new(launchctl);
        print.args(["print", &domain]);
        match bounded(print, STREAMS_DEADLINE) {
            Ok(printed) if printed.status.success() => Ok(Self { tree, home }),
            answered => Err(format!(
                "launchd has no {domain} domain for this user to load a definition into: \
                 {answered:?}"
            )),
        }
    }

    /// Says why a service test did not run, or fails it where it has to run.
    fn not_here(why: &str) -> Option<Self> {
        user_manager::not_tested_here(why);
        None
    }

    /// The label the service manager knows this environment's daemon by.
    fn label(&self) -> String {
        format!("kr-controller-{}", self.tree.environment_id())
    }

    /// Where the definition of this environment's daemon belongs, in the test's own home.
    fn definition(&self) -> PathBuf {
        if cfg!(target_os = "macos") {
            self.home
                .join("Library/LaunchAgents")
                .join(format!("{}.plist", self.label()))
        } else {
            self.home
                .join(".config/systemd/user")
                .join(format!("{}.service", self.label()))
        }
    }

    /// Where `kr host startup` records the definition it wrote.
    fn record(&self) -> PathBuf {
        self.tree
            .environment()
            .state_dir()
            .join("controller-service.json")
    }

    /// Where this environment's configuration document is.
    fn document(&self) -> PathBuf {
        self.tree.environment().state_dir().join("config.json")
    }

    /// `kr` from the service installation, against this tree, this home and this host's manager.
    fn kr(&self, arguments: &[&str]) -> Command {
        let mut command = Command::new(service_installation().join("kr"));
        command
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env(
                kr_ipc::paths::RUNTIME_DIR_VARIABLE,
                self.tree.paths().runtime_root(),
            )
            .env(
                kr_ipc::paths::STATE_DIR_VARIABLE,
                self.tree.paths().state_root(),
            )
            .current_dir(service_installation())
            .stdin(Stdio::null());
        if let Some(temporary) = std::env::var_os("TMPDIR") {
            command.env("TMPDIR", temporary);
        }
        #[cfg(target_os = "linux")]
        command.env("XDG_RUNTIME_DIR", &self.manager.runtime);
        command
    }

    /// `kr new` for an invisible, headless session of `/bin/sh` working in this tree.
    fn new_session(&self) -> Command {
        let cwd = self.tree.root().display().to_string();
        self.kr(&[
            "--json",
            "new",
            "--shell-mode",
            "native_compat",
            "--invisible",
            "--headless",
            "--cwd",
            &cwd,
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
        ])
    }

    /// Chooses the service start as a person does, and returns what `kr host startup` reported.
    fn select_service(&self) -> Value {
        let output = start(self.kr(&["--json", "host", "startup", "--set", "service"]))
            .finish("kr host startup");
        let chosen = document(&output, "kr host startup");
        assert!(
            output.status.success(),
            "{chosen}; it said {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(chosen["startup"]["controller"], "service", "{chosen}");
        let definition = &chosen["startup"]["definition"];
        assert_eq!(definition["state"], "matches", "{chosen}");
        assert_eq!(definition["label"], self.label(), "{chosen}");
        assert_eq!(
            definition["path"],
            self.definition().display().to_string(),
            "{chosen}"
        );
        chosen
    }

    /// Has the test's user manager read its unit files again, as a person does after changing
    /// one.
    #[cfg(target_os = "linux")]
    fn reload(&self) {
        let reloaded = bounded(self.manager.systemctl(&["daemon-reload"]), STREAMS_DEADLINE)
            .expect("the manager reloads");
        assert!(
            reloaded.status.success(),
            "the manager reloads: {}",
            String::from_utf8_lossy(&reloaded.stderr)
        );
    }

    /// Closes a session this test created, through the daemon that holds it.
    fn close(&self, created: &Value) {
        let session = created["session_id"]
            .as_str()
            .expect("a session identifier");
        let output = start(self.kr(&["--json", "close", session])).finish("kr close");
        let closed = document(&output, "kr close");
        assert!(output.status.success(), "{closed}");
    }

    /// Whether anything answers on this environment's endpoint now.
    fn answers(&self) -> bool {
        answers(&self.tree.environment())
    }

    /// Asks this environment's daemon one question.
    fn ask<T: kr_protocol::wire::WireMessage>(
        &self,
        method: Method,
        params: &impl serde::Serialize,
    ) -> T {
        ask(&self.tree.environment(), method, params)
    }

    /// The process the service manager says the daemon's job is running, when it says one is.
    fn daemon(&self) -> Option<u32> {
        #[cfg(target_os = "macos")]
        {
            let uid = kr_ipc::paths::current_uid();
            [format!("gui/{uid}"), format!("user/{uid}")]
                .into_iter()
                .find_map(|domain| {
                    let mut print = Command::new("/bin/launchctl");
                    print.args(["print", &format!("{domain}/{}", self.label())]);
                    let printed = bounded(print, STREAMS_DEADLINE).ok()?;
                    String::from_utf8_lossy(&printed.stdout)
                        .lines()
                        .find_map(|line| line.strip_prefix("\tpid = ")?.trim().parse().ok())
                })
        }
        #[cfg(target_os = "linux")]
        {
            let unit = format!("{}.service", self.label());
            let shown = bounded(
                self.manager
                    .systemctl(&["show", "--property=MainPID", "--value", &unit]),
                STREAMS_DEADLINE,
            )
            .ok()?;
            String::from_utf8_lossy(&shown.stdout)
                .trim()
                .parse()
                .ok()
                .filter(|pid| *pid != 0)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }

    /// Establishes that the service manager started the daemon: its parent is the manager, it
    /// leads a process group of its own in a session no terminal ends, it has no controlling
    /// terminal, and it works in the environment's own directory.
    fn assert_started_by_the_manager(&self, pid: u32) {
        let (parent, name) = parent_of(pid);
        #[cfg(target_os = "macos")]
        assert!(
            parent == 1 && name.ends_with("launchd"),
            "launchd started the daemon: its parent is {parent} ({name})"
        );
        #[cfg(target_os = "linux")]
        assert!(
            parent == self.manager.pid() && name == "systemd",
            "the user manager started the daemon: its parent is {parent} ({name}), and the \
             manager is {}",
            self.manager.pid()
        );
        let process = rustix::process::Pid::from_raw(i32::try_from(pid).expect("a process number"))
            .expect("a process number");
        assert_eq!(
            rustix::process::getpgid(Some(process)).expect("its process group"),
            process,
            "the daemon leads a process group of its own"
        );
        // launchd runs a per-user agent such as this one in the session it leads as process 1,
        // which no terminal ends. A test that a launchd job runs, as on a hosted runner, is in
        // that session too, so the daemon's session is named here rather than compared with this
        // test's.
        #[cfg(target_os = "macos")]
        assert_eq!(
            rustix::process::getsid(Some(process))
                .expect("its session")
                .as_raw_nonzero()
                .get(),
            1,
            "and is in launchd's own session, which no terminal ends"
        );
        #[cfg(not(target_os = "macos"))]
        assert_ne!(
            rustix::process::getsid(Some(process)).expect("its session"),
            rustix::process::getsid(None).expect("this test's session"),
            "and is outside the session this test and its commands run in"
        );
        assert_eq!(
            kr_ipc::identity::controlling_terminal(pid).expect("its controlling terminal"),
            None,
            "and has no controlling terminal"
        );
        assert_eq!(
            working_directory(pid),
            std::fs::canonicalize(self.tree.environment().state_dir())
                .expect("the state directory"),
            "and works in the environment's own directory"
        );
    }

    /// Ends the daemon through the service manager that started it, and says what could not be
    /// established as ended.
    fn end_the_daemon(&self) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            let uid = kr_ipc::paths::current_uid();
            for domain in [format!("gui/{uid}"), format!("user/{uid}")] {
                let target = format!("{domain}/{}", self.label());
                let loaded = |target: &str| {
                    let mut print = Command::new("/bin/launchctl");
                    print.args(["print", target]);
                    bounded(print, STREAMS_DEADLINE).map(|printed| printed.status.success())
                };
                if !loaded(&target)? {
                    continue;
                }
                let mut bootout = Command::new("/bin/launchctl");
                bootout.args(["bootout", &target]);
                let removed = bounded(bootout, TEARDOWN_BOUND)?;
                // The job goes a moment after `bootout` answers, so it is asked about again until
                // the bound.
                let until = Instant::now() + STREAMS_DEADLINE;
                while loaded(&target)? {
                    if Instant::now() >= until {
                        return Err(format!(
                            "{target} is still loaded after it was removed: {}",
                            String::from_utf8_lossy(&removed.stderr).trim()
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            Ok(())
        }
        #[cfg(target_os = "linux")]
        {
            // Ending the manager's scope ends the daemon too; stopping it here first means nothing
            // is started while the rest ends.
            let unit = format!("{}.service", self.label());
            let stopped = bounded(self.manager.systemctl(&["stop", &unit]), TEARDOWN_BOUND)?;
            // The manager answers late when it is busy, and the unit can take a moment to go, so
            // the question is asked again until the bound.
            let asking_until = Instant::now() + TEARDOWN_BOUND;
            loop {
                let shown = bounded(
                    self.manager
                        .systemctl(&["show", "--property=ActiveState", "--value", &unit]),
                    STREAMS_DEADLINE,
                );
                let state = match &shown {
                    Ok(shown) => String::from_utf8_lossy(&shown.stdout).trim().to_owned(),
                    Err(_) => String::new(),
                };
                if matches!(state.as_str(), "inactive" | "failed") {
                    return Ok(());
                }
                if Instant::now() >= asking_until {
                    shown?;
                    return Err(format!(
                        "{unit} is {state} after it was stopped: {}",
                        String::from_utf8_lossy(&stopped.stderr).trim()
                    ));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Ok(())
        }
    }
}

/// Only a run that sets `KR_ALLOW_ACCOUNT_LAUNCHD` to `1` asks for the account's own launchd: the
/// variable absent, empty, or set to anything else does not.
#[test]
fn only_a_run_that_sets_the_account_launchd_variable_to_one_asks_for_the_accounts_launchd() {
    use std::ffi::OsStr;

    assert!(account_launchd(Some(OsStr::new("1"))).is_ok());
    for refused in [
        None,
        Some(""),
        Some("0"),
        Some("true"),
        Some("11"),
        Some(" 1"),
    ] {
        let why = account_launchd(refused.map(OsStr::new)).expect_err("does not ask");
        assert!(why.contains(ALLOW_ACCOUNT_LAUNCHD), "{why}");
    }
}

/// The text of a program in the place of `launchctl` that appends each call it is given to the
/// file `calls`. The path is quoted for the shell that reads the text, whatever it holds.
#[cfg(unix)]
fn a_launchctl_that_records(calls: &Path) -> String {
    format!(
        "#!/bin/sh\necho \"$@\" >> {}\n",
        kr_worker::testing::shell_quoted(calls)
    )
}

/// A program in the place of `launchctl` that records into a folder whose name holds a quote and a
/// space records the call it is given: the shell that reads its text gets the path as one word.
#[cfg(unix)]
#[test]
fn a_launchctl_stand_in_records_into_a_folder_whose_name_holds_a_quote_and_a_space() {
    let tree = teardown::Tree::create();
    let folder = tree.root().join("it's a folder");
    std::fs::create_dir(&folder).expect("a folder whose name holds a quote and a space");
    let calls = folder.join("launchctl calls");
    let stand_in = folder.join("launchctl");
    kr_ipc::testing::place_script(&stand_in, a_launchctl_that_records(&calls));
    let mut command = Command::new(&stand_in);
    command.args(["print", "gui/501/a label"]);
    let run = bounded(command, STREAMS_DEADLINE).expect("the stand-in runs");
    assert!(run.status.success(), "{run:?}");
    assert_eq!(
        std::fs::read_to_string(&calls).expect("the stand-in records the call"),
        "print gui/501/a label\n"
    );
}

/// A Mac run that did not ask for the account's own launchd gets no host from the service-start
/// cases and runs no `launchctl`, not to load a job and not to read one. A program in the place of
/// `launchctl` records each call it is given, and it is shown to record before it is trusted to
/// show there was none.
#[cfg(target_os = "macos")]
#[test]
fn a_run_that_did_not_ask_for_the_accounts_launchd_gets_no_host_and_runs_no_launchctl() {
    use std::ffi::OsStr;

    let tree = teardown::Tree::create();
    let calls = tree.root().join("launchctl-calls");
    let stand_in = tree.root().join("launchctl");
    kr_ipc::testing::place_script(&stand_in, a_launchctl_that_records(&calls));
    let control = bounded(Command::new(&stand_in), STREAMS_DEADLINE).expect("the stand-in runs");
    assert!(control.status.success(), "{control:?}");
    assert!(calls.exists(), "the stand-in does not record a call");
    std::fs::remove_file(&calls).expect("clears the record");

    for asked in [None, Some(OsStr::new("")), Some(OsStr::new("0"))] {
        assert!(
            ServiceHost::in_launchd(asked, &stand_in).is_err(),
            "a run that asked {asked:?} got a host"
        );
    }
    assert!(!calls.exists(), "launchctl was run");
}

/// KR-REQ-07.12: with the service start chosen, three first invocations at once converge on the
/// one control daemon the user's service manager starts.
///
/// `kr host startup --set service` writes the definition in the test's own home and has the
/// manager take it. Three `kr new` commands then start together with no daemon running, and each
/// asks the manager to start the daemon. The manager starts one: its parent is the manager, the
/// environment's generation advanced once, and every session the three commands created is in its
/// registry. The commands write nothing in the home: asking a manager to start what it was given
/// installs nothing.
#[test]
fn three_first_invocations_at_once_converge_on_the_one_daemon_the_service_manager_starts() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let before = every_path_under(&host.home);

    let started: Vec<Running> = (0..3).map(|_| start(host.new_session())).collect();
    let mut sessions = Vec::new();
    let mut documents = Vec::new();
    for (index, running) in started.into_iter().enumerate() {
        let what = format!("kr new {index}");
        let output = running.finish(&what);
        let created = document(&output, &what);
        assert!(
            output.status.success(),
            "{what} created its session: {created}; it said {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(created["state"], "live", "{what}: {created}");
        let session_id: SessionId = created["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("parses");
        sessions.push(session_id);
        documents.push(created);
    }

    let daemon = host
        .daemon()
        .expect("the service manager reports the daemon it started");
    host.assert_started_by_the_manager(daemon);
    let info: HostInfoResult = host.ask(Method::HostInfo, &());
    assert_eq!(info.environment_id, host.tree.environment_id());
    assert_eq!(
        info.generation.get(),
        1,
        "the environment's generation advanced once, for the one daemon the manager started"
    );
    let listed: SessionListResult = host.ask(
        Method::SessionList,
        &SessionListParams {
            environment_id: Nullable::some(host.tree.environment_id()),
            include_closed: false,
        },
    );
    for session_id in &sessions {
        assert!(
            listed
                .sessions
                .iter()
                .any(|summary| summary.session_id == *session_id),
            "session {session_id} is in the one daemon's registry: {:?}",
            listed.sessions
        );
    }
    assert!(
        every_path_under(&host.home) == before,
        "kr new wrote, removed or changed nothing in the home: it only asked the manager"
    );
    for created in &documents {
        host.close(created);
    }
}

/// KR-REQ-07.12, KR-REQ-26.04: the service start's definition and its record are what
/// `kr host startup --set service` wrote, `kr doctor` reports the choice, its source and that the
/// definition matches, and `--clear` removes the definition and its record without ending the
/// daemon, which keeps serving.
#[test]
fn clearing_the_service_start_removes_its_definition_and_record_and_the_daemon_keeps_serving() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    assert!(host.definition().is_file(), "the definition was written");
    let record: Value =
        serde_json::from_slice(&std::fs::read(host.record()).expect("the record was written"))
            .expect("the record is JSON");
    assert_eq!(
        record["path"],
        host.definition().display().to_string(),
        "the record names the definition: {record}"
    );

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let daemon = host
        .daemon()
        .expect("the service manager reports the daemon it started");

    // A diagnostic that did not pass makes the command's status a failure, and the document it
    // printed is still the whole report.
    let reported = |what: &str| {
        let output = start(host.kr(&["--json", "doctor"])).finish(what);
        document(&output, what)
    };
    let report = reported("kr doctor");
    let row = report["configuration"]["values"]
        .as_array()
        .and_then(|values| {
            values
                .iter()
                .find(|value| value["key"] == "startup.controller")
                .cloned()
        })
        .unwrap_or_else(|| panic!("kr doctor reports the startup: {report}"));
    assert_eq!(row["value"], "service", "{row}");
    assert_eq!(row["source"], "host_configuration", "{row}");
    let check = report["doctor"]["checks"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["id"] == "startup-definition")
                .cloned()
        })
        .unwrap_or_else(|| panic!("kr doctor reports the definition: {report}"));
    assert_eq!(check["status"], "ok", "{check}");

    let cleared =
        start(host.kr(&["--json", "host", "startup", "--clear"])).finish("kr host startup");
    let none = document(&cleared, "kr host startup");
    assert!(cleared.status.success(), "{none}");
    assert_eq!(none["startup"]["controller"], Value::Null, "{none}");
    let removed: Vec<&str> = none["removed"]
        .as_array()
        .unwrap_or_else(|| panic!("the clear says what it removed: {none}"))
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for path in [host.definition(), host.record()] {
        assert!(
            removed.contains(&path.display().to_string().as_str()),
            "{} is among what the clear removed: {none}",
            path.display()
        );
        assert!(!path.exists(), "{} is gone", path.display());
    }
    assert!(host.answers(), "and the daemon keeps serving");
    assert_eq!(
        host.daemon(),
        Some(daemon),
        "the same daemon, which nothing ended"
    );
    let listed = start(host.kr(&["--json", "list"])).finish("kr list");
    assert!(
        listed.status.success(),
        "a command reaches it: {}",
        String::from_utf8_lossy(&listed.stdout)
    );

    let report = reported("kr doctor after the clear");
    let row = report["configuration"]["values"]
        .as_array()
        .and_then(|values| {
            values
                .iter()
                .find(|value| value["key"] == "startup.controller")
                .cloned()
        })
        .unwrap_or_else(|| panic!("kr doctor reports the startup: {report}"));
    assert_eq!(row["value"], "none", "{row}");
    assert_eq!(row["source"], "default", "{row}");
    assert!(
        report["doctor"]["checks"]
            .as_array()
            .is_some_and(|checks| checks
                .iter()
                .all(|check| check["id"] != "startup-definition")),
        "and no definition is left to report: {report}"
    );
    host.close(&created);
}

/// KR-REQ-07.12, KR-REQ-26.04: a definition kr did not write, under the label this environment's
/// daemon would have, is refused and left exactly as it was: nothing is recorded, the choice is not
/// made, and the manager is asked to load or start nothing under that label.
#[test]
fn a_foreign_definition_under_the_same_label_is_refused_and_left_as_it_was() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    let foreign = b"# another program's definition, under the label this environment would use\n";
    std::fs::create_dir_all(host.definition().parent().expect("a directory"))
        .expect("the directory definitions live in");
    std::fs::write(host.definition(), foreign).expect("writes a foreign definition");

    let output = start(host.kr(&["--json", "host", "startup", "--set", "service"]))
        .finish("kr host startup");
    let refused = document(&output, "kr host startup");
    assert_eq!(output.status.code(), Some(2), "refused: {refused}");
    let message = refused["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&host.definition().display().to_string())
            && message.contains("did not write"),
        "the refusal names the definition and whose it is not: {message}"
    );
    assert_eq!(
        std::fs::read(host.definition()).expect("the foreign definition"),
        foreign,
        "the definition is left exactly as it was"
    );
    assert!(!host.record().exists(), "nothing was recorded");
    assert!(!host.document().exists(), "and the choice was not made");
    assert_eq!(
        host.daemon(),
        None,
        "and nothing was started under the label"
    );
    assert!(!host.answers());
}

/// KR-REQ-07.12: with the service start chosen, a definition that was changed after kr wrote it, or
/// that has gone, stops `kr new` with a failure that names it and the setup action. The command
/// replaces nothing and starts nothing.
#[test]
fn a_definition_that_was_changed_or_has_gone_is_named_and_never_replaced() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let mut changed = std::fs::read(host.definition()).expect("the definition");
    changed.extend_from_slice(b"\n");
    std::fs::write(host.definition(), &changed).expect("changes the definition");

    let output = start(host.new_session()).finish("kr new with the definition changed");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("changed") && message.contains("kr host startup --set service"),
        "the failure names what is wrong and what to do about it: {message}"
    );
    assert_eq!(
        std::fs::read(host.definition()).expect("the definition"),
        changed,
        "the changed definition was not replaced"
    );

    std::fs::remove_file(host.definition()).expect("removes the definition");
    let output = start(host.new_session()).finish("kr new with the definition gone");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("missing") && message.contains("kr host startup --set service"),
        "the failure names what is wrong and what to do about it: {message}"
    );
    assert!(
        !host.definition().exists(),
        "and nothing was written in its place"
    );
    assert_eq!(host.daemon(), None, "nothing was started");
    assert!(!host.answers());
}

/// KR-REQ-07.12: the service start is chosen and used on a host where no daemon has ever run.
///
/// Such a host has the environment's identity and none of the environment's directories.
/// `kr host startup --set service` makes the directories the record lives in, writes and records the
/// definition, and `kr new` then has the manager start the daemon and creates its session.
#[test]
fn the_service_start_is_chosen_and_used_where_no_daemon_has_ever_run() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    std::fs::remove_dir_all(host.tree.paths().runtime_root()).expect("no runtime tree");
    std::fs::remove_dir_all(host.tree.paths().state_root().join("environments"))
        .expect("no environment directories");

    host.select_service();
    assert!(host.record().is_file(), "the record was written");
    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(created["state"], "live", "{created}");
    host.assert_started_by_the_manager(
        host.daemon()
            .expect("the service manager reports the daemon it started"),
    );
    host.close(&created);
}

/// KR-REQ-07.12: a service manager holding anything but the definition kr wrote is not asked to
/// start it, and kr does not change what it holds either.
///
/// The file is exactly what kr wrote, and the manager holds something else under its label: on
/// macOS launchd holds the job with an argument added, and on Linux the user manager reads a
/// drop-in of the unit's own that runs another command. `kr new` names what the manager holds and
/// the setup action, and nothing is started. The setup names the same thing and its remedy, which
/// is the person's to apply, and changes nothing in the manager. Once the person has applied it,
/// the setup has the manager take the definition, and `kr new` goes on.
#[test]
fn a_manager_holding_anything_but_the_definition_kr_wrote_is_not_asked_to_start_it() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    let chosen = host.select_service();
    let written = std::fs::read(host.definition()).expect("the definition");
    #[cfg(target_os = "macos")]
    {
        let domain = chosen["startup"]["definition"]["domain"]
            .as_str()
            .expect("a domain")
            .to_owned();
        let target = format!("{domain}/{}", host.label());
        let launchctl = |arguments: &[&str]| {
            let mut command = Command::new("/bin/launchctl");
            command.args(arguments);
            let answer = bounded(command, STREAMS_DEADLINE).expect("launchctl answers");
            assert!(
                answer.status.success(),
                "launchctl {arguments:?}: {}",
                String::from_utf8_lossy(&answer.stderr)
            );
        };
        let other = String::from_utf8(written.clone())
            .expect("text")
            .replacen(
                "\t\t<string>--runtime-dir</string>",
                "\t\t<string>--worker</string>\n\t\t<string>/usr/bin/false</string>\n\t\t<string>--runtime-dir</string>",
                1,
            );
        launchctl(&["bootout", &target]);
        std::fs::write(host.definition(), other).expect("another form");
        let path = host.definition().display().to_string();
        launchctl(&["bootstrap", &domain, &path]);
        // The file is kr's again, and launchd still holds the other form.
        std::fs::write(host.definition(), &written).expect("the definition kr wrote");
    }
    #[cfg(target_os = "linux")]
    {
        let _ = &chosen;
        let drop_ins = host
            .definition()
            .with_file_name(format!("{}.service.d", host.label()));
        std::fs::create_dir_all(&drop_ins).expect("a drop-in directory");
        std::fs::write(
            drop_ins.join("override.conf"),
            "[Service]\nExecStart=\nExecStart=/bin/true\n",
        )
        .expect("a drop-in");
        host.reload();
    }

    let output = start(host.new_session()).finish("kr new");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("kr host startup --set service"),
        "the failure names what the manager holds and the setup action: {message}"
    );
    assert_eq!(host.daemon(), None, "nothing was started");
    assert!(!host.answers());
    assert_eq!(
        std::fs::read(host.definition()).expect("the definition"),
        written,
        "and the definition kr wrote was not touched"
    );

    let refused = start(host.kr(&["--json", "host", "startup", "--set", "service"]))
        .finish("kr host startup while the manager holds another form");
    let refusal = document(&refused, "kr host startup");
    assert_ne!(refused.status.code(), Some(0), "{refusal}");
    let message = refusal["message"].as_str().unwrap_or_default();
    #[cfg(target_os = "macos")]
    {
        let domain = chosen["startup"]["definition"]["domain"]
            .as_str()
            .expect("a domain");
        let target = format!("{domain}/{}", host.label());
        assert!(
            message.contains(&format!("launchctl bootout {target}")),
            "the setup names the remedy and leaves it to the person: {message}"
        );
        // Still the other form: the setup did not replace it.
        let mut print = Command::new("/bin/launchctl");
        print.args(["print", &target]);
        let printed = bounded(print, STREAMS_DEADLINE).expect("launchctl answers");
        assert!(
            String::from_utf8_lossy(&printed.stdout).contains("/usr/bin/false"),
            "launchd still holds the other form"
        );
        let mut bootout = Command::new("/bin/launchctl");
        bootout.args(["bootout", &target]);
        let removed = bounded(bootout, STREAMS_DEADLINE).expect("launchctl answers");
        assert!(removed.status.success(), "the person removes it");
    }
    #[cfg(target_os = "linux")]
    {
        let drop_ins = host
            .definition()
            .with_file_name(format!("{}.service.d", host.label()));
        assert!(
            message.contains("one of them sets ExecStart")
                && message.contains(&format!(
                    "systemctl --user cat {}.service shows",
                    host.label()
                )),
            "the setup says what the drop-in sets and where the person sees it: {message}"
        );
        assert!(
            !message.contains("override.conf") && !message.contains("/bin/true"),
            "and repeats neither its name nor what it holds: {message}"
        );
        std::fs::remove_dir_all(drop_ins).expect("the person removes the drop-in");
    }
    host.select_service();
    let output = start(host.new_session()).finish("kr new once the setup ran again");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host.close(&created);
}

/// KR-REQ-07.12: on Linux no drop-in changes the command the user manager runs for the daemon,
/// wherever the drop-in is: in the directory every service reads, or in the unit's own directory
/// reached through a link to a directory that is also named `service.d`.
///
/// For each, `kr new` names the command the manager would run and the setup action, and nothing
/// is started: the other command leaves a mark when it runs, and there is none. Once the person
/// has removed the drop-in, `kr new` goes on.
#[cfg(target_os = "linux")]
#[test]
fn no_drop_in_anywhere_changes_the_command_the_user_manager_runs() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let units = host
        .definition()
        .parent()
        .expect("the user unit directory")
        .to_path_buf();
    let own = units.join(format!("{}.service.d", host.label()));
    let linked = host.tree.root().join("overrides/service.d");
    let mark = host.tree.root().join("the-other-command-ran");
    for (place, drop_in) in [
        (
            "a drop-in every service reads",
            units.join("service.d/zz-command.conf"),
        ),
        (
            "a drop-in in the unit's own directory, linked to one named service.d",
            linked.join("zz-command.conf"),
        ),
    ] {
        let directory = drop_in.parent().expect("a drop-in directory");
        std::fs::create_dir_all(directory).expect("a drop-in directory");
        std::fs::write(
            &drop_in,
            format!("[Service]\nExecStart=\nExecStart={}\n", touching(&mark)),
        )
        .expect("a drop-in");
        if directory == linked {
            std::os::unix::fs::symlink(&linked, &own).expect("the unit's own directory, linked");
        }
        host.reload();

        let output = start(host.new_session()).finish("kr new");
        let failure = document(&output, "kr new");
        assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{place}: {failure}");
        let message = failure["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("one of them sets ExecStart")
                && message.contains("ExecStartEx with a command kr did not write"),
            "{place}: the failure says the manager would run another command: {message}"
        );
        assert!(
            !message.contains("/usr/bin/touch") && !message.contains("zz-command.conf"),
            "{place}: and repeats neither that command nor the drop-in's name: {message}"
        );
        assert!(
            message.contains("kr host startup --set service"),
            "{place}: and the setup action: {message}"
        );
        assert!(!mark.exists(), "{place}: the other command never ran");
        assert_eq!(host.daemon(), None, "{place}: nothing was started");
        assert!(!host.answers(), "{place}: nothing answers");

        std::fs::remove_file(&drop_in).expect("the person removes the drop-in");
        if own.is_symlink() {
            std::fs::remove_file(&own).expect("and the link");
        }
        host.reload();
    }

    let output = start(host.new_session()).finish("kr new once the drop-ins are gone");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host.close(&created);
}

/// KR-REQ-07.12: on Linux every question kr puts to the user manager and every request it makes
/// go through `systemctl --user` from the same environment, so the manager whose definition kr
/// checked is the manager it asks to start the daemon.
///
/// Two managers are reachable. The test's own, named by the runtime directory, holds the
/// definition kr wrote. A second one holds another unit under the same name whose command leaves a
/// mark, and is reachable over the message bus its own `dbus.socket` starts. With
/// `SYSTEMCTL_FORCE_BUS=1` and that bus named, `systemctl` reaches the second manager for every
/// call: kr checks what that manager holds, refuses it, and asks nothing to start, so the mark never
/// appears. Without them, the test's own manager starts the daemon.
#[cfg(target_os = "linux")]
#[test]
fn the_user_manager_kr_checks_is_the_one_it_asks() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let other_home = host.tree.root().join("other-home");
    let other_units = other_home.join(".config/systemd/user");
    std::fs::create_dir_all(&other_units).expect("the other manager's unit directory");
    let mark = host.tree.root().join("the-other-manager-ran-its-unit");
    let other_unit = other_units.join(format!("{}.service", host.label()));
    std::fs::write(
        &other_unit,
        format!("[Service]\nType=exec\nExecStart={}\n", touching(&mark)),
    )
    .expect("another unit under the same name");
    let other = UserManager::start(&other_home, host.tree.holder()).and_then(|other| {
        // A manager that has only just come up answers late when the machine is busy, and
        // `systemctl` gives up on a bus that is slow to answer by itself. The start is therefore
        // asked again until the bound, each call given what is left of it (and never less than
        // the time a call that answers needs): only a manager that has not started its bus socket
        // by then is one that cannot.
        let asking_until = Instant::now() + TEARDOWN_BOUND;
        loop {
            let left = asking_until.saturating_duration_since(Instant::now());
            let failed = match bounded(
                other.systemctl(&["start", "dbus.socket"]),
                left.max(STREAMS_DEADLINE),
            ) {
                Ok(started) if started.status.success() => return Ok(other),
                Ok(started) => format!(
                    "its dbus.socket did not start: {}",
                    String::from_utf8_lossy(&started.stderr).trim()
                ),
                Err(why) => why,
            };
            if Instant::now() >= asking_until {
                return Err(failed);
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
    let other = match other {
        Ok(other) => other,
        Err(why) => {
            assert!(
                std::env::var_os(REQUIRE_SERVICE_MANAGER).is_none(),
                "a second manager with a bus of its own could not be started: {why}"
            );
            eprintln!("the manager choice is not tested here: {why}");
            return;
        }
    };
    let bus = bus_address(&other.runtime.join("bus"));
    let over_the_bus = |command: &mut Command| {
        command
            .env("SYSTEMCTL_FORCE_BUS", "1")
            .env("DBUS_SESSION_BUS_ADDRESS", &bus);
    };
    // The second manager answers on its bus before kr is pointed there.
    let begun = Instant::now();
    loop {
        let mut asked = Command::new("systemctl");
        asked.args(["--user", "show", "--property=Version", "--value"]);
        over_the_bus(&mut asked);
        if bounded(asked, STREAMS_DEADLINE).is_ok_and(|answer| answer.status.success()) {
            break;
        }
        assert!(
            begun.elapsed() < LIVENESS_DEADLINE,
            "the second manager did not answer on its bus"
        );
        std::thread::sleep(Duration::from_millis(100));
    }

    let mut elsewhere = host.new_session();
    over_the_bus(&mut elsewhere);
    let output = start(elsewhere).finish("kr new pointed at the other manager");
    let failure = document(&output, "kr new");
    assert_eq!(failure["code"], "HOST_NOT_CONFIGURED", "{failure}");
    let message = failure["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("from a file other than the definition kr wrote"),
        "the failure says the other manager holds another file: {message}"
    );
    assert!(
        !message.contains(&other_unit.display().to_string()),
        "and does not repeat the file the other manager names: {message}"
    );
    assert!(
        !mark.exists(),
        "the other manager was asked to start nothing"
    );
    assert_eq!(host.daemon(), None, "and the test's own started nothing");
    assert!(!host.answers(), "nothing answers");

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host.assert_started_by_the_manager(
        host.daemon()
            .expect("the test's own manager reports the daemon it started"),
    );
    assert!(!mark.exists(), "and the other manager still ran nothing");
    host.close(&created);
    drop(other);
}

/// KR-REQ-07.12: on Linux a drop-in that sets the daemon's command is refused even when the
/// manager prints the command exactly as kr wrote it. The drop-in keeps kr's program and words
/// and only joins two of them into one, which `systemctl show` prints the same way, so it is the
/// drop-in itself that is read: the command comes from kr's own file or not at all.
#[cfg(target_os = "linux")]
#[test]
fn a_drop_in_that_resplits_the_command_is_refused_though_it_prints_the_same() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let written = std::fs::read_to_string(host.definition()).expect("the definition");
    let command = written
        .lines()
        .find(|line| line.starts_with("ExecStart="))
        .expect("the definition's command");
    let resplit = command.replacen("\"--runtime-dir\" \"", "\"--runtime-dir ", 1);
    assert_ne!(
        resplit, command,
        "the command names its runtime directory: {command}"
    );
    let own = host
        .definition()
        .with_file_name(format!("{}.service.d", host.label()));
    std::fs::create_dir_all(&own).expect("the unit's own drop-in directory");
    let drop_in = own.join("20-resplit.conf");
    // Once as plain lines, and once as systemd also reads it: keys continued onto the next line
    // with a backslash, and lines ended by carriage returns alone.
    let continued = resplit.replacen("ExecStart=", "ExecStart\\\r=", 1);
    for contents in [
        format!("[Service]\nExecStart=\n{resplit}\n"),
        format!("[Service]\rExecStart\\\r=\r{continued}\r"),
    ] {
        std::fs::write(&drop_in, &contents).expect("a drop-in");
        host.reload();

        let output = start(host.new_session()).finish("kr new");
        let failure = document(&output, "kr new");
        assert_eq!(
            failure["code"], "HOST_NOT_CONFIGURED",
            "{contents:?}: {failure}"
        );
        let message = failure["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("one of them sets ExecStart"),
            "{contents:?}: the failure says what the drop-in sets: {message}"
        );
        assert!(
            !message.contains("20-resplit.conf"),
            "{contents:?}: and does not repeat the drop-in's name: {message}"
        );
        assert_eq!(host.daemon(), None, "{contents:?}: nothing was started");
        assert!(!host.answers(), "{contents:?}: nothing answers");
    }
}

/// KR-REQ-07.12: on Linux a drop-in every service reads that leaves commands alone, such as the
/// timeout policy some distributions ship for every user service, is the host's own: the setup
/// names it and `kr new` has the manager start the daemon under it.
#[cfg(target_os = "linux")]
#[test]
fn a_host_wide_timeout_drop_in_is_the_hosts_and_the_daemon_starts_under_it() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    let every_service = host
        .definition()
        .parent()
        .expect("the user unit directory")
        .join("service.d");
    std::fs::create_dir_all(&every_service).expect("the directory every service reads");
    let drop_in = every_service.join("10-timeout-abort.conf");
    std::fs::write(&drop_in, "[Service]\nTimeoutStopFailureMode=abort\n").expect("a drop-in");

    let chosen = host.select_service();
    assert!(
        chosen["notes"]
            .as_array()
            .is_some_and(|notes| notes.iter().any(|note| note
                .as_str()
                .is_some_and(|note| note.contains(&drop_in.display().to_string())))),
        "the setup names the drop-in the manager reads: {chosen}"
    );
    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    host.assert_started_by_the_manager(
        host.daemon()
            .expect("the service manager reports the daemon it started"),
    );
    host.close(&created);
}

/// KR-REQ-07.12: on Linux a drop-in that leaves the command alone is the person's own. `kr host
/// startup --set service` takes the definition and names the drop-in, and `kr new` has the user
/// manager start the daemon under it.
#[cfg(target_os = "linux")]
#[test]
fn a_drop_in_that_leaves_the_command_alone_is_the_persons_and_the_daemon_starts_under_it() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    let own = host
        .definition()
        .with_file_name(format!("{}.service.d", host.label()));
    std::fs::create_dir_all(&own).expect("the unit's own drop-in directory");
    let drop_in = own.join("10-host-policy.conf");
    std::fs::write(
        &drop_in,
        "[Service]\nEnvironment=KR_TEST_HOST_POLICY=kept\n",
    )
    .expect("a drop-in");

    let chosen = host.select_service();
    assert!(
        chosen["notes"]
            .as_array()
            .is_some_and(|notes| notes.iter().any(|note| note
                .as_str()
                .is_some_and(|note| note.contains(&drop_in.display().to_string())))),
        "the setup names the drop-in the manager reads: {chosen}"
    );

    let output = start(host.new_session()).finish("kr new");
    let created = document(&output, "kr new");
    assert!(
        output.status.success(),
        "{created}; it said {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pid = host
        .daemon()
        .expect("the service manager reports the daemon it started");
    host.assert_started_by_the_manager(pid);
    let environment = std::fs::read(format!("/proc/{pid}/environ")).expect("its environment");
    assert!(
        environment
            .split(|byte| *byte == 0)
            .any(|entry| entry == b"KR_TEST_HOST_POLICY=kept"),
        "the manager started the daemon under the person's drop-in"
    );
    host.close(&created);
}

/// KR-REQ-26.04: `--clear` leaves a definition that was changed after kr wrote it, says so, and
/// removes the record, so the file is no longer taken for kr's: the next `--set service` refuses it
/// and leaves it as it is.
#[test]
fn clearing_leaves_a_definition_changed_since_kr_wrote_it() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let mut changed = std::fs::read(host.definition()).expect("the definition");
    changed.extend_from_slice(b"\n");
    std::fs::write(host.definition(), &changed).expect("changes the definition");

    let cleared =
        start(host.kr(&["--json", "host", "startup", "--clear"])).finish("kr host startup");
    let none = document(&cleared, "kr host startup");
    assert!(cleared.status.success(), "{none}");
    let left = none["left"]
        .as_array()
        .unwrap_or_else(|| panic!("the clear says what it left: {none}"));
    assert!(
        left.iter()
            .any(|entry| entry["path"] == host.definition().display().to_string()),
        "the changed definition is among what the clear left: {none}"
    );
    let removed: Vec<&str> = none["removed"]
        .as_array()
        .unwrap_or_else(|| panic!("the clear says what it removed: {none}"))
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(
        removed,
        [host.record().display().to_string().as_str()],
        "only the record: {none}"
    );
    assert_eq!(
        std::fs::read(host.definition()).expect("the definition"),
        changed,
        "left exactly as it was"
    );
    assert!(!host.record().exists());

    let refused = start(host.kr(&["--json", "host", "startup", "--set", "service"]))
        .finish("kr host startup");
    let refusal = document(&refused, "kr host startup");
    assert_eq!(refused.status.code(), Some(2), "{refusal}");
    assert!(
        refusal["message"]
            .as_str()
            .unwrap_or_default()
            .contains("did not write"),
        "{refusal}"
    );
    assert_eq!(
        std::fs::read(host.definition()).expect("the definition"),
        changed,
        "and it is still as it was"
    );
}

/// Ends a process by its identity when the test is over, however it ended.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct EndedWithTheTest(Option<kr_protocol::identity::ProcessStartIdentity>);

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for EndedWithTheTest {
    fn drop(&mut self) {
        if let Some(identity) = self.0.take() {
            let _ = kr_ipc::identity::stop_process(&identity, kr_ipc::identity::Stop::Kill);
        }
    }
}

/// The leaf of a process's control group, as the kernel names it.
#[cfg(target_os = "linux")]
fn control_group_of(pid: u32) -> String {
    let text = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .expect("reads the process's control group");
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .and_then(|path| path.rsplit('/').next())
        .expect("a unified control group")
        .to_owned()
}

/// The leaf of the control group the first environment's session runs its worker in.
#[cfg(target_os = "linux")]
fn control_group_of_worker(host: &ServiceHost, inside: &Inside) -> String {
    control_group_of(u32::try_from(inside.worker(host).pid.get()).expect("a pid"))
}

/// Polls `check` until it gives something, for at most [`LIVENESS_DEADLINE`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn until_there<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let begun = Instant::now();
    loop {
        if let Some(found) = check() {
            return found;
        }
        assert!(
            begun.elapsed() < LIVENESS_DEADLINE,
            "waited {LIVENESS_DEADLINE:?} for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// How the second environment's commands and daemon are set up.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy, Default)]
struct Setup<'a> {
    /// A directory of recording tools they find first on their `PATH`.
    tools: Option<&'a Path>,
    /// Whether they cannot reach the test's user manager.
    #[cfg(target_os = "linux")]
    no_manager: bool,
    /// Whether the daemon waits, as a process of the command that started it, until the test lets
    /// it go.
    hold: bool,
    /// Whether the session's root shell waits for the test before it runs the second `kr new`.
    gate: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl<'a> Setup<'a> {
    #[cfg(target_os = "linux")]
    fn recorded_by(tools: &'a Path) -> Self {
        Self {
            tools: Some(tools),
            ..Self::default()
        }
    }

    fn held() -> Self {
        Self {
            hold: true,
            ..Self::default()
        }
    }

    fn gated() -> Self {
        Self {
            gate: true,
            ..Self::default()
        }
    }

    #[cfg(target_os = "linux")]
    fn without_a_manager(mut self) -> Self {
        self.no_manager = true;
        self
    }
}

/// A second environment, with the standalone start chosen, whose daemon `kr new` starts.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Second {
    tree: teardown::Tree,
    /// Where a held daemon records its number and is let go.
    hold: PathBuf,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Second {
    fn create(host: &ServiceHost) -> Self {
        let tree = teardown::Tree::create();
        kr_ipc::paths::write_owner_only_file(
            &tree.environment().state_dir().join("config.json"),
            br#"{"version": 1, "revision": 1, "startup": {"controller": "standalone"}}"#,
        )
        .expect("writes the second environment's configuration document");
        let hold = host.tree.root().join("hold");
        std::fs::create_dir_all(&hold).expect("a directory for the hold");
        Self { tree, hold }
    }

    /// The whole environment its commands run in.
    fn variables(&self, host: &ServiceHost, setup: Setup<'_>) -> Vec<(String, String)> {
        let mut path = "/usr/bin:/bin".to_owned();
        if let Some(tools) = setup.tools {
            path = format!("{}:{path}", tools.display());
        }
        let mut variables = vec![
            ("PATH".to_owned(), path),
            ("HOME".to_owned(), host.home.display().to_string()),
            (
                kr_ipc::paths::RUNTIME_DIR_VARIABLE.to_owned(),
                self.tree.paths().runtime_root().display().to_string(),
            ),
            (
                kr_ipc::paths::STATE_DIR_VARIABLE.to_owned(),
                self.tree.paths().state_root().display().to_string(),
            ),
        ];
        #[cfg(target_os = "linux")]
        if !setup.no_manager {
            variables.push((
                "XDG_RUNTIME_DIR".to_owned(),
                host.manager.runtime.display().to_string(),
            ));
        }
        if setup.hold {
            variables.push((
                "KR_TEST_HOLD_DIR".to_owned(),
                self.hold.display().to_string(),
            ));
        }
        variables
    }

    /// The second environment's `kr`, run by the test itself.
    #[cfg(target_os = "linux")]
    fn kr(&self, host: &ServiceHost, setup: Setup<'_>, arguments: &[&str]) -> Command {
        let mut command = Command::new(service_installation().join("kr"));
        command
            .args(arguments)
            .env_clear()
            .envs(self.variables(host, setup))
            .current_dir(service_installation())
            .stdin(Stdio::null());
        command
    }

    /// The process the environment's lock names as its daemon, once there is one.
    fn daemon(&self) -> Option<u32> {
        kr_controller::singleton::SingletonLock::holder(&self.tree.environment().singleton_lock())
            .ok()
            .flatten()
    }
}

/// A session of the host's first environment whose root shell runs `kr new` for the second one: the
/// second environment's daemon starts from inside the first worker's job.
///
/// The root shell is a script that runs that `kr new` in the background and then is an ordinary
/// shell. While the daemon is held it prints, so that the worker observes its session often.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Inside {
    session_id: SessionId,
    #[cfg(target_os = "linux")]
    created: Value,
    second: Second,
    said: PathBuf,
}

/// The second environment's daemon, started.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct Started {
    daemon: kr_protocol::identity::ProcessStartIdentity,
    /// The process the second `kr new` said it started.
    #[cfg(target_os = "linux")]
    reported: Option<u32>,
    /// What the second `kr new` said on its standard error.
    #[cfg(target_os = "linux")]
    said: String,
    _ended: EndedWithTheTest,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Inside {
    /// Creates the session. Its shell runs the second `kr new` meanwhile.
    fn begin(host: &ServiceHost, second: Second, setup: Setup<'_>) -> Self {
        let said = host.tree.root().join("inner-new");
        let shell = host.tree.root().join("session-shell");
        let text = host.tree.root().join("session-shell.text");
        let environment: String = second
            .variables(host, setup)
            .iter()
            .map(|(name, value)| format!("{name}='{value}' "))
            .collect();
        let waiting = if setup.hold {
            format!(
                "while [ ! -e '{}/go' ]; do echo .; sleep 0.2; done\n",
                second.hold.display()
            )
        } else {
            String::new()
        };
        let gate = if setup.gate {
            format!(
                "while [ ! -e '{}/start' ]; do sleep 0.05; done\n",
                second.hold.display()
            )
        } else {
            String::new()
        };
        std::fs::write(
            &text,
            format!(
                "#!/bin/sh\n\
                 {gate}\
                 ( env -i {environment}'{kr}' new --invisible --headless --cwd '{cwd}' \
                 --shell /bin/sh --shell-mode native_compat --startup interactive \
                 < /dev/null > '{said}.out' 2> '{said}.err'; \
                 echo $? > '{said}.tmp' && mv '{said}.tmp' '{said}.status' ) &\n\
                 {waiting}\
                 exec /bin/sh \"$@\"\n",
                kr = service_installation().join("kr").display(),
                cwd = second.tree.root().display(),
                said = said.display(),
            ),
        )
        .expect("writes the session's root shell");
        kr_ipc::testing::place_program(&text, &shell);

        let output = start(host.kr(&[
            "--json",
            "new",
            "--shell-mode",
            "native_compat",
            "--invisible",
            "--headless",
            "--cwd",
            &host.tree.root().display().to_string(),
            "--shell",
            &shell.display().to_string(),
            "--startup",
            "interactive",
        ]))
        .finish("kr new");
        let created = document(&output, "kr new");
        assert!(
            output.status.success(),
            "kr new created its session: {created}; it said {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let session_id: SessionId = created["session_id"]
            .as_str()
            .expect("a session identifier")
            .parse()
            .expect("parses");
        Self {
            session_id,
            #[cfg(target_os = "linux")]
            created,
            second,
            said,
        }
    }

    /// The number of the held daemon, once it has recorded it.
    fn daemon_in_hold(&self) -> u32 {
        until_there("the held daemon to record its number", || {
            std::fs::read_to_string(self.second.hold.join("daemon.pid"))
                .ok()?
                .trim()
                .parse()
                .ok()
        })
    }

    /// What the first worker has recorded of its session's processes, read as the control daemon
    /// reads it.
    fn recorded(&self, host: &ServiceHost) -> Option<kr_worker::ownership::OwnedRecord> {
        let journal = kr_worker::journal::Journal::open_read_only(
            host.tree.environment().journal_database(self.session_id),
        )
        .ok()?;
        journal.read_owned(self.session_id).ok().flatten()
    }

    /// Waits until the first worker's record of its session's processes names `pid`.
    fn wait_until_recorded(&self, host: &ServiceHost, pid: u32) {
        until_there("the first worker to record the held daemon", || {
            self.recorded(host)?
                .processes
                .iter()
                .any(|process| process.pid.get() == u64::from(pid))
                .then_some(())
        });
    }

    /// Lets the session's root shell run the second `kr new`.
    fn start(&self) {
        std::fs::write(self.second.hold.join("start"), b"").expect("lets the shell start");
    }

    /// Lets the held daemon go on.
    fn release(&self) {
        std::fs::write(self.second.hold.join("go"), b"").expect("lets the daemon go");
    }

    /// Waits for the second `kr new` to end and the second daemon to answer.
    fn finish(&self) -> Started {
        let status = self.said.with_extension("status");
        let text_of = |extension: &str| {
            std::fs::read_to_string(self.said.with_extension(extension)).unwrap_or_default()
        };
        until_there("the second kr new to end", || status.exists().then_some(()));
        // The second kr new waits for its daemon no longer than its own start bound, which the
        // test cannot lengthen. Where the daemon is held until the first worker has recorded it,
        // that wait includes the recording. A command that ends on the bound ends the case here,
        // and the message names the bound rather than leave it to look like a defect.
        assert!(
            !text_of("err").contains("did not answer within"),
            "precondition: the second kr new gave up waiting for its daemon at its start bound: {}",
            text_of("err")
        );
        assert_eq!(
            text_of("status").trim(),
            "0",
            "the second environment's kr new succeeded: {}; it said {}",
            text_of("out"),
            text_of("err")
        );
        let daemon = self.second.daemon().expect("the lock names the daemon");
        let daemon =
            kr_ipc::identity::process_start_identity(daemon).expect("the daemon's identity");
        let ended = EndedWithTheTest(Some(daemon.clone()));
        assert!(
            answers(&self.second.tree.environment()),
            "the second environment's daemon answers"
        );
        #[cfg(target_os = "linux")]
        let said = text_of("err");
        // "kr: started the control daemon for environment <id> (process <pid>) under the ..."
        #[cfg(target_os = "linux")]
        let reported = said
            .split_once("(process ")
            .and_then(|(_, rest)| rest.split_once(')'))
            .and_then(|(pid, _)| pid.parse().ok());
        Started {
            daemon,
            #[cfg(target_os = "linux")]
            reported,
            #[cfg(target_os = "linux")]
            said,
            _ended: ended,
        }
    }

    /// The worker of the session.
    fn worker(&self, host: &ServiceHost) -> kr_protocol::identity::ProcessStartIdentity {
        let registry = kr_controller::registry::Registry::open(
            host.tree.environment().registry_database(),
            host.tree.environment_id(),
        )
        .expect("opens the first environment's registry");
        registry
            .workers()
            .expect("reads the worker records")
            .into_iter()
            .find(|worker| worker.session_id == self.session_id)
            .expect("the session's worker record")
            .process_identity
    }

    /// Waits until the first daemon has closed the session, and returns its closure.
    fn wait_until_closed(&self, host: &ServiceHost) -> kr_protocol::session::ClosureRecord {
        until_there("the session to be closed", || {
            let listed: SessionListResult = host.ask(
                Method::SessionList,
                &SessionListParams {
                    environment_id: Nullable::some(host.tree.environment_id()),
                    include_closed: true,
                },
            );
            listed
                .sessions
                .into_iter()
                .find(|summary| {
                    summary.session_id == self.session_id
                        && summary.state == kr_protocol::session::SessionState::Closed
                })
                .and_then(|summary| summary.closure.0)
        })
    }
}

/// How the session of a daemon that was started inside it ends.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy)]
enum End {
    /// The worker is killed, having been stopped first so that it observes nothing more: the first
    /// daemon's cleanup works from what the worker last recorded.
    Crash,
    /// The session is closed: the worker observes its session once more as it closes.
    #[cfg(target_os = "linux")]
    Close,
    /// The daemon ends after the worker has read it in its scope, and then the session is closed:
    /// the worker can no longer read the daemon, and has to remember that it left.
    #[cfg(target_os = "linux")]
    CloseAfterItEnded,
}

/// A daemon `kr new` starts from inside a session is still running, and still answers, once that
/// session has ended, however it ended.
///
/// With `recorded` the daemon is held, as a process of the session, until the first worker has
/// recorded it: what the worker records stands for a process of another environment, which the
/// session did not start for itself. Without it the worker is stopped before the second `kr new`
/// runs, so it records nothing more; the daemon is a process of the session's job and nothing else
/// ties it to the session.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn a_daemon_started_from_inside_a_session_outlives_it(recorded: bool, end: End) {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let setup = if recorded {
        Setup::held()
    } else {
        Setup::gated()
    };
    let inside = Inside::begin(&host, Second::create(&host), setup);
    let held = recorded.then(|| inside.daemon_in_hold());
    if let Some(held) = held {
        inside.wait_until_recorded(&host, held);
    }
    let worker = inside.worker(&host);
    #[cfg(target_os = "linux")]
    let service = control_group_of(u32::try_from(worker.pid.get()).expect("a process identifier"));
    if matches!(end, End::Crash) {
        // From here the worker observes nothing, so what its record names is what it names now:
        // the stop is waited for, not assumed from the signal having been sent.
        assert_eq!(
            kr_ipc::identity::process_state(&worker),
            ProcessState::Running
        );
        stop_the_worker(&worker);
    }
    if recorded {
        inside.release();
    } else {
        inside.start();
    }
    let started = inside.finish();
    if let Some(held) = held {
        assert_eq!(
            started.daemon.pid.get(),
            u64::from(held),
            "the held process is the daemon"
        );
    }
    // What the worker has recorded when the session ends: the daemon if it was held until
    // recorded, and not if the worker was stopped before the daemon was started.
    if matches!(end, End::Crash) {
        let record = inside.recorded(&host).expect("the worker's record");
        assert_eq!(
            record.processes.contains(&started.daemon),
            recorded,
            "the worker's record names the daemon exactly when it was held until recorded: \
             {record:?}"
        );
    }
    #[cfg(target_os = "linux")]
    if matches!(end, End::CloseAfterItEnded) {
        // The worker has read the daemon in its scope once it no longer records it: the next
        // observation moved it out. Then the daemon ends, with nothing left to read it by.
        until_there("the worker to stop recording the daemon", || {
            (!inside.recorded(&host)?.processes.contains(&started.daemon)).then_some(())
        });
        assert!(
            matches!(
                kr_ipc::identity::stop_process(&started.daemon, kr_ipc::identity::Stop::Kill),
                kr_ipc::identity::Stopped::Signalled
            ),
            "the daemon is ended"
        );
        until_there("the daemon to end", || {
            (kr_ipc::identity::process_state(&started.daemon) == ProcessState::Ended).then_some(())
        });
    }
    match end {
        End::Crash => assert!(
            matches!(
                kr_ipc::identity::stop_process(&worker, kr_ipc::identity::Stop::Kill),
                kr_ipc::identity::Stopped::Signalled
            ),
            "the worker is killed"
        ),
        #[cfg(target_os = "linux")]
        End::Close | End::CloseAfterItEnded => host.close(&inside.created),
    }
    let closure = inside.wait_until_closed(&host);
    // On Linux the manager drops a service once nothing is left in it, so its being gone is the
    // cleanup being over, whether the service held the daemon or not.
    #[cfg(target_os = "linux")]
    until_there("the manager to drop the session's service", || {
        let shown = bounded(
            host.manager
                .systemctl(&["show", "--property=LoadState", "--value", &service]),
            STREAMS_DEADLINE,
        )
        .expect("asks the manager");
        (String::from_utf8_lossy(&shown.stdout).trim() == "not-found").then_some(())
    });
    // Ended on purpose, the daemon of the last case is gone; the others go on running.
    #[cfg(target_os = "linux")]
    let ended_on_purpose = matches!(end, End::CloseAfterItEnded);
    #[cfg(not(target_os = "linux"))]
    let ended_on_purpose = false;
    if !ended_on_purpose {
        assert_eq!(
            kr_ipc::identity::process_state(&started.daemon),
            ProcessState::Running,
            "the second environment's daemon is still running once the first session is over"
        );
        assert!(
            answers(&inside.second.tree.environment()),
            "and still answers"
        );
    }
    // The closure does not count the daemon among the session's processes, ended or surviving.
    let pid = started.daemon.pid.get();
    assert!(
        closure
            .terminated
            .iter()
            .all(|process| process.identity.pid.get() != pid),
        "the closure does not say it ended the daemon: {closure:?}"
    );
    assert!(
        closure
            .surviving
            .iter()
            .all(|resource| resource.kind != "process"
                || !resource.detail.contains(&format!("process {pid} "))),
        "and does not name it a survivor of the session: {closure:?}"
    );
    // A daemon the worker had recorded is named for what it is: not the session's, and left
    // running. One it never recorded is not mentioned.
    assert_eq!(
        closure
            .surviving
            .iter()
            .filter(
                |resource| resource.kind == kr_worker::ownership::LEFT_FOR_A_DAEMON
                    && resource.detail.contains(&format!("process {pid} "))
            )
            .count(),
        usize::from(recorded && !ended_on_purpose),
        "{closure:?}"
    );
    #[cfg(target_os = "linux")]
    if matches!(end, End::Crash) {
        assert_eq!(
            closure.ownership_coverage,
            kr_protocol::session::OwnershipCoverage::Complete,
            "the service's control group was read empty, and the daemon had left it: {closure:?}"
        );
    }
}

/// Stops the worker where it is, without ending it, and waits until it runs nothing.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stop_the_worker(worker: &kr_protocol::identity::ProcessStartIdentity) {
    let pid = rustix::process::Pid::from_raw(i32::try_from(worker.pid.get()).expect("a pid"))
        .expect("a process number");
    rustix::process::kill_process(pid, rustix::process::Signal::STOP).expect("stops it");
    until_there("the worker to stop", || {
        #[cfg(target_os = "linux")]
        {
            // Every thread of the worker is stopped, not only the one the signal found first.
            let threads = std::fs::read_dir(format!("/proc/{}/task", worker.pid.get())).ok()?;
            threads
                .flatten()
                .all(|thread| {
                    std::fs::read_to_string(thread.path().join("stat"))
                        .ok()
                        .and_then(|stat| {
                            stat.rsplit_once(')').and_then(|(_, rest)| {
                                rest.split_whitespace().next().map(str::to_owned)
                            })
                        })
                        .is_some_and(|state| state == "T" || state == "t")
                })
                .then_some(())
        }
        #[cfg(target_os = "macos")]
        {
            let state = spawning(|| {
                Command::new("/bin/ps")
                    .args(["-o", "state=", "-p", &worker.pid.get().to_string()])
                    .output()
            })
            .ok()?;
            String::from_utf8_lossy(&state.stdout)
                .trim()
                .starts_with('T')
                .then_some(())
        }
    });
}

/// KR-REQ-07.12, KR-REQ-07.66: a control daemon that `kr new` starts from inside a session, which
/// the session's worker has not recorded, is not ended by the crash of that worker.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn a_daemon_started_from_inside_a_session_outlives_the_crash_of_its_worker() {
    a_daemon_started_from_inside_a_session_outlives_it(false, End::Crash);
}

/// KR-REQ-07.12, KR-REQ-07.66: a control daemon that `kr new` starts from inside a session, and
/// that the worker has recorded among the session's processes, is not ended by the crash of that
/// worker.
#[cfg(target_os = "linux")]
#[test]
fn a_daemon_the_worker_recorded_outlives_the_crash_of_its_worker() {
    a_daemon_started_from_inside_a_session_outlives_it(true, End::Crash);
}

/// KR-REQ-07.12, KR-REQ-07.66: a control daemon that `kr new` starts from inside a session, and
/// that the worker has recorded among the session's processes, is not ended when the session is
/// closed.
#[cfg(target_os = "linux")]
#[test]
fn a_daemon_the_worker_recorded_outlives_the_close_of_its_session() {
    a_daemon_started_from_inside_a_session_outlives_it(true, End::Close);
}

/// KR-REQ-07.12, KR-REQ-07.66: a daemon the worker read in its own scope and that ends before the
/// session is closed is not a process the session ended: the worker remembers that it left.
#[cfg(target_os = "linux")]
#[test]
fn a_daemon_that_left_and_ended_before_the_session_closed_is_not_one_the_session_ended() {
    a_daemon_started_from_inside_a_session_outlives_it(true, End::CloseAfterItEnded);
}

/// KR-REQ-07.12, KR-REQ-07.13: a daemon `kr new` starts from inside a service this host started
/// asks the user's service manager for one transient scope, for itself, and for nothing else in
/// starting; it is the same process `kr new` started, now in a control group of its own.
///
/// The second environment's commands find recording tools first on their `PATH`, which record the
/// call and go on to the real tool. Every call the daemon made is on the allow-list for a daemon
/// started inside a service that has a manager, the scope is the first of its calls to `systemd-run`
/// and is made by the daemon's own process, and the process `kr new` says it started is the one the
/// environment's lock names and the one that answers.
#[cfg(target_os = "linux")]
#[test]
fn a_daemon_started_inside_a_service_asks_for_one_scope_and_is_the_process_kr_started() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let calls = host.tree.root().join("tool-calls");
    let tools = host.tree.root().join("tools");
    recording_tools(&tools, &calls, &["systemctl", "systemd-run", "loginctl"]);
    let setup = Setup::recorded_by(&tools);
    let inside = Inside::begin(&host, Second::create(&host), setup);
    let started = inside.finish();

    let daemon = u32::try_from(started.daemon.pid.get()).expect("a pid");
    assert_eq!(
        started.reported,
        Some(daemon),
        "kr new says it started the process that serves the environment: {}",
        started.said
    );
    let program = service_installation().join("daemon").join("kr-controller");
    let worker_program = service_installation().join("daemon").join("kr-worker");
    let recorded = recorded_calls(&calls);
    let allowance = Allowance {
        scope_for: Some(&program),
        no_expansion: systemd_run_stops_expansion(),
        workers: Some(&worker_program),
    };
    for call in &recorded {
        if let Err(refused) = allowed(call, &[daemon], allowance) {
            panic!("{refused}; everything recorded: {recorded:?}");
        }
    }
    // What the daemon starts, apart from the version it reads of the tool it runs: the scope is
    // the first, it is the only one, and the daemon's own process asks for it; then the one worker
    // of the one session its `kr new` created.
    let launches: Vec<&Recorded> = recorded
        .iter()
        .filter(|call| call.tool == "systemd-run" && call.arguments != ["--version"])
        .collect();
    let is_scope = |call: &&Recorded| call.arguments.iter().any(|argument| argument == "--scope");
    assert_eq!(
        launches.iter().filter(|call| is_scope(call)).count(),
        1,
        "one scope was asked for: {recorded:?}"
    );
    assert!(
        is_scope(&launches[0]) && launches[0].pid == daemon,
        "the first thing started is the scope, asked for by the daemon's own process: {recorded:?}"
    );
    assert_eq!(
        launches.len(),
        2,
        "and the one worker of the one session: {recorded:?}"
    );
    // The manager is asked about the service the daemon is in before the scope is: the first
    // environment's worker, whose service the second `kr new` ran in.
    let service = control_group_of_worker(&host, &inside);
    let asked = recorded
        .iter()
        .position(|call| {
            call.tool == "systemctl"
                && call
                    .arguments
                    .iter()
                    .any(|argument| argument == "--property=ControlGroup")
                && call.arguments.last().map(String::as_str) == Some(service.as_str())
        })
        .unwrap_or_else(|| panic!("the manager is asked about {service}: {recorded:?}"));
    let scoped = recorded
        .iter()
        .position(|call| std::ptr::eq(call, launches[0]))
        .expect("the scope is recorded");
    assert!(
        asked < scoped,
        "and asked before the scope is: {recorded:?}"
    );
    let group = control_group_of(daemon);
    assert!(
        group.starts_with("kr-daemon-") && group.ends_with(".scope"),
        "the daemon runs in the scope: {group}"
    );
    // A daemon in a scope of its own has nothing to say about where it runs.
    let output = start(inside.second.kr(&host, setup, &["--json", "doctor"])).finish("kr doctor");
    let report = document(&output, "kr doctor");
    assert!(
        report["doctor"]["checks"]
            .as_array()
            .is_some_and(|checks| checks
                .iter()
                .all(|check| check["id"] != "daemon-control-group")),
        "the doctor names no control group: {report}"
    );
}

/// KR-REQ-07.12, KR-REQ-07.13, KR-REQ-26.13: where the user's service manager does not answer, a
/// daemon `kr new` starts from inside a service this host started starts as it always did, in that
/// service's control group, and `kr doctor` says so.
///
/// The second environment's commands cannot reach a manager, so the real tools fail as they do on
/// a host without one. The daemon asks, is refused, asks for no scope and stays where it started.
#[cfg(target_os = "linux")]
#[test]
fn a_daemon_that_cannot_leave_the_service_it_started_in_is_named_by_the_doctor() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let calls = host.tree.root().join("tool-calls");
    let tools = host.tree.root().join("tools");
    recording_tools(&tools, &calls, &["systemctl", "systemd-run", "loginctl"]);
    let second = Second::create(&host);
    let setup = Setup::recorded_by(&tools).without_a_manager();
    let inside = Inside::begin(&host, second, setup);
    let started = inside.finish();

    let daemon = u32::try_from(started.daemon.pid.get()).expect("a pid");
    let program = service_installation().join("daemon").join("kr-controller");
    let recorded = recorded_calls(&calls);
    for call in &recorded {
        let allowance = Allowance {
            scope_for: Some(&program),
            no_expansion: systemd_run_stops_expansion(),
            workers: None,
        };
        if let Err(refused) = allowed(call, &[daemon], allowance) {
            panic!("{refused}; everything recorded: {recorded:?}");
        }
    }
    assert!(
        recorded.iter().all(|call| call.tool != "systemd-run"),
        "a manager that does not answer is asked for nothing: {recorded:?}"
    );
    // Its session's shell is in the group the worker made below its service, and a process it
    // starts is in that group: the service's all the same, which a manager that answered would
    // have the daemon leave.
    let group = std::fs::read_to_string(format!("/proc/{daemon}/cgroup"))
        .expect("reads the daemon's control group");
    assert!(
        group.contains("/kr-worker-") && group.trim().ends_with(".service/session"),
        "the daemon stays in the service it started in: {group}"
    );

    let output = start(inside.second.kr(&host, setup, &["--json", "doctor"])).finish("kr doctor");
    let report = document(&output, "kr doctor");
    let check = report["doctor"]["checks"]
        .as_array()
        .and_then(|checks| {
            checks
                .iter()
                .find(|check| check["id"] == "daemon-control-group")
        })
        .unwrap_or_else(|| panic!("the doctor names the daemon's control group: {report}"));
    assert_eq!(check["status"], "warning", "{check}");
}

/// KR-REQ-07.12, KR-REQ-07.13: a daemon `kr new` starts anywhere but inside a service this host
/// started asks for no scope: the rule takes it only from there.
///
/// The recording tools go on to the real ones and a manager answers, so a daemon that took a scope
/// wherever a manager answers would be seen taking it.
#[cfg(target_os = "linux")]
#[test]
fn a_daemon_started_outside_a_service_asks_for_no_scope() {
    let Some(host) = ServiceHost::create() else {
        return;
    };
    host.select_service();
    let calls = host.tree.root().join("tool-calls");
    let tools = host.tree.root().join("tools");
    recording_tools(&tools, &calls, &["systemctl", "systemd-run", "loginctl"]);
    let second = Second::create(&host);
    let setup = Setup::recorded_by(&tools);
    let cwd = second.tree.root().display().to_string();
    let output = start(second.kr(
        &host,
        setup,
        &[
            "--json",
            "new",
            "--shell-mode",
            "native_compat",
            "--invisible",
            "--headless",
            "--cwd",
            &cwd,
            "--shell",
            "/bin/sh",
            "--startup",
            "interactive",
        ],
    ))
    .finish("kr new");
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let daemon = second.daemon().expect("the lock names the daemon");
    let _ended = EndedWithTheTest(Some(
        kr_ipc::identity::process_start_identity(daemon).expect("the daemon's identity"),
    ));
    let worker_program = service_installation().join("daemon").join("kr-worker");
    let recorded = recorded_calls(&calls);
    for call in &recorded {
        let allowance = Allowance {
            scope_for: None,
            no_expansion: false,
            workers: Some(&worker_program),
        };
        if let Err(refused) = allowed(call, &[daemon], allowance) {
            panic!("{refused}; everything recorded: {recorded:?}");
        }
    }
    assert_eq!(
        recorded
            .iter()
            .filter(|call| call.tool == "systemd-run" && call.arguments != ["--version"])
            .count(),
        1,
        "what it started is the one worker of the one session its kr new created: {recorded:?}"
    );
    assert!(
        !control_group_of(daemon).starts_with("kr-daemon-"),
        "and the daemon is not in a scope of its own"
    );
}

// -------------------------------------------------------------------------------------------------
// `kr host stop`
// -------------------------------------------------------------------------------------------------

/// A terminal attached to a session on its worker's own endpoint, that types into the session and
/// reads what it shows, with the daemon in the middle or not there at all.
struct Typing {
    client: LocalClient,
    session_id: SessionId,
    attachment_id: AttachmentId,
    epoch: Option<kr_protocol::ids::InputLeaseEpoch>,
    sequence: u64,
    seen: String,
}

impl Typing {
    async fn attach(host: &Standalone, session_id: SessionId, keys: bool) -> Self {
        let descriptor = kr_ipc::descriptor::read_all(&host.tree.environment())
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
            .expect("the worker answers its descriptor's challenge");
        let target = ActionTarget {
            environment_id: descriptor.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        };
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(Dimensions::new(120, 40)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the attach succeeds")
            .to_typed()
            .expect("decodes");
        let attachment_id = attached.attachment.attachment_id;
        let epoch = if keys {
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
                .expect("the lease is acquired")
                .to_typed()
                .expect("decodes");
            Some(lease.lease.epoch)
        } else {
            None
        };
        let mut streams = CanonicalSet::new();
        streams.insert(kr_protocol::recovery::EventStream::Output);
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
            epoch,
            sequence: 0,
            seen: String::new(),
        }
    }

    /// Types one line into the session, under this terminal's lease.
    async fn type_line(&mut self, line: &str) {
        let epoch = self.epoch.expect("this terminal holds the keys");
        self.client
            .request(
                Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    epoch,
                    sequence: kr_protocol::ids::InputSequence::new(self.sequence),
                    input: kr_protocol::input::InputContent::Bytes {
                        bytes: kr_protocol::scalars::Bytes::new(format!("{line}\n").into_bytes()),
                    },
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker takes the line");
        self.sequence += 1;
    }

    /// Reads until `marker` has reached this terminal.
    async fn shown(&mut self, marker: &str) {
        use kr_protocol::envelope::ControlFrame;

        let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
        while !self.seen.contains(marker) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.client.recv()).await {
                Ok(Ok(ControlFrame::Notification(notification)))
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
                    "waited for {marker:?} and the connection ended ({error}): {:?}",
                    self.seen
                ),
                Err(_) => panic!("waited for {marker:?}: {:?}", self.seen),
            }
        }
    }
}

/// A host with a daemon and one live session, the daemon's process and the session, or none where
/// this run did not ask for the account's own launchd.
fn a_host_with_a_session() -> Option<(Standalone, SessionId, Value, u32)> {
    let host = Standalone::create()?;
    host.select_standalone();
    let output = host.finish_through_a_slow_start("kr new", || host.new_session());
    let created = document(&output, "kr new");
    assert!(output.status.success(), "{created}");
    let session_id: SessionId = created["session_id"]
        .as_str()
        .expect("a session identifier")
        .parse()
        .expect("parses");
    let daemon = host.one_daemon();
    Some((host, session_id, created, daemon))
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}

/// What `kr host stop` keeps apart in its result.
fn stop_of(document: &Value) -> &str {
    document["stop"].as_str().expect("a stop member")
}

/// Whether anything holds the environment's singleton lock.
fn lock_is_held(host: &Standalone) -> bool {
    let environment = host.tree.environment();
    matches!(
        kr_controller::singleton::SingletonLock::hold(
            &environment.singleton_lock(),
            host.tree.environment_id()
        ),
        Err(kr_controller::ControllerError::AlreadyRunning { .. })
    )
}

/// The record each attempt keeps, as the next command reads it.
fn attempts(host: &Standalone) -> Vec<kr_controller::attempt::Recorded> {
    kr_controller::attempt::recorded(&host.tree.environment())
}

/// KR-REQ-02.03, KR-REQ-05.01 (the stop's half): `kr host stop` ends the daemon, and no session goes
/// with it. The daemon's process answered with its number has ended, the endpoint is gone and the
/// lock is free; a terminal attached before the stop goes on reading and writing, the variable the
/// shell was given stands, and a terminal attached after it works with no daemon. The command's
/// own record of the attempt is gone once it has seen the end.
#[test]
fn kr_host_stop_ends_the_daemon_and_no_session_goes_with_it() {
    let Some((host, session_id, _created, daemon)) = a_host_with_a_session() else {
        return;
    };
    let runtime = runtime();
    let mut before = runtime.block_on(async {
        let mut terminal = Typing::attach(&host, session_id, true).await;
        terminal
            .type_line("KR_STOP_KEPT=kept; echo first-$KR_STOP_KEPT")
            .await;
        terminal.shown("first-kept").await;
        terminal
    });

    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let stopped = document(&output, "kr host stop");
    assert!(output.status.success(), "{stopped}");
    assert_eq!(stopped["ok"], true, "{stopped}");
    assert_eq!(stop_of(&stopped), "ended", "{stopped}");
    assert_eq!(
        stopped["pid"].as_u64(),
        Some(u64::from(daemon)),
        "{stopped}"
    );
    assert_eq!(stopped["unsettled"].as_u64(), Some(0), "{stopped}");

    assert!(host.running().is_empty(), "the daemon has ended");
    assert!(!host.answers(), "nothing answers on the endpoint");
    assert!(!lock_is_held(&host), "the environment's lock is free");
    assert!(attempts(&host).is_empty(), "the command removed its record");

    let after = runtime.block_on(async {
        before.type_line("echo second-$KR_STOP_KEPT").await;
        before.shown("second-kept").await;
        // A new attachment, made with no daemon, reads what the session writes next.
        let mut after = Typing::attach(&host, session_id, false).await;
        before.type_line("echo third-$KR_STOP_KEPT").await;
        after.shown("third-kept").await;
        after
    });
    drop((before, after));
}

/// The worker of a session, by the process the descriptor names.
fn worker_of(host: &Standalone, session_id: SessionId) -> u32 {
    let descriptor = kr_ipc::descriptor::read_all(&host.tree.environment())
        .expect("reads the runtime directory")
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .find(|descriptor| descriptor.session_id == session_id)
        .expect("the session's descriptor is published");
    u32::try_from(descriptor.process_start_identity.pid.get()).expect("a process number")
}

/// Sends a signal to a process of this test's own tree, by its number.
fn signal(name: &str, pid: u32) {
    let sent = spawning(|| {
        Command::new("/bin/kill")
            .arg(format!("-{name}"))
            .arg(pid.to_string())
            .status()
    })
    .expect("runs kill");
    assert!(sent.success(), "sends {name} to {pid}");
}

/// KR-REQ-07.58 (the guard): `kr host stop` refuses where the session variables are set, and where
/// a live session's worker says the process is its own, and the daemon that answered before
/// answers after. The worker's word is what the second form shows: the command typed into the
/// session's shell with both variables taken out, as a workflow's shell node would run it, is
/// refused. The control: a worker that cannot say lets the command go on, and the daemon stops.
#[test]
fn kr_host_stop_is_refused_inside_a_session_and_goes_on_where_a_worker_cannot_say() {
    let Some((host, session_id, _created, daemon)) = a_host_with_a_session() else {
        return;
    };
    for variable in ["KR_SESSION", "KR_ATTACHMENT"] {
        let mut command = host.kr(&["--json", "host", "stop"]);
        command.env(variable, "x");
        let output = start(command).finish("kr host stop");
        let refused = document(&output, "kr host stop");
        assert_eq!(output.status.code(), Some(8), "{variable}: {refused}");
        assert_eq!(refused["ok"], false, "{refused}");
        assert_eq!(refused["code"], "PERMISSION_DENIED", "{refused}");
        assert_eq!(stop_of(&refused), "not_asked", "{refused}");
    }
    assert_eq!(host.running(), vec![daemon], "the daemon was not stopped");

    // The worker's word: both variables are taken out, so only the worker can tell.
    let said = host.tree.root().join("typed-stop.out");
    let line = format!(
        "env -u KR_SESSION -u KR_ATTACHMENT {runtime_variable}={runtime} {state_variable}={state} \
         {kr} host stop > {said} 2>&1; echo done-$?",
        runtime_variable = kr_ipc::paths::RUNTIME_DIR_VARIABLE,
        runtime = host.tree.paths().runtime_root().display(),
        state_variable = kr_ipc::paths::STATE_DIR_VARIABLE,
        state = host.tree.paths().state_root().display(),
        kr = installation().join("kr").display(),
        said = said.display(),
    );
    let runtime = runtime();
    runtime.block_on(async {
        let mut terminal = Typing::attach(&host, session_id, true).await;
        terminal.type_line(&line).await;
        terminal.shown("done-8").await;
    });
    let typed = std::fs::read_to_string(&said).expect("the command's output");
    assert!(typed.contains("inside session"), "{typed}");
    assert!(typed.contains("Nothing was stopped"), "{typed}");
    assert_eq!(host.running(), vec![daemon], "the daemon was not stopped");
    assert!(host.answers());

    // The control: a worker that is stopped cannot say, and the command goes on.
    let worker = worker_of(&host, session_id);
    signal("STOP", worker);
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    signal("CONT", worker);
    let stopped = document(&output, "kr host stop");
    assert!(output.status.success(), "{stopped}");
    assert_eq!(stop_of(&stopped), "ended", "{stopped}");
    assert!(host.running().is_empty());
}

/// KR-REQ-07.12 (two stops at once): one daemon has ended, and each command says something true.
/// A command may see the daemon end, or find no daemon, or meet a holder that does not answer
/// (the listener has closed and the lock is not yet free) and ask nothing; none says that something
/// started the daemon again, and at least one saw the end. A command that finds the connection
/// closed before it can make its request meets a daemon that ends, and ends with the end's result
/// too. A command may also write its request, be told nothing of what became of it because the
/// daemon is already stopping for the other command, and then see the daemon end: it says that
/// the daemon did not show whether it took the stop and that it has ended.
#[test]
fn two_kr_host_stops_at_once_each_say_what_is_true_and_one_daemon_ends() {
    let Some((host, _session_id, _created, _daemon)) = a_host_with_a_session() else {
        return;
    };
    let first = start(host.kr(&["host", "stop"]));
    let second = start(host.kr(&["host", "stop"]));
    let results = [
        first.finish("the first stop"),
        second.finish("the second stop"),
    ];
    let mut saw_the_end = false;
    for output in &results {
        let out = String::from_utf8_lossy(&output.stdout);
        let err = String::from_utf8_lossy(&output.stderr);
        assert!(!out.contains("started it again"), "{out} {err}");
        assert!(!err.contains("started it again"), "{out} {err}");
        if output.status.success() {
            // Written, not answered, and the daemon ended: what the command knows, in two parts.
            let not_shown_and_ended = out.contains("did not show whether it took the stop")
                && out.contains("and it has ended");
            saw_the_end |=
                out.contains("Stopped the control daemon for environment") || not_shown_and_ended;
            assert!(
                out.contains("Stopped the control daemon for environment")
                    || not_shown_and_ended
                    || out.contains("No control daemon runs for environment")
                    || out.contains("This command sent nothing."),
                "{out} {err}"
            );
        } else {
            assert_eq!(output.status.code(), Some(1), "{out} {err}");
            assert!(
                err.contains("does not answer, so it may be starting or stopping"),
                "{out} {err}"
            );
            assert!(err.contains("No stop was requested"), "{out} {err}");
        }
    }
    assert!(saw_the_end, "one command saw the daemon end");
    assert!(host.running().is_empty(), "the daemon ended");
    assert!(!lock_is_held(&host));
    assert!(
        attempts(&host).is_empty(),
        "each command removed its own record"
    );
}

/// KR-REQ-07.12 (no daemon, and a holder that does not answer): with no daemon, the command says
/// so and exits 0. A process that holds the environment's lock and does not serve is not stopped:
/// the command says that nothing was requested and exits 1, and names the process only where it
/// runs this installation's daemon.
#[test]
fn kr_host_stop_says_when_no_daemon_runs_and_names_a_holder_that_does_not_answer() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let output = start(host.kr(&["host", "stop"])).finish("kr host stop");
    assert!(output.status.success());
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(said.contains("No control daemon runs"), "{said}");
    assert!(said.contains("Nothing was stopped"), "{said}");

    let lock = host.tree.environment().singleton_lock();
    let held = kr_controller::singleton::SingletonLock::hold(&lock, host.tree.environment_id())
        .expect("takes the lock");
    for (program, named) in [("kr-controller", true), ("a-holder", false)] {
        let mut holder =
            start_a_copy_that_holds_still(host.tree.root(), &host.tree.root().join(program));
        std::fs::write(&lock, format!("{}\n", holder.id())).expect("names the holder");
        let output = start(host.kr(&["host", "stop"])).finish("kr host stop");
        let _ = holder.kill();
        let _ = holder.wait();
        assert_eq!(output.status.code(), Some(1), "{program}");
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(said.contains("No stop was requested"), "{said}");
        assert_eq!(
            said.contains(&format!("kill -KILL {}", holder.id())),
            named,
            "{program}: {said}"
        );
    }
    drop(held);
}

/// The case below that a copy of this test program runs: a process that a lock file can name under
/// the name of a program, which a copy of a system binary cannot be on macOS (it is killed there).
const HOLD_STILL: &str = "a_copy_of_this_program_that_holds_still_for_a_case_that_names_it";

/// Holds still for the seconds that `KR_HOLD_STILL_SECONDS` gives, and at once where it is not set.
#[test]
#[ignore = "run only as a copy of this program, by the case that names it"]
fn a_copy_of_this_program_that_holds_still_for_a_case_that_names_it() {
    if let Some(seconds) = std::env::var("KR_HOLD_STILL_SECONDS")
        .ok()
        .and_then(|text| text.parse().ok())
    {
        std::thread::sleep(Duration::from_secs(seconds));
    }
}

/// What a test daemon does with a request to stop.
#[derive(Clone)]
enum OnStop {
    /// Takes no notice of it until the test lets it go, and then answers with `pid` and ends, as a
    /// daemon that took the stop does: it listens no more.
    HoldThenAnswer(u32),
    /// Answers at once with `pid` and goes on listening, as a daemon that took the stop and has not
    /// ended.
    AnswerAndStay(u32),
    /// Closes the connection with no answer, and ends.
    Cut,
    /// Refuses it as a daemon that does not list the method does.
    Refuse,
    /// Refuses it, and takes no notice of the probe that follows until the test lets it go, so that
    /// the command is held after the refusal.
    RefuseAndHoldTheProbe,
    /// Takes no notice of `host.info`, the command's first request, until the test lets it go, so
    /// that the command is held before its request to stop has left.
    HoldTheLook,
    /// Answers `host.info` and, in the same write, sends a frame that cannot be read, and then
    /// closes the connection, so that the command cannot make its request to stop.
    CloseAfterTheLook,
    /// Answers `host.info` and, in the same write, sends a frame that cannot be read, then closes
    /// the connection and stops listening, as a daemon whose stop has taken effect does: the
    /// command cannot make its request, and the daemon has ended.
    CloseAfterTheLookAndEnd,
    /// Answers the first `host.info` and closes the connection with nothing else sent, so that the
    /// command finds it closed; answers the first two looks that follow on connections of their
    /// own, as a daemon that is going may, and then stops listening. It has ended only once two
    /// looks have followed its close, whatever the time between the events.
    CloseAndEndAfterTwoLooks,
    /// Refuses `host.info`, the command's first request, with `code`: the command's own read of
    /// the daemon is refused.
    RefuseTheRead(kr_protocol::error::ErrorCode),
    /// Answers `host.info` with a result that does not decode.
    UndecodableRead,
    /// Answers the request to stop with the error `code`, and ends where `end` is set.
    AnswerTheStopWithError {
        code: kr_protocol::error::ErrorCode,
        end: bool,
    },
    /// Answers the hello with a version of another major than this program's.
    AnotherMajor,
}

/// How many `host.info` that follow its close `OnStop::CloseAndEndAfterTwoLooks` answers before it
/// stops listening.
const LOOKS_BEFORE_THE_END: u32 = 2;

/// A daemon of this test's own that answers `host.info` and the probe the level documents, and
/// does with a stop what the test says. It holds no lock and runs no session: it is what a person's
/// `kr` meets, nothing more.
struct TestDaemon {
    received: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    release: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ended: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set when the daemon left its accept loop, so that it listens no more: taken before the
    /// listener is let go, so that whatever saw the endpoint vacant finds it set.
    stopped_listening: std::sync::Arc<std::sync::Mutex<Option<Instant>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    socket: PathBuf,
}

impl TestDaemon {
    /// Serves the tree's controller endpoint. `build` is what it reports in `host.info`, and
    /// `probe_answered` whether it answers the probe or refuses it as the grant's own refusal.
    fn serve(host: &Standalone, build: &str, on_stop: OnStop, probe_answered: bool) -> Self {
        Self::serve_generation(host, build, on_stop, probe_answered, 1)
    }

    /// The same, answering `host.info` as the daemon of that generation.
    fn serve_generation(
        host: &Standalone,
        build: &str,
        on_stop: OnStop,
        probe_answered: bool,
        generation: u64,
    ) -> Self {
        use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Response};

        let environment = host.tree.environment();
        let environment_id = host.tree.environment_id();
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let received = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stopped_listening = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (heard, released, over, stopped) = (
            received.clone(),
            release.clone(),
            ended.clone(),
            stopped_listening.clone(),
        );
        let build = build.to_owned();
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let boot_epoch = kr_ipc::identity::boot_epoch(&boot).expect("a boot epoch");
        let info = kr_protocol::hostinfo::HostInfoResult {
            build_id: BuildId::new(&build).expect("a build identifier"),
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            environment_id,
            generation: kr_protocol::ids::ControllerGeneration::new(generation),
            boot_identity: boot.clone(),
            started_at_ms: kr_protocol::scalars::TimestampMs::new(1_700_000_000_000),
            live_sessions: kr_protocol::scalars::U64::new(0),
            session_limit: kr_protocol::scalars::U64::new(8),
            default_worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            power: kr_protocol::desktop::SleepInhibitionState::off(
                kr_protocol::desktop::InhibitionMechanism::None,
                kr_protocol::desktop::PowerSource::Unknown,
            ),
            machine: None,
            privacy: None,
            default_shell_mode: None,
        };
        // The listener belongs to the runtime that serves it: it is bound before this returns, so
        // that the endpoint exists when the test starts the command, and bound inside the runtime.
        let runtime = runtime();
        let listener = {
            let _inside = runtime.enter();
            kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint")
        };
        let socket = PathBuf::from(endpoint.as_text());
        let thread = std::thread::spawn(move || {
            runtime.block_on(async move {
                // How many `host.info` the daemon has answered since it closed a connection, where it
                // has closed one.
                let mut looks_since_the_close: Option<u32> = None;
                loop {
                    if over.load(std::sync::atomic::Ordering::SeqCst) {
                        *stopped.lock().expect("the instant") = Some(Instant::now());
                        break;
                    }
                    let accepted =
                        tokio::time::timeout(Duration::from_millis(100), listener.accept()).await;
                    let Ok(Ok((connection, peer))) = accepted else {
                        continue;
                    };
                    let (mut reader, mut writer) =
                        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
                    let connection_id = kr_protocol::ids::ConnectionId::new(kr_ipc::new_uuid());
                    while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                        let mut then_end = false;
                        let mut then_close = false;
                        let answer = match frame {
                            ControlFrame::Hello(_) => ControlFrame::HelloAck(Box::new(
                                kr_protocol::local::LocalHelloAck {
                                    selected_version: if matches!(on_stop, OnStop::AnotherMajor) {
                                        kr_protocol::hello::ProtocolVersion::new(
                                            kr_protocol::hello::PROTOCOL_VERSION.major + 1,
                                            0,
                                        )
                                    } else {
                                        kr_protocol::hello::PROTOCOL_VERSION
                                    },
                                    role: kr_protocol::local::LocalRole::Controller,
                                    connection_id,
                                    environment_id,
                                    boot_identity: boot.clone(),
                                    peer: peer.to_wire(),
                                    action_window: kr_protocol::hello::ActionWindow {
                                        action_window_id: kr_protocol::ids::ActionWindowId::new(
                                            "test-daemon",
                                        )
                                        .expect("a window identifier"),
                                        connection_id,
                                        boot_epoch,
                                        issued_at_ms: kr_protocol::scalars::TimestampMs::new(0),
                                        valid_for_ms: kr_protocol::scalars::DurationMs::new(
                                            600_000,
                                        ),
                                    },
                                    capabilities: CanonicalSet::new(),
                                    max_receive: kr_protocol::hello::ReceiveLimits::default(),
                                    build: Some(kr_protocol::local::LocalBuild {
                                        build_id: BuildId::new(&build).expect("a build"),
                                        protocol_version: kr_protocol::hello::PACKAGE_VERSION,
                                    }),
                                },
                            )),
                            ControlFrame::Request(request) => {
                                let method = request.method.as_str().to_owned();
                                heard.lock().expect("the record").push(method.clone());
                                let held = match request.method.method() {
                                    Some(Method::HostInfo) => {
                                        matches!(on_stop, OnStop::HoldTheLook)
                                    }
                                    Some(Method::BackupStatus) => {
                                        matches!(on_stop, OnStop::RefuseAndHoldTheProbe)
                                    }
                                    _ => false,
                                };
                                if held {
                                    while !released.load(std::sync::atomic::Ordering::SeqCst) {
                                        tokio::time::sleep(Duration::from_millis(20)).await;
                                    }
                                }
                                then_close = request.method.method() == Some(Method::HostInfo)
                                    && match on_stop {
                                        OnStop::CloseAfterTheLook
                                        | OnStop::CloseAfterTheLookAndEnd => true,
                                        OnStop::CloseAndEndAfterTwoLooks => {
                                            looks_since_the_close.is_none()
                                        }
                                        _ => false,
                                    };
                                if let Some(looks) = looks_since_the_close.as_mut()
                                    && request.method.method() == Some(Method::HostInfo)
                                {
                                    *looks += 1;
                                    then_end = *looks >= LOOKS_BEFORE_THE_END;
                                }
                                let outcome = match (request.method.method(), &on_stop) {
                                    (Some(Method::HostInfo), OnStop::RefuseTheRead(code)) => {
                                        Outcome::Error(kr_client::error::refusal(
                                            *code,
                                            kr_client::shown::Shown::said(
                                                "this daemon refuses the read of its state",
                                            ),
                                        ))
                                    }
                                    (Some(Method::HostInfo), OnStop::UndecodableRead) => {
                                        Outcome::Ok(ParamsValue::empty())
                                    }
                                    (Some(Method::HostInfo), _) => Outcome::Ok(
                                        ParamsValue::from_typed(&info).expect("encodes"),
                                    ),
                                    (Some(Method::BackupStatus), _) if probe_answered => {
                                        Outcome::Ok(ParamsValue::empty())
                                    }
                                    _ => Outcome::Error(kr_client::error::refusal(
                                        kr_protocol::error::ErrorCode::PermissionDenied,
                                        kr_client::shown::Shown::said(
                                            "this host's grant does not carry the right",
                                        ),
                                    )),
                                };
                                ControlFrame::Response(Response {
                                    request_id: request.request_id,
                                    outcome,
                                })
                            }
                            ControlFrame::Mutation(mutation) => {
                                heard
                                    .lock()
                                    .expect("the record")
                                    .push(mutation.method.as_str().to_owned());
                                match &on_stop {
                                    OnStop::Cut => {
                                        over.store(true, std::sync::atomic::Ordering::SeqCst);
                                        break;
                                    }
                                    OnStop::Refuse
                                    | OnStop::HoldTheLook
                                    | OnStop::CloseAfterTheLook
                                    | OnStop::CloseAfterTheLookAndEnd
                                    | OnStop::CloseAndEndAfterTwoLooks
                                    | OnStop::RefuseTheRead(_)
                                    | OnStop::UndecodableRead
                                    | OnStop::AnotherMajor
                                    | OnStop::RefuseAndHoldTheProbe => {
                                        ControlFrame::Response(Response {
                                            request_id: mutation.request_id,
                                            outcome: Outcome::Error(kr_client::error::refusal(
                                                kr_protocol::error::ErrorCode::PermissionDenied,
                                                kr_client::shown::Shown::said(
                                                    "this method is not in this host's registry",
                                                ),
                                            )),
                                        })
                                    }
                                    OnStop::AnswerTheStopWithError { code, end } => {
                                        then_end = *end;
                                        ControlFrame::Response(Response {
                                            request_id: mutation.request_id,
                                            outcome: Outcome::Error(kr_client::error::refusal(
                                                *code,
                                                kr_client::shown::Shown::said(
                                                    "this daemon cannot say what became of the stop",
                                                ),
                                            )),
                                        })
                                    }
                                    OnStop::HoldThenAnswer(pid) | OnStop::AnswerAndStay(pid) => {
                                        if matches!(on_stop, OnStop::HoldThenAnswer(_)) {
                                            while !released
                                                .load(std::sync::atomic::Ordering::SeqCst)
                                            {
                                                tokio::time::sleep(Duration::from_millis(20)).await;
                                            }
                                            then_end = true;
                                        }
                                        ControlFrame::Response(Response {
                                            request_id: mutation.request_id,
                                            outcome: Outcome::Ok(
                                                ParamsValue::from_typed(
                                                    &kr_protocol::update::HostStopResult {
                                                        pid: kr_protocol::scalars::U64::new(
                                                            u64::from(*pid),
                                                        ),
                                                        unsettled: kr_protocol::scalars::U64::new(
                                                            0,
                                                        ),
                                                        launch: Nullable::null(),
                                                    },
                                                )
                                                .expect("encodes"),
                                            ),
                                        })
                                    }
                                }
                            }
                            _ => continue,
                        };
                        let written =
                            if then_close && !matches!(on_stop, OnStop::CloseAndEndAfterTwoLooks) {
                                // The answer and a frame that cannot be read, in ONE write: the
                                // command meets the unreadable frame whenever it next reads, whatever
                                // the order of what follows this write.
                                let codec = kr_protocol::frame::FrameCodec::new(
                                    kr_protocol::frame::StreamKind::Control,
                                );
                                let mut bytes = codec.encode_message(&answer).expect("encodes");
                                bytes.extend(codec.encode(&[0xff, 0xff]).expect("frames"));
                                writer.write_frame(&bytes).await
                            } else {
                                writer.write_message(&answer).await
                            };
                        if written.is_err() {
                            break;
                        }
                        if then_end {
                            over.store(true, std::sync::atomic::Ordering::SeqCst);
                            break;
                        }
                        if then_close {
                            if matches!(on_stop, OnStop::CloseAfterTheLookAndEnd) {
                                over.store(true, std::sync::atomic::Ordering::SeqCst);
                            }
                            if matches!(on_stop, OnStop::CloseAndEndAfterTwoLooks) {
                                looks_since_the_close = Some(0);
                            }
                            break;
                        }
                    }
                }
            });
        });
        Self {
            received,
            release,
            ended,
            stopped_listening,
            thread: Some(thread),
            socket,
        }
    }

    /// Waits until the daemon has received `method`, which is how a test knows a request left.
    fn until_it_received(&self, method: &str) {
        let started = Instant::now();
        while !self
            .received
            .lock()
            .expect("the record")
            .iter()
            .any(|got| got == method)
        {
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the test daemon never received {method}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn received(&self) -> Vec<String> {
        self.received.lock().expect("the record").clone()
    }

    /// The instant the daemon stopped listening, where it has.
    fn stopped_listening_at(&self) -> Option<Instant> {
        *self.stopped_listening.lock().expect("the instant")
    }

    /// Lets a held stop be answered.
    fn let_go(&self) {
        self.release
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Stops listening, so that the endpoint is vacant again.
    fn end(&mut self) {
        self.release
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.ended.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// A number no process has: the process a test daemon says it is.
const NOBODY: u32 = 4_194_000;

/// KR-REQ-07.12 (the interrupts): once the request has left, a hangup does not end the command and
/// the stop is carried to its end when the daemon answers. The command that waits is the control of
/// the case below, which an interrupt ends.
#[test]
fn a_hangup_after_the_request_has_left_does_not_end_kr_host_stop() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::HoldThenAnswer(NOBODY),
        true,
    );
    let running = start(host.kr(&["--json", "host", "stop"]));
    daemon.until_it_received("host.stop");
    signal("HUP", running.child.as_ref().expect("the child").id());
    // Only now does the daemon answer: a command that the hangup ended has gone with its report.
    daemon.let_go();
    let output = running.finish("kr host stop");
    let stopped = document(&output, "kr host stop");
    assert!(output.status.success(), "{stopped}");
    assert_eq!(stop_of(&stopped), "ended", "{stopped}");
    assert_eq!(stopped["pid"].as_u64(), Some(u64::from(NOBODY)));
    daemon.end();
}

/// KR-REQ-07.12 (the interrupts, and the record): an interrupt after the request has left says what
/// may be so, exits 1 and does not cancel the stop. The command's record stands, and the next
/// command that finds no daemon says what it recorded, as a record, and removes it once it has
/// ended with its own result.
#[test]
fn an_interrupt_after_the_request_has_left_says_what_may_be_so_and_the_record_stands() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::HoldThenAnswer(NOBODY),
        true,
    );
    let running = start(host.kr(&["host", "stop"]));
    daemon.until_it_received("host.stop");
    signal("INT", running.child.as_ref().expect("the child").id());
    let output = running.finish("kr host stop");
    assert_eq!(output.status.code(), Some(1));
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("Asked the control daemon"), "{said}");
    assert!(
        said.contains("an interrupt does not cancel the stop"),
        "{said}"
    );
    assert!(said.contains("interrupted while it asked"), "{said}");
    assert!(said.contains("may have taken the request"), "{said}");
    let records = attempts(&host);
    assert_eq!(records.len(), 1, "the interrupted command's record stands");
    assert_eq!(
        records[0].attempt.phase,
        kr_controller::attempt::Phase::Asking
    );
    assert_eq!(
        records[0].standing(),
        kr_controller::attempt::Standing::Gone
    );

    // The daemon is gone, and the next command that says no daemon runs gives the record.
    daemon.end();
    let output = start(host.kr(&["host", "stop"])).finish("kr host stop");
    assert!(output.status.success());
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(said.contains("The last record of a kr host stop"), "{said}");
    assert!(
        said.contains("What happened after that is not recorded"),
        "{said}"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("No control daemon runs"));
    assert!(
        attempts(&host).is_empty(),
        "the command removed the record it said"
    );

    // A reader of the words that no daemon runs gives a record and removes none.
    let again = start(host.kr(&["host", "stop"])).finish("kr host stop");
    assert!(again.status.success());
}

/// An interrupt before the request to stop has left says that nothing was asked and nothing was
/// stopped, and the command leaves no record: the daemon had received only the command's look.
#[test]
fn an_interrupt_before_the_request_says_that_nothing_was_asked_and_leaves_no_record() {
    let Some(host) = Standalone::create() else {
        return;
    };
    leave_a_record(&host);
    let mut daemon = TestDaemon::serve(&host, "kr-controller/9.9.9", OnStop::HoldTheLook, true);
    let running = start(host.kr(&["host", "stop"]));
    daemon.until_it_received("host.info");
    signal("INT", running.child.as_ref().expect("the child").id());
    let output = running.finish("kr host stop");
    assert_eq!(output.status.code(), Some(1));
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("was interrupted before it asked the control daemon"),
        "{said}"
    );
    assert!(said.contains("Nothing was stopped."), "{said}");
    assert!(
        !daemon.received().iter().any(|method| method == "host.stop"),
        "no request to stop left: {:?}",
        daemon.received()
    );
    assert_eq!(
        attempts(&host).len(),
        1,
        "the command left no record of its own, and the earlier one was not its to remove"
    );
    daemon.let_go();
    daemon.end();
}

/// A copy of this test program under the name of the daemon, in a folder of its own, which holds
/// still: a process that a lock file can name as a control daemon.
fn a_process_named_kr_controller(host: &Standalone, folder: &str) -> Child {
    let directory = host.tree.root().join(folder);
    std::fs::create_dir_all(&directory).expect("a folder");
    start_a_copy_that_holds_still(host.tree.root(), &directory.join("kr-controller"))
}

/// Places a copy of this test program at `copy` and starts it, holding still, with `working` as its
/// working directory.
///
/// The copy is written by a copier process, as the suite's other programs are: no thread of this
/// test holds a descriptor that writes it, so no process this test starts can inherit one, and the
/// system never refuses the start with "Text file busy" because of this test's own process.
fn start_a_copy_that_holds_still(working: &Path, copy: &Path) -> Child {
    kr_ipc::testing::place_program(&std::env::current_exe().expect("this test"), copy);
    spawning(|| {
        Command::new(copy)
            .args(["--ignored", "--exact", HOLD_STILL, "--nocapture"])
            .env("KR_HOLD_STILL_SECONDS", "600")
            .current_dir(working)
            .spawn()
    })
    .expect("starts")
}

/// A daemon that ends and is replaced before the command sees the end reads as ended, with the
/// words that something started it again, where the replacement is shown: the old process is gone,
/// and the lock file names a live process named kr-controller that is not the old one.
#[test]
fn a_successor_that_holds_the_environment_after_the_stop_reads_as_the_daemons_end() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let lock = host.tree.environment().singleton_lock();
    let held = kr_controller::singleton::SingletonLock::hold(&lock, host.tree.environment_id())
        .expect("takes the lock");
    let mut old = a_process_named_kr_controller(&host, "old");
    let mut successor = a_process_named_kr_controller(&host, "successor");
    std::fs::write(&lock, format!("{}\n", old.id())).expect("names the old daemon");
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::HoldThenAnswer(old.id()),
        true,
    );
    let running = start(host.kr(&["host", "stop"]));
    daemon.until_it_received("host.stop");
    // The old daemon ends, and the lock is held again by the one that replaces it.
    old.kill().expect("ends the old daemon");
    old.wait().expect("collects it");
    std::fs::write(&lock, format!("{}\n", successor.id())).expect("names the successor");
    daemon.let_go();
    let output = running.finish("kr host stop");
    assert!(output.status.success(), "{output:?}");
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains(&format!(
            "The control daemon (process {}) ended; process {} now holds environment",
            old.id(),
            successor.id()
        )),
        "{said}"
    );
    assert!(said.contains("so something started it again"), "{said}");
    assert!(attempts(&host).is_empty(), "the command removed its record");
    let _ = successor.kill();
    let _ = successor.wait();
    drop(held);
    daemon.end();
}

/// A lock that is held and a lock file that names no live control daemon is no successor, and a
/// daemon of another generation that answers is: with no process identity known, the daemon that was
/// asked ended when its listener closed, and the one that answers after it is another.
#[test]
fn a_daemon_of_another_generation_that_answers_after_the_stop_is_a_successor() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let lock = host.tree.environment().singleton_lock();
    let held = kr_controller::singleton::SingletonLock::hold(&lock, host.tree.environment_id())
        .expect("takes the lock");
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::HoldThenAnswer(NOBODY),
        true,
    );
    let running = start(host.kr(&["host", "stop"]));
    daemon.until_it_received("host.stop");
    daemon.let_go();
    daemon.end();
    let mut again =
        TestDaemon::serve_generation(&host, "kr-controller/9.9.9", OnStop::Refuse, true, 2);
    let output = running.finish("kr host stop");
    assert!(output.status.success(), "{output:?}");
    let said = String::from_utf8_lossy(&output.stdout);
    assert!(
        said.contains("The control daemon ended; another control daemon now holds environment"),
        "{said}"
    );
    assert!(said.contains("so something started it again"), "{said}");
    drop(held);
    again.end();
}

/// KR-REQ-07.12 (a reader never removes): `kr new` with no start chosen says that no daemon runs and
/// gives the record a killed `kr host stop` left, as a record and not as a claim of what happened
/// after it, and leaves the record where it was.
#[test]
fn a_reader_of_no_daemon_gives_the_record_of_a_killed_stop_and_removes_nothing() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::HoldThenAnswer(NOBODY),
        true,
    );
    let mut running = start(host.kr(&["host", "stop"]));
    daemon.until_it_received("host.stop");
    running
        .child
        .as_mut()
        .expect("the child")
        .kill()
        .expect("kills the command");
    let _ = running.finish("the killed kr host stop");
    daemon.end();
    assert_eq!(
        attempts(&host).len(),
        1,
        "the killed command left its record"
    );

    let output = start(host.new_session()).finish("kr new");
    assert!(!output.status.success());
    let failed = document(&output, "kr new");
    let said = failed["message"].as_str().expect("a message");
    assert!(said.contains("The last record of a kr host stop"), "{said}");
    assert!(said.contains("asking the control daemon"), "{said}");
    assert_eq!(attempts(&host).len(), 1, "reading removed nothing");
}

/// KR-REQ-07.12 (a missing answer): a daemon that closes the connection with no answer to the stop
/// leaves an unknown outcome, never "not stopped". The command looks at the lock, finds the
/// environment free, and says that the daemon ended; the stop it reports is `ended`, with no
/// process it did not learn.
#[test]
fn a_stop_with_no_answer_is_an_unknown_outcome_and_the_command_looks_at_the_lock() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(&host, "kr-controller/9.9.9", OnStop::Cut, true);
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let stopped = document(&output, "kr host stop");
    assert!(output.status.success(), "{stopped}");
    assert_eq!(stop_of(&stopped), "ended", "{stopped}");
    assert!(stopped["pid"].is_null(), "{stopped}");
    daemon.end();
}

/// The first code whose retry category is `category`, and which is not the grant's own refusal.
fn an_error_code_of(category: kr_protocol::error::RetryCategory) -> kr_protocol::error::ErrorCode {
    kr_protocol::error::ErrorCode::ALL
        .iter()
        .copied()
        .find(|code| {
            *code != kr_protocol::error::ErrorCode::PermissionDenied
                && code.retry_category() == category
        })
        .expect("a code of the category")
}

/// KR-REQ-07.12 (the command's own read of the daemon): a daemon that answers the hello and refuses
/// the read of its state is refused as its own, and the command exits 8; a result of that read that
/// does not decode is no refusal, and the command exits 1. Both end the command before any stop is
/// asked, and say `not_asked`.
#[test]
fn a_refused_read_of_the_daemon_exits_8_and_one_that_does_not_decode_exits_1_with_no_stop_asked() {
    for (on_stop, exit) in [
        (
            OnStop::RefuseTheRead(an_error_code_of(kr_protocol::error::RetryCategory::NoRetry)),
            8,
        ),
        (OnStop::UndecodableRead, 1),
    ] {
        let Some(host) = Standalone::create() else {
            return;
        };
        let mut daemon = TestDaemon::serve(&host, "kr-controller/9.9.9", on_stop, true);
        let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
        let said = document(&output, "kr host stop");
        assert_eq!(output.status.code(), Some(exit), "{said}");
        assert_eq!(stop_of(&said), "not_asked", "{said}");
        assert!(
            !daemon.received().iter().any(|method| method == "host.stop"),
            "no stop was asked: {:?}",
            daemon.received()
        );
        assert!(attempts(&host).is_empty(), "no record of an attempt");
        daemon.end();
    }
}

/// KR-REQ-07.12 (a daemon of another major): the command offers its own major only, so a daemon
/// that answers the hello with another major is a version that does not fit. The command asks for
/// no stop, says `not_asked` and exits 3. Which way the failure goes (a daemon's reply is never
/// looked at) is held by the library case that makes no look after such a failure; this case holds
/// the refusal at the hello.
#[test]
fn a_daemon_that_answers_the_hello_with_another_major_is_refused_with_exit_3_and_no_stop_asked() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(&host, "kr-controller/9.9.9", OnStop::AnotherMajor, true);
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert_eq!(output.status.code(), Some(3), "{said}");
    assert_eq!(stop_of(&said), "not_asked", "{said}");
    assert!(
        !daemon.received().iter().any(|method| method == "host.stop"),
        "no stop was asked: {:?}",
        daemon.received()
    );
    daemon.end();
}

/// KR-REQ-07.12 (an unknown-outcome answer): a daemon that answers the stop with an error whose
/// category is "outcome unknown" has not said that nothing was taken. The command waits for it as
/// for one that took the stop and, seeing it end, says `ended`; a definite refusal of the stop
/// would be `refused`.
#[test]
fn a_stop_answered_with_an_unknown_outcome_error_is_waited_for_and_not_refused() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::AnswerTheStopWithError {
            code: an_error_code_of(kr_protocol::error::RetryCategory::OutcomeUnknown),
            end: true,
        },
        true,
    );
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert!(output.status.success(), "{said}");
    assert_eq!(stop_of(&said), "ended", "{said}");
    daemon.end();
}

/// KR-REQ-07.12 (the record of the attempt): where the request may have left and no answer says
/// that the daemon took it, the command's record of the attempt stays as one that asked, and the
/// daemon not seen to end after 30 seconds is `maybe_asked`.
#[test]
fn the_record_of_a_stop_whose_outcome_is_unknown_is_not_told() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::AnswerTheStopWithError {
            code: an_error_code_of(kr_protocol::error::RetryCategory::OutcomeUnknown),
            end: false,
        },
        true,
    );
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(stop_of(&said), "maybe_asked", "{said}");
    let records = attempts(&host);
    assert_eq!(records.len(), 1, "its own record stands");
    assert_eq!(
        records[0].attempt.phase,
        kr_controller::attempt::Phase::Asking,
        "an unknown outcome is not told"
    );
    daemon.end();
}

/// KR-REQ-07.12 (the record of the attempt): where the daemon answered that it took the stop and
/// was not seen to end after 30 seconds, the command's record of the attempt says that the daemon
/// was told.
#[test]
fn the_record_of_a_stop_that_the_daemon_took_and_has_not_ended_is_told() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::AnswerAndStay(std::process::id()),
        true,
    );
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(stop_of(&said), "told", "{said}");
    let records = attempts(&host);
    assert_eq!(records.len(), 1, "its own record stands");
    assert_eq!(
        records[0].attempt.phase,
        kr_controller::attempt::Phase::Told,
        "the daemon's answer is told"
    );
    daemon.end();
}

/// KR-REQ-07.12 (an earlier daemon): a daemon that refuses the stop and answers the read that every
/// build lists does not list the request. Nothing is stopped, no handover step is asked, the same
/// daemon answers after the command, and the command exits 1 and says how to switch this host to
/// another release. The control: a daemon that refuses the read too has refused as its own, which
/// the command shows as the refusal with exit 8, with nothing else asked.
#[test]
fn a_daemon_that_lists_no_stop_is_left_as_it_is_and_a_refusal_of_its_own_is_shown() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/0.1.0+aaaaaaaaaaaa",
        OnStop::Refuse,
        true,
    );
    let output = start(host.kr(&["host", "stop"])).finish("kr host stop");
    assert_eq!(output.status.code(), Some(1));
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("is of another build and takes no stop request"),
        "{said}"
    );
    assert!(said.contains("Nothing was stopped."), "{said}");
    assert!(
        said.contains("kr host update or kr host rollback"),
        "{said}"
    );
    assert_eq!(
        daemon.received(),
        ["host.info", "host.stop", "backup.status"],
        "the stop, then the probe, and no step of an update's handover"
    );
    assert!(host.answers(), "the same daemon answers after the command");
    assert!(attempts(&host).is_empty());
    daemon.end();

    let mut lease = TestDaemon::serve(
        &host,
        "kr-controller/0.1.0+aaaaaaaaaaaa",
        OnStop::Refuse,
        false,
    );
    let output = start(host.kr(&["host", "stop"])).finish("kr host stop");
    assert_eq!(output.status.code(), Some(8));
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(
        said.contains("the check that tells which was refused too"),
        "{said}"
    );
    assert!(
        said.contains("this host's grant does not carry the right"),
        "{said}"
    );
    assert!(!said.contains("another build"), "{said}");
    assert_eq!(
        lease.received(),
        ["host.info", "host.stop", "backup.status"]
    );
    lease.end();
}

/// KR-REQ-07.12 (a reader that has gone): a `kr host stop` whose output nobody reads any more
/// still stops the daemon and removes its own record, because what it says is not what it does.
#[test]
fn kr_host_stop_goes_on_when_nobody_reads_what_it_says() {
    let Some((host, _session_id, _created, _daemon)) = a_host_with_a_session() else {
        return;
    };
    let mut child = spawning(|| {
        host.kr(&["host", "stop"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    })
    .expect("kr starts");
    drop(child.stdout.take());
    drop(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("waits for kr") {
            break status;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "kr host stop did not end"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        status.success() || status.code().is_some(),
        "the command ended by itself: {status:?}"
    );
    assert!(host.running().is_empty(), "the daemon ended");
    assert!(!lock_is_held(&host));
    assert!(attempts(&host).is_empty(), "the command removed its record");
}

/// Leaves the record of a `kr host stop` that was killed, as the command that has gone left it.
fn leave_a_record(host: &Standalone) {
    let environment = host.tree.environment();
    let directory = environment
        .state_dir()
        .join(kr_controller::attempt::DIRECTORY);
    kr_ipc::paths::create_private_directory(&directory).expect("the directory");
    let attempt = kr_controller::attempt::Attempt {
        command: kr_controller::attempt::Command::Stop,
        phase: kr_controller::attempt::Phase::Told,
        process: kr_ipc::identity::ended_process_identity(NOBODY),
        at_ms: 1_700_000_000_000,
        daemon: None,
    };
    kr_ipc::paths::write_owner_only_file(
        &directory.join(kr_ipc::new_uuid().to_string()),
        &serde_json::to_vec(&attempt).expect("encodes"),
    )
    .expect("writes the record");
}

/// Runs `kr host stop` with one stream that nobody reads: its reader is closed before the command
/// starts, so the command's first write to it fails. Says whether the command ended by itself.
fn stop_that_nobody_reads(host: &Standalone, arguments: &[&str], stream: &str) -> bool {
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    let mut command = host.kr(arguments);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stream == "stdout" {
        command.stdout(writer);
    } else {
        command.stderr(writer);
    }
    let mut child = spawning(|| command.spawn()).expect("kr starts");
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("waits for kr") {
            return status.code().is_some();
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "kr host stop did not end"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// KR-REQ-07.12 (a request that was refused): `--json` says `refused` for a request that left and
/// that the daemon refused, whether the probe shows a daemon of another build or is refused too.
/// `not_asked` is for what never left.
#[test]
fn a_request_the_daemon_refused_is_refused_in_json_and_not_asked() {
    let Some(host) = Standalone::create() else {
        return;
    };
    for (probe_answered, code) in [(true, 1), (false, 8)] {
        let mut daemon = TestDaemon::serve(
            &host,
            "kr-controller/0.1.0+aaaaaaaaaaaa",
            OnStop::Refuse,
            probe_answered,
        );
        let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
        let said = document(&output, "kr host stop");
        assert_eq!(output.status.code(), Some(code), "{said}");
        assert_eq!(said["ok"], false, "{said}");
        assert_eq!(stop_of(&said), "refused", "{said}");
        assert!(
            daemon.received().iter().any(|method| method == "host.stop"),
            "the request left: {:?}",
            daemon.received()
        );
        daemon.end();
    }
}

/// KR-REQ-07.12 (the interrupts): an interrupt after the daemon took the stop says that it may still
/// be ending and to run the command again to see, gives `told`, and the command's record stands.
#[test]
fn an_interrupt_after_the_daemon_was_told_says_what_may_be_so_and_the_record_stands() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::AnswerAndStay(NOBODY),
        true,
    );
    let running = start(host.kr(&["--json", "host", "stop"]));
    until_there("the record says that the daemon was told", || {
        attempts(&host)
            .iter()
            .any(|recorded| recorded.attempt.phase == kr_controller::attempt::Phase::Told)
            .then_some(())
    });
    signal("INT", running.child.as_ref().expect("the child").id());
    let output = running.finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(stop_of(&said), "told", "{said}");
    let message = said["message"].as_str().expect("a message");
    assert!(
        message.contains("was told to stop and may still be ending"),
        "{message}"
    );
    assert!(
        message.contains("interrupted before it saw the end"),
        "{message}"
    );
    assert!(
        message.ends_with("Run kr host stop again to see."),
        "{message}"
    );
    assert!(!message.contains("to wait for it"), "{message}");
    assert_eq!(attempts(&host).len(), 1, "the record stands");
    daemon.end();
}

/// KR-REQ-07.12 (the interrupts): an interrupt after the daemon refused the request says that
/// nothing was stopped, gives `refused`, and leaves no record.
#[test]
fn an_interrupt_after_the_daemon_refused_says_that_nothing_was_stopped_and_leaves_no_record() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/0.1.0+aaaaaaaaaaaa",
        OnStop::RefuseAndHoldTheProbe,
        true,
    );
    let running = start(host.kr(&["--json", "host", "stop"]));
    daemon.until_it_received("backup.status");
    signal("INT", running.child.as_ref().expect("the child").id());
    let output = running.finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(stop_of(&said), "refused", "{said}");
    let message = said["message"].as_str().expect("a message");
    assert!(
        message.contains("interrupted after the control daemon"),
        "{message}"
    );
    assert!(
        message.contains("refused the request. Nothing was stopped."),
        "{message}"
    );
    assert!(attempts(&host).is_empty(), "no record stands");
    daemon.let_go();
    daemon.end();
}

/// KR-REQ-07.12 (M4): a daemon that took the stop and has not ended after 30 seconds is named with
/// the way to end it, where the process that held the environment still runs as a control daemon.
/// The result removes nothing: the command's own record and an earlier attempt's both stand.
#[test]
fn a_daemon_that_took_the_stop_and_has_not_ended_is_named_and_no_record_is_removed() {
    let Some(host) = Standalone::create() else {
        return;
    };
    leave_a_record(&host);
    let lock = host.tree.environment().singleton_lock();
    let held = kr_controller::singleton::SingletonLock::hold(&lock, host.tree.environment_id())
        .expect("takes the lock");
    let mut old = a_process_named_kr_controller(&host, "old");
    std::fs::write(&lock, format!("{}\n", old.id())).expect("names the daemon");
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::AnswerAndStay(old.id()),
        true,
    );
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    let pid = old.id();
    let _ = old.kill();
    let _ = old.wait();
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(stop_of(&said), "told", "{said}");
    let message = said["message"].as_str().expect("a message");
    assert!(
        message.contains("was told to stop and has not ended after 30 seconds."),
        "{message}"
    );
    assert!(
        message.contains("It may be finishing a write."),
        "{message}"
    );
    assert!(
        message.contains(&format!(
            "kill -KILL {pid} ends it, and the next daemon recovers as it does after a crash."
        )),
        "{message}"
    );
    assert!(!message.contains("wait again"), "{message}");
    assert_eq!(
        attempts(&host).len(),
        2,
        "its own record and the earlier one stand"
    );
    drop(held);
    daemon.end();
}

/// KR-REQ-07.12 (earlier records): the records of earlier attempts are removed only after the
/// command has put them out. A command whose document or standard error nobody reads leaves them,
/// and the one that is read says them and then removes them.
#[test]
fn the_records_of_earlier_attempts_are_removed_only_after_they_were_put_out() {
    let Some(host) = Standalone::create() else {
        return;
    };
    leave_a_record(&host);
    assert!(stop_that_nobody_reads(
        &host,
        &["--json", "host", "stop"],
        "stdout"
    ));
    assert_eq!(attempts(&host).len(), 1, "the document was not written");
    assert!(stop_that_nobody_reads(&host, &["host", "stop"], "stderr"));
    assert_eq!(attempts(&host).len(), 1, "the record was not said");
    // In text mode the record is said on standard error and the result is a line on standard
    // output: where that line cannot be written, the command's result was not written either.
    assert!(stop_that_nobody_reads(&host, &["host", "stop"], "stdout"));
    assert_eq!(attempts(&host).len(), 1, "the result line was not written");

    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert!(output.status.success(), "{said}");
    let records = said["records"].as_array().expect("a records member");
    assert_eq!(records.len(), 1, "{said}");
    assert!(
        records[0]
            .as_str()
            .expect("a sentence")
            .contains("The last record of a kr host stop"),
        "{said}"
    );
    assert!(attempts(&host).is_empty(), "the document put it out");
}

/// KR-REQ-07.12 (a daemon that does not answer `host.info`): a daemon that answers the hello and
/// not the first read is a holder that is silent. The command gives up at its bound and asks
/// nothing; it does not wait for ever.
#[test]
fn a_daemon_that_does_not_answer_host_info_is_a_holder_that_is_silent_and_no_stop_is_asked() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(&host, "kr-controller/9.9.9", OnStop::HoldTheLook, true);
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(stop_of(&said), "not_asked", "{said}");
    let message = said["message"].as_str().expect("a message");
    assert!(
        message.contains("did not answer within 10 seconds"),
        "{message}"
    );
    assert!(message.contains("No stop was requested"), "{message}");
    assert!(
        !daemon.received().iter().any(|method| method == "host.stop"),
        "no request to stop left: {:?}",
        daemon.received()
    );
    assert!(attempts(&host).is_empty(), "no record stands");
    daemon.let_go();
    daemon.end();
}

/// KR-REQ-07.12 (a lock that could not be looked at): a daemon that closes the connection with no
/// answer leaves an unknown outcome, and the check of the lock then fails (a directory stands where
/// the lock file is). The text says that the daemon did not show whether it took the stop and that
/// whether it ended could not be read, and never that the daemon was told.
#[test]
fn an_unknown_answer_followed_by_a_failed_lock_check_does_not_say_the_daemon_was_told() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let lock = host.tree.environment().singleton_lock();
    let _ = std::fs::remove_file(&lock);
    std::fs::create_dir_all(&lock).expect("a directory where the lock file is");
    let mut daemon = TestDaemon::serve(&host, "kr-controller/9.9.9", OnStop::Cut, true);
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert_eq!(output.status.code(), Some(1), "{said}");
    assert_eq!(stop_of(&said), "maybe_asked", "{said}");
    let message = said["message"].as_str().expect("a message");
    assert!(
        message.contains("did not show whether it took the stop ("),
        "{message}"
    );
    assert!(
        message.contains("whether it has ended could not be read after 30 seconds: "),
        "{message}"
    );
    assert!(!message.contains("was told to stop"), "{message}");
    assert!(
        message.ends_with("Run kr host stop again in a moment."),
        "{message}"
    );
    daemon.end();
}

/// KR-REQ-07.12 (a request that could not be made): a daemon that answers the look and closes the
/// connection leaves the command unable to make its request. Nothing was sent, so the result is
/// `not_asked`, with the text of its own, no wait for an end and no record; the exit is the
/// failure's (3). The daemon here stays and answers at its endpoint, which is what tells it from
/// one that has ended. It received `host.info` exactly twice, once from the command and once from
/// the command's one look at the endpoint: a command that made no look would have sent it once,
/// and one that waited would have looked again and again.
#[test]
fn a_request_that_could_not_be_made_is_not_asked_and_nothing_is_waited_for() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::CloseAfterTheLook,
        true,
    );
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert_eq!(output.status.code(), Some(3), "{said}");
    assert_eq!(stop_of(&said), "not_asked", "{said}");
    let message = said["message"].as_str().expect("a message");
    assert!(
        message.starts_with(
            "kr host stop could not make its request for the control daemon of environment "
        ),
        "{message}"
    );
    assert!(
        message.ends_with(". Nothing was sent, and nothing was stopped."),
        "{message}"
    );
    let received = daemon.received();
    assert!(
        !received.iter().any(|method| method == "host.stop"),
        "no request to stop left: {received:?}"
    );
    assert_eq!(
        received
            .iter()
            .filter(|method| *method == "host.info")
            .count(),
        2,
        "the command asked once and looked once, and waited for nothing: {received:?}"
    );
    assert!(attempts(&host).is_empty(), "no record stands");
    daemon.end();
}

/// KR-REQ-07.12 (a request that could not be made because the daemon ended): a daemon that answers
/// the look, closes the connection and stops listening has ended when the command comes to make
/// its request, as one does whose stop another command has taken. The result is the end's: exit 0,
/// `ended`, a sentence that says it ended and that this command sent nothing, no request sent and
/// no record.
#[test]
fn a_request_that_could_not_be_made_because_the_daemon_ended_is_the_daemons_end() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::CloseAfterTheLookAndEnd,
        true,
    );
    let output = start(host.kr(&["--json", "host", "stop"])).finish("kr host stop");
    let said = document(&output, "kr host stop");
    assert_eq!(output.status.code(), Some(0), "{said}");
    assert_eq!(stop_of(&said), "ended", "{said}");
    assert!(said["unsettled"].is_null(), "{said}");
    let text = start(host.kr(&["host", "stop"])).finish("kr host stop");
    assert!(text.status.success(), "no daemon runs now");
    assert!(
        !daemon.received().iter().any(|method| method == "host.stop"),
        "no request to stop left: {:?}",
        daemon.received()
    );
    assert!(attempts(&host).is_empty(), "no record stands");
    daemon.end();
}

/// The text of the same result, without `--json`: the daemon ended, why the request could not be
/// made, and that this command sent nothing.
#[test]
fn the_end_of_a_daemon_that_closed_before_the_request_says_that_nothing_was_sent() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::CloseAfterTheLookAndEnd,
        true,
    );
    let output = start(host.kr(&["host", "stop"])).finish("kr host stop");
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{out}");
    assert!(
        out.starts_with("The control daemon for environment "),
        "{out}"
    );
    assert!(
        out.contains(" ended, and this command could not make its request for it: "),
        "{out}"
    );
    assert!(
        out.trim_end().ends_with("This command sent nothing."),
        "{out}"
    );
    daemon.end();
}

/// KR-REQ-07.12 (a daemon that closed the connection and goes): a daemon that answers the look,
/// closes the connection and goes on answering until two looks have followed its close is waited
/// for to its end, and the command ends 0 with a sentence of its own. This case does not choose
/// the path to that end, because a process cannot: where the close has reached the command when it
/// composes its request, it makes no request and says so; where the command composed first it sent
/// its request into the closed connection and waits for the daemon as one that may have taken it,
/// and says that the daemon did not show whether it took the stop and that it has ended.
/// So the case takes the sentence that its run came to, from the sentence itself, and holds what is
/// true of the path it names: the unmade request's own sentence and no line that says a request
/// was asked, or the end of a daemon whose outcome was not shown; no request reached the daemon; no record stands; and the
/// daemon had answered both looks and stopped listening, which a command that took a daemon that
/// still answers for one that had ended could not have waited for, since it looks once. It can
/// miss a fault of the closed-connection branch on a run that composed first, which the unit cases
/// of the stop's decision hold.
#[test]
fn a_daemon_that_closed_the_connection_and_goes_is_waited_for_to_its_end_whichever_path_is_taken() {
    let Some(host) = Standalone::create() else {
        return;
    };
    let mut daemon = TestDaemon::serve(
        &host,
        "kr-controller/9.9.9",
        OnStop::CloseAndEndAfterTwoLooks,
        true,
    );
    let output = start(host.kr(&["host", "stop"])).finish("kr host stop");
    let out = String::from_utf8_lossy(&output.stdout);
    let said = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{out} {said}");
    if out.contains("did not show whether it took the stop") && out.contains("and it has ended") {
        // The request that was made into the closed connection: not answered, and the daemon ended.
        assert!(
            out.starts_with("The control daemon for environment "),
            "neither path's sentence: {out}"
        );
    } else if out.starts_with("The control daemon for environment ") {
        // The unmade request.
        assert!(
            out.contains(" ended, and this command could not make its request for it: "),
            "{out}"
        );
        assert!(
            out.trim_end().ends_with("This command sent nothing."),
            "{out}"
        );
        assert!(!said.contains("Asked the control daemon"), "{said}");
    } else {
        // The request that was made into the closed connection, and answered.
        assert!(
            out.starts_with("Stopped the control daemon for environment "),
            "neither path's sentence: {out}"
        );
    }
    assert!(
        !daemon.received().iter().any(|method| method == "host.stop"),
        "no request to stop reached the daemon: {:?}",
        daemon.received()
    );
    assert!(
        daemon.stopped_listening_at().is_some(),
        "the command ended before the daemon had answered two looks after its close: {out}"
    );
    assert!(attempts(&host).is_empty(), "no record stands");
    daemon.end();
}
