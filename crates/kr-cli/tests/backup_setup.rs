//! `kr backup setup`, against a real control daemon, the storage service stand-in and the real `kr`
//! binary on a pseudo-terminal.
//!
//! KR-REQ-20.14, KR-REQ-20.15, KR-REQ-20.18, KR-REQ-24.16 and KR-ACC-033: the owner's command makes
//! the recovery seed in its own process, shows the kit once, and gives the daemon what it needs to
//! write the bundle, enrol the host's writer and record the setup, and nothing that opens a backup.
//! Everything but the service is real. The service is the stand-in (`kr-service-stand-in`), which
//! answers as the deployed Worker does and is held to a recording of it.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_client::recovery::{kit_fingerprint, parse_kit};
use kr_client::services::ServiceFuture;
use kr_client::services::account::{
    AccountIdentity, AccountService, AccountToken, AccountUsage, AuthorisationGrant, Exchanged,
    IssuedGrant, RefreshToken, Refreshed, StoredGrant,
};
use kr_controller::account::{HostAccount, Service};
use kr_controller::quiet::Timer;
use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_controller::testing::HeldTimer;
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::paths::Endpoint;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::backup_setup::{BackupSetupState, BackupStatusParams, BackupStatusResult};
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_service_stand_in::{Moment, Served, TOKEN, serve};

mod support;

use support::kr;

/// How long a wait for something to happen is given. It fails when the thing never happens.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// Where the stand-in is asked to write and read the recovery bundle.
const SYNC: &str = "/api/sync/exchange";

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/* -------------------------------------------------------------------------- */
/* A host and its daemon                                                       */
/* -------------------------------------------------------------------------- */

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

/// The account service of a host that is signed in before its daemon starts: the seeding keeps a
/// grant and asks the service nothing.
#[derive(Debug)]
struct NeverAsked;

fn never_asked<T>() -> ServiceFuture<'static, T> {
    Box::pin(async {
        Err(kr_client::ClientError::refusal(
            kr_protocol::error::ErrorCode::ResourceUnavailable,
            kr_client::shown::Shown::said("this stand-in is never asked"),
        ))
    })
}

impl AccountService for NeverAsked {
    fn exchange<'a>(&'a self, _grant: &'a AuthorisationGrant) -> ServiceFuture<'a, Exchanged> {
        never_asked()
    }

    fn refresh<'a>(&'a self, _stored: &'a StoredGrant) -> ServiceFuture<'a, Refreshed> {
        never_asked()
    }

    fn revoke<'a>(&'a self, _refresh: &'a RefreshToken) -> ServiceFuture<'a, ()> {
        never_asked()
    }

    fn identity<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountIdentity> {
        never_asked()
    }

    fn usage<'a>(&'a self, _access: &'a AccountToken) -> ServiceFuture<'a, AccountUsage> {
        never_asked()
    }
}

/// A host signed in to the stand-in's account, with its daemon, and directories of its own for the
/// commands it runs.
struct Rig {
    temp: kr_ipc::testing::TempHost,
    served: Served,
    endpoint: Endpoint,
    _controller: Arc<Controller>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::error::Result<()>>>,
    work: PathBuf,
    home: PathBuf,
}

impl Drop for Rig {
    fn drop(&mut self) {
        for task in &self.serving {
            task.abort();
        }
    }
}

impl Rig {
    async fn start() -> Self {
        let served = serve().await;
        let temp = kr_ipc::testing::TempHost::create();
        let work = temp.root().join("w");
        let home = temp.root().join("h");
        for directory in [&work, &home] {
            std::fs::create_dir(directory).expect("a directory on the internal disk");
        }
        write_document(&temp, served.origin());
        keep_sign_in(&temp, served.origin()).await;
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        environment.create().expect("the environment's directories");
        let secrets = environment.secrets_dir();
        let timer = HeldTimer::automatic();
        let origin = served.origin().to_owned();
        let controller = kr_controller::testing::taken_over(|| {
            let secrets = secrets.clone();
            kr_controller::testing::with_account_origin(
                Some(origin.clone()),
                Controller::start_on_timer(
                    ControllerSetup {
                        paths: environment.clone(),
                        environment_id,
                        identity: Box::new(move || {
                            let store = open_store_in(&secrets)
                                .expect("a secret store for the test environment");
                            Ok(ControllerIdentity::open(
                                store.store.as_ref(),
                                environment_id,
                                false,
                            )
                            .expect("an identity"))
                        }),
                        secret_store: StoreSelection::File,
                        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
                        supervisor: Box::new(NoWorkers),
                        worker_program: PathBuf::from("/nonexistent/kr-worker"),
                        build_id: build(),
                        release: "0".to_owned(),
                        shell_packages: None,
                        terminal: Box::new(kr_controller::supervision::NoTerminal),
                    },
                    Arc::clone(&timer) as Arc<dyn Timer>,
                ),
            )
        })
        .await
        .unwrap_or_else(|error| panic!("the daemon starts: {error}"));
        let endpoint = environment.controller_endpoint().expect("an endpoint");
        let clients = Listener::bind(&endpoint).expect("binds the client endpoint");
        let serving = vec![tokio::spawn(Arc::clone(&controller).serve_clients(clients))];
        Self {
            temp,
            served,
            endpoint,
            _controller: controller,
            serving,
            work,
            home,
        }
    }

    fn origin(&self) -> &str {
        self.served.origin()
    }

    /// The requests the stand-in has been given for `path`.
    fn requests_to(&self, path: &str) -> usize {
        self.served.web().requests_to(path)
    }

    /// The environment every `kr` this test runs is given: this host's directories, a home of its
    /// own, and nothing of the person running the test.
    fn variables(&self) -> Vec<(&'static str, String)> {
        vec![
            ("PATH", "/usr/bin:/bin".to_owned()),
            ("TERM", "xterm-256color".to_owned()),
            ("HOME", self.home.display().to_string()),
            (
                "KR_RUNTIME_DIR",
                self.temp.paths().runtime_root().display().to_string(),
            ),
            (
                "KR_STATE_DIR",
                self.temp.paths().state_root().display().to_string(),
            ),
        ]
    }

    /// Runs `kr` with `line` and waits for it. Its standard input is empty and its output is a
    /// pipe, so it is not at a terminal.
    fn run(&self, line: &[&str]) -> std::process::Output {
        std::process::Command::new(kr())
            .args(line)
            .env_clear()
            .envs(self.variables())
            .current_dir(&self.work)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("kr runs")
    }

    /// `backup.status`, as the command asks it.
    async fn status(&self) -> BackupStatusResult {
        let mut client = LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        client
            .request(Method::BackupStatus, &BackupStatusParams {})
            .await
            .expect("the call reaches the daemon")
            .expect("backup.status is served on the local socket")
            .to_typed()
            .expect("a result of the declared shape")
    }

    /// The fingerprint of the setup the daemon records, when it records one.
    async fn recorded_kit(&self) -> Option<String> {
        match self.status().await.setup {
            BackupSetupState::Committed {
                kit_fingerprint, ..
            } => Some(kit_fingerprint),
            BackupSetupState::None {} | BackupSetupState::InProgress { .. } => None,
        }
    }
}

fn write_document(host: &kr_ipc::testing::TempHost, origin: &str) {
    let environment = host.environment();
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 1;
    document.storage.origin = Nullable::some(origin.to_owned());
    let path = kr_worker::config::document_path(&environment);
    std::fs::create_dir_all(path.parent().expect("a state directory")).expect("the directory");
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("the document");
}

/// Keeps a sign-in in the secret store the daemon will open, as a finished browser sign-in leaves
/// one.
async fn keep_sign_in(host: &kr_ipc::testing::TempHost, origin: &str) {
    let environment = host.environment();
    let store = open_store_in(&environment.secrets_dir()).expect("the daemon's secret store");
    let account = HostAccount::new(
        Arc::from(store.store),
        host.environment_id(),
        environment.runtime_root(),
        Ok(Service {
            origin: origin.to_owned(),
            scopes: Vec::new(),
            account: Arc::new(NeverAsked),
            closed: None,
        }),
        None,
    );
    account
        .keep_for_test(IssuedGrant {
            access_token: AccountToken::new(TOKEN).expect("a token"),
            expires_in_seconds: 3600,
            refresh_token: RefreshToken::new("a-refresh-token").expect("a token"),
            scopes: ["openid", "voice", "backup.write"]
                .iter()
                .map(|scope| (*scope).to_owned())
                .collect(),
            subject: "account-1".to_owned(),
        })
        .await;
}

/* -------------------------------------------------------------------------- */
/* A terminal window                                                           */
/* -------------------------------------------------------------------------- */

/// A terminal window `kr` runs in, with the person's side of it: what the window has shown, and a
/// way to type.
struct Window {
    terminal: portable_pty::PtyPair,
    shell: Box<dyn portable_pty::Child + Send + Sync>,
    typing: Box<dyn Write + Send>,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Drop for Window {
    fn drop(&mut self) {
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

impl Window {
    /// Opens a window whose shell runs `kr` with `arguments`, prints the status it ended with, and
    /// then reads one line of its own, so a test can tell whether anything was left waiting in the
    /// terminal's input.
    fn run(rig: &Rig, arguments: &[&str]) -> Self {
        Self::run_with(rig, arguments, &[])
    }

    /// As [`Self::run`], with more variables in the command's environment.
    fn run_with(rig: &Rig, arguments: &[&str], more: &[(&str, &str)]) -> Self {
        let terminal = portable_pty::native_pty_system()
            .openpty(portable_pty::PtySize {
                rows: 24,
                cols: 200,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("opens a terminal");
        let mut command = portable_pty::CommandBuilder::new("/bin/sh");
        command.arg("-c");
        // The shell ignores the interrupt a Ctrl-C raises, so that it outlives the command it runs
        // and the test can read what the command left; `kr` installs its own handler.
        command.arg(
            "trap '' INT; \"$KR\" \"$@\"; echo \"kr ended $?\"; IFS= read -r first; echo \"first:$first\"",
        );
        command.arg("sh");
        for argument in arguments {
            command.arg(argument);
        }
        command.env_clear();
        for (name, value) in rig.variables() {
            command.env(name, value);
        }
        for (name, value) in more {
            command.env(name, value);
        }
        command.env("KR", kr().display().to_string());
        command.cwd(&rig.work);
        let typing = terminal.master.take_writer().expect("a writer");
        let shell = terminal
            .slave
            .spawn_command(command)
            .expect("starts the window's shell");
        let mut reader = terminal.master.try_clone_reader().expect("a reader");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                collected
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(&buffer[..read]);
            }
        });
        Self {
            terminal,
            shell,
            typing,
            seen,
        }
    }

    /// What the window has shown so far, with the terminal's own line endings made plain.
    fn shown(&self) -> String {
        String::from_utf8_lossy(&self.seen.lock().unwrap_or_else(PoisonError::into_inner))
            .replace("\r\n", "\n")
    }

    /// Waits until the window has shown `marker`, and returns what it has shown. It fails when it
    /// never does.
    fn wait_for(&self, marker: &str) -> String {
        let started = Instant::now();
        loop {
            let shown = self.shown();
            if shown.contains(marker) {
                return shown;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the window never showed {marker:?}: {}",
                shown.escape_debug()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits until the window has shown `marker` `count` times. A question is shown again after
    /// each wrong answer, and an answer typed before it is shown again is thrown away.
    fn wait_for_nth(&self, marker: &str, count: usize) -> String {
        let started = Instant::now();
        loop {
            let shown = self.shown();
            if shown.matches(marker).count() >= count {
                return shown;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the window never showed {marker:?} {count} times: {}",
                shown.escape_debug()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Types bytes as they are.
    fn type_bytes(&mut self, bytes: &[u8]) {
        self.typing
            .write_all(bytes)
            .and_then(|()| self.typing.flush())
            .expect("types into the window");
    }

    /// Types one line, as a person does.
    fn type_line(&mut self, line: &str) {
        self.type_bytes(format!("{line}\n").as_bytes());
    }

    /// Whether the terminal echoes what is typed, as its modes say now.
    fn echoes(&self) -> bool {
        use std::os::unix::fs::OpenOptionsExt as _;

        let name = self
            .terminal
            .master
            .tty_name()
            .expect("the terminal's name");
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOCTTY)
            .open(name)
            .expect("the terminal opens");
        rustix::termios::tcgetattr(&tty)
            .expect("the terminal's modes")
            .local_modes
            .contains(rustix::termios::LocalModes::ECHO)
    }

    /// Answers the plan and brings the dialogue to the question about the end of the seed. Returns
    /// the kit it showed.
    fn bring_up_the_kit(&mut self) -> Kit {
        self.wait_for("Type yes to go on");
        self.type_line("yes");
        let shown = self.wait_for("type the last 8 symbols of its seed line");
        Kit::of(&shown)
    }

    /// Types the end of the kit's seed, in the case and with the dashes a person may use, and says
    /// that the kit is stored.
    fn confirm(&mut self, kit: &Kit) {
        self.type_line(&kit.end_as_typed());
        self.wait_for("Type yes when the kit is stored");
        self.type_line("yes");
    }
}

/// The kit as the window showed it.
struct Kit {
    text: String,
}

impl Kit {
    /// Takes the kit out of what the window showed: from its format line to its last origin line.
    fn of(shown: &str) -> Self {
        let start = shown
            .find("kalareach-recovery-kit/1")
            .expect("the kit is shown");
        let rest = &shown[start..];
        let last_origin = rest.rfind("origin: ").expect("the kit names an origin");
        let end = last_origin + rest[last_origin..].find('\n').expect("a line end");
        Self {
            text: format!("{}\n", &rest[..end]),
        }
    }

    fn seed_line(&self) -> &str {
        self.text
            .lines()
            .find_map(|line| line.strip_prefix("seed: "))
            .expect("a seed line")
    }

    /// The last eight symbols of the seed line, in lower case, grouped as printed.
    fn end_as_typed(&self) -> String {
        let symbols: String = self.seed_line().chars().filter(|c| *c != '-').collect();
        let end = &symbols[symbols.len() - 8..];
        format!("{}-{}", &end[..4], &end[4..]).to_lowercase()
    }

    /// The fingerprint the kit's seed gives the recovery recipient.
    fn fingerprint(&self) -> String {
        let kit = parse_kit(&self.text).expect("the kit shown is a recovery kit");
        let seed = RecoverySeed::from_kit(&kit).expect("the checksum holds");
        kit_fingerprint(seed.recipient().expect("a recipient").public())
    }

    fn locator(&self) -> &str {
        self.text
            .lines()
            .find_map(|line| line.strip_prefix("locator: "))
            .expect("a locator line")
    }
}

/// The fingerprint a window printed.
fn printed_fingerprint(shown: &str) -> String {
    shown
        .lines()
        .find_map(|line| line.strip_prefix("Kit fingerprint: "))
        .expect("a fingerprint is printed")
        .trim()
        .to_owned()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Every file below `root`, by relative path.
fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, at: &Path, into: &mut BTreeMap<String, Vec<u8>>) {
        let Ok(entries) = std::fs::read_dir(at) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(root, &path, into);
            } else if let Ok(bytes) = std::fs::read(&path) {
                into.insert(
                    path.strip_prefix(root)
                        .expect("below the root")
                        .display()
                        .to_string(),
                    bytes,
                );
            }
        }
    }
    let mut found = BTreeMap::new();
    walk(root, root, &mut found);
    found
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/* -------------------------------------------------------------------------- */
/* The setup                                                                   */
/* -------------------------------------------------------------------------- */

/// The whole run, at a terminal: the plan, the kit shown once, the end of the seed typed back in
/// the case and with the dashes a person may use, the word yes. The kit that was shown is the kit a
/// restore reads, its fingerprint is the one the host records and `kr doctor` shows, and the
/// service holds a bundle at the kit's place that the kit's seed opens. What the daemon was given
/// carries nothing that opens a backup: not the seed's bytes, not its printed symbols, not the kit,
/// not the bundle's key; and no file of the host holds them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_kit_that_setup_shows_is_the_one_the_host_records_and_the_daemon_is_given_no_seed() {
    let rig = Rig::start().await;
    kr_controller::testing::tap_backup_enable(rig.temp.environment_id());
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    assert_eq!(
        kit.text.lines().next(),
        Some("kalareach-recovery-kit/1"),
        "{}",
        kit.text
    );
    window.confirm(&kit);
    let shown = window.wait_for("kr ended 0");
    assert!(shown.contains("Backups are set up."), "{shown}");

    // The kit is a kit: it parses, its checksum holds and it names the service as the daemon holds
    // it, byte for byte.
    let parsed = parse_kit(&kit.text).expect("the kit shown is a recovery kit");
    assert_eq!(parsed.service_origins, [rig.origin().to_owned()]);
    // The fingerprint printed is the kit's, the daemon's and the doctor's.
    let fingerprint = kit.fingerprint();
    assert_eq!(printed_fingerprint(&shown), fingerprint);
    assert_eq!(rig.recorded_kit().await, Some(fingerprint.clone()));
    let doctor = rig.run(&["doctor", "--json"]);
    assert!(
        text(&doctor.stdout).contains(&format!("set up with the kit {fingerprint}")),
        "{}",
        text(&doctor.stdout)
    );
    // The bundle is where the kit says, and the kit's seed opens it.
    let sealed = rig
        .served
        .web()
        .bundle(kit.locator())
        .expect("the service holds the bundle");
    let seed = RecoverySeed::from_kit(&parsed).expect("the checksum holds");
    let context = parsed
        .context(rig.origin())
        .expect("the kit names the origin");
    let key = seed.bundle_key_for(&context).expect("a key");
    let bundle = kr_crypto::archive::decrypt_recovery_bundle(&key, &sealed)
        .expect("the bundle opens under the kit");
    assert_eq!(bundle.trusted_writers.len(), 1);
    assert_eq!(bundle.trusted_producers.len(), 1);

    // What the daemon was given, as it arrived.
    let calls = kr_controller::testing::tapped_backup_enable(rig.temp.environment_id());
    assert_eq!(calls.len(), 1, "one call reached the daemon");
    let symbols: String = kit.seed_line().chars().filter(|c| *c != '-').collect();
    let hidden: Vec<(&str, Vec<u8>)> = vec![
        ("the seed's bytes", parsed.seed.expose().to_vec()),
        ("the seed as printed", kit.seed_line().as_bytes().to_vec()),
        ("the seed's symbols", symbols.as_bytes().to_vec()),
        ("the kit's text", kit.text.as_bytes().to_vec()),
        ("the bundle's key", key.expose().to_vec()),
    ];
    for (name, value) in &hidden {
        assert!(!contains(&calls[0], value), "the call carries {name}");
    }
    assert!(
        contains(&calls[0], &sealed),
        "the tap sees the bundle the daemon was given, so its search is not empty"
    );
    // Nor does any file of the host.
    for (name, bytes) in tree(rig.temp.root()) {
        for (what, value) in &hidden {
            assert!(!contains(&bytes, value), "{name} holds {what}");
        }
    }
}

/// Typed at the question about the end of the seed three times wrongly, or with the end right and
/// anything but yes at the question after it, the command ends and nothing has been sent to the
/// service or recorded by the host. It says that the kit it showed opens nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_end_of_the_seed_or_an_answer_but_yes_sets_nothing_up() {
    let rig = Rig::start().await;

    let mut window = Window::run(&rig, &["backup", "setup"]);
    window.bring_up_the_kit();
    for tries in 1..=3 {
        window.type_line("AAAAAAAA");
        if tries < 3 {
            window.wait_for_nth("type the last 8 symbols of its seed line", tries + 1);
        }
    }
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(shown.contains("opens nothing"), "{shown}");

    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    window.type_line(&kit.end_as_typed());
    window.wait_for("Type yes when the kit is stored");
    window.type_line("no");
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(shown.contains("opens nothing"), "{shown}");

    assert_eq!(rig.requests_to(SYNC), 0, "no bundle was written");
    assert_eq!(rig.recorded_kit().await, None);
    assert!(matches!(
        rig.status().await.setup,
        BackupSetupState::None {}
    ));
}

/// Text pasted after the last answer never reaches the shell the command was run from: the
/// command puts the terminal back with the input still waiting discarded, so the next thing the
/// shell reads is the next thing typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn text_pasted_past_the_last_answer_never_reaches_the_shell() {
    let rig = Rig::start().await;
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    window.type_line(&kit.end_as_typed());
    window.wait_for("Type yes when the kit is stored");
    // More than the command reads at once, so some of it is still in the terminal's queue when the
    // command ends.
    let after = "PASTED-AFTER-THE-ANSWER\n".repeat(25);
    window.type_bytes(format!("yes\n{after}").as_bytes());
    window.wait_for("kr ended 0");
    window.type_line("marker");
    let shown = window.wait_for("first:");
    assert!(shown.contains("first:marker"), "{}", shown.escape_debug());
}

/// The command is refused where a kit must not be shown or the call cannot be answered, and each
/// refusal comes before anything is made or sent: inside a session, whose worker keeps its output;
/// without a terminal; with `--json`, which a dialogue has no form for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setup_is_refused_inside_a_session_without_a_terminal_and_as_json() {
    let rig = Rig::start().await;

    let window = Window::run_with(
        &rig,
        &["backup", "setup"],
        &[("KR_SESSION", "00000000-0000-4000-8000-000000000001")],
    );
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(shown.contains("KR_SESSION"), "{shown}");
    assert!(!shown.contains("kalareach-recovery-kit"), "{shown}");

    let output = rig.run(&["backup", "setup"]);
    assert!(!output.status.success());
    assert!(
        text(&output.stderr).contains("needs a terminal"),
        "{}",
        text(&output.stderr)
    );

    let output = rig.run(&["backup", "setup", "--json"]);
    assert!(!output.status.success());
    let said = format!("{}{}", text(&output.stdout), text(&output.stderr));
    assert!(said.contains("no --json form"), "{said}");

    assert_eq!(rig.requests_to(SYNC), 0);
    assert_eq!(rig.recorded_kit().await, None);
}

/// A refusal the person can mend, here an account with no allowance, says that the kit opens
/// nothing yet and offers the same kit again. Once it is mended, `retry` sets the host up with the
/// kit that was shown first, and no second kit is shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_a_person_can_mend_is_followed_by_the_same_kit_offered_again() {
    let rig = Rig::start().await;
    rig.served.web().refuse_bundle_writes(true);
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    window.confirm(&kit);
    let shown = window.wait_for("type retry to use the same kit again");
    assert!(shown.contains("no allowance"), "{shown}");
    assert_eq!(rig.recorded_kit().await, None, "nothing is recorded");
    assert!(rig.served.web().bundle(kit.locator()).is_none());

    rig.served.web().refuse_bundle_writes(false);
    window.type_line("retry");
    let shown = window.wait_for("kr ended 0");
    assert_eq!(
        shown.matches("kalareach-recovery-kit/1").count(),
        1,
        "the kit is shown once"
    );
    assert_eq!(rig.recorded_kit().await, Some(kit.fingerprint()));
    assert!(rig.served.web().bundle(kit.locator()).is_some());
}

/// An answer the daemon could not give is asked for again with the same bytes: a bundle written
/// whose answer was lost, and a read that settles it that fails too, is no reason for a second kit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_whose_outcome_is_unknown_is_repeated_and_finishes() {
    let rig = Rig::start().await;
    rig.served.web().fail(SYNC, 1, Moment::After);
    rig.served.web().fail(SYNC, 2, Moment::Before);
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    window.confirm(&kit);
    let shown = window.wait_for("kr ended 0");
    assert_eq!(shown.matches("kalareach-recovery-kit/1").count(), 1);
    assert_eq!(rig.recorded_kit().await, Some(kit.fingerprint()));
}

/// An outcome that stays unknown after the repeats says to keep the kit, and what settles it. The
/// host records nothing here: the first line says only what `kr doctor` will show.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_outcome_that_stays_unknown_says_to_keep_the_kit_until_the_doctor_settles_it() {
    let rig = Rig::start().await;
    for nth in 1..=40 {
        rig.served.web().fail(SYNC, nth, Moment::Before);
    }
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    window.confirm(&kit);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(shown.contains("Keep the kit"), "{shown}");
    assert!(shown.contains(&kit.fingerprint()), "{shown}");
    assert!(shown.contains("kr doctor"), "{shown}");
    assert_eq!(rig.recorded_kit().await, None);
}

/// A host that is set up is not set up again without `--replace`, and says which kit is in use.
/// `--replace` shows what it replaces, sets the host up under a new kit, and leaves the earlier
/// archive's bundle at the service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn setting_up_again_needs_replace_and_a_replacement_changes_the_kit() {
    let rig = Rig::start().await;
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let first = window.bring_up_the_kit();
    window.confirm(&first);
    window.wait_for("kr ended 0");
    let first_fingerprint = first.fingerprint();
    assert_eq!(rig.recorded_kit().await, Some(first_fingerprint.clone()));

    let window = Window::run(&rig, &["backup", "setup"]);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(shown.contains(&first_fingerprint), "{shown}");
    assert!(shown.contains("--replace"), "{shown}");
    assert!(!shown.contains("kalareach-recovery-kit/1"), "{shown}");

    let mut window = Window::run(&rig, &["backup", "setup", "--replace"]);
    let second = window.bring_up_the_kit();
    window.confirm(&second);
    let shown = window.wait_for("kr ended 0");
    assert!(
        shown.contains(&format!(
            "Replacing the setup whose kit fingerprint is {first_fingerprint}"
        )),
        "{shown}"
    );
    let second_fingerprint = second.fingerprint();
    assert_ne!(first_fingerprint, second_fingerprint);
    assert_eq!(rig.recorded_kit().await, Some(second_fingerprint));
    assert!(rig.served.web().bundle(first.locator()).is_some());
    assert!(rig.served.web().bundle(second.locator()).is_some());
}

/// Ctrl-C at a question ends the command with the terminal as it was found and nothing sent: at the
/// plan nothing was shown, and after the kit was shown the kit opens nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_at_a_question_sets_nothing_up_and_puts_the_terminal_back() {
    let rig = Rig::start().await;

    let mut window = Window::run(&rig, &["backup", "setup"]);
    window.wait_for("Type yes to go on");
    window.type_bytes(&[0x03]);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(shown.contains("Nothing was set up."), "{shown}");
    assert!(window.echoes(), "echo is on");
    assert!(!shown.contains("kalareach-recovery-kit"), "{shown}");

    let mut window = Window::run(&rig, &["backup", "setup"]);
    window.bring_up_the_kit();
    window.type_bytes(&[0x03]);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(shown.contains("opens nothing"), "{shown}");
    assert!(window.echoes(), "echo is on");

    assert_eq!(rig.requests_to(SYNC), 0);
    assert_eq!(rig.recorded_kit().await, None);
}
