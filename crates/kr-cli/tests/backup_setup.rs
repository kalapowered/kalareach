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
use kr_controller::backup::store::{Production, Remote};
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
use kr_protocol::ids::{ArchiveId, BackupGeneration, BuildId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_service_stand_in::{Moment, Served, TOKEN, serve};
use serde_json::Value;

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
    served: Arc<Served>,
    endpoint: Endpoint,
    controller: Arc<Controller>,
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
        Self::start_at(Arc::new(serve().await), |_| {}).await
    }

    /// A host that stands before its daemon starts as `prepare` leaves it.
    async fn start_with(prepare: impl FnOnce(&kr_ipc::testing::TempHost)) -> Self {
        Self::start_at(Arc::new(serve().await), prepare).await
    }

    /// A host configured for `served`, which may hold the backups of another host.
    async fn start_at(
        served: Arc<Served>,
        prepare: impl FnOnce(&kr_ipc::testing::TempHost),
    ) -> Self {
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
        prepare(&temp);
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
            controller,
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

    /// Whether the daemon's record shows `generation` of `archive` as made and published.
    fn published(&self, archive: ArchiveId, generation: u64) -> bool {
        self.controller
            .backup()
            .generation(archive, BackupGeneration::new(generation))
            .expect("the store reads")
            .is_some_and(|record| {
                record.production == Production::Complete && record.remote == Remote::Published
            })
    }

    /// Waits until `generation` of `archive` is published, looking again each time the daemon
    /// finishes a pass.
    async fn until_published(&self, archive: ArchiveId, generation: u64) {
        self.until_published_within(archive, generation, LIVENESS_DEADLINE)
            .await;
    }

    /// As [`Self::until_published`], with a deadline of the caller's.
    async fn until_published_within(
        &self,
        archive: ArchiveId,
        generation: u64,
        deadline: Duration,
    ) {
        let mut passes = self
            .controller
            .backup_runtime()
            .expect("a carrier")
            .passes();
        tokio::time::timeout(deadline, async {
            while !self.published(archive, generation) {
                passes.changed().await.expect("the carrier is running");
            }
        })
        .await
        .unwrap_or_else(|_| panic!("generation {generation} was never published"));
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
            // Long enough that a slow run is not ended by a token that nothing here can renew.
            expires_in_seconds: 86_400,
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
    // The bundle is where the kit says.
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
    // The bundle the daemon was given is the one the kit's seed opens.
    let bundle = kr_crypto::archive::decrypt_recovery_bundle(&key, &sealed)
        .expect("the bundle opens under the kit");
    assert_eq!(bundle.trusted_writers.len(), 1);
    assert_eq!(bundle.trusted_producers.len(), 1);
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
    let said = shown
        .rsplit_once("How the setup ended is not known.")
        .expect("the ending is said")
        .1;
    assert!(said.contains("Keep the kit"), "{said}");
    assert!(said.contains(&kit.fingerprint()), "{said}");
    assert!(said.contains("kr doctor"), "{said}");
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

/// Ctrl-C while the daemon has the call says to keep the kit, and the kit is in use: the daemon
/// records the setup after the command has gone. A command that told the person to delete the kit
/// here would have them delete the only way to read these backups.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_while_the_daemon_has_the_call_says_to_keep_the_kit() {
    let rig = Rig::start().await;
    let (arrived, go) = rig.controller.backup().pause_the_next_setup_commit();
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    window.confirm(&kit);
    tokio::task::spawn_blocking(move || arrived.recv_timeout(LIVENESS_DEADLINE))
        .await
        .expect("the wait ends")
        .expect("the commit is on its thread");

    window.type_bytes(&[0x03]);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    // The kit was printed with its fingerprint above; what the interrupt says is what follows it.
    let said = shown
        .rsplit_once("The command stopped while the setup was under way")
        .expect("the interrupt is said")
        .1;
    assert!(said.contains("Keep the kit"), "{said}");
    assert!(said.contains(&kit.fingerprint()), "{said}");
    assert!(!shown.contains("Nothing was set up"), "{shown}");
    assert!(!shown.contains("opens nothing: delete it"), "{shown}");
    assert!(window.echoes(), "echo is on");

    go.send(()).expect("the commit is waiting");
    tokio::time::timeout(LIVENESS_DEADLINE, async {
        while rig.recorded_kit().await.is_none() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the daemon records the setup the command stopped waiting for");
    assert_eq!(rig.recorded_kit().await, Some(kit.fingerprint()));
}

/// Ctrl-C while the daemon has the call of a replacement names the earlier kit as the only one
/// whose fingerprint in `kr doctor` voids the new kit, because the new setup may be made and then
/// replaced by another before the person looks: a kit that opens nothing is the earlier setup
/// standing, and any other fingerprint is a reason to keep the new kit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_during_a_replacement_voids_the_new_kit_only_by_the_earlier_fingerprint() {
    let rig = Rig::start().await;
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let first = window.bring_up_the_kit();
    window.confirm(&first);
    window.wait_for("kr ended 0");
    let first_fingerprint = first.fingerprint();

    let (arrived, go) = rig.controller.backup().pause_the_next_setup_commit();
    let mut window = Window::run(&rig, &["backup", "setup", "--replace"]);
    let second = window.bring_up_the_kit();
    window.confirm(&second);
    tokio::task::spawn_blocking(move || arrived.recv_timeout(LIVENESS_DEADLINE))
        .await
        .expect("the wait ends")
        .expect("the commit is on its thread");
    window.type_bytes(&[0x03]);
    let shown = window.wait_for("kr ended");
    let said = shown
        .rsplit_once("The command stopped while the setup was under way")
        .expect("the interrupt is said")
        .1;
    assert!(said.contains("Keep the kit"), "{said}");
    assert!(said.contains(&second.fingerprint()), "{said}");
    assert!(
        said.contains(&format!("earlier kit fingerprint {first_fingerprint}")),
        "{said}"
    );
    assert!(
        said.contains("any other fingerprint, keep the kit"),
        "{said}"
    );

    go.send(()).expect("the commit is waiting");
    tokio::time::timeout(LIVENESS_DEADLINE, async {
        while rig.recorded_kit().await != Some(second.fingerprint()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the replacement is recorded after the command has gone");
}

/// Ctrl-C while the command waits for a daemon that has accepted the connection and says nothing
/// ends the command at once, and says that nothing was set up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_while_the_daemon_says_nothing_ends_the_command_at_once() {
    let mut rig = Rig::start().await;
    for task in std::mem::take(&mut rig.serving) {
        task.abort();
        let _ = task.await;
    }
    let silent = Listener::bind(&rig.endpoint).expect("binds the endpoint");
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let _held = tokio::time::timeout(LIVENESS_DEADLINE, silent.accept())
        .await
        .expect("the command connects")
        .expect("accepts");
    window.type_bytes(&[0x03]);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    // The interrupt ended it, and not the ten seconds the connection is given.
    assert!(shown.contains("stopped before it finished"), "{shown}");
    assert_eq!(shown.matches("Nothing was set up.").count(), 1, "{shown}");
    assert!(window.echoes(), "echo is on");
}

/// As the case above, after the kit was shown and `yes` was typed: the call's own connection is the
/// one that waits. The interrupt is said once, and says that the kit opens nothing, because
/// nothing has been sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupt_while_the_daemon_says_nothing_to_the_call_is_said_once() {
    let mut rig = Rig::start().await;
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    for task in std::mem::take(&mut rig.serving) {
        task.abort();
        let _ = task.await;
    }
    let silent = Listener::bind(&rig.endpoint).expect("binds the endpoint");
    window.confirm(&kit);
    let _held = tokio::time::timeout(LIVENESS_DEADLINE, silent.accept())
        .await
        .expect("the command connects")
        .expect("accepts");
    window.type_bytes(&[0x03]);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(shown.contains("stopped before it finished"), "{shown}");
    assert_eq!(
        shown
            .matches("The kit that was shown opens nothing: delete it.")
            .count(),
        1,
        "{shown}"
    );
    assert_eq!(rig.requests_to(SYNC), 0, "nothing reached the service");
}

/// Two setups begun on one host: the one that finishes second is declined at its first try, which
/// recorded nothing, so its kit opens nothing and the host stays set up under the kit of the setup
/// that finished first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_setup_declined_at_its_first_try_because_another_finished_first_opens_nothing() {
    let rig = Rig::start().await;
    let mut slow = Window::run(&rig, &["backup", "setup"]);
    let slow_kit = slow.bring_up_the_kit();
    slow.type_line(&slow_kit.end_as_typed());
    slow.wait_for("Type yes when the kit is stored");

    let mut quick = Window::run(&rig, &["backup", "setup"]);
    let quick_kit = quick.bring_up_the_kit();
    quick.confirm(&quick_kit);
    quick.wait_for("kr ended 0");
    assert_eq!(rig.recorded_kit().await, Some(quick_kit.fingerprint()));

    // The slow window's kit was made before the other setup was recorded.
    slow.type_line("yes");
    let shown = slow.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(
        shown.contains("Nothing was set up. The kit that was shown opens nothing: delete it."),
        "{shown}"
    );
    // The plan above says to keep the kit and its fingerprint together; the unknown ending does not.
    assert!(!shown.contains("Keep the kit until kr doctor"), "{shown}");
    assert_eq!(rig.recorded_kit().await, Some(quick_kit.fingerprint()));
    assert_ne!(slow_kit.fingerprint(), quick_kit.fingerprint());
    // The decline came before the bundle was written: the service holds nothing for the slow kit.
    assert!(rig.served.web().bundle(slow_kit.locator()).is_none());
}

/// A first try whose answer is lost, and a repeat the daemon declines (here, an account with no
/// allowance): the first try may have recorded the setup, so the decline does not void the kit. The
/// command says to keep it until `kr doctor` settles it, and offers no `retry`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_decline_that_follows_a_lost_answer_says_to_keep_the_kit() {
    let rig = Rig::start().await;
    // The first write and the read that would settle it are lost; the repeat's write is refused for
    // want of an allowance. The faults count requests, so no delay decides which one it meets.
    rig.served.web().fail(SYNC, 1, Moment::Before);
    rig.served.web().fail(SYNC, 2, Moment::Before);
    rig.served.web().fail(
        SYNC,
        3,
        Moment::Refuse {
            status: 402,
            code: "QUOTA_EXHAUSTED",
            retry_after_seconds: None,
        },
    );
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    window.confirm(&kit);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    let said = shown
        .rsplit_once("The daemon declined the call")
        .expect("the decline is said")
        .1;
    assert!(said.contains("no allowance"), "{said}");
    assert!(
        said.contains("An earlier try of this call may have set backups up under this kit."),
        "{said}"
    );
    assert!(said.contains("Keep the kit"), "{said}");
    assert!(said.contains(&kit.fingerprint()), "{said}");
    assert!(!shown.contains("type retry"), "{shown}");
    assert!(!shown.contains("opens nothing: delete it"), "{shown}");
}

/// A daemon that cannot be reached when the call is to be made has been given nothing, so the kit
/// that was shown opens nothing. The call is made over a connection of its own: one kept from the
/// start of the dialogue would still reach the daemon here, and the setup would be made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_daemon_that_cannot_be_reached_when_the_call_is_made_has_been_given_nothing() {
    let mut rig = Rig::start().await;
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    for task in std::mem::take(&mut rig.serving) {
        task.abort();
        let _ = task.await;
    }
    window.confirm(&kit);
    let shown = window.wait_for("kr ended");
    assert!(!shown.contains("kr ended 0"), "{shown}");
    assert!(
        shown.contains("Nothing was set up. The kit that was shown opens nothing: delete it."),
        "{shown}"
    );
    assert_eq!(rig.requests_to(SYNC), 0, "nothing reached the service");
    assert!(window.echoes(), "echo is on");
}

/// A closed session the registry holds a closure for, with output in its spool, written into the
/// host's tree before its daemon starts.
fn closed_session(
    host: &kr_ipc::testing::TempHost,
    output: &[u8],
    closed_at_ms: u64,
) -> kr_protocol::ids::SessionId {
    closed_session_in(
        host,
        output,
        closed_at_ms,
        kr_worker::history::SpoolLayout::new(8, 1 << 20),
    )
}

/// As [`closed_session`], with the layout its spool is kept in.
fn closed_session_in(
    host: &kr_ipc::testing::TempHost,
    output: &[u8],
    closed_at_ms: u64,
    layout: kr_worker::history::SpoolLayout,
) -> kr_protocol::ids::SessionId {
    use kr_controller::registry::{LaunchPhase, Registry};
    use kr_protocol::ids::{ActorId, SessionEpoch};
    use kr_protocol::scalars::{Digest256, TimestampMs, U64};
    use kr_protocol::session::{ClosureReason, ClosureRecord, Durability, OwnershipCoverage};

    let mut registry = Registry::open(
        host.environment().registry_database(),
        host.environment_id(),
    )
    .expect("the registry");
    let admission = registry
        .reserve(
            &ActorId::new("local:501").expect("a principal"),
            kr_ipc::new_uuid(),
            Digest256::from_bytes([1; 32]),
            &[0xa0],
            TimestampMs::new(1),
        )
        .expect("a reservation");
    let session_id = admission.reservation.session_id;
    registry
        .set_phase(admission.reservation.reservation_id, LaunchPhase::Closed)
        .expect("the session closes");
    registry
        .record_closure(&ClosureRecord {
            session_id,
            session_epoch: SessionEpoch::V1,
            reason: ClosureReason::RootExit,
            root_exit_code: Nullable::some(U64::new(0)),
            root_signal: Nullable::null(),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: OwnershipCoverage::Complete,
            durability: Durability::Durable,
            closed_at_ms: TimestampMs::new(closed_at_ms),
        })
        .expect("the closure");
    let mut history = kr_worker::history::OutputHistory::with_spool(
        8,
        host.environment().session_spool(session_id),
        layout,
    )
    .expect("a spool");
    history.append(output);
    session_id
}

/// KR-REQ-20.14, 20.15, 20.18, KR-REQ-24.16 and KR-ACC-033, end to end: a host is set up through
/// `kr` at a terminal, its daemon makes a backup of the session that closed on it, and a fresh
/// host, with a state directory of its own and nothing but the kit that was printed, restores the
/// session's output and the configuration as readable files.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_host_restores_the_session_a_set_up_host_backed_up_from_the_kit_setup_printed() {
    let output = b"the output this session wrote\r\n";
    let rig = Rig::start_with(|host| {
        closed_session(host, output, 9_000);
    })
    .await;
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    window.confirm(&kit);
    window.wait_for("kr ended 0");

    let BackupSetupState::Committed { archive_id, .. } = rig.status().await.setup else {
        panic!("the host is set up");
    };
    rig.until_published(archive_id, 1).await;

    // A fresh host on the same service: its own state directory, and the kit as the only thing it
    // is given.
    let fresh = Rig::start_at(Arc::clone(&rig.served), |_| {}).await;
    let kit_file = fresh.work.join("kit.txt");
    std::fs::write(&kit_file, &kit.text).expect("the kit file");
    let into = fresh.work.join("restored");
    std::fs::create_dir(&into).expect("a folder to fill");
    let kit_arg = kit_file.display().to_string();
    let into_arg = into.display().to_string();
    let line = |more: &[&str]| -> Vec<String> {
        let mut line: Vec<String> = [
            "backup",
            "restore",
            "--into",
            &into_arg,
            "--kit-file",
            &kit_arg,
        ]
        .iter()
        .map(|word| (*word).to_owned())
        .collect();
        line.extend(more.iter().map(|word| (*word).to_owned()));
        line
    };
    let run = |line: Vec<String>| {
        let words: Vec<&str> = line.iter().map(String::as_str).collect();
        fresh.run(&words)
    };
    let preview = run(line(&["--preview", "--json"]));
    assert!(preview.status.success(), "{}", text(&preview.stderr));
    let plan: Value = serde_json::from_slice(&preview.stdout).expect("the plan is JSON");
    assert_eq!(plan["archive"], archive_id.get().to_string());
    let digest = plan["digest"].as_str().expect("a digest").to_owned();
    let restored = run(line(&["--confirm-plan", &digest, "--json"]));
    assert!(restored.status.success(), "{}", text(&restored.stderr));

    let files = tree(&into);
    let names: Vec<&str> = files.keys().map(String::as_str).collect();
    assert!(names.contains(&"session-0001.json"), "{names:?}");
    assert!(names.contains(&"configuration.json"), "{names:?}");
    // The configuration is the document the set up host reads, and not an empty file.
    let source: Value = serde_json::from_slice(
        &std::fs::read(kr_worker::config::document_path(&rig.temp.environment()))
            .expect("the set up host's document"),
    )
    .expect("the source is JSON");
    let restored_configuration: Value =
        serde_json::from_slice(&files["configuration.json"]).expect("the configuration is JSON");
    assert_eq!(restored_configuration, source);
    // The session's document carries the output it wrote.
    let document: Value = serde_json::from_slice(&files["session-0001.json"]).expect("a document");
    let mut carried = Vec::new();
    for chunk in document["output"]["chunks"]
        .as_array()
        .expect("the document's chunks")
    {
        carried.extend(
            kr_protocol::scalars::from_base64url(chunk["base64url"].as_str().expect("text"))
                .expect("base64url"),
        );
    }
    assert!(
        text(&carried).contains("the output this session wrote"),
        "{}",
        text(&carried)
    );
}

/// The convention's sizes, at their real values: the producer packs sessions up to the total a
/// restore accepts and leaves the rest out, and a restore of what it made accepts all of it.
///
/// Fourteen closed sessions each hold output that alternates one byte of text with one byte a
/// terminal engine drops, which is the shape that makes the most pieces from the least output: about
/// 7 MB of spool for each, and a document of about 126 MiB (each piece is an entry of at most 38
/// bytes). Together they are over the 1.5 GiB a restore accepts, and twelve of them fit. The
/// generation the host makes holds the newest that fit; the restore's plan of it lists every one as
/// a file to restore and none as refused, and what it restores is under the total.
///
/// It packs, encrypts, uploads and restores more than a gigabyte, so it runs on the build box and
/// only when asked: `cargo test -p kr-cli --test backup_setup -- --ignored the_bounds_hold`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "packs, uploads and restores about 1.5 GiB at the convention's real sizes; run it on the build box with --ignored"]
async fn the_bounds_hold_at_the_real_scale_and_a_restore_accepts_what_the_producer_packed() {
    /// What a restore accepts of all members together: the convention's 1.5 GiB.
    const TOTAL: u64 = 3 << 29;
    const SESSIONS: usize = 14;
    let pairs = 3_500_000;
    let mut output = Vec::with_capacity(pairs * 2);
    for _ in 0..pairs {
        output.extend_from_slice(&[b'x', 0x07]);
    }
    // Each session with the time it closed at.
    let closed: Mutex<Vec<(u64, String)>> = Mutex::new(Vec::new());
    let rig = Rig::start_with(|host| {
        for closed_at in (9_000..).take(SESSIONS) {
            let id = closed_session_in(
                host,
                &output,
                closed_at,
                kr_worker::history::SpoolLayout::new(8 << 20, 128 << 20),
            );
            closed.lock().unwrap_or_else(PoisonError::into_inner).push((
                closed_at,
                serde_json::to_value(id).expect("an id").to_string(),
            ));
        }
    })
    .await;
    let mut window = Window::run(&rig, &["backup", "setup"]);
    let kit = window.bring_up_the_kit();
    window.confirm(&kit);
    window.wait_for("kr ended 0");
    let BackupSetupState::Committed { archive_id, .. } = rig.status().await.setup else {
        panic!("the host is set up");
    };
    rig.until_published_within(archive_id, 1, Duration::from_secs(3600))
        .await;

    let fresh = Rig::start_at(Arc::clone(&rig.served), |_| {}).await;
    let kit_file = fresh.work.join("kit.txt");
    std::fs::write(&kit_file, &kit.text).expect("the kit file");
    let into = fresh.work.join("restored");
    std::fs::create_dir(&into).expect("a folder to fill");
    let kit_arg = kit_file.display().to_string();
    let into_arg = into.display().to_string();
    let preview = fresh.run(&[
        "backup",
        "restore",
        "--into",
        &into_arg,
        "--kit-file",
        &kit_arg,
        "--preview",
        "--json",
    ]);
    assert!(preview.status.success(), "{}", text(&preview.stderr));
    let plan: Value = serde_json::from_slice(&preview.stdout).expect("the plan is JSON");
    let files = plan["files"].as_array().expect("files");
    let sessions: Vec<u64> = files
        .iter()
        .filter(|file| file["role"] == "a session's export")
        .map(|file| file["bytes"].as_u64().expect("a size"))
        .collect();
    let packed: u64 = sessions.iter().sum();
    assert!(
        plan["not_restored"]
            .as_array()
            .expect("not restored")
            .is_empty(),
        "the restore refuses nothing the producer packed: {}",
        plan["not_restored"]
    );
    assert!(packed <= TOTAL, "the members total {packed} bytes");
    assert!(
        sessions.len() < SESSIONS,
        "the sessions together are over the total, so one is left out: {} packed, {packed} bytes",
        sessions.len()
    );
    let largest = sessions.iter().copied().max().expect("a session");
    assert!(
        packed + largest > TOTAL,
        "the producer left room for another session: {packed} bytes packed"
    );
    let digest = plan["digest"].as_str().expect("a digest").to_owned();
    let restored = fresh.run(&[
        "backup",
        "restore",
        "--into",
        &into_arg,
        "--kit-file",
        &kit_arg,
        "--confirm-plan",
        &digest,
        "--json",
    ]);
    assert!(restored.status.success(), "{}", text(&restored.stderr));

    // What was left out is the oldest: the sessions restored are the newest that fit.
    let mut newest = closed.into_inner().unwrap_or_else(PoisonError::into_inner);
    newest.sort_by_key(|(closed_at, _)| std::cmp::Reverse(*closed_at));
    let expected: std::collections::BTreeSet<String> = newest
        .into_iter()
        .take(sessions.len())
        .map(|(_, id)| id)
        .collect();
    let restored_ids: std::collections::BTreeSet<String> = std::fs::read_dir(&into)
        .expect("the folder")
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("session-"))
        .map(|entry| session_id_at_the_head_of(&entry.path()))
        .collect();
    assert_eq!(restored_ids, expected);
}

/// The identifier a restored session document names, read from the head of the file: a document
/// of this size is not read whole to find it.
fn session_id_at_the_head_of(path: &Path) -> String {
    let mut head = vec![0_u8; 8192];
    let read = std::fs::File::open(path)
        .and_then(|mut file| file.read(&mut head))
        .expect("the document's head");
    let head = String::from_utf8_lossy(&head[..read]);
    let key = "\"session_id\":";
    let at = head.find(key).expect("the document names its session") + key.len();
    let value = head[at..].trim_start();
    let end = value[1..].find('"').expect("a closing quote") + 2;
    value[..end].to_owned()
}
