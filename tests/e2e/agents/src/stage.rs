//! The stage a part runs on: a host, its owner device, the agent's connector package installed on
//! that device's confirmation, and the managed sessions the agent runs in.
//!
//! The host, the device, the terminal windows and the process record are the cross-boundary
//! checkpoint's own ([`kr_e2e_m1b`]). What this adds is what a qualification needs beyond it: the
//! forwarder beside the host's other binaries, an installation that asks the owner to confirm the
//! capabilities it grants, a session environment in which a vendor build can run without an
//! account or a network, the processes an agent runs as, and a control daemon that is killed and
//! started again on the address its paired device already knows.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kr_client::cursors::StreamCursors;
use kr_e2e_m1b::LIVENESS;
use kr_e2e_m1b::catalogue::{copy_tree, directory_url, enrol};
use kr_e2e_m1b::ceremony;
use kr_e2e_m1b::device::{Device, PairedHost, Remote};
use kr_e2e_m1b::host::{Host, document};
use kr_e2e_m1b::run::{Run, ended_within, output_within, process_table, signal};
use kr_e2e_m1b::shells::ManagedShell;
use kr_e2e_m1b::window::{Window, answered};
use kr_ipc::identity::{ProcessQuery, query_process};
use kr_protocol::catalogue::{
    CatalogueKind, CatalogueListParams, CatalogueListResult, PluginInstallParams,
    PluginInstallResult,
};
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{PluginId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::pairing::SensitiveAction;
use kr_protocol::recovery::{EventsSnapshotParams, EventsSnapshotResult};
use kr_protocol::scalars::{CanonicalSet, Nullable};

use crate::build::Build;

/// The prompt the run's own startup file sets, so a part knows the shell reads.
pub const PROMPT: &str = "kr-agents$ ";

/// The run's own startup file for the session's shell: a prompt, and nothing of anybody's own.
/// `kr shell install` adds the marked entry that loads the package's integration after it.
const ZSHRC: &str =
    "PROMPT='kr-agents$ '\nRPROMPT=''\nHISTFILE=''\nsetopt no_beep\nunsetopt prompt_sp\n";

/// The catalogue the package is installed from, as this host names it.
pub const CATALOGUE: &str = "development";

/// What a repository enrolled with the default ceiling permits by itself. Everything else a
/// package requests is granted to its installation explicitly, on the owner's confirmation.
const DEFAULT_CEILING: [&str; 3] = [
    "metadata.match",
    "presentation.declarative",
    "broker.semantic_events",
];

/// How long a daemon is given to stop once it has been interrupted.
const DAEMON_STOP: Duration = Duration::from_secs(20);

/// A runtime for the device's calls.
///
/// # Panics
///
/// Panics when one cannot be made.
#[must_use]
pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("a runtime")
}

/// Copies `kr-hook` beside the host's other binaries in the run's directory, and starts it once
/// where nothing is timed.
///
/// # Panics
///
/// Panics when this build has no `kr-hook`: a part that went on without it would report nothing
/// about the forwarder it was asked to try.
pub fn place_forwarder(run: &Run) {
    let source = built_directory().join("kr-hook");
    assert!(
        source.is_file(),
        "the forwarder is not built at {}; build it with `cargo build -p kr-hook --bins`",
        source.display()
    );
    kr_ipc::testing::place_and_start_once(&source, &run.binary("kr-hook"), &["--version"]);
}

/// The directory this build put its binaries in, beside this test's own.
fn built_directory() -> PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    directory
}

/// The host's owner device, paired first, and its connection.
pub struct Owner {
    /// The device.
    pub device: Device,
    /// What it holds about the host.
    pub paired: PairedHost,
    /// Its paired connection. A reconnection replaces it.
    pub remote: Remote,
}

impl std::fmt::Debug for Owner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Owner").finish_non_exhaustive()
    }
}

impl Owner {
    /// Pairs a new device as the host's first owner, by direct QR over loopback.
    #[must_use]
    pub fn pair(host: &Host<'_>, runtime: &tokio::runtime::Runtime) -> Self {
        let device = runtime.block_on(Device::create("owner", &host.run().root().join("d")));
        let (paired, remote) = ceremony::pair_first_owner(host, &device, runtime);
        Self {
            device,
            paired,
            remote,
        }
    }

    /// Opens another connection to the host. A connection serves one session, so each session a
    /// part watches or types into has one of its own.
    ///
    /// # Panics
    ///
    /// Panics when the host cannot be reached.
    #[must_use]
    pub fn connect(&self, runtime: &tokio::runtime::Runtime) -> Remote {
        runtime
            .block_on(self.device.reconnect(&self.paired, StreamCursors::new()))
            .unwrap_or_else(|why| panic!("the device connects again: {why}"))
    }

    /// The loopback port the host's endpoint was paired at.
    ///
    /// # Panics
    ///
    /// Panics when the pairing pinned no loopback address.
    #[must_use]
    pub fn paired_port(&self) -> u16 {
        self.paired
            .address
            .ip_addrs()
            .find(|address| address.ip().is_loopback())
            .map(std::net::SocketAddr::port)
            .expect("the pairing pinned a loopback address")
    }

    /// Ends the connection and the device's endpoint.
    pub fn close(self, runtime: &tokio::runtime::Runtime) {
        self.remote.close();
        runtime.block_on(self.device.close());
    }
}

/// The package as the host installed it.
#[derive(Clone, Debug)]
pub struct Installed {
    /// The package.
    pub plugin_id: PluginId,
    /// The release.
    pub version: String,
    /// The manifest digest the installation was confirmed for.
    pub package_digest: String,
    /// The capabilities granted beyond the default ceiling, on the owner's confirmation.
    pub grant: Vec<String>,
    /// What `plugin.install` answered.
    pub result: PluginInstallResult,
}

/// Installs the package from a copy of `generation` the way a person's owner device does: the
/// device confirms the repository's root, the host synchronises it, the device confirms the exact
/// installation with the capabilities it grants, and the package is enabled.
///
/// # Panics
///
/// Panics at the first step the host refuses, naming it.
#[must_use]
pub fn install(
    host: &Host<'_>,
    owner: &Owner,
    runtime: &tokio::runtime::Runtime,
    generation: &Path,
    package: &str,
) -> Installed {
    let copy = host.run().root().join("generation");
    copy_tree(generation, &copy);
    let root = std::fs::read(copy.join("root.json")).expect("the generation's root");
    let index: serde_json::Value = serde_json::from_slice(
        &std::fs::read(copy.join("targets/index.json")).expect("the generation's index"),
    )
    .expect("the index is JSON");
    let entry = index["entries"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["plugin_id"] == package))
        .unwrap_or_else(|| panic!("the generation's index names {package}"));
    let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_owned();
    let version = text(&entry["version"]);
    let package_digest = text(&entry["manifest_digest"]);
    let mut grant: Vec<String> = entry["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|request| text(&request["capability"]))
        .filter(|capability| !DEFAULT_CEILING.contains(&capability.as_str()))
        .collect();
    grant.sort();
    grant.dedup();

    let _ = runtime
        .block_on(enrol(
            &owner.remote,
            CATALOGUE,
            CatalogueKind::Local,
            &directory_url(&copy.join("metadata")),
            &directory_url(&copy.join("targets")),
            &root,
        ))
        .unwrap_or_else(|why| panic!("the owner device enrols the generation: {why}"));
    let _ = host.kr_json(&["plugin", "repo", "sync", CATALOGUE]);

    let environment_id = owner.remote.environment_id();
    let listed: CatalogueListResult = runtime
        .block_on(owner.remote.read(
            Method::CatalogueList,
            &CatalogueListParams { environment_id },
        ))
        .unwrap_or_else(|error| panic!("catalogue.list: {error}"));
    let ceiling: CanonicalSet<String> = listed
        .catalogues
        .into_iter()
        .find(|catalogue| catalogue.catalogue_id == CATALOGUE)
        .map(|catalogue| catalogue.ceiling.into_iter().collect())
        .unwrap_or_else(|| panic!("catalogue.list names {CATALOGUE}"));
    let plugin_id = PluginId::new(package).expect("a plugin identifier");
    let plan = kr_controller::sharing::PluginInstallPlan {
        environment_id,
        catalogue_id: CATALOGUE.to_owned(),
        ceiling,
        plugin_id: plugin_id.clone(),
        version: version.clone(),
        package_digest: package_digest.clone(),
        grant: grant.iter().cloned().collect(),
    };
    let digest = plan
        .action_digest()
        .unwrap_or_else(|error| panic!("the installation's digest: {error}"));
    let proof = runtime
        .block_on(
            owner
                .remote
                .confirm_described(SensitiveAction::GrantExecutableCapability, digest),
        )
        .unwrap_or_else(|why| panic!("the owner confirms the installation: {why}"));
    let result: PluginInstallResult = runtime
        .block_on(owner.remote.mutate_environment(
            Method::PluginInstall,
            &PluginInstallParams {
                environment_id,
                catalogue_id: CATALOGUE.to_owned(),
                plugin_id: plugin_id.clone(),
                version: version.clone(),
                package_digest: package_digest.clone(),
                grant: grant.clone(),
                owner_confirmation: Nullable::some(proof),
            },
        ))
        .unwrap_or_else(|error| panic!("plugin.install: {error}"));
    let _ = host.kr_json(&["plugin", "enable", package]);
    Installed {
        plugin_id,
        version,
        package_digest,
        grant,
        result,
    }
}

/// A loopback port nothing listens on: one the operating system handed out and took back.
///
/// # Panics
///
/// Panics when no port can be bound.
#[must_use]
pub fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    listener.local_addr().expect("its address").port()
}

/// A loopback port for a server the terminal route starts, free when this returns.
#[must_use]
pub fn free_port() -> u16 {
    closed_port()
}

/// The directory the session's PATH names first, `agent/current/bin` in the run's directory:
/// `current` is a link to an installed build, so an upgrade is one atomic change of that link.
#[derive(Clone, Debug)]
pub struct Installation {
    current: PathBuf,
}

impl Installation {
    /// Links `current` to the build installed at `prefix`.
    ///
    /// # Panics
    ///
    /// Panics when the link cannot be made.
    #[must_use]
    pub fn link(run: &Run, prefix: &Path) -> Self {
        let directory = run.root().join("agent");
        kr_ipc::paths::create_private_tree(run.root(), &directory).expect("the installation");
        let current = directory.join("current");
        std::os::unix::fs::symlink(prefix, &current).expect("links the installed build");
        Self { current }
    }

    /// The directory the command is found in.
    #[must_use]
    pub fn bin(&self) -> PathBuf {
        self.current.join("bin")
    }

    /// Points `current` at the build installed at `prefix` in one step: a new link renamed over
    /// the old one, as an installer that switches versions does.
    ///
    /// # Panics
    ///
    /// Panics when the link cannot be replaced.
    pub fn upgrade(&self, prefix: &Path) {
        let next = self.current.with_file_name("current.next");
        std::os::unix::fs::symlink(prefix, &next).expect("links the newer build");
        std::fs::rename(&next, &self.current).expect("replaces the link");
    }
}

/// The environment a session is created with, and so the environment its shell and the agent
/// run in: the host's own variables for `kr`, PATH naming the installation first, the run's home
/// as the home and the startup directory, every proxy variable at a loopback port nothing listens
/// on (loopback itself excepted, where a terminal route's own server listens), and the build's
/// own switches.
#[must_use]
pub fn session_variables(
    host: &Host<'_>,
    shell: &ManagedShell,
    build: &Build,
    installation: &Installation,
    closed: u16,
) -> Vec<(String, String)> {
    let home = host.run().home().display().to_string();
    let mut variables: Vec<(String, String)> = host
        .variables()
        .into_iter()
        .filter(|(name, _)| name != "PATH" && name != "TERM")
        .collect();
    // The window answers kr's probe as a terminal whose keyboard supplies both enhanced protocols,
    // and it says so by name: the host decides which encodings an attachment supplies from the
    // terminal it names, and an agent that turns an enhanced protocol on reads keys only from a
    // terminal that supplies it. The session's own TERM is the host's, whatever this names.
    variables.push(("TERM".to_owned(), Keyboard::PROFILE.to_owned()));
    let mut path = vec![installation.bin().display().to_string()];
    path.extend(
        build
            .runtime_path
            .iter()
            .map(|directory| directory.display().to_string()),
    );
    path.extend(["/usr/bin".to_owned(), "/bin".to_owned()]);
    variables.push(("PATH".to_owned(), path.join(":")));
    variables.push(("ZDOTDIR".to_owned(), home));
    variables.push(("SHELL".to_owned(), shell.executable.display().to_string()));
    variables.push(("LANG".to_owned(), "en_US.UTF-8".to_owned()));
    let proxy = format!("http://127.0.0.1:{closed}");
    for name in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        variables.push((name.to_owned(), proxy.clone()));
    }
    for name in ["NO_PROXY", "no_proxy"] {
        variables.push((name.to_owned(), "localhost,127.0.0.1,::1".to_owned()));
    }
    for (name, value) in &build.environment {
        variables.push((name.clone(), value.clone()));
    }
    variables
}

/// Writes the run's own startup file and lets `kr shell install` add its marked entry after it.
///
/// # Panics
///
/// Panics when either step fails.
pub fn prepare_home(host: &Host<'_>, variables: &[(String, String)]) {
    let home = host.run().home();
    std::fs::write(home.join(".zshrc"), ZSHRC).expect("writes the startup file");
    let mut install = host.command(&["shell", "install", "--json"]);
    install.envs(variables.iter().cloned());
    let installed =
        output_within(install, LIVENESS).unwrap_or_else(|why| panic!("kr shell install: {why}"));
    assert!(
        installed.status.success(),
        "kr shell install: {}{}",
        String::from_utf8_lossy(&installed.stdout),
        String::from_utf8_lossy(&installed.stderr)
    );
}

/// One managed session on a terminal of its own: `kr new --attach` in a window.
pub struct Session {
    /// The local terminal the session is attached to.
    pub window: Window,
    /// The session.
    pub session_id: SessionId,
    /// Its display number.
    pub display: String,
    /// Its root shell.
    pub root_shell: ProcessStartIdentity,
    /// Its worker.
    pub worker: ProcessStartIdentity,
    /// The owner device's connection for this session.
    pub remote: Remote,
}

impl Session {
    /// Replaces the session's device connection with a new one, as a device does after the host it
    /// was connected to went away.
    ///
    /// # Errors
    ///
    /// Returns why the host could not be reached.
    pub fn reconnect(
        &mut self,
        owner: &Owner,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<(), String> {
        let remote =
            runtime.block_on(owner.device.reconnect(&owner.paired, StreamCursors::new()))?;
        self.remote.close();
        self.remote = remote;
        Ok(())
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// Opens a managed session with `kr new --attach` on a window of its own, with exactly
/// `variables`, and waits for its shell to read.
///
/// # Panics
///
/// Panics when the session does not come up, naming the step.
#[must_use]
pub fn open_session(
    host: &Host<'_>,
    owner: &Owner,
    runtime: &tokio::runtime::Runtime,
    shell: &ManagedShell,
    variables: &[(String, String)],
    what: &str,
) -> Session {
    let run = host.run();
    let before: Vec<String> = host
        .live_sessions()
        .iter()
        .map(|session| session["session_id"].to_string())
        .collect();
    let work = run.work().display().to_string();
    let executable = shell.executable.display().to_string();
    let window = Window::open(
        run,
        what,
        &run.binary("kr"),
        &[
            "new",
            "--attach",
            "--headless",
            "--shell",
            &executable,
            "--shell-mode",
            "managed",
            "--startup",
            "interactive",
            "--cwd",
            &work,
        ],
        run.root(),
        variables,
    );
    answered(&window, window.answer_capability_queries(0));
    let _ = window.wait_for_screen(PROMPT.trim_end(), "the managed shell reads at its terminal");
    let created: Vec<serde_json::Value> = host
        .live_sessions()
        .into_iter()
        .filter(|session| !before.contains(&session["session_id"].to_string()))
        .collect();
    assert_eq!(created.len(), 1, "one new live session: {created:?}");
    let session_id: SessionId = created[0]["session_id"]
        .as_str()
        .expect("a session identifier")
        .parse()
        .expect("a session identifier");
    let display = created[0]["display_number"].to_string();
    let remote = owner.connect(runtime);
    let snapshot = events_snapshot(&remote, runtime, session_id);
    let root_shell = snapshot
        .session
        .root_process
        .0
        .clone()
        .expect("the session names its root shell");
    run.record(root_shell.clone(), &format!("the root shell of {what}"));
    let worker = worker_of(run, &session_id.to_string());
    Session {
        window,
        session_id,
        display,
        root_shell,
        worker,
        remote,
    }
}

/// Reads a session's snapshot over the device connection that serves it.
///
/// # Panics
///
/// Panics when the host refuses it.
#[must_use]
pub fn events_snapshot(
    remote: &Remote,
    runtime: &tokio::runtime::Runtime,
    session_id: SessionId,
) -> EventsSnapshotResult {
    runtime
        .block_on(remote.read(
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id,
                agent_resources_from: Nullable::null(),
            },
        ))
        .unwrap_or_else(|error| panic!("events.snapshot: {error}"))
}

/// The identity of the worker that serves `session_id`: the process running this run's copy of
/// `kr-worker` for that session, recorded while its start holds the number the table gave.
fn worker_of(run: &Run, session_id: &str) -> ProcessStartIdentity {
    let started = Instant::now();
    let session = format!("--session {session_id}");
    loop {
        if let Some(identity) = kr_e2e_m1b::run::processes_under(run.root())
            .unwrap_or_default()
            .into_iter()
            .filter(|(_, command)| command.contains("kr-worker") && command.contains(&session))
            .find_map(|(pid, _)| {
                run.record_named(pid, "the session's worker", &["kr-worker", &session])
            })
        {
            return identity;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "no worker for session {session_id} is in the process table"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One process an agent runs as.
#[derive(Clone, Debug)]
pub struct AgentProcess {
    /// Who it is.
    pub identity: ProcessStartIdentity,
    /// Its command line, as the process table shows it.
    pub command: String,
    /// Its parent's number, as the process table shows it.
    pub parent: u32,
}

/// Types the agent's command at the session's prompt and waits for its first screen, then returns
/// the agent's execution: the program the shell started for the command, which is the root shell's
/// own child whatever it calls itself, and every process beneath it that belongs to the build.
///
/// A process belongs to the build when its command line names one of `marks`, or the file it
/// executes lies in one of them: the build's own directory, its runtime's, and the run's link to
/// the installation. A helper an agent starts from somewhere else, such as a probe it unpacks into
/// its home and runs for a moment, is recorded with the run all the same, and ended with it, but it
/// is not the execution a part watches.
///
/// # Panics
///
/// Panics when the agent does not draw `ready`, or nothing of the build runs beneath the shell.
#[must_use]
pub fn launch(
    run: &Run,
    session: &Session,
    line: &str,
    ready: &str,
    marks: &[PathBuf],
) -> Vec<AgentProcess> {
    session.window.type_text(format!("{line}\r").as_bytes());
    let _ = session
        .window
        .wait_for_screen(ready, "the agent draws its first screen");
    let started = Instant::now();
    let shell = u32::try_from(session.root_shell.pid.get()).expect("a process number");
    loop {
        let found: Vec<AgentProcess> = beneath(run, &session.root_shell, "the agent")
            .into_iter()
            .filter(|process| process.parent == shell || belongs(process, marks))
            .collect();
        if !found.is_empty() {
            return found;
        }
        assert!(
            started.elapsed() < LIVENESS,
            "nothing of the build runs beneath the session's root shell"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Whether a process belongs to the build `marks` name: its command line names one of them, or
/// the file it executes lies in one of them.
fn belongs(process: &AgentProcess, marks: &[PathBuf]) -> bool {
    if marks
        .iter()
        .any(|mark| process.command.contains(&mark.display().to_string()))
    {
        return true;
    }
    let Ok(pid) = u32::try_from(process.identity.pid.get()) else {
        return false;
    };
    text_image(pid)
        .ok()
        .and_then(|(path, _)| std::fs::canonicalize(path).ok())
        .is_some_and(|image| marks.iter().any(|mark| image.starts_with(mark)))
}

/// Every process beneath `ancestor` now, each recorded with the run by its start identity.
///
/// # Panics
///
/// Panics when the search does not finish, which the run's closing check would also fail on.
#[must_use]
pub fn beneath(run: &Run, ancestor: &ProcessStartIdentity, what: &str) -> Vec<AgentProcess> {
    run.record_descendants(ancestor, what)
        .unwrap_or_else(|why| panic!("the processes beneath {what}: {why}"));
    let table = process_table().unwrap_or_else(|why| panic!("{why}"));
    let mut found = Vec::new();
    let mut parents = vec![u32::try_from(ancestor.pid.get()).expect("a process number")];
    while let Some(parent) = parents.pop() {
        for entry in table.iter().filter(|entry| entry.parent == parent) {
            if let ProcessQuery::Present(identity) = query_process(entry.pid) {
                run.record(identity.clone(), &format!("{what}: {}", entry.command));
                found.push(AgentProcess {
                    identity,
                    command: entry.command.clone(),
                    parent: entry.parent,
                });
                parents.push(entry.pid);
            }
        }
    }
    found
}

/// The file a process executes, as the kernel mapped it: its path and its inode, from the
/// process's own text mapping, so a file replaced on disk since it started is not mistaken for
/// what it runs.
///
/// # Errors
///
/// Returns why the mapping could not be read.
pub fn text_image(pid: u32) -> Result<(PathBuf, u64), String> {
    let mut lsof = Command::new("/usr/sbin/lsof");
    lsof.args(["-a", "-p", &pid.to_string(), "-d", "txt", "-Fin"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin");
    let output = output_within(lsof, LIVENESS).map_err(|why| format!("lsof {why}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut inode = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix('i') {
            inode = value.parse::<u64>().ok();
        } else if let Some(name) = line.strip_prefix('n')
            && let Some(inode) = inode
        {
            return Ok((PathBuf::from(name), inode));
        }
    }
    Err(format!("lsof named no text file for process {pid}: {text}"))
}

/// A file's inode, following links.
///
/// # Panics
///
/// Panics when the file cannot be read.
#[must_use]
pub fn inode_of(path: &Path) -> u64 {
    std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .ino()
}

/// Kills the host's control daemon by its recorded identity and waits for it to end.
///
/// # Panics
///
/// Panics when the host has no daemon or it does not end.
pub fn kill_daemon(host: &Host<'_>) -> ProcessStartIdentity {
    let daemon = host.daemon_identity().expect("the host's daemon");
    signal(&daemon, rustix::process::Signal::KILL);
    assert!(
        ended_within(&daemon, DAEMON_STOP),
        "the control daemon ended when killed"
    );
    daemon
}

/// A control daemon this part started in place of one it killed, on the same host tree and at
/// the address the owner device was paired at.
#[derive(Debug)]
pub struct Replacement {
    child: Child,
    identity: ProcessStartIdentity,
}

impl Replacement {
    /// Starts a daemon as the host started its own, with the configuration document now naming the
    /// loopback `port` its endpoint was paired at, and waits for it to answer.
    ///
    /// # Panics
    ///
    /// Panics when it does not answer within [`LIVENESS`].
    #[must_use]
    pub fn start(host: &Host<'_>, port: u16) -> Self {
        let run = host.run();
        let path = kr_worker::config::document_path(host.environment());
        let mut configuration: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("the configuration document"))
                .expect("the configuration document is JSON");
        configuration["network"]["bind_address"] = serde_json::json!(format!("127.0.0.1:{port}"));
        configuration["revision"] =
            serde_json::json!(configuration["revision"].as_u64().unwrap_or(1) + 1);
        kr_ipc::paths::write_owner_only_file(
            &path,
            &serde_json::to_vec_pretty(&configuration).expect("a document"),
        )
        .expect("rewrites the configuration document");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(run.root().join("controller.log"))
            .expect("the daemon's log");
        let mut command = Command::new(run.binary("kr-controller"));
        command
            .arg("--runtime-dir")
            .arg(host.roots().runtime_root())
            .arg("--state-dir")
            .arg(host.roots().state_root())
            .arg("--secret-store")
            .arg("file")
            .arg("--worker")
            .arg(run.binary("kr-worker"))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", run.home())
            .current_dir(run.root())
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("the daemon's log"))
            .stderr(log);
        for inherited in ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] {
            if let Some(value) = std::env::var_os(inherited) {
                command.env(inherited, value);
            }
        }
        if let Some((_, packages)) = host
            .variables()
            .into_iter()
            .find(|(name, _)| name == "KR_SHELL_PACKAGES")
        {
            command.env("KR_SHELL_PACKAGES", packages);
        }
        let mut child = command.spawn().expect("the replacement daemon starts");
        let Some(identity) = run.record_child(child.id(), "the replacement control daemon") else {
            let _ = child.wait();
            panic!(
                "the replacement daemon ended at once: {}",
                host.daemon_said()
            );
        };
        let mut replacement = Self { child, identity };
        let started = Instant::now();
        loop {
            if host
                .kr_within(&["list", "--json"], Duration::from_secs(20))
                .is_ok_and(|output| output.status.success() && document(&output.stdout).is_ok())
            {
                return replacement;
            }
            if started.elapsed() >= LIVENESS {
                signal(&replacement.identity, rustix::process::Signal::KILL);
                let _ = replacement.child.wait();
                panic!(
                    "the replacement daemon did not answer within {LIVENESS:?}: {}",
                    host.daemon_said()
                );
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The daemon's identity.
    #[must_use]
    pub const fn identity(&self) -> &ProcessStartIdentity {
        &self.identity
    }

    /// Asks the daemon to stop, as the host asks its own, and waits for it.
    ///
    /// # Errors
    ///
    /// Returns what went wrong: it did not stop when asked, or it ended with a failure.
    pub fn stop(mut self) -> Result<(), String> {
        signal(&self.identity, rustix::process::Signal::INT);
        if !ended_within(&self.identity, DAEMON_STOP) {
            signal(&self.identity, rustix::process::Signal::KILL);
            let _ = self.child.wait();
            return Err(format!(
                "the replacement daemon did not stop within {DAEMON_STOP:?} of being interrupted"
            ));
        }
        let status = self.child.wait().map_err(|error| error.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("the replacement daemon ended with {status}"))
        }
    }

    /// Kills the daemon, for a control that breaks the property on purpose.
    pub fn kill(mut self) {
        signal(&self.identity, rustix::process::Signal::KILL);
        let _ = ended_within(&self.identity, DAEMON_STOP);
        let _ = self.child.wait();
    }
}

/// A device attachment that types, beside the one that watches.
///
/// An application that turns on an enhanced keyboard protocol reads keys in that encoding, and the
/// host gives the input lease only to an attachment whose terminal supplies it. This attachment
/// declares [`Keyboard::PROFILE`], whose keyboard supplies both enhanced protocols an agent may turn
/// on, so it can hold the lease whatever the agent negotiated. Everything a part types through it
/// is printable text, an arrow or Enter, which each of those encodings sends as the ordinary one
/// does.
#[derive(Debug)]
pub struct Keyboard {
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    next: u64,
}

impl Keyboard {
    /// The terminal this attachment declares.
    pub const PROFILE: &'static str = "ghostty";

    /// Attaches to `session_id` over the device connection that serves it, holding no lease yet.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal of the attachment.
    pub fn attach(
        remote: &Remote,
        runtime: &tokio::runtime::Runtime,
        session_id: SessionId,
    ) -> Result<Self, String> {
        use kr_protocol::attachment::{
            AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
        };
        let dimensions = events_snapshot(remote, runtime, session_id)
            .geometry
            .dimensions;
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: SessionAttachResult = runtime
            .block_on(remote.mutate(
                Method::SessionAttach,
                kr_e2e_m1b::view::session_target(remote, session_id),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(dimensions),
                    terminal_profile_id: Nullable::some(Self::PROFILE.to_owned()),
                    requested,
                },
            ))
            .map_err(|error| format!("session.attach: {error}"))?;
        Ok(Self {
            session_id,
            attachment_id: attached.attachment.attachment_id,
            epoch: kr_protocol::ids::InputLeaseEpoch::new(0),
            next: 0,
        })
    }

    /// Takes the input lease for this attachment.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal of the lease.
    pub fn acquire(
        &mut self,
        remote: &Remote,
        runtime: &tokio::runtime::Runtime,
    ) -> Result<(), String> {
        use kr_protocol::input::{InputAcquireParams, InputAcquireResult};
        let acquired: InputAcquireResult = runtime
            .block_on(remote.mutate(
                Method::InputAcquire,
                kr_e2e_m1b::view::session_target(remote, self.session_id),
                &InputAcquireParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    expected_epoch: Nullable::null(),
                },
            ))
            .map_err(|error| format!("input.acquire: {error}"))?;
        self.epoch = acquired.lease.epoch;
        self.next = acquired.lease.next_sequence.get();
        Ok(())
    }

    /// Types `text` under the lease, and requires the host to acknowledge it at its place in the
    /// connection's ordered input with every byte forwarded to the terminal.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, or an acknowledgement that is not of these bytes.
    pub fn type_text(
        &mut self,
        remote: &Remote,
        runtime: &tokio::runtime::Runtime,
        text: &str,
    ) -> Result<kr_protocol::input::InputWriteResult, String> {
        let params = kr_protocol::input::InputWriteParams {
            session_id: self.session_id,
            attachment_id: self.attachment_id,
            epoch: self.epoch,
            sequence: kr_protocol::ids::InputSequence::new(self.next),
            bytes: kr_protocol::scalars::Bytes::new(text.as_bytes().to_vec()),
        };
        let written = runtime
            .block_on(remote.session().write_input(&params))
            .map_err(|error| format!("input.write: {error}"))?;
        let length = u64::try_from(text.len()).unwrap_or(u64::MAX);
        if written.sequence.get() != self.next || written.forwarded_bytes.get() != length {
            return Err(format!(
                "input {} of {length} bytes was acknowledged as {} with {} bytes forwarded",
                self.next,
                written.sequence.get(),
                written.forwarded_bytes.get()
            ));
        }
        self.next += 1;
        Ok(written)
    }
}
