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
use kr_e2e_m1b::run::{
    PlacedDirectory, RootPin, Run, describe, ended_within, link_below, output_within,
    process_table, signal,
};
use kr_e2e_m1b::shells::ManagedShell;
use kr_e2e_m1b::window::{Window, answered};
use kr_ipc::identity::{ProcessQuery, ProcessState, process_state, query_process};
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

use crate::provenance::{EXPORTED_FILE, Expected, LIST_END, PATH_FILE, Provenance, STARTED_FILE};

/// The prompt the run's own startup file sets, so a part knows the shell reads.
pub const PROMPT: &str = "kr-agents$ ";

/// The run's own startup file for the session's shell: a prompt, hooks that write the PATH the
/// shell searches, and the names of the variables it exports, to the run's home before each
/// prompt, and the names again just before each command line runs, and nothing of anybody's own.
/// `kr shell install` adds the marked entry that loads the package's integration after it.
#[must_use]
pub fn startup_file() -> String {
    format!(
        "zmodload zsh/parameter 2>/dev/null\nPROMPT='kr-agents$ '\nRPROMPT=''\nHISTFILE=''\nsetopt no_beep\n\
         unsetopt prompt_sp\n\
         kr_agents_path() {{ print -r -- \"$PATH\" >| \"$ZDOTDIR/{PATH_FILE}\"; \
         print -rl -- ${{(k)parameters[(R)*export*]}} '{LIST_END}' >| \"$ZDOTDIR/{EXPORTED_FILE}\" }}\n\
         kr_agents_started() {{ print -rl -- ${{(k)parameters[(R)*export*]}} '{LIST_END}' >| \"$ZDOTDIR/{STARTED_FILE}\" }}\n\
         precmd_functions+=(kr_agents_path)\n\
         preexec_functions+=(kr_agents_started)\n"
    )
}

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
/// That start is in the test's own process tree. It pays the cost of a file's first start there,
/// but not what the system asks of the first run of a file under the host's own daemon, about half
/// a second of waiting with no work of the file's own: a part that times the forwarder from a
/// session of the host runs it once there first, where nothing is timed.
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
    let copy = enrol_generation(host, owner, runtime, generation);
    install_package(host, owner, runtime, &copy, package)
}

/// Enrols a copy of `generation` the way a person's owner device does: the device confirms the
/// repository's root and the host synchronises it. Returns the copy, which every installation
/// from it reads its index from.
///
/// # Panics
///
/// Panics at the first step the host refuses, naming it.
#[must_use]
pub fn enrol_generation(
    host: &Host<'_>,
    owner: &Owner,
    runtime: &tokio::runtime::Runtime,
    generation: &Path,
) -> PathBuf {
    let copy = host.run().root().join("generation");
    copy_tree(generation, &copy);
    let root = std::fs::read(copy.join("root.json")).expect("the generation's root");
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
    copy
}

/// Installs one package from the enrolled copy of a generation the way a person's owner device
/// does: the device confirms the exact installation with the capabilities it grants, and the
/// package is enabled.
///
/// # Panics
///
/// Panics at the first step the host refuses, naming it.
#[must_use]
pub fn install_package(
    host: &Host<'_>,
    owner: &Owner,
    runtime: &tokio::runtime::Runtime,
    copy: &Path,
    package: &str,
) -> Installed {
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
    let holds = |name: &str| grant.iter().any(|capability| capability == name);
    let grant_statement = kr_protocol::confirmation::install_statement(
        holds("native_bridge.install")
            .then(|| native_bridge_statement(copy, entry))
            .as_deref(),
        holds("command_integration.launch")
            .then(|| integration_statement(copy, entry))
            .as_deref(),
    );

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
    let plan = kr_protocol::confirmation::PluginInstallPlan {
        environment_id,
        catalogue_id: CATALOGUE.to_owned(),
        ceiling,
        plugin_id: plugin_id.clone(),
        version: version.clone(),
        package_digest: package_digest.clone(),
        grant: grant.iter().cloned().collect(),
        grant_statement,
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

/// What the release's manifest says its native bridge does, which the owner is shown and the
/// installation's digest covers.
///
/// # Panics
///
/// Panics when the generation's copy holds no manifest for the entry or the manifest names no
/// native bridge statement.
fn native_bridge_statement(copy: &Path, entry: &serde_json::Value) -> String {
    release_manifest(copy, entry)["native_bridge"]["grant_statement"]
        .as_str()
        .expect("a native bridge release's manifest carries its grant statement")
        .to_owned()
}

/// The host's reading of the command integration the generation's manifest for `entry` declares,
/// which is what an owner device is shown for it.
///
/// # Panics
///
/// Panics when the generation's copy holds no manifest for the entry or the manifest declares no
/// command integration.
fn integration_statement(copy: &Path, entry: &serde_json::Value) -> String {
    let declared = release_manifest(copy, entry)["command_integration"].clone();
    serde_json::from_value::<kr_plugin_sdk::integration::CommandIntegration>(declared)
        .expect("a command integration release's manifest declares one")
        .statement()
}

/// The manifest the generation's copy holds for the release `entry` names.
///
/// # Panics
///
/// Panics when the copy holds no manifest for the entry.
fn release_manifest(copy: &Path, entry: &serde_json::Value) -> serde_json::Value {
    let text = |name: &str| entry[name].as_str().unwrap_or_default();
    let manifest = copy
        .join("targets/packages")
        .join(text("publisher_id"))
        .join(text("plugin_name"))
        .join(text("version"))
        .join("plugin.json");
    serde_json::from_slice(
        &std::fs::read(&manifest).unwrap_or_else(|error| panic!("{}: {error}", manifest.display())),
    )
    .expect("the manifest is JSON")
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

/// The directory of a run that holds the links to the installed build and to the runtimes it needs.
const INSTALLATION_DIRECTORY: &str = "agent";

/// The link in [`INSTALLATION_DIRECTORY`] to the installed build.
const CURRENT_LINK: &str = "current";

/// The directory in [`INSTALLATION_DIRECTORY`] that holds a link to each runtime the build needs.
const RUNTIME_DIRECTORY: &str = "runtime";

/// The places, relative to a run's directory and joined by `/`, where [`Installation::link`] makes
/// links when the build needs the executables `runtime`: the link to the installed build, and one
/// link in the directory of the runtimes for each executable, under its own name. A link in any
/// other place is not the harness's.
#[must_use]
pub fn installation_links(runtime: &[PathBuf]) -> Vec<String> {
    let mut places = vec![format!("{INSTALLATION_DIRECTORY}/{CURRENT_LINK}")];
    places.extend(
        runtime
            .iter()
            .filter_map(|executable| executable.file_name())
            .map(|name| {
                format!(
                    "{INSTALLATION_DIRECTORY}/{RUNTIME_DIRECTORY}/{}",
                    name.to_string_lossy()
                )
            }),
    );
    places
}

/// The rules for the scan of `run`'s directory: the directory the run made, the links the harness
/// makes ([`installation_links`]) and the links the pinned build makes in its own home, which say
/// the pinned executable `pinned` in the run's installation of the build, by the path the run starts
/// it by and by its resolved path `resolved`, which is the system's answer from before the agent
/// started, and nothing else.
#[must_use]
pub fn scan_rules(
    run: &Run,
    pinned: &str,
    resolved: Option<&Path>,
    runtime: &[PathBuf],
) -> crate::account::RunRules {
    let mut executables = vec![
        run.root()
            .join(INSTALLATION_DIRECTORY)
            .join(CURRENT_LINK)
            .join(pinned),
    ];
    executables.extend(resolved.map(Path::to_path_buf));
    crate::account::RunRules::new(run.pin(), installation_links(runtime))
        .with_agent_links(crate::held::CONFIG_DIRECTORY, executables)
}

/// The directories a session searches, in order: the run's link to the installed build, the run's
/// links to the runtimes the build needs, and the system's own.
#[must_use]
pub fn session_path(run: &Run) -> String {
    let agent = run.root().join(INSTALLATION_DIRECTORY);
    [
        agent.join(CURRENT_LINK).join("bin"),
        agent.join(RUNTIME_DIRECTORY),
    ]
    .iter()
    .map(|directory| directory.display().to_string())
    .chain(["/usr/bin".to_owned(), "/bin".to_owned()])
    .collect::<Vec<_>>()
    .join(":")
}

/// The directory the session's PATH names first, `agent/current/bin` in the run's directory:
/// `current` is a link to an installed build, so an upgrade is one atomic change of that link.
/// Beside it, `agent/runtime` holds a link to each runtime the build needs and nothing else.
#[derive(Clone, Debug)]
pub struct Installation {
    current: PathBuf,
}

impl Installation {
    /// Links `current` to the build installed at `prefix`, and each of `runtime`'s executables
    /// into `agent/runtime` by its own name.
    ///
    /// # Panics
    ///
    /// Panics when a link cannot be made.
    #[must_use]
    pub fn link(run: &Run, prefix: &Path, runtime: &[PathBuf]) -> Self {
        let directory = run.root().join(INSTALLATION_DIRECTORY);
        let runtimes = directory.join(RUNTIME_DIRECTORY);
        kr_ipc::paths::create_private_tree(run.root(), &runtimes).expect("the installation");
        let current = directory.join(CURRENT_LINK);
        std::os::unix::fs::symlink(prefix, &current).expect("links the installed build");
        for executable in runtime {
            let name = executable.file_name().expect("a runtime executable's name");
            std::os::unix::fs::symlink(executable, runtimes.join(name))
                .unwrap_or_else(|error| panic!("links {}: {error}", executable.display()));
        }
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

/// The largest program [`PlacedProgram`] reads whole.
const PROGRAM_AT_MOST: u64 = 1 << 30;

/// The agent's program as the run placed it, recorded before the agent first starts: the installation
/// the link `agent/current` names, the links in `agent/runtime`, the file the installed build's
/// `bin/<command>` resolves to with each directory above it, that file's digest, and the directory it
/// is started in. The agent runs in the same account and may leave another link, file
/// or directory on the route its command is found by, or in place of the directory it is started
/// in, so [`PlacedProgram::checked`] compares what is there now with this before each start, and
/// the program is started by the absolute path of the file that was recorded, not by a name on a
/// search path, in the directory that was recorded and no other ([`PlacedProgram::command`]).
#[derive(Clone, Debug)]
pub struct PlacedProgram {
    command: String,
    prefix: PathBuf,
    runtime: Vec<(String, PathBuf)>,
    program: PathBuf,
    /// The file the entry pins, as the system resolved it when the program was recorded.
    pinned: Option<PathBuf>,
    directories: Vec<(PathBuf, (u64, u64))>,
    digest: [u8; 32],
    /// The directory a probe of the build is started in.
    work: PlacedDirectory,
}

impl PlacedProgram {
    /// Records the program the installed build at `prefix` gives for `command`, the file it pins
    /// (`pinned`, relative to the prefix), the links [`Installation::link`] makes for `runtime`, and
    /// the directory `work` that a start is made in.
    ///
    /// # Errors
    ///
    /// Returns why the command is not a file of the installed build, or could not be read.
    pub fn record(
        prefix: &Path,
        runtime: &[PathBuf],
        command: &str,
        pinned: &str,
        work: PlacedDirectory,
    ) -> Result<Self, String> {
        let program = std::fs::canonicalize(prefix.join("bin").join(command)).map_err(|error| {
            format!("`{command}` is not a command of the installed build: {error}")
        })?;
        let directories = program
            .ancestors()
            .skip(1)
            .map(|directory| {
                std::fs::metadata(directory)
                    .map(|found| (directory.to_path_buf(), (found.dev(), found.ino())))
                    .map_err(|error| format!("a directory the command is found in: {error}"))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let file = std::fs::File::open(&program)
            .map_err(|error| format!("the installed build's `{command}`: {error}"))?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        let digest = Self::digest_of(file, &metadata)?;
        Ok(Self {
            command: command.to_owned(),
            prefix: prefix.to_path_buf(),
            runtime: runtime
                .iter()
                .filter_map(|executable| {
                    executable
                        .file_name()
                        .map(|name| (name.to_string_lossy().into_owned(), executable.clone()))
                })
                .collect(),
            program,
            pinned: std::fs::canonicalize(prefix.join(pinned)).ok(),
            directories,
            digest,
            work,
        })
    }

    fn digest_of(file: std::fs::File, metadata: &std::fs::Metadata) -> Result<[u8; 32], String> {
        if metadata.len() > PROGRAM_AT_MOST {
            return Err("the agent's program is larger than the harness reads".to_owned());
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut &file, &mut bytes).map_err(|error| error.to_string())?;
        Ok(kr_cbor::sha256(&bytes))
    }

    /// The file the installed build's command resolved to when it was recorded.
    #[must_use]
    pub fn resolved(&self) -> &Path {
        &self.program
    }

    /// The file the entry pins, as the system resolved it when the program was recorded.
    #[must_use]
    pub fn pinned_resolved(&self) -> Option<&Path> {
        self.pinned.as_deref()
    }

    /// Checks that the route the agent is started by is as it was placed, and returns the absolute
    /// path of the program: the link `agent/current` below the run's directory `root`, which `pin`
    /// names, read with no link followed, names the recorded installation; each link in
    /// `agent/runtime` is as it was; the installed build's command resolves to the recorded file
    /// through the recorded directories; and the bytes of the file, read now, are the digest recorded.
    ///
    /// # Errors
    ///
    /// Returns what is not as it was placed, as a class and no name outside the run.
    pub fn checked(&self, root: &Path, pin: &RootPin) -> Result<&Path, String> {
        let said = |what: &str| format!("the agent's program is not as the run placed it: {what}");
        let link = |relative: String| {
            link_below(root, pin, Path::new(&relative))
                .map_err(|why| said(&format!("{relative}: {why}")))
        };
        if link(format!("{INSTALLATION_DIRECTORY}/{CURRENT_LINK}"))?.as_deref()
            != Some(self.prefix.as_path())
        {
            return Err(said("the link agent/current names another installation"));
        }
        for (name, target) in &self.runtime {
            if link(format!(
                "{INSTALLATION_DIRECTORY}/{RUNTIME_DIRECTORY}/{name}"
            ))?
            .as_deref()
                != Some(target.as_path())
            {
                return Err(said(&format!("the link agent/runtime/{name} is another")));
            }
        }
        match std::fs::canonicalize(self.prefix.join("bin").join(&self.command)) {
            Ok(now) if now == self.program => {}
            _ => {
                return Err(said(
                    "the installed build's command resolves to another file",
                ));
            }
        }
        for (directory, identity) in &self.directories {
            match std::fs::metadata(directory) {
                Ok(found) if (found.dev(), found.ino()) == *identity => {}
                _ => return Err(said("a directory on the route is not the one recorded")),
            }
        }
        let file = std::fs::File::open(&self.program)
            .map_err(|error| said(&format!("the program cannot be opened: {error}")))?;
        let metadata = file.metadata().map_err(|error| said(&error.to_string()))?;
        if Self::digest_of(file, &metadata).map_err(|why| said(&why))? != self.digest {
            return Err(said("its bytes differ"));
        }
        Ok(&self.program)
    }

    /// A command that runs the program, with the name it is typed as as its first word, once the
    /// route is checked ([`PlacedProgram::checked`]), in the directory that was recorded: reached
    /// by the walk from the pin with no link followed, compared on the same handle, and named by the
    /// place that handle has now ([`PlacedDirectory::place_for_a_start`]).
    ///
    /// # Errors
    ///
    /// Returns why the route or the directory is not as it was placed.
    pub fn command(&self, root: &Path, pin: &RootPin) -> Result<Command, String> {
        let mut command = Command::new(self.checked(root, pin)?);
        std::os::unix::process::CommandExt::arg0(&mut command, &self.command);
        command.current_dir(self.work.place_for_a_start(root, pin)?);
        Ok(command)
    }
}

/// The environment a session is created with, and so the environment its shell and the agent
/// run in: the host's own variables for `kr`, the run's PATH ([`session_path`]), the run's home as
/// the home and the startup directory, every proxy variable at a loopback port nothing listens on
/// (loopback itself excepted, where a terminal route's own server listens), and the build's own
/// switches, `switches`.
#[must_use]
pub fn session_variables(
    host: &Host<'_>,
    shell: &ManagedShell,
    switches: &std::collections::BTreeMap<String, String>,
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
    variables.push(("PATH".to_owned(), session_path(host.run())));
    // What a program in the session unpacks for itself lands in the run, not the system's own
    // temporary directory.
    let temporary = host.run().root().join("tmp");
    if !temporary.is_dir() {
        kr_ipc::paths::create_private_tree(host.run().root(), &temporary)
            .expect("the run's temporary directory");
    }
    variables.push(("TMPDIR".to_owned(), temporary.display().to_string()));
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
    for (name, value) in switches {
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
    std::fs::write(home.join(".zshrc"), startup_file()).expect("writes the startup file");
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

/// What a session a person starts with their own home reads as its default keychain.
#[derive(Clone, Debug)]
pub struct OwnHome {
    /// The line `security default-keychain` printed in the session.
    pub default_keychain: String,
    /// The execution context the host chose for the session, as `kr list --json` names it.
    pub worker_profile: serde_json::Value,
    /// Whether the host named a desktop the session is bound to.
    pub bound_to_a_desktop: bool,
    /// What `security show-keychain-info` exited with in the session, where it said: 36, user
    /// interaction not allowed, is a keychain a program in the session cannot read.
    pub keychain_info_status: Option<i64>,
}

/// Starts a session the way a person does, `kr new` at a terminal with no choice of execution
/// context, so the host gives it the one it gives every session, with `home` as the session's home
/// and no agent; reads the default keychain its shell sees with `security default-keychain`, and
/// whether a program there can read it with `security show-keychain-info`, neither of which changes
/// anything; and ends the session.
///
/// The session's shell reads the run's own startup file, not the person's, so nothing of theirs
/// runs; what the keychain search depends on, the home the session names, is theirs.
///
/// # Panics
///
/// Panics when the session does not start, or `security` prints no keychain.
#[must_use]
pub fn default_keychain_of_a_session(
    host: &Host<'_>,
    shell: &ManagedShell,
    home: &Path,
) -> OwnHome {
    let run = host.run();
    let mut variables: Vec<(String, String)> = host
        .variables()
        .into_iter()
        .filter(|(name, _)| name != "TERM")
        .collect();
    variables.push(("TERM".to_owned(), Keyboard::PROFILE.to_owned()));
    variables.push(("ZDOTDIR".to_owned(), run.home().display().to_string()));
    variables.push(("SHELL".to_owned(), shell.executable.display().to_string()));
    variables.push(("LANG".to_owned(), "en_US.UTF-8".to_owned()));
    // The run's startup file and the package integration are installed with the run's home.
    prepare_home(host, &variables);
    for (name, value) in &mut variables {
        if name == "HOME" {
            *value = home.display().to_string();
        }
    }
    let work = run.work().display().to_string();
    let executable = shell.executable.display().to_string();
    let before: Vec<String> = host
        .live_sessions()
        .iter()
        .map(|session| session["session_id"].to_string())
        .collect();
    let (mut window, queries) = Window::open_answering(
        run,
        "a session with the person's own home",
        &run.binary("kr"),
        &[
            "new",
            "--attach",
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
        &variables,
    );
    answered(&window, queries);
    let _ = window.wait_for_screen(PROMPT.trim_end(), "the managed shell reads at its terminal");
    let created: Vec<serde_json::Value> = host
        .live_sessions()
        .into_iter()
        .filter(|session| !before.contains(&session["session_id"].to_string()))
        .collect();
    assert_eq!(created.len(), 1, "one new live session: {created:?}");
    window.type_text(b"/usr/bin/security default-keychain\r");
    let rows = window.wait_for_screen(".keychain", "security names the default keychain");
    let named = rows
        .iter()
        .find(|row| row.contains(".keychain") && !row.contains("security default-keychain"))
        .map(|row| row.trim().to_owned())
        .expect("a keychain row");
    // Whether a program in the session can read that keychain: the status alone, as 1000 more than
    // itself so the line that shows it is not the command's own echo, and nothing it printed.
    window.type_text(
        b"/usr/bin/security show-keychain-info >/dev/null 2>&1; echo kr-keychain-probe-$(( $? + 1000 ))\r",
    );
    let rows = window.wait_for_screen(
        "kr-keychain-probe-1",
        "the session says how its keychain answered",
    );
    let keychain_info_status = rows
        .iter()
        .find_map(|row| {
            let at = row.find("kr-keychain-probe-1")?;
            row[at + "kr-keychain-probe-".len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<i64>()
                .ok()
        })
        .map(|shown| shown - 1000);
    window.type_text(b"exit\r");
    let _ = window.exit_code(LIVENESS);
    OwnHome {
        default_keychain: named,
        worker_profile: created[0]["worker_profile"].clone(),
        bound_to_a_desktop: created[0]["desktop"]["desktop_session_id"].is_string(),
        keychain_info_status,
    }
}

/// Starts a session with `kr new --attach` in a window of its own, with exactly `variables`, in the
/// host's headless context and with no agent, waits for its shell to read, and returns the names
/// its shell exports as it wrote them before its first prompt, one on each line and never a value,
/// ending with [`LIST_END`]. Then it ends the session. The home must have been prepared with
/// [`prepare_home`] first, so that the shell writes its names.
///
/// # Panics
///
/// Panics when the session does not come up or its shell writes no whole list in time.
#[must_use]
pub fn names_a_session_exports(
    host: &Host<'_>,
    shell: &ManagedShell,
    variables: &[(String, String)],
) -> String {
    let run = host.run();
    let file = run.home().join(EXPORTED_FILE);
    crate::provenance::forget_names(&file).unwrap_or_else(|why| panic!("{why}"));
    let work = run.work().display().to_string();
    let executable = shell.executable.display().to_string();
    let (mut window, queries) = Window::open_answering(
        run,
        "a session that exports names",
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
    answered(&window, queries);
    let _ = window.wait_for_screen(PROMPT.trim_end(), "the managed shell reads at its terminal");
    let deadline = Instant::now() + LIVENESS;
    let names = loop {
        let read = std::fs::read_to_string(&file);
        if let Ok(names) = &read
            && names.lines().last() == Some(LIST_END)
        {
            break names.clone();
        }
        assert!(
            Instant::now() < deadline,
            "the session's shell wrote no whole list of the names it exports to {}",
            file.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    window.type_text(b"exit\r");
    let _ = window.exit_code(LIVENESS);
    names
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

/// Where a session's processes run: the host's headless user context, bound to no desktop and
/// given none of its handles, where nothing can show a dialog; or the person's desktop, as the
/// sessions a person starts at their own terminal do, where a login kept as a keychain item can
/// be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// `kr new --headless`.
    Headless,
    /// `kr new --desktop`.
    Desktop,
}

/// Opens a managed session with `kr new --attach` on a window of its own, in `context`, with
/// exactly `variables`, and waits for its shell to read.
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
    context: Context,
) -> Session {
    let run = host.run();
    let before: Vec<String> = host
        .live_sessions()
        .iter()
        .map(|session| session["session_id"].to_string())
        .collect();
    let work = run.work().display().to_string();
    let executable = shell.executable.display().to_string();
    let (window, queries) = Window::open_answering(
        run,
        what,
        &run.binary("kr"),
        &[
            "new",
            "--attach",
            match context {
                Context::Headless => "--headless",
                Context::Desktop => "--desktop",
            },
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
    answered(&window, queries);
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
    let worker = run.worker_of(&session_id.to_string());
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
/// A process belongs to the build when its command line names one of the provenance's marks, or
/// the file it executes lies in one of them: the build's own directory, its runtime's, and the
/// run's link to the installation. A helper an agent starts from somewhere else, such as a probe it
/// unpacks into its home and runs for a moment, is recorded with the run all the same, and ended
/// with it, but it is not the execution a part watches.
///
/// The screen must not show `ready` before the command is typed, so a screen left from an earlier
/// program is never read as this one's. Before the command is typed, the PATH the shell searches is
/// checked and the session is watched from then to the end of the part; once the agent draws its
/// first screen, the image every process beneath the shell maps is recorded and checked, and the
/// launch must have run `expected` in the way its build list names ([`Provenance`]). `between` is
/// called just before the command is typed and every few tens of milliseconds while the agent is
/// awaited, for what the part checks. `command` is the program the shell must find first in the run's
/// link to the build: the line's first word, or, where a wrapper the system provides starts it (the
/// sandbox program), the program the wrapper starts.
///
/// # Panics
///
/// Panics when the screen already shows `ready`, the agent does not draw it, nothing of the build
/// runs beneath the shell, the session searched or ran anything but the build under test, its
/// runtime, the run's own and the system's, or its shell exports a variable the build list clears;
/// and where `between` panics.
#[must_use]
pub fn launch(
    run: &Run,
    session: &Session,
    start: (&str, &str, &str),
    provenance: &Provenance,
    expected: &Expected,
    between: &dyn Fn(),
) -> Vec<AgentProcess> {
    match launch_or_refusal(run, session, start, None, provenance, expected, between) {
        Ok(processes) => processes,
        Err(refused) => panic!(
            "the agent was refused where a launch was expected to reach its first screen: {refused}"
        ),
    }
}

/// The staged parts start only the test's own stand-in: the program a part runs is checked to be
/// this build's `agent-stand-in`, by the bytes of the file the typed command resolves to and not by
/// the digest the build's description states. A part's live route, with the pinned build and its
/// login, is closed until the parts' own round, since the parts run `kr` after the agent has
/// started, in a run's state that the agent can change. Every part passes this check before it
/// starts its first program ([`closed_for_all_but_the_stand_in`]).
///
/// The description's digest must name the stand-in, the launch must be a native one, `command` in
/// the installed build's `bin` must resolve to the file the description pins, and that file's own
/// digest, read now, must be the stand-in's.
///
/// # Errors
///
/// Returns the refusal, which says that nothing was started.
pub fn closed_route(expected: &Expected, command: &str, stand_in: &Path) -> Result<(), String> {
    let digest_of = |path: &Path| {
        std::fs::read(path).map(|bytes| {
            kr_cbor::sha256(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
    };
    let refused = |why: &str| {
        Err(format!(
            "the staged parts' live route is closed until their own round: {why}, so nothing was \
             started"
        ))
    };
    if !digest_of(stand_in).is_ok_and(|digest| digest == expected.sha256) {
        return refused("the program this launch must run is not the test's own stand-in");
    }
    if expected.launch != crate::build::Launch::Native
        || std::fs::canonicalize(expected.prefix.join("bin").join(command))
            .ok()
            .as_deref()
            != Some(expected.file.as_path())
    {
        return refused("the command this launch types does not run the file the build pins");
    }
    if !digest_of(&expected.file).is_ok_and(|digest| digest == expected.sha256) {
        return refused("the file this launch runs is not the test's own stand-in");
    }
    Ok(())
}

/// The check every staged part passes before it starts its first program, a probe of the build, a
/// session or the agent: the build the part is given must be this crate's own stand-in
/// ([`closed_route`]).
///
/// # Errors
///
/// Returns the refusal, which says that nothing was started.
pub fn closed_for_all_but_the_stand_in(build: &crate::build::Build) -> Result<(), String> {
    closed_route(
        &Expected::pinned(build),
        &build.command,
        &built_directory().join("agent-stand-in"),
    )
}

/// An agent's start that reached no first screen because the agent refused to run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    /// The text of those the caller named that the screen showed, or none where the shell's prompt
    /// came back below the typed command instead.
    pub shown: Option<String>,
    /// The screen when it was seen.
    pub rows: Vec<String>,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.shown {
            Some(text) => write!(formatter, "the agent's screen shows {text:?}")?,
            None => formatter.write_str("the shell's prompt came back below the typed command")?,
        }
        write!(formatter, ", and the screen is:\n{}", self.rows.join("\n"))
    }
}

/// [`launch`], where the caller says what a refusal looks like: `refusal` names the texts the
/// agent shows when it will not run (`Some`, however many), and a start that shows one of them, or
/// ends so that the shell's prompt comes back below the typed command, before it shows `ready`, is
/// returned as [`Refused`] and not a panic. A start that shows neither within [`LIVENESS`] still
/// panics: nothing says the agent refused.
///
/// # Errors
///
/// Returns [`Refused`] as above.
///
/// # Panics
///
/// As [`launch`] does, for everything but a refusal.
pub fn launch_or_refusal(
    run: &Run,
    session: &Session,
    (line, ready, command): (&str, &str, &str),
    refusal: Option<&[String]>,
    provenance: &Provenance,
    expected: &Expected,
    between: &dyn Fn(),
) -> std::result::Result<Vec<AgentProcess>, Refused> {
    assert!(
        !session
            .window
            .screen()
            .iter()
            .any(|row| row.contains(ready)),
        "the screen already shows {ready:?} before `{line}` is typed"
    );
    provenance
        .check_path(command)
        .unwrap_or_else(|why| panic!("{why}"));
    provenance
        .check_cleared()
        .unwrap_or_else(|why| panic!("{why}"));
    provenance.watch(session.root_shell.clone());
    // The last look before the agent's command is typed, once the session is set up.
    between();
    let typed_at = session.window.mark();
    provenance
        .forget_started()
        .unwrap_or_else(|why| panic!("{why}"));
    session.window.type_text(format!("{line}\r").as_bytes());
    // The shell writes the names it exports just before it runs the line: what the agent starts
    // with, checked before anything is typed to it. What the shell started for the line is
    // recorded with the run before the part stops, so an agent that started with a name the build
    // list clears is ended with everything else, having been sent nothing.
    if let Err(why) = provenance.check_cleared_at_start(Duration::from_secs(10)) {
        // A search that does not finish keeps its reason with the run, whose close fails on it; the
        // part still stops on the refusal.
        let began = Instant::now();
        loop {
            let searched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                beneath(run, &session.root_shell, "the agent")
            }));
            if searched.map_or(true, |found| !found.is_empty())
                || began.elapsed() >= Duration::from_secs(2)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("{why}");
    }
    let drawn = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let waited = Instant::now();
        loop {
            between();
            let rows = session.window.screen();
            if rows.iter().any(|row| row.contains(ready)) {
                return Ok(rows);
            }
            if let Some(texts) = refusal {
                let shown = texts
                    .iter()
                    .find(|text| rows.iter().any(|row| row.contains(text.as_str())));
                let prompt_back = {
                    let since = session.window.collected().since(typed_at);
                    String::from_utf8_lossy(&since).contains(PROMPT.trim_end())
                };
                if shown.is_some() || prompt_back {
                    return Err(Refused {
                        shown: shown.cloned(),
                        rows,
                    });
                }
            }
            assert!(
                waited.elapsed() < LIVENESS,
                "the agent draws its first screen: its terminal did not show {ready:?} within \
                 {LIVENESS:?}, and its screen is:\n{}",
                rows.join("\n")
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }));
    let drawn = match drawn {
        Ok(Ok(rows)) => Ok(rows),
        Ok(Err(refused)) => return Err(refused),
        Err(panic) => Err(panic),
    };
    if let Err(panic) = drawn {
        // What the program wrote since its command was typed says why it did not draw, where
        // the screen it left no longer does.
        let since = session.window.collected().since(typed_at);
        let head = &since[..since.len().min(16384)];
        let tail = &since[since.len().saturating_sub(1024).max(head.len())..];
        eprintln!(
            "the terminal was sent, since `{line}` was typed, first: {}\nand last: {}",
            String::from_utf8_lossy(head).escape_debug(),
            String::from_utf8_lossy(tail).escape_debug()
        );
        std::panic::resume_unwind(panic);
    }
    let started = Instant::now();
    let shell = u32::try_from(session.root_shell.pid.get()).expect("a process number");
    loop {
        between();
        let everything = beneath(run, &session.root_shell, "the agent");
        let found: Vec<AgentProcess> = everything
            .iter()
            .filter(|process| process.parent == shell || belongs(process, provenance.marks()))
            .cloned()
            .collect();
        if !found.is_empty() {
            provenance
                .record(&everything)
                .unwrap_or_else(|why| panic!("{why}"));
            provenance
                .verify_launch(&found, session.root_shell.pid.get(), expected, line)
                .unwrap_or_else(|why| panic!("{why}"));
            return Ok(found);
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
/// A number in the process table can name another process by the time it is looked up, so a
/// process is taken only as the run's own search takes it: its start identity is read, its parent
/// is read again while that start holds the number, and the parent it was found under must still
/// be the process it was. Anything else is passed over, never recorded, and so never ended.
///
/// # Panics
///
/// Panics when the search does not finish, which the run's closing check would also fail on.
#[must_use]
pub fn beneath(run: &Run, ancestor: &ProcessStartIdentity, what: &str) -> Vec<AgentProcess> {
    // A search that does not finish keeps its reason with the run before it stops the part, so the
    // run's close fails on it too: what was not found was not ended either.
    let fail = |why: String| -> ! {
        run.undiscovered(&why);
        panic!("{why}")
    };
    run.record_descendants(ancestor, what)
        .unwrap_or_else(|why| panic!("the processes beneath {what}: {why}"));
    let table =
        process_table().unwrap_or_else(|why| fail(format!("the processes beneath {what}: {why}")));
    let mut found = Vec::new();
    let mut under = vec![ancestor.clone()];
    while let Some(parent) = under.pop() {
        let parent_pid = u32::try_from(parent.pid.get()).expect("a process number");
        for entry in table.iter().filter(|entry| entry.parent == parent_pid) {
            let identity = match query_process(entry.pid) {
                ProcessQuery::Present(identity) => identity,
                ProcessQuery::Gone => continue,
                // One of the system's own programs running as another user is none of the
                // agent's processes: it is noted for the run's close, and it may start nothing,
                // since what it started could not be followed back to it.
                ProcessQuery::CannotEstablish(error) => {
                    let Some(path) = kr_e2e_m1b::run::system_program_of_another_user(
                        entry.pid,
                        &error.to_string(),
                    ) else {
                        fail(format!(
                            "process {} beneath {what} could not be identified: {error}",
                            entry.pid
                        ))
                    };
                    run.note_system_program(entry.pid, &path);
                    if let Some(child) = table.iter().find(|child| child.parent == entry.pid) {
                        fail(format!(
                            "the system program {} (process {}) beneath {what} started process \
                             {}, which cannot be followed back to it",
                            path.display(),
                            entry.pid,
                            child.pid
                        ))
                    }
                    continue;
                }
            };
            let Some(described) = describe(&identity)
                .unwrap_or_else(|why| fail(format!("the processes beneath {what}: {why}")))
            else {
                continue;
            };
            match process_state(&parent) {
                ProcessState::Running => {}
                ProcessState::Ended => continue,
                ProcessState::Unknown { detail } => fail(format!(
                    "whether the parent of process {} runs is not established: {detail}",
                    entry.pid
                )),
            }
            if described.parent != parent_pid {
                continue;
            }
            run.record(identity.clone(), &format!("{what}: {}", described.command));
            found.push(AgentProcess {
                identity: identity.clone(),
                command: described.command,
                parent: parent_pid,
            });
            under.push(identity);
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

/// Every file a process maps as text, the executable first, each with its inode.
///
/// # Errors
///
/// Returns why the mappings could not be read.
pub fn mapped_files(pid: u32) -> Result<Vec<(PathBuf, u64)>, String> {
    let mut lsof = Command::new("/usr/sbin/lsof");
    lsof.args(["-a", "-p", &pid.to_string(), "-d", "txt", "-Fin"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin");
    let output = output_within(lsof, LIVENESS).map_err(|why| format!("lsof {why}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut found = Vec::new();
    let mut inode = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix('i') {
            inode = value.parse::<u64>().ok();
        } else if let Some(name) = line.strip_prefix('n')
            && let Some(inode) = inode.take()
        {
            found.push((PathBuf::from(name), inode));
        }
    }
    if found.is_empty() {
        return Err(format!("lsof named no text file for process {pid}: {text}"));
    }
    Ok(found)
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
            .env(run.mark().0, run.mark().1)
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

    /// The attachment this keyboard types through.
    #[must_use]
    pub const fn attachment_id(&self) -> kr_protocol::ids::AttachmentId {
        self.attachment_id
    }

    /// The lease epoch it holds.
    #[must_use]
    pub const fn epoch(&self) -> kr_protocol::ids::InputLeaseEpoch {
        self.epoch
    }

    /// The sequence its next input carries.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next
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
    /// connection's ordered input with every byte forwarded to the terminal or held as the start of
    /// a bracketed-paste delimiter, as a lone Escape is while the terminal takes pastes: the worker
    /// forwards such a prefix once its short deadline passes.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, or an acknowledgement that is not of these bytes.
    pub fn type_text(
        &mut self,
        remote: &Remote,
        runtime: &tokio::runtime::Runtime,
        text: &str,
    ) -> Result<kr_protocol::input::InputWriteResult, InputRefusal> {
        let params = kr_protocol::input::InputWriteParams {
            session_id: self.session_id,
            attachment_id: self.attachment_id,
            epoch: self.epoch,
            sequence: kr_protocol::ids::InputSequence::new(self.next),
            input: kr_protocol::input::InputContent::Bytes {
                bytes: kr_protocol::scalars::Bytes::new(text.as_bytes().to_vec()),
            },
        };
        let written = runtime
            .block_on(remote.session().write_input(&params))
            .map_err(|error| InputRefusal {
                code: match &error {
                    kr_client::error::ClientError::Host(refusal) => Some(refusal.code),
                    _ => None,
                },
                detail: format!("input.write: {error}"),
            })?;
        let length = u64::try_from(text.len()).unwrap_or(u64::MAX);
        let taken = written
            .forwarded_bytes
            .get()
            .saturating_add(written.held_prefix_bytes.get());
        if written.sequence.get() != self.next || taken < length {
            return Err(InputRefusal {
                code: None,
                detail: format!(
                    "input {} of {length} bytes was acknowledged as {} with {} bytes forwarded \
                     and {} held",
                    self.next,
                    written.sequence.get(),
                    written.forwarded_bytes.get(),
                    written.held_prefix_bytes.get()
                ),
            });
        }
        self.next += 1;
        Ok(written)
    }
}

/// Why typed input was not taken.
#[derive(Clone, Debug)]
pub struct InputRefusal {
    /// The code the host refused it with, when the host answered with a refusal.
    pub code: Option<kr_protocol::error::ErrorCode>,
    /// What happened, in words.
    pub detail: String,
}

impl std::fmt::Display for InputRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance::exported_clear;

    /// A part asked for a program that is not the test's own stand-in is refused, with the closed
    /// route named and nothing started; the stand-in itself is let through, a stand-in file that is
    /// not there refuses too, and so does a description that states the stand-in's digest over
    /// another file, or whose command resolves to another file than the one it pins.
    #[test]
    fn a_part_asked_for_the_pinned_build_is_refused_before_anything_is_started() {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("the temporary directory")
            .join(format!("kr-closed-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(base.join("bin")).expect("a scratch directory");
        let stand_in = base.join("agent-stand-in");
        std::fs::write(&stand_in, b"the stand-in").expect("a stand-in");
        let installed = base.join("bin/codex");
        std::fs::write(&installed, b"the stand-in").expect("the installed build");
        let other = base.join("other");
        std::fs::write(&other, b"another build").expect("another build");
        let digest: String = kr_cbor::sha256(b"the stand-in")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let expected = |sha256: &str, file: &Path| Expected {
            file: file.to_path_buf(),
            sha256: sha256.to_owned(),
            launch: crate::build::Launch::Native,
            prefix: base.clone(),
        };
        closed_route(&expected(&digest, &installed), "codex", &stand_in)
            .expect("the stand-in is let through");
        let said = closed_route(&expected(&"0".repeat(64), &installed), "codex", &stand_in)
            .expect_err("the pinned build is refused");
        assert!(said.contains("live route is closed"), "{said}");
        assert!(said.contains("nothing was started"), "{said}");
        assert!(
            closed_route(
                &expected(&digest, &installed),
                "codex",
                &base.join("missing")
            )
            .is_err()
        );
        // The description states the stand-in's digest, and the file it pins is another file.
        let said = closed_route(&expected(&digest, &other), "codex", &stand_in)
            .expect_err("a digest stated over another file is refused");
        assert!(
            said.contains("does not run the file the build pins"),
            "{said}"
        );
        // The file the description pins has the stand-in's bytes, and the installed command is a link
        // to another build: what the typed line runs is not what the digest was read from.
        let pinned = base.join("pinned");
        std::fs::write(&pinned, b"the stand-in").expect("a copy of the stand-in");
        std::fs::remove_file(&installed).expect("the installed build goes");
        std::os::unix::fs::symlink(&other, &installed).expect("a link to another build");
        let said = closed_route(&expected(&digest, &pinned), "codex", &stand_in)
            .expect_err("a command that resolves to another file is refused");
        assert!(
            said.contains("does not run the file the build pins"),
            "{said}"
        );
        // The pinned file is the one the command resolves to, and its bytes are not the stand-in's.
        let said = closed_route(&expected(&digest, &other), "codex", &stand_in)
            .expect_err("a file that is not the stand-in is refused");
        assert!(said.contains("live route is closed"), "{said}");
        std::fs::remove_dir_all(&base).expect("clean up");
    }

    /// An installation whose `bin/codex` is a script that appends `name` to `mark`.
    fn installation(base: &Path, name: &str, mark: &Path) -> PathBuf {
        let prefix = base.join(name);
        std::fs::create_dir_all(prefix.join("bin")).expect("an installation");
        let program = prefix.join("bin/codex");
        std::fs::write(
            &program,
            format!("#!/bin/sh\necho {name} >> '{}'\n", mark.display()),
        )
        .expect("a program");
        std::fs::set_permissions(
            &program,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("executable");
        prefix
    }

    /// The agent's program is started only by the route that was placed: a link at `agent/current`
    /// to another installation, a link in `agent/runtime` that is another, a command of the
    /// installed build that resolves to another file, and a program rewritten in place are each a
    /// class, and the other installation's program, which leaves a mark when it runs, never runs;
    /// the placed program, run first, does.
    #[test]
    fn a_route_that_is_not_the_one_placed_is_a_class_and_no_other_program_runs() {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("the temporary directory")
            .join(format!("kr-route-{}", kr_ipc::new_uuid()));
        let root = base.join("run");
        std::fs::create_dir_all(root.join("agent/runtime")).expect("the run's installation");
        let mark = base.join("mark");
        let (one, two) = (
            installation(&base, "one", &mark),
            installation(&base, "two", &mark),
        );
        let runtime = base.join("node");
        std::fs::write(&runtime, b"a runtime").expect("a runtime");
        let current = root.join("agent/current");
        std::os::unix::fs::symlink(&one, &current).expect("the link");
        std::os::unix::fs::symlink(&runtime, root.join("agent/runtime/node")).expect("a runtime");
        std::fs::create_dir(root.join("w")).expect("the working directory");
        let pin = RootPin::of(&root).expect("a pin");
        let work = PlacedDirectory::record(&root, &pin, Path::new("w")).expect("the directory");
        let placed = PlacedProgram::record(
            &one,
            std::slice::from_ref(&runtime),
            "codex",
            "bin/codex",
            work,
        )
        .expect("recorded");
        let marks = || std::fs::read_to_string(&mark).unwrap_or_default();
        let ran = |placed: &PlacedProgram| -> Result<(), String> {
            let mut command = placed.command(&root, &pin)?;
            let status = command.status().map_err(|error| error.to_string())?;
            assert!(status.success());
            Ok(())
        };
        ran(&placed).expect("the placed route is started");
        assert_eq!(marks(), "one\n");
        // A link at agent/current to another installation, whose codex leaves a mark.
        std::fs::remove_file(&current).expect("the link goes");
        std::os::unix::fs::symlink(&two, &current).expect("another installation");
        let said = ran(&placed).expect_err("another installation is not started");
        assert!(said.contains("agent/current"), "{said}");
        assert_eq!(marks(), "one\n", "the other installation's codex never ran");
        std::fs::remove_file(&current).expect("the link goes");
        std::os::unix::fs::symlink(&one, &current).expect("the placed link");
        ran(&placed).expect("the placed link is as it was");
        // A link in agent/runtime that is another.
        std::fs::remove_file(root.join("agent/runtime/node")).expect("the link goes");
        std::os::unix::fs::symlink(base.join("elsewhere"), root.join("agent/runtime/node"))
            .expect("another runtime");
        assert!(
            ran(&placed)
                .expect_err("another runtime")
                .contains("agent/runtime/node")
        );
        std::fs::remove_file(root.join("agent/runtime/node")).expect("the link goes");
        std::os::unix::fs::symlink(&runtime, root.join("agent/runtime/node")).expect("as it was");
        // The installed build's command is now a link to the other installation's file.
        let program = one.join("bin/codex");
        let held = base.join("held");
        std::fs::rename(&program, &held).expect("the program moves");
        std::os::unix::fs::symlink(two.join("bin/codex"), &program).expect("a link");
        assert!(
            ran(&placed)
                .expect_err("another file")
                .contains("another file")
        );
        std::fs::remove_file(&program).expect("the link goes");
        std::fs::rename(&held, &program).expect("the program is back");
        ran(&placed).expect("the placed program is as it was");
        // A directory on the route replaced by another that holds the same program.
        let bin = one.join("bin");
        let held_bin = base.join("held-bin");
        std::fs::rename(&bin, &held_bin).expect("the directory moves");
        std::fs::create_dir(&bin).expect("another directory");
        std::fs::copy(held_bin.join("codex"), bin.join("codex")).expect("a copy of the program");
        std::fs::set_permissions(
            bin.join("codex"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("executable");
        assert!(
            ran(&placed)
                .expect_err("another directory")
                .contains("directory on the route")
        );
        std::fs::remove_dir_all(&bin).expect("the copy goes");
        std::fs::rename(&held_bin, &bin).expect("the directory is back");
        ran(&placed).expect("the placed directory is as it was");
        // The program rewritten in place, to bytes of another length.
        std::fs::write(
            &program,
            "#!/bin/sh\necho rewritten >> /dev/null\n# more bytes\n",
        )
        .expect("rewritten");
        assert!(
            ran(&placed)
                .expect_err("rewritten")
                .contains("bytes differ")
        );
        assert_eq!(
            marks(),
            "one\none\none\none\n",
            "only the placed program ever ran"
        );
        std::fs::remove_dir_all(&base).expect("clean up");
    }

    /// The agent's program is started in the directory that was placed, reached by the walk from the
    /// pin with no link followed and compared on the same handle: a link left in place of the
    /// directory (the directory itself moved aside), another directory made in its place, and no
    /// directory at all are each a class, and the program, which writes the directory it started in
    /// to a file when it runs, never starts outside; the placed directory, run first and again once
    /// it is back, is the one it starts in.
    #[test]
    fn a_working_directory_that_is_not_the_one_placed_is_refused_and_nothing_starts_outside() {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .expect("the temporary directory")
            .join(format!("kr-work-{}", kr_ipc::new_uuid()));
        let root = base.join("run");
        std::fs::create_dir_all(root.join("agent/runtime")).expect("the run's installation");
        std::fs::create_dir(root.join("w")).expect("the working directory");
        let outside = base.join("outside");
        std::fs::create_dir(&outside).expect("a directory outside the run");
        let mark = base.join("mark");
        let prefix = base.join("build");
        std::fs::create_dir_all(prefix.join("bin")).expect("an installation");
        let program = prefix.join("bin/codex");
        std::fs::write(
            &program,
            format!("#!/bin/sh\npwd -P >> '{}'\n", mark.display()),
        )
        .expect("a program");
        std::fs::set_permissions(
            &program,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("executable");
        std::os::unix::fs::symlink(&prefix, root.join("agent/current")).expect("the link");
        let pin = RootPin::of(&root).expect("a pin");
        let work = PlacedDirectory::record(&root, &pin, Path::new("w")).expect("the directory");
        let placed =
            PlacedProgram::record(&prefix, &[], "codex", "bin/codex", work).expect("recorded");
        let started_in = || std::fs::read_to_string(&mark).unwrap_or_default();
        let ran = || -> Result<(), String> {
            let status = placed
                .command(&root, &pin)?
                .status()
                .map_err(|error| error.to_string())?;
            assert!(status.success());
            Ok(())
        };
        ran().expect("the placed directory is started in");
        assert_eq!(started_in(), format!("{}\n", root.join("w").display()));
        // The directory moved aside and a link to a directory outside left in its place.
        std::fs::rename(root.join("w"), root.join("w2")).expect("the directory moves");
        std::os::unix::fs::symlink(&outside, root.join("w")).expect("a link in its place");
        let said = ran().expect_err("a link in place of the directory is not started in");
        assert!(said.contains("symbolic link"), "{said}");
        std::fs::remove_file(root.join("w")).expect("the link goes");
        // No directory at the place at all.
        let said = ran().expect_err("no directory is not started in");
        assert!(said.contains("not there"), "{said}");
        // Another directory made in its place.
        std::fs::create_dir(root.join("w")).expect("another directory");
        let said = ran().expect_err("another directory is not started in");
        assert!(said.contains("another directory"), "{said}");
        std::fs::remove_dir(root.join("w")).expect("the other directory goes");
        std::fs::rename(root.join("w2"), root.join("w")).expect("the directory is back");
        ran().expect("the placed directory is as it was");
        assert_eq!(
            started_in(),
            format!("{0}\n{0}\n", root.join("w").display()),
            "only the placed directory was ever started in"
        );
        assert_eq!(
            std::fs::read_dir(&outside).expect("the outside").count(),
            0,
            "nothing was made outside"
        );
        std::fs::remove_dir_all(&base).expect("clean up");
    }

    /// The startup file's hooks write the names a session's shell exports and never a value: at the
    /// prompt, and again just before a command line runs, so that what the agent's line started
    /// with is what the second names. A variable exported after the prompt is only in the second, a
    /// variable that is only set is in neither, and the check refuses the one and passes the other.
    #[test]
    fn the_startup_files_hooks_write_the_names_a_shell_exports_and_never_a_value() {
        let shell = match kr_e2e_m1b::shells::managed_zsh() {
            Ok(shell) => shell,
            Err(why) if kr_e2e_m1b::shells::required() => {
                panic!("the startup file's hooks need the managed shell: {why}")
            }
            Err(why) => {
                eprintln!("skipping: the startup file's hooks: {why}");
                return;
            }
        };
        let unique: String = kr_ipc::new_uuid()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let directory = std::env::temp_dir().join(format!("kr-startup-{unique}"));
        std::fs::create_dir(&directory).expect("a directory of the test's own");
        std::fs::write(directory.join(".zshrc"), startup_file()).expect("writes the startup file");
        let value = "a-value-that-must-not-be-written";
        let output = std::process::Command::new(&shell.executable)
            .args([
                "-f",
                "-c",
                ". \"$ZDOTDIR/.zshrc\"; print -r -- \"${(j:,:)precmd_functions}:${(j:,:)preexec_functions}\"; \
                 PROBE_SET_ONLY=1; kr_agents_path; export PROBE_EXPORTED_LATE=1; kr_agents_started",
            ])
            .env_clear()
            .env("ZDOTDIR", &directory)
            .env("PATH", "/usr/bin:/bin")
            .env("PROBE_CLEARED_HERE", value)
            .output()
            .expect("the managed shell runs");
        assert!(output.status.success(), "the hooks run: {output:?}");
        assert!(
            output.stderr.is_empty(),
            "the startup file prints nothing to the session: {output:?}"
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "kr_agents_path:kr_agents_started\n",
            "each hook is registered where the shell runs it, and the startup file prints nothing else"
        );
        let read = |file: &str| {
            std::fs::read_to_string(directory.join(file)).expect("the hook wrote its names")
        };
        let (prompt, started) = (read(EXPORTED_FILE), read(STARTED_FILE));
        let path = read(PATH_FILE);
        std::fs::remove_dir_all(&directory).expect("removes the test's directory");
        for names in [&prompt, &started] {
            assert!(
                names.lines().any(|line| line == "PROBE_CLEARED_HERE")
                    && names.lines().any(|line| line == "PATH"),
                "an exported variable is named: {names}"
            );
            assert!(
                !names.lines().any(|line| line == "PROBE_SET_ONLY"),
                "a variable that is set and not exported is not: {names}"
            );
            assert!(
                !names.contains(value),
                "no value is written with the names: {names}"
            );
        }
        assert!(
            !prompt.lines().any(|line| line == "PROBE_EXPORTED_LATE")
                && started.lines().any(|line| line == "PROBE_EXPORTED_LATE"),
            "the second list is the one written just before the command line"
        );
        assert!(
            prompt.ends_with(&format!("{LIST_END}\n"))
                && started.ends_with(&format!("{LIST_END}\n")),
            "each list ends with its mark: {prompt} {started}"
        );
        assert_eq!(path.trim_end(), "/usr/bin:/bin");
        let cleared = ["PROBE_CLEARED_HERE".to_owned(), "PROBE_SET_ONLY".to_owned()];
        let refused =
            exported_clear(&started, &cleared, &[]).expect_err("the exported name is refused");
        assert!(refused.contains("PROBE_CLEARED_HERE") && !refused.contains("PROBE_SET_ONLY"));
        assert_eq!(exported_clear(&started, &cleared[1..], &[]), Ok(()));
        assert_eq!(
            exported_clear(
                &started,
                &["PROBE_*".to_owned()],
                &["PROBE_CLEARED_HERE".to_owned()]
            ),
            Err(format!(
                "{} the session's shell exports PROBE_EXPORTED_LATE, which the build list clears",
                crate::provenance::ENVIRONMENT_NOT_CLEAR
            ))
        );
    }
}
