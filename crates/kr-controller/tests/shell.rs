//! Creating a session with a shell, and setting that shell up.
//!
//! Three things meet here: which shell a create request is allowed to launch, what the session it
//! produces is labelled as, and what `kr shell` writes into the user's own configuration. None of
//! them can be answered by a unit test on its own, because each is a decision one component takes
//! about another's inputs.
//!
//! Every path is on the internal disk: the daemon's runtime tree, its registry and the shell
//! packages these tests install are all under a temporary host tree, and nothing a launched process
//! opens is in the workspace.

use std::path::Path;
use std::sync::Arc;

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{EnvironmentVariable, Presentation, SessionCreateParams, ShellMode};
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::host::package::{
    CURRENT_BASENAME, MANIFEST_BASENAME, PACKAGE_ROOT_VARIABLE, PackageManifest, PackageSet,
    PackageShell, PackageStartupEntry, ShellPackage, StartupMode,
};
use kr_shell_integration::host::startup::{self, Change, HomeLayout};
use kr_shell_integration::host::terminal::{
    self, Source, TerminalApplication, TerminalUnavailable,
};
use kr_worker::environment::{ExecutionContext, build as build_environment};

mod teardown;

/// A supervisor that starts nothing. Every test here is about what happens before a worker runs.
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

struct Host {
    _temp: kr_ipc::testing::TempHost,
    _controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

async fn host(shell_packages: Option<std::path::PathBuf>) -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(NoWorkers),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    Host {
        _temp: temp,
        _controller: controller,
        environment_id,
        endpoint,
    }
}

fn create(
    environment_id: EnvironmentId,
    mode: ShellMode,
    shell: Option<&str>,
) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable(shell.map(str::to_owned)),
        shell_mode: mode,
        cwd: Nullable::some("/".to_owned()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: Vec::new(),
        palette: Nullable::null(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        terminal: Nullable::null(),
    }
}

fn target(environment_id: EnvironmentId) -> ActionTarget {
    ActionTarget {
        environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// Installs a package the way a build does: an identity directory, a record and a current pointer.
///
/// The executable is a copy of a real program on the internal disk, because what these tests check
/// about it is that the host resolves and launches the package's own binary rather than a
/// substitute.
fn install_package(root: &Path, kind: ShellKind) {
    let identity = "identity-1";
    let directory = root.join(kind.as_str()).join(identity);
    std::fs::create_dir_all(directory.join("bin")).expect("creates the package");
    let executable = directory.join("bin").join(kind.as_str());
    kr_ipc::testing::place_program(std::path::Path::new("/bin/cat"), &executable);
    std::fs::create_dir_all(directory.join("startup")).expect("creates the entry directory");
    std::fs::write(
        directory.join("startup/entry"),
        b"# the package's own entry\n",
    )
    .expect("writes the entry");
    let manifest = PackageManifest {
        identity: identity.to_owned(),
        shell: PackageShell {
            kind,
            executable,
            upstream_version: "5.9".to_owned(),
            editor_abi: "zle-5.9".to_owned(),
            integration_version: "1".to_owned(),
            patches: Vec::new(),
            modules: Vec::new(),
        },
        startup_entry: PackageStartupEntry {
            file: "startup/entry".to_owned(),
        },
    };
    std::fs::write(
        directory.join(MANIFEST_BASENAME),
        serde_json::to_string(&manifest).expect("encodes"),
    )
    .expect("writes the record");
    std::fs::write(root.join(kind.as_str()).join(CURRENT_BASENAME), identity)
        .expect("names the identity this installation uses");
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.19, KR-REQ-07.20: an unsupported shell is named, and native_compat is labelled.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.19, KR-REQ-07.16.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_managed_create_without_a_qualified_package_is_refused_before_anything_is_spawned() {
    let packages = tempfile::tempdir().expect("a directory");
    // The daemon is told where its packages are rather than being expected to find a variable: a
    // test then describes an installation that has none without changing this process's own
    // environment.
    let host = host(Some(packages.path().to_path_buf())).await;
    let mut client = LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target(host.environment_id),
            &create(host.environment_id, ShellMode::Managed, None),
        )
        .await
        .expect("reaches the daemon")
        .expect_err("refused");
    assert_eq!(refused.code, ErrorCode::ShellIntegrationUnsupported);

    // A shell KalaReach qualifies, with no package installed for it, is the same refusal by name.
    install_package(packages.path(), ShellKind::Zsh);
    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target(host.environment_id),
            &create(host.environment_id, ShellMode::Managed, Some("/bin/ksh")),
        )
        .await
        .expect("reaches the daemon")
        .expect_err("refused");
    assert_eq!(refused.code, ErrorCode::ShellIntegrationUnsupported);
    assert!(
        refused.message.contains("ksh"),
        "the refusal names the shell: {}",
        refused.message
    );

    // And a script invocation never becomes an interactive shell.
    let refused = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target(host.environment_id),
            &create(
                host.environment_id,
                ShellMode::Managed,
                Some("zsh -c 'make release'"),
            ),
        )
        .await
        .expect("reaches the daemon")
        .expect_err("refused");
    assert_eq!(refused.code, ErrorCode::ShellIntegrationUnsupported);
}

/// KR-REQ-07.16: the worker launches the package its daemon resolved, not one of its own.
#[test]
fn the_package_a_worker_launches_is_the_one_the_daemon_resolved() {
    let admitted = tempfile::tempdir().expect("a directory");
    install_package(admitted.path(), ShellKind::Zsh);
    let elsewhere = tempfile::tempdir().expect("a second directory");
    install_package(elsewhere.path(), ShellKind::Zsh);

    let resolved = PackageSet::discover(admitted.path())
        .expect("reads the package")
        .select(Some("zsh"))
        .expect("qualified")
        .directory
        .clone();
    // What the worker is told to read is one directory, and reading it gives exactly the package
    // that directory holds: the other installation is a different build of the same shell and is
    // never reached from here.
    let launched = ShellPackage::read(&resolved).expect("reads the resolved package");
    assert_eq!(launched.directory, resolved);
    assert_eq!(launched.kind(), ShellKind::Zsh);
    let other = ShellPackage::read(
        &PackageSet::discover(elsewhere.path())
            .expect("reads the package")
            .select(Some("zsh"))
            .expect("qualified")
            .directory
            .clone(),
    )
    .expect("reads the other package");
    assert_ne!(
        launched.executable(),
        other.executable(),
        "two installations of the same shell are two different binaries"
    );

    // A directory with no identity record is a named failure rather than a fall back to discovery.
    let empty = tempfile::tempdir().expect("a third directory");
    assert!(ShellPackage::read(empty.path()).is_err());
}

/// KR-REQ-07.20, KR-ACC-035: stock compatibility is an explicit choice and never a substitution.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stock_shell_is_labelled_rather_than_claiming_the_managed_contract() {
    assert!(!ShellMode::NativeCompat.claims_managed_editor());
    assert!(ShellMode::Managed.claims_managed_editor());
    assert_eq!(ShellMode::NativeCompat.as_str(), "native_compat");
    // The controller refuses a managed create it cannot serve rather than quietly creating a
    // native_compat session in its place, which is what "never an automatic fallback" means.
    let packages = tempfile::tempdir().expect("a directory");
    let set = PackageSet::discover(packages.path()).expect("reads nothing");
    assert!(set.select(None).is_err());
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.16, KR-REQ-07.17: the exact package, its declared flags and its recorded identity.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.16, KR-REQ-07.17.
#[test]
fn a_managed_session_launches_the_package_binary_with_this_platforms_arguments() {
    let packages = tempfile::tempdir().expect("a directory");
    install_package(packages.path(), ShellKind::Zsh);
    let set = PackageSet::discover(packages.path()).expect("reads the package");
    let package = set.select(Some("zsh")).expect("qualified");
    assert_eq!(
        package.executable(),
        packages.path().join("zsh/identity-1/bin/zsh"),
        "the exact binary the reader patch was built into"
    );
    // The arguments belong to the host rather than to the record: a package says what it was built
    // from, not how a session starts it. Section 7 gives macOS the login startup and Linux the
    // interactive one, so what this asserts is the mode rather than one platform's answer.
    assert_eq!(package.arguments(StartupMode::Login), vec!["-l", "-i"]);
    assert_eq!(package.arguments(StartupMode::Interactive), vec!["-i"]);
    assert_eq!(
        package.interactive_flags(),
        package.arguments(StartupMode::for_host())
    );
    let identity = package.identity();
    assert_eq!(identity.kind, ShellKind::Zsh);
    assert_eq!(identity.upstream_version, "5.9");
    assert_eq!(identity.editor_abi, "zle-5.9");
    assert_eq!(identity.integration_version, "1");
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.25 to 07.28: what the root shell's environment is built from.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.25, KR-REQ-07.26, KR-REQ-07.27, KR-REQ-07.28.
#[test]
fn the_environment_is_the_creators_snapshot_filtered_and_then_the_contexts_and_then_the_hosts() {
    let session_id = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    let snapshot: Vec<EnvironmentVariable> = [
        ("PATH", "/usr/bin:/bin"),
        ("LANG", "en_GB.UTF-8"),
        ("ITERM_SESSION_ID", "w0t0p0"),
        ("LC_TERMINAL", "iTerm2"),
        ("WT_SESSION", "abc"),
        ("KONSOLE_DBUS_SESSION", "/Sessions/1"),
        ("TERM", "xterm-kitty"),
        ("SSH_TTY", "/dev/ttys004"),
        ("SSH_CONNECTION", "10.0.0.1 52000 10.0.0.2 22"),
        ("DISPLAY", ":99"),
        ("KR_SHELL_BRIDGE", "/tmp/forged"),
        ("KR_SHELL_BRIDGE_SECRET", "forged"),
        ("ANTHROPIC_API_KEY", "a-credential"),
    ]
    .into_iter()
    .map(|(name, value)| EnvironmentVariable {
        name: name.to_owned(),
        value: value.to_owned(),
    })
    .collect();
    let mut context = ExecutionContext::default();
    context
        .variables
        .insert("DISPLAY".to_owned(), ":0".to_owned());
    let built = build_environment(&snapshot, &context, "/opt/kr/zsh", "0.4.0", session_id);

    // Physical-terminal identity is removed and replaced, and the removal is what diagnostics show.
    for removed in [
        "ITERM_SESSION_ID",
        "LC_TERMINAL",
        "WT_SESSION",
        "KONSOLE_DBUS_SESSION",
        "SSH_TTY",
    ] {
        assert!(
            !built.variables.contains_key(removed),
            "{removed} is removed"
        );
        assert!(built.removed.iter().any(|name| name == removed));
    }
    assert_eq!(
        built.variables.get("TERM").map(String::as_str),
        Some("xterm-256color")
    );
    assert_eq!(
        built.variables.get("COLORTERM").map(String::as_str),
        Some("truecolor")
    );
    assert_eq!(
        built.variables.get("TERM_PROGRAM").map(String::as_str),
        Some("KalaReach")
    );
    assert_eq!(
        built
            .variables
            .get("TERM_PROGRAM_VERSION")
            .map(String::as_str),
        Some("0.4.0")
    );
    // `SHELL` names the executable that was actually launched.
    assert_eq!(
        built.variables.get("SHELL").map(String::as_str),
        Some("/opt/kr/zsh")
    );
    // Connection facts that describe the selected environment are kept.
    assert!(built.variables.contains_key("SSH_CONNECTION"));
    // The execution context wins over the creator's snapshot.
    assert_eq!(
        built.variables.get("DISPLAY").map(String::as_str),
        Some(":0")
    );
    // Reserved bootstrap values come only from the worker: a creator cannot preload one.
    assert!(!built.variables.contains_key("KR_SHELL_BRIDGE"));
    assert!(!built.variables.contains_key("KR_SHELL_BRIDGE_SECRET"));
    // A credential the creator had is passed to the shell and never named in the diagnostics.
    assert_eq!(
        built.variables.get("ANTHROPIC_API_KEY").map(String::as_str),
        Some("a-credential")
    );
    let diagnostics = format!("{:?} {:?}", built.sources, built.removed);
    assert!(
        !diagnostics.contains("a-credential"),
        "a credential never appears in diagnostics: {diagnostics}"
    );
    assert_eq!(built.sources.path, "creator snapshot");
    assert_eq!(built.sources.locale, "creator snapshot");
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.29, KR-REQ-07.30, KR-REQ-07.40, KR-REQ-07.41: the guarded startup entries.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.29, KR-REQ-07.30, KR-REQ-07.40.
#[test]
fn setup_adds_one_marked_entry_per_shell_and_removal_deletes_only_that() {
    let home = tempfile::tempdir().expect("a directory");
    let packages = tempfile::tempdir().expect("a directory");
    install_package(packages.path(), ShellKind::Zsh);
    install_package(packages.path(), ShellKind::Bash);
    let set = PackageSet::discover(packages.path()).expect("reads the packages");

    // The user has their own configuration, and a ZDOTDIR that moves where Zsh reads from.
    let zdotdir = home.path().join("dotfiles/zsh");
    std::fs::create_dir_all(&zdotdir).expect("creates ZDOTDIR");
    std::fs::write(zdotdir.join(".zshrc"), "export EDITOR=vim\n").expect("writes");
    std::fs::write(home.path().join(".bashrc"), "alias ll='ls -la'\n").expect("writes");
    std::fs::write(
        home.path().join(".bash_profile"),
        "export PATH=$PATH:/opt\n",
    )
    .expect("writes");
    let layout = HomeLayout {
        home: home.path().to_path_buf(),
        zdotdir: Some(zdotdir.clone()),
        xdg_config_home: None,
        powershell: None,
    };

    for package in set.packages() {
        for target in layout.targets(package.kind()) {
            let body = startup::entry(
                &target,
                &package.startup_entry(),
                package.kind() == ShellKind::Zsh,
            );
            assert_eq!(
                startup::install(&target.path, &body).expect("installs"),
                Change::Added
            );
        }
    }

    // Zsh's entry is in the file the shell actually reads.
    let zshrc = std::fs::read_to_string(zdotdir.join(".zshrc")).expect("reads");
    assert!(
        zshrc.starts_with("export EDITOR=vim\n"),
        "the user's own line is kept"
    );
    assert!(zshrc.contains(startup::MARKER_BEGIN));
    assert!(
        !home.path().join(".zshrc").exists(),
        "nothing is written to a file this shell does not read"
    );
    // Bash gets .bashrc and the login file that does not source it, and neither is replaced.
    let bashrc = std::fs::read_to_string(home.path().join(".bashrc")).expect("reads");
    assert!(bashrc.starts_with("alias ll='ls -la'\n"));
    let profile = std::fs::read_to_string(home.path().join(".bash_profile")).expect("reads");
    assert!(profile.starts_with("export PATH=$PATH:/opt\n"));
    // Nothing anywhere points a shell somewhere else.
    for text in [&zshrc, &bashrc, &profile] {
        for forbidden in ["ZDOTDIR=", "--rcfile", "--norc", "--noprofile"] {
            assert!(
                !text.contains(forbidden),
                "{forbidden} appears in a startup file"
            );
        }
    }
    // The bootstrap values are what activation depends on: the entry does nothing without them.
    assert!(zshrc.contains("KR_SHELL_BRIDGE"));

    // Removal deletes the marked entry and leaves everything else exactly as it was.
    for package in set.packages() {
        for target in layout.targets(package.kind()) {
            assert_eq!(
                startup::remove(&target.path).expect("removes"),
                Change::Removed
            );
        }
    }
    assert_eq!(
        std::fs::read_to_string(zdotdir.join(".zshrc")).expect("reads"),
        "export EDITOR=vim\n"
    );
    assert_eq!(
        std::fs::read_to_string(home.path().join(".bashrc")).expect("reads"),
        "alias ll='ls -la'\n"
    );
    assert_eq!(
        std::fs::read_to_string(home.path().join(".bash_profile")).expect("reads"),
        "export PATH=$PATH:/opt\n"
    );
}

/// KR-REQ-07.41: the documented bypass for a known auto-wrapper, inside KalaReach shells only.
#[test]
fn a_known_auto_wrapper_gets_its_documented_session_local_bypass() {
    let target = kr_shell_integration::host::startup::StartupTarget {
        kind: ShellKind::Zsh,
        path: std::path::PathBuf::from("/home/someone/.zshrc"),
        reason: "a test",
        shared: false,
    };
    let with = startup::entry(&target, Path::new("/opt/kr/entry"), true);
    assert!(with.contains(startup::NSH_BYPASS_VARIABLE));
    assert!(
        with.contains("KR_SHELL_BRIDGE"),
        "the bypass is set only where the worker exported the bridge, which is a KR shell"
    );
    let without = startup::entry(&target, Path::new("/opt/kr/entry"), false);
    assert!(!without.contains(startup::NSH_BYPASS_VARIABLE));
    // And nothing else of that tool's configuration is touched: the entry names one variable.
    assert_eq!(with.matches("NSH_").count(), 1);
}

// --------------------------------------------------------------------------------------------
// KR-REQ-07.31, KR-REQ-07.43, KR-REQ-01.21: the terminal a presented session opens in.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.31, KR-REQ-07.43.
#[test]
fn the_terminal_is_chosen_in_order_and_a_host_with_none_says_so_once() {
    let available = vec![
        TerminalApplication {
            id: "iterm2".to_owned(),
            name: "iTerm2".to_owned(),
            detail: "/Applications/iTerm.app".to_owned(),
        },
        TerminalApplication {
            id: "apple-terminal".to_owned(),
            name: "Terminal".to_owned(),
            detail: "/System/Applications/Utilities/Terminal.app".to_owned(),
        },
    ];
    assert_eq!(
        terminal::select(Some("apple-terminal"), Some("iterm2"), &available)
            .expect("chosen")
            .source,
        Source::Profile
    );
    assert_eq!(
        terminal::select(None, Some("apple-terminal"), &available)
            .expect("chosen")
            .source,
        Source::Preference
    );
    assert_eq!(
        terminal::select(None, None, &available)
            .expect("chosen")
            .source,
        Source::Detected
    );
    let unavailable = terminal::select(None, None, &[]).expect_err("refused");
    assert_eq!(unavailable, TerminalUnavailable::NoneAvailable);
    assert_eq!(unavailable.code(), ErrorCode::TerminalUnavailable);
    // The presentation failure is separate from the session: it carries its own code, and nothing
    // here creates or names a second session.
    assert_eq!(
        unavailable.to_protocol_error().code,
        ErrorCode::TerminalUnavailable
    );
}

/// One request a presenter was asked to open: the application named, and the command.
type PresentationRequest = (Option<String>, Vec<String>);

/// A presenter that opens nothing and records what it was asked to open.
#[derive(Debug, Clone, Default)]
struct RefusingTerminal {
    asked: Arc<std::sync::Mutex<Vec<PresentationRequest>>>,
}

impl kr_controller::supervision::TerminalPresenter for RefusingTerminal {
    fn present(
        &self,
        requested: Option<&str>,
        command: &[String],
    ) -> std::result::Result<terminal::Selection, TerminalUnavailable> {
        self.asked
            .lock()
            .expect("the record is not poisoned")
            .push((requested.map(str::to_owned), command.to_vec()));
        Err(TerminalUnavailable::NoneAvailable)
    }

    fn describe(&self) -> String {
        "a presenter that opens nothing".to_owned()
    }
}

/// KR-REQ-07.43, KR-REQ-07.31, KR-REQ-01.21: a terminal that cannot be opened is reported against
/// the session that was created, and nothing creates a second one.
/// KR-REQ-07.11: the failed presentation is attempted once and never retries the execution.
/// KR-REQ-07.02: a create presented in a terminal asks for one terminal window running
/// `kr attach` on the new session.
/// KR-REQ-07.50: the terminal is asked to run an argument vector in which the session's identity is
/// an argument of its own, never text assembled into a command line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_terminal_that_cannot_be_opened_leaves_one_live_session_and_a_presentation_error() {
    let worker_build = worker_beside_this_test();
    // This test's daemon starts a real worker through the platform's own supervisor, so the tree
    // ends whatever it started, and removes its job, however the test ends.
    let temp = teardown::Tree::create();
    // On the internal disk, and never the copy in the workspace: a worker a service manager starts
    // is its own privacy identity, and one that opened a path on the external volume would stop
    // for a dialog. Started once here, where nothing is timed, so the operating system's check of
    // a new executable is not paid inside the create's rendezvous.
    let worker = temp.root().join("kr-worker");
    kr_ipc::testing::place_and_start_once(&worker_build, &worker, &["--version"]);
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let presenter = RefusingTerminal::default();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: temp.supervisor(kr_controller::supervision::detect()),
        worker_program: worker,
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(presenter.clone()),
    })
    .await
    .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let serving = tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
        .expect("binds the rendezvous");
    let rendezvous_serving = tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous));
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");

    let mut request = create(environment_id, ShellMode::NativeCompat, Some("/bin/sh"));
    request.presentation = Presentation::Terminal;
    request.cwd = Nullable::some(temp.root().display().to_string());
    let created: kr_protocol::session::SessionCreateResult = client
        .mutate(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target(environment_id),
            &request,
        )
        .await
        .expect("reaches the daemon")
        .expect("the session is created whether or not a window opened")
        .to_typed()
        .expect("decodes");

    let refusal = created
        .presentation_error
        .0
        .expect("a terminal that did not open is reported");
    assert_eq!(refusal.code, ErrorCode::TerminalUnavailable);
    assert_eq!(
        created.session.state,
        kr_protocol::session::SessionState::Live,
        "the session is available: only the window is missing"
    );
    assert!(
        created.endpoint.0.is_some(),
        "and it can be attached to without another call"
    );

    // Exactly one, and the window it would have opened names the session's own identifier and its
    // environment rather than a display number.
    let asked: Vec<PresentationRequest> = presenter
        .asked
        .lock()
        .expect("the record is not poisoned")
        .clone();
    assert_eq!(asked.len(), 1, "a presentation is attempted once");
    let (requested, command) = &asked[0];
    assert_eq!(requested.as_deref(), None);
    assert!(command.contains(&"attach".to_owned()));
    assert!(command.contains(&created.session.session_id.to_string()));
    assert!(command.contains(&environment_id.to_string()));
    assert!(
        !command.contains(&created.session.display_number.to_string()),
        "a window opened on a display number would attach to whichever environment resolved it"
    );

    let listed: kr_protocol::session::SessionListResult = client
        .request(
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::some(environment_id),
                include_closed: false,
            },
        )
        .await
        .expect("reaches the daemon")
        .expect("lists")
        .to_typed()
        .expect("decodes");
    assert_eq!(
        listed.sessions.len(),
        1,
        "a failed presentation never produces a duplicate session"
    );

    let _: kr_protocol::session::SessionCloseResult = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id,
                session_id: Nullable::some(created.session.session_id),
                session_epoch: Nullable::some(created.session.session_epoch),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &kr_protocol::session::SessionCloseParams {
                session_id: created.session.session_id,
            },
        )
        .await
        .expect("reaches the daemon")
        .expect("closes")
        .to_typed()
        .expect("decodes");
    serving.abort();
    rendezvous_serving.abort();
}

/// Returns the worker binary beside this test's own.
///
/// # Panics
///
/// Panics, naming where the worker should be and how to build it, when the build has not produced
/// one. A test that returned early instead would report a pass for a session it never started. A
/// test run of the whole workspace builds the worker, because the worker's own tests launch it.
fn worker_beside_this_test() -> std::path::PathBuf {
    let mut directory = std::env::current_exe().expect("the test binary");
    directory.pop();
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory.pop();
    }
    let worker = directory.join(if cfg!(windows) {
        "kr-worker.exe"
    } else {
        "kr-worker"
    });
    assert!(
        worker.is_file(),
        "this test starts a worker process and there is none at {}; build it with \
         `cargo build -p kr-worker`, or run the whole workspace's tests, which build it",
        worker.display()
    );
    worker
}

// --------------------------------------------------------------------------------------------
// The built packages, when this run has them.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.16, KR-REQ-07.85: the packages a build produced, when it produced any.
#[test]
fn the_built_packages_are_qualified_where_this_run_has_them() {
    // What this run was told to use, and nothing else. An ordinary acceptance run says nothing
    // about a package it was not pointed at, because the machine's own installation is not this
    // suite's to depend on; a run that names one is a run that expects it to be there.
    let Some(root) = std::env::var_os(PACKAGE_ROOT_VARIABLE) else {
        eprintln!(
            "skipped: {PACKAGE_ROOT_VARIABLE} names no directory, so no built package is checked"
        );
        return;
    };
    let set = PackageSet::discover(Path::new(&root)).expect("reads the built packages");
    assert!(
        !set.packages().is_empty(),
        "{PACKAGE_ROOT_VARIABLE} named {root:?} and it holds no package record"
    );
    for package in set.packages() {
        assert!(
            package.executable().is_file(),
            "{} names an executable that is not installed",
            package.directory.display()
        );
        let identity = package.identity();
        assert!(!identity.editor_abi.is_empty());
        assert!(!identity.integration_version.is_empty());
        assert!(
            !identity.patches.is_empty(),
            "a qualified package records the reader patches behind it"
        );
    }
}

// --------------------------------------------------------------------------------------------
// Section 7 paragraph 4: a worker proves nothing for a session whose integration has never
// qualified, and the session is found again when it does.
// --------------------------------------------------------------------------------------------

/// A daemon that restarts mid-qualification finds the session again once the reader comes up.
///
/// The worker's endpoint is open before its integration is live, so a session still being created
/// is reachable. What it will not do is answer a daemon's proof: a worker that has never qualified
/// would otherwise be published as a live session before its reader existed. That refusal leaves
/// the claim unresolved, so the next request that goes looking for the session looks again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_has_not_qualified_proves_nothing_and_is_found_when_it_does() {
    use kr_controller::registry::{LaunchPhase, Registry};
    use kr_protocol::hello::PROTOCOL_VERSION;
    use kr_protocol::ids::{ActorId, SessionEpoch};
    use kr_protocol::scalars::Digest256;
    use kr_protocol::session::SessionState;
    use kr_shell_integration::contract::events::{BridgeEvent, EofGesture, HooksActivated};
    use kr_shell_integration::contract::fence::LeaseView;
    use kr_shell_integration::contract::transport::{HandshakeOutcome, WorkerExpectation};
    use kr_shell_integration::host::endpoint::HostEndpoint;
    use kr_shell_integration::host::scripted::{ReferenceShell, ScriptedBridge, qualified_hello};
    use kr_worker::fence::FenceDriver;
    use kr_worker::runtime::SessionRuntime;
    use kr_worker::service::{ServiceBinding, WorkerService};
    use kr_worker::session::{Session, SessionConfig};

    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");

    // What a create that got as far as the claim leaves behind: a reservation this daemon will find
    // when it starts, naming a worker it has not adopted.
    let actor_id = ActorId::new("local:test").expect("a principal");
    let reservation = {
        let mut registry =
            Registry::open(environment.registry_database(), environment_id).expect("a registry");
        let admission = registry
            .reserve(
                &actor_id,
                kr_ipc::new_uuid(),
                Digest256::from_bytes([0x5c; 32]),
                b"an intent",
                kr_ipc::now_ms(),
            )
            .expect("reserves");
        let reservation_id = admission.reservation.reservation_id;
        registry
            .record_launch(reservation_id, &process)
            .expect("records the launcher");
        registry
            .set_phase(reservation_id, LaunchPhase::Spawned)
            .expect("spawned");
        admission.reservation
    };
    let session_id = reservation.session_id;
    // The endpoint the daemon will look for this worker on is the one its own reservation names.
    let display = reservation.display_number;

    // The worker: a managed session whose bridge has registered and whose hooks are not live yet.
    let identity = Arc::new(
        kr_ipc::verify::WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process.clone(),
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    {
        let mut registry =
            Registry::open(environment.registry_database(), environment_id).expect("a registry");
        registry
            .claim_rendezvous(reservation.reservation_id, *identity.public_key())
            .expect("claims");
    }
    let host_endpoint = HostEndpoint::open_for_session(
        environment.runtime_root(),
        environment.runtime_dir(),
        session_id,
    )
    .expect("binds the bridge");
    let address = host_endpoint.address().clone();
    let secret = host_endpoint.secret().clone();
    let mut session = Session::open(SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: display,
        shell: kr_worker::pty::ShellCommand {
            program: "/bin/cat".to_owned(),
            arguments: Vec::new(),
            cwd: "/".to_owned(),
            environment: Vec::new(),
        },
        shell_mode: ShellMode::Managed,
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    })
    .expect("opens the session");
    session.launch().expect("launches the shell");
    session.install_fence(FenceDriver::new(
        session_id,
        LeaseView::unheld(kr_protocol::ids::InputLeaseEpoch::new(0)),
        Arc::new(kr_transport::clock::SystemContinuousClock::new()),
    ));
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let worker_endpoint = environment.worker_endpoint(display).expect("an endpoint");
    let worker_listener = Listener::bind(&worker_endpoint).expect("binds the worker endpoint");
    let bridge_task = tokio::spawn(
        kr_worker::fence::bridge::BridgeServer::new(
            Arc::clone(&runtime),
            host_endpoint,
            WorkerExpectation {
                session_id,
                root_process: process.clone(),
                supported_editor_abis: vec!["zle-5.9".to_owned()],
                supported_integration_versions: vec!["1".to_owned()],
                launched_package: None,
                already_registered: false,
                gesture: EofGesture::default(),
            },
        )
        .serve(),
    );
    let controller_identity = {
        let secrets = environment.secrets_dir();
        let store = open_store_in(&secrets).expect("a secret store");
        ControllerIdentity::open(store.store.as_ref(), environment_id, false).expect("an identity")
    };
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            worker_endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: *controller_identity.public_key(),
                controller_generation: kr_protocol::ids::ControllerGeneration::new(1),
                build_id: build(),
                journal_path: Some(environment.journal_database(session_id)),
            },
        )
        .expect("a service"),
    );
    let serving = tokio::spawn(Arc::clone(&service).serve(worker_listener));

    let hello = qualified_hello(
        &ReferenceShell::new(ShellKind::Zsh, "/bin/cat", "5.9", "zle-5.9"),
        session_id,
        &address,
        process,
        &secret,
    )
    .expect("a hello");
    let (mut bridge, outcome) = ScriptedBridge::connect(&address, &hello)
        .await
        .expect("connects");
    assert!(
        matches!(outcome, HandshakeOutcome::Accepted(_)),
        "{outcome:?}"
    );

    // The daemon starts on this environment and finds the claim. The worker has registered and has
    // not qualified, so it proves nothing and the claim stays where it was.
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new({
            let secrets = environment.secrets_dir();
            move || {
                let store = open_store_in(&secrets).expect("a secret store");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(NoWorkers),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let controller_client_endpoint = environment.controller_endpoint().expect("an endpoint");
    let clients = Listener::bind(&controller_client_endpoint).expect("binds the client endpoint");
    let controller_serving = tokio::spawn(Arc::clone(&controller).serve_clients(clients));
    let mut client =
        LocalClient::connect(&controller_client_endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
    let unknown = client
        .request(
            Method::SessionRead,
            &kr_protocol::session::SessionReadParams { session_id },
        )
        .await
        .expect("reaches the daemon")
        .expect_err("a session whose worker proves nothing is not published");
    assert_eq!(unknown.code, ErrorCode::UnknownSession, "{unknown}");

    // The user's startup files finish and the reader's hooks come up. The next read looks again.
    bridge
        .send_event(BridgeEvent::HooksActivated(HooksActivated {
            session_id,
            prompt_generation: kr_protocol::root::PromptGeneration::new(1),
        }))
        .await
        .expect("reports");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let found = loop {
        let answer = client
            .request(
                Method::SessionRead,
                &kr_protocol::session::SessionReadParams { session_id },
            )
            .await
            .expect("reaches the daemon");
        if let Ok(value) = answer {
            break value;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the qualified session was never found again"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    };
    let read: kr_protocol::session::SessionReadResult = found.to_typed().expect("decodes");
    assert_eq!(read.session.session_id, session_id);
    assert_eq!(read.session.state, SessionState::Live);

    // A list is the other way somebody finds a session, and it sees the same one.
    let listed: kr_protocol::session::SessionListResult = client
        .request(
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::some(environment_id),
                include_closed: false,
            },
        )
        .await
        .expect("reaches the daemon")
        .expect("lists")
        .to_typed()
        .expect("decodes");
    assert!(
        listed
            .sessions
            .iter()
            .any(|summary| summary.session_id == session_id),
        "the recovered session is in the list too"
    );

    runtime
        .close(kr_protocol::session::ClosureReason::CloseRequested)
        .1
        .release();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(30), runtime.wait_closed()).await;
    bridge_task.abort();
    serving.abort();
    controller_serving.abort();
}
