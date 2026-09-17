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
use kr_crypto::store::open_store;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{EnvironmentVariable, Presentation, SessionCreateParams, ShellMode};
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::host::package::{MANIFEST_BASENAME, PackageManifest, PackageSet};
use kr_shell_integration::host::startup::{self, Change, HomeLayout};
use kr_shell_integration::host::terminal::{
    self, Source, TerminalApplication, TerminalUnavailable,
};
use kr_worker::environment::{ExecutionContext, build as build_environment};

/// A supervisor that starts nothing. Every test here is about what happens before a worker runs.
#[derive(Debug)]
struct NoWorkers;

impl WorkerSupervisor for NoWorkers {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> String {
        "a supervisor that starts nothing".to_owned()
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
            let store = open_store(CONTROLLER_SECRET_SERVICE, &secrets).expect("a secret store");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(NoWorkers),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages,
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

/// Installs a package manifest whose executable is a copy of a real program on the internal disk.
fn install_package(root: &Path, kind: ShellKind, flags: &[&str]) {
    let directory = root.join(kind.as_str()).join("identity-1");
    std::fs::create_dir_all(directory.join("bin")).expect("creates the package");
    std::fs::copy("/bin/cat", directory.join("bin/shell")).expect("copies a program");
    std::fs::create_dir_all(directory.join("share")).expect("creates the entry directory");
    std::fs::write(
        directory.join("share/entry"),
        b"# the package's own entry\n",
    )
    .expect("writes the entry");
    let manifest = PackageManifest {
        shell: kind,
        executable: "bin/shell".to_owned(),
        upstream_version: "5.9".to_owned(),
        editor_abi: "zle-5.9".to_owned(),
        integration_version: "1".to_owned(),
        interactive_flags: flags.iter().map(|flag| (*flag).to_owned()).collect(),
        patches: Vec::new(),
        modules: Vec::new(),
        startup_entry: "share/entry".to_owned(),
    };
    std::fs::write(
        directory.join(MANIFEST_BASENAME),
        serde_json::to_string(&manifest).expect("encodes"),
    )
    .expect("writes the manifest");
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
    install_package(packages.path(), ShellKind::Zsh, &["-l", "-i"]);
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
fn a_managed_session_launches_the_package_binary_with_the_flags_it_declares() {
    let packages = tempfile::tempdir().expect("a directory");
    install_package(packages.path(), ShellKind::Zsh, &["-l", "-i"]);
    let set = PackageSet::discover(packages.path()).expect("reads the package");
    let package = set.select(Some("zsh")).expect("qualified");
    assert_eq!(
        package.executable(),
        packages.path().join("zsh/identity-1/bin/shell"),
        "the exact binary the reader patch was built into"
    );
    assert_eq!(package.interactive_flags(), vec!["-l", "-i"]);
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
    install_package(packages.path(), ShellKind::Zsh, &["-l", "-i"]);
    install_package(packages.path(), ShellKind::Bash, &["-l", "-i"]);
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
    };

    for package in set.packages() {
        let body = startup::entry(
            package.manifest.shell,
            &package.startup_entry(),
            package.manifest.shell == ShellKind::Zsh,
        );
        for target in layout.targets(package.manifest.shell) {
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
        for target in layout.targets(package.manifest.shell) {
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
    let with = startup::entry(ShellKind::Zsh, Path::new("/opt/kr/entry"), true);
    assert!(with.contains(startup::NSH_BYPASS_VARIABLE));
    assert!(
        with.contains("KR_SHELL_BRIDGE"),
        "the bypass is set only where the worker exported the bridge, which is a KR shell"
    );
    let without = startup::entry(ShellKind::Zsh, Path::new("/opt/kr/entry"), false);
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

// --------------------------------------------------------------------------------------------
// The built packages, when this run has them.
// --------------------------------------------------------------------------------------------

/// KR-REQ-07.16, KR-REQ-07.85: the packages a build produced, when it produced any.
#[test]
fn the_built_packages_are_qualified_where_this_run_has_them() {
    let Some(root) = std::env::var_os("KR_SHELL_PACKAGES_BUILT") else {
        // The packages are built by their own tooling and are not a prerequisite for this suite.
        // Nothing is asserted about a package this run does not have.
        eprintln!(
            "skipped: KR_SHELL_PACKAGES_BUILT names no directory, so no built package is checked"
        );
        return;
    };
    let set = PackageSet::discover(Path::new(&root)).expect("reads the built packages");
    assert!(
        !set.packages().is_empty(),
        "KR_SHELL_PACKAGES_BUILT named {root:?} and it holds no package manifest"
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
