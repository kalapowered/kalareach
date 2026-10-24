//! The managed PowerShell shell on Windows, against a real daemon and a real worker.
//!
//! A person publishes the PowerShell package for the PowerShell they have, runs `kr shell install`,
//! and then a default `kr new` starts their own `pwsh.exe` as the session's root shell under the
//! package, in a pseudo-console, with the command route live. These cases run that: the package
//! is published into a prefix of the test's own, the entries go into the account's own PowerShell
//! profiles, the daemon runs in this process and starts each worker through the environment's
//! scheduled task, and the test types into the session's terminal and reads what comes back and
//! what the daemon and the plugin runtime report.
//!
//! The profiles are the account's: PowerShell finds them through the Documents known folder, which
//! no variable moves. Each case saves both files before it writes either and puts them back as
//! they were, a file it made included, so it runs only where the switch below says a profile may be
//! written. The cases are ignored in an ordinary run for that reason.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use kr_plugin_catalogue::transport::RepositoryTransport;
use kr_plugin_catalogue::{
    CapabilityCeiling, Catalogue, Change, Enrolment, InstallationGrant, Owner, RepositoryId,
    RepositoryKind,
};
use kr_plugin_sdk::capability::PluginCapability;
use kr_protocol::admission::ComponentState;
use kr_protocol::ids::PluginId;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::host::package::{PACKAGE_ROOT_VARIABLE, ShellPackage};
use kr_shell_integration::host::startup::{HomeLayout, PowerShell};

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
mod windows_session;

/// The catalogue's own builder of signed generations, for a package this suite writes.
#[allow(dead_code)]
#[path = "../../kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

use windows_session::{Created, LIVENESS_DEADLINE, Prepared, WorkerHost, WorkerTerminal};

/// The switch that says a case may write the account's PowerShell profiles.
const PROFILE_SWITCH: &str = "KR_ALLOW_PROFILE_WRITE";

/// Why these cases are ignored in an ordinary run.
macro_rules! writes_profiles {
    () => {
        "writes the account's PowerShell profiles and puts them back; it runs with --ignored and \
         KR_ALLOW_PROFILE_WRITE=1 where the account is disposable or a run records and restores it"
    };
}

/// The module's own directory in this checkout.
fn module_directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("shells")
        .join("psreadline")
        .join("module")
}

/// Publishes the package into `prefix` the way a person does, and returns its directory.
fn publish(prefix: &Path) -> PathBuf {
    let module = module_directory().join("KalaReach.ShellBridge.psd1");
    let published = Command::new("pwsh.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            "Import-Module '{}'; Publish-KalaReachQualification -Prefix '{}' | Out-Null",
            module.display(),
            prefix.display()
        ))
        .output()
        .expect("PowerShell 7 is the shell this package is published for, and it did not start");
    assert!(
        published.status.success(),
        "the package was not published:\n{}\n{}",
        String::from_utf8_lossy(&published.stdout),
        String::from_utf8_lossy(&published.stderr)
    );
    let identity = std::fs::read_to_string(prefix.join("powershell").join("current"))
        .expect("the published package is the current one");
    prefix.join("powershell").join(identity.trim())
}

/// The first 16 hexadecimal digits of a file's SHA-256, or what stands in for a file that is not
/// there.
fn fingerprint(path: &Path) -> String {
    use sha2::{Digest as _, Sha256};

    match std::fs::read(path) {
        Ok(bytes) => Sha256::digest(bytes)
            .iter()
            .take(8)
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        Err(_) => "absent".to_owned(),
    }
}

/// One case at a time writes the account's profiles: they are the account's, and a second case that
/// saved them while the first had written would put the first's entries back.
static PROFILE_WRITER: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The two profile files PowerShell reads for this account, as they were before a case wrote to
/// them, and the directories above them that did not exist; put back when this is dropped.
///
/// What was in a file is also kept in a file of its own, so a run that is stopped halfway leaves the
/// bytes to put back as well as the entries to take out.
struct Profiles {
    files: Vec<(PathBuf, Option<Vec<u8>>)>,
    made: Vec<PathBuf>,
    _copies: tempfile::TempDir,
    _writer: std::sync::MutexGuard<'static, ()>,
}

impl Profiles {
    /// Records the files the package's own PowerShell names for the account.
    ///
    /// # Panics
    ///
    /// Panics when a file that is there cannot be read, since it could not be put back.
    fn saved(package: &ShellPackage) -> Self {
        assert!(
            std::env::var(PROFILE_SWITCH).is_ok_and(|value| value == "1"),
            "this case writes the account's PowerShell profiles; set {PROFILE_SWITCH}=1 where that \
             is allowed"
        );
        let writer = PROFILE_WRITER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let layout = HomeLayout::from_environment().launching(PowerShell::of_package(package));
        let mut paths: Vec<PathBuf> = layout
            .targets(ShellKind::PowerShell)
            .into_iter()
            .map(|target| target.path)
            .collect();
        paths.sort();
        paths.dedup();
        assert!(
            !paths.is_empty(),
            "PowerShell named no profile for the account"
        );
        let mut made = Vec::new();
        for path in &paths {
            let mut parent = path.parent();
            while let Some(directory) = parent {
                if directory.exists() || made.iter().any(|seen: &PathBuf| seen == directory) {
                    break;
                }
                made.push(directory.to_path_buf());
                parent = directory.parent();
            }
        }
        let copies = tempfile::Builder::new()
            .prefix("kr-profile-copies-")
            .tempdir()
            .expect("a directory on the internal disk");
        let files = paths
            .into_iter()
            .enumerate()
            .map(|(number, path)| {
                eprintln!(
                    "profile before: {} sha256={}",
                    path.display(),
                    fingerprint(&path)
                );
                let before = match std::fs::read(&path) {
                    Ok(bytes) => {
                        std::fs::write(copies.path().join(format!("profile-{number}")), &bytes)
                            .expect("a copy of the profile");
                        Some(bytes)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => {
                        panic!("{} cannot be read to be put back: {error}", path.display())
                    }
                };
                (path, before)
            })
            .collect();
        Self {
            files,
            made,
            _copies: copies,
            _writer: writer,
        }
    }
}

impl Drop for Profiles {
    fn drop(&mut self) {
        for (path, before) in &self.files {
            let restored = match before {
                Some(bytes) => std::fs::write(path, bytes),
                None => match std::fs::remove_file(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    other => other,
                },
            };
            if let Err(error) = restored {
                eprintln!("PROFILE NOT RESTORED: {}: {error}", path.display());
            }
            eprintln!(
                "profile after: {} sha256={}",
                path.display(),
                fingerprint(path)
            );
        }
        // The directories this case made, innermost first, and only while they are empty.
        for directory in &self.made {
            let _ = std::fs::remove_dir(directory);
        }
    }
}

/// A host whose PowerShell package is published and whose daemon reads it, and the account's
/// profiles as they were.
struct Managed {
    /// Before the packages, so the daemon and its workers are gone before the files they read.
    host: WorkerHost,
    packages: tempfile::TempDir,
    /// Last, so the profiles come back after the shell that read them has ended.
    _profiles: Profiles,
}

impl Managed {
    /// Publishes the package, saves the profiles, and starts the daemon on `prepared`.
    async fn start(prepared: Prepared) -> Self {
        let packages = tempfile::tempdir().expect("a directory on the internal disk");
        let directory = publish(packages.path());
        let package = ShellPackage::read(&directory).expect("the host reads the published package");
        let profiles = Profiles::saved(&package);
        let host = prepared.start(Some(packages.path().to_path_buf())).await;
        Self {
            host,
            packages,
            _profiles: profiles,
        }
    }

    /// Runs `kr` with the published packages named, as a person who published them has them found.
    async fn kr(&self, arguments: &[&str]) -> std::process::Output {
        let packages = self.packages.path().display().to_string();
        self.host
            .kr(arguments, &[(PACKAGE_ROOT_VARIABLE, packages.as_str())])
            .await
    }

    /// `kr shell install` for PowerShell.
    async fn install_entries(&self) {
        let installed = self
            .kr(&["--json", "shell", "install", "--shell", "powershell"])
            .await;
        assert!(
            installed.status.success(),
            "kr shell install: {}{}",
            String::from_utf8_lossy(&installed.stdout),
            String::from_utf8_lossy(&installed.stderr)
        );
    }

    /// Attaches a terminal to the session `created` made.
    async fn terminal(&self, created: &Created) -> WorkerTerminal {
        let (session_id, dimensions) = created.session();
        WorkerTerminal::attach(&self.host.tree.environment(), session_id, dimensions).await
    }
}

/// Waits until the managed shell has drawn its prompt and answers.
async fn answering(terminal: &mut WorkerTerminal) {
    terminal.type_line("Write-Output ('kr-' + 'answers')").await;
    terminal
        .shown("kr-answers", "the managed shell answers")
        .await;
}

/// The lines of `whoami`'s own account and group reports that tell one principal from another: the
/// account's identifier, the integrity level, and the Administrators group with the state it is in.
fn standing() -> Vec<String> {
    let whoami = PathBuf::from(std::env::var_os("SystemRoot").expect("the system directory"))
        .join("System32")
        .join("whoami.exe");
    let mut lines = Vec::new();
    for switch in ["/user", "/groups"] {
        let output = Command::new(&whoami)
            .args([switch, "/fo", "csv", "/nh"])
            .output()
            .expect("whoami runs");
        assert!(output.status.success(), "whoami {switch} failed");
        lines.extend(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| {
                    switch == "/user"
                        || line.contains("Mandatory Label")
                        || line.contains("S-1-5-32-544")
                })
                .map(str::to_owned),
        );
    }
    lines
}

/// KR-REQ-06.12: the managed root shell runs as the account and at the integrity level of the host
/// that started it, with the Administrators group in the state this process has it in. The shell
/// is asked what `whoami` says of it, and this process is asked the same.
async fn the_shell_runs_as_this_process(terminal: &mut WorkerTerminal) {
    let expected = standing();
    assert!(
        expected.len() >= 2,
        "whoami told this process nothing to compare: {expected:?}"
    );
    terminal
        .type_line(
            "& \"$env:SystemRoot\\System32\\whoami.exe\" /user /fo csv /nh; \
             & \"$env:SystemRoot\\System32\\whoami.exe\" /groups /fo csv /nh; \
             Write-Output ('kr-' + 'whoami-done')",
        )
        .await;
    terminal
        .shown("kr-whoami-done", "the managed shell says who it is")
        .await;
    let shown = terminal.text();
    for line in expected {
        let flat: String = line.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        assert!(
            shown.contains(&flat),
            "the managed shell does not read as this process does ({flat}); it showed: {shown}"
        );
    }
}

/// What the terminal shows after the last copy of `marker`.
fn after(terminal: &WorkerTerminal, marker: &str) -> String {
    let text = terminal.text();
    text.rfind(marker)
        .map(|at| text[at + marker.len()..].to_owned())
        .unwrap_or_default()
}

/// A copy of the Windows command shell named for a program a package recognises.
///
/// What it is given after `/c` is the command it runs, so a typed line decides what the stand-in
/// prints and where it stays: it expands the variables its launcher set, and it prints the flags
/// the integration added after the words that were typed.
fn stand_in(directory: &Path, name: &str) -> PathBuf {
    let cmd = PathBuf::from(std::env::var_os("SystemRoot").expect("the system directory"))
        .join("System32")
        .join("cmd.exe");
    let program = directory.join(format!("{name}.exe"));
    kr_ipc::testing::place_program(&cmd, &program);
    program
}

/// A directory for stand-in programs, on the internal disk.
fn stand_ins() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kr-stand-ins-")
        .tempdir()
        .expect("a directory on the internal disk")
}

/// Puts `directory` first on the search path of the shell the terminal is attached to, and waits
/// until the shell says it has.
async fn first_on_the_path(terminal: &mut WorkerTerminal, directory: &Path) {
    terminal
        .type_line(&format!(
            "$env:PATH = '{}' + ';' + $env:PATH; Write-Output ('kr-' + 'path-set')",
            directory.display()
        ))
        .await;
    terminal
        .shown("kr-path-set", "the search path is set")
        .await;
}

/// The words of the doctor's report of a package's command integration: its state and the mode an
/// invocation of its command runs in.
async fn integration_report(host: &WorkerHost, plugin: &str) -> String {
    let doctor = host.kr(&["--json", "doctor"], &[]).await;
    let document: serde_json::Value =
        serde_json::from_slice(&doctor.stdout).unwrap_or(serde_json::Value::Null);
    let mut found = String::new();
    collect_integration(&document, plugin, &mut found);
    found
}

/// Gathers every object of the doctor's document that names `plugin`, whole.
fn collect_integration(value: &serde_json::Value, plugin: &str, into: &mut String) {
    match value {
        serde_json::Value::Object(map) => {
            if map
                .values()
                .any(|member| member.as_str().is_some_and(|text| text == plugin))
            {
                into.push_str(&value.to_string());
                into.push('\n');
            }
            for member in map.values() {
                collect_integration(member, plugin, into);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_integration(item, plugin, into);
            }
        }
        _ => {}
    }
}

/// KR-REQ-06.12, KR-REQ-07.16: with the package published and the entry not installed, a default
/// `kr new` is refused at once by the worker, with the command that installs the entry; with the
/// entry installed it starts the person's own `pwsh.exe` as the managed root shell, and the shell
/// answers at its prompt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = writes_profiles!()]
async fn a_default_session_is_refused_without_the_entry_and_managed_with_it() {
    let managed = Managed::start(Prepared::new()).await;

    let refused = managed.host.kr_new(&[]).await;
    assert!(
        !refused.succeeded(),
        "a create went ahead with no entry in the profile: {}",
        refused.said()
    );
    assert!(
        refused.said().contains("kr shell install"),
        "the refusal does not name the command that installs the entry: {}",
        refused.said()
    );

    managed.install_entries().await;
    let created = managed.host.kr_new(&[]).await;
    let (session_id, _) = created.session();
    assert_eq!(
        created.document["shell_mode"], "managed",
        "{}",
        created.document
    );
    assert!(
        created.document["shell"]
            .as_str()
            .is_some_and(|shell| shell.to_lowercase().ends_with("pwsh.exe")),
        "the root shell is not the person's own pwsh.exe: {}",
        created.document
    );
    let mut terminal = managed.terminal(&created).await;
    answering(&mut terminal).await;
    the_shell_runs_as_this_process(&mut terminal).await;

    drop(terminal);
    let closed = managed
        .host
        .kr(&["--json", "close", &session_id.to_string()], &[])
        .await;
    assert!(closed.status.success());
}

/// The directory the bundle ships a package in.
fn bundled_package(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../bundled-plugins/targets/packages/kalareach")
        .join(name)
        .join("0.5.0")
}

/// Publishes the package in `directory` in a signed generation of its own, enrols that repository,
/// and installs and enables the package as the owner who confirmed what it may do, before any
/// daemon opens the catalogue. Returns the directory the generation is published in, which has to
/// stay while the daemon runs.
///
/// Every capability the manifest asks for is granted, as the install requires. A native bridge's is
/// among them, and on Windows the host applies no bridge, so nothing is written into the person's
/// own agent directory.
async fn install_package(
    prepared: &Prepared,
    directory: &Path,
    repository: &str,
) -> tempfile::TempDir {
    let environment = prepared.tree.environment();
    let environment_id = environment.environment_id();
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("plugin.json")).expect("a manifest"))
            .expect("a manifest");
    let plugin = PluginId::new(format!(
        "{}/{}",
        manifest["publisher_id"].as_str().expect("a publisher"),
        manifest["plugin_name"].as_str().expect("a name")
    ))
    .expect("a plugin identifier");
    let version = kr_plugin_sdk::version::PackageVersion::parse(
        manifest["version"].as_str().expect("a version"),
    )
    .expect("a version");
    let grants: Vec<PluginCapability> = manifest["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .map(|entry| {
            serde_json::from_value(entry["capability"].clone()).expect("a known capability")
        })
        .collect();

    let generation_home = tempfile::tempdir().expect("a directory on the internal disk");
    let generation = generations::Generation::build(
        generation_home.path(),
        generations::GenerationSpec {
            package: Some(directory.to_path_buf()),
            ..generations::GenerationSpec::default()
        },
    )
    .await;
    let mut catalogue = Catalogue::open(
        &environment.state_dir().join("catalogue"),
        std::sync::Arc::new(RepositoryTransport::local_only(
            "this test reads its repository from disk",
        )),
    )
    .expect("an openable catalogue");
    let id = RepositoryId::new(repository).expect("an identifier");
    catalogue
        .enrol(
            Enrolment::new(
                id.clone(),
                RepositoryKind::Local,
                generations::directory_url(&generation.metadata_dir()),
                generations::directory_url(&generation.targets_dir()),
                generation.root_bytes(),
                kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
                CapabilityCeiling::default_ceiling(),
            )
            .expect("an enrollable repository"),
            true,
        )
        .expect("the owner adopted the root");
    catalogue.sync(&id).await.expect("a generation");
    let digest = catalogue
        .index(&id)
        .expect("activated")
        .find(&plugin, &version)
        .expect("the package")
        .manifest_digest;
    catalogue
        .install_with(
            &id,
            environment_id,
            &plugin,
            &version,
            digest,
            InstallationGrant::with(grants),
            None,
            &mut Change::new(&Owner::confirming()),
        )
        .await
        .expect("installed");
    catalogue
        .set_enabled(environment_id, &plugin, true)
        .await
        .expect("enabled");
    generation_home
}

/// KR-REQ-12.07, KR-REQ-07.45: the bundled Claude Code and Qoder CLI packages (the release's own
/// files, published in a generation of the test's own), with their integrations turned on, launch
/// the program a person types in the managed shell through the forwarder, which adds the flags
/// each package declares and gives the program the variables of its registration. The controls are
/// the same program started by its path, which is not integrated and runs as typed, and a shim
/// found first, which is never launched through the forwarder.
///
/// The programs are copies of the command shell, which prints what it is given after `/c` once it
/// has expanded the variables in it, so the launch is read from what the program printed. Each
/// marker the case waits for is one the typed line cannot spell, since the terminal echoes the line.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = writes_profiles!()]
async fn the_bundled_agents_typed_at_the_managed_prompt_are_launched_through_the_forwarder() {
    // Gemini CLI's hooks are for a POSIX shell, so the release does not publish its package for
    // Windows.
    let gemini: serde_json::Value = serde_json::from_slice(
        &std::fs::read(bundled_package("gemini-cli").join("plugin.json")).expect("a manifest"),
    )
    .expect("a manifest");
    assert!(
        !gemini["platforms"]
            .as_array()
            .expect("platforms")
            .iter()
            .any(|platform| platform["os"] == "windows"),
        "Gemini CLI's package is published for Windows"
    );

    // The package's flags name the forwarder by placeholder, which the daemon and the worker have
    // to write as one path.
    let prepared = Prepared::beside_the_test();
    let _claude_published =
        install_package(&prepared, &bundled_package("claude-code"), "claude").await;
    let _qoder_published = install_package(&prepared, &bundled_package("qoder-cli"), "qoder").await;
    let managed = Managed::start(prepared).await;
    managed.install_entries().await;
    for plugin in ["kalareach/claude-code", "kalareach/qoder-cli"] {
        let enabled = managed
            .host
            .kr(&["--json", "plugin", "integration", "enable", plugin], &[])
            .await;
        assert!(
            enabled.status.success(),
            "{}{}",
            String::from_utf8_lossy(&enabled.stdout),
            String::from_utf8_lossy(&enabled.stderr)
        );
        let report = integration_report(&managed.host, plugin).await;
        eprintln!("the doctor on {plugin}: {report}");
        assert!(
            report.contains("\"state\":\"on\""),
            "the doctor does not read {plugin}'s integration as on: {report}"
        );
    }

    let programs = stand_ins();
    let claude = stand_in(programs.path(), "claude");
    let _qoder = stand_in(programs.path(), "qodercli");
    let created = managed.host.kr_new(&[]).await;
    let mut terminal = managed.terminal(&created).await;
    answering(&mut terminal).await;
    first_on_the_path(&mut terminal, programs.path()).await;

    // `^n` is `n` to the command shell, so the line the terminal echoes does not hold the marker
    // the program prints.
    terminal
        .type_line("claude /c echo claude-reg^=%KR_REGISTRATION% claude-e^nd")
        .await;
    terminal
        .shown("claude-end", "the program started by its name prints")
        .await;
    let printed = after(&terminal, "claude-reg=");
    eprintln!("claude printed: {printed}");
    assert!(
        printed
            .split_whitespace()
            .next()
            .is_some_and(|registration| !registration.is_empty() && !registration.starts_with('%')),
        "the program was given no registration: {printed}"
    );
    assert!(
        printed.contains("--dangerously-load-development-channels")
            && printed.contains("plugin:kalareach-channels@skills-dir"),
        "the launch did not add the flags the package declares: {printed}"
    );

    terminal
        .type_line("qodercli /c echo qoder-reg^=%KR_REGISTRATION% qoder-e^nd")
        .await;
    terminal
        .shown("qoder-end", "the program started by its name prints")
        .await;
    let printed = after(&terminal, "qoder-reg=");
    eprintln!("qodercli printed: {printed}");
    assert!(
        printed
            .split_whitespace()
            .next()
            .is_some_and(|registration| !registration.is_empty() && !registration.starts_with('%')),
        "the program was given no registration: {printed}"
    );
    assert!(
        printed.contains("--settings"),
        "the launch did not add the settings the package declares: {printed}"
    );

    // The control: the same program started by its path is not asked about and runs as typed.
    terminal
        .type_line(&format!(
            "& '{}' /c echo path-reg^=%KR_REGISTRATION% path-e^nd",
            claude.display()
        ))
        .await;
    terminal
        .shown("path-end", "the program started by its path prints")
        .await;
    let printed = after(&terminal, "path-reg=");
    assert!(
        printed.starts_with('%'),
        "a program started by its path was given a registration: {printed}"
    );
    assert!(
        !printed.contains("--dangerously-load-development-channels"),
        "a program started by its path was given the integration's flags: {printed}"
    );

    // Where the shell finds a shim first, nothing is established and the shim runs as typed: a
    // batch file is run by the command shell, whose identity is not the agent's.
    let shims = stand_ins();
    std::fs::write(
        shims.path().join("claude.cmd"),
        "@if defined KR_REGISTRATION (echo shim-registered) else (echo shim-plain)\r\n",
    )
    .expect("a shim");
    terminal
        .type_line(&format!(
            "$kr_path = $env:PATH; $env:PATH = '{}' + ';' + $env:PATH; Write-Output ('shim-' + 'set')",
            shims.path().display()
        ))
        .await;
    terminal
        .shown("shim-set", "the shim is first on the path")
        .await;
    terminal.type_line("claude").await;
    terminal.shown("shim-plain", "the shim ran").await;
    terminal
        .type_line("$env:PATH = $kr_path; Write-Output ('shim-' + 'done')")
        .await;
    terminal
        .shown("shim-done", "the search path came back")
        .await;
    let shown = terminal.text();
    assert!(
        shown.contains("shim-plain") && !shown.contains("shim-registered"),
        "a shim found first was launched through the forwarder: {shown}"
    );

    // The status the program ends with is the line's.
    terminal.type_line("claude /c exit 7").await;
    terminal
        .type_line("Write-Output (\"kr-st=\" + $LASTEXITCODE + \"-end\")")
        .await;
    terminal
        .shown("kr-st=7-end", "the launcher passes the program's status on")
        .await;
}

/// Claude Code's integration and connector as the test fixtures shape them, with the built test
/// component in it and Windows among the platforms it is published for, written under `into`.
fn component_package(into: &Path, component: &[u8]) -> PathBuf {
    let shape = kr_worker::broker::connectors::fixture::Shape {
        native_bridge: false,
        component: true,
        ..kr_worker::broker::connectors::fixture::Shape::claude_code()
    };
    let source =
        kr_worker::broker::connectors::fixture::package(into, &into.join("kr-hook.exe"), &shape)
            .expect("the package is written");
    // The fixture's component stands for the bytes, and its platforms are the Unix ones.
    let directory = source.package_dir;
    std::fs::write(directory.join("component.wasm"), component).expect("the component");
    let manifest_path = directory.join("plugin.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("the manifest"))
            .expect("a manifest");
    for payload in manifest["payloads"].as_array_mut().expect("payloads") {
        if payload["role"] == "component" {
            payload["digest"] =
                serde_json::json!(kr_plugin_sdk::digest::PayloadDigest::of(component).to_string());
            payload["size_bytes"] = serde_json::json!(component.len().to_string());
        }
    }
    manifest["platforms"]
        .as_array_mut()
        .expect("platforms")
        .push(serde_json::json!({ "os": "windows", "architectures": ["x86_64"] }));
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("a manifest"),
    )
    .expect("the manifest");
    directory
}

/// Loads the built test component, or says how to build it.
fn well_behaved() -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/plugins/components/build/well-behaved.wasm");
    std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "the test component is not built ({}: {error}); build it with \
             scripts/build-plugin-fixtures.sh where the wasm32-wasip2 target is installed and copy \
             it here",
            path.display()
        )
    })
}

/// KR-REQ-07.69: a program a package with a component recognises, typed at the
/// managed prompt of a session on Windows, binds the package, and the daemon starts the plugin
/// host through the environment's scheduled task and registers the package's component in it.
///
/// Nothing starts the host but the daemon, and nothing asks it to but a worker whose binding wants
/// a component. The program stays alive, so the binding outlives the line that started it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = writes_profiles!()]
async fn a_program_whose_package_ships_a_component_starts_the_plugin_host_on_windows() {
    let component = well_behaved();
    let prepared = Prepared::new();
    let package = tempfile::tempdir().expect("a directory on the internal disk");
    let directory = component_package(package.path(), &component);
    let _published = install_package(&prepared, &directory, "development").await;
    let managed = Managed::start(prepared).await;
    managed.install_entries().await;
    let enabled = managed
        .host
        .kr(
            &[
                "--json",
                "plugin",
                "integration",
                "enable",
                "kalareach/claude-code",
            ],
            &[],
        )
        .await;
    assert!(
        enabled.status.success(),
        "{}{}",
        String::from_utf8_lossy(&enabled.stdout),
        String::from_utf8_lossy(&enabled.stderr)
    );

    let environment = managed.host.tree.environment();
    let published = || {
        kr_plugin_service::launcher::read_descriptor(
            &environment,
            &kr_plugin_service::protocol::HostProtocol::THIS,
        )
        .ok()
        .flatten()
    };
    assert!(
        published().is_none(),
        "a plugin host was published before any program was typed"
    );
    // The plugin host is the environment's own job, which no test teardown ends: it goes when this
    // case does, whatever way the case goes.
    let _host_ends = HostEnding(&published);

    let programs = stand_ins();
    let _claude = stand_in(programs.path(), "claude");
    let created = managed.host.kr_new(&[]).await;
    let mut terminal = managed.terminal(&created).await;
    answering(&mut terminal).await;
    first_on_the_path(&mut terminal, programs.path()).await;

    // The program prints the registration its launcher gave it, which the typed line cannot spell,
    // and waits for a line to be typed to it, then the line ends; `rem` takes the flags the
    // integration adds after what was typed, so they reach the command shell as a comment. The
    // binding lasts as long as the program does, which is until this case says so.
    terminal
        .type_line("claude /c 'echo reg=%KR_REGISTRATION% & set /p kr_release=waiting & rem'")
        .await;
    // The daemon is asked about the binding only once the launch is committed: a round of the
    // daemon's that reaches the worker between the answer the program was launched under and its
    // binding moves the admissions the answer was decided at, and the launch runs as typed.
    terminal
        .shown("registration.", "the program started with its registration")
        .await;

    let controller = managed.host.controller();
    let started = tokio::time::Instant::now();
    let registered = loop {
        controller.refresh_admissions().await;
        let reports: Vec<_> = controller
            .reported_components()
            .into_iter()
            .map(|(_, _, report)| report.state)
            .collect();
        if reports.len() == 1 && reports[0] == ComponentState::Registered {
            break reports;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the component was not registered; the workers report {reports:?}; the terminal \
             shows: {}",
            terminal.text()
        );
        terminal.watch(Duration::from_millis(250)).await;
    };
    assert_eq!(registered, [ComponentState::Registered]);

    let host = published().expect("the plugin host is published");
    eprintln!("plugin host published: {host:?}");
    let client = kr_plugin_service::client::PluginClient::connect(&environment)
        .await
        .expect("the plugin host answers");
    let health = client.health().await.expect("the host reports its health");
    assert_eq!(health.live_bindings, 1, "{health:?}");

    // The program ends when it is given its line, and the shell comes back.
    terminal.type_line("").await;
    answering(&mut terminal).await;
}

/// Ends the plugin host that was published when this is dropped, by the identity it was started
/// under.
struct HostEnding<'a, F: Fn() -> Option<kr_plugin_service::protocol::HostDescriptor>>(&'a F);

impl<F: Fn() -> Option<kr_plugin_service::protocol::HostDescriptor>> Drop for HostEnding<'_, F> {
    fn drop(&mut self) {
        use kr_ipc::identity::{ProcessState, Stop, stop_process};

        let Some(host) = (self.0)() else {
            return;
        };
        let process = host.process_start_identity;
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let _ = stop_process(&process, Stop::Kill);
            if kr_ipc::identity::process_state(&process) == ProcessState::Ended
                || std::time::Instant::now() >= deadline
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!(
            "plugin host {} is {:?}",
            process.pid.get(),
            kr_ipc::identity::process_state(&process)
        );
    }
}
