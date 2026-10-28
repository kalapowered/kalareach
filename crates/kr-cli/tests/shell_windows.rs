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

/// The switch that says a case may sign the account that runs it out, which is for an account that
/// is disposable.
const SIGN_OUT_SWITCH: &str = "KR_ALLOW_SIGN_OUT";

/// Why these cases are ignored in an ordinary run.
macro_rules! writes_profiles {
    () => {
        "writes the account's PowerShell profiles and puts them back; it runs with --ignored and \
         KR_ALLOW_PROFILE_WRITE=1 where the account is disposable or a run records and restores it"
    };
}

/// Why the case that signs the account out is ignored in an ordinary run.
macro_rules! signs_out {
    () => {
        "signs the account that runs it out, and writes the account's PowerShell profiles and puts \
         them back; it runs with --ignored, KR_ALLOW_PROFILE_WRITE=1 and KR_ALLOW_SIGN_OUT=1 where \
         the account is disposable and a run signs it in again for the case that follows"
    };
}

/// Why the case that follows the sign-out is ignored in an ordinary run.
macro_rules! follows_a_sign_out {
    () => {
        "reads what the case that signs the account out left, in the account's next sign-in; it runs \
         with --ignored after that case, as a run that signs the account in again arranges"
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

/// Held by the case that is running.
static CASE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A case's turn: one case at a time runs in this process, from before it places anything until it
/// has put everything back.
///
/// The profiles are the account's, and a second case that saved them while the first had written
/// would put the first's entries back. The programs a case places beside this test's executable are
/// the ones the daemon this process hosts finds, so a second case that started its daemon while they
/// were there would run the first case's forwarder.
struct Turn {
    _held: std::sync::MutexGuard<'static, ()>,
}

impl Turn {
    /// Waits for the case that has the turn.
    fn take() -> Self {
        Self {
            _held: CASE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        }
    }
}

/// The turn, and then the tree a case starts its daemon on with the programs its worker needs placed
/// in it, so that nothing is placed before the case has its turn.
fn take_a_turn() -> (Turn, Prepared) {
    let turn = Turn::take();
    (turn, Prepared::new())
}

/// As [`take_a_turn`], with the worker and the forwarder beside this test's executable instead of
/// in the tree.
fn take_a_turn_beside_the_test() -> (Turn, Prepared) {
    let turn = Turn::take();
    (turn, Prepared::beside_the_test())
}

/// The two profile files PowerShell reads for this account, as they were before a case wrote to
/// them, and the directories above them that did not exist; put back when this is dropped.
///
/// What was in a file is also kept in a file of its own, so a run that is stopped halfway leaves the
/// bytes to put back as well as the entries to take out. A profile that is not back as it was when
/// this is dropped keeps those copies where they are, names them, and fails the case.
struct Profiles {
    files: Vec<(PathBuf, Option<Vec<u8>>)>,
    made: Vec<PathBuf>,
    copies: Option<tempfile::TempDir>,
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
                    "profile before: {} sha256={} copy={}",
                    path.display(),
                    fingerprint(&path),
                    copies.path().join(format!("profile-{number}")).display()
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
            copies: Some(copies),
        }
    }
}

impl Drop for Profiles {
    fn drop(&mut self) {
        let mut unrestored = Vec::new();
        for (path, before) in &self.files {
            let restored = match before {
                Some(bytes) => std::fs::write(path, bytes),
                None => match std::fs::remove_file(path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    other => other,
                },
            };
            if let Err(error) = &restored {
                eprintln!("PROFILE NOT RESTORED: {}: {error}", path.display());
            }
            // What is there now, read back, is what decides whether the profile came back.
            let now = std::fs::read(path).ok();
            if restored.is_err() || now != *before {
                unrestored.push(path.display().to_string());
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
        if unrestored.is_empty() {
            return;
        }
        // The copies are the only place the original bytes are, so they stay.
        let kept = self.copies.take().map(tempfile::TempDir::keep);
        eprintln!(
            "PROFILES NOT RESTORED: {}; the copies of what they held are in {kept:?}",
            unrestored.join(", ")
        );
        // A case that is already failing is not made to panic twice.
        assert!(
            std::thread::panicking(),
            "the profiles {} are not as they were; the copies are in {kept:?}",
            unrestored.join(", ")
        );
    }
}

/// A host whose PowerShell package is published and whose daemon reads it, and the account's
/// profiles as they were.
struct Managed {
    /// Before the packages, so the daemon and its workers are gone before the files they read.
    host: WorkerHost,
    packages: tempfile::TempDir,
    /// After the daemon, so the profiles come back after the shell that read them has ended.
    _profiles: Profiles,
    /// Last, so the turn is given up once the profiles are back and the programs placed beside the
    /// test have gone.
    _turn: Turn,
}

impl Managed {
    /// Publishes the package, saves the profiles, and starts the daemon on `prepared`, which `turn`
    /// made. Arguments are given up last to first, so a setup that panics gives up the programs
    /// `prepared` placed before the turn.
    async fn start(turn: Turn, prepared: Prepared) -> Self {
        let packages = tempfile::tempdir().expect("a directory on the internal disk");
        let directory = publish(packages.path());
        let package = ShellPackage::read(&directory).expect("the host reads the published package");
        let profiles = Profiles::saved(&package);
        let host = prepared.start(Some(packages.path().to_path_buf())).await;
        Self {
            host,
            packages,
            _profiles: profiles,
            _turn: turn,
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

/// Waits until the shell has run a line of its own after a program, which it does only once that
/// program has ended and everything the program printed has been shown.
async fn back_at_the_prompt(terminal: &mut WorkerTerminal, name: &str) {
    terminal
        .type_line(&format!("Write-Output ('kr-' + '{name}')"))
        .await;
    terminal
        .shown(&format!("kr-{name}"), "the shell is back at its prompt")
        .await;
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
    let (turn, prepared) = take_a_turn();
    let managed = Managed::start(turn, prepared).await;

    let refused = managed.host.kr_new(&[]).await;
    assert!(
        !refused.succeeded(),
        "a create went ahead with no entry in the profile: {}",
        refused.said()
    );
    // The worker's own refusal, which names the missing entry. The words of a wait that ran out
    // name the command too, so they are not what shows that the create was refused at once.
    assert_eq!(
        refused.document["code"],
        "SHELL_INTEGRATION_UNSUPPORTED",
        "{}",
        refused.said()
    );
    assert!(
        refused.said().contains("no startup entry"),
        "the refusal is not the worker's, made before a shell started: {}",
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

/// Publishes the package in `directory` in a generation signed with `keys`, enrols that repository,
/// and installs and enables the package as the owner who confirmed what it may do, before any
/// daemon opens the catalogue. Returns the directory the generation is published in, which has to
/// stay while the daemon runs.
///
/// The catalogue gives a publisher's name to one root, so repositories that list the same
/// publisher are published under the same keys.
///
/// Every capability the manifest asks for is granted, as the install requires. A native bridge's is
/// among them, and on Windows the host applies no bridge, so nothing is written into the person's
/// own agent directory.
async fn install_package(
    prepared: &Prepared,
    directory: &Path,
    repository: &str,
    keys: &generations::KeySet,
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
            keys: Some(keys.clone()),
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
///
/// KR-REQ-01.06, the part about commands and agent names that work unchanged: with both
/// integrations on, a program started by its path is given no registration and no flags, a shim
/// found first on the search path runs as typed, and the status a launched program ends with is
/// the line's.
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
    let (turn, prepared) = take_a_turn_beside_the_test();
    // Both packages are the release's own, from one publisher, so their repositories share a root.
    let keys = generations::KeySet::generate();
    let _claude_published =
        install_package(&prepared, &bundled_package("claude-code"), "claude", &keys).await;
    let _qoder_published =
        install_package(&prepared, &bundled_package("qoder-cli"), "qoder", &keys).await;
    let managed = Managed::start(turn, prepared).await;
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
    back_at_the_prompt(&mut terminal, "claude-over").await;
    let printed = after(&terminal, "claude-reg=");
    eprintln!("claude printed: {printed}");
    assert!(
        printed
            .split_whitespace()
            .next()
            .is_some_and(|registration| registration.contains("registration.")),
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
    back_at_the_prompt(&mut terminal, "qoder-over").await;
    let printed = after(&terminal, "qoder-reg=");
    eprintln!("qodercli printed: {printed}");
    assert!(
        printed
            .split_whitespace()
            .next()
            .is_some_and(|registration| registration.contains("registration.")),
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
    back_at_the_prompt(&mut terminal, "path-over").await;
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
/// host and registers the package's component in it.
///
/// Nothing starts the host but the daemon, and nothing asks it to but a worker whose binding wants
/// a component. The program stays alive, so the binding outlives the line that started it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = writes_profiles!()]
async fn a_program_whose_package_ships_a_component_starts_the_plugin_host_on_windows() {
    let component = well_behaved();
    let (turn, prepared) = take_a_turn();
    let package = tempfile::tempdir().expect("a directory on the internal disk");
    let directory = component_package(package.path(), &component);
    let _published = install_package(
        &prepared,
        &directory,
        "development",
        &generations::KeySet::generate(),
    )
    .await;
    let managed = Managed::start(turn, prepared).await;
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

    // The program ends when it is given its line, and the shell comes back: a line the shell is
    // given after it runs only if the program did not take it.
    terminal.type_line("").await;
    back_at_the_prompt(&mut terminal, "program-ended").await;
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

/// The system directory's own copy of a program, which no search path can stand in for.
fn system32(program: &str) -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").expect("the system directory"))
        .join("System32")
        .join(program)
}

/// The processes the system lists, with what it says of each: image name, identifier, login
/// session number and the account each runs as.
///
/// A listing that did not come is not an empty one: it stops the case.
fn listed_processes() -> Vec<(String, u32, u32, String)> {
    let listed = Command::new(system32("tasklist.exe"))
        .args(["/V", "/FO", "CSV", "/NH"])
        .output()
        .expect("tasklist runs");
    assert!(
        listed.status.success(),
        "tasklist did not list the processes: {}{}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr)
    );
    String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim().trim_matches('"').split("\",\"");
            let image = fields.next()?.to_owned();
            let pid = fields.next()?.parse().ok()?;
            let _session_name = fields.next()?;
            let session = fields.next()?.parse().ok()?;
            let user = fields.nth(2)?.to_owned();
            Some((image, pid, session, user))
        })
        .collect()
}

/// The programs of the product (`kr-*` and `kr`) that run as this account, in any login session,
/// by image name.
fn product_programs_of_this_account() -> Vec<String> {
    let account = format!(
        "{}\\{}",
        std::env::var("USERDOMAIN").expect("this account's domain"),
        std::env::var("USERNAME").expect("this account's name")
    );
    let listed = listed_processes();
    assert!(
        listed
            .iter()
            .any(|(_, _, _, user)| user.eq_ignore_ascii_case(&account)),
        "the listing names no process of {account}, so it cannot show that none of the product's is \
         left"
    );
    listed
        .into_iter()
        .filter(|(image, _, _, user)| {
            let image = image.to_ascii_lowercase();
            (image.starts_with("kr-") || image == "kr.exe") && user.eq_ignore_ascii_case(&account)
        })
        .map(|(image, pid, session, _)| format!("{image} (process {pid}, login session {session})"))
        .collect()
}

/// What the system says of the processes [`descendants_in`] walks, behind a seam so that a case
/// can put a reading that fails where it wants one, which no real kernel does on request.
trait Readings {
    /// Asks the system about one process identifier.
    fn process(&self, pid: u32) -> kr_ipc::identity::ProcessQuery;

    /// The process the kernel shows started `child`, as the identity it was started under; or why
    /// no process is shown to have.
    fn parent_of(
        &self,
        child: &kr_protocol::identity::ProcessStartIdentity,
    ) -> Result<kr_protocol::identity::ProcessStartIdentity, String>;

    /// When the process started, on the kernel's interrupt clock, which a clock that moved does
    /// not change; or what stopped the reading.
    fn started(&self, process: &kr_protocol::identity::ProcessStartIdentity)
    -> Result<u64, String>;

    /// Whether the process is still the one that was started.
    fn state(
        &self,
        process: &kr_protocol::identity::ProcessStartIdentity,
    ) -> kr_ipc::identity::ProcessState;
}

/// The system's own readings.
struct Kernel;

impl Readings for Kernel {
    fn process(&self, pid: u32) -> kr_ipc::identity::ProcessQuery {
        kr_ipc::identity::query_process(pid)
    }

    fn parent_of(
        &self,
        child: &kr_protocol::identity::ProcessStartIdentity,
    ) -> Result<kr_protocol::identity::ProcessStartIdentity, String> {
        kr_worker::windows::lineage::parent_of(child)
    }

    fn started(
        &self,
        process: &kr_protocol::identity::ProcessStartIdentity,
    ) -> Result<u64, String> {
        kr_worker::windows::lineage::monotonic_start(process)
    }

    fn state(
        &self,
        process: &kr_protocol::identity::ProcessStartIdentity,
    ) -> kr_ipc::identity::ProcessState {
        kr_ipc::identity::process_state(process)
    }
}

/// What the readings say of when a process started.
enum Start {
    /// The process started then, on the kernel's interrupt clock.
    At(u64),
    /// The start was not read, and the process is shown to have ended.
    Ended,
    /// The start was not read, and the process is not shown to have ended: what stopped the
    /// reading, and what the state of the process says.
    Unread(String),
}

/// When `process` started, or why that is not known. A start that was not read of a process that
/// still runs, or may, is not an ended process.
fn start_of(
    readings: &impl Readings,
    process: &kr_protocol::identity::ProcessStartIdentity,
) -> Start {
    use kr_ipc::identity::ProcessState;

    match readings.started(process) {
        Ok(started) => Start::At(started),
        Err(why) => match readings.state(process) {
            ProcessState::Ended => Start::Ended,
            ProcessState::Running => Start::Unread(format!(
                "process {} runs and its start was not read: {why}",
                process.pid.get()
            )),
            ProcessState::Unknown { detail } => Start::Unread(format!(
                "process {} could not be shown to have ended, and its start was not read: {why}; \
                 {detail}",
                process.pid.get()
            )),
        },
    }
}

/// Every process of `pairs` (a process identifier and the identifier it names as its parent) that
/// descends, through parents shown to be running, from one of `roots`, as the identity it was
/// started under.
///
/// A process is a child when the kernel names the recorded parent as the process that started it.
/// One that names a recorded parent's identifier but was started by another process is not its
/// child: the identifier was another process's, which has ended. Where the kernel names no parent,
/// the order of its starts, which a clock that moved does not change, tells the two apart: a parent
/// was running before its child existed, so one that started after it is no parent, and a process
/// the kernel shows ended since the list was made is not there to record. A reading that did not
/// come is neither of these, and stops the case: a process whose parent could not be established
/// is not one the record can leave out.
///
/// # Panics
///
/// Panics when a process of the list cannot be read, or its parent cannot be shown to be its
/// parent or not, and neither process is shown to have ended. Both processes are read before that
/// is decided, so that a process shown to have ended is skipped whatever the other read.
fn descendants_in(
    pairs: &[(u32, u32)],
    roots: &[kr_protocol::identity::ProcessStartIdentity],
    readings: &impl Readings,
) -> Vec<kr_protocol::identity::ProcessStartIdentity> {
    use kr_ipc::identity::ProcessQuery;

    let mut found: Vec<kr_protocol::identity::ProcessStartIdentity> = Vec::new();
    let mut parents: Vec<kr_protocol::identity::ProcessStartIdentity> = roots.to_vec();
    while let Some(parent) = parents.pop() {
        for (pid, _) in pairs
            .iter()
            .filter(|(_, named)| u64::from(*named) == parent.pid.get())
        {
            // A process that ended since the list was read is not one to record; one the system
            // will not describe is a process that cannot be shown to have ended, and stops the
            // case.
            let child = match readings.process(*pid) {
                ProcessQuery::Present(child) => child,
                ProcessQuery::Gone => continue,
                ProcessQuery::CannotEstablish(error) => {
                    panic!(
                        "process {pid}, which names process {} as its parent: {error}",
                        parent.pid.get()
                    )
                }
            };
            if found.contains(&child) || roots.contains(&child) {
                continue;
            }
            match readings.parent_of(&child) {
                Ok(started_by) if started_by == parent => {
                    found.push(child.clone());
                    parents.push(child);
                }
                Ok(started_by) => eprintln!(
                    "process {pid} names process {} as its parent, but process {} started it, so it \
                     is not recorded",
                    parent.pid.get(),
                    started_by.pid.get()
                ),
                // The kernel would not name a parent. What it would not say is told apart by the
                // starts: a parent that started after its child is not its parent, and a process
                // that has ended is not there to record; anything else is a reading that failed.
                Err(why) => match (start_of(readings, &parent), start_of(readings, &child)) {
                    // Either process shown ended is not one to record, whatever the other read.
                    (Start::Ended, _) | (_, Start::Ended) => eprintln!(
                        "process {pid} or its parent has ended and is not recorded: {why}"
                    ),
                    (Start::At(parent_started), Start::At(child_started))
                        if parent_started > child_started =>
                    {
                        eprintln!(
                            "process {pid} names process {} as its parent, which started after it \
                             did, so it is not recorded: {why}",
                            parent.pid.get()
                        );
                    }
                    (Start::At(_), Start::At(_)) => panic!(
                        "process {pid} names process {} as its parent, which started no later than \
                         it did, and the kernel would not name its parent: {why}",
                        parent.pid.get()
                    ),
                    (Start::Unread(unread), _) | (_, Start::Unread(unread)) => panic!(
                        "process {pid} names process {} as its parent, and the kernel would not \
                         name its parent ({why}): {unread}",
                        parent.pid.get()
                    ),
                },
            }
        }
    }
    found
}

/// Every process that is running now and descends, through running parents, from one of `roots`, by
/// the parent each names, as the identity it was started under, read from the system's own list of
/// processes.
///
/// # Panics
///
/// Panics when the list cannot be had, or [`descendants_in`] stops.
fn descendants_of(
    roots: &[kr_protocol::identity::ProcessStartIdentity],
) -> Vec<kr_protocol::identity::ProcessStartIdentity> {
    let listed = Command::new("pwsh.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance Win32_Process | ForEach-Object { \"$($_.ProcessId) $($_.ParentProcessId)\" }",
        ])
        .output()
        .expect("PowerShell starts");
    assert!(
        listed.status.success(),
        "the processes were not listed: {}{}",
        String::from_utf8_lossy(&listed.stdout),
        String::from_utf8_lossy(&listed.stderr)
    );
    let pairs: Vec<(u32, u32)> = String::from_utf8_lossy(&listed.stdout)
        .lines()
        .filter_map(|line| {
            let mut numbers = line.split_whitespace().map(|number| number.parse().ok());
            Some((numbers.next()??, numbers.next()??))
        })
        .collect();
    assert!(!pairs.is_empty(), "the system listed no process");
    descendants_in(&pairs, roots, &Kernel)
}

/// The walk over a table of readings that a case writes down, with the reading that fails where it
/// wants one.
mod the_walk {
    use std::collections::{BTreeMap, BTreeSet};

    use kr_ipc::identity::{ProcessQuery, ProcessState};
    use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};

    use super::{Readings, descendants_in};

    /// The identity of the process numbered `pid`.
    fn identity(pid: u32) -> ProcessStartIdentity {
        ProcessStartIdentity::new(
            u64::from(pid),
            ProcessStartSource::WindowsProcessCreationTime,
            1_000 + u64::from(pid),
        )
    }

    /// What the system says, where a process not named here is running, was started by the
    /// process the list names, and started when its number says: the lower the earlier.
    #[derive(Default)]
    struct Scripted {
        /// Processes no longer there when they are asked about.
        gone: BTreeSet<u32>,
        /// Processes shown to have ended when their state is asked for.
        ended: BTreeSet<u32>,
        /// What the kernel says of who started a process, by the process: the number of the
        /// process, or why none is named.
        started_by: BTreeMap<u32, Result<u32, String>>,
        /// What the kernel says of when a process started, by the process.
        starts: BTreeMap<u32, Result<u64, String>>,
    }

    impl Readings for Scripted {
        fn process(&self, pid: u32) -> ProcessQuery {
            if self.gone.contains(&pid) {
                ProcessQuery::Gone
            } else {
                ProcessQuery::Present(identity(pid))
            }
        }

        fn parent_of(&self, child: &ProcessStartIdentity) -> Result<ProcessStartIdentity, String> {
            let pid = u32::try_from(child.pid.get()).expect("a process identifier");
            let named = LIST
                .iter()
                .find(|(listed, _)| *listed == pid)
                .map_or(0, |(_, parent)| *parent);
            self.started_by
                .get(&pid)
                .cloned()
                .unwrap_or(Ok(named))
                .map(identity)
        }

        fn started(&self, process: &ProcessStartIdentity) -> Result<u64, String> {
            let pid = u32::try_from(process.pid.get()).expect("a process identifier");
            self.starts.get(&pid).cloned().unwrap_or(Ok(u64::from(pid)))
        }

        fn state(&self, process: &ProcessStartIdentity) -> ProcessState {
            let pid = u32::try_from(process.pid.get()).expect("a process identifier");
            if self.ended.contains(&pid) {
                ProcessState::Ended
            } else {
                ProcessState::Running
            }
        }
    }

    /// The process the walk starts from, and the list: process 20 and process 30 are its child and
    /// its grandchild, and process 40 names a parent that is not recorded.
    const ROOT: u32 = 10;
    const LIST: [(u32, u32); 3] = [(20, ROOT), (30, 20), (40, 5)];

    #[test]
    fn what_the_kernel_shows_a_recorded_process_started_is_recorded_with_what_that_started() {
        let found = descendants_in(&LIST, &[identity(ROOT)], &Scripted::default());
        assert_eq!(found, [identity(20), identity(30)]);
    }

    #[test]
    #[should_panic(expected = "runs and its start was not read")]
    fn a_child_whose_start_was_not_read_stops_the_walk_and_is_not_left_out() {
        let refused = "process 20 could not be opened: access is denied".to_owned();
        let mut readings = Scripted::default();
        readings.started_by.insert(20, Err(refused.clone()));
        readings.starts.insert(20, Err(refused));
        descendants_in(&LIST, &[identity(ROOT)], &readings);
    }

    #[test]
    #[should_panic(expected = "runs and its start was not read")]
    fn a_grandchild_whose_start_was_not_read_stops_the_walk_and_does_not_leave_out_its_subtree() {
        let refused = "process 30 could not be opened: access is denied".to_owned();
        let mut readings = Scripted::default();
        readings.started_by.insert(30, Err(refused.clone()));
        readings.starts.insert(30, Err(refused));
        descendants_in(&LIST, &[identity(ROOT)], &readings);
    }

    #[test]
    #[should_panic(expected = "runs and its start was not read")]
    fn a_parent_whose_start_was_not_read_stops_the_walk() {
        let refused = "process 10 could not be opened: access is denied".to_owned();
        let mut readings = Scripted::default();
        readings.started_by.insert(20, Err(refused.clone()));
        readings.starts.insert(ROOT, Err(refused));
        descendants_in(&LIST, &[identity(ROOT)], &readings);
    }

    #[test]
    #[should_panic(expected = "would not name its parent")]
    fn a_refusal_that_no_reading_explains_stops_the_walk() {
        let mut readings = Scripted::default();
        readings
            .started_by
            .insert(20, Err("process 20 changed while it was read".to_owned()));
        descendants_in(&LIST, &[identity(ROOT)], &readings);
    }

    #[test]
    fn a_process_the_kernel_shows_ended_since_the_list_was_made_is_not_recorded() {
        let ended = "process 20 has ended".to_owned();
        let mut readings = Scripted::default();
        readings.ended.insert(20);
        readings.started_by.insert(20, Err(ended.clone()));
        readings.starts.insert(20, Err(ended));
        assert_eq!(
            descendants_in(&LIST, &[identity(ROOT)], &readings),
            Vec::<ProcessStartIdentity>::new()
        );
    }

    #[test]
    fn a_child_shown_ended_is_skipped_whatever_the_parents_start_read() {
        let refused = "process 10 could not be opened: access is denied".to_owned();
        let mut readings = Scripted::default();
        readings.ended.insert(20);
        readings
            .started_by
            .insert(20, Err("process 20 has ended".to_owned()));
        readings
            .starts
            .insert(20, Err("process 20 has ended".to_owned()));
        readings.starts.insert(ROOT, Err(refused));
        assert_eq!(
            descendants_in(&LIST, &[identity(ROOT)], &readings),
            Vec::<ProcessStartIdentity>::new()
        );
    }

    #[test]
    fn a_process_that_is_gone_when_it_is_asked_about_is_not_recorded() {
        let mut readings = Scripted::default();
        readings.gone.insert(20);
        assert_eq!(
            descendants_in(&LIST, &[identity(ROOT)], &readings),
            Vec::<ProcessStartIdentity>::new()
        );
    }

    #[test]
    fn a_process_the_kernel_shows_another_process_started_is_not_recorded() {
        let mut readings = Scripted::default();
        readings.started_by.insert(20, Ok(7));
        assert_eq!(
            descendants_in(&LIST, &[identity(ROOT)], &readings),
            Vec::<ProcessStartIdentity>::new()
        );
    }

    #[test]
    fn a_process_that_started_before_the_parent_it_names_is_not_its_child() {
        let mut readings = Scripted::default();
        readings.started_by.insert(
            20,
            Err("the process that holds identifier 10 started after process 20 did".to_owned()),
        );
        readings.starts.insert(ROOT, Ok(500));
        readings.starts.insert(20, Ok(100));
        assert_eq!(
            descendants_in(&LIST, &[identity(ROOT)], &readings),
            Vec::<ProcessStartIdentity>::new()
        );
    }
}

/// The component with a section of its own at the end, so that its digest is one no host has
/// compiled before and a registration of it is a cold compile.
fn a_component_of_its_own(component: &[u8]) -> Vec<u8> {
    let name = b"kr-attempt";
    let identity = kr_ipc::new_uuid();
    let identity = identity.as_bytes();
    let mut section = vec![u8::try_from(name.len()).expect("a short name")];
    section.extend_from_slice(name);
    section.extend_from_slice(identity);
    let mut bytes = component.to_vec();
    // A custom section: its identifier, its size (one byte holds a size under 128), then its
    // contents.
    bytes.push(0);
    bytes.push(
        u8::try_from(section.len())
            .ok()
            .filter(|size| *size < 128)
            .expect("a short section"),
    );
    bytes.extend_from_slice(&section);
    bytes
}

/// Asks `check` until it answers, or the liveness deadline passes.
async fn until<T, Fut>(what: &str, mut check: impl FnMut() -> Fut) -> T
where
    Fut: std::future::Future<Output = Option<T>>,
{
    let started = tokio::time::Instant::now();
    loop {
        if let Some(found) = check().await {
            return found;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {LIVENESS_DEADLINE:?} for {what}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Reads what the session writes until `done` says the terminal shows what it waits for, or the
/// liveness deadline passes.
async fn watched_until(
    terminal: &mut WorkerTerminal,
    what: &str,
    done: impl Fn(&WorkerTerminal) -> bool,
) {
    let started = tokio::time::Instant::now();
    while !done(terminal) {
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {LIVENESS_DEADLINE:?} for {what}; the terminal shows: {}",
            terminal.text()
        );
        terminal.watch(Duration::from_millis(50)).await;
    }
}

/// The plugin host the daemon has published for `environment`, where it has.
fn published_host(
    environment: &kr_ipc::paths::EnvironmentPaths,
) -> Option<kr_plugin_service::protocol::HostDescriptor> {
    kr_plugin_service::launcher::read_descriptor(
        environment,
        &kr_plugin_service::protocol::HostProtocol::THIS,
    )
    .ok()
    .flatten()
}

/// The process identity the worker of `session_id` published.
fn worker_of(
    environment: &kr_ipc::paths::EnvironmentPaths,
    session_id: kr_protocol::ids::SessionId,
) -> kr_protocol::identity::ProcessStartIdentity {
    kr_ipc::descriptor::read_all(environment)
        .expect("reads the runtime directory")
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .find(|descriptor| descriptor.session_id == session_id)
        .expect("the worker published its descriptor")
        .process_start_identity
}

/// Ends the process by the identity it was started under, and waits until it is read as ended.
async fn end_by_identity(process: &kr_protocol::identity::ProcessStartIdentity) {
    use kr_ipc::identity::{ProcessState, Stop, Stopped, process_state, stop_process};

    let answer = stop_process(process, Stop::Kill);
    if !matches!(answer, Stopped::Signalled | Stopped::Gone) {
        eprintln!("process {} was not stopped: {answer:?}", process.pid.get());
    }
    until("the process to end", || async {
        (process_state(process) == ProcessState::Ended).then_some(())
    })
    .await;
}

/// Whether `report` says the worker is registering a binding's component with the plugin host and
/// has no answer: the component is pending, for a reason that says it is registering and not asking
/// the daemon for the host or connecting to it.
fn is_registering(report: &kr_protocol::admission::ComponentReport) -> bool {
    report.state == ComponentState::Pending
        && report
            .reason
            .0
            .as_deref()
            .is_some_and(|reason| reason.contains("registering"))
}

/// What every worker reports of its bindings' components, with the binding each is for, after each
/// has been asked again; or nothing, where a worker did not answer.
async fn reported_fresh(
    controller: &kr_controller::service::Controller,
) -> Option<
    Vec<(
        kr_protocol::ids::BrokerBindingId,
        kr_protocol::admission::ComponentReport,
    )>,
> {
    controller.refresh_admissions().await.then(|| {
        controller
            .reported_components()
            .into_iter()
            .map(|(_, binding, report)| (binding, report))
            .collect()
    })
}

/// The highest number of the numbered lines the stand-in program has printed that the terminal
/// shows.
fn ticks(terminal: &WorkerTerminal) -> u64 {
    terminal
        .text()
        .split("tick-")
        .skip(1)
        .filter_map(|piece| {
            piece
                .chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
                .parse::<u64>()
                .ok()
        })
        .max()
        .unwrap_or(0)
}

/// A managed session on a host whose catalogue holds a package that ships a component, with the
/// package's integration on and a stand-in for the agent it recognises first on the shell's
/// search path.
struct Running {
    /// What the session's shell is typed at, first so it goes before the host.
    terminal: WorkerTerminal,
    /// The host, which goes before the files its daemon and workers read.
    managed: Managed,
    session_id: kr_protocol::ids::SessionId,
    environment: kr_ipc::paths::EnvironmentPaths,
    /// The package, its published generation and the stand-in, in use as long as the host runs.
    directories: Vec<tempfile::TempDir>,
}

impl Running {
    /// Starts the host and the session around a package that ships `component`.
    async fn start(component: &[u8]) -> Self {
        let (turn, prepared) = take_a_turn();
        let package = tempfile::tempdir().expect("a directory on the internal disk");
        let directory = component_package(package.path(), component);
        let published = install_package(
            &prepared,
            &directory,
            "development",
            &generations::KeySet::generate(),
        )
        .await;
        let managed = Managed::start(turn, prepared).await;
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
        let programs = stand_ins();
        stand_in(programs.path(), "claude");
        let created = managed.host.kr_new(&[]).await;
        let (session_id, _) = created.session();
        let mut terminal = managed.terminal(&created).await;
        answering(&mut terminal).await;
        first_on_the_path(&mut terminal, programs.path()).await;
        let environment = managed.host.tree.environment();
        Self {
            terminal,
            managed,
            session_id,
            environment,
            directories: vec![package, published, programs],
        }
    }
}

/// The plugin host's registration gate, closed while this is held: a plugin host built with the
/// `testing` feature holds every registration it is sent, before it reads or compiles anything and
/// so before it can answer, for as long as the gate file is in the environment's state directory,
/// and makes a second file there when one has reached the gate. The names are the host's own
/// (`REGISTRATION_GATE` and `REGISTRATION_GATE_REACHED` in `kr-plugin-runtime`'s `service::host`);
/// a host built without the feature reads neither.
struct RegistrationGate {
    gate: PathBuf,
    reached: PathBuf,
}

impl RegistrationGate {
    /// Closes the gate for the environment's hosts.
    fn close(environment: &kr_ipc::paths::EnvironmentPaths) -> Self {
        let directory = environment.state_dir();
        std::fs::create_dir_all(directory).expect("the environment's state directory");
        let gate = directory.join("hold-registrations");
        std::fs::write(&gate, b"closed").expect("the gate is closed");
        Self {
            gate,
            reached: directory.join("hold-registrations.reached"),
        }
    }

    /// Whether a registration has reached the closed gate of some host.
    fn reached(&self) -> bool {
        self.reached.exists()
    }

    /// Opens the gate: the registrations it holds go on.
    fn open(&self) {
        match std::fs::remove_file(&self.gate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("the gate is not opened: {error}"),
        }
    }
}

impl Drop for RegistrationGate {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.gate);
    }
}

/// KR-REQ-05.07: a plugin host that ends with a registration unanswered takes no worker with it,
/// and the binding comes back, on Windows.
///
/// A worker is running a program a package that ships a component recognises, which prints a
/// numbered line every moment, and registers its binding with the plugin host the daemon started.
/// The host holds the registration at its closed gate (`RegistrationGate`), before it reads or
/// compiles anything, so it has not answered and cannot: the host says so itself, by the file it
/// makes when the registration reaches the gate. The worker's own report, asked for again after the
/// terminal has been sent twenty lines more, still reads that it is registering. The host is then
/// ended by the identity it was started under with that request outstanding. The worker goes on,
/// the terminal goes on being sent lines it had not been sent, and with the gate open the daemon
/// starts a replacement under its bound, which the worker registers the same binding with again,
/// so that the host holds the binding. The replacement had to compile the component: the first
/// host never reached its compile.
///
/// It needs the plugin host built with the `testing` feature, as the other cases of the plugin
/// runtime do; with any other host the registration never reaches the gate and the case fails
/// there, since nothing else shows that a registration was held unanswered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = writes_profiles!()]
async fn a_plugin_host_that_ends_with_a_registration_unanswered_takes_no_worker_with_it_on_windows()
{
    // A component whose digest no host has compiled, so that a registration of it is a cold compile.
    let component = a_component_of_its_own(&well_behaved());
    let mut world = Running::start(&component).await;
    let environment = world.environment.clone();
    let published = || published_host(&environment);
    assert!(
        published().is_none(),
        "a plugin host was published before any program was typed"
    );
    // The plugin host is the environment's own job, which no test teardown ends: it goes when this
    // case does, whichever way the case goes.
    let _host_ends = HostEnding(&published);
    let controller = world.managed.host.controller();
    let gate = RegistrationGate::close(&environment);

    // The program prints the registration its launcher gave it, which the typed line cannot spell,
    // and then a numbered line every moment; `rem` takes the flags the integration adds after what
    // was typed, so they reach the command shell as a comment.
    world
        .terminal
        .type_line(
            "claude /c 'echo reg=%KR_REGISTRATION% & for /l %i in (1,1,100000) do \
             @(echo tick-%i & ping -n 1 127.0.0.1 >nul) & rem'",
        )
        .await;
    world
        .terminal
        .shown("registration.", "the program started with its registration")
        .await;

    // The worker's report is looked at as fast as the workers answer, until it reads that the
    // registration is under way.
    let started = tokio::time::Instant::now();
    let binding = loop {
        let reports = reported_fresh(&controller).await;
        match reports.as_deref() {
            Some([(id, report)]) if is_registering(report) => {
                eprintln!("the worker reports the registration as sent: {report:?}");
                break *id;
            }
            Some([(_, report)]) if report.state == ComponentState::Registered => panic!(
                "the registration was answered through a closed gate: the plugin host is not built \
                 with the testing feature"
            ),
            _ => {}
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the registration was never reported as sent; the workers report {reports:?}; the \
             terminal shows: {}",
            world.terminal.text()
        );
        world.terminal.watch(Duration::from_millis(5)).await;
    };
    let host = published()
        .expect("the plugin host is published while a worker registers with it")
        .process_start_identity;
    // The registration has reached the host and stands at its gate: neither compiled nor answered.
    until("the registration to reach the closed gate", || async {
        gate.reached().then_some(())
    })
    .await;
    eprintln!(
        "the registration is held at the closed gate of plugin host {}",
        host.pid.get()
    );

    // The registration stays outstanding if the worker's own report, asked for again after the
    // terminal has been sent twenty more lines, still says so.
    let mark = ticks(&world.terminal);
    let looked_at = tokio::time::Instant::now();
    loop {
        world.terminal.watch(Duration::from_millis(50)).await;
        if let Some(reports) = reported_fresh(&controller).await {
            match reports.as_slice() {
                [(id, report)] if *id == binding && is_registering(report) => {
                    let shown = ticks(&world.terminal);
                    if shown > mark + 20 {
                        eprintln!(
                            "the registration is held, the worker still reports it as sent \
                             ({report:?}), and the terminal was sent lines {mark} to {shown}"
                        );
                        break;
                    }
                }
                other => panic!("a held registration is reported as {other:?}"),
            }
        }
        assert!(
            looked_at.elapsed() < LIVENESS_DEADLINE,
            "the terminal was sent no more lines while the registration was outstanding: {}",
            world.terminal.text()
        );
    }
    assert_eq!(
        kr_ipc::identity::process_state(&host),
        kr_ipc::identity::ProcessState::Running,
        "the host is held at its gate and is not ended"
    );

    // The host ends with the registration outstanding; the gate opens once it has.
    let worker = worker_of(&environment, world.session_id);
    end_by_identity(&host).await;
    gate.open();
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        kr_ipc::identity::ProcessState::Running,
        "the worker ended with the plugin host"
    );
    eprintln!(
        "the host {} ended with the registration outstanding; the worker {} is running",
        host.pid.get(),
        worker.pid.get()
    );
    let after_the_end = ticks(&world.terminal);
    watched_until(
        &mut world.terminal,
        "the terminal to be sent lines after the host ended",
        |terminal| ticks(terminal) > after_the_end + 20,
    )
    .await;

    // A replacement is the daemon's doing, on the worker's asking: a host that is not the first,
    // and the binding registered with it.
    let replacement = until("a replacement plugin host to be published", || async {
        published()
            .map(|descriptor| descriptor.process_start_identity)
            .filter(|started| *started != host)
    })
    .await;
    eprintln!(
        "the daemon started a replacement plugin host, process {}",
        replacement.pid.get()
    );
    let waiting = tokio::time::Instant::now();
    loop {
        world.terminal.watch(Duration::from_millis(50)).await;
        let reports = reported_fresh(&controller).await;
        let registered = reports.as_deref().and_then(|reports| match reports {
            [(id, report)] if *id == binding && report.state == ComponentState::Registered => {
                report.reason.0.as_deref()
            }
            _ => None,
        });
        // The first host never reached its compile, so the replacement compiles the component: a
        // replacement that loaded it from the cache found a filing that nothing made.
        assert!(
            !registered
                .is_some_and(|reason| reason.contains("loaded from the compiled-code cache")),
            "the replacement loaded a component that the held host had not compiled: {reports:?}"
        );
        if registered.is_some_and(|reason| reason.contains("compiled in")) {
            eprintln!("the binding is registered with the replacement: {reports:?}");
            break;
        }
        assert!(
            waiting.elapsed() < LIVENESS_DEADLINE,
            "the binding was not registered with the replacement; the workers report {reports:?}"
        );
    }
    let client = kr_plugin_service::client::PluginClient::connect(&environment)
        .await
        .expect("the replacement answers");
    let health = client
        .health()
        .await
        .expect("the replacement reports its health");
    assert_eq!(health.live_bindings, 1, "{health:?}");
    assert_ne!(replacement, host);

    // And nothing else went with the host: the worker, and the program, which goes on printing.
    assert_eq!(
        kr_ipc::identity::process_state(&worker),
        kr_ipc::identity::ProcessState::Running
    );
    let after_the_recovery = ticks(&world.terminal);
    watched_until(
        &mut world.terminal,
        "the terminal to be sent lines after the recovery",
        |terminal| ticks(terminal) > after_the_recovery + 20,
    )
    .await;
    eprintln!(
        "the worker {} runs, and the terminal was sent lines {after_the_recovery} to {}",
        worker.pid.get(),
        ticks(&world.terminal)
    );
}

/// Where the case that signs the account out leaves what the case that follows the sign-out reads:
/// in the account's own temporary directory, which the sign-out keeps.
fn sign_out_record() -> PathBuf {
    std::env::temp_dir().join("kr-sign-out-record.json")
}

/// The environment's task, as the Task Scheduler exports it, or nothing where there is none.
fn exported_task(name: &str) -> Option<String> {
    let output = Command::new(system32("schtasks.exe"))
        .args(["/Query", "/TN", name, "/XML"])
        .output()
        .expect("schtasks runs");
    output
        .status
        .success()
        .then(|| kr_controller::supervision::windows::decode_output(&output.stdout))
}

/// What the host guide says of the per-user startup entry, read from `exported`: the user's own
/// account, logged on where the user is signed in, with the least privilege, no trigger, instances
/// in parallel, no time limit, and one action that runs the installation's `kr-controller` as the
/// environment's starter.
fn assert_the_entry_is_as_documented(exported: &str) {
    use kr_controller::supervision::windows::{LogonType, RegisteredTask};

    let user = kr_ipc::starter::current_user_sid().expect("this account");
    let task = RegisteredTask::parse(exported);
    assert_eq!(
        task.user, user,
        "the entry is not this account's: {exported}"
    );
    assert_eq!(
        task.logon,
        Some(LogonType::InteractiveToken),
        "the entry does not log on where the user is signed in: {exported}"
    );
    assert!(
        task.run_level.is_empty() || task.run_level == "LeastPrivilege",
        "the entry does not run with the least privilege: {exported}"
    );
    assert!(!task.triggered, "the entry has a trigger: {exported}");
    assert_eq!(task.multiple_instances, "Parallel", "{exported}");
    assert_eq!(task.execution_time_limit, "PT0S", "{exported}");
    assert_eq!(task.actions, 1, "{exported}");
    assert!(
        task.command
            .to_ascii_lowercase()
            .ends_with("kr-controller.exe")
            && task.arguments.contains("--starter"),
        "the entry's action does not run the starter: {exported}"
    );
}

/// KR-REQ-07.69: with a plugin host running, an account's sign-out ends the session, and what the
/// session started is the session's: the first half runs the session as a person's would run it
/// and signs the account out, and the half that follows reads what is left.
///
/// A program a package with a component recognises is typed at the managed prompt of a session on
/// Windows, and the daemon starts the plugin host and registers the component in it. Before the
/// sign-out, the daemon (this test's process), the worker, the plugin host and every running
/// process the kernel shows either of the last two started, the shell and the program among them,
/// are each shown running, by the identity they were started under, in this login session. That is
/// the record, and it holds what the kernel shows: a process whose parent had ended when the
/// processes were listed is not shown to descend from either and is outside it, and a reading that
/// did not come stops the case, so that no process is left out for want of one. The startup entry
/// is shown to be the one the product registers, and as the host guide says it is. The identities
/// and the entry as the Task Scheduler exports it are kept for the half that follows; the
/// account's profiles are put back; nothing this case holds is let go of, so that only the sign-out
/// can end what it started; and the account is signed out, which ends this process.
///
/// The case is run by a run that signs the account in again afterwards, as a temporary standard
/// account, and runs the case that follows. It signs out the account that runs it, so it runs only
/// where `KR_ALLOW_SIGN_OUT=1` says that account is disposable, and never for an account in the
/// Administrators group.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = signs_out!()]
async fn with_a_plugin_host_running_the_session_is_set_up_and_the_account_signed_out() {
    // Before anything is started: a run of every case in this file at once, or a run as an account
    // whose session others depend on, must not end that session.
    assert!(
        std::env::var(SIGN_OUT_SWITCH).is_ok_and(|value| value == "1"),
        "this case signs the account that runs it out; set {SIGN_OUT_SWITCH}=1 where that account \
         is disposable"
    );
    assert!(
        !standing().iter().any(|line| line.contains("S-1-5-32-544")),
        "this case signs its account out, and an account in the Administrators group is not one to \
         sign out"
    );
    // A record of an earlier run is not the record of this one.
    match std::fs::remove_file(sign_out_record()) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("the record of an earlier run is not removed: {error}"),
    }
    let component = well_behaved();
    let mut world = Running::start(&component).await;
    let environment = world.environment.clone();
    let published = || published_host(&environment);
    assert!(
        published().is_none(),
        "a plugin host was published before any program was typed"
    );
    // A host the sign-out does not end is still ended when the sign-out does not come, up to the
    // point where the case lets go of it so that only the sign-out ends what it started.
    let _host_ends = HostEnding(&published);
    let controller = world.managed.host.controller();

    // The program prints the registration its launcher gave it, and waits for a line to be typed to
    // it; `rem` takes the flags the integration adds after what was typed.
    world
        .terminal
        .type_line("claude /c 'echo reg=%KR_REGISTRATION% & set /p kr_release=waiting & rem'")
        .await;
    world
        .terminal
        .shown("registration.", "the program started with its registration")
        .await;
    let started = tokio::time::Instant::now();
    loop {
        let reports = reported_fresh(&controller).await;
        if reports.as_deref().is_some_and(
            |reports| matches!(reports, [(_, report)] if report.state == ComponentState::Registered),
        ) {
            break;
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "the component was not registered; the workers report {reports:?}; the terminal \
             shows: {}",
            world.terminal.text()
        );
        world.terminal.watch(Duration::from_millis(250)).await;
    }
    let host = published().expect("the plugin host is published");
    let client = kr_plugin_service::client::PluginClient::connect(&environment)
        .await
        .expect("the plugin host answers");
    let health = client.health().await.expect("the host reports its health");
    assert_eq!(health.live_bindings, 1, "{health:?}");

    // What the sign-out is about: the daemon, the worker, the plugin host and every running process
    // that either of those two started, by the identity each was started under, all in this login
    // session.
    let session = kr_ipc::starter::current_session().expect("this process's login session");
    let me = kr_ipc::identity::current_process_start_identity().expect("this process's identity");
    let worker = worker_of(&environment, world.session_id);
    let host_identity = host.process_start_identity.clone();
    let started = descendants_of(&[worker.clone(), host_identity.clone()]);
    let mut processes = vec![
        ("the daemon (this test's process)".to_owned(), me),
        ("the worker".to_owned(), worker),
        ("the plugin host".to_owned(), host_identity),
    ];
    processes.extend(started.into_iter().map(|process| {
        let image = kr_ipc::starter::process_facts(
            u32::try_from(process.pid.get()).expect("a process identifier"),
        )
        .map_or_else(
            |error| format!("an unreadable process ({error})"),
            |facts| facts.image.display().to_string(),
        );
        (format!("a process they started, {image}"), process)
    }));
    assert!(
        processes
            .iter()
            .any(|(what, _)| what.to_ascii_lowercase().ends_with("claude.exe")),
        "the program is not among what the worker started: {processes:?}"
    );
    assert!(
        processes
            .iter()
            .any(|(what, _)| what.to_ascii_lowercase().ends_with("pwsh.exe")),
        "the shell is not among what the worker started: {processes:?}"
    );
    for (what, process) in &processes {
        let facts = kr_ipc::starter::process_facts(
            u32::try_from(process.pid.get()).expect("a process identifier"),
        )
        .unwrap_or_else(|error| panic!("{what} ({}) is read: {error}", process.pid.get()));
        assert_eq!(
            kr_ipc::identity::process_state(process),
            kr_ipc::identity::ProcessState::Running,
            "{what} is running"
        );
        assert_eq!(
            facts.session,
            session,
            "{what} ({}) is in this login session",
            process.pid.get()
        );
        eprintln!(
            "before the sign-out: {what}, process {}, {}, login session {}",
            process.pid.get(),
            facts.image.display(),
            facts.session
        );
    }

    // The startup entry: the product registered it for this environment as it registers the
    // setup step's, and it is as the host guide says.
    let starter = kr_controller::supervision::windows::testing::built_binary("kr-controller")
        .unwrap_or_else(|missing| panic!("{missing}"));
    let definition =
        kr_controller::supervision::windows::testing::definition(&environment, &starter)
            .expect("the definition this host registers");
    assert_eq!(
        kr_controller::supervision::windows::standing(&definition)
            .expect("the Task Scheduler answers"),
        kr_controller::supervision::windows::Standing::Owned(Vec::new()),
        "the environment's task is not the one this build registers"
    );
    let exported = exported_task(&definition.name).expect("the environment's task is registered");
    assert_the_entry_is_as_documented(&exported);
    eprintln!(
        "before the sign-out: the entry {} is as documented",
        definition.name
    );

    let directories: Vec<String> = world
        .directories
        .iter()
        .map(|directory| directory.path().display().to_string())
        .chain([
            world.managed.host.tree.root().display().to_string(),
            world.managed.packages.path().display().to_string(),
        ])
        .collect();
    let record = serde_json::json!({
        "session": session,
        "task": definition.name,
        "entry": exported,
        "processes": processes
            .iter()
            .map(|(what, identity)| serde_json::json!({ "what": what, "identity": identity }))
            .collect::<Vec<_>>(),
        "directories": directories,
    });

    // The account's profiles go back as they were before the sign-out, which would not put them
    // back: the shell has read them and does not read them again.
    let Running {
        terminal,
        managed,
        directories,
        ..
    } = world;
    let Managed {
        host: daemon,
        packages,
        _profiles: profiles,
        _turn: turn,
    } = managed;
    drop(profiles);
    // From here only the sign-out may end what the session started. Nothing this case holds is let
    // go of, so that a sign-out that does not come leaves the processes running and the case
    // failing, and the "after" case, which needs a record, is not run on processes this case ended
    // itself.
    std::mem::forget((terminal, daemon, packages, directories, turn, _host_ends));
    std::fs::write(
        sign_out_record(),
        serde_json::to_vec_pretty(&record).expect("a record"),
    )
    .expect("the record of what the sign-out is about");
    eprintln!("signing out login session {session}");
    let signed_out = Command::new(system32("logoff.exe"))
        .status()
        .expect("logoff runs");
    assert!(signed_out.success(), "logoff: {signed_out}");
    // The end of the session ends this process, and nothing after this line runs.
    tokio::time::sleep(LIVENESS_DEADLINE).await;
    panic!("login session {session} was not ended within {LIVENESS_DEADLINE:?} of the sign-out");
}

/// KR-REQ-07.69: after the sign-out, nothing the session started is left, the plugin host included,
/// and the per-user startup entry stands, as the host guide says it does.
///
/// Run in the account's next sign-in, by the identities the half before the sign-out recorded: every
/// process the record holds, of any image, is ended. That is the daemon (the first half's own
/// process, which ends with the session), the worker, the plugin host and the running processes the
/// kernel showed either of the last two had started, the shell, the program and the console hosts
/// among them. Beyond the record only the product's own programs are looked for, the `kr` and
/// `kr-*` images that run as this account in any login session, so nothing started at the sign-in;
/// a process that is neither in the record nor an image of the product is not looked for. The
/// environment's task is registered with no trigger and is exactly as it was exported before, so
/// that nothing starts until a `kr new` after this sign-in.
#[test]
#[ignore = follows_a_sign_out!()]
fn after_a_sign_out_nothing_the_session_started_is_left_and_the_startup_entry_stands() {
    let path = sign_out_record();
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|error| {
            panic!(
                "{}: {error}; the case that signs the account out is run first, and this one in \
                 the account's next sign-in",
                path.display()
            )
        }))
        .expect("a record");

    // Each process, by the identity it was started under. A process whose identifier another
    // account's process holds now cannot be read, and is not read as ended.
    let mut left = Vec::new();
    let mut unread = Vec::new();
    for entry in record["processes"].as_array().expect("processes") {
        let identity: kr_protocol::identity::ProcessStartIdentity =
            serde_json::from_value(entry["identity"].clone()).expect("an identity");
        let what = format!(
            "{} (process {})",
            entry["what"].as_str().expect("a name"),
            identity.pid.get()
        );
        match kr_ipc::identity::process_state(&identity) {
            kr_ipc::identity::ProcessState::Ended => {
                eprintln!("after the sign-out: {what} is ended")
            }
            kr_ipc::identity::ProcessState::Running => left.push(what),
            kr_ipc::identity::ProcessState::Unknown { detail } => {
                unread.push(format!("{what}: {detail}"));
            }
        }
    }
    assert!(
        left.is_empty(),
        "the sign-out left these running: {}",
        left.join(", ")
    );
    assert!(
        unread.is_empty(),
        "these could not be read as ended or running: {}",
        unread.join(", ")
    );

    // The product has started nothing as this account, in this login session or any other.
    let before = record["session"].as_u64().expect("a session");
    let now = kr_ipc::starter::current_session().expect("this process's login session");
    assert_eq!(
        product_programs_of_this_account(),
        Vec::<String>::new(),
        "programs of the product run as this account after the sign-out and the sign-in"
    );
    eprintln!(
        "after the sign-out: in login session {now} (the session that was signed out was {before}) \
         and in every other, no program of the product runs as this account"
    );

    // The entry is still registered, exactly as it was.
    let name = record["task"].as_str().expect("a task");
    let exported = exported_task(name).unwrap_or_else(|| panic!("the entry {name} is gone"));
    assert_eq!(
        exported,
        record["entry"].as_str().expect("an entry"),
        "the entry changed with the sign-out"
    );
    assert_the_entry_is_as_documented(&exported);
    eprintln!("after the sign-out: the entry {name} is registered, as it was and as documented");

    // What the first half left in the account's temporary directory goes, the entry with it.
    let removed = Command::new(system32("schtasks.exe"))
        .args(["/Delete", "/TN", name, "/F"])
        .status()
        .expect("schtasks runs");
    assert!(removed.success(), "the entry {name} is removed: {removed}");
    for directory in record["directories"].as_array().expect("directories") {
        let _ = std::fs::remove_dir_all(directory.as_str().expect("a directory"));
    }
    std::fs::remove_file(&path).expect("the record is removed");
}
