//! The PSReadLine package as a Windows host publishes it, reads it and starts its shell.
//!
//! `pwsh_windows.rs` proves the transport under the module with the editor out of the picture.
//! This is the part before it: a host that has PowerShell 7 publishes the package into a cache of
//! its own, the host reads that package as a worker does, and the shell a session would start is
//! the host the package qualified, with the package's module found by name and agreeing with what
//! the worker expects of it. Nothing here writes outside a temporary directory, and no profile is
//! read or written.

#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::transport::{ModuleEntry, ShellIdentity};
use kr_shell_integration::host::package::{PackageSet, ShellPackage};

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

/// What the module in the shell a session would start says about itself, as the worker would be
/// told it, and the path the module was imported from.
///
/// The shell is started the way a session starts it: the package's executable, with what the
/// package's launch sets over the environment `base` stands for.
fn the_module_in(package: &ShellPackage, base: &[(String, String)]) -> (ShellIdentity, String) {
    let script = "Import-Module KalaReach.ShellBridge; \
                  $module = Get-Module KalaReach.ShellBridge; \
                  'kr-base=' + $module.ModuleBase; \
                  'kr-identity=' + ((& $module { Get-KrPackageIdentity }) | ConvertTo-Json -Depth 6 -Compress)";
    let launch = package.launch_environment(base, true);
    let mut command = Command::new(package.executable());
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .env_remove("KR_SHELL_BRIDGE")
        .env_remove("KR_SHELL_BRIDGE_SECRET")
        .env_remove("KR_SESSION");
    for (name, value) in base {
        command.env(name, value);
    }
    for (name, value) in launch {
        command.env(name, value);
    }
    let asked = command.output().expect("the package's host starts");
    let said = String::from_utf8_lossy(&asked.stdout).into_owned();
    assert!(
        asked.status.success(),
        "the package's host ended {:?}:\n{said}\n{}",
        asked.status,
        String::from_utf8_lossy(&asked.stderr)
    );
    let line = |prefix: &str| {
        said.lines()
            .find_map(|line| line.strip_prefix(prefix))
            .unwrap_or_else(|| panic!("the host said no {prefix}:\n{said}"))
            .trim()
            .to_owned()
    };
    let identity: serde_json::Value =
        serde_json::from_str(&line("kr-identity=")).expect("the module's identity is JSON");
    let text = |value: &serde_json::Value| value.as_str().expect("text").to_owned();
    let modules = identity["modules"]
        .as_array()
        .expect("the module tree")
        .iter()
        .map(|module| ModuleEntry {
            name: text(&module["name"]),
            search_path: text(&module["search_path"]),
            editor_abi: text(&module["editor_abi"]),
        })
        .collect();
    (
        ShellIdentity {
            kind: ShellKind::PowerShell,
            executable: text(&identity["executable"]),
            upstream_version: text(&identity["upstream_version"]),
            editor_abi: text(&identity["editor_abi"]),
            integration_version: text(&identity["integration_version"]),
            patches: Vec::new(),
            modules,
        },
        line("kr-base="),
    )
}

/// The environment of this process, as a session's builder would hand it on.
fn this_environment() -> Vec<(String, String)> {
    std::env::vars().collect()
}

fn same_place(left: &str, right: &Path) -> bool {
    left.trim_end_matches(['\\', '/'])
        .eq_ignore_ascii_case(right.to_string_lossy().trim_end_matches(['\\', '/']))
}

/// A host publishes the package, reads it as a worker does, and the shell a session would start
/// is the host the package qualified: its module is found by name from the package, even with a
/// module of the same name first on the module path, and what the module says of itself agrees
/// with what the worker expects of the package.
#[test]
fn the_package_a_windows_host_publishes_is_the_shell_a_session_would_start() {
    let prefix = tempfile::tempdir().expect("a directory");
    let directory = publish(prefix.path());

    let set = PackageSet::discover(prefix.path()).expect("the host reads the package");
    let package = set
        .select(None)
        .expect("a default session finds the package");
    assert_eq!(package.kind(), ShellKind::PowerShell);
    assert!(
        package.executable().is_absolute() && package.executable().is_file(),
        "the package names an absolute path to the host: {}",
        package.executable().display()
    );
    assert!(
        !package.executable().starts_with(&directory),
        "and the host is not a copy inside the package"
    );

    // A module of the same name first on the person's own module path.
    let competing = tempfile::tempdir().expect("a directory");
    let beside = competing.path().join("KalaReach.ShellBridge");
    std::fs::create_dir_all(&beside).expect("a directory for the competing module");
    for entry in std::fs::read_dir(module_directory())
        .expect("the module")
        .flatten()
    {
        std::fs::copy(entry.path(), beside.join(entry.file_name())).expect("a file of the module");
    }
    let mut base = this_environment();
    base.retain(|(name, _)| !name.eq_ignore_ascii_case("PSModulePath"));
    base.push((
        "PSModulePath".to_owned(),
        competing.path().display().to_string(),
    ));

    let (identity, imported_from) = the_module_in(&package, &base);
    assert!(
        same_place(
            &imported_from,
            &directory.join("modules").join("KalaReach.ShellBridge")
        ),
        "the module a session imports is the package's own: {imported_from}"
    );
    assert_eq!(
        package.declaration().disagreement(&identity),
        None,
        "the module in the shell agrees with what the worker expects of the package"
    );
    assert_eq!(
        identity.executable,
        package.declaration().executable,
        "the process reports the path the package names, spelt as the worker would start it"
    );
}

/// The package is moved with the directory it was published in gone, and a session still starts its
/// own module, which states the record it was published with.
#[test]
fn a_package_that_is_moved_starts_its_own_module_on_windows() {
    let prefix = tempfile::tempdir().expect("a directory");
    let published = publish(prefix.path());
    let moved = tempfile::tempdir().expect("a directory");
    let identity_name = published.file_name().expect("an identity").to_owned();
    let package_directory = moved.path().join("powershell").join(&identity_name);
    copy_tree(&published, &package_directory);
    std::fs::write(
        moved.path().join("powershell").join("current"),
        identity_name.to_string_lossy().as_bytes(),
    )
    .expect("names the identity");
    drop(prefix);
    assert!(!published.exists(), "the place it was published in is gone");

    let package = PackageSet::discover(moved.path())
        .expect("the host reads the moved package")
        .select(None)
        .expect("a default session finds it")
        .clone();
    let (identity, imported_from) = the_module_in(&package, &this_environment());
    assert!(
        same_place(
            &imported_from,
            &package_directory
                .join("modules")
                .join("KalaReach.ShellBridge")
        ),
        "the module a session imports is the moved package's own: {imported_from}"
    );
    assert_eq!(package.declaration().disagreement(&identity), None);
}

/// A Microsoft Store build of PowerShell is installed under `WindowsApps`, whose programs an account
/// does not start by their path, so no package is published for one, and the refusal says why and
/// what to do instead.
#[test]
fn a_store_build_of_powershell_is_refused_by_name_with_its_reason() {
    let module = module_directory().join("KalaReach.ShellBridge.psd1");
    let asked = Command::new("pwsh.exe")
        .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"])
        .arg(format!(
            "Import-Module '{}'; $module = Get-Module KalaReach.ShellBridge; \
             $answer = & $module {{ Test-KrHostCanBeStarted \
             'C:\\Program Files\\WindowsApps\\Microsoft.PowerShell_7.5.0.0_x64__8wekyb3d8bbwe\\pwsh.exe' }}; \
             'kr-reason=' + $answer.Reason; 'kr-detail=' + $answer.Detail",
            module.display()
        ))
        .output()
        .expect("PowerShell 7 starts");
    let said = String::from_utf8_lossy(&asked.stdout);
    assert!(said.contains("kr-reason=powershell_store_build"), "{said}");
    assert!(
        said.contains("WindowsApps"),
        "the refusal says where the program is: {said}"
    );
    assert!(
        said.contains("--shell-mode native_compat"),
        "and what a session can use instead: {said}"
    );
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory for the copy");
    for entry in std::fs::read_dir(from)
        .expect("a directory to copy")
        .flatten()
    {
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).expect("a file to copy");
        }
    }
}
