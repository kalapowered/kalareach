//! `kr shell`: the setup that puts the managed integration in reach, and the diagnostics that say
//! what it resolved to.
//!
//! Three operations, and all three are honest about what they touch. `status` writes nothing.
//! `install` adds one marked entry per shell to the file that shell actually reads, beside whatever
//! the user already has there. `remove` deletes exactly those lines. Nothing replaces `.bashrc`,
//! points a shell at another `ZDOTDIR`, substitutes an `--rcfile` or disables a profile, and the
//! entry itself is inert in every shell KalaReach did not start.

use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::host::package::{
    PACKAGE_ROOT_VARIABLE, PackageSet, ShellPackage, default_package_root,
};
use kr_shell_integration::host::startup::{self, Change, HomeLayout};
use serde_json::{Value, json};

use crate::error::{CliError, Result};

/// What one shell's integration is, as `kr shell status` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShellReport {
    /// Which managed shell this is.
    pub kind: ShellKind,
    /// The executable a managed session would launch.
    pub executable: String,
    /// The flags that package declares an interactive root shell is launched with.
    pub flags: Vec<String>,
    /// The upstream shell version the package was built from.
    pub version: String,
    /// The editor ABI its reader patch was built against.
    pub editor_abi: String,
    /// The integration version of the package.
    pub integration_version: String,
    /// Where its guarded entry goes, and whether it is there.
    pub entries: Vec<EntryReport>,
}

/// One startup file, and what is in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntryReport {
    /// The file.
    pub path: String,
    /// Why this file rather than another.
    pub reason: &'static str,
    /// Whether the marked entry is there now.
    pub installed: bool,
    /// What an operation did to it.
    pub change: Option<Change>,
}

/// Reads the packages this installation has.
///
/// # Errors
///
/// Returns a configuration failure when a package's manifest cannot be read.
pub fn packages() -> Result<PackageSet> {
    PackageSet::installed(&default_package_root())
        .map_err(|fault| CliError::ShellIntegrationUnsupported(fault.to_string()))
}

/// Returns the packages one selector names.
///
/// # Errors
///
/// Returns a usage failure when the selector names a shell KalaReach does not qualify, and a
/// configuration failure when this installation has no package for it.
pub fn selected<'a>(set: &'a PackageSet, shell: Option<&str>) -> Result<Vec<&'a ShellPackage>> {
    let Some(requested) = shell else {
        return Ok(set.packages().iter().collect());
    };
    let kind = ShellKind::ALL
        .iter()
        .copied()
        .find(|kind| kind.as_str() == requested)
        .ok_or_else(|| {
            CliError::Usage(format!(
                "{requested} is not a shell KalaReach qualifies; it qualifies zsh, bash, fish and powershell"
            ))
        })?;
    set.get(kind).map(|package| vec![package]).ok_or_else(|| {
        CliError::ShellIntegrationUnsupported(format!(
            "this installation has no qualified {requested} package"
        ))
    })
}

/// Reports one package without changing anything.
#[must_use]
pub fn report(package: &ShellPackage, layout: &HomeLayout) -> ShellReport {
    ShellReport {
        executable: package.executable().display().to_string(),
        flags: package.interactive_flags(),
        version: package.manifest.upstream_version.clone(),
        editor_abi: package.manifest.editor_abi.clone(),
        integration_version: package.manifest.integration_version.clone(),
        ..entries_only(package.manifest.shell, layout)
    }
}

/// Reports where one shell's entries go, with nothing a package would have said about it.
///
/// What is left blank is exactly what an installed package answers: which executable a session
/// would launch and what it was built from. An operation that needs none of that says so by
/// leaving them empty rather than by inventing them.
fn entries_only(kind: ShellKind, layout: &HomeLayout) -> ShellReport {
    let entries = layout
        .targets(kind)
        .into_iter()
        .map(|target| EntryReport {
            installed: startup::installed(&target.path),
            path: target.path.display().to_string(),
            reason: target.reason,
            change: None,
        })
        .collect();
    ShellReport {
        kind,
        executable: String::new(),
        flags: Vec::new(),
        version: String::new(),
        editor_abi: String::new(),
        integration_version: String::new(),
        entries,
    }
}

/// Adds one package's guarded entry to every file that shell reads.
///
/// # Errors
///
/// Returns a resource failure when a startup file cannot be read or written.
pub fn install(
    package: &ShellPackage,
    layout: &HomeLayout,
    nsh_bypass: bool,
    dry_run: bool,
) -> Result<ShellReport> {
    let body = startup::entry(package.manifest.shell, &package.startup_entry(), nsh_bypass);
    let mut reported = report(package, layout);
    for entry in &mut reported.entries {
        let path = std::path::Path::new(&entry.path);
        let change = if dry_run {
            if startup::installed(path) {
                Change::Unchanged
            } else {
                Change::Added
            }
        } else {
            startup::install(path, &body)
                .map_err(|error| CliError::Other(format!("{}: {error}", entry.path)))?
        };
        entry.change = Some(change);
        // A dry run reports what is there; a real one reports what it just wrote.
        entry.installed = if dry_run {
            startup::installed(path)
        } else {
            true
        };
    }
    Ok(reported)
}

/// Returns the shells a selector names, for an operation that needs no package.
///
/// Every shell KalaReach qualifies, or the one the selector names. The set of installed packages
/// says nothing here: a marked entry is in a file whether or not the package it points at is still
/// there, and an entry that outlived its package is exactly the one a person needs to remove.
///
/// # Errors
///
/// Returns a usage failure when the selector names a shell KalaReach does not qualify.
pub fn shells(selector: Option<&str>) -> Result<Vec<ShellKind>> {
    let Some(requested) = selector else {
        return Ok(ShellKind::ALL.to_vec());
    };
    ShellKind::ALL
        .iter()
        .copied()
        .find(|kind| kind.as_str() == requested)
        .map(|kind| vec![kind])
        .ok_or_else(|| {
            CliError::Usage(format!(
                "{requested} is not a shell KalaReach qualifies; it qualifies zsh, bash, fish and powershell"
            ))
        })
}

/// Deletes one shell's guarded entry, and nothing else.
///
/// It takes the shell rather than the package, because removal needs neither the executable nor the
/// manifest: the markers say what to take out, and a person whose package was uninstalled or whose
/// manifest no longer parses still has entries to remove.
///
/// # Errors
///
/// Returns a resource failure when a startup file cannot be read or written.
pub fn remove(kind: ShellKind, layout: &HomeLayout, dry_run: bool) -> Result<ShellReport> {
    let mut reported = entries_only(kind, layout);
    for entry in &mut reported.entries {
        let path = std::path::Path::new(&entry.path);
        let change = if dry_run {
            if startup::installed(path) {
                Change::Removed
            } else {
                Change::Absent
            }
        } else {
            startup::remove(path)
                .map_err(|error| CliError::Other(format!("{}: {error}", entry.path)))?
        };
        entry.change = Some(change);
        entry.installed = if dry_run {
            startup::installed(path)
        } else {
            false
        };
    }
    Ok(reported)
}

/// Renders one report for a script.
#[must_use]
pub fn to_json(reports: &[ShellReport]) -> Value {
    json!({
        "ok": true,
        "package_root_variable": PACKAGE_ROOT_VARIABLE,
        "shells": reports
            .iter()
            .map(|report| json!({
                "shell": report.kind.as_str(),
                "executable": report.executable,
                "flags": report.flags,
                "version": report.version,
                "editor_abi": report.editor_abi,
                "integration_version": report.integration_version,
                "integration_mode": "managed",
                "entries": report
                    .entries
                    .iter()
                    .map(|entry| json!({
                        "path": entry.path,
                        "reason": entry.reason,
                        "installed": entry.installed,
                        "change": entry.change.map(change_name),
                    }))
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
    })
}

/// Prints one report for a person.
pub fn print(reports: &[ShellReport]) {
    if reports.is_empty() {
        println!(
            "no qualified shell packages are installed; set {PACKAGE_ROOT_VARIABLE} to a directory that holds one"
        );
        return;
    }
    for report in reports {
        println!(
            "{} {}: {} ({}), editor ABI {}, integration {}, mode managed",
            report.kind,
            report.version,
            report.executable,
            if report.flags.is_empty() {
                "no flags".to_owned()
            } else {
                report.flags.join(" ")
            },
            report.editor_abi,
            report.integration_version,
        );
        for entry in &report.entries {
            let state = entry.change.map_or_else(
                || {
                    if entry.installed {
                        "installed".to_owned()
                    } else {
                        "not installed".to_owned()
                    }
                },
                |change| change_name(change).to_owned(),
            );
            println!("  {}: {state} ({})", entry.path, entry.reason);
        }
    }
}

/// Returns the stable word for one change.
#[must_use]
pub const fn change_name(change: Change) -> &'static str {
    match change {
        Change::Added => "added",
        Change::Replaced => "replaced",
        Change::Unchanged => "unchanged",
        Change::Removed => "removed",
        Change::Absent => "absent",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_change_has_a_stable_word() {
        let words: Vec<&str> = [
            Change::Added,
            Change::Replaced,
            Change::Unchanged,
            Change::Removed,
            Change::Absent,
        ]
        .into_iter()
        .map(change_name)
        .collect();
        assert_eq!(
            words,
            vec!["added", "replaced", "unchanged", "removed", "absent"]
        );
    }

    #[test]
    fn a_shell_kalareach_does_not_qualify_is_a_usage_failure() {
        let set = PackageSet::default();
        let error = selected(&set, Some("ksh")).expect_err("refused");
        assert!(matches!(error, CliError::Usage(_)), "{error}");
        let error = selected(&set, Some("zsh")).expect_err("refused");
        assert!(
            matches!(error, CliError::ShellIntegrationUnsupported(_)),
            "{error}"
        );
        assert!(selected(&set, None).expect("every package").is_empty());
    }

    #[test]
    fn an_entry_is_removed_from_an_installation_that_has_no_package_left() {
        // Removal takes out the lines it put in. A person whose package was uninstalled, or whose
        // manifest no longer reads, still has those lines in their own configuration, and they are
        // exactly the ones they are trying to be rid of.
        let home = tempfile::tempdir().expect("a directory");
        let layout = HomeLayout {
            home: home.path().to_path_buf(),
            zdotdir: None,
            xdg_config_home: None,
        };
        let theirs = "export EDITOR=vim\n";
        let zshrc = home.path().join(".zshrc");
        std::fs::write(&zshrc, theirs).expect("writes");
        let body = startup::entry(
            ShellKind::Zsh,
            std::path::Path::new("/gone/entry.zsh"),
            false,
        );
        assert_eq!(
            startup::install(&zshrc, &body).expect("installs"),
            Change::Added
        );

        // No package set is consulted, and none exists.
        assert_eq!(shells(Some("zsh")).expect("a shell"), vec![ShellKind::Zsh]);
        assert_eq!(
            shells(None).expect("every shell").len(),
            ShellKind::ALL.len()
        );
        let report = remove(ShellKind::Zsh, &layout, false).expect("removes");
        assert_eq!(report.kind, ShellKind::Zsh);
        assert!(
            report
                .entries
                .iter()
                .any(|entry| entry.change == Some(Change::Removed)),
            "{report:?}"
        );
        assert_eq!(std::fs::read_to_string(&zshrc).expect("reads"), theirs);
        assert!(!startup::installed(&zshrc));

        // And a selector KalaReach does not qualify is still a usage failure.
        assert!(matches!(
            shells(Some("ksh")).expect_err("refused"),
            CliError::Usage(_)
        ));
    }
}
