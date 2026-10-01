//! `kr shell`: the setup that puts the managed integration in reach, and the diagnostics that say
//! what it resolved to.
//!
//! Three operations, and all three are honest about what they touch. `status` writes nothing.
//! `install` adds one marked entry per shell to the file that shell actually reads, beside whatever
//! the user already has there, and records each file it writes to. `remove` deletes exactly those
//! lines from exactly the files the record names. Nothing replaces `.bashrc`, points a shell at
//! another `ZDOTDIR`, substitutes an `--rcfile` or disables a profile, and the entry itself is
//! inert in every shell KalaReach did not start.
//!
//! A file is read and written by its exact name throughout, and the text a report shows for it is
//! never read back as a path.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::host::package::{
    PACKAGE_ROOT_VARIABLE, PackageSet, ShellPackage, default_package_root,
};
use kr_shell_integration::host::startup::{self, Change, EntryRecord, HomeLayout, RecordError};

use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Line, Request};
use crate::stdout_line;

/// What one shell's integration is, as `kr shell status` reports it.
#[derive(Clone, PartialEq, Eq)]
pub struct ShellReport {
    /// Which managed shell this is.
    pub kind: ShellKind,
    /// What the installed package says, when this operation resolved one.
    ///
    /// Removal resolves none: it takes out the lines it put in, which are in the file whether or
    /// not a package is still installed. A report with none says so rather than printing blanks
    /// that read like answers.
    pub package: Option<PackageReport>,
    /// Where its guarded entry goes, and whether it is there.
    pub entries: Vec<EntryReport>,
}

kr_client::debug_fields!(ShellReport { kind });

/// What the installed package for one shell resolved to.
#[derive(Clone, PartialEq, Eq)]
pub struct PackageReport {
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
}

/// One startup file, and what is in it.
#[derive(Clone, PartialEq, Eq)]
pub struct EntryReport {
    /// The file, by its exact name: what every read and write of it uses.
    pub file: std::path::PathBuf,
    /// The file, as a report shows it. It is never read back as a path: a name that is not text
    /// shows here with a replacement character in it, and that is another file's name.
    pub path: String,
    /// Why this file rather than another.
    pub reason: &'static str,
    /// Whether the marked entry is there now.
    pub installed: bool,
    /// What an operation did to it.
    pub change: Option<Change>,
}

/// The store this kr is a release of, where it is one.
fn installed_store() -> Option<kr_ipc::install::Store> {
    kr_ipc::install::this_process()
        .ok()
        .and_then(kr_ipc::install::Running::store)
        .cloned()
}

/// Reads the packages this installation has.
///
/// A kr of an installed release reads the current release's packages, through the store's
/// `current`: those are the packages a new session is started with, whichever release this kr
/// is. Anywhere else, the packages the build writes, or those [`PACKAGE_ROOT_VARIABLE`] names.
///
/// # Errors
///
/// Returns a configuration failure when a package's manifest cannot be read.
pub fn packages() -> Result<PackageSet> {
    if let Some(store) = installed_store() {
        let root = store.stable_shells();
        return PackageSet::discover(&root).map_err(|fault| {
            CliError::ShellIntegrationUnsupported(crate::shown::package_fault(&fault, &root))
        });
    }
    let default = default_package_root();
    PackageSet::installed(&default).map_err(|fault| {
        // The root the package set read, as it chose it: the variable when it is set.
        let root =
            std::env::var_os(PACKAGE_ROOT_VARIABLE).map_or(default, std::path::PathBuf::from);
        CliError::ShellIntegrationUnsupported(crate::shown::package_fault(&fault, &root))
    })
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
            CliError::Usage(Shown::said(
                "the shell given is not one KalaReach qualifies; it qualifies zsh, bash, fish and \
                 powershell",
            ))
        })?;
    set.get(kind).map(|package| vec![package]).ok_or_else(|| {
        CliError::ShellIntegrationUnsupported(shown!(
            "this installation has no qualified {} package",
            kind.as_str()
        ))
    })
}

/// The file a startup entry sources on a host installed as a store of releases: the shell's
/// entry in the current release, `current/shells/<shell>/<entry>`, by the name the package gives
/// its own entry. `None` anywhere else, where the entry sources the package's own file.
///
/// The file only calls the running shell's own bridge builtin, so a shell of any release the host
/// keeps reads it: a shell of the release a session started from runs its own release's
/// integration, and an entry written once keeps working across every update, since `current`
/// follows the update and the file stays where the entry names it.
///
/// # Errors
///
/// Returns a configuration failure when the current release has no such file, which would leave
/// the entry sourcing nothing.
fn stable_entry(package: &ShellPackage) -> Result<Option<std::path::PathBuf>> {
    let Some(store) = installed_store() else {
        return Ok(None);
    };
    let own = package.startup_entry();
    let Some(name) = own.file_name() else {
        return Ok(None);
    };
    let stable = store
        .stable_shells()
        .join(package.kind().as_str())
        .join(name);
    if !stable.is_file() {
        return Err(CliError::ShellIntegrationUnsupported(shown!(
            "the current release has no {} startup entry at {}, which the startup file of an \
             installed host sources",
            package.kind().as_str(),
            Shown::root(&stable)
        )));
    }
    Ok(Some(stable))
}

/// Reports one package without changing anything.
#[must_use]
pub fn report(package: &ShellPackage, layout: &HomeLayout) -> ShellReport {
    ShellReport {
        package: Some(PackageReport {
            executable: package.executable().display().to_string(),
            flags: package.interactive_flags(),
            version: package.manifest.shell.upstream_version.clone(),
            editor_abi: package.manifest.shell.editor_abi.clone(),
            integration_version: package.manifest.shell.integration_version.clone(),
        }),
        ..entries_only(package.kind(), layout)
    }
}

/// Reports where one shell's entries go, with nothing a package would have said about it.
///
/// What is left out is exactly what an installed package answers: which executable a session would
/// launch and what it was built from. An operation that needs none of that says so rather than
/// printing a blank where an answer belongs.
fn entries_only(kind: ShellKind, layout: &HomeLayout) -> ShellReport {
    let entries = layout
        .targets(kind)
        .into_iter()
        .map(|target| EntryReport {
            installed: startup::installed(&target.path),
            path: target.path.display().to_string(),
            file: target.path,
            reason: target.reason,
            change: None,
        })
        .collect();
    ShellReport {
        kind,
        package: None,
        entries,
    }
}

/// Adds one package's guarded entry to every file that shell reads, and records each of them.
///
/// Every entry is made before any file is touched, so an entry that cannot be made leaves every
/// startup file as it was. The files are recorded before any of them is written, so a file an
/// install that stopped part way wrote into is one the removal knows; a file recorded and never
/// written is one the removal finds nothing in.
///
/// # Errors
///
/// Returns a usage failure naming the package's entry when that path is not text, which no startup
/// file can name, and a resource failure when the record or a startup file cannot be read or
/// written.
pub fn install(
    package: &ShellPackage,
    layout: &HomeLayout,
    record: &EntryRecord,
    nsh_bypass: bool,
    dry_run: bool,
) -> Result<ShellReport> {
    let package_entry = stable_entry(package)?.unwrap_or_else(|| package.startup_entry());
    // The entry each file gets is the entry for that file: `.profile` is read by shells that are
    // not this one, and its entry says so.
    let bodies = layout
        .targets(package.kind())
        .into_iter()
        .map(|target| {
            startup::entry(&target, &package_entry, nsh_bypass)
                .map(|body| (target.path, body, target.placement))
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|refused| {
            CliError::Usage(shown!(
                "{} cannot be written into a shell's startup file: it is not UTF-8",
                Shown::root(&refused.path)
            ))
        })?;
    let mut reported = report(package, layout);
    // Held from before the first file is recorded until the last entry is written, so a removal
    // run at the same time waits for the whole install rather than reading the record part way
    // through it. A dry run writes nothing and holds nothing.
    let held = if dry_run {
        None
    } else {
        let held = record
            .hold()
            .map_err(|error| record_failure(record, &error))?;
        let files = bodies
            .iter()
            .map(|(file, _, _)| file.clone())
            .collect::<Vec<_>>();
        held.add(package.kind(), &files)
            .map_err(|error| record_failure(record, &error))?;
        Some(held)
    };
    for entry in &mut reported.entries {
        let Some((_, body, placement)) = bodies.iter().find(|(file, _, _)| *file == entry.file)
        else {
            continue;
        };
        let io_failure = |error: std::io::Error| {
            CliError::Other(shown!(
                "{}: {}",
                Shown::root(&entry.file),
                Shown::io(&error)
            ))
        };
        let change = if dry_run {
            startup::plan(&entry.file, body, placement).map_err(io_failure)?
        } else {
            startup::install(&entry.file, body, placement, record).map_err(io_failure)?
        };
        entry.change = Some(change);
        // A dry run reports what is there; a real one reports what it just wrote.
        entry.installed = if dry_run {
            startup::installed(&entry.file)
        } else {
            true
        };
    }
    drop(held);
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
            CliError::Usage(Shown::said(
                "the shell given is not one KalaReach qualifies; it qualifies zsh, bash, fish and \
                 powershell",
            ))
        })
}

/// Why a file the record names is in a removal's report when the layout names it no more.
const RECORDED: &str = "a file kr shell install recorded writing this entry to";

/// Why a file holding an entry the record does not name is in a removal's report.
const UNRECORDED: &str = "an entry kr shell install has no record of writing, which removal leaves";

/// Deletes one shell's guarded entry from each file `kr shell install` recorded writing it to, and
/// nothing else.
///
/// It works from the record alone: from the files an install wrote, by their exact names, and not
/// from where the entry would go now, which moves when a `ZDOTDIR` is set or unset or a login file
/// is created. A file the record does not name is left as it is, and one that holds a marked entry
/// all the same is reported as left. Each file is taken out of the record once its entry is gone,
/// and the record is held for the whole removal, so an install run at the same time waits for it.
/// A dry run reads the record as it is and changes nothing.
///
/// It takes the shell rather than the package, because removal needs neither the executable nor the
/// manifest: the record says where to look and the markers say what to take out, and a person whose
/// package was uninstalled or whose manifest no longer parses still has entries to remove.
///
/// # Errors
///
/// Returns a resource failure when the record or a startup file cannot be read or written.
pub fn remove(
    kind: ShellKind,
    layout: &HomeLayout,
    record: &EntryRecord,
    dry_run: bool,
) -> Result<ShellReport> {
    let targets = layout.targets(kind);
    let held = if dry_run {
        None
    } else {
        Some(
            record
                .hold()
                .map_err(|error| record_failure(record, &error))?,
        )
    };
    let recorded = held
        .as_ref()
        .map_or_else(|| record.files(kind), |held| held.files(kind))
        .map_err(|error| record_failure(record, &error))?;
    let mut entries = Vec::new();
    for file in recorded {
        let reason = targets
            .iter()
            .find(|target| target.path == file)
            .map_or(RECORDED, |target| target.reason);
        let change = match &held {
            None => {
                if startup::installed(&file) {
                    Change::Removed
                } else {
                    Change::Absent
                }
            }
            Some(held) => {
                let change = startup::remove(&file, record).map_err(|error| {
                    CliError::Other(shown!("{}: {}", Shown::root(&file), Shown::io(&error)))
                })?;
                held.forget(kind, &file)
                    .map_err(|error| record_failure(record, &error))?;
                change
            }
        };
        entries.push(EntryReport {
            installed: dry_run && startup::installed(&file),
            path: file.display().to_string(),
            file,
            reason,
            change: Some(change),
        });
    }
    drop(held);
    for target in targets {
        if !entries.iter().any(|entry| entry.file == target.path)
            && startup::installed(&target.path)
        {
            entries.push(EntryReport {
                installed: true,
                path: target.path.display().to_string(),
                file: target.path,
                reason: UNRECORDED,
                change: None,
            });
        }
    }
    Ok(ShellReport {
        kind,
        package: None,
        entries,
    })
}

/// What a failure of the record says: where it is, and what to do about one that is not a record.
fn record_failure(record: &EntryRecord, error: &RecordError) -> CliError {
    match error {
        RecordError::Store(error) => CliError::Other(shown!(
            "the record of the startup entries kr shell install wrote, {}: {}",
            Shown::root(record.path()),
            Shown::ipc(error)
        )),
        RecordError::NotARecord => CliError::Other(shown!(
            "{} is not a record of startup entries this build reads; move it aside, and kr shell \
             install records the entries it writes again",
            Shown::root(record.path())
        )),
    }
}

/// Renders one report for a script: the files and what the package resolved to are the shell's own,
/// shown to the person who asked about it.
#[must_use]
pub fn document(reports: &[ShellReport]) -> Document {
    let asked = |text: &str| Asked::text(Request::ShellFiles, text);
    Document::new()
        .with("ok", true)
        .with("package_root_variable", PACKAGE_ROOT_VARIABLE)
        .with(
            "shells",
            reports
                .iter()
                .map(|report| {
                    let package = report.package.as_ref();
                    Document::new()
                        .with("shell", report.kind.as_str())
                        // Null rather than empty where no package was resolved: a reader can tell
                        // "this operation did not ask" from "the package says nothing".
                        .with(
                            "executable",
                            package.map(|package| {
                                Asked::path(Request::ShellFiles, &package.executable)
                            }),
                        )
                        .with(
                            "flags",
                            package.map(|package| {
                                package
                                    .flags
                                    .iter()
                                    .map(|flag| asked(flag))
                                    .collect::<Vec<_>>()
                            }),
                        )
                        .with("version", package.map(|package| asked(&package.version)))
                        .with(
                            "editor_abi",
                            package.map(|package| asked(&package.editor_abi)),
                        )
                        .with(
                            "integration_version",
                            package.map(|package| asked(&package.integration_version)),
                        )
                        .with("integration_mode", package.map(|_| "managed"))
                        .with(
                            "entries",
                            report
                                .entries
                                .iter()
                                .map(|entry| {
                                    Document::new()
                                        .with("path", Asked::path(Request::ShellFiles, &entry.path))
                                        .with("reason", entry.reason)
                                        .with("installed", entry.installed)
                                        .with("change", entry.change.map(change_name))
                                })
                                .collect::<Vec<_>>(),
                        )
                })
                .collect::<Vec<_>>(),
        )
}

/// Prints one report for a person.
pub fn print(reports: &[ShellReport]) {
    output::lines(&lines(reports));
}

/// One report as lines for a person: the files and what the package resolved to are the shell's
/// own, shown to the person who asked about it.
#[must_use]
pub fn lines(reports: &[ShellReport]) -> Vec<Line> {
    if reports.is_empty() {
        return vec![stdout_line!(
            "no qualified shell packages are installed; set {} to a directory that holds one",
            PACKAGE_ROOT_VARIABLE
        )];
    }
    let asked = |text: &str| Asked::text(Request::ShellFiles, text);
    let mut lines = Vec::new();
    for report in reports {
        match &report.package {
            Some(package) => lines.push(stdout_line!(
                "{} {}: {} ({}), editor ABI {}, integration {}, mode managed",
                report.kind.as_str(),
                asked(&package.version),
                Asked::path(Request::ShellFiles, &package.executable),
                if package.flags.is_empty() {
                    asked("no flags")
                } else {
                    asked(&package.flags.join(" "))
                },
                asked(&package.editor_abi),
                asked(&package.integration_version),
            )),
            None => lines.push(stdout_line!("{}", report.kind.as_str())),
        }
        for entry in &report.entries {
            let state = entry.change.map_or(
                if entry.installed {
                    "installed"
                } else {
                    "not installed"
                },
                change_name,
            );
            lines.push(stdout_line!(
                "  {}: {} ({})",
                Asked::path(Request::ShellFiles, &entry.path),
                state,
                entry.reason
            ));
        }
    }
    lines
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
    use crate::output::planted::{only_asked, only_asked_lines, planted_text};
    use crate::shown::marker::MARKER;
    use kr_shell_integration::host::startup::Placement;

    /// KR-REQ-23.25: text planted in every field a shell's report holds shows only where the person
    /// asked for it, which is every one of them: the package's executable, flags, version, editor
    /// ABI and integration version, and each startup file.
    #[test]
    fn planted_text_in_a_shell_report_shows_only_where_it_was_asked_for() {
        let planted = planted_text();
        let reports = [ShellKind::Zsh, ShellKind::Bash, ShellKind::Fish]
            .into_iter()
            .map(|kind| ShellReport {
                kind,
                package: Some(PackageReport {
                    executable: format!("/{planted}/bin/shell"),
                    flags: vec![planted.clone(), planted.clone()],
                    version: planted.clone(),
                    editor_abi: planted.clone(),
                    integration_version: planted.clone(),
                }),
                entries: vec![EntryReport {
                    file: std::path::PathBuf::from(format!("/{planted}/.profile")),
                    path: format!("/{planted}/.profile"),
                    reason: "the file an interactive login reads",
                    installed: true,
                    change: Some(Change::Added),
                }],
            })
            .collect::<Vec<_>>();
        let shown = only_asked("kr shell status", &document(&reports));
        for asked in [
            "shells[].executable",
            "shells[].flags[]",
            "shells[].version",
            "shells[].editor_abi",
            "shells[].integration_version",
            "shells[].entries[].path",
        ] {
            assert!(
                shown.contains(asked),
                "{asked} shows what was asked for: {shown:?}"
            );
        }
        let said = lines(&reports);
        only_asked_lines("kr shell status", &said);
        assert!(said.iter().all(|line| line.text().contains(MARKER)));
    }

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
        let state = tempfile::tempdir().expect("a directory");
        let record = EntryRecord::in_state_directory(&state.path().join("state"));
        let layout = HomeLayout {
            home: home.path().to_path_buf(),
            zdotdir: None,
            xdg_config_home: None,
            powershell: None,
        };
        let theirs = "export EDITOR=vim\n";
        let zshrc = home.path().join(".zshrc");
        std::fs::write(&zshrc, theirs).expect("writes");
        let body = startup::entry(
            &layout.targets(ShellKind::Zsh)[0],
            std::path::Path::new("/gone/entry.zsh"),
            false,
        )
        .expect("the path is text");
        assert_eq!(
            startup::install(&zshrc, &body, &Placement::End, &record).expect("installs"),
            Change::Added
        );
        // The install that wrote it recorded the file.
        record
            .hold()
            .expect("holds")
            .add(ShellKind::Zsh, std::slice::from_ref(&zshrc))
            .expect("records");

        // No package set is consulted, and none exists.
        assert_eq!(shells(Some("zsh")).expect("a shell"), vec![ShellKind::Zsh]);
        assert_eq!(
            shells(None).expect("every shell").len(),
            ShellKind::ALL.len()
        );
        let report = remove(ShellKind::Zsh, &layout, &record, false).expect("removes");
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
        assert!(
            record.files(ShellKind::Zsh).expect("reads").is_empty(),
            "a file whose entry is gone is taken out of the record"
        );

        // And a selector KalaReach does not qualify is still a usage failure.
        assert!(matches!(
            shells(Some("ksh")).expect_err("refused"),
            CliError::Usage(_)
        ));
    }

    /// KR-REQ-07.29: a package whose entry is not text is refused by name, and no startup file
    /// changes.
    ///
    /// Unix, where a path is bytes and one of them can be a byte UTF-8 has no character for.
    #[cfg(unix)]
    #[test]
    fn a_package_whose_entry_is_not_text_is_refused_and_nothing_is_written() {
        use kr_shell_integration::host::package::{
            PackageManifest, PackageShell, PackageStartupEntry,
        };
        use std::os::unix::ffi::OsStrExt as _;

        let home = tempfile::tempdir().expect("a directory");
        let state = tempfile::tempdir().expect("a directory");
        let record = EntryRecord::in_state_directory(&state.path().join("state"));
        let layout = HomeLayout {
            home: home.path().to_path_buf(),
            zdotdir: None,
            xdg_config_home: None,
            powershell: None,
        };
        let theirs = "export EDITOR=vim\n";
        let zshrc = home.path().join(".zshrc");
        std::fs::write(&zshrc, theirs).expect("writes");
        // A package in a directory whose name is not text. Nothing is read from it, which is as
        // well: a file system that keeps its names as UTF-8 could not hold it.
        let directory =
            std::path::PathBuf::from(std::ffi::OsStr::from_bytes(b"/opt/kr\xff/zsh/identity-1"));
        let package = ShellPackage {
            manifest: PackageManifest {
                identity: "identity-1".to_owned(),
                shell: PackageShell {
                    kind: ShellKind::Zsh,
                    executable: directory.join("bin/zsh"),
                    upstream_version: "5.9".to_owned(),
                    editor_abi: "zle-5.9".to_owned(),
                    integration_version: "1".to_owned(),
                    patches: Vec::new(),
                    modules: Vec::new(),
                },
                startup_entry: PackageStartupEntry {
                    file: "startup/entry".to_owned(),
                },
            },
            directory,
        };
        for dry_run in [false, true] {
            let outcome = install(&package, &layout, &record, false, dry_run);
            assert_eq!(
                std::fs::read_to_string(&zshrc).expect("reads"),
                theirs,
                "no startup file changes (dry run: {dry_run})"
            );
            assert!(
                !record.path().exists(),
                "and nothing is recorded (dry run: {dry_run})"
            );
            let refused = outcome.expect_err("an entry that is not text is refused");
            assert!(matches!(refused, CliError::Usage(_)), "{refused}");
            let said = refused.to_string();
            assert!(
                said.contains("identity-1/startup/entry") && said.contains("not UTF-8"),
                "the refusal names the path and says why: {said}"
            );
        }
    }
}
