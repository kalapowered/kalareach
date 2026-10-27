//! Terminal.app: a profile is an entry of the `Window Settings` dictionary in its preferences,
//! copied from the profile the person has chosen as their default so that it looks as theirs does,
//! and given a command of its own.
//!
//! Terminal keeps its profiles in memory while it runs and rewrites its preferences when it ends,
//! so an outside write while it runs is not one anything is known to survive: install and remove
//! are refused while the person's own Terminal is running (the caller asks [`is_running`]), and the
//! person is told to run the command from another application.
//!
//! Everything goes through `defaults` and `plutil`, which read and write the preferences as the
//! system does. A domain is the preferences' name, or the path of a file standing in for them.

use std::io::Write as _;
use std::process::{Command, Stdio};

use super::record::PreferencesWrote;
use super::{PROFILE_NAME, ProfileError, ProfileHome, ProfileTerminal};

/// The program that reads and writes preferences.
const DEFAULTS: &str = "/usr/bin/defaults";

/// The program that edits and converts property lists.
const PLUTIL: &str = "/usr/bin/plutil";

/// The program that finds processes by name.
#[cfg(unix)]
const PGREP: &str = "/usr/bin/pgrep";

/// The key of the dictionary of profiles.
const WINDOW_SETTINGS: &str = "Window Settings";

/// The preference that names the profile new windows open with.
const DEFAULT_PROFILE: &str = "Default Window Settings";

/// The preference that names the profile the first window opens with when the application starts.
const STARTUP_PROFILE: &str = "Startup Window Settings";

/// Runs a tool with `input` on its standard input. `Ok(Some(..))` is what it printed on success,
/// `Ok(None)` is a tool that ran and refused, and an error is a tool that could not be run.
fn run(program: &str, arguments: &[&str], input: &[u8]) -> Result<Option<Vec<u8>>, ProfileError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| failed())?;
    if let Some(mut stdin) = child.stdin.take() {
        // A tool that stops reading early closes the pipe; what it answers decides.
        let _ = stdin.write_all(input);
    }
    let output = child.wait_with_output().map_err(|_| failed())?;
    Ok(output.status.success().then_some(output.stdout))
}

/// Runs a tool that must succeed.
fn run_ok(program: &str, arguments: &[&str], input: &[u8]) -> Result<Vec<u8>, ProfileError> {
    run(program, arguments, input)?.ok_or_else(failed)
}

/// The tool failed, as the terminal application's error.
fn failed() -> ProfileError {
    ProfileError::ToolFailed {
        terminal: ProfileTerminal::AppleTerminal,
        status: None,
    }
}

/// The preferences as property list text. `defaults` writes a list that parses, so a key that
/// `plutil` cannot find in what this returns is a key that is not there.
fn export(domain: &str) -> Result<Vec<u8>, ProfileError> {
    run_ok(DEFAULTS, &["export", domain, "-"], b"")
}

/// The value at a key path of a property list, as property list text: `None` where there is no
/// value at the path.
///
/// The text is in the one format `plutil` writes with its keys in order, and holds every type a
/// preference can: Terminal keeps a profile's fonts and colours as data, which JSON cannot hold.
fn entry(list: &[u8], key_path: &str) -> Result<Option<Vec<u8>>, ProfileError> {
    run(
        PLUTIL,
        &["-extract", key_path, "xml1", "-o", "-", "-"],
        list,
    )
}

/// A property list in the one format `plutil` writes, so that two lists that hold one value are
/// one text.
fn normal(list: &[u8]) -> Result<Vec<u8>, ProfileError> {
    run_ok(PLUTIL, &["-convert", "xml1", "-o", "-", "-"], list)
}

/// A property list without the value at a key path, or `None` where there is none to remove.
fn without(list: &[u8], key_path: &str) -> Result<Option<Vec<u8>>, ProfileError> {
    run(PLUTIL, &["-remove", key_path, "-o", "-", "-"], list)
}

/// A string preference's value.
fn entry_string(list: &[u8], key: &str) -> Result<Option<String>, ProfileError> {
    Ok(
        run(PLUTIL, &["-extract", key, "raw", "-o", "-", "-"], list)?
            .map(|raw| String::from_utf8_lossy(&raw).trim().to_owned()),
    )
}

/// The whole domain's snapshot, put back: `defaults import` replaces the domain with it.
fn restore(domain: &str, snapshot: &[u8]) -> Result<(), ProfileError> {
    run_ok(DEFAULTS, &["import", domain, "-"], snapshot).map(|_| ())
}

/// The dictionary of profiles without this profile's entry, and everything else in the domain
/// without the dictionary: the parts a write of this entry must leave as they were.
fn others(exported: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ProfileError> {
    let dictionary = entry(exported, WINDOW_SETTINGS)?.unwrap_or_default();
    let profiles = if dictionary.is_empty() {
        dictionary
    } else {
        normal(&without(&dictionary, PROFILE_NAME)?.unwrap_or(dictionary))?
    };
    let rest = normal(&without(exported, WINDOW_SETTINGS)?.unwrap_or_else(|| exported.to_vec()))?;
    Ok((profiles, rest))
}

/// Whether the application is installed: its application is in one of the folders applications are
/// found in.
#[must_use]
pub(super) fn present(home: &ProfileHome) -> bool {
    home.has_application("Terminal.app")
}

/// Whether the person's own Terminal is running.
#[cfg(unix)]
#[must_use]
pub fn is_running() -> bool {
    let uid = rustix::process::getuid().as_raw().to_string();
    Command::new(PGREP)
        .args(["-x", "-u", &uid, "Terminal"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Whether the person's own Terminal is running: there is no Terminal here to be.
#[cfg(not(unix))]
#[must_use]
pub const fn is_running() -> bool {
    false
}

/// Whether an entry of the profiles' name is there that no record names. A preference that cannot
/// be read says nothing is.
#[must_use]
pub(super) fn foreign(home: &ProfileHome) -> bool {
    export(&home.terminal_preferences)
        .and_then(|exported| entry(&exported, &entry_path(PROFILE_NAME)))
        .is_ok_and(|found| found.is_some())
}

/// The key path of one profile's entry.
fn entry_path(name: &str) -> String {
    format!("{WINDOW_SETTINGS}.{name}")
}

/// What installing the profile would write, worked out before anything is.
#[derive(Clone, Debug)]
pub(super) struct PreferencesPlan {
    pub domain: String,
    pub wrote: PreferencesWrote,
    /// The profile as a property list, which is what `defaults` is given.
    pub entry: String,
}

/// Works out the install, and refuses what it must not write beside.
///
/// # Errors
///
/// Returns why the profile is not written.
pub(super) fn plan(
    home: &ProfileHome,
    command_text: &str,
    recorded: Option<&PreferencesWrote>,
) -> Result<PreferencesPlan, ProfileError> {
    let domain = recorded.map_or_else(
        || home.terminal_preferences.clone(),
        |recorded| recorded.domain.clone(),
    );
    let exported = export(&domain)?;
    // The dictionary of profiles has to be there: writing one entry into a preference that has none
    // would make a dictionary of this entry alone.
    if entry(&exported, WINDOW_SETTINGS)?.is_none() {
        return Err(ProfileError::NoProfiles(ProfileTerminal::AppleTerminal));
    }
    let existing = entry(&exported, &entry_path(PROFILE_NAME))?;
    match (existing.as_deref(), recorded) {
        (Some(_), None) => {
            return Err(ProfileError::ForeignProfile(ProfileTerminal::AppleTerminal));
        }
        (Some(present), Some(recorded)) if !same_entry(present, &recorded.canonical) => {
            return Err(ProfileError::Changed {
                place: std::path::PathBuf::from(entry_path(PROFILE_NAME)),
            });
        }
        _ => {}
    }
    // A copy of the profile the person opens windows with, else the one every installation has.
    let chosen = entry_string(&exported, DEFAULT_PROFILE)?;
    let mut base = None;
    for name in [chosen.as_deref(), Some("Basic")].into_iter().flatten() {
        if let Some(copy) = entry(&exported, &entry_path(name))? {
            base = Some(copy);
            break;
        }
    }
    let copy = base.ok_or(ProfileError::NoProfiles(ProfileTerminal::AppleTerminal))?;
    let edited = [
        vec!["-replace", "name", "-string", PROFILE_NAME],
        vec!["-replace", "CommandString", "-string", command_text],
        vec!["-replace", "RunCommandAsShell", "-bool", "true"],
    ]
    .into_iter()
    .try_fold(copy, |list, edit| {
        let mut arguments = edit;
        arguments.extend(["-o", "-", "-"]);
        run_ok(PLUTIL, &arguments, &list)
    })?;
    let canonical = normal(&edited)?;
    Ok(PreferencesPlan {
        wrote: PreferencesWrote {
            domain: domain.clone(),
            key: WINDOW_SETTINGS.to_owned(),
            entry: PROFILE_NAME.to_owned(),
            canonical: String::from_utf8_lossy(&canonical).trim().to_owned(),
        },
        domain,
        entry: String::from_utf8_lossy(&canonical).into_owned(),
    })
}

/// Whether the entry read from the preferences is the one the record holds. Both are in the one
/// format `plutil` writes, so equal values are equal text.
fn same_entry(present: &[u8], canonical: &str) -> bool {
    String::from_utf8_lossy(present).trim() == canonical.trim()
}

/// Writes the entry into the dictionary of profiles, and checks by another process that the entry
/// is there as it was written and that nothing else in the preferences changed. A write that is
/// not takes itself back by putting the whole domain back as it was before.
///
/// # Errors
///
/// Returns why the profile is not written, and whether the preferences may not be as they were
/// before the write, which the caller then keeps the record's entry for.
pub(super) fn write(plan: &PreferencesPlan) -> Result<(), (ProfileError, bool)> {
    let before = export(&plan.domain).map_err(|error| (error, false))?;
    let held = (|| {
        run_ok(
            DEFAULTS,
            &[
                "write",
                &plan.domain,
                WINDOW_SETTINGS,
                "-dict-add",
                PROFILE_NAME,
                &plan.entry,
            ],
            b"",
        )?;
        let after = export(&plan.domain)?;
        let ours = entry(&after, &entry_path(PROFILE_NAME))?;
        Ok::<bool, ProfileError>(
            ours.is_some_and(|ours| same_entry(&ours, &plan.wrote.canonical))
                && others(&after)? == others(&before)?,
        )
    })();
    if held.is_ok_and(|held| held) {
        return Ok(());
    }
    // Back to the whole domain as it was before this write began, unless nothing changed: nothing
    // else is trusted to have been left alone.
    let put_back = as_it_was(&plan.domain, &before)
        || (restore(&plan.domain, &before).is_ok() && as_it_was(&plan.domain, &before));
    Err((failed(), !put_back))
}

/// Whether the preferences are as the snapshot `before` has them: this profile's entry, the rest of
/// the dictionary of profiles and everything else in the domain.
fn as_it_was(domain: &str, before: &[u8]) -> bool {
    let Ok(now) = export(domain) else {
        return false;
    };
    match (
        others(&now),
        others(before),
        entry(&now, &entry_path(PROFILE_NAME)),
        entry(before, &entry_path(PROFILE_NAME)),
    ) {
        (Ok(now_others), Ok(before_others), Ok(now_ours), Ok(before_ours)) => {
            now_others == before_others && now_ours == before_ours
        }
        _ => false,
    }
}

/// Where the entry stands against what was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Reading {
    /// The entry is there and is what was written.
    Matches,
    /// The entry is there and is something else.
    Changed,
    /// The entry is not there.
    Missing,
}

/// Reads where the recorded entry stands.
///
/// # Errors
///
/// Returns the failure of a tool: an entry that cannot be read is not one that is gone.
pub(super) fn reading(domain: &str, wrote: &PreferencesWrote) -> Result<Reading, ProfileError> {
    let exported = export(domain)?;
    Ok(
        match entry(&exported, &format!("{}.{}", wrote.key, wrote.entry))? {
            None => Reading::Missing,
            Some(present) if same_entry(&present, &wrote.canonical) => Reading::Matches,
            Some(_) => Reading::Changed,
        },
    )
}

/// Whether the recorded entry is the profile Terminal opens windows with, or starts with.
///
/// # Errors
///
/// Returns the failure of a tool: what cannot be read is not taken to be no default.
pub(super) fn is_default(domain: &str, wrote: &PreferencesWrote) -> Result<bool, ProfileError> {
    let exported = export(domain)?;
    for key in [DEFAULT_PROFILE, STARTUP_PROFILE] {
        if entry_string(&exported, key)?.is_some_and(|name| name == wrote.entry) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Takes the entry out of the dictionary of profiles: the dictionary is read, the entry is removed
/// from the copy, and the copy is written back as the dictionary. The result is read by another
/// process and compared with what was meant; a write that is not that puts the whole domain back
/// as it was.
///
/// # Errors
///
/// Returns why it could not be, with the preferences as they were.
pub(super) fn take_out(domain: &str) -> Result<(), ProfileError> {
    let before = export(domain)?;
    let Some(dictionary) = entry(&before, WINDOW_SETTINGS)? else {
        return Err(failed());
    };
    if entry(&before, &entry_path(PROFILE_NAME))?.is_none() {
        // Gone since it was read: nothing to take out.
        return Ok(());
    }
    let reduced = without(&dictionary, PROFILE_NAME)?.ok_or_else(failed)?;
    let reduced = normal(&reduced)?;
    let held = (|| {
        run_ok(
            DEFAULTS,
            &[
                "write",
                domain,
                WINDOW_SETTINGS,
                &String::from_utf8_lossy(&reduced),
            ],
            b"",
        )?;
        let after = export(domain)?;
        let dictionary = entry(&after, WINDOW_SETTINGS)?.map(|list| normal(&list));
        let same_dictionary = match dictionary {
            Some(Ok(list)) => list == reduced,
            Some(Err(error)) => return Err(error),
            None => false,
        };
        let rest_after = normal(&without(&after, WINDOW_SETTINGS)?.unwrap_or(after))?;
        let rest_before =
            normal(&without(&before, WINDOW_SETTINGS)?.unwrap_or_else(|| before.clone()))?;
        Ok::<bool, ProfileError>(same_dictionary && rest_after == rest_before)
    })();
    if held.is_ok_and(|held| held) {
        return Ok(());
    }
    // Whatever was written is not what was meant: the whole domain goes back as it was, unless it
    // is as it was already.
    if !as_it_was(domain, &before) {
        let _ = restore(domain, &before);
    }
    Err(failed())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two entries are one value when `plutil` writes them as one text, and the record's text is
    /// compared after its ends are trimmed.
    #[test]
    fn two_entries_are_the_same_when_their_text_is() {
        assert!(same_entry(b"<dict/>\n", "<dict/>"));
        assert!(!same_entry(b"<dict/>", "<array/>"));
    }
}
