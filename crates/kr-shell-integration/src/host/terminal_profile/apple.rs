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
const PGREP: &str = "/usr/bin/pgrep";

/// The key of the dictionary of profiles.
const WINDOW_SETTINGS: &str = "Window Settings";

/// The preference that names the profile new windows open with.
const DEFAULT_PROFILE: &str = "Default Window Settings";

/// The preference that names the profile the first window opens with when the application starts.
const STARTUP_PROFILE: &str = "Startup Window Settings";

/// Runs a tool with `input` on its standard input, and returns what it printed on success.
fn run(program: &str, arguments: &[&str], input: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    if let Some(mut stdin) = child.stdin.take() {
        // A tool that stops reading early closes the pipe; what it answers decides.
        let _ = stdin.write_all(input);
    }
    let output = child.wait_with_output().ok()?;
    output.status.success().then_some(output.stdout)
}

/// The tool failed, as the terminal application's error.
fn failed() -> ProfileError {
    ProfileError::ToolFailed {
        terminal: ProfileTerminal::AppleTerminal,
        status: None,
    }
}

/// The preferences as property list text.
fn export(domain: &str) -> Option<Vec<u8>> {
    run(DEFAULTS, &["export", domain, "-"], b"")
}

/// The value at a key path of a property list, in the format asked for.
fn extract(list: &[u8], key_path: &str, format: &str) -> Option<Vec<u8>> {
    run(
        PLUTIL,
        &["-extract", key_path, format, "-o", "-", "-"],
        list,
    )
}

/// A string preference's value.
fn extract_string(list: &[u8], key: &str) -> Option<String> {
    extract(list, key, "raw").map(|raw| String::from_utf8_lossy(&raw).trim().to_owned())
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

/// Whether an entry of the profiles' name is there that no record names.
#[must_use]
pub(super) fn foreign(home: &ProfileHome) -> bool {
    export(&home.terminal_preferences)
        .and_then(|exported| {
            extract(
                &exported,
                &format!("{WINDOW_SETTINGS}.{PROFILE_NAME}"),
                "json",
            )
        })
        .is_some()
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
    let exported = export(&domain).ok_or_else(failed)?;
    // The dictionary of profiles has to be there: writing one entry into a preference that has none
    // would make a dictionary of this entry alone.
    if extract(&exported, WINDOW_SETTINGS, "xml1").is_none() {
        return Err(ProfileError::NoProfiles(ProfileTerminal::AppleTerminal));
    }
    let existing = extract(
        &exported,
        &format!("{WINDOW_SETTINGS}.{PROFILE_NAME}"),
        "json",
    );
    match (existing.as_deref(), recorded) {
        (Some(_), None) => {
            return Err(ProfileError::ForeignProfile(ProfileTerminal::AppleTerminal));
        }
        (Some(present), Some(recorded)) if !same_entry(present, &recorded.canonical) => {
            return Err(ProfileError::Changed {
                place: std::path::PathBuf::from(format!("{WINDOW_SETTINGS}.{PROFILE_NAME}")),
            });
        }
        _ => {}
    }
    // A copy of the profile the person opens windows with, else the one every installation has.
    let chosen = extract_string(&exported, DEFAULT_PROFILE);
    let base = [chosen.as_deref(), Some("Basic")]
        .into_iter()
        .flatten()
        .find(|name| extract(&exported, &format!("{WINDOW_SETTINGS}.{name}"), "xml1").is_some())
        .map(str::to_owned)
        .ok_or(ProfileError::NoProfiles(ProfileTerminal::AppleTerminal))?;
    let copy =
        extract(&exported, &format!("{WINDOW_SETTINGS}.{base}"), "xml1").ok_or_else(failed)?;
    let edited = [
        vec!["-replace", "name", "-string", PROFILE_NAME],
        vec!["-replace", "CommandString", "-string", command_text],
        vec!["-replace", "RunCommandAsShell", "-bool", "true"],
    ]
    .into_iter()
    .try_fold(copy, |list, edit| {
        let mut arguments = edit;
        arguments.extend(["-o", "-", "-"]);
        run(PLUTIL, &arguments, &list)
    })
    .ok_or_else(failed)?;
    let canonical =
        run(PLUTIL, &["-convert", "json", "-o", "-", "-"], &edited).ok_or_else(failed)?;
    let entry = run(PLUTIL, &["-convert", "xml1", "-o", "-", "-"], &edited).ok_or_else(failed)?;
    Ok(PreferencesPlan {
        wrote: PreferencesWrote {
            domain: domain.clone(),
            key: WINDOW_SETTINGS.to_owned(),
            entry: PROFILE_NAME.to_owned(),
            canonical: String::from_utf8_lossy(&canonical).trim().to_owned(),
        },
        domain,
        entry: String::from_utf8_lossy(&entry).into_owned(),
    })
}

/// Whether two property lists in JSON hold one value.
fn same_entry(left: &[u8], right: &str) -> bool {
    match (
        serde_json::from_slice::<serde_json::Value>(left),
        serde_json::from_str::<serde_json::Value>(right),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Writes the entry into the dictionary of profiles, and checks by another process that it is
/// there as it was written. A write that is not takes itself back.
///
/// # Errors
///
/// Returns why the profile is not written; nothing of it is left.
pub(super) fn write(plan: &PreferencesPlan) -> Result<(), ProfileError> {
    let written = Command::new(DEFAULTS)
        .args([
            "write",
            &plan.domain,
            WINDOW_SETTINGS,
            "-dict-add",
            PROFILE_NAME,
            &plan.entry,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !written {
        return Err(failed());
    }
    if reading(&plan.domain, &plan.wrote) != Reading::Matches {
        let _ = take_out(&plan.domain);
        return Err(failed());
    }
    Ok(())
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
pub(super) fn reading(domain: &str, wrote: &PreferencesWrote) -> Reading {
    let Some(exported) = export(domain) else {
        return Reading::Changed;
    };
    match extract(&exported, &format!("{}.{}", wrote.key, wrote.entry), "json") {
        None => Reading::Missing,
        Some(present) if same_entry(&present, &wrote.canonical) => Reading::Matches,
        Some(_) => Reading::Changed,
    }
}

/// Whether the recorded entry is the profile Terminal opens windows with, or starts with.
pub(super) fn is_default(domain: &str, wrote: &PreferencesWrote) -> bool {
    let Some(exported) = export(domain) else {
        return false;
    };
    [DEFAULT_PROFILE, STARTUP_PROFILE]
        .iter()
        .any(|key| extract_string(&exported, key).is_some_and(|name| name == wrote.entry))
}

/// Takes the entry out of the dictionary of profiles: the dictionary is read, the entry is removed
/// from the copy, and the copy is written back as the dictionary.
///
/// # Errors
///
/// Returns why it could not be.
pub(super) fn take_out(domain: &str) -> Result<(), ProfileError> {
    let exported = export(domain).ok_or_else(failed)?;
    let dictionary = extract(&exported, WINDOW_SETTINGS, "xml1").ok_or_else(failed)?;
    let without = run(
        PLUTIL,
        &["-remove", PROFILE_NAME, "-o", "-", "-"],
        &dictionary,
    )
    .ok_or_else(failed)?;
    let written = Command::new(DEFAULTS)
        .args([
            "write",
            domain,
            WINDOW_SETTINGS,
            &String::from_utf8_lossy(&without),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if written { Ok(()) } else { Err(failed()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two entries in JSON are one value whatever order their keys are in.
    #[test]
    fn two_entries_are_one_whatever_order_their_keys_are_in() {
        assert!(same_entry(br#"{"a":1,"b":"x"}"#, r#"{"b":"x","a":1}"#));
        assert!(!same_entry(br#"{"a":1}"#, r#"{"a":2}"#));
        assert!(!same_entry(b"not json", "{}"));
    }
}
