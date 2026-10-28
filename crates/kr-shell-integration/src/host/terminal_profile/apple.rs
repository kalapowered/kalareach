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
//!
//! Every write is checked by reading the preferences again in another process. A write that did not
//! land as meant is taken back by writing only what this module wrote: its own entry, never a
//! profile or a preference of the person's own. The one exception is taking out an entry that was
//! not there before, and a removal: `defaults` cannot remove one entry of a dictionary, so the
//! dictionary of profiles is written whole, and only while it is as the read just before shows it.

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

/// Runs a tool with `input` on its standard input. `Ok(Some(..))` is what it printed on success.
/// `Ok(None)` is a tool that ran and answered "no" with exit status 1, which `plutil` does for a
/// key that is not there. Any other end (another status, a signal) is a failure, never a "no".
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
    match output.status.code() {
        Some(0) => Ok(Some(output.stdout)),
        Some(1) => Ok(None),
        _ => Err(failed()),
    }
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
        run(PLUTIL, &["-extract", key, "raw", "-o", "-", "-"], list)?.map(|raw| {
            // `plutil` ends the value with a line feed; the spaces a name has are its own.
            let text = String::from_utf8_lossy(&raw).into_owned();
            text.strip_suffix('\n').map_or(text.clone(), str::to_owned)
        }),
    )
}

/// The key path of one profile's entry. A key path is split at each dot, so a dot in a profile's
/// name is escaped with a backslash to stay part of it. `plutil` reads no other escape: a backslash
/// stands for itself, and `\\` is two of them.
fn entry_path(name: &str) -> String {
    let mut path = format!("{WINDOW_SETTINGS}.");
    for character in name.chars() {
        if character == '.' {
            path.push('\\');
        }
        path.push(character);
    }
    path
}

/// Whether the entry read from the preferences is one the record holds: what was written, or what
/// the entry was before an install again that could not take itself back. Both sides pass through
/// this `plutil`, so a recorded text that an earlier `plutil` wrote differently is still the same
/// value.
fn is_recorded(present: &[u8], wrote: &PreferencesWrote) -> Result<bool, ProfileError> {
    let present = normal(present)?;
    for recorded in std::iter::once(&wrote.canonical).chain(wrote.earlier.iter()) {
        if normal(recorded.as_bytes())? == present {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The dictionary of profiles without this profile's entry, as text: what a write of the entry must
/// leave as it found it.
fn others(exported: &[u8]) -> Result<Vec<u8>, ProfileError> {
    let Some(dictionary) = entry(exported, WINDOW_SETTINGS)? else {
        return Ok(Vec::new());
    };
    match without(&dictionary, PROFILE_NAME)? {
        Some(rest) => normal(&rest),
        None => normal(&dictionary),
    }
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

/// What installing the profile would write, worked out before anything is.
#[derive(Clone, Debug)]
pub(super) struct PreferencesPlan {
    pub domain: String,
    pub wrote: PreferencesWrote,
    /// What the record holds for the profile now, which the entry must still be when it is written
    /// over; `None` where the entry must not be there.
    pub previous: Option<PreferencesWrote>,
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
    check_ownership(&exported, recorded)?;
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
            earlier: None,
        },
        previous: recorded.cloned(),
        domain,
        entry: String::from_utf8_lossy(&canonical).into_owned(),
    })
}

/// Refuses an entry of the profiles' name that is not the one the record names: one where the
/// record names none, and one the person changed since it was written.
fn check_ownership(
    exported: &[u8],
    recorded: Option<&PreferencesWrote>,
) -> Result<(), ProfileError> {
    let existing = entry(exported, &entry_path(PROFILE_NAME))?;
    match (existing.as_deref(), recorded) {
        (Some(_), None) => Err(ProfileError::ForeignProfile(ProfileTerminal::AppleTerminal)),
        (Some(present), Some(recorded)) if !is_recorded(present, recorded)? => {
            Err(ProfileError::Changed {
                place: std::path::PathBuf::from(entry_path(PROFILE_NAME)),
            })
        }
        _ => Ok(()),
    }
}

/// Writes the entry into the dictionary of profiles, and checks by another process that the entry
/// is there as it was written and that no other profile moved. A write that is not takes itself
/// back: the entry only, never a profile or a preference of the person's own, but for taking out an
/// entry that was not there, which writes the dictionary of profiles whole while it is as the read
/// just before shows it.
///
/// # Errors
///
/// Returns why the profile is not written, and whether the entry may not be as it was before the
/// write, which the caller then keeps the record's entry for.
pub(super) fn write(plan: &PreferencesPlan) -> Result<(), (ProfileError, bool)> {
    let before = export(&plan.domain).map_err(|error| (error, false))?;
    // The ownership the plan found is checked again on what is there now: a profile of this name
    // that the person saved since is not written over.
    check_ownership(&before, plan.previous.as_ref()).map_err(|error| (error, false))?;
    let was = entry(&before, &entry_path(PROFILE_NAME)).map_err(|error| (error, false))?;
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
        let ours_match = match ours {
            Some(ours) => normal(&ours)? == normal(plan.wrote.canonical.as_bytes())?,
            None => false,
        };
        Ok::<bool, ProfileError>(ours_match && others(&after)? == others(&before)?)
    })();
    if held.is_ok_and(|held| held) {
        return Ok(());
    }
    // The entry is kr's to put back while it is what kr attempted to write; anything else there
    // now is another writer's.
    let left = [plan.wrote.canonical.as_bytes(), plan.entry.as_bytes()];
    let put_back = put_back(&plan.domain, was.as_deref(), &left);
    Err((failed(), !put_back))
}

/// Whether two property lists hold one value.
fn same(left: &[u8], right: &[u8]) -> bool {
    matches!((normal(left), normal(right)), (Ok(left), Ok(right)) if left == right)
}

/// Puts this profile's entry back as the snapshot had it (`was`: the entry, or `None` for none),
/// leaving everything else as it is now, and says whether it is.
///
/// The entry is touched only while it is something kr could have left: absent, as `was` had it, or
/// as one of `left` has it (what kr attempted to write). An entry that is anything else was changed
/// by another writer since, and is theirs. Putting back an entry that was
/// not there takes the dictionary of profiles out whole, which is written only while it is as the
/// read just before shows it; otherwise nothing is written and the entry is not put back.
fn put_back(domain: &str, was: Option<&[u8]>, left: &[&[u8]]) -> bool {
    let as_was = |now: &Option<Vec<u8>>| match (now, was) {
        (None, None) => true,
        (Some(now), Some(was)) => same(now, was),
        _ => false,
    };
    let Ok(exported) = export(domain) else {
        return false;
    };
    let Ok(now) = entry(&exported, &entry_path(PROFILE_NAME)) else {
        return false;
    };
    if as_was(&now) {
        return true;
    }
    if now
        .as_deref()
        .is_some_and(|now| !left.iter().any(|ours| same(now, ours)))
    {
        return false;
    }
    let restored = match was {
        Some(entry) => run_ok(
            DEFAULTS,
            &[
                "write",
                domain,
                WINDOW_SETTINGS,
                "-dict-add",
                PROFILE_NAME,
                &String::from_utf8_lossy(entry),
            ],
            b"",
        )
        .is_ok(),
        None => write_without(domain, &exported).is_ok_and(|written| written),
    };
    restored
        && export(domain)
            .and_then(|exported| entry(&exported, &entry_path(PROFILE_NAME)))
            .is_ok_and(|now| as_was(&now))
}

/// The dictionary of profiles as `plutil` writes it, or `None` where there is none.
fn dictionary(exported: &[u8]) -> Result<Option<Vec<u8>>, ProfileError> {
    entry(exported, WINDOW_SETTINGS)?
        .map(|list| normal(&list))
        .transpose()
}

/// Writes the dictionary of profiles without this profile's entry, if the preferences are still the
/// ones `seen` shows. `Ok(false)` is preferences that moved since (a profile, or which profile is the
/// default): nothing was written, so a profile the person changed meanwhile is not put back to what
/// it was. What is written is worked out from `seen` before the preferences are read once more, so
/// what remains is the time between that read and the write.
fn write_without(domain: &str, seen: &[u8]) -> Result<bool, ProfileError> {
    let list = entry(seen, WINDOW_SETTINGS)?.ok_or_else(failed)?;
    let reduced = normal(&without(&list, PROFILE_NAME)?.ok_or_else(failed)?)?;
    if export(domain)? != seen {
        return Ok(false);
    }
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
    Ok(true)
}

/// The profile's entry as the preferences hold it now, in the text a record keeps it in, or `None`
/// where there is none, for a record that names it as `recorded`.
///
/// # Errors
///
/// Returns the failure of a tool: an entry that cannot be read is not one that is not there. An
/// entry that is not one `recorded` names is [`ProfileError::Changed`]: it is not kr's, so it is not
/// to be written into a record as if it were.
pub(super) fn current_entry(recorded: &PreferencesWrote) -> Result<Option<String>, ProfileError> {
    let exported = export(&recorded.domain)?;
    let Some(present) = entry(&exported, &entry_path(PROFILE_NAME))? else {
        return Ok(None);
    };
    if !is_recorded(&present, recorded)? {
        return Err(ProfileError::Changed {
            place: std::path::PathBuf::from(entry_path(PROFILE_NAME)),
        });
    }
    Ok(Some(
        String::from_utf8_lossy(&normal(&present)?)
            .trim()
            .to_owned(),
    ))
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
    reading_in(&exported, wrote)
}

/// The same, from preferences already read.
fn reading_in(exported: &[u8], wrote: &PreferencesWrote) -> Result<Reading, ProfileError> {
    Ok(match entry(exported, &entry_path(&wrote.entry))? {
        None => Reading::Missing,
        Some(present) if is_recorded(&present, wrote)? => Reading::Matches,
        Some(_) => Reading::Changed,
    })
}

/// Whether the recorded entry is the profile Terminal opens windows with, or starts with.
///
/// # Errors
///
/// Returns the failure of a tool: what cannot be read is not taken to be no default.
pub(super) fn is_default(domain: &str, wrote: &PreferencesWrote) -> Result<bool, ProfileError> {
    is_default_in(&export(domain)?, wrote)
}

/// The same, from preferences already read.
fn is_default_in(exported: &[u8], wrote: &PreferencesWrote) -> Result<bool, ProfileError> {
    for key in [DEFAULT_PROFILE, STARTUP_PROFILE] {
        if entry_string(exported, key)?.is_some_and(|name| name == wrote.entry) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// What taking the entry out came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TakenOut {
    /// The entry is out.
    Removed,
    /// There was none.
    AlreadyGone,
    /// It is not what was written, and is left.
    Changed,
    /// It is the profile Terminal opens windows with, and is left.
    Default,
}

/// Takes the recorded entry out of the dictionary of profiles, from one read of the preferences: the
/// entry is the one the record names and not the default as that read has them, the dictionary is
/// written back without it, and the result is read by another process and compared with what was
/// meant. A write that is not that puts this entry back.
///
/// # Errors
///
/// Returns why it could not be, with the entry as it was.
pub(super) fn take_out(domain: &str, wrote: &PreferencesWrote) -> Result<TakenOut, ProfileError> {
    let before = export(domain)?;
    let found = reading_in(&before, wrote)?;
    if found != Reading::Missing && is_default_in(&before, wrote)? {
        return Ok(TakenOut::Default);
    }
    match found {
        Reading::Missing => return Ok(TakenOut::AlreadyGone),
        Reading::Changed => return Ok(TakenOut::Changed),
        Reading::Matches => {}
    }
    let was = entry(&before, &entry_path(PROFILE_NAME))?;
    let list = entry(&before, WINDOW_SETTINGS)?.ok_or_else(failed)?;
    let reduced = normal(&without(&list, PROFILE_NAME)?.ok_or_else(failed)?)?;
    // Written only while the dictionary is as the read above shows it.
    if !write_without(domain, &before)? {
        return Err(ProfileError::Changing(ProfileTerminal::AppleTerminal));
    }
    let held = (|| {
        let after = export(domain)?;
        Ok::<bool, ProfileError>(dictionary(&after)?.is_some_and(|list| list == reduced))
    })();
    if held.is_ok_and(|held| held) {
        return Ok(TakenOut::Removed);
    }
    // Whatever was written is not what was meant: this entry goes back, and nothing else is
    // touched.
    let _ = put_back(domain, was.as_deref(), &[]);
    Err(failed())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    /// Preferences of a scratch file of this test's own, by path, with two profiles.
    fn scratch(name: &str) -> (std::path::PathBuf, String) {
        let directory = std::env::temp_dir().join(format!(
            "kr-apple-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        std::fs::create_dir_all(&directory).expect("a directory");
        let domain = directory.join("com.apple.Terminal");
        std::fs::write(
            directory.join("com.apple.Terminal.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Default Window Settings</key><string>Pro</string>
<key>Window Settings</key><dict>
<key>Basic</key><dict><key>name</key><string>Basic</string></dict>
<key>Pro</key><dict><key>name</key><string>Pro</string><key>Font</key><data>YnBsaXN0</data></dict>
</dict></dict></plist>"#,
        )
        .expect("preferences");
        let text = domain.display().to_string();
        (directory, text)
    }

    /// A plan whose entry is not what its record says it is, so that the check after the write fails
    /// and the write has to be taken back.
    fn a_plan_that_does_not_hold(
        domain: &str,
        previous: Option<PreferencesWrote>,
    ) -> PreferencesPlan {
        PreferencesPlan {
            domain: domain.to_owned(),
            wrote: PreferencesWrote {
                domain: domain.to_owned(),
                key: WINDOW_SETTINGS.to_owned(),
                entry: PROFILE_NAME.to_owned(),
                canonical: "<dict><key>name</key><string>Not what was written</string></dict>"
                    .to_owned(),
                earlier: None,
            },
            previous,
            entry: r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>name</key><string>KalaReach</string></dict></plist>"#
                .to_owned(),
        }
    }

    /// A write that does not hold is taken back: with no entry before, the entry goes out again,
    /// and a profile of the person's that was changed meanwhile is not touched by it; with an entry
    /// before, that entry is back, to the byte.
    #[test]
    fn a_write_that_does_not_hold_puts_the_entry_back_and_touches_nothing_else() {
        let (directory, domain) = scratch("putback");
        let before = export(&domain).expect("exports");
        let failed_write = write(&a_plan_that_does_not_hold(&domain, None));
        assert!(
            matches!(failed_write, Err((_, false))),
            "put back, nothing left over: {failed_write:?}"
        );
        assert_eq!(export(&domain).expect("exports"), before);

        // An entry before: it is the one that comes back.
        run_ok(
            DEFAULTS,
            &[
                "write",
                &domain,
                WINDOW_SETTINGS,
                "-dict-add",
                PROFILE_NAME,
                "<dict><key>name</key><string>KalaReach</string><key>Font</key><data>AAEC</data></dict>",
            ],
            b"",
        )
        .expect("an entry kr wrote earlier");
        let with_entry = export(&domain).expect("exports");
        let earlier = PreferencesWrote {
            domain: domain.clone(),
            key: WINDOW_SETTINGS.to_owned(),
            entry: PROFILE_NAME.to_owned(),
            canonical: String::from_utf8_lossy(
                &entry(&with_entry, &entry_path(PROFILE_NAME))
                    .expect("reads")
                    .expect("there"),
            )
            .into_owned(),
            earlier: None,
        };
        let failed_write = write(&a_plan_that_does_not_hold(&domain, Some(earlier)));
        assert!(
            matches!(failed_write, Err((_, false))),
            "put back, nothing left over: {failed_write:?}"
        );
        assert_eq!(export(&domain).expect("exports"), with_entry);
        let _ = std::fs::remove_dir_all(directory);
    }

    /// Writes `entry` as the value of the profile `name` in the scratch preferences.
    fn put_profile(domain: &str, name: &str, entry: &str) {
        run_ok(
            DEFAULTS,
            &["write", domain, WINDOW_SETTINGS, "-dict-add", name, entry],
            b"",
        )
        .expect("a profile");
    }

    fn profile_of(name: &str, marker: &str) -> String {
        format!(
            "<dict><key>name</key><string>{name}</string><key>Marker</key><string>{marker}</string></dict>"
        )
    }

    /// KR-REQ-01.21: the dictionary of profiles is written without the entry only while it is as the
    /// read shows it. A profile of the person's that changed after the read is not put back to what
    /// it was: nothing is written.
    #[test]
    fn a_dictionary_that_moved_since_the_read_is_not_written() {
        let (directory, domain) = scratch("moved");
        put_profile(&domain, PROFILE_NAME, &profile_of(PROFILE_NAME, "ours"));
        let seen = export(&domain).expect("exports");

        put_profile(&domain, "Pro", &profile_of("Pro", "the person changed it"));
        let after_the_edit = export(&domain).expect("exports");
        assert!(
            !write_without(&domain, &seen).expect("answers"),
            "a dictionary that moved is not written"
        );
        assert_eq!(export(&domain).expect("exports"), after_the_edit);

        // As the read shows it, only the entry goes.
        let seen = export(&domain).expect("exports");
        assert!(write_without(&domain, &seen).expect("answers"));
        let now = export(&domain).expect("exports");
        assert!(
            entry(&now, &entry_path(PROFILE_NAME))
                .expect("reads")
                .is_none()
        );
        assert!(
            String::from_utf8_lossy(
                &entry(&now, &entry_path("Pro"))
                    .expect("reads")
                    .expect("Pro stays")
            )
            .contains("the person changed it")
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    /// KR-REQ-01.21: a take-back touches the entry only while it is something kr left. An entry the
    /// person changed after the write is theirs and stays; one kr's own write left is put back.
    #[test]
    fn a_take_back_leaves_an_entry_the_person_changed() {
        let (directory, domain) = scratch("theirs");
        let earlier = profile_of(PROFILE_NAME, "earlier");
        let ours = profile_of(PROFILE_NAME, "ours");
        put_profile(&domain, PROFILE_NAME, &ours);
        let was = earlier.as_bytes();
        let left = [ours.as_bytes()];

        // The person saved the profile after kr wrote it: not in `left`, so not put back.
        put_profile(&domain, PROFILE_NAME, &profile_of(PROFILE_NAME, "theirs"));
        let theirs = export(&domain).expect("exports");
        assert!(!put_back(&domain, Some(was), &left));
        assert_eq!(export(&domain).expect("exports"), theirs);
        assert!(!put_back(&domain, None, &left));
        assert_eq!(export(&domain).expect("exports"), theirs);

        // What kr's write left is put back to the earlier entry, or taken out.
        put_profile(&domain, PROFILE_NAME, &ours);
        assert!(put_back(&domain, Some(was), &left));
        let now = export(&domain).expect("exports");
        let entry_now = entry(&now, &entry_path(PROFILE_NAME))
            .expect("reads")
            .expect("there");
        assert!(String::from_utf8_lossy(&entry_now).contains("earlier"));
        put_profile(&domain, PROFILE_NAME, &ours);
        assert!(put_back(&domain, None, &left));
        let now = export(&domain).expect("exports");
        assert!(
            entry(&now, &entry_path(PROFILE_NAME))
                .expect("reads")
                .is_none()
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    /// KR-REQ-01.21: a default profile whose name has a dot is copied, not another profile: the key
    /// path escapes the dot.
    #[test]
    fn a_default_profile_with_a_dot_in_its_name_is_the_one_copied() {
        let (directory, domain) = scratch("dotted");
        // The profiles are written into the file whole: `defaults` itself reads a backslash in the
        // name it is given as an escape, which Terminal's own names do not.
        let names = [" Work.Dark", "Work.Dark", "p\\q", "m\\.n", "a.b\\c"];
        let profiles = |kr: bool| -> String {
            names
                .iter()
                .map(|name| {
                    let marker = match *name {
                        " Work.Dark" => "spaced",
                        "Work.Dark" => "dotted",
                        _ => "found",
                    };
                    format!("<key>{name}</key>{}", profile_of(name, marker))
                })
                .chain(kr.then(|| {
                    format!(
                        "<key>{PROFILE_NAME}</key>{}",
                        profile_of(PROFILE_NAME, "ours")
                    )
                }))
                .collect()
        };
        let preferences = |kr: bool| {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Default Window Settings</key><string> Work.Dark</string>
<key>Window Settings</key><dict>
<key>Basic</key><dict><key>name</key><string>Basic</string></dict>{}</dict></dict></plist>"#,
                profiles(kr)
            )
        };
        std::fs::write(format!("{domain}.plist"), preferences(false)).expect("preferences");
        let mut home = ProfileHome::under(&directory, Vec::new());
        home.terminal_preferences = domain.clone();
        let plan = plan(&home, "kr new --attach --hold-on-failure", None).expect("a plan");
        assert!(
            plan.entry.contains("spaced") && !plan.entry.contains("dotted"),
            "the profile named as the default, spaces and all, is the one copied: {}",
            plan.entry
        );
        // `plutil` reads `\.` as a dot of the name and every other backslash as itself.
        assert_eq!(entry_path("a.b\\c"), "Window Settings.a\\.b\\c");
        let finds_every_name = |exported: &[u8]| {
            for name in names {
                let found = entry(exported, &entry_path(name)).expect("reads");
                assert!(
                    found.is_some_and(|text| !text.is_empty()),
                    "{name} is found"
                );
            }
        };
        finds_every_name(&export(&domain).expect("exports"));

        // A removal writes the dictionary through `defaults`, and those names come out of it as
        // they went in.
        std::fs::write(format!("{domain}.plist"), preferences(true)).expect("preferences");
        let seen = export(&domain).expect("exports");
        assert!(write_without(&domain, &seen).expect("answers"));
        let after = export(&domain).expect("exports");
        finds_every_name(&after);
        assert!(
            entry(&after, &entry_path(PROFILE_NAME))
                .expect("reads")
                .is_none()
        );
        let _ = std::fs::remove_dir_all(directory);
    }

    /// KR-REQ-01.21: the entry an install again records as what it holds is read against the record:
    /// the entry the record names is recorded, none is none, and one that is not the record's is a
    /// changed profile and is not written into a record as kr's.
    #[test]
    fn an_entry_that_is_not_the_recorded_one_is_not_recorded_as_kr_s() {
        let (directory, domain) = scratch("recorded");
        let recorded = |canonical: String| PreferencesWrote {
            domain: domain.clone(),
            key: WINDOW_SETTINGS.to_owned(),
            entry: PROFILE_NAME.to_owned(),
            canonical,
            earlier: None,
        };
        assert_eq!(
            current_entry(&recorded(String::new())).expect("reads"),
            None
        );
        put_profile(&domain, PROFILE_NAME, &profile_of(PROFILE_NAME, "ours"));
        let other = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>name</key><string>Other</string></dict></plist>"#;
        let ours = current_entry(&recorded(other.to_owned()));
        assert!(
            matches!(ours, Err(ProfileError::Changed { .. })),
            "an entry the record does not name: {ours:?}"
        );
        let text = entry(
            &export(&domain).expect("exports"),
            &entry_path(PROFILE_NAME),
        )
        .expect("reads")
        .expect("there");
        let known = recorded(String::from_utf8_lossy(&text).into_owned());
        let now = current_entry(&known).expect("reads").expect("there");
        assert!(now.contains("ours"), "{now}");
        put_profile(&domain, PROFILE_NAME, &profile_of(PROFILE_NAME, "theirs"));
        assert!(matches!(
            current_entry(&known),
            Err(ProfileError::Changed { .. })
        ));
        let _ = std::fs::remove_dir_all(directory);
    }
}
