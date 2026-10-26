//! Konsole: a profile is a plain file in its data directory, and Konsole reads the directory as
//! it changes.

use std::path::{Path, PathBuf};

use super::words;
use super::{ProfileError, ProfileHome};

/// The file name of the profile.
const FILE_NAME: &str = "KalaReach.profile";

/// Konsole's directory of profiles in the data home.
#[must_use]
pub(super) fn watched(home: &ProfileHome) -> PathBuf {
    home.data_home.join("konsole")
}

/// Where the profile is written.
#[must_use]
pub(super) fn profile_path(home: &ProfileHome) -> PathBuf {
    watched(home).join(FILE_NAME)
}

/// Whether Konsole is installed: its program is on the search path.
#[must_use]
pub(super) fn present(home: &ProfileHome) -> bool {
    home.has_program("konsole")
}

/// The profile file's text.
///
/// # Errors
///
/// Returns a refusal when the command holds something Konsole would expand before it ran, which
/// the profile has no way to say is literal.
pub(super) fn profile_text(command: &[String]) -> Result<String, ProfileError> {
    if let Some(word) = command
        .iter()
        .find(|word| words::konsole_would_expand(word))
    {
        return Err(ProfileError::KonsoleExpands {
            word: PathBuf::from(word),
        });
    }
    Ok(format!(
        "[General]\nCommand={}\nName={}\nParent=FALLBACK/\n",
        kconfig_value(&words::shell_words(command)),
        super::PROFILE_NAME,
    ))
}

/// A value as a KDE configuration file keeps it: a backslash, a line break and a tab are escaped,
/// and so is a space at either end.
fn kconfig_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    let characters: Vec<char> = value.chars().collect();
    for (index, character) in characters.iter().enumerate() {
        match character {
            '\\' => escaped.push_str(r"\\"),
            '\n' => escaped.push_str(r"\n"),
            '\r' => escaped.push_str(r"\r"),
            '\t' => escaped.push_str(r"\t"),
            ' ' if index == 0 || index + 1 == characters.len() => escaped.push_str(r"\s"),
            other => escaped.push(*other),
        }
    }
    escaped
}

/// Whether Konsole's default profile is `KalaReach`.
#[must_use]
pub(super) fn is_default(home: &ProfileHome) -> bool {
    let settings = home.config_home.join("konsolerc");
    default_in(&std::fs::read_to_string(settings).unwrap_or_default())
}

/// The default profile a `konsolerc` text names, compared with this profile's file name.
fn default_in(text: &str) -> bool {
    let mut section = "";
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            section = name;
        } else if section == "Desktop Entry"
            && let Some(value) = line.strip_prefix("DefaultProfile=")
        {
            return value.trim() == FILE_NAME;
        }
    }
    false
}

/// The directory a removal stages a file in: the parent of the directory Konsole watches.
#[must_use]
pub(super) fn staging(destination: &Path) -> Option<PathBuf> {
    destination.parent()?.parent().map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile file, with the command quoted for Konsole's parse of it and a path with a
    /// space, a quote and a backslash escaped for the file's own syntax.
    #[test]
    fn the_profile_file_holds_the_command_quoted_for_both_layers() {
        let command = |kr: &str| {
            [kr, "new", "--attach", "--hold-on-failure"]
                .map(str::to_owned)
                .to_vec()
        };
        assert_eq!(
            profile_text(&command("/opt/kr/current/bin/kr")).expect("a profile"),
            "[General]\nCommand=/opt/kr/current/bin/kr new --attach --hold-on-failure\n\
             Name=KalaReach\nParent=FALLBACK/\n"
        );
        assert_eq!(
            profile_text(&command(r"/home/a b/o'c\d/kr")).expect("a profile"),
            "[General]\nCommand='/home/a b/o'\\\\''c\\\\d/kr' new --attach --hold-on-failure\n\
             Name=KalaReach\nParent=FALLBACK/\n"
        );
    }

    /// A command Konsole would expand is not written.
    #[test]
    fn a_command_konsole_would_expand_is_refused() {
        for kr in ["/opt/$HOME/kr", "~/kr"] {
            let command = [kr, "new"].map(str::to_owned).to_vec();
            assert!(profile_text(&command).is_err(), "{kr}");
        }
    }

    /// The default profile is read from the `konsolerc` section Konsole keeps it in.
    #[test]
    fn the_default_profile_is_read_from_konsolerc() {
        assert!(default_in(
            "[Desktop Entry]\nDefaultProfile=KalaReach.profile\n"
        ));
        assert!(!default_in(
            "[Desktop Entry]\nDefaultProfile=Shell.profile\n"
        ));
        assert!(!default_in("[Other]\nDefaultProfile=KalaReach.profile\n"));
        assert!(!default_in(""));
    }
}
