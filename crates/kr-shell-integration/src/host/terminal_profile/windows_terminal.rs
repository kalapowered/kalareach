//! Windows Terminal: a profile is a JSON fragment in the folder Windows Terminal reads fragments
//! from. A fragment adds profiles and changes none of the person's.

use std::path::{Path, PathBuf};

use super::words;
use super::{PROFILE_NAME, ProfileError, ProfileHome, ProfileTerminal};

/// The folder of this fragment inside the folder Windows Terminal reads fragments from.
const FRAGMENT_FOLDER: &str = "KalaReach";

/// The file name of the fragment.
const FILE_NAME: &str = "kalareach.json";

/// The identifier the fragment gives its profile, which the settings name the default by when the
/// person picks it in Windows Terminal's settings page.
const PROFILE_GUID: &str = "{b4c63c26-b403-43b0-a8fd-20e5747d3446}";

/// The folder Windows Terminal reads fragments from, or `None` where there is no local
/// application data folder.
#[must_use]
pub(super) fn watched(home: &ProfileHome) -> Option<PathBuf> {
    Some(
        home.local_app_data
            .as_ref()?
            .join("Microsoft")
            .join("Windows Terminal")
            .join("Fragments"),
    )
}

/// Where the fragment is written.
#[must_use]
pub(super) fn profile_path(home: &ProfileHome) -> Option<PathBuf> {
    Some(watched(home)?.join(FRAGMENT_FOLDER).join(FILE_NAME))
}

/// Whether Windows Terminal is installed: its program is in one of the directories programs are
/// found in.
#[must_use]
pub(super) fn present(home: &ProfileHome) -> bool {
    home.has_program("wt.exe")
}

/// The fragment's text.
#[must_use]
pub(super) fn profile_text(command: &[String]) -> String {
    let document = serde_json::json!({
        "profiles": [{
            "guid": PROFILE_GUID,
            "name": PROFILE_NAME,
            "commandline": words::command_line(command),
        }]
    });
    let mut text = serde_json::to_string_pretty(&document).unwrap_or_default();
    text.push('\n');
    text
}

/// Whether the person's settings name this profile as the one Windows Terminal opens: by its name,
/// or by the identifier the fragment gives it, which is what the settings page writes.
///
/// # Errors
///
/// Returns [`ProfileError::DefaultUnknown`] when a settings file is there and cannot be read: what
/// cannot be read is not taken to name another profile.
pub(super) fn is_default(home: &ProfileHome) -> Result<bool, ProfileError> {
    let Some(local) = home.local_app_data.as_ref() else {
        return Ok(false);
    };
    let packaged = |package: &str| {
        local
            .join("Packages")
            .join(package)
            .join("LocalState")
            .join("settings.json")
    };
    let candidates = [
        packaged("Microsoft.WindowsTerminal_8wekyb3d8bbwe"),
        packaged("Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe"),
        packaged("Microsoft.WindowsTerminalCanary_8wekyb3d8bbwe"),
        local
            .join("Microsoft")
            .join("Windows Terminal")
            .join("settings.json"),
    ];
    for settings in &candidates {
        let unknown = || ProfileError::DefaultUnknown {
            terminal: ProfileTerminal::WindowsTerminal,
            place: settings.clone(),
        };
        let text = match std::fs::read_to_string(settings) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(unknown()),
        };
        match default_in(&text).ok_or_else(unknown)? {
            Some(default) if names_this_profile(&default) => return Ok(true),
            _ => {}
        }
    }
    Ok(false)
}

/// Whether a `defaultProfile` value is this profile's name or its identifier.
fn names_this_profile(default: &str) -> bool {
    default == PROFILE_NAME || default.eq_ignore_ascii_case(PROFILE_GUID)
}

/// The `defaultProfile` a settings file names, `Some(None)` where it names none, and `None` where
/// the file does not read. The file is JSON with comments and trailing commas, which Windows
/// Terminal's own parser accepts.
fn default_in(text: &str) -> Option<Option<String>> {
    let document: serde_json::Value = serde_json::from_str(&without_json_extensions(
        text.trim_start_matches('\u{feff}'),
    ))
    .ok()?;
    Some(
        document
            .get("defaultProfile")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    )
}

/// JSON with comments and trailing commas as plain JSON: both kinds of comment are dropped and so
/// is a comma that nothing follows in its object or array. Text inside a string is never touched.
fn without_json_extensions(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut characters = text.chars().peekable();
    let mut in_string = false;
    while let Some(character) = characters.next() {
        if in_string {
            plain.push(character);
            match character {
                '\\' => plain.extend(characters.next()),
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match (character, characters.peek()) {
            ('"', _) => {
                in_string = true;
                plain.push(character);
            }
            ('/', Some('/')) => {
                for next in characters.by_ref() {
                    if next == '\n' {
                        plain.push('\n');
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                characters.next();
                let mut previous = ' ';
                for next in characters.by_ref() {
                    if previous == '*' && next == '/' {
                        break;
                    }
                    previous = next;
                }
                plain.push(' ');
            }
            _ => plain.push(character),
        }
    }
    drop_trailing_commas(&plain)
}

/// The text without a comma that only whitespace separates from the end of its object or array.
fn drop_trailing_commas(text: &str) -> String {
    let characters: Vec<char> = text.chars().collect();
    let mut kept = String::with_capacity(text.len());
    let mut in_string = false;
    let mut index = 0;
    while index < characters.len() {
        let character = characters[index];
        if in_string {
            kept.push(character);
            if character == '\\' {
                index += 1;
                kept.extend(characters.get(index));
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
            kept.push(character);
        } else if character == ','
            && characters[index + 1..]
                .iter()
                .find(|next| !next.is_whitespace())
                .is_some_and(|next| matches!(next, '}' | ']'))
        {
            // A trailing comma: dropped.
        } else {
            kept.push(character);
        }
        index += 1;
    }
    kept
}

/// The directory a removal stages a file in: the folder above the folder Windows Terminal reads
/// fragments from.
#[must_use]
pub(super) fn staging(destination: &Path) -> Option<PathBuf> {
    destination
        .parent()?
        .parent()?
        .parent()
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fragment: one profile with a name and a command line quoted the way Windows reads one.
    #[test]
    fn the_fragment_holds_a_named_profile_with_a_windows_command_line() {
        let text = profile_text(
            &[
                r"C:\Program Files\kr\kr.exe",
                "new",
                "--attach",
                "--hold-on-failure",
            ]
            .map(str::to_owned),
        );
        let document: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(document["profiles"][0]["name"], "KalaReach");
        assert_eq!(
            document["profiles"][0]["commandline"],
            r#""C:\Program Files\kr\kr.exe" new --attach --hold-on-failure"#
        );
        assert_eq!(document["profiles"][0]["guid"], PROFILE_GUID);
    }

    /// The default profile is read from settings that carry comments of both kinds and trailing
    /// commas, and a value that holds what looks like a comment is left alone.
    #[test]
    fn the_default_profile_is_read_from_settings_with_comments_and_trailing_commas() {
        let settings = "\u{feff}// the person's settings\n{\n  /* a block\n comment */\n  \"defaultProfile\": \"KalaReach\", // the one\n  \"profiles\": { \"list\": [ { \"name\": \"a // b\", }, ], },\n}\n";
        assert_eq!(default_in(settings), Some(Some("KalaReach".to_owned())));
        assert_eq!(default_in("{}"), Some(None));
        assert_eq!(default_in("not json"), None);
        assert_eq!(
            default_in("{\"defaultProfile\": \"a, }\"}"),
            Some(Some("a, }".to_owned()))
        );
    }

    /// The profile is the default by its name, or by the identifier the settings page writes, in
    /// either case.
    #[test]
    fn the_default_is_named_by_the_profile_s_name_or_its_identifier() {
        assert!(names_this_profile("KalaReach"));
        assert!(names_this_profile(PROFILE_GUID));
        assert!(names_this_profile(&PROFILE_GUID.to_uppercase()));
        assert!(!names_this_profile("Ubuntu"));
        assert!(!names_this_profile(
            "{00000000-0000-0000-0000-000000000000}"
        ));
    }
}
