//! Windows Terminal: a profile is a JSON fragment in the folder Windows Terminal reads fragments
//! from. A fragment adds profiles and changes none of the person's.

use std::path::{Path, PathBuf};

use super::words;
use super::{PROFILE_NAME, ProfileHome};

/// The folder of this fragment inside the folder Windows Terminal reads fragments from.
const FRAGMENT_FOLDER: &str = "KalaReach";

/// The file name of the fragment.
const FILE_NAME: &str = "kalareach.json";

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

/// The fragment's text. It names no identifier: Windows Terminal makes one from the profile's name
/// and where it came from.
#[must_use]
pub(super) fn profile_text(command: &[String]) -> String {
    let document = serde_json::json!({
        "profiles": [{
            "name": PROFILE_NAME,
            "commandline": words::command_line(command),
        }]
    });
    let mut text = serde_json::to_string_pretty(&document).unwrap_or_default();
    text.push('\n');
    text
}

/// Whether the person's settings name this profile as the one Windows Terminal opens.
#[must_use]
pub(super) fn is_default(home: &ProfileHome) -> bool {
    let Some(local) = home.local_app_data.as_ref() else {
        return false;
    };
    let packaged = local
        .join("Packages")
        .join("Microsoft.WindowsTerminal_8wekyb3d8bbwe")
        .join("LocalState")
        .join("settings.json");
    let unpackaged = local
        .join("Microsoft")
        .join("Windows Terminal")
        .join("settings.json");
    [packaged, unpackaged].iter().any(|settings| {
        std::fs::read_to_string(settings)
            .ok()
            .and_then(|text| default_in(&text))
            .is_some_and(|default| default == PROFILE_NAME)
    })
}

/// The `defaultProfile` a settings file names. The file is JSON with comments, which are dropped
/// before it is read; a file that still does not read names none.
fn default_in(text: &str) -> Option<String> {
    let without_comments: String = text
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    serde_json::from_str::<serde_json::Value>(&without_comments)
        .ok()?
        .get("defaultProfile")?
        .as_str()
        .map(str::to_owned)
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
        assert!(document["profiles"][0].get("guid").is_none());
    }

    /// The default profile is read from settings that carry comments.
    #[test]
    fn the_default_profile_is_read_from_settings_with_comments() {
        assert_eq!(
            default_in("// the person's settings\n{\n  \"defaultProfile\": \"KalaReach\"\n}\n")
                .as_deref(),
            Some("KalaReach")
        );
        assert_eq!(default_in("{}"), None);
        assert_eq!(default_in("not json"), None);
    }
}
