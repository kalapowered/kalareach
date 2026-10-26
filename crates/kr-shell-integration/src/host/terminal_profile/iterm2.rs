//! iTerm2: a profile is a Dynamic Profiles file, which iTerm2 reads from its own folder and
//! reloads while it runs. The person's profiles are in iTerm2's own database and are not touched.

use std::path::{Path, PathBuf};

use super::words;
use super::{PROFILE_NAME, ProfileHome};

/// The file name of the profile.
const FILE_NAME: &str = "KalaReach.json";

/// The folder iTerm2 watches.
#[must_use]
pub(super) fn watched(home: &ProfileHome) -> PathBuf {
    home.application_support
        .join("iTerm2")
        .join("DynamicProfiles")
}

/// Where the profile is written.
#[must_use]
pub(super) fn profile_path(home: &ProfileHome) -> PathBuf {
    watched(home).join(FILE_NAME)
}

/// Whether iTerm2 is installed: its application is in one of the folders applications are in.
#[must_use]
pub(super) fn present(home: &ProfileHome) -> bool {
    home.has_application("iTerm.app")
}

/// A new identifier for the profile.
#[must_use]
pub(super) fn new_guid() -> String {
    kr_ipc::new_uuid().to_string().to_uppercase()
}

/// The identifier a profile file of ours already holds, so that a profile written again is the
/// same profile to iTerm2.
#[must_use]
pub(super) fn guid_in(text: &str) -> Option<String> {
    let document: serde_json::Value = serde_json::from_str(text).ok()?;
    document
        .get("Profiles")?
        .as_array()?
        .iter()
        .find(|profile| {
            profile.get("Name").and_then(serde_json::Value::as_str) == Some(PROFILE_NAME)
        })?
        .get("Guid")?
        .as_str()
        .map(str::to_owned)
}

/// The profile file's text. No parent is named, so the profile is the person's default profile
/// with a command of its own.
#[must_use]
pub(super) fn profile_text(command: &[String], guid: &str) -> String {
    let document = serde_json::json!({
        "Profiles": [{
            "Name": PROFILE_NAME,
            "Guid": guid,
            "Custom Command": "Yes",
            "Command": words::shell_words(command),
        }]
    });
    let mut text = serde_json::to_string_pretty(&document).unwrap_or_default();
    text.push('\n');
    text
}

/// Whether iTerm2's default profile is this one: its preference names the profile's identifier.
#[must_use]
pub(super) fn is_default(home: &ProfileHome, guid: &str) -> bool {
    super::preferences::read_string(&home.iterm_preferences, "Default Bookmark Guid")
        .is_some_and(|default| default == guid)
}

/// The directory a removal stages a file in: the folder above the one iTerm2 watches.
#[must_use]
pub(super) fn staging(destination: &Path) -> Option<PathBuf> {
    destination.parent()?.parent().map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile file: a Dynamic Profiles document with one profile, a custom command quoted for
    /// iTerm2's parse of it, and the file's own JSON escaping for a path with a quote and a
    /// backslash in it.
    #[test]
    fn the_profile_file_is_a_dynamic_profile_with_the_command_quoted() {
        let command = |kr: &str| {
            [kr, "new", "--attach", "--hold-on-failure"]
                .map(str::to_owned)
                .to_vec()
        };
        let text = profile_text(
            &command("/Users/a b/Library/Application Support/kr/current/bin/kr"),
            "11111111-2222-4333-8444-555555555555",
        );
        let document: serde_json::Value = serde_json::from_str(&text).expect("JSON");
        assert_eq!(document["Profiles"][0]["Name"], "KalaReach");
        assert_eq!(
            document["Profiles"][0]["Guid"],
            "11111111-2222-4333-8444-555555555555"
        );
        assert_eq!(document["Profiles"][0]["Custom Command"], "Yes");
        assert_eq!(
            document["Profiles"][0]["Command"],
            "'/Users/a b/Library/Application Support/kr/current/bin/kr' new --attach --hold-on-failure"
        );
        let hard = profile_text(&command(r#"/a"b\c/kr"#), "G");
        let hard: serde_json::Value = serde_json::from_str(&hard).expect("JSON");
        assert_eq!(
            hard["Profiles"][0]["Command"], r#"'/a"b\c/kr' new --attach --hold-on-failure"#,
            "both layers: the file's JSON escapes decode to the shell's single quotes"
        );
    }

    /// A profile written again keeps the identifier it had.
    #[test]
    fn the_identifier_is_read_back_from_the_file() {
        let text = profile_text(&["/kr".to_owned()], "AAAA");
        assert_eq!(guid_in(&text).as_deref(), Some("AAAA"));
        assert_eq!(guid_in("not json"), None);
    }
}
