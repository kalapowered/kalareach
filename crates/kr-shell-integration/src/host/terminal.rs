//! Which terminal application a presented session opens, in the order section 7 fixes.
//!
//! An explicit profile, then the saved per-environment preference, then a detected supported
//! terminal. macOS prefers iTerm2 when it is installed, otherwise Terminal.app; Windows prefers
//! Windows Terminal, otherwise a new console window; Linux uses an installed desktop terminal
//! through the configured desktop launcher.
//!
//! When nothing can open a window the session is still created. The caller is told
//! `TERMINAL_UNAVAILABLE` against the session it already has, and a retry never produces a second
//! one: choosing a terminal and creating a session are separate steps, and this module is only the
//! first.

use kr_protocol::error::{ErrorCode, ProtocolError};
use serde::{Deserialize, Serialize};

/// A terminal application this host can open a session in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalApplication {
    /// The stable identifier a profile and a preference name it by.
    pub id: String,
    /// What to show a person.
    pub name: String,
    /// Where it was found, for diagnostics.
    pub detail: String,
}

/// Why a terminal was chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The create request named it.
    Profile,
    /// The environment's saved preference named it.
    Preference,
    /// It was detected on this host.
    Detected,
}

impl Source {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Preference => "preference",
            Self::Detected => "detected",
        }
    }
}

/// The terminal a presented session opens in, and why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    /// The application.
    pub application: TerminalApplication,
    /// Which of the three steps chose it.
    pub source: Source,
}

/// Why no terminal could be opened.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TerminalUnavailable {
    /// The profile named an application this host does not have.
    #[error("the profile names {requested}, which is not installed on this host")]
    ProfileMissing {
        /// What was asked for.
        requested: String,
    },
    /// Nothing supported is installed, or there is no desktop launcher to open one with.
    #[error("no supported terminal application is available on this host")]
    NoneAvailable,
    /// The chosen application is installed and would not open a window.
    #[error("{application} is installed and did not open a window: {detail}")]
    CouldNotOpen {
        /// Which application was chosen.
        application: String,
        /// What the platform said.
        detail: String,
    },
}

impl TerminalUnavailable {
    /// Returns the stable protocol code. It is the same for both: the session exists either way.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        ErrorCode::TerminalUnavailable
    }

    /// Returns this as the presentation error a created session is answered with.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(self.code(), self.to_string())
    }
}

/// Chooses the terminal a presented session opens in.
///
/// The order is the specification's, and it is a preference order rather than a fallback chain in
/// one respect: a profile that names an application this host does not have is an error, not an
/// invitation to open a different one. Somebody asked for that terminal.
///
/// # Errors
///
/// Returns [`TerminalUnavailable`] when the profile names something that is not installed, or when
/// nothing supported is available at all.
pub fn select(
    profile: Option<&str>,
    preference: Option<&str>,
    available: &[TerminalApplication],
) -> Result<Selection, TerminalUnavailable> {
    if let Some(requested) = profile {
        return available
            .iter()
            .find(|application| application.id == requested)
            .map(|application| Selection {
                application: application.clone(),
                source: Source::Profile,
            })
            .ok_or_else(|| TerminalUnavailable::ProfileMissing {
                requested: requested.to_owned(),
            });
    }
    if let Some(saved) = preference
        && let Some(application) = available.iter().find(|application| application.id == saved)
    {
        // A preference that names something no longer installed is not an error: nobody asked for
        // it just now, so detection carries on below.
        return Ok(Selection {
            application: application.clone(),
            source: Source::Preference,
        });
    }
    available
        .first()
        .map(|application| Selection {
            application: application.clone(),
            source: Source::Detected,
        })
        .ok_or(TerminalUnavailable::NoneAvailable)
}

/// Opens the chosen terminal application on a command.
///
/// The command is an argument vector, never a command line: nothing here is assembled by
/// interpolating text, and the one platform whose launcher re-parses what it is given quotes every
/// word of it before handing it over.
///
/// # Errors
///
/// Returns [`TerminalUnavailable::CouldNotOpen`] when the application is installed and no window
/// appeared.
#[cfg(target_vendor = "apple")]
pub fn open(selection: &Selection, command: &[String]) -> Result<(), TerminalUnavailable> {
    // `do script` hands its text to a shell, so every word of it is quoted here. The identifiers
    // are the host's own and the path is an executable's, but quoting a path that happens to
    // contain a space is not optional and neither is doing it in one place.
    let line = command
        .iter()
        .map(|word| shell_quoted(word))
        .collect::<Vec<_>>()
        .join(" ");
    let application = match selection.application.id.as_str() {
        "iterm2" => "iTerm",
        _ => "Terminal",
    };
    let script = format!(
        "tell application \"{application}\" to activate\n\
         tell application \"{application}\" to do script \"{}\"",
        line.replace('\\', "\\\\").replace('"', "\\\"")
    );
    let started = std::process::Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(&script)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match started {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(TerminalUnavailable::CouldNotOpen {
            application: selection.application.name.clone(),
            detail: format!("the script ended with {status}"),
        }),
        Err(error) => Err(TerminalUnavailable::CouldNotOpen {
            application: selection.application.name.clone(),
            detail: error.to_string(),
        }),
    }
}

/// Returns one word quoted for a shell that will re-parse it.
#[cfg(target_vendor = "apple")]
fn shell_quoted(word: &str) -> String {
    // Single quotes, with an embedded single quote closed, escaped and reopened. Nothing inside
    // single quotes is interpreted by the shell, so this is the whole rule.
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Opens the chosen terminal application on a command.
///
/// # Errors
///
/// Returns [`TerminalUnavailable::CouldNotOpen`] when the application is installed and no window
/// appeared.
#[cfg(all(unix, not(target_vendor = "apple")))]
pub fn open(selection: &Selection, command: &[String]) -> Result<(), TerminalUnavailable> {
    // Each launcher takes its own separator before the vector, and the vector is passed as
    // arguments rather than as a line a shell would re-parse.
    let separator = match selection.application.id.as_str() {
        "gnome-terminal" => "--",
        _ => "-e",
    };
    let mut arguments = vec![separator.to_owned()];
    arguments.extend_from_slice(command);
    std::process::Command::new(&selection.application.id)
        .args(&arguments)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|error| TerminalUnavailable::CouldNotOpen {
            application: selection.application.name.clone(),
            detail: error.to_string(),
        })
}

/// Opens the chosen terminal application on a command.
///
/// # Errors
///
/// Returns [`TerminalUnavailable::CouldNotOpen`] when the application is installed and no window
/// appeared.
#[cfg(not(unix))]
pub fn open(selection: &Selection, command: &[String]) -> Result<(), TerminalUnavailable> {
    let (program, prefix): (&str, &[&str]) = match selection.application.id.as_str() {
        "windows-terminal" => ("wt.exe", &[]),
        _ => ("cmd.exe", &["/c", "start", ""]),
    };
    let mut process = std::process::Command::new(program);
    process.args(prefix);
    process.args(command);
    process
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|error| TerminalUnavailable::CouldNotOpen {
            application: selection.application.name.clone(),
            detail: error.to_string(),
        })
}

/// Returns the terminals this host has, in the platform's own preference order.
#[must_use]
pub fn detect() -> Vec<TerminalApplication> {
    #[cfg(target_vendor = "apple")]
    {
        let mut found = Vec::new();
        for (id, name, path) in [
            ("iterm2", "iTerm2", "/Applications/iTerm.app"),
            (
                "apple-terminal",
                "Terminal",
                "/System/Applications/Utilities/Terminal.app",
            ),
            (
                "apple-terminal",
                "Terminal",
                "/Applications/Utilities/Terminal.app",
            ),
        ] {
            if std::path::Path::new(path).exists()
                && !found
                    .iter()
                    .any(|application: &TerminalApplication| application.id == id)
            {
                found.push(TerminalApplication {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    detail: path.to_owned(),
                });
            }
        }
        found
    }
    #[cfg(all(unix, not(target_vendor = "apple")))]
    {
        // A desktop terminal is opened through the configured desktop launcher. Without one there
        // is nothing to open a window with, whatever is installed.
        let Some(launcher) = executable_in_path("gio").or_else(|| executable_in_path("gtk-launch"))
        else {
            return Vec::new();
        };
        [
            "gnome-terminal",
            "konsole",
            "xfce4-terminal",
            "alacritty",
            "kitty",
            "xterm",
        ]
        .into_iter()
        .filter_map(|name| {
            executable_in_path(name).map(|path| TerminalApplication {
                id: name.to_owned(),
                name: name.to_owned(),
                detail: format!("{path} through {launcher}"),
            })
        })
        .collect()
    }
    #[cfg(not(unix))]
    {
        let mut found = Vec::new();
        if let Some(path) = executable_in_path("wt.exe") {
            found.push(TerminalApplication {
                id: "windows-terminal".to_owned(),
                name: "Windows Terminal".to_owned(),
                detail: path,
            });
        }
        // Every Windows installation can open a console window, so the list is never empty.
        found.push(TerminalApplication {
            id: "windows-console".to_owned(),
            name: "Console window".to_owned(),
            detail: "conhost".to_owned(),
        });
        found
    }
}

/// Returns the first executable of this name on `PATH`.
#[cfg(not(target_vendor = "apple"))]
fn executable_in_path(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn applications() -> Vec<TerminalApplication> {
        vec![
            TerminalApplication {
                id: "iterm2".to_owned(),
                name: "iTerm2".to_owned(),
                detail: "/Applications/iTerm.app".to_owned(),
            },
            TerminalApplication {
                id: "apple-terminal".to_owned(),
                name: "Terminal".to_owned(),
                detail: "/System/Applications/Utilities/Terminal.app".to_owned(),
            },
        ]
    }

    #[test]
    fn the_order_is_profile_then_preference_then_detection() {
        let available = applications();
        let chosen = select(Some("apple-terminal"), Some("iterm2"), &available).expect("chosen");
        assert_eq!(chosen.source, Source::Profile);
        assert_eq!(chosen.application.id, "apple-terminal");

        let chosen = select(None, Some("apple-terminal"), &available).expect("chosen");
        assert_eq!(chosen.source, Source::Preference);
        assert_eq!(chosen.application.id, "apple-terminal");

        let chosen = select(None, None, &available).expect("chosen");
        assert_eq!(chosen.source, Source::Detected);
        assert_eq!(chosen.application.id, "iterm2");
    }

    #[test]
    fn a_profile_that_names_something_missing_is_an_error_rather_than_a_substitution() {
        let error = select(Some("kitty"), Some("iterm2"), &applications()).expect_err("refused");
        assert_eq!(error.code(), ErrorCode::TerminalUnavailable);
        assert!(matches!(error, TerminalUnavailable::ProfileMissing { .. }));
    }

    #[test]
    fn a_stale_preference_falls_through_to_detection() {
        let chosen = select(None, Some("kitty"), &applications()).expect("chosen");
        assert_eq!(chosen.source, Source::Detected);
        assert_eq!(chosen.application.id, "iterm2");
    }

    #[test]
    fn a_host_with_no_terminal_says_so_once() {
        let error = select(None, None, &[]).expect_err("refused");
        assert_eq!(error, TerminalUnavailable::NoneAvailable);
        assert_eq!(error.code(), ErrorCode::TerminalUnavailable);
    }
}
