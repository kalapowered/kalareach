//! What the login item's file holds: pure functions of a few values already read as text.
//!
//! Both renderers are compiled on macOS and on Linux, so every case of them runs on either.

use serde::{Deserialize, Serialize};

/// What kind of file the login item is on a system.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    /// A launch agent's property list, in `~/Library/LaunchAgents`.
    LaunchAgent,
    /// An autostart entry, in `${XDG_CONFIG_HOME:-~/.config}/autostart`.
    AutostartEntry,
}

kr_client::debug_as_name!(Kind);

impl Kind {
    /// The kind this system uses.
    pub(super) const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::LaunchAgent
        } else {
            Self::AutostartEntry
        }
    }

    /// The name of the directory the file is in.
    pub(super) const fn directory(self) -> &'static str {
        match self {
            Self::LaunchAgent => "LaunchAgents",
            Self::AutostartEntry => "autostart",
        }
    }

    /// The extension of the file's name.
    pub(super) const fn extension(self) -> &'static str {
        match self {
            Self::LaunchAgent => "plist",
            Self::AutostartEntry => "desktop",
        }
    }
}

/// The values a file is written from, each already read as text a path may be (see [`text`]).
pub(super) struct Parts<'a> {
    /// The label: the file's name without its extension.
    pub label: &'a str,
    /// The control daemon's program.
    pub program: &'a str,
    /// The runtime root, the daemon's `--runtime-dir`.
    pub runtime_root: &'a str,
    /// The state root, the daemon's `--state-dir`.
    pub state_root: &'a str,
    /// The environment's state directory, where the daemon runs.
    pub state_dir: &'a str,
    /// The environment's `controller.log`, where a launch agent's output goes.
    pub log: &'a str,
}

/// A path the file cannot hold exactly: the text of it, and the kind of file that refused it.
pub(super) struct Refused {
    /// The path.
    pub path: String,
    /// The kind of file.
    pub kind: Kind,
}

/// A path as the text a file names it by: UTF-8, absolute, with no control character and no space
/// at either end.
pub(super) fn text(path: &std::path::Path) -> Option<&str> {
    let text = path.to_str()?;
    (path.is_absolute() && !text.chars().any(char::is_control) && text.trim() == text)
        .then_some(text)
}

/// Writes the file for `kind`, or says which path it cannot hold.
pub(super) fn render(kind: Kind, parts: &Parts<'_>) -> Result<String, Refused> {
    match kind {
        Kind::LaunchAgent => Ok(plist(parts)),
        Kind::AutostartEntry => desktop_entry(parts),
    }
}

/// The comment a file carries, which says what wrote it and what takes it out.
const COMMENT: &str = "The KalaReach control daemon, started when you log in. kr host login-item \
                       install wrote this file and kr host login-item remove takes it out.";

fn escaped(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn plist(parts: &Parts<'_>) -> String {
    let string = |value: &str| format!("\t<string>{}</string>\n", escaped(value));
    let mut contents = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <!-- {COMMENT} -->\n\
         <plist version=\"1.0\">\n<dict>\n"
    );
    contents.push_str("\t<key>Label</key>\n");
    contents.push_str(&string(parts.label));
    contents.push_str("\t<key>ProgramArguments</key>\n\t<array>\n");
    for argument in [
        parts.program,
        "--runtime-dir",
        parts.runtime_root,
        "--state-dir",
        parts.state_root,
    ] {
        contents.push_str(&format!("\t{}", string(argument)));
    }
    contents.push_str("\t</array>\n");
    contents.push_str("\t<key>RunAtLoad</key>\n\t<true/>\n");
    contents.push_str("\t<key>KeepAlive</key>\n\t<false/>\n");
    contents.push_str("\t<key>LimitLoadToSessionType</key>\n");
    contents.push_str(&string("Aqua"));
    contents.push_str("\t<key>ProcessType</key>\n");
    contents.push_str(&string("Interactive"));
    contents.push_str("\t<key>WorkingDirectory</key>\n");
    contents.push_str(&string(parts.state_dir));
    contents.push_str("\t<key>Umask</key>\n\t<integer>63</integer>\n");
    contents.push_str("\t<key>StandardOutPath</key>\n");
    contents.push_str(&string(parts.log));
    contents.push_str("\t<key>StandardErrorPath</key>\n");
    contents.push_str(&string(parts.log));
    contents.push_str("</dict>\n</plist>\n");
    contents
}

/// Whether a value can stand in a Desktop Entry's `Exec` word, which is double-quoted, or in a
/// plain string value: none of the characters the quoting and the escapes give a meaning to.
fn entry_safe(value: &str) -> bool {
    !value.contains(['"', '`', '$', '\\', '%'])
}

/// Double-quotes one `Exec` word. Every word is quoted, every time, so no word depends on the
/// list of characters the specification reserves.
fn quote(word: &str) -> String {
    format!("\"{word}\"")
}

fn desktop_entry(parts: &Parts<'_>) -> Result<String, Refused> {
    let refused = |path: &str| Refused {
        path: path.to_owned(),
        kind: Kind::AutostartEntry,
    };
    // The specification says the executable's name or path may not hold an equals sign.
    if parts.program.contains('=') {
        return Err(refused(parts.program));
    }
    for value in [
        parts.program,
        parts.runtime_root,
        parts.state_root,
        parts.state_dir,
    ] {
        if !entry_safe(value) {
            return Err(refused(value));
        }
    }
    Ok(format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=KalaReach control daemon\n\
         Comment=Started when you log in. kr host login-item install wrote this file and kr host \
         login-item remove takes it out.\n\
         Exec={} {} {} {} {}\n\
         TryExec={}\n\
         Path={}\n\
         Terminal=false\n",
        quote(parts.program),
        quote("--runtime-dir"),
        quote(parts.runtime_root),
        quote("--state-dir"),
        quote(parts.state_root),
        parts.program,
        parts.state_dir,
    ))
}
