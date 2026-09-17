//! Putting a worker in the selected desktop's session.
//!
//! Two of the three platforms do this for us. A macOS job bootstrapped into the user's graphical
//! domain is in the Aqua login session by construction, and a Windows worker started by the
//! per-user host agent is in the interactive logon session that agent runs in. Neither needs
//! anything carried across.
//!
//! Linux does need it. A user service manager started at boot — which is what a lingering user
//! has — has no display, no compositor socket and no session message bus, because those belong to
//! a graphical login that happened later. A worker started as a transient service of that manager
//! would inherit nothing and every desktop tool in the session would fail at its first call.
//!
//! So the graphical session's own environment is collected here and passed to the worker's unit.
//! The session's leader is asked first, because its environment is that session's by definition:
//! the user manager holds one environment for the whole user, which on a host with two concurrent
//! logins can describe either of them or neither. The manager is the fallback, and what it offers
//! is used only when it names the session this host selected or names no session at all.
//!
//! The selected session's own identifier travels with the rest, so the worker reads the session
//! this host chose rather than looking one up again.
//!
//! Nothing here enables anything. Lingering, in particular, is reported and never set: a session
//! that turned on a persistence setting as a side effect of being created would be exactly what
//! section 3 forbids.

use std::collections::BTreeMap;

use kr_protocol::identity::WorkerProfile;

/// The variables a graphical login session publishes that a desktop tool needs.
///
/// Each one is a handle to something that belongs to the login session: the display, the
/// compositor socket, the display authority, the session message bus, the session's runtime
/// directory and the session's own identity. A worker that is missing one of them is in the login
/// session and unable to reach part of it.
///
/// It is the worker's own list rather than a second one. What is collected here is exactly what a
/// session's environment takes from its execution context, and two lists that drifted apart would
/// mean a variable collected and then discarded, or discarded and then missed.
pub const DESKTOP_VARIABLES: &[&str] = kr_worker::environment::DESKTOP_VARIABLES;

/// Returns the desktop environment a worker of this profile is started with.
///
/// A headless worker is started with none of it. That is not an omission: the profile exists to
/// outlive the graphical login, and a session carrying a display, a message bus and a runtime
/// directory belonging to a login it is not in would fail at the first tool that used one.
#[must_use]
pub fn environment(profile: WorkerProfile) -> Vec<(String, String)> {
    if profile != WorkerProfile::DesktopBound {
        return Vec::new();
    }
    let mut variables = BTreeMap::new();
    for (name, value) in platform::desktop_environment() {
        if DESKTOP_VARIABLES.contains(&name.as_str()) && !value.is_empty() {
            variables.insert(name, value);
        }
    }
    variables.into_iter().collect()
}

/// Returns whether this user's per-user service manager keeps running after logout.
#[must_use]
pub fn lingering(uid: u32) -> bool {
    platform::lingering(uid)
}

/// Returns the `Key=Value` pairs of a printed property or environment listing.
#[cfg(target_os = "linux")]
fn key_values(printed: &str) -> Vec<(String, String)> {
    printed
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

/// Returns the pairs of a null-separated environment block.
#[cfg(target_os = "linux")]
fn environ_pairs(block: &str) -> Vec<(String, String)> {
    block
        .split('\0')
        .filter_map(|entry| entry.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
}

#[cfg(target_os = "linux")]
mod platform {
    /// Reads the graphical session's environment, from its leader and then the user manager.
    ///
    /// The leader's own environment is that session's, so it is read first. The user manager holds
    /// one environment for the user rather than one per session, so what it offers is accepted
    /// only when it names the selected session or names none at all: on a host where the same user
    /// is logged in twice, the manager can be describing the other login.
    pub(super) fn desktop_environment() -> Vec<(String, String)> {
        let Some(session) = display_session() else {
            return Vec::new();
        };
        let mut collected = Vec::new();
        if let Some(leader) = session_leader(&session)
            && let Ok(block) = std::fs::read_to_string(format!("/proc/{leader}/environ"))
        {
            collected.extend(super::environ_pairs(&block));
        }
        if collected
            .iter()
            .any(|(name, _)| name == "DISPLAY" || name == "WAYLAND_DISPLAY")
        {
            return with_session(collected, &session);
        }
        if let Some(printed) = output("systemctl", &["--user", "show-environment"]) {
            let offered = super::key_values(&printed);
            let names_another = offered.iter().any(|(name, value)| {
                name == "XDG_SESSION_ID" && !value.is_empty() && value != &session
            });
            if !names_another {
                collected.extend(offered);
            }
        }
        with_session(collected, &session)
    }

    /// Returns the collected environment with the selected session named in it.
    ///
    /// The worker reads its own desktop from the session this names, so a set that carried another
    /// session's identifier would have the worker bind to a desktop this host did not select.
    fn with_session(mut collected: Vec<(String, String)>, session: &str) -> Vec<(String, String)> {
        collected.retain(|(name, _)| name != "XDG_SESSION_ID");
        collected.push(("XDG_SESSION_ID".to_owned(), session.to_owned()));
        collected
    }

    /// Returns whether lingering is enabled for this user.
    pub(super) fn lingering(uid: u32) -> bool {
        output(
            "loginctl",
            &["show-user", &uid.to_string(), "--property=Linger"],
        )
        .is_some_and(|printed| {
            super::key_values(&printed)
                .iter()
                .any(|(key, value)| key == "Linger" && value == "yes")
        })
    }

    /// Returns this user's graphical session, as the login manager names it.
    fn display_session() -> Option<String> {
        let uid = kr_ipc::paths::current_uid();
        let printed = output(
            "loginctl",
            &["show-user", &uid.to_string(), "--property=Display"],
        )?;
        super::key_values(&printed)
            .into_iter()
            .find(|(key, _)| key == "Display")
            .map(|(_, value)| value)
            .filter(|value| !value.is_empty())
    }

    /// Returns the leader of one session.
    fn session_leader(session: &str) -> Option<u32> {
        let printed = output("loginctl", &["show-session", session, "--property=Leader"])?;
        super::key_values(&printed)
            .into_iter()
            .find(|(key, _)| key == "Leader")
            .and_then(|(_, value)| value.parse().ok())
    }

    /// Runs a command and returns what it printed, or nothing when it failed.
    fn output(program: &str, arguments: &[&str]) -> Option<String> {
        let output = std::process::Command::new(program)
            .args(arguments)
            .stdin(std::process::Stdio::null())
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    /// macOS and Windows place a per-user job in the login session that started it, so there is
    /// nothing to carry across.
    pub(super) const fn desktop_environment() -> Vec<(String, String)> {
        Vec::new()
    }

    /// Neither platform has a per-user service manager that outlives a logout, so there is no
    /// lingering to report.
    pub(super) const fn lingering(_uid: u32) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_headless_worker_inherits_no_desktop_variable() {
        assert!(
            environment(WorkerProfile::HeadlessUser).is_empty(),
            "outliving the graphical login is what the profile is for"
        );
    }

    #[test]
    fn only_the_desktop_variables_are_carried() {
        for (name, _) in environment(WorkerProfile::DesktopBound) {
            assert!(
                DESKTOP_VARIABLES.contains(&name.as_str()),
                "{name} is not one of the login session's handles"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn an_environment_block_and_a_property_listing_both_yield_their_pairs() {
        let block = environ_pairs("DISPLAY=:0\0XAUTHORITY=/run/user/1000/.mutter-Xwaylandauth\0");
        assert_eq!(block.len(), 2);
        assert!(block.contains(&("DISPLAY".to_owned(), ":0".to_owned())));
        let printed = key_values("DISPLAY=:0\nWAYLAND_DISPLAY=wayland-0\n");
        assert!(printed.contains(&("WAYLAND_DISPLAY".to_owned(), "wayland-0".to_owned())));
    }
}
