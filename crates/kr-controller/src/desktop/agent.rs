//! Putting a worker in the selected desktop's session.
//!
//! A macOS job bootstrapped into the user's graphical domain is in the Aqua login session by
//! construction, so nothing has to be carried across. On Windows a worker is a child of this
//! daemon and runs in the logon session this daemon runs in, which is the only session this host
//! puts a worker in: choosing another one means starting the worker from an agent already inside
//! it, and the desktop-bound profile there is the daemon's own session rather than a selected one.
//!
//! Linux does need it. A user service manager started at boot — which is what a lingering user
//! has — has no display, no compositor socket and no session message bus, because those belong to
//! a graphical login that happened later. A worker started as a transient service of that manager
//! would inherit nothing and every desktop tool in the session would fail at its first call.
//!
//! So the graphical session's own environment is collected here and passed to the worker's unit.
//! The session's leader is asked first, because its environment is that session's by definition:
//! the user manager holds one environment for the whole user, which on a host with two concurrent
//! logins can describe either of them. The manager is the fallback, and what it offers is used
//! only when it says which session it describes and says the selected one; a listing attributed
//! to no session is not evidence about this one.
//!
//! What is passed to the unit is the whole of what it gets. Every other login-session handle is
//! removed from the environment the user manager would otherwise pass on, because a display this
//! host did not collect would still reach the worker from whichever login imported it.
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
/// Each one is a handle to something the login session publishes: the display, the compositor
/// socket, the display authority, the session message bus, the user's runtime directory and the
/// session's own identity. A worker that is missing one of them is in the login session and unable
/// to reach part of it.
///
/// It is the worker's own list rather than a second one. What is collected here is exactly what a
/// session's environment takes from its execution context, and two lists that drifted apart would
/// mean a variable collected and then discarded, or discarded and then missed.
pub const DESKTOP_VARIABLES: &[&str] = kr_worker::environment::DESKTOP_VARIABLES;

/// The desktop variable that belongs to the user rather than to one of the user's login sessions.
///
/// The runtime directory is the same directory for every login of one user, so it says nothing
/// about which desktop a value came from, and it carries the host's own socket paths as well as
/// the desktop's.
const USER_RUNTIME_DIRECTORY: &str = "XDG_RUNTIME_DIR";

/// Returns the desktop variables that belong to one login session.
///
/// These are the handles a worker must not inherit from a login this host did not select: each one
/// names that login's own display, authority, message bus or session. Removing them and then
/// putting the selected session's back is what makes the worker's context the selected desktop's
/// rather than the union of every login the user has.
#[must_use]
pub fn session_variables() -> Vec<&'static str> {
    DESKTOP_VARIABLES
        .iter()
        .copied()
        .filter(|name| *name != USER_RUNTIME_DIRECTORY)
        .collect()
}

/// Returns the desktop environment a worker of this profile is started with.
///
/// The selected session is the one this host read its desktop identity from, and it is passed in
/// rather than looked up again: a host where the same user is logged in twice has two graphical
/// sessions, and collecting the environment of the other one would start the worker on a desktop
/// this host did not select and does not describe.
///
/// A headless worker is started with none of it. That is not an omission: the profile exists to
/// outlive the graphical login, and a session carrying a display, a message bus and a runtime
/// directory belonging to a login it is not in would fail at the first tool that used one.
#[must_use]
pub fn environment(profile: WorkerProfile, selected: Option<&str>) -> Vec<(String, String)> {
    if profile != WorkerProfile::DesktopBound {
        return Vec::new();
    }
    let Some(selected) = selected else {
        // No session was selected, so there is none to collect the environment of.
        return Vec::new();
    };
    let mut variables = BTreeMap::new();
    for (name, value) in platform::desktop_environment(selected) {
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
    /// The leader's own environment is that session's by definition, so it is read first. The user
    /// manager holds one environment for the whole user rather than one per session, so what it
    /// offers is used only when it says which session it describes and says the selected one. A
    /// listing that attributes itself to nothing is not evidence about this session: on a host
    /// where the same user is logged in twice it is as likely to be the other login's display, and
    /// a worker given that would watch one desktop while its tools reached another.
    ///
    /// A session whose environment cannot be attributed is a worker started with no desktop
    /// handles, which its capability records then say. That is the honest answer, and it is a
    /// better one than a display belonging to a login this host did not select.
    pub(super) fn desktop_environment(session: &str) -> Vec<(String, String)> {
        let mut collected = Vec::new();
        if let Some(leader) = session_leader(session)
            && let Ok(block) = std::fs::read_to_string(format!("/proc/{leader}/environ"))
        {
            collected.extend(super::environ_pairs(&block));
        }
        if collected
            .iter()
            .any(|(name, _)| name == "DISPLAY" || name == "WAYLAND_DISPLAY")
        {
            return with_session(collected, session);
        }
        if let Some(printed) = output("systemctl", &["--user", "show-environment"]) {
            let offered = super::key_values(&printed);
            let names_this_session = offered
                .iter()
                .any(|(name, value)| name == "XDG_SESSION_ID" && value == session);
            if names_this_session {
                collected.extend(offered);
            }
        }
        with_session(collected, session)
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
    pub(super) const fn desktop_environment(_session: &str) -> Vec<(String, String)> {
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
            environment(WorkerProfile::HeadlessUser, Some("1")).is_empty(),
            "outliving the graphical login is what the profile is for"
        );
    }

    #[test]
    fn a_worker_with_no_selected_session_inherits_nothing_either() {
        assert!(
            environment(WorkerProfile::DesktopBound, None).is_empty(),
            "there is no session to collect the environment of"
        );
    }

    #[test]
    fn only_the_desktop_variables_are_carried() {
        for (name, _) in environment(WorkerProfile::DesktopBound, Some("1")) {
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
