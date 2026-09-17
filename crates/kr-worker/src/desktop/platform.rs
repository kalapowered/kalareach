//! Reading one login session, on each platform, and asking cheaply whether it is still there.
//!
//! Every platform names a graphical login differently, and every platform has one process that
//! owns it. That process is the anchor of this module: it supplies the login-session generation
//! and it answers the question a desktop-bound session asks over and over.
//!
//! | Platform | The login session | Its owning process |
//! | --- | --- | --- |
//! | macOS | the Aqua security session behind the user's `gui` launchd domain | `loginwindow`, which the domain names as its creator |
//! | Linux | the login manager's session for this user's graphical login | the session's leader |
//! | Windows | the interactive logon session | that session's `winlogon` |
//!
//! Anchoring on a process buys two things. The generation is the kernel's own start value for that
//! process, so two logins that happen to share a session number are still told apart. And the
//! recheck is one kernel query about a recorded identity —
//! [`kr_ipc::identity::process_state`] — rather than another conversation with the platform's
//! session facilities. That matters because a live session asks the question on every wake of its
//! supervision, and a reading that cost a subprocess each time would spend more of a processor on
//! watching nothing happen than the whole host is allowed while idle.
//!
//! A reading the platform refuses to give is unknown, never death. A desktop-bound session is
//! closed only when the platform says the login session has ended.

use kr_protocol::desktop::{
    DesktopAvailability, DesktopGenerationSource, DesktopSessionKind, DisplayServer,
};
use kr_protocol::identity::ProcessStartIdentity;

/// One login session, as the platform describes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Login {
    /// Which platform facility named it.
    pub kind: DesktopSessionKind,
    /// The platform's own identifier for it.
    pub platform_session: Option<String>,
    /// The generation, from the owning process's start value.
    pub generation: Option<u64>,
    /// What the generation was read from.
    pub generation_source: DesktopGenerationSource,
    /// The process that owns the login session, where the platform names one.
    pub anchor: Option<ProcessStartIdentity>,
    /// Whether the session has graphical access.
    pub graphic_access: bool,
    /// Whether it is a remote login.
    pub remote: bool,
    /// Whether it is usable right now.
    pub availability: DesktopAvailability,
    /// The display server it presents.
    pub display_server: DisplayServer,
    /// The desktop environment or compositor it runs, where the platform names one.
    pub compositor: Option<String>,
}

impl Login {
    /// Returns the login of a context that is not in a graphical session.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            kind: DesktopSessionKind::None,
            platform_session: None,
            generation: None,
            generation_source: DesktopGenerationSource::Unavailable,
            anchor: None,
            graphic_access: false,
            remote: false,
            availability: DesktopAvailability::Unknown,
            display_server: DisplayServer::None,
            compositor: None,
        }
    }

    /// Returns whether this reading names a graphical login session.
    #[must_use]
    pub fn is_desktop(&self) -> bool {
        self.kind != DesktopSessionKind::None && self.platform_session.is_some()
    }
}

/// Whether a login session this host recorded is still the one that is there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Presence {
    /// It is still there.
    Present,
    /// It has ended. A desktop-bound session closes with `desktop_lost`.
    Ended,
    /// The platform did not answer. Neither conclusion is established.
    Unknown,
}

/// Asks whether a recorded login session is still present, cheaply.
///
/// The recorded owning process is the question. A process identifier alone would be worthless —
/// the operating system reuses one within milliseconds — so the recorded start identity is
/// compared with it, which is what makes a new login's owning process a different answer rather
/// than the same one.
#[must_use]
pub fn presence(login: &Login) -> Presence {
    let Some(anchor) = login.anchor.as_ref() else {
        // Nothing was anchored, so nothing here can say. A session with no anchor was never bound
        // to a desktop this host can watch, and `Watch` treats that as never lost rather than as
        // lost at once.
        return Presence::Unknown;
    };
    match kr_ipc::identity::process_state(anchor) {
        kr_ipc::identity::ProcessState::Running => Presence::Present,
        kr_ipc::identity::ProcessState::Ended => Presence::Ended,
        kr_ipc::identity::ProcessState::Unknown { .. } => Presence::Unknown,
    }
}

/// Reads the graphical login session this process's user currently has.
///
/// Returns [`Login::none`] where there is none, which is what a headless installation, an
/// SSH-only host and a container all read as.
#[must_use]
pub fn read_login(uid: u32) -> Login {
    implementation::read_login(uid)
}

/// Runs a platform command and returns what it printed, or nothing when it failed.
///
/// A platform facility that refuses to answer leaves the reading empty rather than producing a
/// guess. Nothing here interpolates text into a command line: the argument vector is a vector.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn output(program: &str, arguments: &[&str]) -> Option<String> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Reads the start identity of a login session's owning process.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn anchor(pid: u32) -> Option<ProcessStartIdentity> {
    kr_ipc::identity::process_start_identity(pid).ok()
}

/// How many lines of a domain description are read before the header is taken to have ended.
///
/// The description continues with every service in the domain, which is hundreds of lines and
/// nothing this module wants. The fields it does want are at the top.
#[cfg(target_os = "macos")]
const HEADER_LINES: usize = 64;

#[cfg(target_os = "macos")]
mod implementation {
    use super::{Login, anchor, output};
    use kr_protocol::desktop::{
        DesktopAvailability, DesktopGenerationSource, DesktopSessionKind, DisplayServer,
    };

    /// Reads the user's Aqua login session through their graphical launchd domain.
    ///
    /// The domain is the login session: it exists while the user is logged in graphically, it
    /// carries the security session identifier as its handle, and it names the process that
    /// created it. A user with no graphical login has no such domain, and the command says so by
    /// failing, which is the same answer this host gives for a headless installation.
    pub(super) fn read_login(uid: u32) -> Login {
        let Some(printed) = output("/bin/launchctl", &["print", &format!("gui/{uid}")]) else {
            return Login::none();
        };
        let fields = super::domain_header(&printed);
        let Some(handle) = fields
            .iter()
            .find(|(key, _)| *key == "handle")
            .map(|(_, value)| (*value).to_owned())
        else {
            return Login::none();
        };
        // `session = Aqua` is the domain saying it is the graphical one. A background domain
        // carries no desktop, and a session whose name this host does not recognise is not
        // presented as one.
        let graphic_access = fields
            .iter()
            .any(|(key, value)| *key == "session" && *value == "Aqua");
        if !graphic_access {
            return Login::none();
        }
        let creator = fields
            .iter()
            .find(|(key, _)| *key == "creator")
            .and_then(|(_, value)| super::creator_pid(value));
        let anchored = creator.and_then(anchor);
        Login {
            kind: DesktopSessionKind::MacosSecuritySession,
            platform_session: Some(handle),
            generation: anchored.as_ref().map(|identity| identity.start_value.get()),
            generation_source: if anchored.is_some() {
                DesktopGenerationSource::MacosSessionCreator
            } else {
                DesktopGenerationSource::Unavailable
            },
            anchor: anchored,
            graphic_access: true,
            // A macOS screen-sharing client joins the console user's own session rather than
            // creating a second one, so this host does not present an Aqua session as remote.
            remote: false,
            // The Aqua session exists, which is what a bound session depends on. macOS publishes
            // no lock state this host can read without involving the person at the machine, so a
            // locked desktop reads as present here: its session and processes keep running, which
            // is what the distinction between availability and process life is for.
            availability: DesktopAvailability::Available,
            display_server: DisplayServer::Quartz,
            compositor: Some("Aqua".to_owned()),
        }
    }
}

#[cfg(target_os = "linux")]
mod implementation {
    use super::{Login, anchor, output};
    use kr_protocol::desktop::{
        DesktopAvailability, DesktopGenerationSource, DesktopSessionKind, DisplayServer,
    };

    /// Reads the user's graphical login session through the login manager.
    ///
    /// The login manager is asked rather than its private state files read: the files carry a
    /// notice not to parse them, and `loginctl` is the documented way to the same facts. The
    /// user's display session is the graphical one; this process's own session is used when the
    /// login manager names it, because a worker started inside a session belongs to that one.
    pub(super) fn read_login(uid: u32) -> Login {
        let Some(id) = session_id(uid) else {
            return Login::none();
        };
        let Some(printed) = output(
            "loginctl",
            &[
                "show-session",
                &id,
                "--property=Type",
                "--property=Class",
                "--property=State",
                "--property=Remote",
                "--property=LockedHint",
                "--property=Active",
                "--property=Leader",
                "--property=Desktop",
                "--property=Name",
            ],
        ) else {
            return Login::none();
        };
        let fields = super::key_values(&printed);
        let field = |name: &str| {
            fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let kind = field("Type").unwrap_or_default();
        let display_server = match kind.as_str() {
            "x11" => DisplayServer::X11,
            "wayland" => DisplayServer::Wayland,
            // A text login is not a desktop. Reporting it as one would offer a display that is
            // not there.
            "tty" | "" => return Login::none(),
            _ => DisplayServer::Unknown,
        };
        let anchored = field("Leader")
            .and_then(|value| value.parse::<u32>().ok())
            .and_then(anchor);
        let state = field("State").unwrap_or_default();
        let locked = field("LockedHint").is_some_and(|value| value == "yes");
        let active = field("Active").is_some_and(|value| value == "yes");
        Login {
            kind: DesktopSessionKind::LinuxLogind,
            platform_session: Some(id),
            generation: anchored.as_ref().map(|identity| identity.start_value.get()),
            generation_source: if anchored.is_some() {
                DesktopGenerationSource::LinuxSessionLeader
            } else {
                DesktopGenerationSource::Unavailable
            },
            anchor: anchored,
            graphic_access: true,
            remote: field("Remote").is_some_and(|value| value == "yes"),
            availability: super::availability(&state, locked, active),
            display_server,
            compositor: field("Desktop").filter(|value| !value.is_empty()),
        }
    }

    /// Returns the graphical session identifier to read.
    fn session_id(uid: u32) -> Option<String> {
        if let Ok(own) = std::env::var("XDG_SESSION_ID")
            && !own.trim().is_empty()
        {
            return Some(own.trim().to_owned());
        }
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
}

#[cfg(windows)]
mod implementation {
    use super::{Login, anchor, output};
    use kr_protocol::desktop::{
        DesktopAvailability, DesktopGenerationSource, DesktopSessionKind, DisplayServer,
    };

    /// The process every interactive logon session owns.
    const LOGON_PROCESS: &str = "winlogon.exe";

    /// Reads the interactive logon session this process runs in.
    ///
    /// The session number is what matters and the account name is not enough: the same account
    /// signs in to different sessions over a remote desktop connection and through user
    /// switching, and a worker belongs to exactly one of them. The session's own logon process
    /// anchors the generation, so a reused session number after a sign-out is a different desktop.
    pub(super) fn read_login(_uid: u32) -> Login {
        let Some(session) = own_session() else {
            return Login::none();
        };
        let remote = std::env::var("SESSIONNAME")
            .is_ok_and(|name| !name.eq_ignore_ascii_case("console") && !name.is_empty());
        // Session 0 is the service session. It has no desktop, and a worker started there is not
        // a desktop execution host whatever else is true of it.
        if session == 0 {
            return Login::none();
        }
        let anchored = logon_process(session).and_then(anchor);
        Login {
            kind: DesktopSessionKind::WindowsInteractive,
            platform_session: Some(session.to_string()),
            generation: anchored.as_ref().map(|identity| identity.start_value.get()),
            generation_source: if anchored.is_some() {
                DesktopGenerationSource::WindowsSessionLogon
            } else {
                DesktopGenerationSource::Unavailable
            },
            anchor: anchored,
            graphic_access: true,
            remote,
            availability: DesktopAvailability::Available,
            display_server: DisplayServer::WindowsDesktop,
            compositor: None,
        }
    }

    /// Returns the session number this process runs in.
    fn own_session() -> Option<u32> {
        let printed = output(
            "tasklist",
            &[
                "/FI",
                &format!("PID eq {}", std::process::id()),
                "/FO",
                "CSV",
                "/NH",
            ],
        )?;
        super::task_rows(&printed)
            .into_iter()
            .find_map(|row| row.session)
    }

    /// Returns the identifier of the logon process that owns one session.
    fn logon_process(session: u32) -> Option<u32> {
        let printed = output(
            "tasklist",
            &[
                "/FI",
                &format!("IMAGENAME eq {LOGON_PROCESS}"),
                "/FO",
                "CSV",
                "/NH",
            ],
        )?;
        super::task_rows(&printed)
            .into_iter()
            .find(|row| row.session == Some(session))
            .and_then(|row| row.pid)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod implementation {
    use super::Login;

    /// A platform this host has no desktop reading for has no desktop.
    pub(super) const fn read_login(_uid: u32) -> Login {
        Login::none()
    }
}

/// Returns the single-depth fields of a printed domain description.
///
/// Only the header is read, and only its own fields: a nested block's contents are indented
/// further and a field whose value opens a block carries nothing this module wants.
#[cfg(target_os = "macos")]
fn domain_header(printed: &str) -> Vec<(&str, &str)> {
    printed
        .lines()
        .take(HEADER_LINES)
        .filter_map(|line| {
            let field = line.strip_prefix('\t')?;
            if field.starts_with('\t') {
                return None;
            }
            let (key, value) = field.split_once(" = ")?;
            (value != "{").then_some((key.trim(), value.trim()))
        })
        .collect()
}

/// Returns the process identifier a domain's creator field names.
///
/// The field reads `loginwindow[606]`: a program and the process it ran as.
#[cfg(target_os = "macos")]
fn creator_pid(creator: &str) -> Option<u32> {
    let (_, rest) = creator.rsplit_once('[')?;
    rest.trim_end_matches(']').parse().ok()
}

/// Returns the `Key=Value` pairs of a printed property listing.
#[cfg(target_os = "linux")]
fn key_values(printed: &str) -> Vec<(String, String)> {
    printed
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

/// Returns what a login manager's state means for a desktop's availability.
///
/// The three answers are different facts. A session that is closing is going away, and a
/// desktop-bound worker in it is about to lose its desktop. A session that is locked, or that a
/// user switch has moved out of the foreground, is still there: nothing about its processes
/// changes, which is why availability is reported separately from process life.
#[cfg(target_os = "linux")]
fn availability(state: &str, locked: bool, active: bool) -> DesktopAvailability {
    match state {
        "closing" => DesktopAvailability::Ended,
        "active" | "online" | "opening" => {
            if locked {
                DesktopAvailability::Locked
            } else if active {
                DesktopAvailability::Available
            } else {
                DesktopAvailability::Background
            }
        }
        _ => DesktopAvailability::Unknown,
    }
}

/// One row of a printed task listing.
#[cfg(windows)]
struct TaskRow {
    /// The process identifier.
    pid: Option<u32>,
    /// The session the process runs in.
    session: Option<u32>,
}

/// Returns the rows of a comma-separated task listing.
///
/// The columns are the image name, the process identifier, the session name, the session number
/// and the memory use. Quoted fields are unwrapped; a row that does not have the columns this
/// module needs contributes nothing.
#[cfg(windows)]
fn task_rows(printed: &str) -> Vec<TaskRow> {
    printed
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let columns: Vec<&str> = line
                .split("\",\"")
                .map(|column| column.trim_matches('"').trim())
                .collect();
            TaskRow {
                pid: columns.get(1).and_then(|value| value.parse().ok()),
                session: columns.get(3).and_then(|value| value.parse().ok()),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    use super::{creator_pid, domain_header};

    #[cfg(target_os = "macos")]
    const PRINTED_DOMAIN: &str = "gui/501 = {\n\
         \ttype = login\n\
         \thandle = 100019\n\
         \tactive count = 450\n\
         \tcreator = loginwindow[606]\n\
         \tcreator euid = 0\n\
         \tsession = Aqua\n\
         \tsecurity context = {\n\
         \t\tuid = 501\n\
         \t\tasid = 100019\n\
         \t}\n\
         \tservices = {\n\
         \t\t0\tcom.apple.example\n\
         \t}\n\
         }\n";

    #[cfg(target_os = "macos")]
    #[test]
    fn the_domain_header_yields_the_session_and_its_creator() {
        let fields = domain_header(PRINTED_DOMAIN);
        assert_eq!(
            fields
                .iter()
                .find(|(key, _)| *key == "handle")
                .map(|(_, value)| *value),
            Some("100019")
        );
        assert_eq!(
            fields
                .iter()
                .find(|(key, _)| *key == "session")
                .map(|(_, value)| *value),
            Some("Aqua")
        );
        assert!(
            !fields.iter().any(|(key, _)| *key == "uid"),
            "a nested block's fields are not the domain's own"
        );
        assert!(
            !fields.iter().any(|(_, value)| *value == "{"),
            "a field that opens a block carries no value"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_creator_field_names_the_process_that_owns_the_login() {
        assert_eq!(creator_pid("loginwindow[606]"), Some(606));
        assert_eq!(creator_pid("launchd[1]"), Some(1));
        assert_eq!(creator_pid("loginwindow"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_locked_or_switched_away_session_is_still_there_and_a_closing_one_is_not() {
        use super::availability;
        use kr_protocol::desktop::DesktopAvailability;

        assert_eq!(
            availability("active", false, true),
            DesktopAvailability::Available
        );
        assert_eq!(
            availability("active", true, true),
            DesktopAvailability::Locked
        );
        assert_eq!(
            availability("online", false, false),
            DesktopAvailability::Background
        );
        assert_eq!(
            availability("closing", false, false),
            DesktopAvailability::Ended
        );
        assert!(availability("active", true, true).is_present());
        assert!(!availability("closing", false, false).is_present());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_property_listing_yields_its_pairs() {
        let fields = super::key_values("Type=wayland\nLeader=1234\nDesktop=GNOME\n");
        assert_eq!(fields.len(), 3);
        assert!(fields.contains(&("Type".to_owned(), "wayland".to_owned())));
        assert!(fields.contains(&("Leader".to_owned(), "1234".to_owned())));
    }

    #[cfg(windows)]
    #[test]
    fn a_task_listing_yields_the_session_a_process_runs_in() {
        let rows = super::task_rows(
            "\"winlogon.exe\",\"968\",\"Console\",\"1\",\"12,345 K\"\n\
             \"winlogon.exe\",\"4242\",\"RDP-Tcp#3\",\"3\",\"11,000 K\"\n",
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pid, Some(968));
        assert_eq!(rows[0].session, Some(1));
        assert_eq!(rows[1].session, Some(3));
    }
}
