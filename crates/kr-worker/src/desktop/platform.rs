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
//! process, so two logins that happen to share a session number are told apart wherever the
//! platform starts that process afresh for each login, which macOS and Linux both do; the Windows
//! reader below says where that does not hold. And the
//! recheck is one kernel query about a recorded identity —
//! [`kr_ipc::identity::process_state`] — rather than another conversation with the platform's
//! session facilities. That matters because a live session asks the question on every wake of its
//! supervision, and a reading that cost a subprocess each time would spend more of a processor on
//! watching nothing happen than the whole host is allowed while idle.
//!
//! # Three answers, not two
//!
//! [`Reading`] separates *there is no graphical login* from *this host could not find out*. The
//! distinction decides whether a desktop-bound session closes: a platform that says the login
//! session has gone is a logout, and a platform that would not answer is an unknown, which leaves
//! the previous answer standing. A reading that cannot name the login-session generation is not a
//! desktop at all, because a platform session number without a generation cannot tell one login
//! from the next one to be given that number.

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

    /// Returns whether this reading names a graphical login session completely.
    ///
    /// Completely is the operative word. A reading with an identifier and no generation names a
    /// number that the platform may hand out again, and a desktop identity built on it would say a
    /// session created in one login belongs to the next.
    #[must_use]
    pub fn is_desktop(&self) -> bool {
        self.kind != DesktopSessionKind::None
            && self.platform_session.is_some()
            && self.generation.is_some()
    }
}

/// What a platform said when it was asked about this user's graphical login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// It described one.
    Desktop(Login),
    /// It answered, and this user has no graphical login session.
    None,
    /// It did not answer, so neither conclusion is established.
    Unavailable,
}

impl Reading {
    /// Returns the login this reading describes, where it describes one.
    #[must_use]
    pub const fn login(&self) -> Option<&Login> {
        match self {
            Self::Desktop(login) => Some(login),
            Self::None | Self::Unavailable => None,
        }
    }

    /// Returns the login this reading describes, or the empty one.
    #[must_use]
    pub fn login_or_none(&self) -> Login {
        self.login().cloned().unwrap_or_else(Login::none)
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

/// Asks whether a recorded login session's owning process is still running.
///
/// The recorded owning process is the question. A process identifier alone would be worthless —
/// the operating system reuses one within milliseconds — so the recorded start identity is
/// compared with it, which is what makes a new login's owning process a different answer rather
/// than the same one.
#[must_use]
pub fn presence(anchor: Option<&ProcessStartIdentity>) -> Presence {
    let Some(anchor) = anchor else {
        // Nothing was anchored, so nothing here can say. The caller asks the platform again
        // instead, on its own slower cadence.
        return Presence::Unknown;
    };
    match kr_ipc::identity::process_state(anchor) {
        kr_ipc::identity::ProcessState::Running => Presence::Present,
        // "Ended" from a comparison can mean two things: the process is gone or has been
        // replaced, or the platform described it with no start value at all, which is what a
        // reader that could not open the process returns. The second is not a death, so the
        // process is read again here and the whole identity compared.
        kr_ipc::identity::ProcessState::Ended => {
            let Ok(pid) = u32::try_from(anchor.pid.get()) else {
                return Presence::Ended;
            };
            match kr_ipc::identity::process_start_identity(pid) {
                // The same process after all: the first comparison was against a reading the
                // platform would not give.
                Ok(again) if &again == anchor => Presence::Present,
                // A reading with no start value is a process the platform would not describe.
                Ok(again) if again.start_value.get() == 0 => Presence::Unknown,
                Ok(_) => Presence::Ended,
                // The kernel answered once and not twice. Neither answer is established.
                Err(_) => Presence::Unknown,
            }
        }
        kr_ipc::identity::ProcessState::Unknown { .. } => Presence::Unknown,
    }
}

/// Reads the graphical login session this process's user currently has.
#[must_use]
pub fn read_login(uid: u32) -> Reading {
    implementation::read_login(uid)
}

/// Asks whether the login session a host recorded, named by the platform's own identifier, is
/// still there.
///
/// This is a different question from which login session the user has now, and it has to be.
/// Linux and Windows both let one user hold several login sessions at once, so a live desktop that
/// is not the recorded one says nothing about the recorded one: a session whose own login is still
/// running must never be recorded as having lost it, and a session whose login has ended must not
/// be excused because another login exists.
///
/// The recorded generation is compared where the platform gives one, which tells a reused session
/// number apart from the login that held it before, as far as the process that platform anchors on
/// allows.
#[must_use]
pub fn named_presence(session: &str, generation: Option<u64>, uid: u32) -> Presence {
    implementation::named_presence(session, generation, uid)
}

/// What running a platform command produced.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
enum Printed {
    /// It ran and succeeded.
    Output(String),
    /// It ran and reported a failure, with what it said about it.
    ///
    /// A failure is an answer only when the platform said which failure it was. A facility that
    /// could not reach its own service, or that refused for a reason of its own, has not
    /// established that a login session is gone, and treating it as though it had would close a
    /// live session.
    Failed(String),
    /// It could not be run at all, so the platform was never asked.
    NotRun,
}

/// Runs a platform command and says what came of it.
///
/// The difference between a command that failed and one that never ran is part of the distinction
/// [`Reading`] exists for; the other part is what a failure said. Nothing here interpolates text
/// into a command line: the argument vector is a vector.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn run(program: &str, arguments: &[&str]) -> Printed {
    let Ok(output) = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .output()
    else {
        return Printed::NotRun;
    };
    if output.status.success() {
        Printed::Output(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        let mut said = String::from_utf8_lossy(&output.stderr).into_owned();
        said.push_str(&String::from_utf8_lossy(&output.stdout));
        Printed::Failed(said.to_ascii_lowercase())
    }
}

/// Returns whether a platform's own words say the thing asked about is not there.
///
/// Only these answers are absence. Everything else a facility can fail with — a service it could
/// not reach, a permission it did not have, a version that does not know the question — leaves the
/// question open.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn says_absent(said: &str, absent: &[&str]) -> bool {
    absent.iter().any(|phrase| said.contains(phrase))
}

/// Reads the start identity of a login session's owning process.
///
/// A start value of zero is not a start value: it is what a platform reader returns when it could
/// not open the process. Treating it as a generation would give every unreadable process the same
/// one.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn anchor(pid: u32) -> Option<ProcessStartIdentity> {
    kr_ipc::identity::process_start_identity(pid)
        .ok()
        .filter(|identity| identity.start_value.get() > 0)
}

/// How many lines of a domain description are read before the header is taken to have ended.
///
/// The description continues with every service in the domain, which is hundreds of lines and
/// nothing this module wants. The fields it does want are at the top.
#[cfg(target_os = "macos")]
const HEADER_LINES: usize = 64;

#[cfg(target_os = "macos")]
mod implementation {
    use super::{Login, Presence, Printed, Reading, anchor, run};
    use kr_protocol::desktop::{
        DesktopAvailability, DesktopGenerationSource, DesktopSessionKind, DisplayServer,
    };

    /// Reads the user's Aqua login session through their graphical launchd domain.
    ///
    /// The domain is the login session: it exists while the user is logged in graphically, it
    /// carries the security session identifier as its handle, and it names the process that
    /// created it. A user with no graphical login has no such domain, and the command says so by
    /// failing.
    pub(super) fn read_login(uid: u32) -> Reading {
        let printed = match run("/bin/launchctl", &["print", &format!("gui/{uid}")]) {
            Printed::Output(printed) => printed,
            // The domain is not there, which is what a graphical logout leaves behind. Any other
            // failure is this host not finding out.
            Printed::Failed(said) => {
                return if super::says_absent(&said, DOMAIN_ABSENT) {
                    Reading::None
                } else {
                    Reading::Unavailable
                };
            }
            Printed::NotRun => return Reading::Unavailable,
        };
        let fields = super::domain_header(&printed);
        let Some(handle) = fields
            .iter()
            .find(|(key, _)| *key == "handle")
            .map(|(_, value)| (*value).to_owned())
        else {
            return Reading::Unavailable;
        };
        // `session = Aqua` is the domain saying it is the graphical one. A background domain
        // carries no desktop, and a session whose name this host does not recognise is not
        // presented as one.
        if !fields
            .iter()
            .any(|(key, value)| *key == "session" && *value == "Aqua")
        {
            return Reading::None;
        }
        let creator = fields
            .iter()
            .find(|(key, _)| *key == "creator")
            .and_then(|(_, value)| super::creator_pid(value));
        let anchored = creator.and_then(anchor);
        if anchored.is_none() {
            // The domain is there and the process that owns it is not readable, so this host
            // cannot name the generation. Half an identity is not one.
            return Reading::Unavailable;
        }
        Reading::Desktop(Login {
            kind: DesktopSessionKind::MacosSecuritySession,
            platform_session: Some(handle),
            generation: anchored.as_ref().map(|identity| identity.start_value.get()),
            generation_source: DesktopGenerationSource::MacosSessionCreator,
            anchor: anchored,
            graphic_access: true,
            // A macOS screen-sharing client joins the console user's own session rather than
            // creating a second one, so this host does not present an Aqua session as remote.
            remote: false,
            availability: availability(),
            display_server: DisplayServer::Quartz,
            compositor: Some("Aqua".to_owned()),
        })
    }

    /// Asks whether a recorded Aqua login session is still there.
    ///
    /// One user has at most one Aqua session at a time: the graphical domain is the user's own,
    /// and switching users gives the other account its own domain rather than this one a second
    /// session. So reading the domain for this user is a question about the recorded session, and
    /// a domain that carries another security session or another creator is that session gone.
    pub(super) fn named_presence(session: &str, generation: Option<u64>, uid: u32) -> Presence {
        match read_login(uid) {
            Reading::Desktop(live) => {
                let same_session = live.platform_session.as_deref() == Some(session);
                let same_generation = match (live.generation, generation) {
                    (Some(live), Some(recorded)) => live == recorded,
                    // Nothing recorded a generation to compare, so the session identifier is all
                    // there is to go on.
                    _ => true,
                };
                if same_session && same_generation {
                    Presence::Present
                } else {
                    Presence::Ended
                }
            }
            // The user has no graphical login at all, so the recorded one is not there either.
            Reading::None => Presence::Ended,
            Reading::Unavailable => Presence::Unknown,
        }
    }

    /// Reads whether the session's screen is locked.
    ///
    /// The window server publishes the lock state in the device registry while the screen is
    /// locked and publishes nothing while it is not, so an absent key is an answer rather than a
    /// failure. What it publishes is about the console session, so it is an answer about this
    /// session only while this session is the one at the console: with another user switched in,
    /// the reading describes their screen and this host says it does not know.
    fn availability() -> DesktopAvailability {
        if !at_the_console() {
            return DesktopAvailability::Unknown;
        }
        match run("/usr/sbin/ioreg", &["-n", "Root", "-d1", "-k", LOCK_KEY]) {
            Printed::Output(printed) => {
                if printed
                    .lines()
                    .any(|line| line.contains(LOCK_KEY) && line.contains("Yes"))
                {
                    DesktopAvailability::Locked
                } else {
                    DesktopAvailability::Available
                }
            }
            Printed::Failed(_) | Printed::NotRun => DesktopAvailability::Unknown,
        }
    }

    /// Returns whether this user is the one at the console.
    ///
    /// The console device belongs to the user whose session is at the machine's own screen, which
    /// is the session the registry's lock state is about.
    fn at_the_console() -> bool {
        let Ok(metadata) = std::fs::metadata("/dev/console") else {
            return false;
        };
        use std::os::unix::fs::MetadataExt as _;
        metadata.uid() == kr_ipc::paths::current_uid()
    }

    /// The device-registry key the window server publishes while the screen is locked.
    const LOCK_KEY: &str = "CGSSessionScreenIsLocked";

    /// What the service manager says when a graphical domain is not there.
    const DOMAIN_ABSENT: &[&str] = &[
        "could not find domain",
        "no such process",
        "domain does not",
    ];
}

#[cfg(target_os = "linux")]
mod implementation {
    use super::{Login, Presence, Printed, Reading, anchor, run};
    use kr_protocol::desktop::{
        DesktopAvailability, DesktopGenerationSource, DesktopSessionKind, DisplayServer,
    };

    /// Reads the user's graphical login session through the login manager.
    ///
    /// The login manager is asked rather than its private state files read: the files carry a
    /// notice not to parse them, and `loginctl` is the documented way to the same facts. The
    /// user's display session is the graphical one; this process's own session is used when the
    /// login manager names it, because a worker started inside a session belongs to that one.
    pub(super) fn read_login(uid: u32) -> Reading {
        let id = match session_id(uid) {
            Ok(Some(id)) => id,
            Ok(None) => return Reading::None,
            Err(()) => return Reading::Unavailable,
        };
        let printed = match run(
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
        ) {
            Printed::Output(printed) => printed,
            // The manager answered that it has no such session, which is what a logout leaves.
            // A manager that could not answer at all has established nothing.
            Printed::Failed(said) => {
                return if super::says_absent(&said, SESSION_ABSENT) {
                    Reading::None
                } else {
                    Reading::Unavailable
                };
            }
            Printed::NotRun => return Reading::Unavailable,
        };
        let fields = super::key_values(&printed);
        let field = |name: &str| {
            fields
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let display_server = match field("Type").unwrap_or_default().as_str() {
            "x11" => DisplayServer::X11,
            "wayland" => DisplayServer::Wayland,
            // A text login is not a desktop. Reporting it as one would offer a display that is
            // not there.
            "tty" | "" => return Reading::None,
            _ => DisplayServer::Unknown,
        };
        let anchored = field("Leader")
            .and_then(|value| value.parse::<u32>().ok())
            .and_then(anchor);
        if anchored.is_none() {
            // The session is there and its leader is not readable, so the generation cannot be
            // named and this reading is not an identity.
            return Reading::Unavailable;
        }
        let state = field("State").unwrap_or_default();
        let locked = field("LockedHint").is_some_and(|value| value == "yes");
        let active = field("Active").is_some_and(|value| value == "yes");
        Reading::Desktop(Login {
            kind: DesktopSessionKind::LinuxLogind,
            platform_session: Some(id),
            generation: anchored.as_ref().map(|identity| identity.start_value.get()),
            generation_source: DesktopGenerationSource::LinuxSessionLeader,
            anchor: anchored,
            graphic_access: true,
            remote: field("Remote").is_some_and(|value| value == "yes"),
            availability: super::availability(&state, locked, active),
            display_server,
            compositor: field("Desktop").filter(|value| !value.is_empty()),
        })
    }

    /// Asks whether a recorded login session is still there.
    ///
    /// The session is asked about by its own identifier, because this user can be logged in to
    /// several sessions at once and the one this host reads first is not necessarily the one being
    /// asked about. The manager saying it has no such session is a logout; a manager that could
    /// not answer establishes nothing.
    pub(super) fn named_presence(session: &str, generation: Option<u64>, _uid: u32) -> Presence {
        let printed = match run("loginctl", &["show-session", session, "--property=Leader"]) {
            Printed::Output(printed) => printed,
            Printed::Failed(said) => {
                return if super::says_absent(&said, SESSION_ABSENT) {
                    Presence::Ended
                } else {
                    Presence::Unknown
                };
            }
            Printed::NotRun => return Presence::Unknown,
        };
        let leader = super::key_values(&printed)
            .into_iter()
            .find(|(key, _)| key == "Leader")
            .and_then(|(_, value)| value.parse::<u32>().ok())
            .and_then(anchor);
        match (leader, generation) {
            // The session number came round again for another login: the session the manager
            // describes is led by a different process from the recorded one.
            (Some(live), Some(recorded)) if live.start_value.get() != recorded => Presence::Ended,
            (Some(_), _) => Presence::Present,
            // The session is described and its leader is not readable, so nothing is established.
            (None, _) => Presence::Unknown,
        }
    }

    /// Returns the graphical session identifier to read, or nothing when there is none.
    ///
    /// The error is the login manager not answering, which is a different thing from the user not
    /// having a graphical session.
    fn session_id(uid: u32) -> Result<Option<String>, ()> {
        if let Ok(own) = std::env::var("XDG_SESSION_ID")
            && !own.trim().is_empty()
        {
            return Ok(Some(own.trim().to_owned()));
        }
        match run(
            "loginctl",
            &["show-user", &uid.to_string(), "--property=Display"],
        ) {
            Printed::Output(printed) => Ok(super::key_values(&printed)
                .into_iter()
                .find(|(key, _)| key == "Display")
                .map(|(_, value)| value)
                .filter(|value| !value.is_empty())),
            // The manager has no record of this user, so the user has no session. Anything else
            // it failed with leaves the question open.
            Printed::Failed(said) => {
                if super::says_absent(&said, SESSION_ABSENT) {
                    Ok(None)
                } else {
                    Err(())
                }
            }
            Printed::NotRun => Err(()),
        }
    }

    /// What the login manager says when a user or a session is not there.
    const SESSION_ABSENT: &[&str] = &[
        "no such session",
        "no session",
        "no such user",
        "no such device or address",
        "not been found",
    ];
}

#[cfg(windows)]
mod implementation {
    use super::{Login, Presence, Printed, Reading, anchor, run};
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
    /// anchors the generation, which tells a session number reused by a later session apart from
    /// this one. It is a weaker generation than the other two platforms give: this host reads the
    /// logon process that owns the session, and does not establish that one is started for each
    /// authenticated sign-in, so a sign-out and a sign-in that kept both the session number and
    /// its logon process would read as the same desktop.
    pub(super) fn read_login(_uid: u32) -> Reading {
        let session = match own_session() {
            Ok(Some(session)) => session,
            Ok(None) => return Reading::None,
            Err(()) => return Reading::Unavailable,
        };
        // Session 0 is the service session. It has no desktop, and a worker started there is not
        // a desktop execution host whatever else is true of it.
        if session == 0 {
            return Reading::None;
        }
        let anchored = match logon_process(session) {
            Ok(Some(pid)) => anchor(pid),
            // No logon process owns that session, so it is not an interactive login.
            Ok(None) => return Reading::None,
            Err(()) => return Reading::Unavailable,
        };
        if anchored.is_none() {
            return Reading::Unavailable;
        }
        let remote = std::env::var("SESSIONNAME")
            .is_ok_and(|name| !name.eq_ignore_ascii_case("console") && !name.is_empty());
        Reading::Desktop(Login {
            kind: DesktopSessionKind::WindowsInteractive,
            platform_session: Some(session.to_string()),
            generation: anchored.as_ref().map(|identity| identity.start_value.get()),
            generation_source: DesktopGenerationSource::WindowsSessionLogon,
            anchor: anchored,
            graphic_access: true,
            remote,
            // Whether the session is attended, locked or disconnected is not something this host
            // reads, and an unlocked desktop is not something it may assume.
            availability: DesktopAvailability::Unknown,
            display_server: DisplayServer::WindowsDesktop,
            compositor: None,
        })
    }

    /// Asks whether a recorded interactive logon session is still there.
    ///
    /// The same account signs in to several sessions at once over a remote desktop connection and
    /// through user switching, so the session number is asked about directly rather than through
    /// the session this process happens to be in. A session number with no logon process is a
    /// sign-out.
    pub(super) fn named_presence(session: &str, generation: Option<u64>, _uid: u32) -> Presence {
        let Ok(number) = session.parse::<u32>() else {
            return Presence::Unknown;
        };
        match logon_process(number) {
            Ok(Some(pid)) => match (anchor(pid), generation) {
                (Some(live), Some(recorded)) if live.start_value.get() != recorded => {
                    Presence::Ended
                }
                (Some(_), _) => Presence::Present,
                (None, _) => Presence::Unknown,
            },
            // No logon process owns that session number, so that login has ended.
            Ok(None) => Presence::Ended,
            Err(()) => Presence::Unknown,
        }
    }

    /// Returns the session number this process runs in.
    fn own_session() -> Result<Option<u32>, ()> {
        match run(
            "tasklist",
            &[
                "/FI",
                &format!("PID eq {}", std::process::id()),
                "/FO",
                "CSV",
                "/NH",
            ],
        ) {
            Printed::Output(printed) => Ok(super::task_rows(&printed)
                .into_iter()
                .find_map(|row| row.session)),
            Printed::Failed(_) | Printed::NotRun => Err(()),
        }
    }

    /// Returns the identifier of the logon process that owns one session.
    fn logon_process(session: u32) -> Result<Option<u32>, ()> {
        match run(
            "tasklist",
            &[
                "/FI",
                &format!("IMAGENAME eq {LOGON_PROCESS}"),
                "/FO",
                "CSV",
                "/NH",
            ],
        ) {
            Printed::Output(printed) => Ok(super::task_rows(&printed)
                .into_iter()
                .find(|row| row.session == Some(session))
                .and_then(|row| row.pid)),
            Printed::Failed(_) | Printed::NotRun => Err(()),
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod implementation {
    use super::{Presence, Reading};

    /// A platform this host has no desktop reading for has no desktop.
    pub(super) const fn read_login(_uid: u32) -> Reading {
        Reading::None
    }

    /// A platform this host has no desktop reading for has nothing to ask about a session.
    pub(super) const fn named_presence(
        _session: &str,
        _generation: Option<u64>,
        _uid: u32,
    ) -> Presence {
        Presence::Unknown
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
    use super::{Login, Presence, presence};
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

    #[test]
    fn a_reading_with_no_generation_is_not_a_desktop() {
        let mut login = Login::none();
        login.kind = kr_protocol::desktop::DesktopSessionKind::LinuxLogind;
        login.platform_session = Some("2".to_owned());
        assert!(
            !login.is_desktop(),
            "a session number the platform may hand out again is not an identity"
        );
        login.generation = Some(7);
        assert!(login.is_desktop());
    }

    #[test]
    fn nothing_anchored_is_unknown_rather_than_ended() {
        assert_eq!(presence(None), Presence::Unknown);
    }

    #[test]
    fn a_process_that_is_gone_is_ended_and_this_one_is_present() {
        let own = kr_ipc::identity::current_process_start_identity().expect("this process");
        assert_eq!(presence(Some(&own)), Presence::Present);
        // The same identifier with a start value no process of this identifier has. The kernel
        // describes the process and the start value disagrees, which is the reuse case.
        let mut reused = own.clone();
        reused.start_value = kr_protocol::scalars::U64::new(own.start_value.get() + 1);
        assert_eq!(presence(Some(&reused)), Presence::Ended);
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
