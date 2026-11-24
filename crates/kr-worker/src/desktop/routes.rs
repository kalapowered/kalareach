//! The closed table of routes the disclosed checks take, and what a check is given to take one.
//!
//! A route is one row: the check, the display server it is for, the program that performs it and
//! what a person at the machine can be asked while it runs. [`resolve`] is the one place a check
//! turns into an operation. The facility that performs the check, the line that names the tools a
//! check runs and the records a run produces all read its answer, so they cannot name different
//! tools. A check with no row is not performed and produces no record: the platform's own record
//! stands, and it says that no route is established.
//!
//! The table holds the macOS rows. A route for another platform is a row its own part adds, from
//! what was observed on a real machine of that platform.

use std::ffi::{OsStr, OsString};

use kr_protocol::desktop::{DesktopContext, DisplayServer};

use super::capability::installed_in;
use super::probe::Check;

/// What a person at the machine can be asked while an operation runs.
///
/// The words of an operation that did not answer in time follow it: a prompt that waits for the
/// person looks like a facility that does not answer, and only a route that has such a prompt may
/// say so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asking {
    /// The platform asks for a permission it grants per signed application.
    ForAGrant,
    /// Some compositors ask before a program may copy the screen, and this route may meet one.
    Maybe,
    /// Nothing on this route is known to ask.
    Never,
}

/// The name of a route and what it can ask.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// The route's name, which a record carries as the schema it speaks.
    pub name: &'static str,
    /// What the person can be asked on this route.
    pub asking: Asking,
}

/// What performs an operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Program {
    /// A program the platform installs, found at this absolute path.
    Tool(String),
    /// A program the route names that this host does not have.
    Absent,
    /// This worker program's own helper. A record names it by its route and carries no digest: the
    /// helper is the worker program, which the host agent's own identity already covers.
    Helper,
    /// A route that is recorded as what it is and never performed, in its own words.
    NotPerformed(&'static str),
}

/// One check, resolved to the route that performs it on this desktop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    /// The check.
    pub check: Check,
    /// The route it takes.
    pub route: Route,
    /// What performs it.
    pub program: Program,
    /// The application a launch starts, where the check starts one.
    pub target: Option<&'static str>,
}

/// One row of the table.
struct Row {
    check: Check,
    display_server: DisplayServer,
    route: Route,
    tool: &'static str,
    target: Option<&'static str>,
}

/// The routes this build knows.
const ROWS: [Row; 3] = [
    Row {
        check: Check::ScreenImage,
        display_server: DisplayServer::Quartz,
        route: Route {
            name: "macos-screen-capture",
            asking: Asking::ForAGrant,
        },
        tool: "/usr/sbin/screencapture",
        target: None,
    },
    Row {
        check: Check::AccessibleElement,
        display_server: DisplayServer::Quartz,
        route: Route {
            name: "macos-system-events",
            asking: Asking::ForAGrant,
        },
        tool: "/usr/bin/osascript",
        target: None,
    },
    Row {
        check: Check::ApplicationLaunch,
        display_server: DisplayServer::Quartz,
        route: Route {
            name: "macos-open-application",
            asking: Asking::ForAGrant,
        },
        tool: "/usr/bin/open",
        // The platform's own calculator: it is on every installation, it has no documents to
        // restore and no saved state to reopen, so a new hidden instance of it does nothing to
        // anything the person owns. An editor would have reopened whatever they last had open,
        // which is a check that changes what is on somebody's screen to find out whether it can.
        target: Some("Calculator"),
    },
];

/// Resolves a check to the operation that performs it on this desktop, where the table has a route
/// for it.
///
/// `search` is the search path a program given by a bare name is looked for in. `None` is a check
/// with no route on this desktop: it is not performed, it produces no record, and the platform's
/// record says that no route is established.
#[must_use]
pub fn resolve(
    check: Check,
    desktop: &DesktopContext,
    search: Option<&OsStr>,
) -> Option<Operation> {
    ROWS.iter()
        .find(|row| row.check == check && row.display_server == desktop.display_server)
        .map(|row| Operation {
            check,
            route: row.route,
            program: installed_in(row.tool, search).map_or(Program::Absent, Program::Tool),
            target: row.target,
        })
}

/// The route the file read takes, which is the same operation everywhere and has no program.
#[must_use]
pub const fn file_read_route(desktop: &DesktopContext) -> Route {
    Route {
        name: "authorised-file-read",
        asking: match desktop.display_server {
            DisplayServer::Quartz => Asking::ForAGrant,
            _ => Asking::Never,
        },
    }
}

/// The variables of this worker's own process that decide where a check acts.
///
/// A route reads these from the worker that performs it, never from the control daemon: the daemon
/// is a service with no display and no session bus of its own.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Variables {
    /// `DISPLAY`: the X11 display.
    pub display: Option<String>,
    /// `WAYLAND_DISPLAY`: the Wayland socket.
    pub wayland_display: Option<String>,
    /// `XAUTHORITY`: the file that holds the display's authority.
    pub authority: Option<String>,
    /// `DBUS_SESSION_BUS_ADDRESS`: the session bus.
    pub session_bus: Option<String>,
    /// `XDG_RUNTIME_DIR`: the login's runtime folder.
    pub runtime_dir: Option<String>,
    /// `PATH`: where a program given by a bare name is looked for.
    pub search: Option<OsString>,
}

impl Variables {
    /// The variables of the process this runs in.
    #[must_use]
    pub fn of_this_process() -> Self {
        let text = |name: &str| std::env::var_os(name).and_then(|value| value.into_string().ok());
        Self {
            display: text("DISPLAY"),
            wayland_display: text("WAYLAND_DISPLAY"),
            authority: text("XAUTHORITY"),
            session_bus: text("DBUS_SESSION_BUS_ADDRESS"),
            runtime_dir: text("XDG_RUNTIME_DIR"),
            search: std::env::var_os("PATH"),
        }
    }
}

/// The desktop a check acts on and the variables it acts with, read at one moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Surroundings {
    /// The execution context.
    pub desktop: DesktopContext,
    /// The worker's own variables.
    pub variables: Variables,
}

/// Where the checks read their surroundings from.
///
/// It is read before each operation and again after it, so that an operation is never reported as
/// a success for a desktop that was not there when it ended. A worker reads the platform; a test
/// scripts the readings.
pub trait ContextSource {
    /// Reads the surroundings now.
    fn read(&self) -> Surroundings;
}

impl<F: Fn() -> Surroundings> ContextSource for F {
    fn read(&self) -> Surroundings {
        self()
    }
}
