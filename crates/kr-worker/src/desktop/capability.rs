//! What may actually be done on a desktop, and how each answer was reached.
//!
//! Selecting a desktop is not evidence for anything. A session can be running in the user's own
//! graphical login and still be unable to take a screen image, because that needs an
//! operating-system permission granted per signed application, and the desktop selection does not
//! carry it. Section 3 says so outright, and this module is where that shows up as data: one
//! [`CapabilityRecord`] per capability, in the shared section 11 shape, each saying which state it
//! is in, what produced the answer and what a person is told when it is not available.
//!
//! # What a probe may do
//!
//! A probe here is bounded and disclosed, and it stays inside two rules from section 11: it never
//! mutates unrelated user data, and it declares its own effects. So the probes are platform
//! queries: is there a graphical login, which display server, is the facility installed and
//! executable, and what exactly is the facility. Nothing here changes a user's screen, clipboard
//! or input, and nothing here performs an operation that would ask the person at the machine for
//! an operating-system permission.
//!
//! That boundary is what the states are about. A platform query can refuse a capability outright:
//! there is no desktop, the tool is not installed, the screen is locked, this is a container.
//! What it cannot do is establish that a screen image can be taken or a keystroke delivered,
//! because on every platform the operation itself is the check. Those records therefore say
//! [`CapabilityState::NotTested`] and name what is missing: what establishes such a capability is
//! the tool in the session performing the operation, under the permissions the operating system
//! granted it.
//!
//! # What the display server changes
//!
//! On X11 a client that holds the display and its authority needs no further permission, so what
//! is left unestablished is only whether the display opens. On Wayland neither a screen image nor
//! synthetic input goes through the display server: capture is the compositor's own business and
//! injection needs a compositor-specific facility, so the answer depends on the compositor and the
//! tool together. A compositor that asks the user for a screen image each time is a
//! [`CapabilityState::PermissionRequired`] the platform itself establishes. That pair is what
//! [`decide_unix`] reads, and it is why two Linux hosts running the same distribution give
//! different answers.

use kr_protocol::desktop::{
    CapabilityEvidenceSource, CapabilityIdentity, CapabilityInvalidation, CapabilityRecord,
    CapabilityState, CapabilitySubject, DesktopAvailability, DesktopCapabilityReport,
    DesktopContext, DisplayServer, capabilities,
};
use kr_protocol::ids::{CapabilityId, CapabilityRevision, EnvironmentId, SessionId};
use kr_protocol::scalars::{Nullable, U64};

/// The version of the capability contracts this host writes records against.
pub const CAPABILITY_VERSION: u64 = 1;

/// What a capability answer came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The state.
    pub state: CapabilityState,
    /// What produced it.
    pub evidence: CapabilityEvidenceSource,
    /// What a person is told, when the capability is not available.
    pub reason: Option<String>,
    /// The facility the answer is about, where one was found.
    pub tool: Option<String>,
}

impl Answer {
    /// An answer that refuses a capability, for a stated reason.
    fn refused(
        state: CapabilityState,
        evidence: CapabilityEvidenceSource,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            state,
            evidence,
            reason: Some(reason.into()),
            tool: None,
        }
    }
}

/// Builds the capability report for one desktop.
///
/// The revision is the caller's: it advances when the evidence can have changed, which a new
/// login, a changed profile and a changed permission all do. Every record carries it, so a caller
/// holding an earlier record can see that what it read has been superseded rather than taking a
/// stale answer for a current one.
#[must_use]
pub fn report(
    environment_id: EnvironmentId,
    session_id: Option<SessionId>,
    desktop: DesktopContext,
    revision: CapabilityRevision,
) -> DesktopCapabilityReport {
    let observed_at_ms = kr_ipc::now_ms();
    let subject = CapabilitySubject {
        environment_id,
        desktop_session_id: desktop.desktop_session_id.clone(),
        session_id: Nullable(session_id),
        application: Nullable::null(),
        terminal: Nullable::null(),
    };
    // In capability-name order, which is the order the shared namespace reads in.
    let names = [
        capabilities::ACCESSIBILITY,
        capabilities::APPLICATION_LAUNCH,
        capabilities::DISPLAY_SERVER,
        capabilities::INPUT_INJECTION,
        capabilities::SCREEN_CAPTURE,
    ];
    let records = names
        .into_iter()
        .filter_map(|name| {
            let (answer, identity) = identified(name, answer(name, &desktop));
            let capability = CapabilityId::new(name).ok()?;
            Some(CapabilityRecord {
                capability,
                version: U64::new(CAPABILITY_VERSION),
                subject: subject.clone(),
                revision,
                state: answer.state,
                evidence_source: answer.evidence,
                identity: CapabilityIdentity {
                    version: Nullable(identity),
                    binary: Nullable(answer.tool),
                    package: Nullable::null(),
                    schema: Nullable::null(),
                    profile: Nullable::some(desktop.worker_profile),
                },
                invalidation: invalidation(name),
                disabled_reason: Nullable(answer.reason),
                observed_at_ms,
            })
        })
        .collect();
    DesktopCapabilityReport { desktop, records }
}

/// Returns an answer together with the identity of the facility it is about.
///
/// An answer about a facility this host cannot identify is not an answer. Section 11 requires the
/// record to name the exact thing the evidence is about, so that replacing the facility
/// invalidates it; a record that named a path and nothing else would go on describing whatever was
/// put there. So a facility that cannot be identified turns the answer into a refusal that says
/// so, and nothing is claimed about the capability.
///
/// A capability whose evidence does not turn on a binary identity has no file in it. The display
/// server is the one of those: the answer is about the server itself, which the platform names,
/// and there is no installed thing whose replacement could invalidate it.
fn identified(capability: &str, answer: Answer) -> (Answer, Option<String>) {
    if !invalidation(capability).contains(&CapabilityInvalidation::BinaryIdentity) {
        return (answer, None);
    }
    let Some(tool) = answer.tool.as_deref() else {
        return (answer, None);
    };
    match facility_identity(tool) {
        Some(identity) => (answer, Some(identity)),
        None => {
            let reason = format!(
                "this host could not identify {tool} within the work a diagnostic may do, so \
                 nothing about this capability is established"
            );
            (
                Answer {
                    state: CapabilityState::TemporarilyUnavailable,
                    evidence: CapabilityEvidenceSource::PlatformQuery,
                    reason: Some(reason),
                    tool: answer.tool,
                },
                None,
            )
        }
    }
}

/// Returns what invalidates one capability's evidence.
fn invalidation(capability: &str) -> Vec<CapabilityInvalidation> {
    let mut triggers = vec![
        CapabilityInvalidation::DesktopGeneration,
        CapabilityInvalidation::WorkerProfile,
    ];
    if capability != capabilities::DISPLAY_SERVER {
        triggers.push(CapabilityInvalidation::OsPermission);
        triggers.push(CapabilityInvalidation::BinaryIdentity);
    }
    triggers
}

/// Answers one capability for one desktop.
///
/// The context is asked first, and it can only refuse: a container, a context with no graphical
/// login and a desktop that is not usable right now each end the question before any facility is
/// looked for. Nothing here can turn a desktop selection into an available capability.
#[must_use]
pub fn answer(capability: &str, desktop: &DesktopContext) -> Answer {
    if let Some(refusal) = context_refusal(capability, desktop) {
        return refusal;
    }
    if capability == capabilities::DISPLAY_SERVER {
        return Answer {
            state: CapabilityState::QualifiedAvailable,
            evidence: CapabilityEvidenceSource::PlatformQuery,
            reason: None,
            tool: desktop
                .compositor
                .as_ref()
                .cloned()
                .or_else(|| Some(desktop.display_server.as_str().to_owned())),
        };
    }
    let tool = facility(capability, desktop.display_server);
    // Starting an application on a desktop this context is in needs no permission on any of these
    // platforms, so a present launcher settles it wherever the desktop is.
    if capability == capabilities::APPLICATION_LAUNCH {
        return match tool {
            Some(tool) => Answer {
                state: CapabilityState::QualifiedAvailable,
                evidence: CapabilityEvidenceSource::PlatformQuery,
                reason: None,
                tool: Some(tool),
            },
            None => Answer::refused(
                CapabilityState::MissingInstallation,
                CapabilityEvidenceSource::PlatformQuery,
                "no installed launcher on this host starts an application on this desktop",
            ),
        };
    }
    match desktop.display_server {
        DisplayServer::X11 | DisplayServer::Wayland | DisplayServer::Unknown => {
            decide_unix(capability, desktop, tool)
        }
        DisplayServer::Quartz => decide_macos(capability, tool),
        DisplayServer::WindowsDesktop => decide_windows(capability, tool),
        DisplayServer::None => Answer::refused(
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::PlatformQuery,
            "this execution context is not in a graphical login session, so there is no desktop \
             to act on",
        ),
    }
}

/// Returns the refusal the execution context itself produces, where there is one.
fn context_refusal(capability: &str, desktop: &DesktopContext) -> Option<Answer> {
    if !desktop.container.reaches_parent_desktop() {
        return Some(Answer::refused(
            CapabilityState::Incompatible,
            CapabilityEvidenceSource::PlatformQuery,
            format!(
                "this session runs in a {} with its own process namespace and its own display; it \
                 does not reach the desktop of the machine hosting it",
                desktop.container.as_str()
            ),
        ));
    }
    if !desktop.is_desktop() || !desktop.graphic_access {
        // What a headless context means differs by platform, and the record says which one this
        // is. Where the platform puts every one of a user's processes in that user's own
        // interactive session, a headless profile supplies no desktop handles and promises nothing
        // about the desktop, and it would be untrue to say the session cannot reach one.
        #[cfg(windows)]
        return Some(Answer::refused(
            CapabilityState::NotTested,
            CapabilityEvidenceSource::PlatformQuery,
            "this session is in the headless user profile, which supplies no desktop handles and \
             promises nothing about a desktop. This platform runs every one of a user's processes \
             in that user's own interactive session, so nothing here establishes that the desktop \
             cannot be reached either",
        ));
        #[cfg(not(windows))]
        return Some(Answer::refused(
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::PlatformQuery,
            "this execution context has no graphical login session's access, which is what the \
             headless profile means",
        ));
    }
    // A desktop that is there and not usable right now is a separate fact from the session's
    // processes, which keep running. Naming the display server is still answerable; acting on the
    // screen is not.
    if desktop.availability == DesktopAvailability::Locked
        && capability != capabilities::DISPLAY_SERVER
    {
        return Some(Answer::refused(
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::PlatformQuery,
            "the desktop is locked; the session and the processes it owns are unaffected",
        ));
    }
    if desktop.availability == DesktopAvailability::Ended {
        return Some(Answer::refused(
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::PlatformQuery,
            "the login session this desktop belonged to has ended",
        ));
    }
    None
}

/// The answer on macOS.
///
/// Launching an application needs no privacy permission, so a present facility settles it. Screen
/// capture, input injection and the accessibility tree each need one that is granted per signed
/// application. This host does not perform the operation that would establish it, and does not
/// read the platform's permission state, so the record names the permission and says that neither
/// answer has been established.
fn decide_macos(capability: &str, tool: Option<String>) -> Answer {
    let Some(tool) = tool else {
        return Answer::refused(
            CapabilityState::MissingInstallation,
            CapabilityEvidenceSource::PlatformQuery,
            "the platform facility this capability uses is not installed",
        );
    };
    if capability == capabilities::APPLICATION_LAUNCH {
        return Answer {
            state: CapabilityState::QualifiedAvailable,
            evidence: CapabilityEvidenceSource::PlatformQuery,
            reason: None,
            tool: Some(tool),
        };
    }
    let permission = match capability {
        capabilities::SCREEN_CAPTURE => "Screen & System Audio Recording",
        capabilities::INPUT_INJECTION | capabilities::ACCESSIBILITY => "Accessibility",
        _ => "a privacy permission",
    };
    Answer {
        state: CapabilityState::NotTested,
        evidence: CapabilityEvidenceSource::NotProbed,
        reason: Some(format!(
            "macOS grants {permission} per signed application. Nothing here has performed the \
             operation this capability is, and nothing here reads the permission itself, so this \
             is not established either way"
        )),
        tool: Some(tool),
    }
}

/// The answer on Windows.
///
/// A process attached to an interactive logon session can start an application there. Taking an
/// image of that session's screen, and sending it input, act on whatever is on the screen, so
/// nothing here does either.
fn decide_windows(capability: &str, tool: Option<String>) -> Answer {
    let Some(tool) = tool else {
        return Answer::refused(
            CapabilityState::MissingInstallation,
            CapabilityEvidenceSource::PlatformQuery,
            "the platform facility this capability uses is not installed",
        );
    };
    if capability == capabilities::APPLICATION_LAUNCH {
        return Answer {
            state: CapabilityState::QualifiedAvailable,
            evidence: CapabilityEvidenceSource::PlatformQuery,
            reason: None,
            tool: Some(tool),
        };
    }
    Answer {
        state: CapabilityState::NotTested,
        evidence: CapabilityEvidenceSource::NotProbed,
        reason: Some(
            "nothing here has taken an image of this session's screen or sent it input, and \
             neither is something to try on a screen somebody may be looking at, so this is not \
             established either way"
                .to_owned(),
        ),
        tool: Some(tool),
    }
}

/// The answer on a Unix desktop, which depends on the display server and the tool together.
///
/// X11 hands a client that holds the display and its authority everything, so what is left
/// unestablished there is only whether the display opens: the record says so and names the tool.
/// Wayland hands it nothing. Capture goes through the compositor's own portal, injection through a
/// compositor-specific facility, and a tool built for one compositor family does not work on
/// another, so the compositor is named beside the tool. A compositor that asks the user for the
/// operation each time is the one case the platform itself settles, and it settles it as a
/// permission the user grants rather than one a tool holds.
#[must_use]
pub fn decide_unix(capability: &str, desktop: &DesktopContext, tool: Option<String>) -> Answer {
    let compositor = desktop
        .compositor
        .as_ref()
        .map_or_else(String::new, |value| value.to_ascii_lowercase());
    let named_compositor = if compositor.is_empty() {
        "this compositor".to_owned()
    } else {
        compositor.clone()
    };
    match desktop.display_server {
        DisplayServer::X11 => match tool {
            Some(tool) if display_reachable() => Answer {
                state: CapabilityState::NotTested,
                evidence: CapabilityEvidenceSource::NotProbed,
                reason: Some(format!(
                    "X11 grants this to a client that holds the display and its authority, and \
                     this context holds both. Nothing here has opened the display with {tool}, so \
                     whether it opens is not established"
                )),
                tool: Some(tool),
            },
            Some(tool) => Answer {
                state: CapabilityState::PermissionRequired,
                evidence: CapabilityEvidenceSource::PlatformQuery,
                reason: Some(
                    "this context has no X11 display and authority, so it cannot reach the X \
                     server"
                        .to_owned(),
                ),
                tool: Some(tool),
            },
            None => Answer::refused(
                CapabilityState::MissingInstallation,
                CapabilityEvidenceSource::PlatformQuery,
                "no installed tool on this host serves this capability on X11",
            ),
        },
        DisplayServer::Wayland => match tool {
            Some(tool) => {
                let route = wayland_route(capability);
                let reason = match wayland_path(capability, &tool, &compositor) {
                    // The compositor implements the protocol this tool uses, so nothing stands in
                    // the way that a permission could remove. What is left is whether it works.
                    WaylandPath::Protocol => format!(
                        "{named_compositor} implements the protocol {tool} uses for {route}, so no \
                         per-use permission stands in the way. Nothing here has run it"
                    ),
                    // The tool does not go through the compositor at all.
                    WaylandPath::Device => format!(
                        "{tool} does not ask the compositor for {route}: it goes through its own \
                         service and the input devices, which need their own permission. Nothing \
                         here has run it"
                    ),
                    // Which route the pair takes is not something a name settles.
                    WaylandPath::Unqualified => format!(
                        "on Wayland {route} goes through the compositor rather than the display \
                         server, and whether {named_compositor} grants it to {tool} or asks the \
                         user for it each time is not established here"
                    ),
                };
                Answer {
                    state: CapabilityState::NotTested,
                    evidence: CapabilityEvidenceSource::NotProbed,
                    reason: Some(reason),
                    tool: Some(tool),
                }
            }
            None => Answer::refused(
                CapabilityState::MissingInstallation,
                CapabilityEvidenceSource::PlatformQuery,
                format!(
                    "no installed tool on this host serves this capability on {}",
                    if compositor.is_empty() {
                        "Wayland".to_owned()
                    } else {
                        compositor
                    }
                ),
            ),
        },
        _ => Answer::refused(
            CapabilityState::NotTested,
            CapabilityEvidenceSource::NotProbed,
            "this host did not name the display server of the login session, so nothing \
             establishes what may be done on it",
        ),
    }
}

/// Returns what a capability goes through on Wayland.
///
/// Naming it is the difference between an answer a person can act on and a shrug: a screen image
/// and a keystroke are refused by different parts of a Wayland desktop, and the fix for one is not
/// the fix for the other.
fn wayland_route(capability: &str) -> &'static str {
    match capability {
        capabilities::SCREEN_CAPTURE => "a screen image",
        capabilities::INPUT_INJECTION => "synthetic input",
        capabilities::ACCESSIBILITY => "the accessibility tree",
        _ => "this capability",
    }
}

/// How one tool reaches one capability on a Wayland desktop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WaylandPath {
    /// A Wayland protocol this compositor implements.
    Protocol,
    /// The tool's own service and the input devices, rather than the compositor.
    Device,
    /// Something this host cannot name from the compositor and the tool alone.
    Unqualified,
}

/// Returns how one tool would reach one capability on this compositor.
///
/// The routes a Wayland desktop offers are genuinely different, and which one a tool takes is a
/// property of the tool rather than of the capability: a permission prompt cannot supply a
/// protocol a compositor does not implement, and a tool that goes through the input devices is not
/// asking the compositor for anything at all.
///
/// The compositor alone does not settle it: the protocol route needs a compositor that implements
/// those protocols *and* a tool built against them, because a compositor that implements them does
/// nothing for a tool that asks its desktop's own service instead.
///
/// What this cannot do from a name is establish that a tool needs the user's permission each time.
/// A desktop's own capture service and its portal are different routes with the same command in
/// front of them, so the answer says the route is not established rather than blaming a
/// permission.
fn wayland_path(capability: &str, tool: &str, compositor: &str) -> WaylandPath {
    let tool = tool.rsplit('/').next().unwrap_or(tool);
    if DEVICE_TOOLS.iter().any(|known| tool.contains(known)) {
        return WaylandPath::Device;
    }
    if !wlroots(compositor) {
        return WaylandPath::Unqualified;
    }
    if capability == capabilities::ACCESSIBILITY {
        // The accessibility bus is not a Wayland protocol, so a compositor family says nothing
        // about it.
        return WaylandPath::Unqualified;
    }
    if !PROTOCOL_TOOLS.iter().any(|known| tool.contains(known)) {
        // The compositor family is qualified and this tool is not one built for it. A desktop's
        // own capture service and the portal are different routes, and which one this tool takes
        // is not something the compositor's name settles.
        return WaylandPath::Unqualified;
    }
    WaylandPath::Protocol
}

/// Tools that reach the input devices through their own service rather than the compositor.
const DEVICE_TOOLS: &[&str] = &["ydotool", "dotool"];

/// Tools built against the Wayland protocols the compositor family below implements.
///
/// The pair has to match, not just the compositor: a compositor that implements the screen-copy
/// and virtual-input protocols does nothing for a tool that asks its desktop's own service
/// instead. Naming both is what makes the answer about this host rather than about Wayland.
const PROTOCOL_TOOLS: &[&str] = &["grim", "grimblast", "wtype"];

/// Returns whether a compositor is one of the family whose protocols the protocol tools use.
///
/// These compositors implement the screen-copy and virtual-input protocols directly, so a tool
/// built against those protocols is not waiting on a permission. Both halves are checked: this
/// list is about the compositor and [`PROTOCOL_TOOLS`] is about the tool. A compositor that is not
/// on it leaves the answer unestablished rather than claimed either way.
fn wlroots(compositor: &str) -> bool {
    ["sway", "river", "hyprland", "wayfire", "labwc", "niri"]
        .iter()
        .any(|known| compositor.contains(known))
}

/// Returns whether this context holds an X11 display and its authority.
fn display_reachable() -> bool {
    std::env::var("DISPLAY").is_ok_and(|value| !value.trim().is_empty())
        && (std::env::var_os("XAUTHORITY").is_some() || std::env::var_os("HOME").is_some())
}

/// Returns the first installed facility that serves one capability on this display server.
fn facility(capability: &str, display_server: DisplayServer) -> Option<String> {
    candidates(capability, display_server)
        .iter()
        .find_map(|candidate| installed(candidate))
}

/// Returns the facilities that serve one capability, most specific first.
fn candidates(capability: &str, display_server: DisplayServer) -> &'static [&'static str] {
    match (capability, display_server) {
        (capabilities::SCREEN_CAPTURE, DisplayServer::Quartz) => &["/usr/sbin/screencapture"],
        (capabilities::SCREEN_CAPTURE, DisplayServer::X11) => {
            &["maim", "import", "scrot", "xwd", "spectacle"]
        }
        (capabilities::SCREEN_CAPTURE, DisplayServer::Wayland) => {
            &["grim", "grimblast", "spectacle", "gnome-screenshot"]
        }
        (capabilities::SCREEN_CAPTURE, DisplayServer::WindowsDesktop) => &["powershell.exe"],
        (capabilities::INPUT_INJECTION, DisplayServer::Quartz) => &["/usr/bin/osascript"],
        (capabilities::INPUT_INJECTION, DisplayServer::X11) => &["xdotool", "xte"],
        (capabilities::INPUT_INJECTION, DisplayServer::Wayland) => &["wtype", "ydotool", "dotool"],
        (capabilities::INPUT_INJECTION, DisplayServer::WindowsDesktop) => &["powershell.exe"],
        (capabilities::ACCESSIBILITY, DisplayServer::Quartz) => &["/usr/bin/osascript"],
        (capabilities::ACCESSIBILITY, DisplayServer::X11 | DisplayServer::Wayland) => {
            &["accerciser", "dbus-send"]
        }
        (capabilities::ACCESSIBILITY, DisplayServer::WindowsDesktop) => &["powershell.exe"],
        (capabilities::APPLICATION_LAUNCH, DisplayServer::Quartz) => &["/usr/bin/open"],
        (capabilities::APPLICATION_LAUNCH, DisplayServer::X11 | DisplayServer::Wayland) => {
            &["gio", "xdg-open"]
        }
        (capabilities::APPLICATION_LAUNCH, DisplayServer::WindowsDesktop) => &["cmd.exe"],
        _ => &[],
    }
}

/// Returns the absolute path of an installed facility, where one is installed and runnable.
///
/// A candidate given as an absolute path is checked where it is. A bare name is looked for in the
/// execution context's own search path, because a facility installed for the user is as real as
/// one installed for everybody, and the search path is part of the context the session runs in.
/// A file that is not executable is not a facility: it would fail at the first attempt to run it.
fn installed(candidate: &str) -> Option<String> {
    let path = std::path::Path::new(candidate);
    if path.is_absolute() {
        return runnable(path).then(|| candidate.to_owned());
    }
    let search = std::env::var_os("PATH")?;
    std::env::split_paths(&search)
        .map(|directory| directory.join(candidate))
        .find(|full| runnable(full))
        .map(|full| full.display().to_string())
}

/// Returns whether a path is a file this context could run.
fn runnable(path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Returns the identity of the file an answer was established about.
///
/// Section 11 requires the record to name the exact thing the answer was about, so that an
/// installed upgrade invalidates it rather than silently changing what the record describes. This
/// is the file's own contents, digested, together with the number of bytes digested: a replacement
/// at the same path is a different file here even when it kept the path, the length and the
/// timestamps.
///
/// The work is bounded twice over. The file is read a block at a time, so identifying it costs one
/// block of memory whatever its size, and the read stops once more than [`MAX_IDENTIFIED`] bytes
/// have been taken, so it reads at most that much plus the block that crossed the line. A file
/// with more than that in it has no identity here, and neither has one that cannot be read: both
/// are answered as the facility this host could not identify rather than as a facility described
/// by its metadata, because a length and a timestamp are what an installer keeps.
///
/// The bound is on the work and not on the clock, and that is deliberate rather than an omission.
/// How long reading those bytes takes is the filesystem's business, and a deadline would make the
/// answer depend on how busy the host was: a facility identified a moment ago and unidentifiable
/// now would advance the capability revision without anything about the facility having changed.
///
/// The digest is for noticing a change rather than for proving one: a capability record is
/// evidence about what is feasible, never authority, and nothing here signs it.
fn facility_identity(tool: &str) -> Option<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(tool).ok()?;
    let mut hasher = std::hash::DefaultHasher::new();
    let mut block = [0_u8; DIGEST_BLOCK];
    let mut digested: u64 = 0;
    loop {
        match file.read(&mut block) {
            Ok(0) => break,
            Ok(count) => {
                std::hash::Hasher::write(&mut hasher, &block[..count]);
                digested = digested.saturating_add(count as u64);
                if digested > MAX_IDENTIFIED {
                    return None;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(format!(
        "{digested} bytes, digest {:016x}",
        std::hash::Hasher::finish(&hasher)
    ))
}

/// How much of a facility is held in memory while it is being digested.
const DIGEST_BLOCK: usize = 64 * 1024;

/// The most of a facility this host reads to identify it.
///
/// Every facility in the table above is a few megabytes. Reading a bounded amount is what a
/// diagnostic can afford; reading a file that keeps growing is not, and a host that spent
/// unbounded time on a capability answer would be a host that stopped answering.
const MAX_IDENTIFIED: u64 = 64 * 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::desktop::{ContainerEnvironment, DesktopGenerationSource, DesktopSessionKind};
    use kr_protocol::identity::{BootIdentity, BootIdentitySource, WorkerProfile};
    use kr_protocol::ids::DesktopSessionId;
    use kr_protocol::scalars::{Bytes, Uuid};

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([5; 16]))
    }

    fn desktop(server: DisplayServer, compositor: Option<&str>) -> DesktopContext {
        DesktopContext {
            desktop_session_id: Nullable::some(
                DesktopSessionId::new("test:uid=1:session=1:generation=1:boot=00").expect("a name"),
            ),
            kind: DesktopSessionKind::LinuxLogind,
            platform_session: Nullable::some("1".to_owned()),
            login_generation: Nullable::some(U64::new(1)),
            generation_source: DesktopGenerationSource::LinuxSessionLeader,
            os_user: "someone".to_owned(),
            uid: Nullable::some(U64::new(1_000)),
            boot_identity: BootIdentity {
                source: BootIdentitySource::LinuxBootId,
                value: Bytes::new(vec![0]),
            },
            graphic_access: true,
            remote: false,
            availability: DesktopAvailability::Available,
            container: ContainerEnvironment::Host,
            display_server: server,
            compositor: Nullable(compositor.map(str::to_owned)),
            worker_profile: WorkerProfile::DesktopBound,
        }
    }

    fn headless() -> DesktopContext {
        let mut context = desktop(DisplayServer::None, None);
        context.desktop_session_id = Nullable::null();
        context.kind = DesktopSessionKind::None;
        context.platform_session = Nullable::null();
        context.graphic_access = false;
        context.worker_profile = WorkerProfile::HeadlessUser;
        context
    }

    #[test]
    fn selecting_a_desktop_never_reports_capture_or_injection_as_available() {
        let report = report(
            environment(),
            None,
            desktop(DisplayServer::Quartz, Some("Aqua")),
            CapabilityRevision::new(1),
        );
        for capability in [capabilities::SCREEN_CAPTURE, capabilities::INPUT_INJECTION] {
            let record = report.record(capability).expect("a record per capability");
            assert!(
                !record.state.is_available(),
                "{capability} was reported available on a desktop selection alone"
            );
            // Which refusal this is depends on whether the platform's own facility is installed
            // and identifiable, which differs between hosts: a facility this host identified
            // leaves the operation itself unestablished, and anything else is a refusal about the
            // facility. Neither of them is the capability being available on a desktop selection.
            assert_eq!(
                record.state == CapabilityState::NotTested,
                record.identity.version.is_present(),
                "{capability}: {record:?}"
            );
            assert_eq!(
                record.evidence_source == CapabilityEvidenceSource::NotProbed,
                record.identity.version.is_present(),
                "{capability}: {record:?}"
            );
            assert!(
                record.disabled_reason.is_present(),
                "{capability} says why it is unavailable"
            );
        }
        let server = report
            .record(capabilities::DISPLAY_SERVER)
            .expect("the display server is a capability of its own");
        assert!(server.state.is_available());
        // Launching an application on a desktop needs no permission on any of these platforms, so
        // the answer depends on the launcher: one this host found and identified is available, one
        // that is not installed is a missing installation, and one it found and could not identify
        // establishes nothing. Which of the three a host gives differs between hosts.
        let launch = report
            .record(capabilities::APPLICATION_LAUNCH)
            .expect("a record");
        assert!(
            matches!(
                launch.state,
                CapabilityState::QualifiedAvailable
                    | CapabilityState::MissingInstallation
                    | CapabilityState::TemporarilyUnavailable
            ),
            "{launch:?}"
        );
        assert_eq!(
            launch.state.is_available(),
            launch.identity.version.is_present(),
            "a launcher this host found and identified is the whole of that answer"
        );
    }

    /// A path of this test's own, in this host's temporary directory.
    fn temporary(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "kalareach-facility-{name}-{}-{}",
            std::process::id(),
            kr_ipc::now_ms().get()
        ))
    }

    #[test]
    fn a_facility_this_host_cannot_identify_establishes_nothing() {
        let asked = |tool: &str| {
            identified(
                capabilities::SCREEN_CAPTURE,
                Answer {
                    state: CapabilityState::NotTested,
                    evidence: CapabilityEvidenceSource::NotProbed,
                    reason: None,
                    tool: Some(tool.to_owned()),
                },
            )
        };

        // A facility this host can read within its bound is identified by its contents. The
        // fixture is a file of this test's own making, because the answer depends on the file's
        // size and a file that came from somewhere else could be any size.
        let small = temporary("small");
        std::fs::write(&small, b"a facility").expect("a file");
        let (answer, identity) = asked(&small.display().to_string());
        let _ = std::fs::remove_file(&small);
        assert_eq!(answer.state, CapabilityState::NotTested);
        let identity = identity.expect("a facility this host read has an identity");
        assert!(identity.contains("digest"), "{identity}");
        assert!(identity.contains("10 bytes"), "{identity}");

        // One it cannot read has no identity, and an answer about a facility with no identity
        // would be an answer about whatever is at that path later.
        let (answer, identity) = asked("/this/path/holds/no/facility");
        assert_eq!(answer.state, CapabilityState::TemporarilyUnavailable);
        assert!(identity.is_none());
        assert!(
            answer
                .reason
                .as_ref()
                .is_some_and(|reason| reason.contains("could not identify")),
            "{answer:?}"
        );

        // And one larger than this host reads to identify it is the same answer. The file is made
        // by its length rather than by writing to it, so the test costs the reading and nothing
        // else.
        let large = temporary("large");
        std::fs::File::create(&large)
            .expect("a file")
            .set_len(MAX_IDENTIFIED + 1)
            .expect("a length");
        let (answer, identity) = asked(&large.display().to_string());
        let _ = std::fs::remove_file(&large);
        assert_eq!(answer.state, CapabilityState::TemporarilyUnavailable);
        assert!(identity.is_none(), "{identity:?}");
    }

    #[test]
    fn a_container_says_it_cannot_control_the_desktop_of_the_machine_hosting_it() {
        for environment_kind in [ContainerEnvironment::Container, ContainerEnvironment::Wsl] {
            let mut context = desktop(DisplayServer::X11, Some("sway"));
            context.container = environment_kind;
            let report = report(environment(), None, context, CapabilityRevision::new(2));
            for record in &report.records {
                assert_eq!(
                    record.state,
                    CapabilityState::Incompatible,
                    "{} was not refused inside a {}",
                    record.capability,
                    environment_kind.as_str()
                );
                let reason = record
                    .disabled_reason
                    .as_ref()
                    .expect("a refusal says why")
                    .clone();
                assert!(
                    reason.contains("does not reach the desktop of the machine hosting it"),
                    "{reason}"
                );
            }
        }
    }

    #[test]
    fn a_headless_context_has_no_desktop_capability_at_all() {
        let report = report(environment(), None, headless(), CapabilityRevision::new(3));
        assert_eq!(
            report.records.len(),
            5,
            "every capability still has a record"
        );
        for record in &report.records {
            assert!(!record.state.is_available(), "{}", record.capability);
            // What a headless context means differs by platform: on one that keeps every one of a
            // user's processes in that user's own session, nothing establishes that the desktop
            // cannot be reached either, and the record says so instead of claiming it cannot.
            assert!(
                matches!(
                    record.state,
                    CapabilityState::TemporarilyUnavailable | CapabilityState::NotTested
                ),
                "{}: {:?}",
                record.capability,
                record.state
            );
            assert!(record.disabled_reason.is_present());
        }
    }

    #[test]
    fn a_locked_desktop_refuses_the_screen_and_keeps_the_session() {
        let mut context = desktop(DisplayServer::X11, Some("i3"));
        context.availability = DesktopAvailability::Locked;
        let report = report(environment(), None, context, CapabilityRevision::new(4));
        let capture = report
            .record(capabilities::SCREEN_CAPTURE)
            .expect("a record");
        assert_eq!(capture.state, CapabilityState::TemporarilyUnavailable);
        assert!(
            capture
                .disabled_reason
                .as_ref()
                .is_some_and(|reason| reason.contains("processes it owns are unaffected")),
            "a locked desktop is a separate fact from process life"
        );
        assert!(
            report
                .record(capabilities::DISPLAY_SERVER)
                .is_some_and(|record| record.state.is_available()),
            "the display server is still nameable while the screen is locked"
        );
    }

    #[test]
    fn the_linux_answer_distinguishes_x11_wayland_and_the_compositor_and_tool_pair() {
        // X11 with a tool present: the display server grants this to any client that holds the
        // display, so the only thing left is whether the display opens.
        let x11 = decide_unix(
            capabilities::INPUT_INJECTION,
            &desktop(DisplayServer::X11, Some("i3")),
            Some("/usr/bin/xdotool".to_owned()),
        );
        // Wayland on a compositor whose own protocols the tool uses.
        let wlroots = decide_unix(
            capabilities::INPUT_INJECTION,
            &desktop(DisplayServer::Wayland, Some("sway")),
            Some("/usr/bin/wtype".to_owned()),
        );
        // The same operation on a compositor whose route for it this host cannot name.
        let portal = decide_unix(
            capabilities::SCREEN_CAPTURE,
            &desktop(DisplayServer::Wayland, Some("GNOME")),
            Some("/usr/bin/gnome-screenshot".to_owned()),
        );
        // Wayland with nothing installed for it.
        let bare = decide_unix(
            capabilities::SCREEN_CAPTURE,
            &desktop(DisplayServer::Wayland, Some("KDE")),
            None,
        );

        // None of the four claims the capability is available: nothing here runs the operation.
        for answer in [&x11, &wlroots, &portal, &bare] {
            assert!(
                !answer.state.is_available(),
                "a tool on a disk is not a capability: {answer:?}"
            );
            assert!(answer.reason.is_some(), "{answer:?}");
        }
        // And each of the four says something different about why.
        assert_eq!(portal.state, CapabilityState::NotTested);
        assert!(
            portal
                .reason
                .as_ref()
                .is_some_and(|reason| reason.contains("gnome")
                    && reason.contains("screen image")
                    && reason.contains("not established")),
            "an answer a tool's name cannot settle names the compositor, the tool and the \
             operation, and says it is not established: {portal:?}"
        );
        assert_eq!(bare.state, CapabilityState::MissingInstallation);
        assert!(
            bare.reason
                .as_ref()
                .is_some_and(|reason| reason.contains("kde")),
            "{bare:?}"
        );
        assert_eq!(wlroots.state, CapabilityState::NotTested);
        assert!(
            wlroots
                .reason
                .as_ref()
                .is_some_and(|reason| reason.contains("sway")
                    && reason.contains("synthetic input")),
            "a wlroots answer names the compositor, the tool and the operation: {wlroots:?}"
        );
        // The X11 answer depends on whether this context holds a display, which a test host may
        // not. Both answers are about X11 and neither is the Wayland one.
        assert!(
            matches!(
                x11.state,
                CapabilityState::NotTested | CapabilityState::PermissionRequired
            ),
            "{x11:?}"
        );
        assert!(
            x11.reason
                .as_ref()
                .is_some_and(|reason| reason.contains("X11") || reason.contains("X server")),
            "an X11 answer says it is about X11: {x11:?}"
        );
    }

    #[test]
    fn every_record_names_what_makes_it_stale() {
        let report = report(
            environment(),
            None,
            desktop(DisplayServer::Quartz, Some("Aqua")),
            CapabilityRevision::new(9),
        );
        for record in &report.records {
            assert_eq!(record.revision, CapabilityRevision::new(9));
            assert!(
                record
                    .invalidation
                    .contains(&CapabilityInvalidation::DesktopGeneration),
                "a new login invalidates {}",
                record.capability
            );
            assert!(
                record
                    .invalidation
                    .contains(&CapabilityInvalidation::WorkerProfile),
                "a changed profile invalidates {}",
                record.capability
            );
            assert_eq!(
                record.identity.profile.as_ref().copied(),
                Some(WorkerProfile::DesktopBound),
                "the record says which profile it was established under"
            );
        }
        let capture = report
            .record(capabilities::SCREEN_CAPTURE)
            .expect("a record");
        assert!(
            capture
                .invalidation
                .contains(&CapabilityInvalidation::OsPermission),
            "a permission change invalidates a permission-gated capability"
        );
    }

    #[test]
    fn an_absolute_facility_is_checked_where_it_is() {
        assert!(installed("/definitely/not/here").is_none());
        assert!(installed("/bin/sh").is_some(), "this host has a shell");
    }
}
