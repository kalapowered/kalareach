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
//! queries — is there a graphical login, which display server, is the facility installed — and
//! nothing that changes a user's screen, clipboard or input.
//!
//! That is a deliberate boundary rather than a shortcut. On macOS the check that would establish
//! screen capture *is* a capture, and the first capture by a program without the permission asks
//! the person at the machine for it. A background probe must not do that on its own, so the record
//! says [`CapabilityState::NotTested`] and names the permission. The setup assistant runs those
//! checks with the person present, and its result replaces this one.
//!
//! # Where an answer is real
//!
//! On X11, a client holding the display and its authority may capture and inject without a further
//! permission, so a present tool is a complete answer. On Wayland neither goes through the display
//! server: capture is the compositor's own business and injection needs a compositor-specific
//! facility, so the answer depends on the compositor and the tool together. That pair is what
//! [`decide_unix`] reads, and it is why two Linux hosts running the same distribution can give
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
/// login, a changed profile and a changed permission all do. Every record carries it, and an
/// action rechecks it rather than trusting a record it read earlier.
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
            let answer = answer(name, &desktop);
            let capability = CapabilityId::new(name).ok()?;
            Some(CapabilityRecord {
                capability,
                version: U64::new(CAPABILITY_VERSION),
                subject: subject.clone(),
                revision,
                state: answer.state,
                evidence_source: answer.evidence,
                identity: CapabilityIdentity {
                    binary: Nullable(answer.tool),
                    version: Nullable::null(),
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
/// application, and the check that would establish it is the operation itself: performing it is
/// what asks the person at the machine. So the record names the permission and says nothing has
/// established either answer.
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
            "macOS grants {permission} per signed application, and the check that would establish \
             it asks the person at this machine; the setup assistant runs it with them present"
        )),
        tool: Some(tool),
    }
}

/// The answer on Windows.
///
/// A process attached to an interactive logon session can start an application there. Taking an
/// image of that session's screen, and sending it input, are checks that belong with the person
/// present: an unattended probe would act on whatever is on the screen.
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
            "nothing has taken an image of this session's screen or sent it input; the setup \
             assistant runs that check in the session with the person present"
                .to_owned(),
        ),
        tool: Some(tool),
    }
}

/// The answer on a Unix desktop, which depends on the display server and the tool together.
///
/// X11 hands a client that holds the display and its authority everything, so a present tool is
/// the whole answer. Wayland hands it nothing: capture goes through the compositor's own portal,
/// injection through a compositor-specific facility, and a tool built for one compositor family
/// does not work on another. That is why the record names the compositor beside the tool.
#[must_use]
pub fn decide_unix(capability: &str, desktop: &DesktopContext, tool: Option<String>) -> Answer {
    let compositor = desktop
        .compositor
        .as_ref()
        .map_or_else(String::new, |value| value.to_ascii_lowercase());
    match desktop.display_server {
        DisplayServer::X11 => match tool {
            Some(tool) if display_reachable() => Answer {
                state: CapabilityState::QualifiedAvailable,
                evidence: CapabilityEvidenceSource::PlatformQuery,
                reason: None,
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
            Some(tool) if wlroots(&compositor) => Answer {
                state: CapabilityState::QualifiedAvailable,
                evidence: CapabilityEvidenceSource::PlatformQuery,
                reason: None,
                tool: Some(tool),
            },
            Some(tool) => Answer {
                state: CapabilityState::PermissionRequired,
                evidence: CapabilityEvidenceSource::PlatformQuery,
                reason: Some(format!(
                    "on Wayland {} goes through the compositor rather than the display server, \
                     and {} asks the user for it each time rather than granting it to a tool",
                    wayland_route(capability),
                    if compositor.is_empty() {
                        "this compositor"
                    } else {
                        compositor.as_str()
                    }
                )),
                tool: Some(tool),
            },
            None => Answer::refused(
                CapabilityState::MissingInstallation,
                CapabilityEvidenceSource::PlatformQuery,
                format!(
                    "no installed tool on this host serves this capability on {}",
                    if compositor.is_empty() {
                        "Wayland"
                    } else {
                        compositor.as_str()
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

/// Returns whether a compositor is one of the family whose protocols the tools below use.
///
/// These compositors implement the screen-copy and virtual-input protocols directly, so a tool
/// built for them needs no per-use permission. The list is a qualification rather than a guess:
/// a compositor that is not on it is reported as needing the user's own permission.
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

/// Returns the absolute path of an installed facility, where it is installed.
///
/// A candidate given as an absolute path is checked where it is. A bare name is looked for in the
/// execution context's own search path, because a facility installed for the user is as real as
/// one installed for everybody, and the search path is part of the context the session runs in.
fn installed(candidate: &str) -> Option<String> {
    let path = std::path::Path::new(candidate);
    if path.is_absolute() {
        return path.is_file().then(|| candidate.to_owned());
    }
    let search = std::env::var_os("PATH")?;
    std::env::split_paths(&search)
        .map(|directory| directory.join(candidate))
        .find(|full| full.is_file())
        .map(|full| full.display().to_string())
}

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
            assert_eq!(record.state, CapabilityState::NotTested);
            assert_eq!(record.evidence_source, CapabilityEvidenceSource::NotProbed);
            assert!(
                record.disabled_reason.is_present(),
                "{capability} says why it is unavailable"
            );
        }
        let server = report
            .record(capabilities::DISPLAY_SERVER)
            .expect("the display server is a capability of its own");
        assert!(server.state.is_available());
        assert!(
            report
                .record(capabilities::APPLICATION_LAUNCH)
                .is_some_and(|record| record.state.is_available()),
            "launching an application on a macOS desktop needs no privacy permission"
        );
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
            assert_eq!(record.state, CapabilityState::TemporarilyUnavailable);
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
        // X11 with a tool present: the display server itself grants it.
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
        // The same tool on a compositor that asks the user each time instead.
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

        assert_eq!(wlroots.state, CapabilityState::QualifiedAvailable);
        assert_eq!(portal.state, CapabilityState::PermissionRequired);
        assert!(
            portal
                .reason
                .as_ref()
                .is_some_and(|reason| reason.contains("gnome")),
            "the answer names the compositor it is about: {portal:?}"
        );
        assert_eq!(bare.state, CapabilityState::MissingInstallation);
        assert!(
            bare.reason
                .as_ref()
                .is_some_and(|reason| reason.contains("kde")),
            "{bare:?}"
        );
        // The X11 answer depends on whether this context holds a display, which a test host may
        // not. Both answers are about X11 and neither is the Wayland one.
        assert!(
            matches!(
                x11.state,
                CapabilityState::QualifiedAvailable | CapabilityState::PermissionRequired
            ),
            "{x11:?}"
        );
        assert_ne!(x11.state, CapabilityState::MissingInstallation);
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
