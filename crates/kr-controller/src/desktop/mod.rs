//! The host's desktop arrangement: which profile a session gets, what logout does to it, and the
//! desktop a worker is started in.
//!
//! The control daemon owns three facts about the desktop that no single session can answer.
//!
//! * **The default execution profile.** A host with a graphical login creates sessions in that
//!   desktop's own context, so a command in a new session can reach the screen the person is
//!   looking at. A host reached only over SSH, or installed without a graphical login, creates
//!   them in its headless user context. This is decided by asking the platform, not by the
//!   presentation the request chose: `--invisible` changes where a session is shown and nothing
//!   about where it runs.
//! * **What logout does.** A `desktop_bound` worker ends with its login session, on every
//!   platform. A `headless_user` worker survives logout only where the platform's per-user service
//!   manager does, and on Linux only when lingering has been enabled — which is an explicit
//!   choice, never a side effect of installing or of creating a session. [`persistence`] reports
//!   the answer for this host rather than assuming one.
//! * **The desktop a worker is started in.** On macOS and Windows the platform places a per-user
//!   job in the login session that started it. Linux does not: a user service manager started at
//!   boot has no display, so the desktop variables a graphical session publishes are collected
//!   here and passed to the worker's own transient unit. That is the desktop-session agent path,
//!   and [`agent`] owns it.
//!
//! The power setting and the sleep assertion live in [`power`].

pub mod agent;
pub mod power;

use kr_protocol::desktop::{
    DesktopCapabilityReport, DesktopContext, LogoutPersistence, ProfilePersistence,
};
use kr_protocol::identity::{BootIdentity, WorkerProfile};
use kr_protocol::ids::{CapabilityRevision, EnvironmentId};

/// Reads the desktop this host's user currently has.
///
/// The reading is the worker crate's, because the desktop a worker runs in and the desktop the
/// daemon reports are the same desktop read the same way. A daemon that answered the question
/// differently from its workers would report a context no session was in.
#[must_use]
pub fn current(boot: BootIdentity) -> DesktopContext {
    kr_worker::desktop::context(WorkerProfile::DesktopBound, boot)
}

/// Returns the profile this host creates sessions with when the request does not choose one.
///
/// A graphical login means the desktop's own context. Anything else — an SSH-only host, a
/// headless installation, a container — means the configured headless user context, because there
/// is no desktop to bind to and a session that claimed one would be claiming access it does not
/// have.
#[must_use]
pub fn default_profile(desktop: &DesktopContext) -> WorkerProfile {
    if desktop.is_desktop() && desktop.graphic_access {
        WorkerProfile::DesktopBound
    } else {
        WorkerProfile::HeadlessUser
    }
}

/// Builds the capability report for this host's desktop.
#[must_use]
pub fn capabilities(
    environment_id: EnvironmentId,
    desktop: DesktopContext,
    revision: CapabilityRevision,
) -> DesktopCapabilityReport {
    kr_worker::desktop::capability::report(environment_id, None, desktop, revision)
}

/// Reports what logout does to each execution profile on this host.
///
/// Both profiles are reported, in profile order, whichever one this host creates sessions with:
/// the answer for the other is what a person needs to choose between them.
#[must_use]
pub fn persistence(supervisor: &str) -> Vec<ProfilePersistence> {
    vec![
        ProfilePersistence {
            profile: WorkerProfile::DesktopBound,
            persistence: LogoutPersistence::EndsAtLogout,
            mechanism: supervisor.to_owned(),
            detail: "A desktop-bound session belongs to one graphical login. It survives losing \
                     every attachment and it survives this daemon restarting; it does not survive \
                     the login session ending, and it closes with reason desktop_lost when that \
                     happens."
                .to_owned(),
        },
        headless_persistence(),
    ]
}

/// Reports what logout does to a headless worker on this platform.
#[must_use]
pub fn headless_persistence() -> ProfilePersistence {
    let (persistence, mechanism, detail) = platform::headless_persistence();
    ProfilePersistence {
        profile: WorkerProfile::HeadlessUser,
        persistence,
        mechanism: mechanism.to_owned(),
        detail,
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use kr_protocol::desktop::LogoutPersistence;

    /// macOS ends a user's agents when the user logs out.
    ///
    /// A job in the graphical domain goes with the login session. A job in the background domain
    /// runs from the moment the user is logged in until they log out, and neither survives it: only
    /// a system-level daemon does, and a system daemon is not a per-user execution context.
    pub(super) fn headless_persistence() -> (LogoutPersistence, &'static str, String) {
        (
            LogoutPersistence::EndsAtLogout,
            "launchd, per-user agent",
            "macOS ends a user's agents at logout, including one loaded into the background \
             domain, so a headless session on this platform does not outlive the user logging \
             out. Nothing in KalaReach can change that, and nothing here asks for the system-wide \
             privileges that would."
                .to_owned(),
        )
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use kr_protocol::desktop::LogoutPersistence;

    /// Linux keeps a user's service manager after logout only when lingering is enabled.
    ///
    /// The setting is the user's own, it is enabled by an explicit choice, and this host never
    /// enables it as a side effect of installing itself or of creating a session.
    pub(super) fn headless_persistence() -> (LogoutPersistence, &'static str, String) {
        let lingering = super::agent::lingering(kr_ipc::paths::current_uid());
        let (persistence, detail) = if lingering {
            (
                LogoutPersistence::SurvivesLogout,
                "Lingering is enabled for this user, so the user service manager keeps running \
                 after logout and a headless session with it.",
            )
        } else {
            (
                LogoutPersistence::AvailableByChoice,
                "The user service manager ends with the last login session unless lingering is \
                 enabled for this user. Enabling it is an explicit choice made outside a session; \
                 creating a session never enables it.",
            )
        };
        (
            persistence,
            "systemd, per-user service manager",
            detail.to_owned(),
        )
    }
}

#[cfg(windows)]
mod platform {
    use kr_protocol::desktop::LogoutPersistence;

    /// Windows ends a per-user task when the user signs out.
    ///
    /// A scheduled task registered for the user runs in the user's own session and is stopped when
    /// that session ends. Running work across a sign-out needs a service under an account with the
    /// right to log on as a service, which is an explicit installation choice and a different
    /// execution context from the user's own.
    pub(super) fn headless_persistence() -> (LogoutPersistence, &'static str, String) {
        (
            LogoutPersistence::EndsAtLogout,
            "per-user host agent",
            "Windows stops a user's own per-user task when the user signs out, so a headless \
             session on this platform ends with the sign-out. Work that must outlive it needs a \
             service installed under an account granted the right to log on as a service, which \
             is a separate explicit choice."
                .to_owned(),
        )
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod platform {
    use kr_protocol::desktop::LogoutPersistence;

    /// A platform with no per-user service manager this host knows.
    pub(super) fn headless_persistence() -> (LogoutPersistence, &'static str, String) {
        (
            LogoutPersistence::NoServiceManager,
            "detached process",
            "This host has no per-user service manager, so a session's worker is a detached \
             process reparented to the system's first process. What a logout does to it is the \
             platform's own behaviour and this host does not claim to know it."
                .to_owned(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::desktop::{
        ContainerEnvironment, DesktopAvailability, DesktopGenerationSource, DesktopSessionKind,
        DisplayServer,
    };
    use kr_protocol::identity::BootIdentitySource;
    use kr_protocol::ids::DesktopSessionId;
    use kr_protocol::scalars::{Bytes, Nullable, U64};

    fn context(desktop: bool) -> DesktopContext {
        DesktopContext {
            desktop_session_id: if desktop {
                Nullable::some(
                    DesktopSessionId::new("test:uid=1:session=1:generation=1:boot=00")
                        .expect("a name"),
                )
            } else {
                Nullable::null()
            },
            kind: if desktop {
                DesktopSessionKind::MacosSecuritySession
            } else {
                DesktopSessionKind::None
            },
            platform_session: if desktop {
                Nullable::some("1".to_owned())
            } else {
                Nullable::null()
            },
            login_generation: Nullable::some(U64::new(1)),
            generation_source: DesktopGenerationSource::MacosSessionCreator,
            os_user: "someone".to_owned(),
            uid: Nullable::some(U64::new(501)),
            boot_identity: BootIdentity {
                source: BootIdentitySource::MacosBootSessionUuid,
                value: Bytes::new(vec![1]),
            },
            graphic_access: desktop,
            remote: false,
            availability: if desktop {
                DesktopAvailability::Available
            } else {
                DesktopAvailability::Unknown
            },
            container: ContainerEnvironment::Host,
            display_server: if desktop {
                DisplayServer::Quartz
            } else {
                DisplayServer::None
            },
            compositor: Nullable::null(),
            worker_profile: WorkerProfile::DesktopBound,
        }
    }

    #[test]
    fn a_desktop_host_defaults_to_the_desktop_and_a_headless_one_to_its_user_context() {
        assert_eq!(
            default_profile(&context(true)),
            WorkerProfile::DesktopBound,
            "a host with a graphical login creates sessions in that desktop"
        );
        assert_eq!(
            default_profile(&context(false)),
            WorkerProfile::HeadlessUser,
            "a host with no graphical login has no desktop to bind to"
        );
    }

    #[test]
    fn both_profiles_report_what_logout_does_to_them() {
        let reported = persistence("launchd, one job per session");
        assert_eq!(reported.len(), 2, "both profiles are reported");
        let bound = &reported[0];
        assert_eq!(bound.profile, WorkerProfile::DesktopBound);
        assert_eq!(bound.persistence, LogoutPersistence::EndsAtLogout);
        assert!(bound.detail.contains("desktop_lost"));
        let headless = &reported[1];
        assert_eq!(headless.profile, WorkerProfile::HeadlessUser);
        assert!(
            !headless.mechanism.is_empty(),
            "the answer names the service mechanism it is about"
        );
        assert!(
            headless.persistence != LogoutPersistence::SurvivesLogout
                || headless.detail.contains("lingering"),
            "a claim that a headless session survives logout says what makes it survive"
        );
    }
}
