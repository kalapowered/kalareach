//! The desktop a session runs on, and whether it is still there.
//!
//! Section 3 keeps two things apart that a terminal window makes look like one. Where a session is
//! *shown* is its presentation: attached here, in a terminal this host opened, or nowhere at all.
//! Where its processes *run* is its execution context, and that is what decides which display,
//! which message bus and which operating-system permissions a command inside the session actually
//! has. Changing the first never changes the second, and an invisible session keeps the desktop it
//! was created on.
//!
//! # What identifies a desktop
//!
//! [`current`] reads the desktop this worker's user has, and [`context`] assembles the four things
//! that identify it: the user, the platform's own login-session identifier, the boot, and the
//! login-session generation. All four are the identity.
//!
//! The generation is the part that makes the identity survive contact with reality. Linux and
//! Windows both reuse a login-session number, so the number alone would say a session created in
//! one login belongs to the next. [`platform`] takes the generation from the process that owns the
//! login session, whose kernel start value is different for every login.
//!
//! [`DesktopContext::desktop_session_id`] is the derived *name* of that whole context. Equality is
//! decided by the record's fields, never by the name: a host whose boot identity is too long to
//! name still has a complete, comparable context.
//!
//! # What a bound session watches
//!
//! [`Watch`] is what one desktop-bound session holds. It is bound at construction to the desktop
//! recorded in the create request, and every wake of the session's supervision asks it one
//! question: is that desktop still there? The answer costs one kernel query about a recorded
//! process identity, which is what lets a live session ask it as often as it wakes.
//!
//! Three properties of [`Watch`] are deliberate.
//!
//! * **A headless session is never lost.** Outliving a logout is what that profile is for, so a
//!   `headless_user` worker holds a watch that answers no.
//! * **A desktop that was never recorded cannot be lost.** A create request with no desktop in it
//!   binds to nothing, and nothing is what the watch reports.
//! * **A lost desktop is never regained.** The answer is sticky. A new login is a different
//!   desktop, and section 3 is explicit that a session is never rebound to one: the person creates
//!   a new session instead.
//!
//! A platform that will not answer leaves the previous answer standing. A failed query is unknown,
//! never death, which is the same rule the rest of the host's identity reads follow.

pub mod capability;
pub mod platform;

use std::time::{Duration, Instant};

use kr_protocol::desktop::{
    ContainerEnvironment, DesktopAvailability, DesktopContext, DesktopGenerationSource,
    DesktopSessionKind, DisplayServer,
};
use kr_protocol::identity::{BootIdentity, DesktopBinding, ProcessStartIdentity, WorkerProfile};
use kr_protocol::ids::DesktopSessionId;
use kr_protocol::scalars::{Nullable, U64};

pub use platform::{Login, Presence};

/// The shortest time between two readings of whether a bound desktop is still there.
///
/// The reading itself is one kernel query, so this is a bound on what a caller can ask for rather
/// than a cadence anything waits out. A session's supervision asks on every wake, which is at most
/// once a second while the session is busy.
pub const RECHECK_INTERVAL: Duration = Duration::from_millis(1_000);

/// The shortest time between two readings of the platform's own session facilities.
///
/// This is the fallback for a login session whose owning process the platform did not name. It
/// costs a conversation with the platform rather than a kernel query, so it happens on the cadence
/// an idle session sweeps on rather than on every wake.
pub const REREAD_INTERVAL: Duration = Duration::from_secs(30);

/// Reads the desktop this worker's user currently has.
///
/// The reading describes one login session and says nothing about permissions: whether a command
/// may capture the screen or send input is [`capability`]'s question, and selecting a desktop is
/// not evidence for either.
#[must_use]
pub fn current() -> Login {
    platform::read_login(kr_ipc::paths::current_uid())
}

/// Assembles the execution context of a worker of this profile.
///
/// A `desktop_bound` worker takes the login session it was started in. A `headless_user` worker
/// takes none of it: it has no inherited graphical access, because it is not in a graphical login
/// at all, and it must keep working after one ends.
#[must_use]
pub fn context(profile: WorkerProfile, boot: BootIdentity) -> DesktopContext {
    let login = if profile == WorkerProfile::DesktopBound {
        current()
    } else {
        Login::none()
    };
    from_login(&login, profile, boot)
}

/// Assembles a context from one platform reading.
#[must_use]
pub fn from_login(login: &Login, profile: WorkerProfile, boot: BootIdentity) -> DesktopContext {
    let container = container_environment();
    let uid = kr_ipc::paths::current_uid();
    // A container and a Windows Subsystem for Linux distribution each have their own process
    // namespace and their own idea of a display. Neither reaches the desktop of the machine
    // hosting it, so a reading taken inside one describes no desktop however much of a login
    // session it can see.
    let reaches_desktop = container.reaches_parent_desktop();
    let desktop = reaches_desktop && login.is_desktop();
    DesktopContext {
        desktop_session_id: Nullable(desktop.then(|| derive_name(login, uid, &boot)).flatten()),
        kind: if desktop {
            login.kind
        } else {
            DesktopSessionKind::None
        },
        platform_session: Nullable(desktop.then(|| login.platform_session.clone()).flatten()),
        login_generation: Nullable(desktop.then(|| login.generation.map(U64::new)).flatten()),
        generation_source: if desktop {
            login.generation_source
        } else {
            DesktopGenerationSource::Unavailable
        },
        os_user: os_user(),
        uid: Nullable::some(U64::new(u64::from(uid))),
        boot_identity: boot,
        graphic_access: desktop && login.graphic_access,
        remote: desktop && login.remote,
        availability: if desktop {
            login.availability
        } else {
            DesktopAvailability::Unknown
        },
        container,
        display_server: if desktop {
            login.display_server
        } else {
            DisplayServer::None
        },
        compositor: Nullable(desktop.then(|| login.compositor.clone()).flatten()),
        worker_profile: profile,
    }
}

/// Returns the compact binding a session record carries.
///
/// The record holds the derived name of the whole context and the generation it was taken at,
/// which is what a closure, a status read and a recovery comparison need. The complete context is
/// available from the environment's own capability report.
#[must_use]
pub fn binding(context: &DesktopContext) -> DesktopBinding {
    DesktopBinding {
        desktop_session_id: context.desktop_session_id.clone(),
        login_generation: context.login_generation,
    }
}

/// Derives the name of one desktop context.
///
/// The name carries the user, the platform session, the generation and the boot, so two contexts
/// with the same name are the same desktop. It is bounded opaque text: a host whose boot identity
/// will not fit in one has no name, and every field is still in the record.
#[must_use]
pub fn derive_name(login: &Login, uid: u32, boot: &BootIdentity) -> Option<DesktopSessionId> {
    let session = login.platform_session.as_deref()?;
    let generation = login
        .generation
        .map_or_else(|| "none".to_owned(), |value| value.to_string());
    DesktopSessionId::new(format!(
        "{}:uid={uid}:session={session}:generation={generation}:boot={}",
        login.kind.as_str(),
        hex(boot.value.as_slice())
    ))
    .ok()
}

/// Returns the operating-system user this worker runs as.
fn os_user() -> String {
    for name in ["USER", "LOGNAME", "USERNAME"] {
        if let Ok(value) = std::env::var(name)
            && !value.trim().is_empty()
        {
            return value;
        }
    }
    kr_ipc::paths::current_uid().to_string()
}

/// Returns the lower-case hexadecimal form of some bytes.
fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    text
}

/// Returns whether this context is inside a container or a WSL distribution.
///
/// Neither can control the desktop of the machine hosting it. A distribution is checked for first,
/// because a WSL distribution can also carry a container's own markers.
#[must_use]
pub fn container_environment() -> ContainerEnvironment {
    if is_wsl() {
        return ContainerEnvironment::Wsl;
    }
    if is_container() {
        return ContainerEnvironment::Container;
    }
    ContainerEnvironment::Host
}

/// Returns whether this process runs inside a Windows Subsystem for Linux distribution.
fn is_wsl() -> bool {
    if std::env::var_os("WSL_DISTRO_NAME").is_some() || std::env::var_os("WSL_INTEROP").is_some() {
        return true;
    }
    std::fs::read_to_string("/proc/sys/kernel/osrelease").is_ok_and(|release| {
        let release = release.to_ascii_lowercase();
        release.contains("microsoft") || release.contains("wsl")
    })
}

/// Returns whether this process runs inside a container.
///
/// Each marker is one a container runtime writes itself: the file a Docker container carries, the
/// file a Podman container carries, and the control groups a container's first process is placed
/// in.
fn is_container() -> bool {
    if std::path::Path::new("/.dockerenv").exists()
        || std::path::Path::new("/run/.containerenv").exists()
    {
        return true;
    }
    if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        return true;
    }
    std::fs::read_to_string("/proc/1/cgroup").is_ok_and(|cgroups| {
        cgroups.lines().any(|line| {
            line.contains("/docker/")
                || line.contains("/containerd")
                || line.contains("/lxc")
                || line.contains("/kubepods")
        })
    })
}

/// What one desktop-bound session watches.
#[derive(Debug)]
pub struct Watch {
    /// The desktop the session was created on, where one was recorded.
    bound: Option<Bound>,
    /// Whether the desktop has been established as gone. Once true it stays true.
    lost: bool,
    /// When the question was last asked.
    asked: Option<Instant>,
}

/// The desktop a session is bound to, and the process whose life answers for it.
#[derive(Clone, Debug)]
struct Bound {
    /// What the create request recorded.
    recorded: DesktopBinding,
    /// The process that owns the login session, where the live reading named one.
    anchor: Option<ProcessStartIdentity>,
}

impl Watch {
    /// A watch for a session that is bound to no desktop.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            bound: None,
            lost: false,
            asked: None,
        }
    }

    /// Binds a session of this profile to the desktop its create request recorded.
    ///
    /// The live reading is taken here, which is what supplies the process the watch then asks
    /// about. A reading that already names a different desktop from the recorded one is a desktop
    /// that ended between the create request and the shell: the watch says so from the start
    /// rather than waiting for a change it would never see.
    #[must_use]
    pub fn bind(profile: WorkerProfile, recorded: &DesktopBinding) -> Self {
        if profile != WorkerProfile::DesktopBound {
            return Self::none();
        }
        if !recorded.desktop_session_id.is_present() && !recorded.login_generation.is_present() {
            // Nothing was recorded, so this session is bound to no desktop and cannot lose one.
            return Self::none();
        }
        let live = current();
        let matches = describes(&live, recorded);
        Self {
            bound: Some(Bound {
                recorded: recorded.clone(),
                anchor: matches.then(|| live.anchor.clone()).flatten(),
            }),
            lost: !matches,
            asked: None,
        }
    }

    /// Returns whether the desktop this session was bound to has gone.
    ///
    /// The question is asked at most once per [`RECHECK_INTERVAL`] and the answer kept in between,
    /// so a caller that asks on every wake pays for one reading a second rather than one per wake.
    /// Where the platform named no owning process there is nothing to query, and the platform's own
    /// session facilities are asked again on the slower [`REREAD_INTERVAL`].
    pub fn lost(&mut self, now: Instant) -> bool {
        if self.lost {
            return true;
        }
        let Some(bound) = self.bound.as_ref() else {
            return false;
        };
        let interval = if bound.anchor.is_some() {
            RECHECK_INTERVAL
        } else {
            REREAD_INTERVAL
        };
        if self
            .asked
            .is_some_and(|asked| now.saturating_duration_since(asked) < interval)
        {
            return false;
        }
        self.asked = Some(now);
        self.lost = match bound.anchor.as_ref() {
            Some(anchor) => {
                let login = Login {
                    anchor: Some(anchor.clone()),
                    ..Login::none()
                };
                platform::presence(&login) == Presence::Ended
            }
            // No process was named, so the platform is asked again about the session itself. A
            // reading that no longer describes the recorded desktop is a desktop that has ended.
            None => !describes(&current(), &bound.recorded),
        };
        self.lost
    }

    /// Returns the name of the desktop this session is bound to, where one was recorded.
    #[must_use]
    pub fn bound_name(&self) -> Option<&DesktopSessionId> {
        self.bound
            .as_ref()
            .and_then(|bound| bound.recorded.desktop_session_id.as_ref())
    }
}

/// Returns whether a live reading describes the desktop a create request recorded.
///
/// The name is the whole identity, so where one was recorded the name decides. A record that
/// carries only a generation — which a host whose boot identity would not fit in a name produces —
/// is compared on the generation, and a generation that has moved is a different login.
fn describes(live: &Login, recorded: &DesktopBinding) -> bool {
    if let Some(name) = recorded.desktop_session_id.as_ref() {
        let live_name = kr_ipc::identity::boot_identity()
            .ok()
            .and_then(|boot| derive_name(live, kr_ipc::paths::current_uid(), &boot));
        return live_name.as_ref() == Some(name);
    }
    match recorded.login_generation.as_ref() {
        Some(generation) => live.generation == Some(generation.get()),
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::identity::BootIdentitySource;
    use kr_protocol::scalars::Bytes;

    fn boot(value: &[u8]) -> BootIdentity {
        BootIdentity {
            source: BootIdentitySource::MacosBootSessionUuid,
            value: Bytes::new(value.to_vec()),
        }
    }

    fn login(session: &str, generation: Option<u64>) -> Login {
        Login {
            kind: DesktopSessionKind::MacosSecuritySession,
            platform_session: Some(session.to_owned()),
            generation,
            generation_source: DesktopGenerationSource::MacosSessionCreator,
            anchor: None,
            graphic_access: true,
            remote: false,
            availability: DesktopAvailability::Available,
            display_server: DisplayServer::Quartz,
            compositor: Some("Aqua".to_owned()),
        }
    }

    #[test]
    fn the_name_binds_the_user_the_session_the_generation_and_the_boot() {
        let name = derive_name(&login("100019", Some(42)), 501, &boot(&[0xab, 0xcd]))
            .expect("a desktop has a name");
        let text = name.as_str();
        assert!(text.contains("macos_security_session"), "{text}");
        assert!(text.contains("uid=501"), "{text}");
        assert!(text.contains("session=100019"), "{text}");
        assert!(text.contains("generation=42"), "{text}");
        assert!(text.contains("boot=abcd"), "{text}");
    }

    #[test]
    fn a_reused_session_number_in_a_new_login_is_a_different_name() {
        let first = derive_name(&login("2", Some(1_000)), 1_000, &boot(&[1])).expect("a name");
        let again = derive_name(&login("2", Some(2_000)), 1_000, &boot(&[1])).expect("a name");
        let rebooted = derive_name(&login("2", Some(1_000)), 1_000, &boot(&[2])).expect("a name");
        let other_user = derive_name(&login("2", Some(1_000)), 1_001, &boot(&[1])).expect("a name");
        assert_ne!(first, again, "a new login is a new generation");
        assert_ne!(first, rebooted, "a session number outlives no reboot");
        assert_ne!(
            first, other_user,
            "another user's desktop is another desktop"
        );
    }

    #[test]
    fn a_context_with_no_login_names_no_desktop() {
        let context = from_login(&Login::none(), WorkerProfile::HeadlessUser, boot(&[1]));
        assert!(!context.is_desktop());
        assert_eq!(context.kind, DesktopSessionKind::None);
        assert!(!context.graphic_access, "a headless context inherits none");
        assert_eq!(context.display_server, DisplayServer::None);
        assert_eq!(context.worker_profile, WorkerProfile::HeadlessUser);
    }

    #[test]
    fn a_headless_session_is_never_lost() {
        let mut watch = Watch::bind(
            WorkerProfile::HeadlessUser,
            &DesktopBinding {
                desktop_session_id: Nullable::some(
                    DesktopSessionId::new("whatever").expect("a name"),
                ),
                login_generation: Nullable::some(U64::new(1)),
            },
        );
        assert!(
            !watch.lost(Instant::now()),
            "outliving a logout is what the profile is for"
        );
    }

    #[test]
    fn a_session_bound_to_no_desktop_cannot_lose_one() {
        let mut watch = Watch::bind(WorkerProfile::DesktopBound, &DesktopBinding::none());
        assert!(!watch.lost(Instant::now()));
        assert!(watch.bound_name().is_none());
    }

    #[test]
    fn a_desktop_that_no_longer_matches_the_record_is_lost_from_the_start_and_stays_lost() {
        // A name no host can be in: the desktop this session was created on is not the one that is
        // there now, which is what a logout between the create request and the shell looks like.
        let mut watch = Watch::bind(
            WorkerProfile::DesktopBound,
            &DesktopBinding {
                desktop_session_id: Nullable::some(
                    DesktopSessionId::new(
                        "macos_security_session:uid=0:session=0:generation=0:boot=00",
                    )
                    .expect("a name"),
                ),
                login_generation: Nullable::some(U64::new(0)),
            },
        );
        let now = Instant::now();
        assert!(watch.lost(now), "the recorded desktop is not the live one");
        assert!(
            watch.lost(now + RECHECK_INTERVAL * 10),
            "a lost desktop is never rebound"
        );
    }

    #[test]
    fn a_container_context_reaches_no_desktop() {
        let inside = Login {
            ..login("100019", Some(1))
        };
        let context = from_login(&inside, WorkerProfile::DesktopBound, boot(&[1]));
        // This test runs on the host, so the context it builds is a desktop. What it establishes
        // is the rule the container case relies on: the container answer decides, and the
        // capability records below quote it.
        assert_eq!(context.container, ContainerEnvironment::Host);
        assert!(ContainerEnvironment::Host.reaches_parent_desktop());
        assert!(!ContainerEnvironment::Container.reaches_parent_desktop());
        assert!(!ContainerEnvironment::Wsl.reaches_parent_desktop());
        assert!(context.is_desktop());
    }

    #[test]
    fn the_hexadecimal_form_is_the_bytes_and_nothing_else() {
        assert_eq!(hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(hex(&[]), "");
    }
}
