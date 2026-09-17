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
//! * **A desktop-bound session always watches a desktop.** Where the create request recorded one,
//!   that is the one. Where it recorded none, the watch takes the login session the worker was
//!   started in, because a desktop-bound session is in one whether the record named it or not,
//!   and a session watching nothing could never report losing anything.
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

pub use platform::{Login, Presence, Reading};

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
///
/// Three answers, not two: the platform can describe a login session, say there is none, or fail
/// to answer. A desktop-bound session closes on the second and not on the third.
#[must_use]
pub fn current() -> Reading {
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
        current().login_or_none()
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
        desktop_session_id: Nullable(
            desktop
                .then(|| derive_name(login, uid, &os_user(), &boot))
                .flatten(),
        ),
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
/// with the same name are the same desktop. Both the account name and the numeric identifier are
/// in it, because a platform that does not number its users has only the name and one that does
/// has both.
///
/// A reading with no generation has no name. A platform session number without a generation cannot
/// tell one login from the next one given that number, and a name that omitted it would say two
/// desktops were one.
///
/// It is bounded opaque text: a host whose boot identity will not fit in one has no name, and every
/// field is still in the record.
#[must_use]
pub fn derive_name(
    login: &Login,
    uid: u32,
    user: &str,
    boot: &BootIdentity,
) -> Option<DesktopSessionId> {
    let session = login.platform_session.as_deref()?;
    let generation = login.generation?;
    DesktopSessionId::new(format!(
        "{}:user={user}:uid={uid}:session={session}:generation={generation}:boot={}",
        login.kind.as_str(),
        hex(boot.value.as_slice())
    ))
    .ok()
}

/// Returns the operating-system user this worker runs as.
#[must_use]
pub fn os_user() -> String {
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
    /// about. Each of the three readings means something different:
    ///
    /// * a login session that is the recorded one binds the watch to the process that owns it;
    /// * a login session that is a different one, or a platform that says there is no graphical
    ///   login at all, is a desktop that ended between the create request and the shell, and the
    ///   watch says so from the start rather than waiting for a change it would never see;
    /// * a platform that would not answer binds without that process. The watch reports no loss
    ///   and asks the platform again on the slower cadence, because a reading this host could not
    ///   take is not evidence that anything ended.
    #[must_use]
    pub fn bind(profile: WorkerProfile, recorded: &DesktopBinding) -> Self {
        if profile != WorkerProfile::DesktopBound {
            return Self::none();
        }
        let live = current();
        if !recorded.desktop_session_id.is_present() && !recorded.login_generation.is_present() {
            // The record names no desktop, and a desktop-bound session is still in one: the login
            // session its worker was started in, read here. A session that watched nothing because
            // a reading failed a moment earlier would be a desktop-bound session that could not
            // lose its desktop.
            return match live {
                Reading::Desktop(live) => Self {
                    bound: Some(Bound {
                        recorded: binding_of(&live),
                        anchor: live.anchor,
                    }),
                    lost: false,
                    asked: None,
                },
                // The platform says there is no graphical login, and this session was created for
                // one.
                Reading::None => Self {
                    bound: None,
                    lost: true,
                    asked: None,
                },
                // Nothing to bind to yet and nothing established. The next question asks again.
                Reading::Unavailable => Self {
                    bound: Some(Bound {
                        recorded: DesktopBinding::none(),
                        anchor: None,
                    }),
                    lost: false,
                    asked: None,
                },
            };
        }
        let (anchor, lost) = match live {
            Reading::Desktop(live) => match describes(&live, recorded) {
                Some(true) => (live.anchor, false),
                Some(false) => (None, true),
                // A reading this host cannot compare with the record establishes nothing.
                None => (None, false),
            },
            Reading::None => (None, true),
            Reading::Unavailable => (None, false),
        };
        Self {
            bound: Some(Bound {
                recorded: recorded.clone(),
                anchor,
            }),
            lost,
            asked: None,
        }
    }

    /// Returns the desktop this watch is bound to, as a session record carries it.
    ///
    /// A session whose create request recorded no desktop is bound to the one its worker was
    /// started in, and this is what it reports, so the record, the closure and `kr status` all
    /// name the same desktop.
    #[must_use]
    pub fn bound_binding(&self) -> Option<DesktopBinding> {
        self.bound
            .as_ref()
            .map(|bound| bound.recorded.clone())
            .filter(|recorded| recorded.desktop_session_id.is_present())
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
        // A watch with nothing to compare against yet takes the first reading it can get, on the
        // slower cadence, because taking it costs a conversation with the platform.
        if !bound.recorded.desktop_session_id.is_present()
            && !bound.recorded.login_generation.is_present()
        {
            if self
                .asked
                .is_some_and(|asked| now.saturating_duration_since(asked) < REREAD_INTERVAL)
            {
                return false;
            }
            self.asked = Some(now);
            match current() {
                Reading::Desktop(live) => {
                    if let Some(bound) = self.bound.as_mut() {
                        bound.recorded = binding_of(&live);
                        bound.anchor = live.anchor;
                    }
                }
                Reading::None => self.lost = true,
                Reading::Unavailable => {}
            }
            return self.lost;
        }
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
        match platform::presence(bound.anchor.as_ref()) {
            Presence::Present => {}
            Presence::Ended => self.lost = true,
            // Either nothing was anchored or the kernel would not answer, so the platform is asked
            // again about the session itself. A reading that describes the recorded desktop also
            // supplies the process to ask about from here on; one that describes a different
            // desktop, or none at all, is a desktop that has ended; one the platform would not
            // give leaves the answer where it was.
            Presence::Unknown => match current() {
                Reading::Desktop(live) => match describes(&live, &bound.recorded) {
                    Some(true) => {
                        if let Some(bound) = self.bound.as_mut() {
                            bound.anchor = live.anchor;
                        }
                    }
                    Some(false) => self.lost = true,
                    None => {}
                },
                Reading::None => self.lost = true,
                Reading::Unavailable => {}
            },
        }
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

/// Returns whether a live reading describes the desktop a record names.
///
/// The name is the whole identity, so where one was recorded the name decides. A record that
/// carries only a generation, which a host whose boot identity would not fit in a name produces,
/// is compared on the generation, and a generation that has moved is a different login.
///
/// `None` means this host could not tell: without the boot it is running in there is no name to
/// compare, and a comparison that guessed would either close a live session or go on watching a
/// desktop that had gone.
#[must_use]
pub fn describes(live: &Login, recorded: &DesktopBinding) -> Option<bool> {
    if let Some(name) = recorded.desktop_session_id.as_ref() {
        let boot = kr_ipc::identity::boot_identity().ok()?;
        let live_name = derive_name(live, kr_ipc::paths::current_uid(), &os_user(), &boot);
        return Some(live_name.as_ref() == Some(name));
    }
    match recorded.login_generation.as_ref() {
        Some(generation) => Some(live.generation == Some(generation.get())),
        None => Some(true),
    }
}

/// Returns the binding one live reading would be recorded as.
fn binding_of(live: &Login) -> DesktopBinding {
    let Ok(boot) = kr_ipc::identity::boot_identity() else {
        return DesktopBinding::none();
    };
    binding(&from_login(live, WorkerProfile::DesktopBound, boot))
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
        let name = derive_name(
            &login("100019", Some(42)),
            501,
            "someone",
            &boot(&[0xab, 0xcd]),
        )
        .expect("a desktop has a name");
        let text = name.as_str();
        assert!(text.contains("macos_security_session"), "{text}");
        assert!(text.contains("user=someone"), "{text}");
        assert!(text.contains("uid=501"), "{text}");
        assert!(text.contains("session=100019"), "{text}");
        assert!(text.contains("generation=42"), "{text}");
        assert!(text.contains("boot=abcd"), "{text}");
    }

    #[test]
    fn a_reused_session_number_in_a_new_login_is_a_different_name() {
        let named = |session: &str, generation: Option<u64>, uid: u32, user: &str, seed: u8| {
            derive_name(&login(session, generation), uid, user, &boot(&[seed])).expect("a name")
        };
        let first = named("2", Some(1_000), 1_000, "someone", 1);
        assert_ne!(
            first,
            named("2", Some(2_000), 1_000, "someone", 1),
            "a new login is a new generation"
        );
        assert_ne!(
            first,
            named("2", Some(1_000), 1_000, "someone", 2),
            "a session number outlives no reboot"
        );
        assert_ne!(
            first,
            named("2", Some(1_000), 1_001, "someone", 1),
            "another user's desktop is another desktop"
        );
        assert_ne!(
            first,
            named("2", Some(1_000), 1_000, "somebody", 1),
            "and a platform that numbers no users still tells them apart"
        );
    }

    #[test]
    fn a_reading_with_no_generation_has_no_name_and_is_no_desktop() {
        assert!(
            derive_name(&login("2", None), 1_000, "someone", &boot(&[1])).is_none(),
            "a session number the platform may hand out again is not an identity"
        );
        let context = from_login(&login("2", None), WorkerProfile::DesktopBound, boot(&[1]));
        assert!(
            !context.is_desktop(),
            "and a context built from it names no desktop"
        );
        assert!(!context.graphic_access);
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
    fn a_record_that_names_no_desktop_binds_to_the_one_the_worker_is_in() {
        let mut watch = Watch::bind(WorkerProfile::DesktopBound, &DesktopBinding::none());
        let now = Instant::now();
        match current() {
            // This host has a desktop, so that is the one to watch: a desktop-bound session with
            // nothing recorded is still in a login session, and one that watched nothing could
            // never report losing it.
            Reading::Desktop(_) => {
                assert!(!watch.lost(now));
                assert!(
                    watch.bound_name().is_some(),
                    "the watch adopted the desktop this worker is in"
                );
                assert!(
                    watch
                        .bound_binding()
                        .is_some_and(|binding| binding.desktop_session_id.is_present()
                            && binding.login_generation.is_present()),
                    "and reports it as a session record carries it"
                );
            }
            // The platform says there is no graphical login, and this session was created for one.
            Reading::None => assert!(watch.lost(now)),
            // Nothing established either way.
            Reading::Unavailable => assert!(!watch.lost(now)),
        }
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
    fn a_context_reaches_a_desktop_only_where_it_is_the_machine_itself() {
        // Whatever this host is, the rule is the same and the context agrees with it: a container
        // and a distribution reach no desktop of the machine hosting them, and a host reaches its
        // own. The test states the rule rather than assuming which of the three it is running in.
        assert!(ContainerEnvironment::Host.reaches_parent_desktop());
        assert!(!ContainerEnvironment::Container.reaches_parent_desktop());
        assert!(!ContainerEnvironment::Wsl.reaches_parent_desktop());

        let context = from_login(
            &login("100019", Some(1)),
            WorkerProfile::DesktopBound,
            boot(&[1]),
        );
        assert_eq!(
            context.container,
            container_environment(),
            "the context reports what this host is"
        );
        assert_eq!(
            context.is_desktop(),
            context.container.reaches_parent_desktop(),
            "and a reading of a login session is a desktop only where this context reaches one"
        );
    }

    #[test]
    fn the_hexadecimal_form_is_the_bytes_and_nothing_else() {
        assert_eq!(hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
        assert_eq!(hex(&[]), "");
    }
}
