//! The short disclosed checks that establish what a desktop permission actually allows.
//!
//! [`capability`](super::capability) answers every capability it can from the platform itself, and
//! stops where the platform stops: on macOS and Windows a screen image, synthetic input and the
//! accessibility tree are all granted per signed application, and nothing a query can ask
//! establishes either answer. Section 3 says how that gap is closed: setup runs short, disclosed
//! checks from the same worker context an agent runs in, and each one performs the operation its
//! capability is. That is the whole idea. A permission cannot be verified without performing the
//! operation it guards, so the check *is* the operation, run once, bounded, against a subject the
//! record names.
//!
//! # The four checks
//!
//! Section 3 names them: reading an authorised test file, obtaining a screen image in memory,
//! finding an accessible user-interface element, and launching an application. Each is one
//! [`Check`], each has one capability, and each declares its [`Effects`] before it runs.
//!
//! Two rules bound every one of them. A check never sends input to an unrelated application, and
//! a check never changes user data. Those are not conventions here; they are what
//! [`Effects::sends_input`] and [`Effects::changes_user_data`] record, and the one check that
//! would break either is [`Check::SyntheticInput`], which is withheld unless the caller supplies
//! an [`IsolatedContext`] of its own. Without one it is never run, and its record says
//! [`CapabilityState::NotTested`] rather than claiming an answer. That is what section 3 means by
//! a destructive probe needing its own explicit isolated test context.
//!
//! # What makes an answer stale
//!
//! A probe result is evidence about one moment, one binary and one login, and none of those is a
//! clock. [`Fingerprint`] is what a result was taken against: the facility's own identity, the
//! host agent's, the desktop generation and the execution profile. [`Fingerprint::changes_since`]
//! names which [`CapabilityInvalidation`] triggers fired between two of them, and [`stale`] keeps
//! only the triggers the record itself lists. A host-agent update moves the agent's build; a
//! new login moves the generation. Each of those ends what was held. The passage of time does not,
//! because nothing about a permission changes by itself. A change of permission is not something
//! this host can read, so it is found by performing the checks again, which a person asks for.
//!
//! # What the time limit bounds, and what it does not
//!
//! One [`Deadline`] covers a whole check. It bounds every wait that a check can abandon: the wait
//! for the child of an operation, the wait for the child of a context command, and the reads of
//! what a command printed and of the files a check reads back or digests. Each read stops between
//! two blocks once the time is gone. A child that was ended is collected within a bound: for an
//! operation, two seconds, inside the time the check keeps back for what follows the operation;
//! for a context command, the time the reading has left, and no more than two seconds. A child not
//! collected within its bound is collected on a thread of its own, and the check goes on without
//! it. A thread that the system refuses to start leaves its child in the process table; only
//! resource exhaustion causes that.
//!
//! It does not bound a call on a regular file against a filesystem that has stopped answering: the
//! open and each read of a capture, an output, a read-back or a digested file, the metadata read
//! that finds a program, the start of a program, which waits until its file is loaded, the
//! creation of the check's directory and files and of a reading's capture directory, and the
//! removal of the image, of the check's own files and of a reading's capture directory. Nothing in
//! this process can abandon such a call. A check that meets one answers when the call returns. If
//! the call came before a check's last test of its time, that check's record says it did not
//! finish within its time limit. The removal of the run's own directory comes after the last of
//! those tests, so nothing in the worker refuses it as late. These are stated limits: the bound is
//! not exact.
//!
//! # What runs the operation
//!
//! [`Facilities`] is the seam. The judgements, the records and the staleness rules above are
//! ordinary functions over data, so they are the same on every platform and a test settles them
//! without a desktop. [`Platform`] is the one implementation that starts a real child process, and
//! it is the only thing here that touches the machine.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_protocol::desktop::{
    CapabilityEvidenceSource, CapabilityIdentity, CapabilityInvalidation, CapabilityRecord,
    CapabilityState, CapabilitySubject, DesktopAvailability, DesktopContext, DisplayServer,
    capabilities,
};
use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{CapabilityId, CapabilityRevision};
use kr_protocol::scalars::{Nullable, U64};

use super::capability::{CAPABILITY_VERSION, facility_identity_within};
use super::routes::{
    Asking, ContextSource, Operation, Program, Route, Surroundings, Variables, file_read_route,
    resolve,
};
use super::wayland;

/// One disclosed check.
///
/// The four section 3 names, and the one it forbids without a context of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Check {
    /// Reads a file the person authorised this context to read.
    AuthorisedFileRead,
    /// Obtains an image of the desktop and holds it in memory.
    ScreenImage,
    /// Finds one element in the desktop's accessibility tree.
    AccessibleElement,
    /// Starts a new instance of an application on the desktop.
    ApplicationLaunch,
    /// Delivers one synthetic keystroke. Withheld without an [`IsolatedContext`].
    SyntheticInput,
}

impl Check {
    /// The checks setup runs, in capability-name order.
    ///
    /// [`Check::SyntheticInput`] is in the list because its record is part of the answer: a
    /// capability left out of the report would read as one nobody asked about, and this one was
    /// asked about and deliberately not performed.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::AccessibleElement,
            Self::ApplicationLaunch,
            Self::AuthorisedFileRead,
            Self::SyntheticInput,
            Self::ScreenImage,
        ]
    }

    /// Whether the check acts on the desktop, so that it needs the desktop to be there when it
    /// starts and when it ends. The file read and the withheld check do not.
    #[must_use]
    pub const fn acts_on_a_desktop(self) -> bool {
        matches!(
            self,
            Self::ScreenImage | Self::AccessibleElement | Self::ApplicationLaunch
        )
    }

    /// The capability this check is evidence about.
    #[must_use]
    pub const fn capability(self) -> &'static str {
        match self {
            Self::AuthorisedFileRead => capabilities::AUTHORISED_FILE_READ,
            Self::ScreenImage => capabilities::SCREEN_CAPTURE,
            Self::AccessibleElement => capabilities::ACCESSIBILITY,
            Self::ApplicationLaunch => capabilities::APPLICATION_LAUNCH,
            Self::SyntheticInput => capabilities::INPUT_INJECTION,
        }
    }

    /// What this check does, declared before it is run.
    #[must_use]
    pub const fn effects(self) -> Effects {
        match self {
            Self::AuthorisedFileRead => Effects {
                performs: "reads the first bytes of the file this check was given, and nothing \
                           else on the filesystem",
                reads: "the nominated file",
                writes: "nothing",
                sends_input: false,
                changes_user_data: false,
                needs_isolated_context: false,
                bound: Duration::from_secs(5),
            },
            Self::ScreenImage => Effects {
                performs: "takes one image of the screen, reads it into memory to measure it, \
                           and keeps nothing",
                reads: "whatever is on the screen at that instant",
                writes: "one image into this check's own directory, read back and removed before \
                         the check answers; a removal that fails is reported rather than passed \
                         over",
                sends_input: false,
                changes_user_data: false,
                needs_isolated_context: false,
                bound: Duration::from_secs(20),
            },
            Self::AccessibleElement => Effects {
                performs: "asks the desktop's accessibility tree for the name of one element",
                reads: "the accessibility tree",
                writes: "nothing",
                sends_input: false,
                changes_user_data: false,
                needs_isolated_context: false,
                bound: Duration::from_secs(20),
            },
            Self::ApplicationLaunch => Effects {
                performs: "starts one new hidden instance of the platform's own calculator, and \
                           ends the instance it started",
                reads: "nothing",
                writes: "nothing of its own: the application this check starts opens no document \
                         and this check gives it nothing to do",
                sends_input: false,
                changes_user_data: false,
                needs_isolated_context: false,
                bound: Duration::from_secs(30),
            },
            Self::SyntheticInput => Effects {
                performs: "delivers one keystroke to an application that belongs to a test context \
                           of its own",
                reads: "nothing",
                writes: "whatever that keystroke writes, inside that context",
                sends_input: true,
                changes_user_data: true,
                needs_isolated_context: true,
                bound: Duration::from_secs(20),
            },
        }
    }
}

/// What a check does, in the words the assistant shows before it runs.
///
/// A disclosed check is one whose effects the person can read in advance, so this is part of the
/// product rather than documentation about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effects {
    /// The operation itself.
    pub performs: &'static str,
    /// What it reads.
    pub reads: &'static str,
    /// What it writes.
    pub writes: &'static str,
    /// Whether it delivers input to an application.
    pub sends_input: bool,
    /// Whether it changes anything the person owns.
    pub changes_user_data: bool,
    /// Whether it may only run inside a test context of its own.
    pub needs_isolated_context: bool,
    /// How long it may take before the check stops waiting for it.
    pub bound: Duration,
}

/// A test context a destructive check may act inside.
///
/// A check that sends input or changes data acts on this and on nothing else. The caller supplies
/// it explicitly, names what makes it isolated, and names the one application a keystroke may
/// reach; a check given no context is withheld rather than pointed at the desktop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IsolatedContext {
    /// What makes this context isolated, in the caller's own words, for the record.
    pub described_as: String,
    /// The bundle identifier or name of the application this context owns.
    pub application: String,
}

/// What a run of the checks was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    /// The file the person authorised this context to read.
    ///
    /// Without one the file check is not run: there is no default file, because a default would
    /// establish something about a file the person did not choose.
    pub authorised_file: Option<PathBuf>,
    /// Where a check may put its own working files. Owner-only, and never on the workspace volume.
    pub scratch: PathBuf,
    /// The test context a destructive check needs, where the caller supplied one.
    pub isolated: Option<IsolatedContext>,
}

impl Plan {
    /// A plan that runs the checks needing nothing but a working directory.
    #[must_use]
    pub fn in_directory(scratch: impl Into<PathBuf>) -> Self {
        Self {
            authorised_file: None,
            scratch: scratch.into(),
            isolated: None,
        }
    }
}

/// What performing one check came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The operation was performed and it worked, with what it established.
    Performed {
        /// What the check saw, in this host's words: a byte count, a number of elements, a
        /// process. A path or a message in it is said as its class and its length.
        detail: Sentence,
    },
    /// The operating system refused it for want of a permission it grants per signed application,
    /// and named which.
    PermissionRefused {
        /// The permission category a person grants, in the platform's own words.
        permission: &'static str,
        /// What the platform said, as this check read it: what the platform printed is said as
        /// its class and its length.
        detail: Sentence,
    },
    /// The permissions on the file or on a folder above it refused it.
    ///
    /// A permission a person could grant is named by [`Outcome::PermissionRefused`]. This is the
    /// refusal of a mode or an access list, which no privacy grant is about, on whatever volume and
    /// in whatever folder the file is.
    FilesystemRefused {
        /// What the platform said, as this check read it: what the platform printed is said as
        /// its class and its length.
        detail: Sentence,
    },
    /// A privacy protection of the operating system refused it, at a place that no permission is
    /// known for.
    ProtectionRefused {
        /// What the platform said, as this check read it: what the platform printed is said as
        /// its class and its length.
        detail: Sentence,
    },
    /// The facility this check performs the operation with is not installed.
    FacilityMissing,
    /// The facility is installed and the operation was started, and the installed version cannot
    /// perform it.
    ///
    /// That is a limit of the version, which no permission and no installation changes, so it is
    /// not [`Outcome::FacilityMissing`].
    Unsupported {
        /// What the facility said, as this check read it: what it printed is said as its class and
        /// its length.
        detail: Sentence,
    },
    /// The facility did not answer inside the check's own bound.
    ///
    /// On a platform that asks the person at the machine for the permission, this is what a
    /// waiting prompt looks like from here, and the reason says so rather than guessing.
    NotAnswered {
        /// How long the check waited.
        waited: Duration,
        /// Whether the facility had stopped by the time the check answered.
        stopped: bool,
    },
    /// The check could not be attempted, for a reason that is not a permission.
    NotAttempted {
        /// What stopped it.
        detail: Sentence,
    },
    /// The check was not run because its effects need a test context of its own.
    WithheldForIsolation,
    /// The route is one this worker records as what it is and does not perform, in the route's
    /// own words.
    NotPerformed {
        /// What the route is and why nothing was run.
        detail: Sentence,
    },
    /// The check's time ran out, and its operation was not running when it did: before it started,
    /// or after it ended and before what it printed or wrote could be read, or before the desktop
    /// could be read again to confirm what it found.
    ///
    /// It is not [`Outcome::NotAnswered`], which says the operation was still running at its bound
    /// and was asked to stop.
    TimedOut,
}

/// One check, what it used and what came of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ran {
    /// The check.
    pub check: Check,
    /// The facility it performed the operation with, by absolute path: where it found the
    /// facility, or, for one that is not installed and that the route names by an absolute path,
    /// where it would be.
    ///
    /// A facility is a program the platform installs, and the record names it and digests it. A
    /// file the person nominated is not one: the read check has none, so no record names the
    /// person's path, and the reason says it as its class and its length.
    pub facility: Option<String>,
    /// What came of it.
    pub outcome: Outcome,
    /// The image the check wrote for itself and could not remove, said wherever the answer ends
    /// up: an outcome that the report replaces after the operation keeps it.
    pub left: Option<ImageLeft>,
}

/// An image a check wrote for itself and could not remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageLeft {
    /// Where it is.
    pub path: std::path::PathBuf,
    /// Why it could not be removed, in the system's own words.
    pub error: String,
}

impl Ran {
    /// This answer, with the image the operation left behind carried into it.
    #[must_use]
    fn keeping(self, left: Option<ImageLeft>) -> Self {
        Self { left, ..self }
    }
}

/// Performs one check on this machine.
///
/// The one seam between the rules in this module and the machine. Everything else here is a
/// function over data.
pub trait Facilities {
    /// Performs one check and says what came of it.
    fn perform(&self, check: Check, plan: &Plan, setting: &Setting<'_>) -> Ran;
}

/// The time one check has, from its start to its end.
///
/// Every call a check makes draws on the same deadline: the route's program, the lookup of the
/// instance it started, the call that ends it. A check that made twenty calls of twenty seconds
/// would otherwise take far longer than the twenty seconds it declares.
#[derive(Clone, Copy, Debug)]
pub struct Deadline {
    started: Instant,
    bound: Duration,
}

impl Deadline {
    /// A deadline that ends `bound` from now.
    #[must_use]
    pub fn after(bound: Duration) -> Self {
        Self {
            started: Instant::now(),
            bound,
        }
    }

    /// How much of the deadline is left.
    #[must_use]
    pub fn left(&self) -> Duration {
        self.bound.saturating_sub(self.started.elapsed())
    }

    /// Whether nothing is left.
    #[must_use]
    pub fn expired(&self) -> bool {
        self.left().is_zero()
    }

    /// How long ago the deadline began.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }

    /// The same deadline, ended `reserve` sooner: what a call uses when the time after it is
    /// needed for cleaning up what it started.
    #[must_use]
    pub fn ending_before(&self, reserve: Duration) -> Self {
        Self {
            started: self.started,
            bound: self.bound.saturating_sub(reserve),
        }
    }
}

/// What a facility is given to perform one check, beyond the plan.
#[derive(Clone, Copy, Debug)]
pub struct Setting<'a> {
    /// The desktop context the operation starts under: the reading taken just before it.
    pub desktop: &'a DesktopContext,
    /// The worker's own display variables and search path.
    pub variables: &'a Variables,
    /// The operation the check resolved to, for a check that acts on a desktop.
    pub operation: Option<&'a Operation>,
    /// The one deadline of this check.
    pub deadline: &'a Deadline,
}

/// The state and evidence one outcome comes to.
///
/// Every check that ran produces [`CapabilityEvidenceSource::DisclosedProbe`], including one that
/// was refused: a refusal by the operating system is the operation having been performed and
/// answered. The two that produce something else are a facility that is not installed, where
/// nothing was performed and the platform was merely asked, and a check that was withheld, where
/// nothing was asked at all.
#[must_use]
pub fn judge(
    check: Check,
    outcome: &Outcome,
    asking: Asking,
) -> (CapabilityState, CapabilityEvidenceSource, Option<Sentence>) {
    match outcome {
        Outcome::Performed { detail } => {
            (
                CapabilityState::QualifiedAvailable,
                CapabilityEvidenceSource::DisclosedProbe,
                Some({
                    let said = Sentence::new()
                        .stated("this context performed the operation: ")
                        .sentence(detail)
                        .stated(
                            ". That is what establishes it, and it establishes it for this binary \
                             and this permission state only",
                        );
                    // Where a grant exists and nothing can see it withdrawn, the person is told so.
                    if asking == Asking::ForAGrant && check != Check::ApplicationLaunch {
                        said.stated(
                            ". A permission you withdraw later shows only when the checks run \
                             again",
                        )
                    } else {
                        said
                    }
                }),
            )
        }
        Outcome::PermissionRefused { permission, detail } => (
            CapabilityState::PermissionRequired,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(
                Sentence::new()
                    .stated(
                        "this context performed the operation and the operating system refused \
                         it: ",
                    )
                    .sentence(detail)
                    .stated(". ")
                    .stated(permission)
                    .stated(" is granted per signed application, and this one does not hold it"),
            ),
        ),
        Outcome::FilesystemRefused { detail } => (
            CapabilityState::PermissionRequired,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(
                Sentence::new()
                    .stated(
                        "this context performed the operation and the operating system refused \
                         it: ",
                    )
                    .sentence(detail)
                    .stated(
                        ". No privacy permission is known for that path: the permissions on the \
                         file or its folders refuse this account",
                    ),
            ),
        ),
        Outcome::ProtectionRefused { detail } => (
            CapabilityState::PermissionRequired,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(
                Sentence::new()
                    .stated(
                        "this context performed the operation and the operating system refused \
                         it: ",
                    )
                    .sentence(detail)
                    .stated(
                        ". No privacy permission is known for that path: a privacy protection of \
                         the operating system refuses this account",
                    ),
            ),
        ),
        Outcome::FacilityMissing => (
            CapabilityState::MissingInstallation,
            CapabilityEvidenceSource::PlatformQuery,
            Some(Sentence::new().stated(if asking == Asking::ForAGrant {
                "the platform facility this check performs the operation with is not installed, \
                 so there was nothing to run and nothing to grant"
            } else {
                // Where no grant exists there is nothing to grant, and saying so would name a
                // permission that is not part of this route.
                "the tool this check runs is not installed, so nothing was run"
            })),
        ),
        Outcome::Unsupported { detail } => (
            CapabilityState::Incompatible,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(
                Sentence::new()
                    .stated(
                        "this context started the operation and the installed facility cannot \
                         perform it: ",
                    )
                    .sentence(detail)
                    .stated(
                        ". That is a limit of this tool on this desktop, not a missing permission; \
                         another tool or route may still work",
                    ),
            ),
        ),
        Outcome::NotAnswered { waited, stopped } => (
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(
                Sentence::new()
                    .stated("the operation was started and had not answered after ")
                    .number(waited.as_secs())
                    .stated(" seconds, so it was asked to stop")
                    .stated(if *stopped {
                        " and it did"
                    } else {
                        ", which it had not done when this check answered"
                    })
                    .stated(" and nothing is established either way. ")
                    .stated(match asking {
                        Asking::ForAGrant => {
                            "A permission the operating system asks the person at the machine \
                             about looks exactly like this from here"
                        }
                        Asking::Maybe => {
                            "Nothing on this desktop is known to ask the person about this \
                             operation. Some compositors ask before a program may copy the \
                             screen; this one may be doing so"
                        }
                        Asking::Never => {
                            "Nothing on this desktop is known to ask the person about this \
                             operation"
                        }
                    }),
            ),
        ),
        Outcome::NotAttempted { detail } => (
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::DisclosedProbe,
            // Not "could not be attempted": some of these started and did not get to the end.
            Some(
                Sentence::new()
                    .stated("this check established nothing: ")
                    .sentence(detail),
            ),
        ),
        Outcome::WithheldForIsolation => (
            CapabilityState::NotTested,
            CapabilityEvidenceSource::NotProbed,
            Some(
                Sentence::new()
                    .stated("this check ")
                    .stated(check.effects().performs)
                    .stated(
                        ", so it runs only inside a test context that owns the application the \
                         keystroke lands in. It was not run and nothing is established either way",
                    ),
            ),
        ),
        // The route's own words: what it is and that nothing was run, said where the route is
        // defined.
        Outcome::NotPerformed { detail } => (
            CapabilityState::NotTested,
            CapabilityEvidenceSource::NotProbed,
            Some(detail.clone()),
        ),
        Outcome::TimedOut => (
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(Sentence::new().stated(
                "the check did not finish within its time limit. It established no result.",
            )),
        ),
    }
}

/// What makes a disclosed probe's answer stale.
///
/// The triggers a held answer can actually be ended by, in the order section 3 writes them. A
/// timer is not among them: nothing about a permission changes because time passed, and a check
/// that re-ran on a clock would take a screen image of somebody's desktop for no reason. A
/// permission is not among them either: nothing in a [`Fingerprint`] reads one, so a finding that
/// listed it would claim an ending nothing can cause. A permission withdrawn after a run shows
/// only when the checks run again.
#[must_use]
pub fn invalidation() -> Vec<CapabilityInvalidation> {
    vec![
        CapabilityInvalidation::BinaryIdentity,
        CapabilityInvalidation::DesktopGeneration,
        CapabilityInvalidation::WorkerProfile,
    ]
}

/// Turns one run into the record a caller reads.
///
/// The identity names what the run was about: the program it ran, by path, with the digest of that
/// file as it was before the run, which the caller takes, and the route it took as the schema. A route that ran this worker's own helper names no
/// program, because the helper is the worker program and the host agent's identity covers it.
#[must_use]
pub fn record(
    ran: &Ran,
    route: &Route,
    subject: &CapabilitySubject,
    profile: WorkerProfile,
    revision: CapabilityRevision,
    observed_at_ms: kr_protocol::scalars::TimestampMs,
    identity: Option<Sentence>,
) -> Option<CapabilityRecord> {
    // An image the check could not remove is said whatever the answer came to, including an answer
    // the report put in the place of the operation's own.
    let outcome = match &ran.left {
        Some(left) => super::payload::with_the_image_left(ran.outcome.clone(), left, route.asking),
        None => ran.outcome.clone(),
    };
    let (state, evidence, reason) = judge(ran.check, &outcome, route.asking);
    Some(CapabilityRecord {
        capability: CapabilityId::new(ran.check.capability()).ok()?,
        version: U64::new(CAPABILITY_VERSION),
        subject: subject.clone(),
        revision,
        state,
        evidence_source: evidence,
        identity: CapabilityIdentity {
            binary: Nullable(ran.facility.clone()),
            version: Nullable(identity),
            package: Nullable::null(),
            schema: Nullable::some(route.name.to_owned()),
            profile: Nullable::some(profile),
        },
        invalidation: invalidation(),
        disabled_reason: Nullable(reason),
        observed_at_ms,
    })
}

/// The operating system a worker runs on, as far as the choice of checks is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostOs {
    /// macOS.
    Macos,
    /// Linux.
    Linux,
    /// Windows.
    Windows,
    /// Any other system, which has no desktop context to check.
    Other,
}

impl HostOs {
    /// The operating system this build runs on.
    #[must_use]
    pub const fn this() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Other
        }
    }
}

/// Returns the checks a context can perform on this machine, in capability-name order.
#[must_use]
pub fn performable(desktop: &DesktopContext) -> Vec<Check> {
    performable_on(HostOs::this(), desktop)
}

/// Returns the checks a context is asked for on an operating system, in capability-name order.
///
/// The file read is the same operation everywhere and is asked of every context. The checks that
/// act on a desktop are asked only where the operating system and the display server the context
/// names belong together: Quartz on macOS, X11 or Wayland on Linux, the interactive desktop on
/// Windows. A context whose display server is unknown or absent, or does not belong to the
/// operating system, is asked for the file read alone, because a check cannot be pointed at a
/// desktop that was never named. They are asked only where the context does not refuse the
/// capability either: a container, a context without a graphical login session's access, a locked
/// desktop, an ended one and one that is in the background are answers the platform already gave,
/// and a check that took an image there would test the wrong screen or none. Synthetic input is
/// never asked; its record is the platform's.
#[must_use]
pub fn performable_on(os: HostOs, desktop: &DesktopContext) -> Vec<Check> {
    Check::all()
        .into_iter()
        .filter(|check| match check {
            Check::SyntheticInput => false,
            Check::AuthorisedFileRead => true,
            _ => {
                has_a_desktop_of(os, desktop.display_server)
                    && !super::capability::context_refuses(check.capability(), desktop)
            }
        })
        .collect()
}

/// Whether the display server belongs to the operating system, so that the checks that act on a
/// desktop have one to act on.
const fn has_a_desktop_of(os: HostOs, display_server: DisplayServer) -> bool {
    matches!(
        (os, display_server),
        (HostOs::Macos, DisplayServer::Quartz)
            | (HostOs::Linux, DisplayServer::X11 | DisplayServer::Wayland)
            | (HostOs::Windows, DisplayServer::WindowsDesktop)
    )
}

/// Runs the checks given and returns one record each, in the order given.
///
/// `first` is the reading the checks were chosen from, which the report holds every later reading
/// against and does not take again.
///
/// A tool-specific permission stays its own record here. There is no aggregate answer to collapse
/// into, and a caller reading this list reads separate states: an accessibility grant that this
/// context holds says nothing about a screen image, and the report never says otherwise.
///
/// The desktop is read before each operation that acts on it and again after it, and one rule
/// settles what that means. An operation starts only if the reading before it is the desktop the
/// first reading selected, in the same login, with the same availability, and the context lets the
/// check act on it; a success stands only if the reading after it is that desktop too. A reading
/// that fails either test stops every later operation too, which is answered without being started.
/// A check that has no route on the desktop it is asked of produces no record, so the platform's
/// record of it stands.
///
/// Each check has one deadline, which starts before its first reading and ends with its last: the
/// readings, the lookup of its route, the operation and what it left behind, and the digest of the
/// program all draw on it. A check whose time ran out before its operation started starts nothing.
#[must_use]
pub fn report(
    first: &Surroundings,
    checks: &[Check],
    subject: &CapabilitySubject,
    source: &dyn ContextSource,
    revision: CapabilityRevision,
    plan: &Plan,
    facilities: &dyn Facilities,
) -> Vec<CapabilityRecord> {
    report_timed(
        checks,
        subject,
        source,
        revision,
        plan,
        facilities,
        &Seams {
            first,
            time_of: &time_of,
            routes: &resolve,
        },
    )
}

/// What a report takes from outside itself, so that a case can give it its own: the time each
/// check has, and how a check is turned into an operation on a desktop.
struct Seams<'a> {
    /// The reading that selected the desktop, which the caller took to choose the checks.
    first: &'a Surroundings,
    time_of: &'a dyn Fn(Check) -> Time,
    routes: Routes<'a>,
}

/// How a check is turned into an operation on a desktop: [`resolve`] in the product.
type Routes<'a> = &'a dyn Fn(Check, &DesktopContext, Option<&std::ffi::OsStr>) -> Option<Operation>;

/// How the time of one check is shared out.
#[derive(Clone, Copy, Debug)]
struct Time {
    /// What the whole check has, from its first reading to its last.
    bound: Duration,
    /// What the check keeps for after its operation: collecting what the operation left behind,
    /// and the reading that follows it.
    after: Duration,
}

/// The time each check has.
fn time_of(check: Check) -> Time {
    Time {
        bound: check.effects().bound,
        after: AFTER_OPERATION,
    }
}

/// The part of a check's time that is kept for after its operation.
///
/// The operation is stopped this long before the check's own end, so that collecting what it left
/// behind and the reading taken after it still fit inside the check's one deadline.
const AFTER_OPERATION: Duration = Duration::from_secs(5);

/// The time the first reading has, which comes before every check and belongs to none.
pub const FIRST_READING: Duration = Duration::from_secs(10);

/// Reads the desktop once for the checks to be chosen from and reported against.
#[must_use]
pub fn first_reading(source: &dyn ContextSource) -> Surroundings {
    source.read(&Deadline::after(FIRST_READING))
}

/// [`report`], with the time each check has and the routes it takes given by the caller.
fn report_timed(
    checks: &[Check],
    subject: &CapabilitySubject,
    source: &dyn ContextSource,
    revision: CapabilityRevision,
    plan: &Plan,
    facilities: &dyn Facilities,
    seams: &Seams<'_>,
) -> Vec<CapabilityRecord> {
    let observed_at_ms = kr_ipc::now_ms();
    let first = seams.first.clone();
    let profile = first.desktop.worker_profile;
    let mut stopped = false;
    let mut records = Vec::new();
    for check in checks {
        let record = if check.acts_on_a_desktop() {
            let time = (seams.time_of)(*check);
            let deadline = Deadline::after(time.bound);
            let before = if stopped {
                first.clone()
            } else {
                source.read(&deadline)
            };
            let Some(operation) =
                (seams.routes)(*check, &before.desktop, before.variables.search.as_deref())
            else {
                continue;
            };
            // The reading must be the desktop the first one selected, and one the context lets the
            // check act on.
            let ready =
                !stopped && may_start(*check, &before.desktop) && unchanged(&first, &before);
            // The program as it is before the operation, which is what the answer is about: it is
            // digested before the operation starts and again after it ends, and an answer about a
            // program that changed in between is about neither.
            let program = match &operation.program {
                Program::Tool(path) if ready && !deadline.expired() => Some(path.as_str()),
                _ => None,
            };
            let identity = program.and_then(|path| facility_identity_within(path, &deadline));
            let ran = if deadline.expired() {
                // What the readings and the lookup took was all the time there was: nothing starts.
                timed_out(*check, None)
            } else if !ready {
                stopped = true;
                not_in_the_state_it_needs(*check, None)
            } else {
                // The operation is stopped early enough for what follows it to fit in the check's
                // own time.
                let working = deadline.ending_before(time.after);
                let ran = facilities.perform(
                    *check,
                    plan,
                    &Setting {
                        desktop: &before.desktop,
                        variables: &before.variables,
                        operation: Some(&operation),
                        deadline: &working,
                    },
                );
                let after = source.read(&deadline);
                let again = program.map(|path| facility_identity_within(path, &deadline));
                if deadline.expired() {
                    // A success whose desktop could not be read again in time is not one that
                    // stands.
                    timed_out(*check, ran.facility).keeping(ran.left)
                } else if !unchanged(&before, &after) {
                    stopped = true;
                    not_in_the_state_it_needs(*check, ran.facility).keeping(ran.left)
                } else {
                    match again
                        .as_ref()
                        .map(|again| held(identity.as_ref(), again.as_ref()))
                    {
                        None | Some(Held::Same) => ran,
                        Some(Held::Replaced) => {
                            replaced_while_running(*check, ran.facility).keeping(ran.left)
                        }
                        Some(Held::Unconfirmed) => {
                            program_not_confirmed(*check, ran.facility).keeping(ran.left)
                        }
                    }
                }
            };
            record(
                &ran,
                &operation.route,
                subject,
                profile,
                revision,
                observed_at_ms,
                identity,
            )
        } else {
            let route = match check {
                Check::SyntheticInput => Route {
                    name: "synthetic-input",
                    asking: Asking::Never,
                },
                _ => file_read_route(&first.desktop),
            };
            let deadline = Deadline::after(check.effects().bound);
            let ran = facilities.perform(
                *check,
                plan,
                &Setting {
                    desktop: &first.desktop,
                    variables: &first.variables,
                    operation: None,
                    deadline: &deadline,
                },
            );
            record(
                &ran,
                &route,
                subject,
                profile,
                revision,
                observed_at_ms,
                None,
            )
        };
        records.extend(record);
    }
    records
}

/// Whether an operation that acts on the desktop may start under this reading.
///
/// The refusals of the context hold on every platform: a desktop that is locked, ended or in the
/// background starts nothing. On Linux and Windows the reading must also say the desktop is
/// available, so a reading that could not be taken starts nothing. macOS keeps the rule it has for
/// the rest: the checks run wherever the context does not refuse them, which includes the hosted
/// runners whose sessions report another value.
fn may_start(check: Check, desktop: &DesktopContext) -> bool {
    let reported = matches!(
        desktop.display_server,
        DisplayServer::X11 | DisplayServer::Wayland | DisplayServer::WindowsDesktop
    );
    !super::capability::context_refuses(check.capability(), desktop)
        && (!reported || desktop.availability == DesktopAvailability::Available)
}

/// Whether the reading after an operation is the desktop the reading before it named.
fn unchanged(before: &Surroundings, after: &Surroundings) -> bool {
    before.desktop.availability == after.desktop.availability
        && before.desktop.login_generation == after.desktop.login_generation
        && before.desktop.is_same_desktop(&after.desktop)
}

/// What the digests of a program, taken before and after its operation, say about it.
enum Held {
    /// They agree, or neither could be read and the record carries no digest.
    Same,
    /// Both were read and they differ.
    Replaced,
    /// One of them could not be read, so whether the program changed is not known.
    Unconfirmed,
}

/// Compares the digest of a program before its operation with the one after it.
fn held(before: Option<&Sentence>, after: Option<&Sentence>) -> Held {
    match (before, after) {
        (Some(before), Some(after)) if before != after => Held::Replaced,
        (Some(_), None) | (None, Some(_)) => Held::Unconfirmed,
        _ => Held::Same,
    }
}

/// What a check came to when the digest of the program it ran could not be compared before and
/// after it ran: a refusal, as for a replacement, without saying that it was replaced.
fn program_not_confirmed(check: Check, facility: Option<String>) -> Ran {
    Ran {
        check,
        facility,
        outcome: Outcome::NotAttempted {
            detail: Sentence::new().stated(
                "the program it ran could not be read both before and after it ran, so it is \
                 not known whether it was replaced while it ran",
            ),
        },
        left: None,
    }
}

/// What a check came to when the program it ran was replaced while it ran.
fn replaced_while_running(check: Check, facility: Option<String>) -> Ran {
    Ran {
        check,
        facility,
        outcome: Outcome::NotAttempted {
            detail: Sentence::new().stated("the program it ran was replaced while it ran"),
        },
        left: None,
    }
}

/// What a check came to when its time ran out where nothing of it was running.
fn timed_out(check: Check, facility: Option<String>) -> Ran {
    Ran {
        check,
        facility,
        outcome: Outcome::TimedOut,
        left: None,
    }
}

/// What a check that did not start, or whose success cannot stand, came to.
///
/// The words do not say the session is locked: another desktop in front, a reading that failed and
/// a change in the middle of the operation are not that.
fn not_in_the_state_it_needs(check: Check, facility: Option<String>) -> Ran {
    Ran {
        check,
        facility,
        outcome: Outcome::NotAttempted {
            detail: Sentence::new().stated(
                "the desktop was not in the state this check needs: it changed during the \
                 check, another desktop was in front, or its state could not be read",
            ),
        },
        left: None,
    }
}

/// What a probe result was taken against.
///
/// Two of these that differ in any field describe two different questions, so a result taken
/// against one of them says nothing about the other. It changes when the thing it describes
/// changes and at no other time.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Fingerprint {
    /// The facility's own identity, as [`facility_identity`] reads it.
    pub facility: Option<String>,
    /// The host agent's own identity: the process of the worker the findings were taken in.
    pub host_agent: Option<String>,
    /// The release the host agent states it is, for the worker a run is performed in. A host-agent
    /// update moves it, and starting another session of the same release does not.
    pub agent_build: Option<String>,
    /// The desktop's login-session generation. A new login moves it.
    pub desktop_generation: Option<u64>,
    /// The execution profile the check ran under.
    pub profile: Option<WorkerProfile>,
}

impl Fingerprint {
    /// Which triggers fired between an earlier fingerprint and this one.
    ///
    /// Each field is compared as it was read, including whether it could be read at all. A
    /// facility that was identified and now cannot be is a change: the thing the answer was about
    /// is not the thing that is there now, and an answer that went on standing would describe a
    /// file nobody can point at. A reading that was unknown and stays unknown is not a change, so
    /// a host that can never read one does not drop what it holds over and over.
    #[must_use]
    pub fn changes_since(&self, earlier: &Self) -> Vec<CapabilityInvalidation> {
        let mut fired = Vec::new();
        if earlier.facility != self.facility
            || earlier.host_agent != self.host_agent
            || earlier.agent_build != self.agent_build
        {
            fired.push(CapabilityInvalidation::BinaryIdentity);
        }
        if earlier.desktop_generation != self.desktop_generation {
            fired.push(CapabilityInvalidation::DesktopGeneration);
        }
        if earlier.profile != self.profile {
            fired.push(CapabilityInvalidation::WorkerProfile);
        }
        fired
    }
}

/// Which of a record's own invalidation triggers have fired since it was taken.
///
/// The record decides what makes it stale, not the caller: a record that does not list a trigger
/// is not invalidated by it, whatever moved. An empty answer means the record still stands.
#[must_use]
pub fn stale(
    record: &CapabilityRecord,
    taken_against: &Fingerprint,
    now: &Fingerprint,
) -> Vec<CapabilityInvalidation> {
    now.changes_since(taken_against)
        .into_iter()
        .filter(|trigger| record.invalidation.contains(trigger))
        .collect()
}

/// The facilities of the machine this host is running on.
///
/// One child process per check, started with an argument vector rather than a command line,
/// bounded by the check's own allowance, and with its output written to files in the check's own
/// directory so a facility that prints a great deal cannot fill a pipe and stop.
#[derive(Clone, Debug, Default)]
pub struct Platform;

impl Facilities for Platform {
    fn perform(&self, check: Check, plan: &Plan, setting: &Setting<'_>) -> Ran {
        match check {
            Check::AuthorisedFileRead => read_authorised_file(plan),
            // The destructive check is never performed here, with or without a context. Delivering
            // a keystroke safely means owning the application it lands in, and nothing this host
            // can start owns one: the platform's own input facility delivers to whatever is in
            // front, which is exactly what section 3 forbids. A caller that can supply such a
            // context supplies the facilities to run it in as well.
            Check::SyntheticInput => Ran {
                check,
                facility: None,
                outcome: Outcome::WithheldForIsolation,
                left: None,
            },
            _ => match setting.operation {
                None => not_performed_on_this_platform(check),
                // A route recorded as what it is and never run: its own words are the record.
                Some(Operation {
                    program: Program::NotPerformed(words),
                    ..
                }) => Ran {
                    check,
                    facility: None,
                    outcome: Outcome::NotPerformed {
                        detail: Sentence::new().stated(words),
                    },
                    left: None,
                },
                // A route is performed by the program it names, whichever platform this build is
                // for: the Wayland screen-copy route is run the same way wherever a case runs it.
                Some(operation) if wayland::performs(operation) => {
                    wayland::perform(check, plan, setting, operation)
                }
                // The X11 routes are the same program on every platform that has an X server.
                Some(operation) if super::x11::performs(operation) => {
                    super::x11::perform(plan, setting, operation)
                }
                Some(operation) => platform::perform(check, plan, setting, operation),
            },
        }
    }
}

/// The authorised-file read, which is the same operation on every platform.
///
/// It opens the file the person nominated once and reads the first block of it from that handle.
/// Reading the whole of a file the check knows nothing about would be a diagnostic that copies a
/// document into memory, so it reads enough to establish that the bytes come out and stops.
fn read_authorised_file(plan: &Plan) -> Ran {
    read_authorised_file_with(plan, |path| read_first_block(&path), permission_for_path)
}

/// The authorised-file read, with the read of the file given rather than chosen.
///
/// The product gives [`read_first_block`] and [`permission_for_path`]. A case can give a read that
/// does not return, or a lookup that does not, to see the check stop waiting for it at its
/// declared bound: the read and the lookup are put on a thread here, and waited for here, whichever
/// they are.
///
/// A regular file on a filesystem that has stopped answering blocks in the kernel, and a read has
/// no deadline of its own. The read is done on a thread and waited for with one, so the check
/// answers whatever the filesystem does. A read that never returns leaves its thread waiting
/// rather than the check, which is the trade this makes deliberately: a diagnostic that cannot
/// answer is worse than a thread that is still asleep when the process ends.
///
/// The question that follows a refused open, which permission the path is under, is put to the
/// filesystem as well, and a network volume can refuse the open at once and then stop answering it.
/// It is asked on the same thread, after the open, so that it is inside the same bound.
fn read_authorised_file_with(
    plan: &Plan,
    read: impl FnOnce(PathBuf) -> std::io::Result<FirstBlock> + Send + 'static,
    lookup: impl FnOnce(&Path) -> Option<&'static str> + Send + 'static,
) -> Ran {
    let check = Check::AuthorisedFileRead;
    let Some(path) = plan.authorised_file.as_deref() else {
        return Ran {
            check,
            facility: None,
            outcome: Outcome::NotAttempted {
                detail: Sentence::new().stated(
                    "no file was nominated for this check, and there is no default: a file the \
                     person did not choose would establish something about the wrong file",
                ),
            },
            left: None,
        };
    };
    // The path is opened once and everything after is asked of that handle, so a file replaced by
    // a pipe or a device between a look and a read is not read at all. The open itself does not
    // wait for the other end of a pipe, and the whole check answers inside its own bound whatever
    // the filesystem does.
    let outcome = match on_a_thread(path, check.effects().bound, move |path| {
        match read(path.clone()) {
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                let refusal = refusal_of(&error, &path, lookup);
                // Windows refuses the open of a folder as it refuses a file the account may not
                // read. A folder is not a file this check reads, whatever its permissions are.
                if matches!(refusal, Refusal::Permissions)
                    && std::fs::metadata(&path).is_ok_and(|found| found.is_dir())
                {
                    return Ok(Read::Block(FirstBlock::NotRegular));
                }
                Ok(Read::Refused { error, refusal })
            }
            other => other.map(Read::Block),
        }
    }) {
        None => Outcome::NotAttempted {
            detail: Sentence::new()
                .path(path)
                .stated(" had not been read after ")
                .number(check.effects().bound.as_secs())
                .stated(
                    " seconds, so this check stopped waiting for it; the read itself is the \
                     filesystem's to finish",
                ),
        },
        Some(Ok(Read::Block(FirstBlock::NotRegular))) => Outcome::NotAttempted {
            detail: Sentence::new()
                .path(path)
                .stated(" is not a regular file, and this check reads only a file"),
        },
        Some(Ok(Read::Block(FirstBlock::Read(count)))) => Outcome::Performed {
            detail: Sentence::new()
                .stated("it read ")
                .number(count as u64)
                .stated(" bytes of ")
                .path(path),
        },
        Some(Ok(Read::Refused { error, refusal })) => {
            let detail = Sentence::new()
                .stated("the platform refused to open ")
                .path(path)
                .stated(": ")
                .withheld(ContentClass::Message, &error.to_string());
            match refusal {
                Refusal::Grant(permission) => Outcome::PermissionRefused { permission, detail },
                Refusal::Protection => Outcome::ProtectionRefused { detail },
                Refusal::Permissions => Outcome::FilesystemRefused { detail },
            }
        }
        Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Outcome::NotAttempted {
            detail: Sentence::new().path(path).stated(" is not there"),
        },
        Some(Err(error)) => Outcome::NotAttempted {
            detail: Sentence::new()
                .path(path)
                .stated(" could not be read: ")
                .withheld(ContentClass::Message, &error.to_string()),
        },
    };
    Ran {
        check,
        facility: None,
        outcome,
        left: None,
    }
}

/// What the thread that opened the nominated file brings back.
enum Read {
    /// The open was not refused for want of a permission.
    Block(FirstBlock),
    /// The open was refused for want of a permission, and what that refusal is about.
    Refused {
        error: std::io::Error,
        refusal: Refusal,
    },
}

/// What a refused open is about.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// A privacy protection of the operating system, at a place under this permission.
    Grant(&'static str),
    /// A privacy protection of the operating system, at a place no permission is known for.
    Protection,
    /// The permissions on the file or on a folder above it.
    Permissions,
}

/// What the refusal of an open is about, by the error number the platform gave.
///
/// macOS refuses with `EPERM` where a privacy protection does and with `EACCES` where the mode of
/// a file or an access list does, and the place of the path says nothing of which it was: a file in
/// a folder that a grant covers is refused by its mode, too. So the place is asked only of the
/// first, and the second is the filesystem's own. The other platforms have no privacy permission
/// to name.
fn refusal_of(
    error: &std::io::Error,
    path: &Path,
    lookup: impl FnOnce(&Path) -> Option<&'static str>,
) -> Refusal {
    if !cfg!(target_os = "macos") || error.raw_os_error() != Some(libc::EPERM) {
        return Refusal::Permissions;
    }
    match lookup(path) {
        Some(permission) => Refusal::Grant(permission),
        None => Refusal::Protection,
    }
}

/// What the first block of a nominated file came to.
#[derive(Debug, PartialEq, Eq)]
enum FirstBlock {
    /// The handle is not a regular file, and nothing was read from it.
    NotRegular,
    /// This many bytes came out.
    Read(usize),
}

/// Runs one filesystem question on a thread and waits for it with a clock.
fn on_a_thread<T: Send + 'static>(
    path: &Path,
    bound: Duration,
    ask: impl FnOnce(std::path::PathBuf) -> std::io::Result<T> + Send + 'static,
) -> Option<std::io::Result<T>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let owned = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = sender.send(ask(owned));
    });
    receiver.recv_timeout(bound).ok()
}

/// How much of the nominated file the read check takes.
const FIRST_BLOCK: usize = 4_096;

/// Opens a path for reading without waiting for whatever is on its other end.
///
/// A pipe opened for reading waits for a writer, and a device can wait for a person. Opening
/// without waiting returns at once for both, and what was opened is then asked what it is. A
/// terminal device named here is not made this process's controlling terminal by being opened.
pub(super) fn open_without_waiting(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    options.open(path)
}

/// Opens a file once, refuses anything that is not a regular file, and returns how many bytes of
/// its first block came out.
fn read_first_block(path: &Path) -> std::io::Result<FirstBlock> {
    use std::io::Read as _;

    let mut file = open_without_waiting(path)?;
    if !file.metadata()?.is_file() {
        return Ok(FirstBlock::NotRegular);
    }
    let mut block = [0_u8; FIRST_BLOCK];
    let mut read = 0_usize;
    loop {
        match file.read(&mut block[read..]) {
            Ok(0) => return Ok(FirstBlock::Read(read)),
            Ok(count) => {
                read += count;
                if read == block.len() {
                    return Ok(FirstBlock::Read(read));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// The permission a path is under, where a privacy protection refuses a read of it, in the
/// platform's own words.
///
/// Naming it is the difference between an answer a person can act on and "permission denied": on
/// macOS the protected locations are separate grants, a removable volume and a network volume are
/// two more, and Full Disk Access is one more that covers them all. A path in none of them has no
/// permission to name. Whether a refusal is a privacy protection's at all is the error number's to
/// say, never the path's: this only says which grant the place is under. Whether a path is on a
/// removable or a network volume is what the kernel says of the volume, never how the path is
/// spelled, and a protected folder is the account's own: the one in its home directory.
#[must_use]
pub fn permission_for_path(path: &Path) -> Option<&'static str> {
    permission_on(
        path,
        volume::flags_of(path),
        std::env::home_dir().as_deref(),
    )
}

/// [`permission_for_path`] for a path whose volume's mount flags are `flags` and for an account
/// whose home directory is `home`, where they could be read. The flags are the one thing about a
/// path that a case cannot make on any machine it runs on, so they are given rather than read, and
/// so is the home directory.
fn permission_on(path: &Path, flags: Option<u32>, home: Option<&Path>) -> Option<&'static str> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    // The volume comes first: a path on a removable one is under that grant whatever its folders
    // are called.
    if flags.is_some_and(volume::removable) {
        return Some("Files & Folders, for removable volumes");
    }
    if flags.is_some_and(volume::network) {
        return Some("Files & Folders, for network volumes");
    }
    let path = lexically_clean(path);
    if let Some(home) = home.map(lexically_clean) {
        for (folder, permission) in [
            ("Desktop", "Files & Folders, for the Desktop folder"),
            ("Documents", "Files & Folders, for the Documents folder"),
            ("Downloads", "Files & Folders, for the Downloads folder"),
            (
                "Library/Application Support/com.apple.TCC",
                "Full Disk Access",
            ),
            ("Library/Mail", "Full Disk Access"),
            ("Library/Messages", "Full Disk Access"),
            ("Library/Safari", "Full Disk Access"),
        ] {
            if path.starts_with(home.join(folder)) {
                return Some(permission);
            }
        }
    }
    // The system's own record of what has been granted is kept outside every home directory.
    if path.starts_with("/Library/Application Support/com.apple.TCC") {
        return Some("Full Disk Access");
    }
    None
}

/// The path with its `.` and `..` parts resolved by their spelling, so that `Documents/../Desktop`
/// is a place in the Desktop folder. A path that is not absolute names no folder of an account.
fn lexically_clean(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut clean = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                clean.pop();
            }
            other => clean.push(other),
        }
    }
    clean
}

/// What the kernel says about the volume a path is on.
mod volume {
    use std::path::Path;

    /// The mount flags of the volume that holds `path`, as the kernel reports them for the nearest
    /// part of the path it answers for: a path inside a volume that refuses the lookup is still on
    /// the volume its mount point is.
    #[cfg(target_os = "macos")]
    pub(super) fn flags_of(path: &Path) -> Option<u32> {
        path.ancestors()
            .find_map(|part| rustix::fs::statfs(part).ok())
            .map(|volume| volume.f_flags)
    }

    /// Only macOS asks: the other platforms have no per-volume permission to name.
    #[cfg(not(target_os = "macos"))]
    pub(super) const fn flags_of(_: &Path) -> Option<u32> {
        None
    }

    /// `MNT_REMOVABLE` of the system's `sys/mount.h`: the volume is on removable media. The
    /// platform's own account of it is the one macOS files a grant under, and `libc` has no name
    /// for the flag.
    const MNT_REMOVABLE: u32 = 0x0000_0200;

    /// `MNT_LOCAL` of the system's `sys/mount.h`: the volume is stored on this machine. A volume
    /// that is not is one the platform files its own grant under, and the flag is only defined
    /// where the system header is.
    const MNT_LOCAL: u32 = 0x0000_1000;

    /// Whether a volume with these mount flags is a removable one.
    pub(super) const fn removable(flags: u32) -> bool {
        flags & MNT_REMOVABLE != 0
    }

    /// Whether a volume with these mount flags is a network one: not stored on this machine.
    pub(super) const fn network(flags: u32) -> bool {
        flags & MNT_LOCAL == 0
    }
}

#[cfg(target_os = "macos")]
mod platform {
    //! The macOS facilities, and what each of them establishes.
    //!
    //! Every operation here is the one its capability is. A screen image is taken with the
    //! platform's own capture tool into this check's own directory, measured and removed. An
    //! element is read out of the accessibility tree through the platform's automation facility,
    //! which needs both the Accessibility grant and the Automation grant for the application being
    //! asked, and a refusal names which. An application is started in the background as a new
    //! instance, and the instance this check started is the only process it ends.

    use std::path::PathBuf;

    use super::{
        Check, ContentClass, Deadline, Exit, Operation, Outcome, Plan, Program, Ran, Sentence,
        Setting, bounded, read_within,
    };

    pub(super) fn perform(
        check: Check,
        plan: &Plan,
        setting: &Setting<'_>,
        operation: &Operation,
    ) -> Ran {
        let Program::Tool(tool) = &operation.program else {
            // The program this route names is not on this host, or the route has none to run. The
            // record names the path it would be installed at, where the route has one, so that a
            // later reading sees the file once it is.
            return Ran {
                check,
                facility: operation.program.named_path().map(str::to_owned),
                outcome: Outcome::FacilityMissing,
                left: None,
            };
        };
        let deadline = setting.deadline;
        match check {
            Check::ScreenImage => screen_image(plan, tool, deadline),
            Check::AccessibleElement => accessible_element(plan, tool, deadline),
            Check::ApplicationLaunch => {
                application_launch(plan, tool, operation.target.unwrap_or_default(), deadline)
            }
            Check::SyntheticInput => {
                unreachable!("the destructive check is withheld before it reaches a platform")
            }
            Check::AuthorisedFileRead => {
                unreachable!("the file read is the same on every platform")
            }
        }
    }

    /// Takes one image of the desktop, measures it and keeps nothing.
    ///
    /// The capture tool writes to a file rather than to its output, so the image goes into this
    /// check's own directory, is measured, and is removed before the check answers, whichever way
    /// it went. `-x` takes it without the platform's shutter sound, because a diagnostic should
    /// not make a noise in a meeting.
    fn screen_image(plan: &Plan, tool: &str, deadline: &Deadline) -> Ran {
        let check = Check::ScreenImage;
        let image: PathBuf = plan.scratch.join("screen-image-check.png");
        let _ = std::fs::remove_file(&image);
        // `-m` is the main display and nothing else: without it this tool writes one file per
        // display, and a check that removed the file it named would leave the others behind.
        let ran = bounded(
            check,
            tool,
            &["-x", "-m", "-t", "png", &image.to_string_lossy()],
            plan,
            deadline,
        );
        // Read into memory, which is what the capability is about, and dropped again. The bytes
        // are never looked at beyond their length and their first four, which say whether this is
        // an image at all.
        let measured = read_within(&image, deadline).map(|bytes| {
            let png = bytes.starts_with(&[0x89, b'P', b'N', b'G']);
            (bytes.len() as u64, png)
        });
        // Removed whatever happened: an image outliving the check is the one thing this must not
        // leave behind, and a removal that failed is said rather than passed over.
        let left = super::super::payload::remove_image(&image);
        let outcome = match (ran.exit, measured) {
            // The tool exits successfully whether or not the platform let it see the screen, so
            // an image it did not write is the refusal rather than the exit status.
            (Exit::Succeeded(_), Some((bytes, png))) if bytes > 0 && png => Outcome::Performed {
                detail: Sentence::new()
                    .stated("it read a ")
                    .number(bytes)
                    .stated("-byte image of the main display into memory")
                    // Kept none of it only where the removal worked.
                    .stated(if left.is_none() {
                        " and kept none of it"
                    } else {
                        ""
                    }),
            },
            // The image could not be read before the check's time ran out.
            (Exit::Succeeded(_), None) => Outcome::TimedOut,
            (Exit::Succeeded(_), Some(_)) => refused_recording(Sentence::new().stated(
                "the capture tool ran and produced no image, which is what this platform does \
                 when the application asking has no recording grant",
            )),
            // What the tool prints when the platform will not give it the display. A context with
            // no desktop at all was refused before this ran, so what is left is the grant.
            (Exit::Failed(said), _)
                if said.to_ascii_lowercase().contains("could not create image") =>
            {
                refused_recording(
                    Sentence::new()
                        .stated("the capture tool could not create an image: ")
                        .withheld(ContentClass::Message, &said),
                )
            }
            (Exit::Failed(said), _) => Outcome::NotAttempted {
                detail: super::failed(&said),
            },
            (Exit::Unfinished(outcome), _) => outcome,
        };
        Ran {
            check,
            facility: ran.facility,
            outcome,
            // Whatever the answer, an image this check could not remove is part of it.
            left,
        }
    }

    /// Reads the name of one element from the accessibility tree.
    ///
    /// The frontmost application's own name is the smallest question that needs the tree at all:
    /// answering it needs the Accessibility grant, and asking it needs the Automation grant for
    /// the platform's user-interface service. Nothing is selected, moved or clicked.
    fn accessible_element(plan: &Plan, tool: &str, deadline: &Deadline) -> Ran {
        let check = Check::AccessibleElement;
        // The question has to be one only the grant answers. A process's own name is a property
        // of the process and comes back without it; the elements inside that process are the
        // accessibility tree, and asking for one of those is what the platform gates.
        let ran = bounded(
            check,
            tool,
            &[
                "-e",
                "tell application \"System Events\" to tell (first application process whose \
                 frontmost is true) to get the count of UI elements",
            ],
            plan,
            deadline,
        );
        let outcome = match ran.exit {
            Exit::Succeeded(said) => match said.trim().parse::<u64>() {
                // An element, not a number. A tree that answered with nothing in it is a tree
                // this check found no element in, and the capability is finding one.
                Ok(0) => Outcome::NotAttempted {
                    detail: Sentence::new().stated(
                        "the frontmost application offered no element to read, so nothing about \
                         the accessibility tree is established",
                    ),
                },
                Ok(count) => Outcome::Performed {
                    detail: Sentence::new()
                        .stated(
                            "it read the accessibility tree of the frontmost application and \
                             found ",
                        )
                        .number(count)
                        .stated(" elements in it"),
                },
                Err(_) => Outcome::NotAttempted {
                    detail: Sentence::new()
                        .stated(
                            "the accessibility tree answered with something that is not a count: ",
                        )
                        .withheld(ContentClass::Message, said.trim()),
                },
            },
            Exit::Failed(said) => refusal(&said),
            Exit::Unfinished(outcome) => outcome,
        };
        Ran {
            check,
            facility: ran.facility,
            outcome,
            left: None,
        }
    }

    /// The refusal for a screen image this platform would not produce.
    const fn refused_recording(detail: Sentence) -> Outcome {
        Outcome::PermissionRefused {
            permission: "Screen & System Audio Recording",
            detail,
        }
    }

    /// Reads a refusal out of what the automation facility said.
    ///
    /// The two grants fail with different words, and a person sent to the wrong settings pane has
    /// been told nothing useful. The words decide which grant this is; the answer says which in
    /// this host's words and says the facility's own as their class and their length. Anything
    /// else is a failure of the facility's own.
    pub(super) fn refusal(said: &str) -> Outcome {
        let lowered = said.to_ascii_lowercase();
        if lowered.contains("not authorized to send apple events")
            || lowered.contains("not authorised to send apple events")
            || lowered.contains("-1743")
        {
            return Outcome::PermissionRefused {
                permission: "Automation, for the platform's user-interface service",
                detail: Sentence::new()
                    .stated(
                        "the platform would not let this application send Apple events to its \
                         user-interface service: ",
                    )
                    .withheld(ContentClass::Message, said),
            };
        }
        if lowered.contains("assistive")
            || lowered.contains("accessibility")
            || lowered.contains("-25211")
        {
            return Outcome::PermissionRefused {
                permission: "Accessibility",
                detail: Sentence::new()
                    .stated(
                        "the platform would not let this application read the accessibility \
                         tree: ",
                    )
                    .withheld(ContentClass::Message, said),
            };
        }
        if lowered.contains("connection is invalid")
            || lowered.contains("-609")
            || lowered.contains("-600")
        {
            // The platform did not refuse the grant; it could not reach the service the question
            // was put to. Saying which is the difference between sending somebody to a settings
            // pane that will not help and telling them what actually happened.
            return Outcome::NotAttempted {
                detail: Sentence::new()
                    .stated(
                        "the desktop's user-interface service could not be reached from this \
                         execution context: ",
                    )
                    .withheld(ContentClass::Message, said)
                    .stated(
                        ". That is the service being unreachable rather than a permission being \
                         refused",
                    ),
            };
        }
        Outcome::NotAttempted {
            detail: super::failed(said),
        }
    }

    /// Starts one new instance of an application in the background, and ends it again.
    ///
    /// `-g` keeps it behind whatever the person is looking at and `-n` makes it a new instance, so
    /// an application they already have open is not disturbed. The process identifiers this check
    /// is given back are the only ones it ends.
    fn application_launch(
        plan: &Plan,
        tool: &str,
        application: &'static str,
        deadline: &Deadline,
    ) -> Ran {
        let check = Check::ApplicationLaunch;
        // This check names its own application, in its route, and takes none from a caller. An
        // application a caller could nominate is one that could write something when it starts,
        // and the effects this check declares would then be true of the default and not of the
        // run.
        // A mark this check made up, passed to the instance it starts. It is how the instance this
        // check is responsible for is told apart from one the person already had open, and it is
        // the only thing this check will end.
        // It carries no leading dash: the process lister takes its pattern as an argument of its
        // own, and one that begins like an option is read as one.
        let mark = format!(
            "kalareach-capability-check-{}-{}",
            std::process::id(),
            kr_ipc::now_ms().get()
        );
        // Hidden, in the background, and without waiting. The launcher's own wait is for the
        // application to exit, and an application that stays open would make a launch that worked
        // look like a check that never answered.
        // The time to find and end the instance is kept back from the launcher's own, so that a
        // launcher that runs to the end of its allowance still leaves time to clean up after it.
        let ran = bounded(
            check,
            tool,
            &["-g", "-j", "-n", "-a", application, "--args", &mark],
            plan,
            &deadline.ending_before(CLEANUP_RESERVE),
        );
        let outcome = match ran.exit {
            // The launcher accepting the request is not the application having started, so the
            // answer waits for the process and says what became of it.
            Exit::Succeeded(_) => match end_marked(&mark, plan, deadline) {
                Ended::Gone(named) => Outcome::Performed {
                    detail: Sentence::new()
                        .stated("it started a new hidden instance of ")
                        .stated(application)
                        .stated(" and ended ")
                        .sentence(&named),
                },
                Ended::Lingering(named) => Outcome::Performed {
                    detail: Sentence::new()
                        .stated("it started a new hidden instance of ")
                        .stated(application)
                        .stated(" and asked ")
                        .sentence(&named)
                        .stated(" to end, which has not happened yet"),
                },
                Ended::NeverAppeared => Outcome::NotAttempted {
                    detail: Sentence::new()
                        .stated("the launcher accepted a request to start ")
                        .stated(application)
                        .stated(
                            " and no process of it appeared, so whether it starts here is not \
                             established",
                        ),
                },
            },
            // A launcher that did not answer may still have started something, so the instance is
            // looked for and ended on this path too.
            Exit::Failed(said) => {
                let _ = end_marked(&mark, plan, deadline);
                Outcome::NotAttempted {
                    detail: super::failed(&said),
                }
            }
            Exit::Unfinished(outcome) => {
                let _ = end_marked(&mark, plan, deadline);
                outcome
            }
        };
        Ran {
            check,
            facility: ran.facility,
            outcome,
            left: None,
        }
    }

    /// What became of the instance the launch check started, with how many there were.
    enum Ended {
        /// It appeared, it was asked to end, and it has.
        Gone(Sentence),
        /// It appeared and it was still there when the check stopped waiting.
        Lingering(Sentence),
        /// No process carrying this check's mark ever appeared.
        NeverAppeared,
    }

    /// Ends the processes carrying this check's own mark, and says what it ended.
    ///
    /// The mark was made a moment ago by this check, so a process carrying it is one this check
    /// started. Nothing else is looked for, and the processes are ended by the identifiers the
    /// platform gave back rather than by any pattern of its own.
    fn end_marked(mark: &str, plan: &Plan, deadline: &Deadline) -> Ended {
        while !deadline.expired() {
            let pids = marked(mark, plan, deadline).unwrap_or_default();
            if !pids.is_empty() {
                let arguments: Vec<&str> = pids.iter().map(String::as_str).collect();
                let _ = bounded(
                    Check::ApplicationLaunch,
                    "/bin/kill",
                    &arguments,
                    plan,
                    deadline,
                );
                let named = if pids.len() == 1 {
                    Sentence::new().stated("the one instance it started")
                } else {
                    Sentence::new()
                        .stated("the ")
                        .number(pids.len() as u64)
                        .stated(" instances it started")
                };
                // Asked to end is not ended, and a listing this check could not take is not a
                // listing that came back empty. Only an answer settles it.
                while !deadline.expired() {
                    std::thread::sleep(LAUNCH_POLL);
                    if marked(mark, plan, deadline).is_some_and(|pids| pids.is_empty()) {
                        return Ended::Gone(named);
                    }
                }
                return Ended::Lingering(named);
            }
            std::thread::sleep(LAUNCH_POLL);
        }
        Ended::NeverAppeared
    }

    /// The process identifiers carrying this check's own mark, where the platform answered.
    ///
    /// `None` is the listing this check could not take, which is a different thing from a listing
    /// that came back empty: one says nothing is there and the other says nobody looked.
    fn marked(mark: &str, plan: &Plan, deadline: &Deadline) -> Option<Vec<String>> {
        let listed = bounded(
            Check::ApplicationLaunch,
            "/usr/bin/pgrep",
            &["-f", mark],
            plan,
            deadline,
        );
        match listed.exit {
            Exit::Succeeded(said) => Some(
                said.split_whitespace()
                    .filter(|word| word.chars().all(|character| character.is_ascii_digit()))
                    .map(std::borrow::ToOwned::to_owned)
                    .collect(),
            ),
            // The lister exits with a failure when it matched nothing, which is an answer.
            Exit::Failed(said) if said.is_empty() => Some(Vec::new()),
            _ => None,
        }
    }

    /// How long the launch check waits between looks for the instance it started.
    const LAUNCH_POLL: std::time::Duration = std::time::Duration::from_millis(100);

    /// The part of the launch check's time that is kept for finding and ending the instance.
    const CLEANUP_RESERVE: std::time::Duration = std::time::Duration::from_secs(5);
}

#[cfg(not(target_os = "macos"))]
mod platform {
    //! The facilities of a platform whose disclosed checks this build does not perform.
    //!
    //! The checks belong to every desktop platform and the operations differ on each: a screen
    //! image comes from the compositor's own portal on Wayland and from the display on X11, and
    //! the accessibility tree is a bus rather than an automation facility. Saying so is the honest
    //! answer; performing the wrong operation and reporting its result would not be.

    use super::{Check, Operation, Plan, Ran, Setting, not_performed_on_this_platform};

    pub(super) fn perform(
        check: Check,
        _plan: &Plan,
        _setting: &Setting<'_>,
        _operation: &Operation,
    ) -> Ran {
        not_performed_on_this_platform(check)
    }
}

/// What a check that acts on a desktop comes to where this build has no operation for the desktop.
///
/// The check was asked, so its record replaces the platform's, and it establishes nothing: the
/// operation was not performed, and an answer the platform gave without performing it is not a
/// success this check can claim.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn not_performed_on_this_platform(check: Check) -> Ran {
    Ran {
        check,
        facility: None,
        outcome: Outcome::NotAttempted {
            detail: Sentence::new().stated(
                "this build does not perform this check on this platform, so the operation was \
                 not performed",
            ),
        },
        left: None,
    }
}

/// Returns the path of an installed facility, where it is there and runnable.
fn installed(path: &str) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    metadata.is_file().then(|| path.to_owned())
}

/// What a facility a check ran came to.
///
/// What a facility prints is its own words rather than this build's. The check that ran it reads
/// them to decide what happened and says what it decided, so they reach an answer as their class
/// and their length and never as themselves.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(super) enum Exit {
    /// It exited successfully, having printed this.
    Succeeded(String),
    /// It exited with a failure, having said this: what it printed on its error output, or on its
    /// output where that was empty, without the space around it.
    Failed(String),
    /// It did not get as far as an exit this check could read, and the outcome says why.
    Unfinished(Outcome),
}

/// One facility, run to an end.
pub(super) struct Run {
    /// The facility, by absolute path, where it was there to run.
    pub(super) facility: Option<String>,
    /// What came of it.
    pub(super) exit: Exit,
    /// What it printed on its error output alone, without the space around it, where it exited with
    /// a failure. [`Exit::Failed`] falls back to the output when the error output is empty, and a
    /// reader that needs to know which stream spoke reads this.
    pub(super) error_output: Option<String>,
}

impl Run {
    /// A run that ended without a failure exit to read, or before the facility could be started.
    fn ended(facility: Option<String>, exit: Exit) -> Self {
        Self {
            facility,
            exit,
            error_output: None,
        }
    }
}

/// What a facility that exited with a failure said, as an answer carries it.
pub(super) fn failed(said: &str) -> Sentence {
    let failure = Sentence::new().stated("the facility exited with a failure");
    if said.is_empty() {
        failure.stated(" and printed nothing")
    } else {
        failure.stated(": ").withheld(ContentClass::Message, said)
    }
}

/// Runs one facility with its own allowance and says what came of it.
///
/// The output goes to files in the check's own directory rather than to pipes, so a facility that
/// prints more than a pipe holds cannot stop halfway through waiting for somebody to read it. The
/// allowance is what is left of the check's one deadline: a facility still running at the end of it
/// is ended with everything it started, and the check answers [`Outcome::NotAnswered`], which is
/// what a permission prompt the person has not answered looks like from here. A facility that
/// finished, whether it succeeded or failed, is ended with everything it started too, before it is
/// collected. A call whose program is not installed answers [`Outcome::FacilityMissing`] whatever
/// the time. For a program that is installed, a call made after the deadline has passed starts
/// nothing and answers [`Outcome::TimedOut`].
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn bounded(
    check: Check,
    program: &str,
    arguments: &[&str],
    plan: &Plan,
    deadline: &Deadline,
) -> Run {
    bounded_with(check, program, arguments, &[], plan, deadline)
}

/// [`bounded`], with variables of its own for the facility: each is set to its value, or removed
/// from what the facility inherits where it has none.
///
/// A route whose facility reads the desktop from its environment gives it the variables the check
/// was resolved with, so that what the check read and what the facility acts on cannot differ.
pub(super) fn bounded_with(
    check: Check,
    program: &str,
    arguments: &[&str],
    environment: &[(&str, Option<&str>)],
    plan: &Plan,
    deadline: &Deadline,
) -> Run {
    let facility = installed(program);
    if facility.is_none() {
        return Run::ended(facility, Exit::Unfinished(Outcome::FacilityMissing));
    }
    if deadline.expired() {
        return Run::ended(facility, Exit::Unfinished(Outcome::TimedOut));
    }
    if let Err(error) = std::fs::create_dir_all(&plan.scratch) {
        return Run::ended(
            facility,
            Exit::Unfinished(Outcome::NotAttempted {
                detail: Sentence::new()
                    .stated("this check's own directory ")
                    .path(&plan.scratch)
                    .stated(" could not be made: ")
                    .withheld(ContentClass::Message, &error.to_string()),
            }),
        );
    }
    let out_path = plan.scratch.join(format!("{}-out.txt", name(check)));
    let err_path = plan.scratch.join(format!("{}-err.txt", name(check)));
    let (Ok(out), Ok(err)) = (
        std::fs::File::create(&out_path),
        std::fs::File::create(&err_path),
    ) else {
        return Run::ended(
            facility,
            Exit::Unfinished(Outcome::NotAttempted {
                detail: Sentence::new().stated(
                    "this check could not open a file of its own to collect what the facility \
                     printed",
                ),
            }),
        );
    };
    let started = std::time::Instant::now();
    let spawned = {
        // Started under the lock every start of this worker's takes on Windows, while a launch's
        // stream ends may be inheritable.
        #[cfg(windows)]
        let _inheriting = crate::windows::launch::inheriting();
        let mut command = std::process::Command::new(program);
        command
            .args(arguments)
            .current_dir(&plan.scratch)
            .stdin(std::process::Stdio::null())
            .stdout(out)
            .stderr(err);
        for (variable, value) in environment {
            match value {
                Some(value) => command.env(variable, value),
                None => command.env_remove(variable),
            };
        }
        // A group of its own, so that ending the facility ends what it started as well: a
        // descendant that outlived its parent would go on running after the check answered.
        super::children::in_a_group_of_its_own(&mut command);
        #[cfg(feature = "testing")]
        kr_ipc::testing::created::note_here("check", &command);
        command.spawn()
    };
    let Ok(mut child) = spawned else {
        return Run::ended(
            facility,
            Exit::Unfinished(Outcome::NotAttempted {
                detail: Sentence::new()
                    .path(Path::new(program))
                    .stated(" could not be started"),
            }),
        );
    };
    // A facility that finished has its group ended before it is collected, so that what it left
    // running does not outlive it, and one that failed is no different.
    let status = loop {
        match super::children::poll(&mut child) {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if deadline.expired() {
                    break None;
                }
                std::thread::sleep(POLL);
            }
            Err(_) => break None,
        }
    };
    // What the facility printed is read within the same deadline: a check that is out of time has
    // nothing left to read it with.
    let mut error_output = None;
    let exit = match status {
        Some(status) if status.success() => text_within(&out_path, deadline)
            .map_or(Exit::Unfinished(Outcome::TimedOut), Exit::Succeeded),
        Some(_) => {
            let on_error = text_within(&err_path, deadline);
            error_output = on_error.as_ref().map(|said| said.trim().to_owned());
            let said = on_error.and_then(|said| {
                if said.trim().is_empty() {
                    text_within(&out_path, deadline)
                } else {
                    Some(said)
                }
            });
            said.map_or(Exit::Unfinished(Outcome::TimedOut), |said| {
                Exit::Failed(said.trim().to_owned())
            })
        }
        None => {
            // Only this check's own child and its own group, by the handle and the group it holds:
            // nothing here looks a process up by name. Collecting it is bounded as well, and a
            // child that is not collected by then is collected on a thread of its own, because a
            // child that will not go is not a reason for a diagnostic to stop answering.
            super::children::end_group(&child);
            let _ = child.kill();
            let stopped = super::children::collect_by(child, super::children::COLLECT);
            Exit::Unfinished(Outcome::NotAnswered {
                waited: started.elapsed(),
                stopped,
            })
        }
    };
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);
    Run {
        facility,
        exit,
        error_output,
    }
}

/// Reads a file of this check's own in blocks, and gives up where the deadline has nothing left.
///
/// A file that cannot be read is an empty one, which is what every caller does with it. `None` is
/// the time running out, which is a different thing.
fn read_within(path: &Path, deadline: &Deadline) -> Option<Vec<u8>> {
    use std::io::Read as _;

    if deadline.expired() {
        return None;
    }
    let Ok(mut file) = std::fs::File::open(path) else {
        return Some(Vec::new());
    };
    let mut bytes = Vec::new();
    let mut block = [0_u8; 64 * 1024];
    loop {
        if deadline.expired() {
            return None;
        }
        match file.read(&mut block) {
            Ok(0) => return Some(bytes),
            Ok(count) => bytes.extend_from_slice(&block[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Some(Vec::new()),
        }
    }
}

/// [`read_within`], as the text the file holds, which is empty where it is not text.
fn text_within(path: &Path, deadline: &Deadline) -> Option<String> {
    read_within(path, deadline).map(|bytes| String::from_utf8(bytes).unwrap_or_default())
}

/// How often a running facility is asked whether it has finished.
const POLL: Duration = Duration::from_millis(50);

/// A short file-name stem for one check.
const fn name(check: Check) -> &'static str {
    match check {
        Check::AuthorisedFileRead => "authorised-file-read",
        Check::ScreenImage => "screen-image",
        Check::AccessibleElement => "accessible-element",
        Check::ApplicationLaunch => "application-launch",
        Check::SyntheticInput => "synthetic-input",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::desktop::{
        ContainerEnvironment, DesktopAvailability, DesktopGenerationSource, DesktopSessionKind,
        DisplayServer,
    };
    use kr_protocol::identity::{BootIdentity, BootIdentitySource};
    use kr_protocol::ids::{DesktopSessionId, EnvironmentId, SessionId};
    use kr_protocol::scalars::{Bytes, Uuid};

    use super::super::capability::facility_identity;

    /// A desktop of this test's own, so nothing here depends on the machine it runs on.
    fn desktop() -> DesktopContext {
        DesktopContext {
            desktop_session_id: Nullable::some(
                DesktopSessionId::new(
                    "macos_security_session:user=someone:uid=501:session=1:generation=2:boot=abcd",
                )
                .expect("a desktop name"),
            ),
            kind: DesktopSessionKind::MacosSecuritySession,
            platform_session: Nullable::some("1".to_owned()),
            login_generation: Nullable::some(U64::new(2)),
            generation_source: DesktopGenerationSource::MacosSessionCreator,
            os_user: "someone".to_owned(),
            uid: Nullable::some(U64::new(501)),
            boot_identity: BootIdentity {
                source: BootIdentitySource::MacosBootSessionUuid,
                value: Bytes::new(vec![0xab, 0xcd]),
            },
            graphic_access: true,
            remote: false,
            availability: DesktopAvailability::Available,
            container: ContainerEnvironment::Host,
            display_server: DisplayServer::Quartz,
            compositor: Nullable::some("Aqua".to_owned()),
            worker_profile: WorkerProfile::DesktopBound,
        }
    }

    fn subject() -> CapabilitySubject {
        CapabilitySubject {
            environment_id: EnvironmentId::new(Uuid::from_bytes([7; 16])),
            desktop_session_id: Nullable::null(),
            session_id: Nullable::<SessionId>::null(),
            application: Nullable::null(),
            terminal: Nullable::null(),
        }
    }

    fn revision() -> CapabilityRevision {
        CapabilityRevision::new(3)
    }

    /// What a person at a macOS machine can be asked, which is what these cases read.
    const MACOS: Route = Route {
        name: "macos-test",
        asking: Asking::ForAGrant,
    };

    /// [`super::judge`] on a route that asks for a grant, as the cases here read the words.
    fn judge(
        check: Check,
        outcome: &Outcome,
    ) -> (CapabilityState, CapabilityEvidenceSource, Option<Sentence>) {
        super::judge(check, outcome, Asking::ForAGrant)
    }

    /// [`super::record`] on a route that asks for a grant.
    fn record(
        ran: &Ran,
        subject: &CapabilitySubject,
        profile: WorkerProfile,
        revision: CapabilityRevision,
        observed_at_ms: kr_protocol::scalars::TimestampMs,
    ) -> Option<CapabilityRecord> {
        super::record(
            ran,
            &MACOS,
            subject,
            profile,
            revision,
            observed_at_ms,
            ran.facility.as_deref().and_then(facility_identity),
        )
    }

    /// A context source that always reads the same desktop, with no variables.
    fn fixed(desktop: &DesktopContext) -> impl ContextSource + use<> {
        let desktop = desktop.clone();
        move |_: &Deadline| Surroundings {
            desktop: desktop.clone(),
            variables: Variables::default(),
        }
    }

    /// The first reading a caller takes from a source, as `checks::perform` does.
    fn first_of(source: &dyn ContextSource) -> Surroundings {
        super::first_reading(source)
    }

    /// [`super::report`] against a desktop that does not change.
    fn report(
        checks: &[Check],
        subject: &CapabilitySubject,
        desktop: &DesktopContext,
        revision: CapabilityRevision,
        plan: &Plan,
        facilities: &dyn Facilities,
    ) -> Vec<CapabilityRecord> {
        let source = fixed(desktop);
        super::report(
            &first_of(&source),
            checks,
            subject,
            &source,
            revision,
            plan,
            facilities,
        )
    }

    /// Performs one check through the platform's facilities, on this test's own macOS desktop.
    fn perform_here(check: Check, plan: &Plan) -> Ran {
        let desktop = desktop();
        let variables = Variables::default();
        let deadline = Deadline::after(check.effects().bound);
        let operation = resolve(check, &desktop, None);
        Platform.perform(
            check,
            plan,
            &Setting {
                desktop: &desktop,
                variables: &variables,
                operation: operation.as_ref(),
                deadline: &deadline,
            },
        )
    }

    /// A stand-in that answers each check with whatever the test put in it.
    struct Scripted(Vec<Ran>);

    impl Facilities for Scripted {
        fn perform(&self, check: Check, _plan: &Plan, _setting: &Setting<'_>) -> Ran {
            self.0
                .iter()
                .find(|ran| ran.check == check)
                .cloned()
                .unwrap_or(Ran {
                    check,
                    facility: None,
                    outcome: Outcome::FacilityMissing,
                    left: None,
                })
        }
    }

    fn ran(check: Check, outcome: Outcome) -> Ran {
        Ran {
            check,
            facility: None,
            outcome,
            left: None,
        }
    }

    fn surroundings(desktop: DesktopContext) -> Surroundings {
        Surroundings {
            desktop,
            variables: Variables::default(),
        }
    }

    /// Readings that come one at a time, the last one again after that.
    struct Readings {
        list: Vec<Surroundings>,
        next: std::sync::atomic::AtomicUsize,
    }

    impl Readings {
        fn of(list: Vec<Surroundings>) -> Self {
            Self {
                list,
                next: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }

    impl ContextSource for Readings {
        fn read(&self, _deadline: &Deadline) -> Surroundings {
            let at = self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.list[at.min(self.list.len() - 1)].clone()
        }
    }

    /// A stand-in that records what each check was given and answers it as performed.
    #[derive(Default)]
    struct Seeing(std::sync::Mutex<Vec<(Check, DisplayServer, DesktopAvailability, Variables)>>);

    impl Facilities for Seeing {
        fn perform(&self, check: Check, _plan: &Plan, setting: &Setting<'_>) -> Ran {
            self.0.lock().expect("the record").push((
                check,
                setting.desktop.display_server,
                setting.desktop.availability,
                setting.variables.clone(),
            ));
            ran(
                check,
                Outcome::Performed {
                    detail: Sentence::new().stated("it ran"),
                },
            )
        }
    }

    fn state_of(records: &[CapabilityRecord], check: Check) -> CapabilityState {
        records
            .iter()
            .find(|record| record.capability.as_str() == check.capability())
            .expect("a record for the check")
            .state
    }

    /// KR-REQ-03.29, S-2: the operation is given the context it starts under, with the worker's own
    /// variables, and the route it resolved to.
    #[test]
    fn the_operation_receives_the_selected_context() {
        let first = surroundings(desktop());
        let before = Surroundings {
            desktop: desktop(),
            variables: Variables {
                display: Some(":7".to_owned()),
                ..Variables::default()
            },
        };
        let source = Readings::of(vec![first, before.clone(), before]);
        let seeing = Seeing::default();
        let records = super::report(
            &first_of(&source),
            &[Check::ScreenImage],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &seeing,
        );
        assert_eq!(records.len(), 1);
        let seen = seeing.0.lock().expect("the record");
        assert_eq!(seen.len(), 1);
        let (_, server, availability, variables) = &seen[0];
        assert_eq!(*server, DisplayServer::Quartz);
        assert_eq!(*availability, DesktopAvailability::Available);
        assert_eq!(variables.display.as_deref(), Some(":7"));
        assert_eq!(
            records[0].identity.schema.as_ref().map(String::as_str),
            Some("macos-screen-capture"),
            "the record names the route the check took"
        );
    }

    /// KR-REQ-03.29, S-3: a success stands only if the reading after the operation is the desktop
    /// the reading before it named, in availability, login and identity.
    #[test]
    fn a_success_is_dropped_unless_the_context_reads_as_at_first() {
        type Change = fn(&mut DesktopContext);
        let changes: [(&str, Change); 4] = [
            ("locked", |desktop| {
                desktop.availability = DesktopAvailability::Locked;
            }),
            ("unknown", |desktop| {
                desktop.availability = DesktopAvailability::Unknown;
            }),
            ("another login, still available", |desktop| {
                desktop.login_generation = Nullable::some(U64::new(3));
            }),
            ("another desktop, still available", |desktop| {
                desktop.platform_session = Nullable::some("2".to_owned());
            }),
        ];
        for (what, change) in changes {
            let mut after = desktop();
            change(&mut after);
            let source = Readings::of(vec![
                surroundings(desktop()),
                surroundings(desktop()),
                surroundings(after),
            ]);
            let records = super::report(
                &first_of(&source),
                &[Check::ScreenImage],
                &subject(),
                &source,
                revision(),
                &Plan::in_directory("."),
                &Seeing::default(),
            );
            assert_eq!(
                state_of(&records, Check::ScreenImage),
                CapabilityState::TemporarilyUnavailable,
                "{what}: nothing is established"
            );
            let reason = records[0]
                .disabled_reason
                .as_ref()
                .map(|sentence| sentence.as_str().to_owned())
                .unwrap_or_default();
            assert!(
                reason.contains("not in the state this check needs"),
                "{what}"
            );
            assert!(!reason.contains("locked"), "{what}: {reason}");
        }
        let same = Readings::of(vec![surroundings(desktop())]);
        let records = super::report(
            &first_of(&same),
            &[Check::ScreenImage],
            &subject(),
            &same,
            revision(),
            &Plan::in_directory("."),
            &Seeing::default(),
        );
        assert_eq!(
            state_of(&records, Check::ScreenImage),
            CapabilityState::QualifiedAvailable,
            "an unchanged reading keeps the success"
        );
    }

    /// KR-REQ-03.29, S-3: a reading that is not available starts nothing on Linux or Windows,
    /// `Unknown` included, and macOS keeps the rule it has.
    #[test]
    fn a_first_reading_that_is_not_available_starts_no_operation_off_macos() {
        for server in [
            DisplayServer::X11,
            DisplayServer::Wayland,
            DisplayServer::WindowsDesktop,
        ] {
            for availability in [
                DesktopAvailability::Unknown,
                DesktopAvailability::Locked,
                DesktopAvailability::Background,
                DesktopAvailability::Ended,
            ] {
                let mut context = desktop();
                context.display_server = server;
                context.availability = availability;
                assert!(
                    !may_start(Check::ScreenImage, &context),
                    "{server:?} {availability:?}"
                );
            }
            let mut context = desktop();
            context.display_server = server;
            assert!(
                may_start(Check::ScreenImage, &context),
                "{server:?} available"
            );
        }
        let mut hosted = desktop();
        hosted.availability = DesktopAvailability::Unknown;
        assert!(
            may_start(Check::ScreenImage, &hosted),
            "macOS keeps its rule for a reading it cannot place"
        );
    }

    /// KR-REQ-03.29, S-3 (R4 before every operation): on macOS a desktop the context refuses, one
    /// that is locked, ended or in the background, starts no operation, and the reading is the
    /// same before and after so that nothing but the start rule can refuse it.
    #[test]
    fn a_macos_desktop_the_context_refuses_starts_no_operation() {
        for availability in [
            DesktopAvailability::Locked,
            DesktopAvailability::Background,
            DesktopAvailability::Ended,
        ] {
            let mut context = desktop();
            context.availability = availability;
            let source = Readings::of(vec![surroundings(context)]);
            let seeing = Seeing::default();
            let records = super::report(
                &first_of(&source),
                &[Check::ScreenImage],
                &subject(),
                &source,
                revision(),
                &Plan::in_directory("."),
                &seeing,
            );
            assert!(
                seeing.0.lock().expect("the record").is_empty(),
                "{availability:?}: nothing was started"
            );
            assert_eq!(
                state_of(&records, Check::ScreenImage),
                CapabilityState::TemporarilyUnavailable,
                "{availability:?}: nothing is established"
            );
        }
    }

    /// KR-REQ-03.29, S-3 (R4 before every operation): a new login that is still available is
    /// another desktop, so the operation after it starts nothing, and the one before it stands.
    #[test]
    fn a_new_login_between_operations_starts_no_later_operation() {
        let mut other = desktop();
        other.login_generation = Nullable::some(U64::new(3));
        // The first reading, the reading before the first operation and after it, then another
        // login before the second operation.
        let source = Readings::of(vec![
            surroundings(desktop()),
            surroundings(desktop()),
            surroundings(desktop()),
            surroundings(other),
        ]);
        let seeing = Seeing::default();
        let records = super::report(
            &first_of(&source),
            &[Check::AccessibleElement, Check::ScreenImage],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &seeing,
        );
        let started: Vec<Check> = seeing
            .0
            .lock()
            .expect("the record")
            .iter()
            .map(|seen| seen.0)
            .collect();
        assert_eq!(
            started,
            vec![Check::AccessibleElement],
            "only the operation before the new login started"
        );
        assert_eq!(
            state_of(&records, Check::AccessibleElement),
            CapabilityState::QualifiedAvailable
        );
        assert_eq!(
            state_of(&records, Check::ScreenImage),
            CapabilityState::TemporarilyUnavailable
        );
    }

    /// KR-REQ-03.29, S-10: after a refused re-read the remaining operations are answered without
    /// being started.
    #[test]
    fn a_changed_context_stops_the_later_operations() {
        let mut locked = desktop();
        locked.availability = DesktopAvailability::Locked;
        let source = Readings::of(vec![
            surroundings(desktop()),
            surroundings(desktop()),
            surroundings(locked),
        ]);
        let seeing = Seeing::default();
        let records = super::report(
            &first_of(&source),
            &[
                Check::ScreenImage,
                Check::AccessibleElement,
                Check::ApplicationLaunch,
            ],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &seeing,
        );
        assert_eq!(records.len(), 3);
        for check in [
            Check::ScreenImage,
            Check::AccessibleElement,
            Check::ApplicationLaunch,
        ] {
            assert_eq!(
                state_of(&records, check),
                CapabilityState::TemporarilyUnavailable,
                "{check:?}"
            );
        }
        assert_eq!(
            seeing.0.lock().expect("the record").len(),
            1,
            "only the first was started"
        );
    }

    /// KR-REQ-03.29, S-5: a check with no route on this desktop produces no record, so the
    /// platform's record stands, and nothing is started for it.
    #[test]
    fn no_route_means_no_record_and_nothing_started() {
        // X11 has a route for the screen image, and its own cases show what a check with none gets
        // there; these two have no row yet.
        for server in [DisplayServer::Wayland, DisplayServer::WindowsDesktop] {
            let mut context = desktop();
            context.display_server = server;
            let seeing = Seeing::default();
            let records = report(
                &[
                    Check::ApplicationLaunch,
                    Check::ScreenImage,
                    Check::AccessibleElement,
                ],
                &subject(),
                &context,
                revision(),
                &Plan::in_directory("."),
                &seeing,
            );
            assert!(records.is_empty(), "{server:?}: {records:?}");
            assert!(
                seeing.0.lock().expect("the record").is_empty(),
                "{server:?}"
            );
        }
    }

    /// KR-REQ-03.29, S-5: a route this worker records as what it is and never performs comes back
    /// as its own record, in the route's words.
    #[test]
    fn a_route_that_is_not_performed_comes_back_as_its_own_record() {
        let desktop = desktop();
        let variables = Variables::default();
        let deadline = Deadline::after(Duration::from_secs(5));
        let operation = Operation {
            check: Check::ScreenImage,
            route: Route {
                name: "a-service-of-its-own",
                asking: Asking::Never,
            },
            program: Program::NotPerformed("this desktop has a capture service of its own"),
            target: None,
        };
        let ran = Platform.perform(
            Check::ScreenImage,
            &Plan::in_directory("."),
            &Setting {
                desktop: &desktop,
                variables: &variables,
                operation: Some(&operation),
                deadline: &deadline,
            },
        );
        let record = super::record(
            &ran,
            &operation.route,
            &subject(),
            WorkerProfile::DesktopBound,
            revision(),
            kr_ipc::now_ms(),
            None,
        )
        .expect("a record");
        assert_eq!(record.state, CapabilityState::NotTested);
        assert_eq!(record.evidence_source, CapabilityEvidenceSource::NotProbed);
        assert_eq!(
            record.disabled_reason.as_ref().map(Sentence::as_str),
            Some("this desktop has a capture service of its own")
        );
    }

    /// KR-REQ-03.29, S-9: a record names the program it ran and its digest, and the route it took;
    /// a run that names no program, which is what a helper of this worker is, carries the route and
    /// no digest.
    #[test]
    fn a_helper_row_is_named_by_its_route_with_no_digest() {
        let route = Route {
            name: "a-helper-route",
            asking: Asking::Never,
        };
        let helper = super::record(
            &ran(
                Check::ScreenImage,
                Outcome::Performed {
                    detail: Sentence::new().stated("it ran"),
                },
            ),
            &route,
            &subject(),
            WorkerProfile::DesktopBound,
            revision(),
            kr_ipc::now_ms(),
            None,
        )
        .expect("a record");
        assert!(!helper.identity.binary.is_present());
        assert!(!helper.identity.version.is_present(), "no digest");
        assert_eq!(
            helper.identity.schema.as_ref().map(String::as_str),
            Some("a-helper-route")
        );
        let file = std::env::temp_dir().join(format!("kr-ran-{}", kr_ipc::new_uuid()));
        std::fs::write(&file, b"a program").expect("a file");
        let program = super::record(
            &Ran {
                check: Check::ScreenImage,
                facility: Some(file.display().to_string()),
                outcome: Outcome::FacilityMissing,
                left: None,
            },
            &route,
            &subject(),
            WorkerProfile::DesktopBound,
            revision(),
            kr_ipc::now_ms(),
            facility_identity(&file.display().to_string()),
        )
        .expect("a record");
        let _ = std::fs::remove_file(&file);
        assert!(program.identity.binary.as_ref().is_some());
        assert!(program.identity.version.as_ref().is_some(), "a digest");
    }

    /// KR-REQ-03.29, S-11, the findings' side: each trigger a finding lists is one that two
    /// fingerprints that differ in the matching field make `stale` return, and a permission is not
    /// among them.
    #[test]
    fn a_finding_lists_only_triggers_something_can_fire() {
        let records = report(
            &Check::all(),
            &subject(),
            &desktop(),
            revision(),
            &Plan::in_directory("."),
            &Scripted(Vec::new()),
        );
        assert!(!records.is_empty());
        for record in &records {
            for trigger in &record.invalidation {
                let (earlier, later) = match trigger {
                    CapabilityInvalidation::BinaryIdentity => (
                        Fingerprint {
                            facility: Some("a".to_owned()),
                            ..Fingerprint::default()
                        },
                        Fingerprint {
                            facility: Some("b".to_owned()),
                            ..Fingerprint::default()
                        },
                    ),
                    CapabilityInvalidation::DesktopGeneration => (
                        Fingerprint {
                            desktop_generation: Some(1),
                            ..Fingerprint::default()
                        },
                        Fingerprint {
                            desktop_generation: Some(2),
                            ..Fingerprint::default()
                        },
                    ),
                    CapabilityInvalidation::WorkerProfile => (
                        Fingerprint {
                            profile: Some(WorkerProfile::DesktopBound),
                            ..Fingerprint::default()
                        },
                        Fingerprint {
                            profile: Some(WorkerProfile::HeadlessUser),
                            ..Fingerprint::default()
                        },
                    ),
                    other => panic!(
                        "{} lists {other:?}, which no fingerprint field fires",
                        record.capability
                    ),
                };
                assert!(
                    stale(record, &earlier, &later).contains(trigger),
                    "{} lists {trigger:?} and it does not fire",
                    record.capability
                );
            }
        }
    }

    /// KR-REQ-03.29, R5: what an operation that did not answer says follows its route: only a
    /// route that asks the person may say that a prompt looks exactly like this.
    #[test]
    fn what_an_unanswered_operation_says_follows_its_route() {
        let said = |asking| {
            super::judge(
                Check::ScreenImage,
                &Outcome::NotAnswered {
                    waited: Duration::from_secs(20),
                    stopped: true,
                },
                asking,
            )
            .2
            .expect("a reason")
            .as_str()
            .to_owned()
        };
        assert!(said(Asking::ForAGrant).contains("looks exactly like this from here"));
        for asking in [Asking::Never, Asking::Maybe] {
            let words = said(asking);
            assert!(!words.contains("looks exactly like this"), "{asking:?}");
            assert!(
                words.contains("Nothing on this desktop is known to ask the person"),
                "{asking:?}"
            );
        }
        assert!(said(Asking::Maybe).contains("Some compositors ask"));
        assert!(!said(Asking::Never).contains("Some compositors ask"));
    }

    /// KR-REQ-03.29, S-6: the facility's whole group ends at the bound, a descendant it started
    /// included.
    #[cfg(unix)]
    #[test]
    fn a_check_child_is_ended_with_its_group() {
        let root = kr_ipc::testing::PrivateTempDir::create();
        let scratch = root.path().join("group");
        std::fs::create_dir_all(&scratch).expect("a directory for this check");
        let child = scratch.join("child.pid");
        let grandchild = scratch.join("grandchild.pid");
        let script = "/bin/sleep 120 & echo $! > \"$2\"; echo $$ > \"$1\"; wait";
        let run = bounded(
            Check::ScreenImage,
            "/bin/sh",
            &[
                "-c",
                script,
                "sh",
                child.to_str().expect("text"),
                grandchild.to_str().expect("text"),
            ],
            &Plan::in_directory(&scratch),
            &Deadline::after(Duration::from_secs(2)),
        );
        let Exit::Unfinished(Outcome::NotAnswered { stopped, .. }) = run.exit else {
            panic!("the stand-in did not run out of its bound");
        };
        assert!(stopped);
        for file in [&child, &grandchild] {
            let number = std::fs::read_to_string(file)
                .expect("the process wrote its number")
                .trim()
                .parse::<i32>()
                .expect("a process number");
            // Gone, or a zombie that only waits to be collected: where nothing collects an orphan
            // at once, a process that was ended still answers a signal for a moment.
            assert!(
                super::super::children::gone_within(number, Duration::from_secs(5)),
                "process {number} of {} is still there after the check answered",
                file.display()
            );
        }
    }

    /// KR-REQ-03.29, S-6: a facility that exits on its own, and one that fails, leave nothing they
    /// started running when the call returns.
    #[cfg(unix)]
    #[test]
    fn a_facility_that_finished_leaves_no_descendant_running() {
        for (what, code) in [("a success", "0"), ("a failure", "3")] {
            let root = kr_ipc::testing::PrivateTempDir::create();
            let scratch = root.path().join("finished");
            std::fs::create_dir_all(&scratch).expect("a directory for this check");
            let file = scratch.join("descendant.pid");
            let script = format!("/bin/sleep 120 & echo $! > \"$1\"; exit {code}");
            let run = bounded(
                Check::ScreenImage,
                "/bin/sh",
                &["-c", &script, "sh", file.to_str().expect("text")],
                &Plan::in_directory(&scratch),
                &Deadline::after(Duration::from_secs(10)),
            );
            assert!(
                matches!(
                    (&run.exit, code),
                    (Exit::Succeeded(_), "0") | (Exit::Failed(_), "3")
                ),
                "{what}: the stand-in exited on its own"
            );
            let number = std::fs::read_to_string(&file)
                .expect("the stand-in wrote the number of what it started")
                .trim()
                .parse::<i32>()
                .expect("a process number");
            let gone = super::super::children::gone_within(number, Duration::from_secs(5));
            if !gone {
                // The case's own cleanup: a failure of it leaves nothing running.
                if let Some(pid) = rustix::process::Pid::from_raw(number) {
                    let _ = rustix::process::kill_process(pid, rustix::process::Signal::KILL);
                }
            }
            assert!(
                gone,
                "{what}: process {number} is still there after the call returned"
            );
        }
    }

    /// A source whose every reading takes `each`, or what the deadline has left if that is less,
    /// and which notes how much the deadline had left when each began.
    struct Paced {
        each: Duration,
        desktop: DesktopContext,
        given: std::sync::Mutex<Vec<Duration>>,
    }

    impl Paced {
        fn of(each: Duration) -> Self {
            Self {
                each,
                desktop: desktop(),
                given: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    impl ContextSource for Paced {
        fn read(&self, deadline: &Deadline) -> Surroundings {
            self.given.lock().expect("the notes").push(deadline.left());
            std::thread::sleep(self.each.min(deadline.left()));
            surroundings(self.desktop.clone())
        }
    }

    /// A stand-in that works until the time it was given is gone, and notes how much it was given.
    #[derive(Default)]
    struct UntilTheDeadline(std::sync::Mutex<Vec<Duration>>);

    impl Facilities for UntilTheDeadline {
        fn perform(&self, check: Check, _plan: &Plan, setting: &Setting<'_>) -> Ran {
            self.0
                .lock()
                .expect("the notes")
                .push(setting.deadline.left());
            while !setting.deadline.expired() {
                std::thread::sleep(Duration::from_millis(20));
            }
            ran(
                check,
                Outcome::Performed {
                    detail: Sentence::new().stated("it ran"),
                },
            )
        }
    }

    /// KR-REQ-03.29, S-8, through the whole check: its readings, its operation and the reading
    /// after it all draw on the one deadline that started before the first of them, so the check
    /// takes no longer than its bound, and the operation is given what is left of it.
    #[test]
    fn the_whole_check_draws_on_one_deadline() {
        let bound = Duration::from_millis(2_400);
        let source = Paced::of(Duration::from_millis(500));
        let facility = UntilTheDeadline::default();
        let started = Instant::now();
        let records = report_timed(
            &[Check::AccessibleElement],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &facility,
            &Seams {
                first: &first_of(&source),
                time_of: &|_| Time {
                    bound,
                    after: Duration::from_millis(800),
                },
                routes: &resolve,
            },
        );
        // The first reading comes before every check and takes its 500 ms outside the bound.
        let taken = started.elapsed();
        assert!(
            taken < Duration::from_millis(500) + bound + Duration::from_millis(100),
            "the check took {taken:?}, which is more than its bound of {bound:?}"
        );
        let given = facility.0.lock().expect("the notes").clone();
        assert_eq!(given.len(), 1, "the operation ran once");
        assert!(
            given[0] <= Duration::from_millis(1_200),
            "the operation was given {:?}, which is more than was left of the check's time \
             after its first reading and before the time kept for after it",
            given[0]
        );
        let reads = source.given.lock().expect("the notes").clone();
        assert!(
            reads.last().is_some_and(|left| !left.is_zero()),
            "the reading after the operation had no time left: {reads:?}"
        );
        assert_eq!(
            state_of(&records, Check::AccessibleElement),
            CapabilityState::QualifiedAvailable
        );
    }

    /// KR-REQ-03.29, S-8: a check whose readings took all its time starts no operation, and says
    /// that its time ran out and not that an operation was started.
    #[test]
    fn a_check_out_of_time_before_its_operation_starts_nothing() {
        let source = Paced::of(Duration::from_millis(700));
        let seeing = Seeing::default();
        let records = report_timed(
            &[Check::AccessibleElement],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &seeing,
            &Seams {
                first: &first_of(&source),
                time_of: &|_| Time {
                    bound: Duration::from_millis(600),
                    after: Duration::from_millis(100),
                },
                routes: &resolve,
            },
        );
        assert!(
            seeing.0.lock().expect("the record").is_empty(),
            "an operation was started with no time left"
        );
        assert_eq!(
            state_of(&records, Check::AccessibleElement),
            CapabilityState::TemporarilyUnavailable
        );
        let reason = records[0]
            .disabled_reason
            .as_ref()
            .map(|sentence| sentence.as_str().to_owned())
            .unwrap_or_default();
        assert_eq!(
            reason,
            "the check did not finish within its time limit. It established no result."
        );
    }

    /// KR-REQ-03.29, S-8: a success whose desktop could not be read again before the check's time
    /// ran out does not stand.
    #[test]
    fn a_success_the_last_reading_had_no_time_to_confirm_does_not_stand() {
        // The readings before the operation are quick; the one after it takes the time that is
        // left, which the operation leaves none of.
        struct SlowAfter {
            reads: std::sync::atomic::AtomicUsize,
        }
        impl ContextSource for SlowAfter {
            fn read(&self, deadline: &Deadline) -> Surroundings {
                let at = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if at >= 2 {
                    std::thread::sleep(deadline.left() + Duration::from_millis(30));
                }
                surroundings(desktop())
            }
        }
        let source = SlowAfter {
            reads: std::sync::atomic::AtomicUsize::new(0),
        };
        let records = report_timed(
            &[Check::AccessibleElement],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &Seeing::default(),
            &Seams {
                first: &first_of(&source),
                time_of: &|_| Time {
                    bound: Duration::from_millis(600),
                    after: Duration::from_millis(100),
                },
                routes: &resolve,
            },
        );
        assert_eq!(
            state_of(&records, Check::AccessibleElement),
            CapabilityState::TemporarilyUnavailable,
            "a success nothing could confirm stands"
        );
        // Where the program's file can be read, the digest taken after the time is gone refuses the
        // answer too, in other words, so the state alone does not show which of the two refused it.
        let reason = records[0]
            .disabled_reason
            .as_ref()
            .map(|sentence| sentence.as_str().to_owned())
            .unwrap_or_default();
        assert_eq!(
            reason, "the check did not finish within its time limit. It established no result.",
            "the answer was refused for another reason than the time that was gone"
        );
    }

    /// What the stand-in does to its program while the operation runs.
    #[derive(Clone, Copy)]
    enum During {
        /// Nothing.
        Nothing,
        /// It writes another build over the file.
        Replacing,
        /// It removes the file, so the program cannot be read again.
        Removing,
    }

    /// A stand-in that runs a program of this test's own and, where asked, changes its file while
    /// the operation is running.
    struct Running {
        program: std::path::PathBuf,
        during: During,
        /// The image the operation could not remove, where it left one.
        left: Option<ImageLeft>,
    }

    impl Facilities for Running {
        fn perform(&self, check: Check, _plan: &Plan, _setting: &Setting<'_>) -> Ran {
            match self.during {
                During::Nothing => {}
                During::Replacing => {
                    std::fs::write(&self.program, b"the second build").expect("the replacement");
                }
                During::Removing => {
                    std::fs::remove_file(&self.program).expect("the removal");
                }
            }
            Ran {
                check,
                facility: Some(self.program.display().to_string()),
                outcome: Outcome::Performed {
                    detail: Sentence::new().stated("it ran"),
                },
                left: self.left.clone(),
            }
        }
    }

    /// Runs the accessibility check against a program of this test's own, which the operation
    /// changes as `during` says, and gives the program's digest from before the operation and the
    /// records.
    fn run_around_a_program(during: During) -> (Option<Sentence>, Vec<CapabilityRecord>) {
        run_around_a_program_leaving(during, None)
    }

    /// [`run_around_a_program`], with an image that the operation could not remove.
    fn run_around_a_program_leaving(
        during: During,
        left: Option<ImageLeft>,
    ) -> (Option<Sentence>, Vec<CapabilityRecord>) {
        let root = kr_ipc::testing::PrivateTempDir::create();
        let program = root.path().join("the-tool");
        let named = program.display().to_string();
        let route = |check: Check, _: &DesktopContext, _: Option<&std::ffi::OsStr>| {
            Some(Operation {
                check,
                route: MACOS,
                program: Program::Tool(named.clone()),
                target: None,
            })
        };
        std::fs::write(&program, b"the first build").expect("the program");
        let before = facility_identity(&named);
        let source = Readings::of(vec![surroundings(desktop())]);
        let records = report_timed(
            &[Check::AccessibleElement],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &Running {
                program,
                during,
                left,
            },
            &Seams {
                first: &first_of(&source),
                time_of: &time_of,
                routes: &route,
            },
        );
        (before, records)
    }

    /// KR-REQ-03.29, R9: the digest an answer carries is the program's before the operation, and an
    /// answer about a program that was replaced while it ran establishes nothing.
    #[test]
    fn a_program_replaced_during_its_operation_establishes_nothing() {
        let (before, records) = run_around_a_program(During::Nothing);
        assert_eq!(
            state_of(&records, Check::AccessibleElement),
            CapabilityState::QualifiedAvailable,
            "a program that stayed as it was"
        );
        assert_eq!(
            records[0].identity.version.as_ref().cloned(),
            before,
            "the digest of the program as it was"
        );
        let (before, records) = run_around_a_program(During::Replacing);
        assert_eq!(
            state_of(&records, Check::AccessibleElement),
            CapabilityState::TemporarilyUnavailable,
            "the answer stood about a program that was replaced while it ran"
        );
        assert_eq!(
            records[0]
                .disabled_reason
                .as_ref()
                .map(|sentence| sentence.as_str()),
            Some("this check established nothing: the program it ran was replaced while it ran")
        );
        assert_eq!(
            records[0].identity.version.as_ref().cloned(),
            before,
            "the record names the program as it was before the operation"
        );
    }

    /// KR-REQ-03.29, R9: a program whose digest cannot be read after the operation is not said to
    /// have been replaced: the answer is refused in words of its own, and the record still names
    /// the program as it was before.
    #[test]
    fn a_program_that_cannot_be_read_after_its_operation_is_not_called_replaced() {
        let (before, records) = run_around_a_program(During::Removing);
        assert_eq!(
            state_of(&records, Check::AccessibleElement),
            CapabilityState::TemporarilyUnavailable,
            "the answer stood about a program nobody could read again"
        );
        assert_eq!(
            records[0]
                .disabled_reason
                .as_ref()
                .map(|sentence| sentence.as_str()),
            Some(
                "this check established nothing: the program it ran could not be read both before \
                 and after it ran, so it is not known whether it was replaced while it ran"
            ),
            "a digest that could not be read is not a replacement"
        );
        assert_eq!(
            records[0].identity.version.as_ref().cloned(),
            before,
            "the record names the program as it was before the operation"
        );
    }

    /// An image that an operation could not remove.
    fn left_behind() -> ImageLeft {
        ImageLeft {
            path: std::path::PathBuf::from("/tmp/the-image.png"),
            error: "permission denied".to_owned(),
        }
    }

    /// What a record's reason says.
    fn said_by(record: &CapabilityRecord) -> String {
        record
            .disabled_reason
            .as_ref()
            .map(|sentence| sentence.as_str().to_owned())
            .unwrap_or_default()
    }

    /// A stand-in whose operation succeeds and leaves an image it could not remove.
    struct Leaving;

    impl Facilities for Leaving {
        fn perform(&self, check: Check, _plan: &Plan, _setting: &Setting<'_>) -> Ran {
            Ran {
                check,
                facility: None,
                outcome: Outcome::Performed {
                    detail: Sentence::new().stated("it ran"),
                },
                left: Some(left_behind()),
            }
        }
    }

    /// KR-REQ-03.29, KR-REQ-03.30, LP-10: an image that could not be removed is said in the answer
    /// the report gives in place of the operation's own, whichever of the four reasons replaced it:
    /// the time limit, a changed context, a program replaced while it ran and a program that could
    /// not be read again.
    #[test]
    fn an_image_that_could_not_be_removed_is_said_when_the_answer_is_replaced_afterwards() {
        let clause = ", and it could not remove ";

        // The time limit: the reading after the operation takes the time that is left.
        struct SlowAfter {
            reads: std::sync::atomic::AtomicUsize,
        }
        impl ContextSource for SlowAfter {
            fn read(&self, deadline: &Deadline) -> Surroundings {
                let at = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if at >= 2 {
                    std::thread::sleep(deadline.left() + Duration::from_millis(30));
                }
                surroundings(desktop())
            }
        }
        let source = SlowAfter {
            reads: std::sync::atomic::AtomicUsize::new(0),
        };
        let records = report_timed(
            &[Check::AccessibleElement],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &Leaving,
            &Seams {
                first: &first_of(&source),
                time_of: &|_| Time {
                    bound: Duration::from_millis(600),
                    after: Duration::from_millis(100),
                },
                routes: &resolve,
            },
        );
        let said = said_by(&records[0]);
        assert!(
            said.starts_with(
                "this check established nothing: the check did not finish within its time limit"
            ) && said.contains(clause),
            "the time limit: {said}"
        );

        // A changed context: the desktop is locked when it is read again.
        let mut locked = desktop();
        locked.availability = DesktopAvailability::Locked;
        let source = Readings::of(vec![
            surroundings(desktop()),
            surroundings(desktop()),
            surroundings(locked),
        ]);
        let records = super::report(
            &first_of(&source),
            &[Check::AccessibleElement],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &Leaving,
        );
        let said = said_by(&records[0]);
        assert!(
            said.contains("the desktop was not in the state this check needs")
                && said.contains(clause),
            "a changed context: {said}"
        );

        // A program replaced while it ran, and one that could not be read again.
        let (_, records) = run_around_a_program_leaving(During::Replacing, Some(left_behind()));
        let said = said_by(&records[0]);
        assert!(
            said.contains("the program it ran was replaced while it ran") && said.contains(clause),
            "a replaced program: {said}"
        );
        let (_, records) = run_around_a_program_leaving(During::Removing, Some(left_behind()));
        let said = said_by(&records[0]);
        assert!(
            said.contains("it is not known whether it was replaced while it ran")
                && said.contains(clause),
            "a program that could not be read again: {said}"
        );
    }

    /// KR-REQ-03.29, R9: a route whose program is not installed keeps the absolute path it would be
    /// installed at in its record, with no digest, so that a later reading sees the file once it
    /// is there.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_tool_that_is_not_installed_keeps_its_path_in_its_record() {
        let route = |check: Check, _: &DesktopContext, _: Option<&std::ffi::OsStr>| {
            Some(Operation {
                check,
                route: MACOS,
                program: Program::Absent(Some("/nonexistent/the-tool".to_owned())),
                target: None,
            })
        };
        let source = Readings::of(vec![surroundings(desktop())]);
        let records = report_timed(
            &[Check::AccessibleElement],
            &subject(),
            &source,
            revision(),
            &Plan::in_directory("."),
            &Platform,
            &Seams {
                first: &first_of(&source),
                time_of: &time_of,
                routes: &route,
            },
        );
        assert_eq!(
            state_of(&records, Check::AccessibleElement),
            CapabilityState::MissingInstallation
        );
        assert_eq!(
            records[0].identity.binary.as_ref().map(String::as_str),
            Some("/nonexistent/the-tool"),
            "the record names the path the tool would be installed at"
        );
        assert!(!records[0].identity.version.is_present(), "and no digest");
    }

    /// KR-REQ-03.29, R11: where a grant exists, a finding says that a permission withdrawn later
    /// shows only when the checks run again; the launch needs no grant and a route with none says
    /// nothing of it.
    #[test]
    fn a_finding_says_a_permission_withdrawn_later_shows_only_on_a_new_run() {
        let said = |check, asking| {
            super::judge(
                check,
                &Outcome::Performed {
                    detail: Sentence::new().stated("it ran"),
                },
                asking,
            )
            .2
            .expect("a reason")
            .as_str()
            .to_owned()
        };
        let words = ". A permission you withdraw later shows only when the checks run again";
        for check in [
            Check::ScreenImage,
            Check::AccessibleElement,
            Check::AuthorisedFileRead,
        ] {
            assert!(said(check, Asking::ForAGrant).ends_with(words), "{check:?}");
            assert!(
                !said(check, Asking::Never).contains("withdraw"),
                "{check:?}"
            );
        }
        assert!(
            !said(Check::ApplicationLaunch, Asking::ForAGrant).contains("withdraw"),
            "the launch needs no grant"
        );
    }

    /// KR-REQ-03.29, S-8: what a check reads of its own files, an image and what a facility printed,
    /// is read inside its time, and a file nobody can read is an empty one and not a time-out.
    #[test]
    fn what_a_check_reads_back_is_read_inside_its_time() {
        let root = kr_ipc::testing::PrivateTempDir::create();
        let file = root.path().join("printed.txt");
        std::fs::write(&file, b"it printed this").expect("a file");
        let live = Deadline::after(Duration::from_secs(60));
        let gone = Deadline::after(Duration::ZERO);
        assert_eq!(
            text_within(&file, &live).as_deref(),
            Some("it printed this")
        );
        assert_eq!(text_within(&file, &gone), None, "time that was gone");
        assert_eq!(
            read_within(&root.path().join("not-there"), &live),
            Some(Vec::new()),
            "a file that is not there is an empty one"
        );
    }

    /// KR-REQ-03.29: a screen image that could not be removed after a time-out is said in the one
    /// sentence the time-out begins, not after the time-out's full stop and a comma.
    #[test]
    fn a_timed_out_image_that_could_not_be_removed_reads_as_one_sentence() {
        let outcome = super::super::payload::with_the_image_left(
            Outcome::TimedOut,
            &ImageLeft {
                path: std::path::PathBuf::from("/tmp/the-image.png"),
                error: "permission denied".to_owned(),
            },
            Asking::ForAGrant,
        );
        let (state, _, reason) = super::judge(Check::ScreenImage, &outcome, Asking::ForAGrant);
        assert_eq!(state, CapabilityState::TemporarilyUnavailable);
        let said = reason
            .expect("the check gives its reason")
            .as_str()
            .to_owned();
        assert!(
            said.starts_with(
                "this check established nothing: the check did not finish within its time limit, \
                 and it could not remove "
            ),
            "the words are one sentence: {said}"
        );
        assert!(!said.contains(".,"), "a comma after a full stop: {said}");
    }

    /// KR-REQ-03.29, S-8: a file that is being read is given up at the next block once the time has
    /// run out in the middle of the read, and what was read so far is not an answer.
    #[cfg(unix)]
    #[test]
    fn a_read_gives_up_at_the_next_block_where_the_time_runs_out_in_the_middle() {
        use std::io::Write as _;

        let root = kr_ipc::testing::PrivateTempDir::create();
        let pipe = root.path().join("slow.pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a pipe for this test");
        // One block at once, and the next one after the time of the read is gone.
        let writer = {
            let pipe = pipe.clone();
            std::thread::spawn(move || {
                let mut end = std::fs::OpenOptions::new()
                    .write(true)
                    .open(pipe)
                    .expect("the writer opens");
                end.write_all(&[b'a'; 1024]).expect("the first block");
                std::thread::sleep(Duration::from_millis(600));
                end.write_all(&[b'b'; 1024]).expect("the second block");
            })
        };
        let read = read_within(&pipe, &Deadline::after(Duration::from_millis(250)));
        writer.join().expect("the writer ended");
        assert_eq!(
            read, None,
            "what was read before the time ran out was given as an answer"
        );
    }

    /// KR-REQ-03.29, S-8: a file is not opened once the time is gone, so what the open would have
    /// said is not an answer: not an empty file and not a missing one.
    #[test]
    fn a_file_is_not_opened_after_the_time_is_gone() {
        let root = kr_ipc::testing::PrivateTempDir::create();
        let gone = Deadline::after(Duration::ZERO);
        assert_eq!(
            read_within(&root.path().join("not-there"), &gone),
            None,
            "a file asked for after the time was gone, which is no answer and not an empty file"
        );
    }

    /// KR-REQ-03.29, S-8: the calls of one check draw on one deadline, so the time they take
    /// together never passes it and each is given the time that is left.
    #[cfg(unix)]
    #[test]
    fn one_deadline_bounds_the_whole_check() {
        let root = kr_ipc::testing::PrivateTempDir::create();
        let scratch = root.path().join("deadline");
        std::fs::create_dir_all(&scratch).expect("a directory for this check");
        let plan = Plan::in_directory(&scratch);
        let deadline = Deadline::after(Duration::from_millis(1_200));
        let started = Instant::now();
        let mut calls = Vec::new();
        for _ in 0..3 {
            let before = started.elapsed();
            let run = bounded(
                Check::ApplicationLaunch,
                "/bin/sh",
                &["-c", "/bin/sleep 0.7"],
                &plan,
                &deadline,
            );
            calls.push((run.exit, started.elapsed() - before));
        }
        assert!(
            matches!(calls[0].0, Exit::Succeeded(_)),
            "the first call has the time it needs"
        );
        let Exit::Unfinished(Outcome::NotAnswered { waited, .. }) = &calls[1].0 else {
            panic!("the second call was given more than was left");
        };
        assert!(*waited < Duration::from_millis(650), "waited {waited:?}");
        assert!(
            matches!(calls[2].0, Exit::Unfinished(Outcome::TimedOut)),
            "a call after the deadline starts nothing, and does not say that it was started"
        );
        assert!(
            started.elapsed() < Duration::from_millis(1_200) + Duration::from_secs(1),
            "the three calls took {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn every_check_declares_what_it_does_before_it_runs() {
        for check in Check::all() {
            let effects = check.effects();
            assert!(!effects.performs.is_empty(), "{check:?} says what it does");
            assert!(effects.bound > Duration::ZERO, "{check:?} is bounded");
        }
    }

    /// KR-REQ-03.30: the one check that sends input or changes data is the destructive one, and it
    /// says it needs a context of its own.
    #[test]
    fn only_the_destructive_check_sends_input_or_changes_data() {
        for check in Check::all() {
            let effects = check.effects();
            if check == Check::SyntheticInput {
                assert!(effects.sends_input);
                assert!(effects.changes_user_data);
                assert!(effects.needs_isolated_context);
            } else {
                assert!(!effects.sends_input, "{check:?} sends no input");
                assert!(!effects.changes_user_data, "{check:?} changes no user data");
                assert!(
                    !effects.needs_isolated_context,
                    "{check:?} needs no context"
                );
            }
        }
    }

    #[test]
    fn a_performed_operation_is_what_establishes_a_capability() {
        let (state, evidence, reason) = judge(
            Check::ScreenImage,
            &Outcome::Performed {
                detail: Sentence::new().stated("it obtained a 1-byte image"),
            },
        );
        assert_eq!(state, CapabilityState::QualifiedAvailable);
        assert_eq!(evidence, CapabilityEvidenceSource::DisclosedProbe);
        assert!(
            reason
                .expect("a reason")
                .as_str()
                .contains("performed the operation")
        );
    }

    #[test]
    fn a_refusal_is_evidence_from_the_probe_and_names_the_permission() {
        let (state, evidence, reason) = judge(
            Check::ScreenImage,
            &Outcome::PermissionRefused {
                permission: "Screen & System Audio Recording",
                detail: Sentence::new().stated("it produced no image"),
            },
        );
        assert_eq!(state, CapabilityState::PermissionRequired);
        assert_eq!(evidence, CapabilityEvidenceSource::DisclosedProbe);
        assert!(
            reason
                .expect("a reason")
                .as_str()
                .contains("Screen & System Audio Recording")
        );
    }

    /// KR-REQ-03.29: a refusal of a macOS permission is said in that platform's scope: the
    /// permission is granted per signed application, and this application does not hold it.
    #[test]
    fn kr_req_03_29_a_macos_refusal_says_the_permission_is_granted_per_signed_application() {
        let (state, evidence, reason) = judge(
            Check::ScreenImage,
            &Outcome::PermissionRefused {
                permission: "Screen & System Audio Recording",
                detail: Sentence::new().stated("it produced no image"),
            },
        );
        assert_eq!(state, CapabilityState::PermissionRequired);
        assert_eq!(evidence, CapabilityEvidenceSource::DisclosedProbe);
        assert_eq!(
            reason.expect("a reason").as_str(),
            "this context performed the operation and the operating system refused it: it \
             produced no image. Screen & System Audio Recording is granted per signed \
             application, and this one does not hold it"
        );
    }

    #[test]
    fn a_withheld_destructive_check_establishes_nothing_either_way() {
        let (state, evidence, reason) =
            judge(Check::SyntheticInput, &Outcome::WithheldForIsolation);
        assert_eq!(state, CapabilityState::NotTested);
        assert_eq!(evidence, CapabilityEvidenceSource::NotProbed);
        assert!(
            reason
                .expect("a reason")
                .as_str()
                .contains("test context of its own")
        );
    }

    /// KR-REQ-03.29: an operation the installed version of a facility cannot perform is
    /// incompatible, and it was performed as far as it could be, so the probe is its evidence; a
    /// facility that is not installed stays a missing installation, which the platform was asked
    /// about and nothing was performed.
    #[test]
    fn kr_req_03_29_an_operation_the_installed_version_cannot_perform_is_incompatible_not_missing()
    {
        let (state, evidence, reason) = judge(
            Check::ScreenImage,
            &Outcome::Unsupported {
                detail: Sentence::new().stated("it has no such option"),
            },
        );
        assert_eq!(state, CapabilityState::Incompatible);
        assert_eq!(evidence, CapabilityEvidenceSource::DisclosedProbe);
        assert_eq!(
            reason.expect("a reason").as_str(),
            "this context started the operation and the installed facility cannot perform it: \
             it has no such option. That is a limit of this tool on this desktop, not a missing \
             permission; another tool or route may still work"
        );
        let (state, evidence, _) = judge(Check::ScreenImage, &Outcome::FacilityMissing);
        assert_eq!(state, CapabilityState::MissingInstallation);
        assert_eq!(evidence, CapabilityEvidenceSource::PlatformQuery);
        // The record a caller reads says the same, and names the facility that was tried.
        let tried = Ran {
            check: Check::ScreenImage,
            facility: Some("/usr/bin/tool".to_owned()),
            outcome: Outcome::Unsupported {
                detail: Sentence::new().stated("it has no such option"),
            },
            left: None,
        };
        let record = record(
            &tried,
            &subject(),
            WorkerProfile::DesktopBound,
            revision(),
            kr_protocol::scalars::TimestampMs::new(1),
        )
        .expect("a record");
        assert_eq!(record.state, CapabilityState::Incompatible);
        assert_eq!(
            record.evidence_source,
            CapabilityEvidenceSource::DisclosedProbe
        );
    }

    #[test]
    fn a_facility_that_is_not_installed_was_never_performed() {
        let (state, evidence, _) = judge(Check::AccessibleElement, &Outcome::FacilityMissing);
        assert_eq!(state, CapabilityState::MissingInstallation);
        assert_eq!(evidence, CapabilityEvidenceSource::PlatformQuery);
    }

    #[test]
    fn a_facility_that_did_not_answer_claims_neither_answer() {
        let (state, evidence, reason) = judge(
            Check::ScreenImage,
            &Outcome::NotAnswered {
                waited: Duration::from_secs(20),
                stopped: true,
            },
        );
        assert_eq!(state, CapabilityState::TemporarilyUnavailable);
        assert_eq!(evidence, CapabilityEvidenceSource::DisclosedProbe);
        assert!(reason.expect("a reason").as_str().contains("20 seconds"));
    }

    #[test]
    fn a_tool_specific_permission_stays_its_own_record() {
        let facilities = Scripted(vec![
            ran(
                Check::AccessibleElement,
                Outcome::Performed {
                    detail: Sentence::new().stated("Finder"),
                },
            ),
            ran(
                Check::ScreenImage,
                Outcome::PermissionRefused {
                    permission: "Screen & System Audio Recording",
                    detail: Sentence::new().stated("no image"),
                },
            ),
            ran(
                Check::ApplicationLaunch,
                Outcome::Performed {
                    detail: Sentence::new().stated("started"),
                },
            ),
            ran(
                Check::AuthorisedFileRead,
                Outcome::Performed {
                    detail: Sentence::new().stated("4096 bytes"),
                },
            ),
            ran(Check::SyntheticInput, Outcome::WithheldForIsolation),
        ]);
        let desktop = desktop();
        let records = report(
            &Check::all(),
            &subject(),
            &desktop,
            revision(),
            &Plan::in_directory("."),
            &facilities,
        );
        assert_eq!(records.len(), 5, "one record per check");
        let state = |capability: &str| {
            records
                .iter()
                .find(|record| record.capability.as_str() == capability)
                .unwrap_or_else(|| panic!("a record for {capability}"))
                .state
        };
        // An accessibility grant this context does hold says nothing about a screen image, and the
        // report does not let one stand in for the other.
        assert_eq!(
            state(capabilities::ACCESSIBILITY),
            CapabilityState::QualifiedAvailable
        );
        assert_eq!(
            state(capabilities::SCREEN_CAPTURE),
            CapabilityState::PermissionRequired
        );
        assert_eq!(
            state(capabilities::INPUT_INJECTION),
            CapabilityState::NotTested
        );
        assert_eq!(
            state(capabilities::AUTHORISED_FILE_READ),
            CapabilityState::QualifiedAvailable
        );
    }

    #[test]
    fn every_probe_record_carries_the_three_triggers_that_end_it() {
        let facilities = Scripted(Vec::new());
        let desktop = desktop();
        let records = report(
            &Check::all(),
            &subject(),
            &desktop,
            revision(),
            &Plan::in_directory("."),
            &facilities,
        );
        for record in &records {
            assert_eq!(
                record.invalidation,
                vec![
                    CapabilityInvalidation::BinaryIdentity,
                    CapabilityInvalidation::DesktopGeneration,
                    CapabilityInvalidation::WorkerProfile,
                ],
                "{} says what makes it stale",
                record.capability
            );
            assert_eq!(
                record.identity.profile.as_ref(),
                Some(&desktop.worker_profile),
                "the record names the profile it was taken under"
            );
        }
    }

    #[test]
    fn a_host_agent_update_a_new_login_and_a_changed_profile_each_end_what_was_held() {
        let earlier = Fingerprint {
            facility: Some("a".to_owned()),
            host_agent: Some("one".to_owned()),
            agent_build: None,
            desktop_generation: Some(11),
            profile: Some(WorkerProfile::DesktopBound),
        };
        let updated = Fingerprint {
            host_agent: Some("two".to_owned()),
            ..earlier.clone()
        };
        assert_eq!(
            updated.changes_since(&earlier),
            vec![CapabilityInvalidation::BinaryIdentity]
        );
        let relogged = Fingerprint {
            desktop_generation: Some(12),
            ..earlier.clone()
        };
        assert_eq!(
            relogged.changes_since(&earlier),
            vec![CapabilityInvalidation::DesktopGeneration]
        );
        let headless = Fingerprint {
            profile: Some(WorkerProfile::HeadlessUser),
            ..earlier.clone()
        };
        assert_eq!(
            headless.changes_since(&earlier),
            vec![CapabilityInvalidation::WorkerProfile]
        );
    }

    #[test]
    fn nothing_ends_what_was_held_because_time_passed() {
        let taken = Fingerprint {
            facility: Some("a".to_owned()),
            host_agent: Some("one".to_owned()),
            agent_build: None,
            desktop_generation: Some(11),
            profile: Some(WorkerProfile::DesktopBound),
        };
        assert!(taken.changes_since(&taken).is_empty());
    }

    #[test]
    fn a_facility_that_can_no_longer_be_identified_is_a_change() {
        let taken = Fingerprint {
            facility: Some("a".to_owned()),
            ..Fingerprint::default()
        };
        let gone = Fingerprint::default();
        assert_eq!(
            gone.changes_since(&taken),
            vec![CapabilityInvalidation::BinaryIdentity],
            "an answer about a file nobody can point at any more is not about that file"
        );
        // And it fires once: a reading that stays unknown is not a change, so a host that can
        // never read one does not drop what it holds over and over.
        assert!(gone.changes_since(&gone).is_empty());
    }

    #[test]
    fn a_record_decides_what_makes_it_stale() {
        let facilities = Scripted(vec![ran(
            Check::ScreenImage,
            Outcome::Performed {
                detail: Sentence::new().stated("an image"),
            },
        )]);
        let desktop = desktop();
        let records = report(
            &Check::all(),
            &subject(),
            &desktop,
            revision(),
            &Plan::in_directory("."),
            &facilities,
        );
        let mut record = records
            .iter()
            .find(|record| record.capability.as_str() == capabilities::SCREEN_CAPTURE)
            .cloned()
            .expect("the screen record");
        let taken = Fingerprint {
            desktop_generation: Some(11),
            ..Fingerprint::default()
        };
        let now = Fingerprint {
            desktop_generation: Some(12),
            ..Fingerprint::default()
        };
        assert_eq!(
            stale(&record, &taken, &now),
            vec![CapabilityInvalidation::DesktopGeneration]
        );
        assert!(stale(&record, &taken, &taken).is_empty());
        // A record that does not list a trigger is not ended by it, whatever moved.
        record
            .invalidation
            .retain(|trigger| *trigger != CapabilityInvalidation::DesktopGeneration);
        assert!(stale(&record, &taken, &now).is_empty());
    }

    #[test]
    fn a_context_is_asked_only_for_the_checks_it_can_perform() {
        // The file read is the same operation everywhere, and synthetic input is never asked.
        let mut context = desktop();
        let asked = performable(&context);
        assert!(asked.contains(&Check::AuthorisedFileRead));
        assert!(!asked.contains(&Check::SyntheticInput));
        // The checks that act on a desktop are this build's on macOS only.
        assert_eq!(
            asked.contains(&Check::ScreenImage),
            cfg!(target_os = "macos")
        );
        // And a context the platform refuses for them is asked for the file read alone.
        context.graphic_access = false;
        assert_eq!(performable(&context), vec![Check::AuthorisedFileRead]);
        let mut locked = desktop();
        locked.availability = DesktopAvailability::Locked;
        assert_eq!(performable(&locked), vec![Check::AuthorisedFileRead]);
        let mut container = desktop();
        container.container = ContainerEnvironment::Container;
        assert_eq!(performable(&container), vec![Check::AuthorisedFileRead]);
    }

    /// The context of an operating system and a display server, otherwise a desktop that nothing
    /// refuses.
    fn desktop_of(display_server: DisplayServer) -> DesktopContext {
        let mut context = desktop();
        context.display_server = display_server;
        context.kind = match display_server {
            DisplayServer::Quartz => DesktopSessionKind::MacosSecuritySession,
            DisplayServer::X11 | DisplayServer::Wayland => DesktopSessionKind::LinuxLogind,
            DisplayServer::WindowsDesktop => DesktopSessionKind::WindowsInteractive,
            DisplayServer::Unknown | DisplayServer::None => context.kind,
        };
        context
    }

    /// The three checks that act on a desktop, with the file read, in capability-name order.
    const ALL_FOUR: [Check; 4] = [
        Check::AccessibleElement,
        Check::ApplicationLaunch,
        Check::AuthorisedFileRead,
        Check::ScreenImage,
    ];

    /// KR-REQ-03.29: which checks a context is asked follows its operating system and the display
    /// server it names. A desktop the build has an operation for gets the checks that act on it; a
    /// display server that is unknown or absent, or that does not belong to the operating system,
    /// gets the file read alone.
    #[test]
    fn kr_req_03_29_the_checks_asked_of_a_context_follow_its_platform_and_display_server() {
        let file_read = vec![Check::AuthorisedFileRead];
        for (os, display_server, wanted) in [
            (HostOs::Macos, DisplayServer::Quartz, ALL_FOUR.to_vec()),
            (HostOs::Linux, DisplayServer::X11, ALL_FOUR.to_vec()),
            (HostOs::Linux, DisplayServer::Wayland, ALL_FOUR.to_vec()),
            (
                HostOs::Windows,
                DisplayServer::WindowsDesktop,
                ALL_FOUR.to_vec(),
            ),
            // A graphical session whose display server this host could not name, and a headless
            // one, have no desktop to point a check at.
            (HostOs::Linux, DisplayServer::Unknown, file_read.clone()),
            (HostOs::Linux, DisplayServer::None, file_read.clone()),
            (HostOs::Macos, DisplayServer::Unknown, file_read.clone()),
            (HostOs::Windows, DisplayServer::Unknown, file_read.clone()),
            (HostOs::Windows, DisplayServer::None, file_read.clone()),
            // A display server of another operating system is not this one's desktop.
            (HostOs::Linux, DisplayServer::Quartz, file_read.clone()),
            (
                HostOs::Linux,
                DisplayServer::WindowsDesktop,
                file_read.clone(),
            ),
            (HostOs::Macos, DisplayServer::X11, file_read.clone()),
            (HostOs::Macos, DisplayServer::Wayland, file_read.clone()),
            (HostOs::Windows, DisplayServer::Wayland, file_read.clone()),
            (HostOs::Windows, DisplayServer::X11, file_read.clone()),
            // A system the build knows no desktop of.
            (HostOs::Other, DisplayServer::X11, file_read.clone()),
            (HostOs::Other, DisplayServer::Quartz, file_read.clone()),
        ] {
            assert_eq!(
                performable_on(os, &desktop_of(display_server)),
                wanted,
                "{os:?} with {display_server:?}"
            );
        }
    }

    /// KR-REQ-03.29: a context the platform already refuses is asked for the file read alone on
    /// every operating system, and a platform that does not read whether the desktop is attended
    /// is still asked.
    #[test]
    fn kr_req_03_29_a_context_the_platform_refuses_is_asked_for_the_file_read_alone() {
        let file_read = vec![Check::AuthorisedFileRead];
        for (os, display_server) in [
            (HostOs::Macos, DisplayServer::Quartz),
            (HostOs::Linux, DisplayServer::X11),
            (HostOs::Linux, DisplayServer::Wayland),
            (HostOs::Windows, DisplayServer::WindowsDesktop),
        ] {
            let mut headless = desktop_of(display_server);
            headless.graphic_access = false;
            let mut locked = desktop_of(display_server);
            locked.availability = DesktopAvailability::Locked;
            let mut ended = desktop_of(display_server);
            ended.availability = DesktopAvailability::Ended;
            let mut container = desktop_of(display_server);
            container.container = ContainerEnvironment::Container;
            let mut wsl = desktop_of(display_server);
            wsl.container = ContainerEnvironment::Wsl;
            for (name, context) in [
                ("headless", headless),
                ("locked", locked),
                ("ended", ended),
                ("container", container),
                ("wsl", wsl),
            ] {
                assert_eq!(
                    performable_on(os, &context),
                    file_read,
                    "{os:?} with {display_server:?}, {name}"
                );
            }
            // Windows reads no attended state at all, and that is not a refusal.
            let mut unread = desktop_of(display_server);
            unread.availability = DesktopAvailability::Unknown;
            assert_eq!(performable_on(os, &unread), ALL_FOUR.to_vec());
        }
    }

    /// KR-REQ-03.29: a session that is present and not displayed, as after a user switch, is not
    /// given the checks that act on the desktop: they would take an image of a screen nobody sees.
    #[test]
    fn kr_req_03_29_a_session_in_the_background_is_not_given_the_desktop_checks() {
        for (os, display_server) in [
            (HostOs::Macos, DisplayServer::Quartz),
            (HostOs::Linux, DisplayServer::X11),
            (HostOs::Linux, DisplayServer::Wayland),
            (HostOs::Windows, DisplayServer::WindowsDesktop),
        ] {
            let mut context = desktop_of(display_server);
            context.availability = DesktopAvailability::Background;
            assert_eq!(
                performable_on(os, &context),
                vec![Check::AuthorisedFileRead],
                "{os:?} with {display_server:?}"
            );
        }
    }

    /// KR-REQ-03.29: a check that acts on a desktop and is asked where this build has no operation
    /// for that desktop establishes nothing: it is never a success, and the record says the
    /// operation was not performed.
    #[test]
    fn kr_req_03_29_a_check_asked_where_this_build_has_no_operation_establishes_nothing() {
        for check in [
            Check::AccessibleElement,
            Check::ApplicationLaunch,
            Check::ScreenImage,
        ] {
            let ran = not_performed_on_this_platform(check);
            let record = record(
                &ran,
                &subject(),
                WorkerProfile::DesktopBound,
                revision(),
                kr_protocol::scalars::TimestampMs::new(1),
            )
            .expect("a record");
            assert_eq!(record.capability.as_str(), check.capability());
            assert_eq!(record.state, CapabilityState::TemporarilyUnavailable);
            assert_eq!(
                record.evidence_source,
                CapabilityEvidenceSource::DisclosedProbe
            );
            assert_eq!(
                record.disabled_reason.0.expect("a reason").as_str(),
                "this check established nothing: this build does not perform this check on this \
                 platform, so the operation was not performed",
                "{check:?}"
            );
        }
    }

    /// KR-REQ-03.29: on an operating system whose operations this build lacks, the machine's own
    /// facilities answer each of the checks that act on a desktop with nothing established.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn kr_req_03_29_the_platform_here_establishes_nothing_for_the_desktop_checks() {
        for check in [
            Check::AccessibleElement,
            Check::ApplicationLaunch,
            Check::ScreenImage,
        ] {
            let ran = perform_here(check, &Plan::in_directory("."));
            assert!(
                matches!(ran.outcome, Outcome::NotAttempted { .. }),
                "{check:?}: {ran:?}"
            );
        }
    }

    #[test]
    fn the_read_check_is_not_run_without_a_file_the_person_nominated() {
        let ran = perform_here(Check::AuthorisedFileRead, &Plan::in_directory("."));
        assert!(matches!(ran.outcome, Outcome::NotAttempted { .. }));
    }

    /// KR-REQ-03.30: without an isolated context of its own, the destructive check is withheld and
    /// nothing is sent.
    #[test]
    fn the_destructive_check_is_withheld_without_a_context_of_its_own() {
        let ran = perform_here(Check::SyntheticInput, &Plan::in_directory("."));
        assert_eq!(ran.outcome, Outcome::WithheldForIsolation);
    }

    #[test]
    fn a_nominated_file_is_read_in_this_context() {
        let directory = std::env::temp_dir().join(format!("kr-probe-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory of this test's own");
        let file = directory.join("authorised.txt");
        std::fs::write(&file, b"the person nominated this").expect("the test's own file");
        let plan = Plan {
            authorised_file: Some(file.clone()),
            ..Plan::in_directory(&directory)
        };
        let ran = perform_here(Check::AuthorisedFileRead, &plan);
        match &ran.outcome {
            Outcome::Performed { detail } => {
                assert!(detail.as_str().contains("25 bytes"), "{detail}");
                // The path is what this host found rather than words of its own, so the detail
                // says its class and its length.
                let path = kr_protocol::hostinfo::export::withheld(
                    ContentClass::Path,
                    &file.display().to_string(),
                );
                assert!(detail.as_str().ends_with(&path), "{detail}");
            }
            other => panic!("the read was performed: {other:?}"),
        }
        // And the reason a person reads never repeats it.
        let (_, _, reason) = judge(ran.check, &ran.outcome);
        let reason = reason.expect("a reason");
        assert!(!reason.as_str().contains("authorised.txt"), "{reason}");
        std::fs::remove_dir_all(&directory).expect("this test's own directory");
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_in_place_of_the_nominated_file_is_not_waited_for() {
        let directory = std::env::temp_dir().join(format!("kr-probe-pipe-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory of this test's own");
        let pipe = directory.join("authorised.pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "a pipe for this test");
        let plan = Plan {
            authorised_file: Some(pipe),
            ..Plan::in_directory(&directory)
        };
        // Nothing writes to it. A read that opened it the ordinary way would wait for a writer
        // that is not coming and answer only when its bound ran out.
        let ran = perform_here(Check::AuthorisedFileRead, &plan);
        match &ran.outcome {
            Outcome::NotAttempted { detail } => {
                assert!(detail.as_str().contains("not a regular file"), "{detail}");
            }
            other => panic!("a pipe is not a file this check reads: {other:?}"),
        }
        std::fs::remove_dir_all(&directory).expect("this test's own directory");
    }

    /// KR-REQ-11.16: a probe declares how long it may take before it runs, and a facility that
    /// keeps running past that bound is ended at it.
    ///
    /// Each check that runs a program is given a facility that does not finish: a shell that
    /// writes its own process number and then becomes a `sleep` far longer than any bound. The
    /// case reads the bound from the check's own declaration, so a bound that moved is the bound
    /// it holds the check to, and it asks the system and not the answer whether the facility is
    /// gone. The four run together, so the case takes as long as the longest bound.
    #[cfg(unix)]
    #[test]
    fn a_facility_that_outlasts_its_checks_declared_bound_is_ended_at_it() {
        // A loaded machine starts and stops processes late, so the upper limit allows for it. A
        // bound that was doubled would still be far outside it.
        const SLACK: Duration = Duration::from_secs(10);
        const LONGER_THAN_ANY_BOUND: &str = "echo $$ > \"$1\"; exec /bin/sleep 120";

        let root = kr_ipc::testing::PrivateTempDir::create();
        let checks = [
            Check::ScreenImage,
            Check::AccessibleElement,
            Check::ApplicationLaunch,
            Check::SyntheticInput,
        ];
        let runs: Vec<_> = checks
            .into_iter()
            .map(|check| {
                let scratch = root.path().join(name(check));
                let pid_file = scratch.join("facility.pid");
                std::thread::spawn(move || {
                    std::fs::create_dir_all(&scratch).expect("a directory for this check");
                    let plan = Plan::in_directory(&scratch);
                    let run = bounded(
                        check,
                        "/bin/sh",
                        &[
                            "-c",
                            LONGER_THAN_ANY_BOUND,
                            "sh",
                            pid_file.to_str().expect("a path that is text"),
                        ],
                        &plan,
                        &Deadline::after(check.effects().bound),
                    );
                    (check, run, pid_file)
                })
            })
            .collect();

        for run in runs {
            let (check, run, pid_file) = run.join().expect("the check's thread finished");
            let bound = check.effects().bound;
            let Exit::Unfinished(Outcome::NotAnswered { waited, stopped }) = run.exit else {
                panic!("{check:?} did not answer that it ran out of its bound");
            };
            assert!(
                waited >= bound,
                "{check:?} gave up after {waited:?}, before its bound of {bound:?}"
            );
            assert!(
                waited < bound + super::super::children::COLLECT + SLACK,
                "{check:?} waited {waited:?} for a facility, past its bound of {bound:?}"
            );
            assert!(
                stopped,
                "{check:?} answered with its facility still running"
            );
            let number = std::fs::read_to_string(&pid_file)
                .expect("the facility wrote its process number")
                .trim()
                .parse::<i32>()
                .expect("a process number");
            let pid = rustix::process::Pid::from_raw(number).expect("a process number above zero");
            assert_eq!(
                rustix::process::test_kill_process(pid),
                Err(rustix::io::Errno::SRCH),
                "the {check:?} facility, process {number}, is still there after the check answered"
            );
        }
    }

    /// KR-REQ-11.16, the bounded clause, for the file check: a read of the nominated file that
    /// never returns is stopped waiting for at the check's declared bound, and the check answers
    /// that it was not attempted, saying how long it waited, rather than holding the run.
    ///
    /// The read is given a stand-in that starts and then does not return for far longer than the
    /// bound. The case reads the bound from the check's own declaration and holds the answer to it
    /// from below and above, and checks whether the stand-in had finished when the check answered,
    /// not only what the check said. Not shown here: a read that the filesystem itself never
    /// finishes (the stand-in replaces the read, not the filesystem); the four checks that run a
    /// program (the case above shows a facility that outlasts its bound is ended); and the control
    /// daemon's own wait for the answer to a run of the checks.
    #[test]
    fn a_file_read_that_never_returns_is_stopped_waiting_for_at_the_checks_declared_bound() {
        // A loaded machine starts a thread late, so the upper limit allows for it.
        const SLACK: Duration = Duration::from_secs(5);

        let root = kr_ipc::testing::PrivateTempDir::create();
        let file = root.path().join("authorised.txt");
        let plan = Plan {
            authorised_file: Some(file.clone()),
            ..Plan::in_directory(root.path().join("scratch"))
        };
        let bound = Check::AuthorisedFileRead.effects().bound;
        // Twice the longest a check that keeps its bound takes (the bound and the slack): the
        // stand-in is still held when a check that keeps its bound answers, and when the case lets
        // it go. A check that waits for the read returns when the stand-in does; one that stops
        // late, but before that, fails the upper limit. It follows the declared bound, whatever
        // that is.
        let stays = (bound + SLACK) * 2;

        let (started_tell, started) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (ended_tell, ended) = std::sync::mpsc::channel();
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stand_in_finished = std::sync::Arc::clone(&finished);
        let began = std::time::Instant::now();
        let ran = read_authorised_file_with(
            &plan,
            move |_| {
                started_tell
                    .send(())
                    .expect("the case is waiting for the stand-in");
                // Kept here until the case lets it go, or for the longest it stays.
                let _ = released.recv_timeout(stays);
                stand_in_finished.store(true, std::sync::atomic::Ordering::SeqCst);
                let _ = ended_tell.send(());
                Ok(FirstBlock::Read(0))
            },
            |_| None,
        );
        let elapsed = began.elapsed();

        assert_eq!(ran.check, Check::AuthorisedFileRead);
        let Outcome::NotAttempted { detail } = &ran.outcome else {
            panic!(
                "the file check did not answer that it was not attempted: {:?}",
                ran.outcome
            );
        };
        assert!(
            elapsed >= bound,
            "the file check answered after {elapsed:?}, before its declared bound of {bound:?}"
        );
        assert!(
            elapsed < bound + SLACK,
            "the file check waited {elapsed:?} for a read that was not coming, past its declared \
             bound of {bound:?}"
        );
        let said = format!(
            " had not been read after {} seconds, so this check stopped waiting for it; the read \
             itself is the filesystem's to finish",
            bound.as_secs()
        );
        assert!(
            detail.as_str().ends_with(&said),
            "the file check's answer does not say it waited {} seconds: {detail}",
            bound.as_secs()
        );
        assert!(
            started.try_recv().is_ok(),
            "the stand-in read had not started when the check answered"
        );
        assert!(
            !finished.load(std::sync::atomic::Ordering::SeqCst),
            "the stand-in read had finished when the check answered, so the check did not stop at \
             its bound"
        );

        let (state, source, reason) = judge(Check::AuthorisedFileRead, &ran.outcome);
        assert_eq!(
            state,
            CapabilityState::TemporarilyUnavailable,
            "a read that did not answer in its bound establishes nothing either way"
        );
        assert_eq!(source, CapabilityEvidenceSource::DisclosedProbe);
        let reason = reason.expect("the evidence says why");
        assert!(
            reason
                .as_str()
                .starts_with("this check established nothing: "),
            "{reason}"
        );

        // The thread the check left waiting ends when the stand-in is let go.
        release.send(()).expect("the stand-in is still waiting");
        ended
            .recv_timeout(SLACK)
            .expect("the stand-in read ended once it was let go");
    }

    /// The file check, on a nominated file in the account's Documents folder whose open is refused
    /// with `errno`, where `lookup` says which permission the place is under.
    #[cfg(unix)]
    fn refused_with(
        errno: i32,
        lookup: impl FnOnce(&Path) -> Option<&'static str> + Send + 'static,
    ) -> Outcome {
        let plan = Plan {
            authorised_file: Some(PathBuf::from("/Users/someone/Documents/notes.txt")),
            ..Plan::in_directory("/nonexistent/scratch")
        };
        read_authorised_file_with(
            &plan,
            move |_| Err(std::io::Error::from_raw_os_error(errno)),
            lookup,
        )
        .outcome
    }

    #[cfg(unix)]
    const DOCUMENTS: &str = "Files & Folders, for the Documents folder";

    /// A privacy protection of macOS refuses an open with `EPERM`; the mode of a file or an access
    /// list refuses it with `EACCES`. The error number decides what the refusal is about, and the
    /// place only says which grant when it was a privacy protection.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_refusal_by_a_privacy_protection_names_the_grant_of_the_place_it_is_in() {
        match refused_with(libc::EPERM, |_| Some(DOCUMENTS)) {
            Outcome::PermissionRefused { permission, .. } => assert_eq!(permission, DOCUMENTS),
            other => panic!("a privacy refusal in a place with a grant names it: {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_refusal_by_a_privacy_protection_at_a_place_no_grant_is_known_for_says_so() {
        let outcome = refused_with(libc::EPERM, |_| None);
        assert!(
            matches!(outcome, Outcome::ProtectionRefused { .. }),
            "{outcome:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_refusal_by_a_mode_or_an_access_list_names_no_grant_in_a_place_that_has_one() {
        // The place that the case above names a grant for: a folder that a grant covers is refused
        // by a file's mode too, and that is not the grant's doing.
        let outcome = refused_with(libc::EACCES, |_| Some(DOCUMENTS));
        assert!(
            matches!(outcome, Outcome::FilesystemRefused { .. }),
            "{outcome:?}"
        );
    }

    /// The record of a read of a file the person nominated names no file: a nominated file is not a
    /// program the platform installs, so the record's `binary` is null, and no part of the path is
    /// anywhere in the record, whatever the read came to.
    #[test]
    fn the_record_of_a_nominated_file_read_holds_no_part_of_the_path() {
        let path = "/mnt/kr_private_volume/kr_private_folder/kr_private_file.txt";
        let plan = Plan {
            authorised_file: Some(PathBuf::from(path)),
            ..Plan::in_directory("/nonexistent/scratch")
        };
        let reads: [fn() -> std::io::Result<FirstBlock>; 4] = [
            || Ok(FirstBlock::Read(5)),
            || Ok(FirstBlock::NotRegular),
            || Err(std::io::ErrorKind::PermissionDenied.into()),
            || Err(std::io::ErrorKind::NotFound.into()),
        ];
        for read in reads {
            let ran = read_authorised_file_with(&plan, move |_| read(), |_| None);
            let made = record(
                &ran,
                &subject(),
                desktop().worker_profile,
                revision(),
                kr_ipc::now_ms(),
            )
            .expect("a record of the read");
            assert!(
                !made.identity.binary.is_present(),
                "the record names the file: {made:?}"
            );
            let json = serde_json::to_string(&made).expect("the record serialises");
            for part in [
                path,
                "kr_private_volume",
                "kr_private_folder",
                "kr_private_file",
            ] {
                assert!(!json.contains(part), "{part} is in the record: {json}");
            }
        }
    }

    /// A folder is not a file this check reads, whatever the platform says of opening it: Windows
    /// refuses the open of a folder as it refuses a file the account may not read, and a person
    /// told that the permissions on the file refuse this account has been told something false.
    #[test]
    fn a_folder_whose_open_is_refused_is_not_a_file_this_check_reads() {
        let root = kr_ipc::testing::PrivateTempDir::create();
        let plan = Plan {
            authorised_file: Some(root.path().to_owned()),
            ..Plan::in_directory(root.path().join("scratch"))
        };
        let ran = read_authorised_file_with(
            &plan,
            |_| Err(std::io::ErrorKind::PermissionDenied.into()),
            |_| None,
        );
        match &ran.outcome {
            Outcome::NotAttempted { detail } => {
                assert!(detail.as_str().contains("not a regular file"), "{detail}");
            }
            other => panic!("a folder is not a file this check reads: {other:?}"),
        }
    }

    /// `permission_for_path` joins what the cases above give it: the account's own home directory
    /// and the volume the kernel says the path is on. A path in a protected folder of the home
    /// directory is under that grant, unless its volume is a removable or a network one, which
    /// decides first.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_permission_for_a_protected_folder_of_the_home_directory_is_read_from_the_account() {
        let home = std::env::home_dir().expect("this account has a home directory");
        // A folder of the home directory can be a link to another volume, so it is the path's own
        // volume that decides here, as it does in the lookup.
        let path = home.join("Library/Mail/notes.txt");
        let expected = match volume::flags_of(&path) {
            Some(flags) if volume::removable(flags) => "Files & Folders, for removable volumes",
            Some(flags) if volume::network(flags) => "Files & Folders, for network volumes",
            _ => "Full Disk Access",
        };
        assert_eq!(permission_for_path(&path), Some(expected));
    }

    /// KR-REQ-11.16, the bounded clause, for the lookup that follows a refused open: the question of
    /// which place a refused path is in is put to the filesystem, and a network volume can refuse
    /// the open at once and then not answer that. It is waited for with the open, so the check
    /// answers at its declared bound and the run is not held.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_lookup_that_stalls_after_a_refused_open_is_stopped_waiting_for_at_the_declared_bound() {
        const SLACK: Duration = Duration::from_secs(5);

        let bound = Check::AuthorisedFileRead.effects().bound;
        let stays = (bound + SLACK) * 2;
        let plan = Plan {
            authorised_file: Some(below_volumes(&["Share", "notes.txt"])),
            ..Plan::in_directory("/nonexistent/scratch")
        };
        let (release, released) = std::sync::mpsc::channel::<()>();
        let (ended_tell, ended) = std::sync::mpsc::channel();
        let began = std::time::Instant::now();
        let ran = read_authorised_file_with(
            &plan,
            |_| Err(std::io::Error::from_raw_os_error(libc::EPERM)),
            move |_| {
                // Kept here until the case lets it go, or for the longest it stays.
                let _ = released.recv_timeout(stays);
                let _ = ended_tell.send(());
                Some(DOCUMENTS)
            },
        );
        let elapsed = began.elapsed();

        assert!(
            matches!(ran.outcome, Outcome::NotAttempted { .. }),
            "the check did not answer that it was not attempted: {:?}",
            ran.outcome
        );
        assert!(
            elapsed < bound + SLACK,
            "the check waited {elapsed:?} for a lookup that was not coming, past its declared \
             bound of {bound:?}"
        );

        // The thread the check left waiting ends when the stand-in is let go.
        release.send(()).expect("the stand-in is still waiting");
        ended
            .recv_timeout(SLACK)
            .expect("the stand-in lookup ended once it was let go");
    }

    #[test]
    fn a_facility_that_failed_is_said_as_the_failure_and_the_measure_of_what_it_printed() {
        let said = "kr-marker-7c1e: no such thing";
        let failure = failed(said);
        assert_eq!(
            failure.as_str(),
            format!(
                "the facility exited with a failure: {}",
                kr_protocol::hostinfo::export::withheld(ContentClass::Message, said)
            )
        );
        assert_eq!(
            failed("").as_str(),
            "the facility exited with a failure and printed nothing"
        );
    }

    /// What the automation facility printed decides which grant a refusal is about, and the answer
    /// names that grant in this host's words and says what was printed as its class and length.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_refusal_is_read_out_of_what_the_facility_printed_and_never_repeats_it() {
        let marker = "kr-marker-7c1e";
        let measured =
            |said: &str| kr_protocol::hostinfo::export::withheld(ContentClass::Message, said);
        for (said, permission) in [
            (
                format!("{marker}: Not authorized to send Apple events to System Events. (-1743)"),
                "Automation, for the platform's user-interface service",
            ),
            (
                format!("{marker}: osascript is not allowed assistive access. (-25211)"),
                "Accessibility",
            ),
        ] {
            match platform::refusal(&said) {
                Outcome::PermissionRefused {
                    permission: named,
                    detail,
                } => {
                    assert_eq!(named, permission);
                    assert!(detail.as_str().ends_with(&measured(&said)), "{detail}");
                    assert!(!detail.as_str().contains(marker), "{detail}");
                }
                other => panic!("{said} is a refusal: {other:?}"),
            }
        }
        for said in [
            format!("{marker}: Connection is invalid. (-609)"),
            format!("{marker}: something else went wrong"),
        ] {
            match platform::refusal(&said) {
                Outcome::NotAttempted { detail } => {
                    assert!(detail.as_str().contains(&measured(&said)), "{detail}");
                    assert!(!detail.as_str().contains(marker), "{detail}");
                }
                other => panic!("{said} is not a refusal: {other:?}"),
            }
        }
    }

    /// What a path's permission is on this platform: only macOS files a refusal under a grant.
    fn on_macos(permission: &'static str) -> Option<&'static str> {
        cfg!(target_os = "macos").then_some(permission)
    }

    #[test]
    fn a_refused_read_names_the_permission_the_path_is_under() {
        let home = Path::new("/Users/someone");
        let on = |path: &str| permission_on(Path::new(path), None, Some(home));
        assert_eq!(
            on("/Users/someone/Documents/notes.txt"),
            on_macos("Files & Folders, for the Documents folder")
        );
        assert_eq!(
            on("/Users/someone/Library/Application Support/com.apple.TCC/TCC.db"),
            on_macos("Full Disk Access")
        );
        assert_eq!(
            on("/Library/Application Support/com.apple.TCC/TCC.db"),
            on_macos("Full Disk Access")
        );
        // A path is read by its parts: `..` leaves the folder it follows.
        assert_eq!(
            on("/Users/someone/Documents/../Desktop/notes.txt"),
            on_macos("Files & Folders, for the Desktop folder")
        );
        assert_eq!(
            on("/Users/someone/Projects/../Downloads/notes.txt"),
            on_macos("Files & Folders, for the Downloads folder")
        );
        assert_eq!(on("/tmp/anything"), None);
    }

    #[test]
    fn a_folder_is_one_of_the_account_s_only_where_the_account_keeps_it() {
        let home = Path::new("/Users/someone");
        // A folder that is called Documents, a folder whose name begins like a protected one, a
        // path that leaves the folder again and another account's folder are not the account's.
        for path in [
            "/opt/Documents/notes.txt",
            "/Users/someone/Projects/Documents/notes.txt",
            "/Users/someone/Library/Mailbox/notes.txt",
            "/Library/Mailbox/notes.txt",
            "/Users/someone/Documents/../Projects/notes.txt",
            "/Users/other/Documents/notes.txt",
        ] {
            assert_eq!(
                permission_on(Path::new(path), None, Some(home)),
                None,
                "{path}"
            );
        }
        // Without a home directory no folder is the account's.
        assert_eq!(
            permission_on(Path::new("/Users/someone/Documents/notes.txt"), None, None),
            None
        );
    }

    /// The mount flags the kernel reported on one Mac for its sealed system volume, its data
    /// volume and an external disk mounted below `/Volumes`.
    const SYSTEM_VOLUME: u32 = 0x4480_d001;
    const DATA_VOLUME: u32 = 0x0490_9080;
    const EXTERNAL_DISK: u32 = 0x04a0_9218;

    /// A path below the folder the volumes are mounted in, built here rather than written out: a
    /// mount path in a source line names a machine.
    fn below_volumes(parts: &[&str]) -> PathBuf {
        parts
            .iter()
            .fold(PathBuf::from("/Volumes"), |path, part| path.join(part))
    }

    #[test]
    fn a_refused_read_on_a_removable_volume_names_the_grant_for_removable_volumes() {
        let on = |parts: &[&str], flags| permission_on(&below_volumes(parts), Some(flags), None);
        let removable = on_macos("Files & Folders, for removable volumes");
        assert_eq!(on(&["Backup", "notes.txt"], EXTERNAL_DISK), removable);
        // The volume is asked before the folder's name: a folder called Documents on an external
        // disk is not the Documents folder of the account.
        assert_eq!(
            on(&["Backup", "Documents", "notes.txt"], EXTERNAL_DISK),
            removable
        );
        // A path on an internal volume, whatever it is spelled like, is not one.
        for flags in [SYSTEM_VOLUME, DATA_VOLUME] {
            assert_eq!(on(&["Internal", "notes.txt"], flags), None);
        }
    }

    /// The mount flags of the same Mac's automounted `/home`: a volume the kernel does not call
    /// local.
    const NETWORK_VOLUME: u32 = 0x0450_0000;

    #[test]
    fn a_refused_read_on_a_network_volume_names_the_grant_for_network_volumes() {
        let on = |parts: &[&str], flags| permission_on(&below_volumes(parts), Some(flags), None);
        let network = on_macos("Files & Folders, for network volumes");
        assert_eq!(on(&["Share", "notes.txt"], NETWORK_VOLUME), network);
        // The volume is asked before the folder's name here too.
        assert_eq!(
            on(&["Share", "Documents", "notes.txt"], NETWORK_VOLUME),
            network
        );
    }

    #[test]
    fn the_volume_decides_before_the_folder_when_the_home_directory_is_on_it() {
        // The cases above give no home directory, so they hold whichever of the two is asked first.
        // Here the Documents folder is the account's own, and the volume that holds it is a
        // removable or a network one.
        let home = below_volumes(&["Backup", "someone"]);
        let path = home.join("Documents/notes.txt");
        let on = |flags| permission_on(&path, Some(flags), Some(&home));
        assert_eq!(
            on(EXTERNAL_DISK),
            on_macos("Files & Folders, for removable volumes")
        );
        assert_eq!(
            on(NETWORK_VOLUME),
            on_macos("Files & Folders, for network volumes")
        );
        // The same folder of the same account on an internal volume is the Documents folder's
        // grant, so the home directory is the account's and the case would not pass without it.
        assert_eq!(
            on(DATA_VOLUME),
            on_macos("Files & Folders, for the Documents folder")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_kernel_answers_for_the_volume_of_a_path_that_is_not_there() {
        let root = kr_ipc::testing::PrivateTempDir::create();
        let flags = volume::flags_of(&root.path().join("nobody/wrote/this.txt"))
            .expect("the kernel answers for the volume of the nearest folder that is there");
        assert!(
            !volume::removable(flags) && !volume::network(flags),
            "this machine's temporary folder is on a removable or a network volume: {flags:#x}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_sentence_for_a_removable_volume_names_its_grant() {
        let path = below_volumes(&["Backup", "notes.txt"]);
        let refused = Outcome::PermissionRefused {
            permission: permission_on(&path, Some(EXTERNAL_DISK), None)
                .expect("a removable volume has a grant to name"),
            detail: Sentence::new()
                .stated("the platform refused to open ")
                .path(&path),
        };
        let (state, _, reason) = judge(Check::AuthorisedFileRead, &refused);
        assert_eq!(state, CapabilityState::PermissionRequired);
        let reason = reason.expect("a refusal says why");
        assert!(
            reason.as_str().ends_with(
                "Files & Folders, for removable volumes is granted per signed application, \
                 and this one does not hold it"
            ),
            "{reason}"
        );
        assert!(!reason.as_str().contains("Backup"), "{reason}");
    }

    #[test]
    fn a_privacy_protection_at_a_place_no_grant_is_known_for_says_so_and_names_no_grant() {
        let refused = Outcome::ProtectionRefused {
            detail: Sentence::new()
                .stated("the platform refused to open ")
                .path(Path::new("/opt/kr-marker/notes.txt")),
        };
        let (state, source, reason) = judge(Check::AuthorisedFileRead, &refused);
        assert_eq!(state, CapabilityState::PermissionRequired);
        assert_eq!(source, CapabilityEvidenceSource::DisclosedProbe);
        let reason = reason.expect("a refusal says why");
        assert!(
            reason.as_str().ends_with(
                "No privacy permission is known for that path: a privacy protection of the \
                 operating system refuses this account"
            ),
            "{reason}"
        );
        assert!(
            !reason.as_str().contains("granted per signed application"),
            "{reason}"
        );
        assert!(!reason.as_str().contains("kr-marker"), "{reason}");
    }

    #[test]
    fn a_refusal_no_privacy_permission_covers_says_so_and_names_no_grant() {
        let refused = Outcome::FilesystemRefused {
            detail: Sentence::new()
                .stated("the platform refused to open ")
                .path(Path::new("/opt/kr-marker/notes.txt")),
        };
        let (state, source, reason) = judge(Check::AuthorisedFileRead, &refused);
        assert_eq!(state, CapabilityState::PermissionRequired);
        assert_eq!(source, CapabilityEvidenceSource::DisclosedProbe);
        let reason = reason.expect("a refusal says why");
        assert!(
            reason.as_str().ends_with(
                "No privacy permission is known for that path: the permissions on the file or \
                 its folders refuse this account"
            ),
            "{reason}"
        );
        assert!(
            !reason.as_str().contains("granted per signed application"),
            "{reason}"
        );
        assert!(!reason.as_str().contains("kr-marker"), "{reason}");
    }
}

/// The disclosed checks, performed on the desktop this process is actually running on.
///
/// Everything else in this module's tests settles a rule; this one settles the machine. It runs
/// the real operations, in this process's own execution context, and writes the records they
/// produce to the file `KR_PROBE_OUT` names.
///
/// It is ignored by default, and deliberately. Two of these checks act on whatever is on the
/// screen of whoever is at the machine, and a suite that took an image of somebody's desktop
/// because they ran the tests would be a suite nobody should run. It is asked for by name, from
/// inside a session's own shell, by the permissions demonstration.
///
/// * `KR_PROBE_OUT` — where the records are written, as JSON. Required.
/// * `KR_PROBE_FILE` — the file the person authorised this context to read. Without one the read
///   check is not performed, because there is no default file worth establishing anything about.
/// * `KR_PROBE_SCRATCH` — the directory a check may put its own working files in. It defaults to
///   the process's temporary directory, and it is never the workspace.
/// * `KR_PROBE_APPLICATION` — the application the launch check starts a new instance of.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "performs the operations the permissions guard; asked for by the permissions demonstration"]
fn the_disclosed_checks_on_this_desktop() {
    use kr_protocol::ids::{CapabilityRevision, EnvironmentId};
    use kr_protocol::scalars::{Nullable, Uuid};

    let out = std::env::var("KR_PROBE_OUT").expect("KR_PROBE_OUT names where the records go");
    let scratch = std::env::var("KR_PROBE_SCRATCH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("kr-disclosed-checks"));
    std::fs::create_dir_all(&scratch).expect("a directory of this check's own");
    let plan = Plan {
        authorised_file: std::env::var("KR_PROBE_FILE").ok().map(Into::into),
        scratch,
        isolated: None,
    };

    let boot = kr_ipc::identity::boot_identity().expect("this host's boot identity");
    let desktop = super::context(WorkerProfile::DesktopBound, boot);
    let subject = CapabilitySubject {
        environment_id: EnvironmentId::new(Uuid::from_bytes([0; 16])),
        desktop_session_id: desktop.desktop_session_id.clone(),
        session_id: Nullable::null(),
        application: Nullable::null(),
        terminal: Nullable::null(),
    };
    let reading = |_: &Deadline| crate::desktop::routes::Surroundings {
        desktop: desktop.clone(),
        variables: crate::desktop::routes::Variables::of_this_process(),
    };
    let records = report(
        &first_reading(&reading),
        &Check::all(),
        &subject,
        &reading,
        CapabilityRevision::new(1),
        &plan,
        &Platform,
    );

    let document = serde_json::json!({
        "login_context": std::env::var("KR_PROBE_CONTEXT").unwrap_or_default(),
        "desktop": desktop,
        "checks": Check::all()
            .into_iter()
            .map(|check| {
                let effects = check.effects();
                serde_json::json!({
                    "capability": check.capability(),
                    "performs": effects.performs,
                    "reads": effects.reads,
                    "writes": effects.writes,
                    "sends_input": effects.sends_input,
                    "changes_user_data": effects.changes_user_data,
                    "needs_isolated_context": effects.needs_isolated_context,
                    "bound_seconds": effects.bound.as_secs(),
                })
            })
            .collect::<Vec<_>>(),
        "records": records,
    });
    std::fs::write(
        &out,
        serde_json::to_string_pretty(&document).expect("the records serialise"),
    )
    .unwrap_or_else(|error| panic!("{out} could not be written: {error}"));

    // Every check answered, and the one that changes something did not run.
    assert_eq!(records.len(), 5, "one record per check");
    let injection = records
        .iter()
        .find(|record| record.capability.as_str() == capabilities::INPUT_INJECTION)
        .expect("a record for synthetic input");
    assert_eq!(
        injection.state,
        CapabilityState::NotTested,
        "a check that changes something is withheld without a context of its own"
    );
    assert_eq!(
        injection.evidence_source,
        CapabilityEvidenceSource::NotProbed
    );
}
