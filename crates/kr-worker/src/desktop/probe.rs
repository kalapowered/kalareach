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
//! A probe result is evidence about one moment, one binary and one permission state, and none of
//! those is a clock. [`Fingerprint`] is what a result was taken against: the facility's own
//! identity, the host agent's, the platform's permission state for this subject, the desktop
//! generation and the execution profile. [`Fingerprint::changes_since`] names which
//! [`CapabilityInvalidation`] triggers fired between two of them, and [`stale`] keeps only the
//! triggers the record itself lists. A host-agent update moves the agent's identity; a permission
//! change moves the permission state; a new login moves the generation. Each of those re-runs the
//! checks. The passage of time does not, because nothing about a permission changes by itself.
//!
//! # What runs the operation
//!
//! [`Facilities`] is the seam. The judgements, the records and the staleness rules above are
//! ordinary functions over data, so they are the same on every platform and a test settles them
//! without a desktop. [`Platform`] is the one implementation that starts a real child process, and
//! it is the only thing here that touches the machine.

use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_protocol::desktop::{
    CapabilityEvidenceSource, CapabilityIdentity, CapabilityInvalidation, CapabilityRecord,
    CapabilityState, CapabilitySubject, DesktopContext, capabilities,
};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{CapabilityId, CapabilityRevision};
use kr_protocol::scalars::{Nullable, U64};

use super::capability::{CAPABILITY_VERSION, facility_identity};

/// Reading a file the person authorised this context to read.
///
/// This is a capability in the same shared namespace as the five
/// [`capabilities`](kr_protocol::desktop::capabilities) the platform queries answer, and it has no
/// constant beside them because nothing that reads the platform alone can produce it: the only
/// evidence for it is the read itself. On macOS the permission behind it is Full Disk Access where
/// the nominated file is in a location the platform protects, and nothing at all where it is not,
/// which is why the record names the file.
pub const AUTHORISED_FILE_READ: &str = "desktop.authorised_file_read";

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

    /// The capability this check is evidence about.
    #[must_use]
    pub const fn capability(self) -> &'static str {
        match self {
            Self::AuthorisedFileRead => AUTHORISED_FILE_READ,
            Self::ScreenImage => capabilities::SCREEN_CAPTURE,
            Self::AccessibleElement => capabilities::ACCESSIBILITY,
            Self::ApplicationLaunch => capabilities::APPLICATION_LAUNCH,
            Self::SyntheticInput => capabilities::INPUT_INJECTION,
        }
    }

    /// Whether the thing this check acts through is an installed facility with an identity.
    ///
    /// Four of them run a program, and replacing that program invalidates what was established
    /// about it. The read check acts on a file the person nominated, which is theirs rather than
    /// an installed thing, and it reads only the first block of it by design.
    #[must_use]
    pub const fn digests_its_facility(self) -> bool {
        !matches!(self, Self::AuthorisedFileRead)
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
                performs: "takes one image of the main display, reads it into memory to measure \
                           it, and keeps nothing",
                reads: "whatever is on the main display at that instant",
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
                writes: "nothing: the application this check starts has no documents to reopen \
                         and no state of its own to write",
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
        /// What the check saw, in plain words: a byte count, an element's name, a process.
        detail: String,
    },
    /// The operating system refused it for want of a permission, and named which.
    PermissionRefused {
        /// The permission category a person grants, in the platform's own words.
        permission: String,
        /// What the platform said.
        detail: String,
    },
    /// The facility this check performs the operation with is not installed.
    FacilityMissing,
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
        detail: String,
    },
    /// The check was not run because its effects need a test context of its own.
    WithheldForIsolation,
}

/// One check, what it used and what came of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ran {
    /// The check.
    pub check: Check,
    /// The facility it performed the operation with, by absolute path, where it found one.
    pub facility: Option<String>,
    /// What came of it.
    pub outcome: Outcome,
}

/// Performs one check on this machine.
///
/// The one seam between the rules in this module and the machine. Everything else here is a
/// function over data.
pub trait Facilities {
    /// Performs one check and says what came of it.
    fn perform(&self, check: Check, plan: &Plan) -> Ran;
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
) -> (CapabilityState, CapabilityEvidenceSource, Option<String>) {
    match outcome {
        Outcome::Performed { detail } => (
            CapabilityState::QualifiedAvailable,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(format!(
                "this context performed the operation: {detail}. That is what establishes it, and \
                 it establishes it for this binary and this permission state only"
            )),
        ),
        Outcome::PermissionRefused { permission, detail } => (
            CapabilityState::PermissionRequired,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(format!(
                "this context performed the operation and the operating system refused it: \
                 {detail}. {permission} is granted per signed application, and this one does not \
                 hold it"
            )),
        ),
        Outcome::FacilityMissing => (
            CapabilityState::MissingInstallation,
            CapabilityEvidenceSource::PlatformQuery,
            Some(
                "the platform facility this check performs the operation with is not installed, \
                 so there was nothing to run and nothing to grant"
                    .to_owned(),
            ),
        ),
        Outcome::NotAnswered { waited, stopped } => (
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(format!(
                "the operation was started and had not answered after {} seconds, so it was asked \
                 to stop{} and nothing is established either way. A permission the operating \
                 system asks the person at the machine about looks exactly like this from here",
                waited.as_secs(),
                if *stopped {
                    " and it did"
                } else {
                    ", which it had not done when this check answered"
                }
            )),
        ),
        Outcome::NotAttempted { detail } => (
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(format!("the check could not be attempted: {detail}")),
        ),
        Outcome::WithheldForIsolation => (
            CapabilityState::NotTested,
            CapabilityEvidenceSource::NotProbed,
            Some(format!(
                "this check {}, so it runs only inside a test context that owns the application \
                 the keystroke lands in. It was not run and nothing is established either way",
                check.effects().performs
            )),
        ),
    }
}

/// What makes a disclosed probe's answer stale.
///
/// The four section 3 names, in the order they are written. A timer is not among them: nothing
/// about a permission changes because time passed, and a check that re-ran on a clock would take
/// a screen image of somebody's desktop for no reason.
#[must_use]
pub fn invalidation() -> Vec<CapabilityInvalidation> {
    vec![
        CapabilityInvalidation::BinaryIdentity,
        CapabilityInvalidation::OsPermission,
        CapabilityInvalidation::DesktopGeneration,
        CapabilityInvalidation::WorkerProfile,
    ]
}

/// Turns one run into the record a caller reads.
#[must_use]
pub fn record(
    ran: &Ran,
    subject: &CapabilitySubject,
    profile: WorkerProfile,
    revision: CapabilityRevision,
    observed_at_ms: kr_protocol::scalars::TimestampMs,
) -> Option<CapabilityRecord> {
    let (state, evidence, reason) = judge(ran.check, &ran.outcome);
    // Only a facility this check ran is digested. The read check's "facility" is the person's own
    // file, and reading a document to the end to put a digest of it in a diagnostic is not
    // something a diagnostic should do, nor is it what the check disclosed.
    let identity = if ran.check.digests_its_facility() {
        ran.facility.as_deref().and_then(facility_identity)
    } else {
        None
    };
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
            schema: Nullable::null(),
            profile: Nullable::some(profile),
        },
        invalidation: invalidation(),
        disabled_reason: Nullable(reason),
        observed_at_ms,
    })
}

/// Runs every check and returns one record each, in capability-name order.
///
/// A tool-specific permission stays its own record here. There is no aggregate answer to collapse
/// into, and a caller reading this list reads five separate states: an accessibility grant that
/// this context holds says nothing about a screen image, and the report never says otherwise.
#[must_use]
pub fn report(
    subject: &CapabilitySubject,
    desktop: &DesktopContext,
    revision: CapabilityRevision,
    plan: &Plan,
    facilities: &dyn Facilities,
) -> Vec<CapabilityRecord> {
    let observed_at_ms = kr_ipc::now_ms();
    Check::all()
        .into_iter()
        .filter_map(|check| {
            let ran = facilities.perform(check, plan);
            record(
                &ran,
                subject,
                desktop.worker_profile,
                revision,
                observed_at_ms,
            )
        })
        .collect()
}

/// What a probe result was taken against.
///
/// Two of these that differ in any field describe two different questions, so a result taken
/// against one of them says nothing about the other. This is what drives a re-check: it changes
/// when the thing it describes changes and at no other time.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Fingerprint {
    /// The facility's own identity, as [`facility_identity`] reads it.
    pub facility: Option<String>,
    /// The host agent's own identity. A host-agent update moves it.
    pub host_agent: Option<String>,
    /// The platform's permission state for this subject, however the platform names it.
    pub permissions: Option<String>,
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
    /// a host that can never read one does not re-run the checks over and over.
    #[must_use]
    pub fn changes_since(&self, earlier: &Self) -> Vec<CapabilityInvalidation> {
        let mut fired = Vec::new();
        if earlier.facility != self.facility || earlier.host_agent != self.host_agent {
            fired.push(CapabilityInvalidation::BinaryIdentity);
        }
        if earlier.permissions != self.permissions {
            fired.push(CapabilityInvalidation::OsPermission);
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
/// is not invalidated by it, whatever moved. An empty answer means the record still stands and the
/// checks do not run again.
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

/// What a caller holds between readings, so a check runs again when it has to and not otherwise.
///
/// This is the re-check rule as an object. A caller keeps one of these per subject, hands it the
/// fingerprint of the moment, and gets the records back; the checks run again only when one of the
/// triggers the held records name has fired since they were taken. A host-agent update, a changed
/// permission, a new login and a changed profile each do that. Nothing else does, and in
/// particular no amount of time passing does, which is the whole point: these checks take an image
/// of somebody's screen and start an application, and they do that when there is a reason.
#[derive(Debug, Default)]
pub struct Schedule {
    held: Vec<CapabilityRecord>,
    taken_against: Option<Fingerprint>,
    ran_with: Option<Plan>,
}

impl Schedule {
    /// A schedule holding nothing, whose first reading runs the checks.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The records this schedule is holding, whether or not they still stand.
    #[must_use]
    pub fn held(&self) -> &[CapabilityRecord] {
        &self.held
    }

    /// Which triggers have fired against the held records since they were taken.
    ///
    /// Empty where nothing has fired, and empty is what means the checks do not run again. A
    /// schedule holding nothing has nothing to compare, and answers that it must run.
    #[must_use]
    pub fn fired(&self, now: &Fingerprint) -> Vec<CapabilityInvalidation> {
        let Some(taken_against) = self.taken_against.as_ref() else {
            return Vec::new();
        };
        let mut fired: Vec<CapabilityInvalidation> = Vec::new();
        for record in &self.held {
            for trigger in stale(record, taken_against, now) {
                if !fired.contains(&trigger) {
                    fired.push(trigger);
                }
            }
        }
        fired
    }

    /// Whether the checks have to run again.
    ///
    /// The plan is part of the question. A run given a file the last one did not have is a
    /// different question, and answering it from what was held would report that no file was
    /// nominated to somebody who had just nominated one.
    #[must_use]
    pub fn must_run(&self, now: &Fingerprint, plan: &Plan) -> bool {
        self.held.is_empty() || self.ran_with.as_ref() != Some(plan) || !self.fired(now).is_empty()
    }

    /// Returns the records, running the checks again only where something fired.
    pub fn refresh(
        &mut self,
        subject: &CapabilitySubject,
        desktop: &DesktopContext,
        revision: CapabilityRevision,
        now: &Fingerprint,
        plan: &Plan,
        facilities: &dyn Facilities,
    ) -> &[CapabilityRecord] {
        if self.must_run(now, plan) {
            self.held = report(subject, desktop, revision, plan, facilities);
            self.taken_against = Some(now.clone());
            self.ran_with = Some(plan.clone());
        }
        &self.held
    }
}

/// The facilities of the machine this host is running on.
///
/// One child process per check, started with an argument vector rather than a command line,
/// bounded by the check's own allowance, and with its output written to files in the check's own
/// directory so a facility that prints a great deal cannot fill a pipe and stop.
#[derive(Clone, Debug, Default)]
pub struct Platform;

impl Facilities for Platform {
    fn perform(&self, check: Check, plan: &Plan) -> Ran {
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
            },
            _ => platform::perform(check, plan),
        }
    }
}

/// The authorised-file read, which is the same operation on every platform.
///
/// It opens the file the person nominated and reads the first block of it. Reading the whole of a
/// file the check knows nothing about would be a diagnostic that copies a document into memory, so
/// it reads enough to establish that the bytes come out and stops.
fn read_authorised_file(plan: &Plan) -> Ran {
    let check = Check::AuthorisedFileRead;
    let Some(path) = plan.authorised_file.as_deref() else {
        return Ran {
            check,
            facility: None,
            outcome: Outcome::NotAttempted {
                detail: "no file was nominated for this check, and there is no default: a file \
                         the person did not choose would establish something about the wrong file"
                    .to_owned(),
            },
        };
    };
    let facility = Some(path.display().to_string());
    // A regular file, and nothing else. Opening a pipe or a device would block for as long as
    // whatever is on the other end feels like, and the bound this check declares is on the
    // operation rather than on a clock it does not have.
    match std::fs::metadata(path) {
        Ok(data) if !data.is_file() => {
            return Ran {
                check,
                facility,
                outcome: Outcome::NotAttempted {
                    detail: format!(
                        "{} is not a regular file, and this check reads only a file",
                        path.display()
                    ),
                },
            };
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Ran {
                check,
                facility,
                outcome: Outcome::PermissionRefused {
                    permission: permission_for_path(path).to_owned(),
                    detail: format!(
                        "the platform refused to look at {}: {error}",
                        path.display()
                    ),
                },
            };
        }
        Err(error) => {
            return Ran {
                check,
                facility,
                outcome: Outcome::NotAttempted {
                    detail: format!("{} could not be looked at: {error}", path.display()),
                },
            };
        }
    }
    let outcome = match bounded_read(path, check.effects().bound) {
        None => Outcome::NotAnswered {
            waited: check.effects().bound,
            stopped: false,
        },
        Some(Ok(count)) => Outcome::Performed {
            detail: format!("it read {count} bytes of {}", path.display()),
        },
        Some(Err(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Outcome::PermissionRefused {
                permission: permission_for_path(path).to_owned(),
                detail: format!("the platform refused to open {}: {error}", path.display()),
            }
        }
        Some(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Outcome::NotAttempted {
            detail: format!("{} is not there", path.display()),
        },
        Some(Err(error)) => Outcome::NotAttempted {
            detail: format!("{} could not be read: {error}", path.display()),
        },
    };
    Ran {
        check,
        facility,
        outcome,
    }
}

/// Reads the first block of a file, or gives up on the clock.
///
/// A regular file on a filesystem that has stopped answering blocks in the kernel, and a read has
/// no deadline of its own. The read is done on a thread and waited for with one, so the check
/// answers whatever the filesystem does. A read that never returns leaves its thread waiting
/// rather than the check, which is the trade this makes deliberately: a diagnostic that cannot
/// answer is worse than a thread that is still asleep when the process ends.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn bounded_read(path: &Path, bound: Duration) -> Option<std::io::Result<usize>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    let owned = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = sender.send(read_first_block(&owned));
    });
    receiver.recv_timeout(bound).ok()
}

/// How much of the nominated file the read check takes.
const FIRST_BLOCK: usize = 4_096;

/// Reads the first block of a file and returns how many bytes came out.
fn read_first_block(path: &Path) -> std::io::Result<usize> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path)?;
    let mut block = [0_u8; FIRST_BLOCK];
    let mut read = 0_usize;
    loop {
        match file.read(&mut block[read..]) {
            Ok(0) => return Ok(read),
            Ok(count) => {
                read += count;
                if read == block.len() {
                    return Ok(read);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// The permission a refused read of one path is about, in the platform's own words.
///
/// Naming it is the difference between an answer a person can act on and "permission denied": on
/// macOS the protected locations are separate grants and Full Disk Access is a fourth that covers
/// them all, and a path outside every one of them was refused by the filesystem's own permissions
/// rather than by a privacy grant.
#[must_use]
pub fn permission_for_path(path: &Path) -> &'static str {
    if !cfg!(target_os = "macos") {
        return "the filesystem's own permissions on that path";
    }
    let text = path.to_string_lossy();
    for (fragment, permission) in [
        ("/Desktop/", "Files & Folders, for the Desktop folder"),
        ("/Documents/", "Files & Folders, for the Documents folder"),
        ("/Downloads/", "Files & Folders, for the Downloads folder"),
        (
            "/Library/Application Support/com.apple.TCC",
            "Full Disk Access",
        ),
        ("/Library/Mail", "Full Disk Access"),
        ("/Library/Messages", "Full Disk Access"),
        ("/Library/Safari", "Full Disk Access"),
    ] {
        if text.contains(fragment) {
            return permission;
        }
    }
    "the filesystem's own permissions on that path"
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

    use super::{Check, Outcome, Plan, Ran, bounded};

    /// The platform's screen capture tool.
    const CAPTURE: &str = "/usr/sbin/screencapture";
    /// The platform's automation facility, which is how the accessibility tree is read.
    const AUTOMATION: &str = "/usr/bin/osascript";
    /// The platform's application launcher.
    const LAUNCHER: &str = "/usr/bin/open";
    /// The application the launch check starts.
    ///
    /// The platform's own calculator: it is on every installation, it has no documents to restore
    /// and no saved state to reopen, so a new hidden instance of it does nothing to anything the
    /// person owns. An editor would have reopened whatever they last had open, which is a check
    /// that changes what is on somebody's screen to find out whether it can.
    const APPLICATION: &str = "Calculator";

    pub(super) fn perform(check: Check, plan: &Plan) -> Ran {
        match check {
            Check::ScreenImage => screen_image(plan),
            Check::AccessibleElement => accessible_element(plan),
            Check::ApplicationLaunch => application_launch(plan),
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
    fn screen_image(plan: &Plan) -> Ran {
        let check = Check::ScreenImage;
        let facility = super::installed(CAPTURE);
        if facility.is_none() {
            return Ran {
                check,
                facility,
                outcome: Outcome::FacilityMissing,
            };
        }
        let image: PathBuf = plan.scratch.join("screen-image-check.png");
        let _ = std::fs::remove_file(&image);
        // `-m` is the main display and nothing else: without it this tool writes one file per
        // display, and a check that removed the file it named would leave the others behind.
        let ran = bounded(
            check,
            CAPTURE,
            &["-x", "-m", "-t", "png", &image.to_string_lossy()],
            plan,
        );
        // Read into memory, which is what the capability is about, and dropped again. The bytes
        // are never looked at beyond their length and their first four, which say whether this is
        // an image at all.
        let measured = std::fs::read(&image).ok().map(|bytes| {
            let png = bytes.starts_with(&[0x89, b'P', b'N', b'G']);
            (bytes.len() as u64, png)
        });
        // Removed whatever happened: an image outliving the check is the one thing this must not
        // leave behind, and a removal that failed is said rather than passed over.
        let removal = std::fs::remove_file(&image);
        let left_behind = match removal {
            Ok(()) => None,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => Some(format!(
                ", and it could not remove {}: {error}",
                image.display()
            )),
        };
        let outcome = match (&ran.outcome, measured) {
            // The tool exits successfully whether or not the platform let it see the screen, so
            // an image it did not write is the refusal rather than the exit status.
            (Outcome::Performed { .. }, Some((bytes, png))) if bytes > 0 && png => {
                Outcome::Performed {
                    detail: format!(
                        "it read a {bytes}-byte image of the main display into memory and kept \
                         none of it"
                    ),
                }
            }
            (Outcome::Performed { .. }, _) => refused_recording(
                "the capture tool ran and produced no image, which is what this platform does \
                 when the application asking has no recording grant",
            ),
            // What the tool prints when the platform will not give it the display. A context with
            // no desktop at all was refused before this ran, so what is left is the grant.
            (Outcome::NotAttempted { detail }, _)
                if detail
                    .to_ascii_lowercase()
                    .contains("could not create image") =>
            {
                refused_recording(detail)
            }
            _ => ran.outcome,
        };
        Ran {
            check,
            facility: ran.facility,
            // Whatever the answer, an image this check could not remove is part of it.
            outcome: match (outcome, left_behind) {
                (outcome, None) => outcome,
                (Outcome::Performed { detail }, Some(said)) => Outcome::Performed {
                    detail: format!("{detail}{said}"),
                },
                (Outcome::PermissionRefused { permission, detail }, Some(said)) => {
                    Outcome::PermissionRefused {
                        permission,
                        detail: format!("{detail}{said}"),
                    }
                }
                (Outcome::NotAttempted { detail }, Some(said)) => Outcome::NotAttempted {
                    detail: format!("{detail}{said}"),
                },
                (other, Some(said)) => Outcome::NotAttempted {
                    detail: format!("{other:?}{said}"),
                },
            },
        }
    }

    /// Reads the name of one element from the accessibility tree.
    ///
    /// The frontmost application's own name is the smallest question that needs the tree at all:
    /// answering it needs the Accessibility grant, and asking it needs the Automation grant for
    /// the platform's user-interface service. Nothing is selected, moved or clicked.
    fn accessible_element(plan: &Plan) -> Ran {
        let check = Check::AccessibleElement;
        if super::installed(AUTOMATION).is_none() {
            return Ran {
                check,
                facility: None,
                outcome: Outcome::FacilityMissing,
            };
        }
        // The question has to be one only the grant answers. A process's own name is a property
        // of the process and comes back without it; the elements inside that process are the
        // accessibility tree, and asking for one of those is what the platform gates.
        let ran = bounded(
            check,
            AUTOMATION,
            &[
                "-e",
                "tell application \"System Events\" to tell (first application process whose \
                 frontmost is true) to get the count of UI elements",
            ],
            plan,
        );
        let outcome = match ran.outcome {
            Outcome::Performed { detail } => match detail.trim().parse::<u64>() {
                // An element, not a number. A tree that answered with nothing in it is a tree
                // this check found no element in, and the capability is finding one.
                Ok(0) => Outcome::NotAttempted {
                    detail: "the frontmost application offered no element to read, so nothing \
                             about the accessibility tree is established"
                        .to_owned(),
                },
                Ok(count) => Outcome::Performed {
                    detail: format!(
                        "it read the accessibility tree of the frontmost application and found \
                         {count} elements in it"
                    ),
                },
                Err(_) => Outcome::NotAttempted {
                    detail: format!(
                        "the accessibility tree answered with something that is not a count: {}",
                        detail.trim()
                    ),
                },
            },
            Outcome::NotAttempted { detail } => refusal(&detail),
            other => other,
        };
        Ran {
            check,
            facility: ran.facility,
            outcome,
        }
    }

    /// The refusal for a screen image this platform would not produce.
    fn refused_recording(said: &str) -> Outcome {
        Outcome::PermissionRefused {
            permission: "Screen & System Audio Recording".to_owned(),
            detail: said.trim().to_owned(),
        }
    }

    /// Reads a refusal out of what the automation facility said.
    ///
    /// The two grants fail with different words, and a person sent to the wrong settings pane has
    /// been told nothing useful. Anything else is carried as it came.
    fn refusal(said: &str) -> Outcome {
        let lowered = said.to_ascii_lowercase();
        if lowered.contains("not authorized to send apple events")
            || lowered.contains("not authorised to send apple events")
            || lowered.contains("-1743")
        {
            return Outcome::PermissionRefused {
                permission: "Automation, for the platform's user-interface service".to_owned(),
                detail: said.trim().to_owned(),
            };
        }
        if lowered.contains("assistive")
            || lowered.contains("accessibility")
            || lowered.contains("-25211")
        {
            return Outcome::PermissionRefused {
                permission: "Accessibility".to_owned(),
                detail: said.trim().to_owned(),
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
                detail: format!(
                    "the desktop's user-interface service could not be reached from this \
                     execution context: {}. That is the service being unreachable rather than a \
                     permission being refused",
                    said.trim()
                ),
            };
        }
        Outcome::NotAttempted {
            detail: said.trim().to_owned(),
        }
    }

    /// Starts one new instance of an application in the background, and ends it again.
    ///
    /// `-g` keeps it behind whatever the person is looking at and `-n` makes it a new instance, so
    /// an application they already have open is not disturbed. The process identifiers this check
    /// is given back are the only ones it ends.
    fn application_launch(plan: &Plan) -> Ran {
        let check = Check::ApplicationLaunch;
        if super::installed(LAUNCHER).is_none() {
            return Ran {
                check,
                facility: None,
                outcome: Outcome::FacilityMissing,
            };
        }
        // This check names its own application and takes none from a caller. An application a
        // caller could nominate is one that could write something when it starts, and the effects
        // this check declares would then be true of the default and not of the run.
        let application = APPLICATION;
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
        let ran = bounded(
            check,
            LAUNCHER,
            &["-g", "-j", "-n", "-a", application, "--args", &mark],
            plan,
        );
        let outcome = match ran.outcome {
            // The launcher accepting the request is not the application having started, so the
            // answer waits for the process and says what became of it.
            Outcome::Performed { .. } => match end_marked(&mark, plan) {
                Ended::Gone(named) => Outcome::Performed {
                    detail: format!(
                        "it started a new hidden instance of {application} and ended {named}"
                    ),
                },
                Ended::Lingering(named) => Outcome::Performed {
                    detail: format!(
                        "it started a new hidden instance of {application} and asked {named} to \
                         end, which has not happened yet"
                    ),
                },
                Ended::NeverAppeared => Outcome::NotAttempted {
                    detail: format!(
                        "the launcher accepted a request to start {application} and no process of \
                         it appeared, so whether it starts here is not established"
                    ),
                },
            },
            // A launcher that did not answer may still have started something, so the instance is
            // looked for and ended on this path too.
            other => {
                let _ = end_marked(&mark, plan);
                other
            }
        };
        Ran {
            check,
            facility: ran.facility,
            outcome,
        }
    }

    /// What became of the instance the launch check started.
    enum Ended {
        /// It appeared, it was asked to end, and it has.
        Gone(String),
        /// It appeared and it was still there when the check stopped waiting.
        Lingering(String),
        /// No process carrying this check's mark ever appeared.
        NeverAppeared,
    }

    /// Ends the processes carrying this check's own mark, and says what it ended.
    ///
    /// The mark was made a moment ago by this check, so a process carrying it is one this check
    /// started. Nothing else is looked for, and the processes are ended by the identifiers the
    /// platform gave back rather than by any pattern of its own.
    fn end_marked(mark: &str, plan: &Plan) -> Ended {
        let deadline = std::time::Instant::now() + Check::ApplicationLaunch.effects().bound;
        while std::time::Instant::now() < deadline {
            let pids = marked(mark, plan).unwrap_or_default();
            if !pids.is_empty() {
                let arguments: Vec<&str> = pids.iter().map(String::as_str).collect();
                let _ = bounded(Check::ApplicationLaunch, "/bin/kill", &arguments, plan);
                let named = if pids.len() == 1 {
                    "the one instance it started".to_owned()
                } else {
                    format!("the {} instances it started", pids.len())
                };
                // Asked to end is not ended, and a listing this check could not take is not a
                // listing that came back empty. Only an answer settles it.
                while std::time::Instant::now() < deadline {
                    std::thread::sleep(LAUNCH_POLL);
                    if marked(mark, plan).is_some_and(|pids| pids.is_empty()) {
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
    fn marked(mark: &str, plan: &Plan) -> Option<Vec<String>> {
        let listed = bounded(
            Check::ApplicationLaunch,
            "/usr/bin/pgrep",
            &["-f", mark],
            plan,
        );
        match listed.outcome {
            Outcome::Performed { detail } => Some(
                detail
                    .split_whitespace()
                    .filter(|word| word.chars().all(|character| character.is_ascii_digit()))
                    .map(std::borrow::ToOwned::to_owned)
                    .collect(),
            ),
            // The lister exits with a failure when it matched nothing, which is an answer.
            Outcome::NotAttempted { detail } if detail.trim().is_empty() => Some(Vec::new()),
            _ => None,
        }
    }

    /// How long the launch check waits between looks for the instance it started.
    const LAUNCH_POLL: std::time::Duration = std::time::Duration::from_millis(100);
}

#[cfg(not(target_os = "macos"))]
mod platform {
    //! The facilities of a platform whose disclosed checks this build does not perform.
    //!
    //! The checks belong to every desktop platform and the operations differ on each: a screen
    //! image comes from the compositor's own portal on Wayland and from the display on X11, and
    //! the accessibility tree is a bus rather than an automation facility. Saying so is the honest
    //! answer; performing the wrong operation and reporting its result would not be.

    use super::{Check, Outcome, Plan, Ran};

    pub(super) fn perform(check: Check, _plan: &Plan) -> Ran {
        Ran {
            check,
            facility: None,
            outcome: Outcome::NotAttempted {
                detail: "this build performs the disclosed checks on macOS; on this platform the \
                         capability records carry what the platform itself answers and nothing \
                         here has performed the operation"
                    .to_owned(),
            },
        }
    }
}

/// Returns the path of an installed facility, where it is there and runnable.
fn installed(path: &str) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    metadata.is_file().then(|| path.to_owned())
}

/// Runs one facility with its own allowance and says what came of it.
///
/// The output goes to files in the check's own directory rather than to pipes, so a facility that
/// prints more than a pipe holds cannot stop halfway through waiting for somebody to read it. The
/// allowance is the check's own: a facility still running at the end of it is ended and the check
/// answers [`Outcome::NotAnswered`], which is what a permission prompt the person has not answered
/// looks like from here.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn bounded(check: Check, program: &str, arguments: &[&str], plan: &Plan) -> Ran {
    let facility = installed(program);
    if facility.is_none() {
        return Ran {
            check,
            facility,
            outcome: Outcome::FacilityMissing,
        };
    }
    if let Err(error) = std::fs::create_dir_all(&plan.scratch) {
        return Ran {
            check,
            facility,
            outcome: Outcome::NotAttempted {
                detail: format!(
                    "this check's own directory {} could not be made: {error}",
                    plan.scratch.display()
                ),
            },
        };
    }
    let out_path = plan.scratch.join(format!("{}-out.txt", name(check)));
    let err_path = plan.scratch.join(format!("{}-err.txt", name(check)));
    let (Ok(out), Ok(err)) = (
        std::fs::File::create(&out_path),
        std::fs::File::create(&err_path),
    ) else {
        return Ran {
            check,
            facility,
            outcome: Outcome::NotAttempted {
                detail: "this check could not open a file of its own to collect what the facility \
                         printed"
                    .to_owned(),
            },
        };
    };
    let started = std::time::Instant::now();
    let spawned = std::process::Command::new(program)
        .args(arguments)
        .current_dir(&plan.scratch)
        .stdin(std::process::Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn();
    let Ok(mut child) = spawned else {
        return Ran {
            check,
            facility,
            outcome: Outcome::NotAttempted {
                detail: format!("{program} could not be started"),
            },
        };
    };
    let bound = check.effects().bound;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if started.elapsed() >= bound {
                    break None;
                }
                std::thread::sleep(POLL);
            }
            Err(_) => break None,
        }
    };
    let outcome = match status {
        Some(status) if status.success() => Outcome::Performed {
            detail: std::fs::read_to_string(&out_path).unwrap_or_default(),
        },
        Some(_) => {
            let mut said = std::fs::read_to_string(&err_path).unwrap_or_default();
            if said.trim().is_empty() {
                said = std::fs::read_to_string(&out_path).unwrap_or_default();
            }
            Outcome::NotAttempted {
                detail: said.trim().to_owned(),
            }
        }
        None => {
            // Only this check's own child, by the handle it holds: nothing here looks a process up
            // by name. Collecting it is bounded as well, because a child that will not go is not
            // a reason for a diagnostic to stop answering.
            let _ = child.kill();
            let collected = std::time::Instant::now();
            let stopped = loop {
                match child.try_wait() {
                    Ok(Some(_)) => break true,
                    Err(_) => break false,
                    Ok(None) if collected.elapsed() >= COLLECT => break false,
                    Ok(None) => std::thread::sleep(POLL),
                }
            };
            Outcome::NotAnswered {
                waited: started.elapsed(),
                stopped,
            }
        }
    };
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);
    Ran {
        check,
        facility,
        outcome,
    }
}

/// How often a running facility is asked whether it has finished.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const POLL: Duration = Duration::from_millis(50);

/// How long a facility that was asked to stop is waited for before the check answers anyway.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const COLLECT: Duration = Duration::from_secs(2);

/// A short file-name stem for one check.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
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

    /// A stand-in that answers each check with whatever the test put in it.
    struct Scripted(Vec<Ran>);

    impl Facilities for Scripted {
        fn perform(&self, check: Check, _plan: &Plan) -> Ran {
            self.0
                .iter()
                .find(|ran| ran.check == check)
                .cloned()
                .unwrap_or(Ran {
                    check,
                    facility: None,
                    outcome: Outcome::FacilityMissing,
                })
        }
    }

    fn ran(check: Check, outcome: Outcome) -> Ran {
        Ran {
            check,
            facility: None,
            outcome,
        }
    }

    #[test]
    fn every_check_declares_what_it_does_before_it_runs() {
        for check in Check::all() {
            let effects = check.effects();
            assert!(!effects.performs.is_empty(), "{check:?} says what it does");
            assert!(effects.bound > Duration::ZERO, "{check:?} is bounded");
        }
    }

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
                detail: "it obtained a 1-byte image".to_owned(),
            },
        );
        assert_eq!(state, CapabilityState::QualifiedAvailable);
        assert_eq!(evidence, CapabilityEvidenceSource::DisclosedProbe);
        assert!(
            reason
                .expect("a reason")
                .contains("performed the operation")
        );
    }

    #[test]
    fn a_refusal_is_evidence_from_the_probe_and_names_the_permission() {
        let (state, evidence, reason) = judge(
            Check::ScreenImage,
            &Outcome::PermissionRefused {
                permission: "Screen & System Audio Recording".to_owned(),
                detail: "it produced no image".to_owned(),
            },
        );
        assert_eq!(state, CapabilityState::PermissionRequired);
        assert_eq!(evidence, CapabilityEvidenceSource::DisclosedProbe);
        assert!(
            reason
                .expect("a reason")
                .contains("Screen & System Audio Recording")
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
                .contains("test context of its own")
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
        assert!(reason.expect("a reason").contains("20 seconds"));
    }

    #[test]
    fn a_tool_specific_permission_stays_its_own_record() {
        let facilities = Scripted(vec![
            ran(
                Check::AccessibleElement,
                Outcome::Performed {
                    detail: "Finder".to_owned(),
                },
            ),
            ran(
                Check::ScreenImage,
                Outcome::PermissionRefused {
                    permission: "Screen & System Audio Recording".to_owned(),
                    detail: "no image".to_owned(),
                },
            ),
            ran(
                Check::ApplicationLaunch,
                Outcome::Performed {
                    detail: "started".to_owned(),
                },
            ),
            ran(
                Check::AuthorisedFileRead,
                Outcome::Performed {
                    detail: "4096 bytes".to_owned(),
                },
            ),
            ran(Check::SyntheticInput, Outcome::WithheldForIsolation),
        ]);
        let desktop = desktop();
        let records = report(
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
            state(AUTHORISED_FILE_READ),
            CapabilityState::QualifiedAvailable
        );
    }

    #[test]
    fn every_probe_record_carries_the_four_triggers_that_re_run_it() {
        let facilities = Scripted(Vec::new());
        let desktop = desktop();
        let records = report(
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
                    CapabilityInvalidation::OsPermission,
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
    fn a_host_agent_update_and_a_permission_change_each_re_run_the_checks() {
        let earlier = Fingerprint {
            facility: Some("a".to_owned()),
            host_agent: Some("one".to_owned()),
            permissions: Some("denied".to_owned()),
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
        let granted = Fingerprint {
            permissions: Some("granted".to_owned()),
            ..earlier.clone()
        };
        assert_eq!(
            granted.changes_since(&earlier),
            vec![CapabilityInvalidation::OsPermission]
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
    fn nothing_re_runs_because_time_passed() {
        let taken = Fingerprint {
            facility: Some("a".to_owned()),
            host_agent: Some("one".to_owned()),
            permissions: Some("denied".to_owned()),
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
        // never read one does not take an image of a screen over and over.
        assert!(gone.changes_since(&gone).is_empty());
    }

    #[test]
    fn a_schedule_runs_the_checks_when_something_fired_and_not_otherwise() {
        let facilities = Scripted(vec![ran(
            Check::ScreenImage,
            Outcome::Performed {
                detail: "an image".to_owned(),
            },
        )]);
        let desktop = desktop();
        let subject = subject();
        let plan = Plan::in_directory(".");
        let taken = Fingerprint {
            permissions: Some("denied".to_owned()),
            profile: Some(WorkerProfile::DesktopBound),
            ..Fingerprint::default()
        };

        let mut schedule = Schedule::new();
        assert!(
            schedule.must_run(&taken, &plan),
            "nothing held is nothing to trust"
        );
        let first = schedule
            .refresh(&subject, &desktop, revision(), &taken, &plan, &facilities)
            .to_vec();
        assert_eq!(first.len(), 5);

        // The same moment: nothing fired, nothing runs, and the answers are the ones already held.
        assert!(!schedule.must_run(&taken, &plan));
        assert!(schedule.fired(&taken).is_empty());
        let again = schedule
            .refresh(&subject, &desktop, revision(), &taken, &plan, &facilities)
            .to_vec();
        assert_eq!(
            again, first,
            "an unchanged moment does not re-run the checks"
        );

        // A permission changed, which is one of the triggers every probe record carries.
        let granted = Fingerprint {
            permissions: Some("granted".to_owned()),
            ..taken.clone()
        };
        assert_eq!(
            schedule.fired(&granted),
            vec![CapabilityInvalidation::OsPermission]
        );
        assert!(schedule.must_run(&granted, &plan));
        // And it runs, rather than handing back what it held against the moment before.
        let after = schedule
            .refresh(&subject, &desktop, revision(), &granted, &plan, &facilities)
            .to_vec();
        assert_eq!(after.len(), 5);
        assert!(
            schedule.fired(&granted).is_empty(),
            "and it is current again"
        );

        // A different question is a different answer, whatever the moment says. A run given a
        // file the last one did not have must not be answered from the one that had none.
        let nominated = Plan {
            authorised_file: Some("/etc/hosts".into()),
            ..Plan::in_directory(".")
        };
        assert!(
            schedule.must_run(&granted, &nominated),
            "a plan the held answers were not taken against is a question nobody has answered"
        );
    }

    #[test]
    fn a_record_decides_what_makes_it_stale() {
        let facilities = Scripted(vec![ran(
            Check::ScreenImage,
            Outcome::Performed {
                detail: "an image".to_owned(),
            },
        )]);
        let desktop = desktop();
        let records = report(
            &subject(),
            &desktop,
            revision(),
            &Plan::in_directory("."),
            &facilities,
        );
        let record = records
            .iter()
            .find(|record| record.capability.as_str() == capabilities::SCREEN_CAPTURE)
            .expect("the screen record");
        let taken = Fingerprint {
            permissions: Some("granted".to_owned()),
            ..Fingerprint::default()
        };
        let now = Fingerprint {
            permissions: Some("revoked".to_owned()),
            ..Fingerprint::default()
        };
        assert_eq!(
            stale(record, &taken, &now),
            vec![CapabilityInvalidation::OsPermission]
        );
        assert!(stale(record, &taken, &taken).is_empty());
    }

    #[test]
    fn the_read_check_is_not_run_without_a_file_the_person_nominated() {
        let ran = Platform.perform(Check::AuthorisedFileRead, &Plan::in_directory("."));
        assert!(matches!(ran.outcome, Outcome::NotAttempted { .. }));
    }

    #[test]
    fn the_destructive_check_is_withheld_without_a_context_of_its_own() {
        let ran = Platform.perform(Check::SyntheticInput, &Plan::in_directory("."));
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
        let ran = Platform.perform(Check::AuthorisedFileRead, &plan);
        match ran.outcome {
            Outcome::Performed { detail } => assert!(detail.contains("25 bytes")),
            other => panic!("the read was performed: {other:?}"),
        }
        std::fs::remove_dir_all(&directory).expect("this test's own directory");
    }

    #[test]
    fn a_refused_read_names_the_permission_the_path_is_under() {
        assert_eq!(
            permission_for_path(Path::new("/Users/someone/Documents/notes.txt")),
            if cfg!(target_os = "macos") {
                "Files & Folders, for the Documents folder"
            } else {
                "the filesystem's own permissions on that path"
            }
        );
        assert_eq!(
            permission_for_path(Path::new(
                "/Users/someone/Library/Application Support/com.apple.TCC/TCC.db"
            )),
            if cfg!(target_os = "macos") {
                "Full Disk Access"
            } else {
                "the filesystem's own permissions on that path"
            }
        );
        assert_eq!(
            permission_for_path(Path::new("/tmp/anything")),
            "the filesystem's own permissions on that path"
        );
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
    let records = report(
        &subject,
        &desktop,
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
