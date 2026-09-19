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
                performs: "takes one image of the desktop, holds it in memory long enough to \
                           measure it, and keeps nothing",
                reads: "whatever is on the screen at that instant",
                writes: "one image into this check's own directory, removed before the check \
                         answers",
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
                performs: "starts one new instance of the nominated application in the \
                           background, and ends the instance it started",
                reads: "nothing",
                writes: "nothing outside the application's own state",
                sends_input: false,
                changes_user_data: false,
                needs_isolated_context: false,
                bound: Duration::from_secs(30),
            },
            Self::SyntheticInput => Effects {
                performs: "delivers one keystroke to the application the isolated context owns",
                reads: "nothing",
                writes: "whatever that keystroke writes, inside the isolated context",
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
    /// The application the launch check starts a new instance of.
    pub application: Option<String>,
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
            application: None,
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
        Outcome::NotAnswered { waited } => (
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(format!(
                "the operation was started and had not answered after {} seconds, so it was \
                 stopped and nothing is established either way. A permission the operating system \
                 asks the person at the machine about looks exactly like this from here",
                waited.as_secs()
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
                "this check {}, so it runs only inside a test context of its own. None was \
                 supplied, so it was not run and nothing is established either way",
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
    let identity = ran.facility.as_deref().and_then(facility_identity);
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
    /// A field that is absent on either side has not been established to have changed, so it fires
    /// nothing: an unreadable permission state is a thing this host does not know, and re-running
    /// a screen capture every time it cannot read one would be a timer wearing a trigger's name.
    #[must_use]
    pub fn changes_since(&self, earlier: &Self) -> Vec<CapabilityInvalidation> {
        let mut fired = Vec::new();
        if moved(earlier.facility.as_ref(), self.facility.as_ref())
            || moved(earlier.host_agent.as_ref(), self.host_agent.as_ref())
        {
            fired.push(CapabilityInvalidation::BinaryIdentity);
        }
        if moved(earlier.permissions.as_ref(), self.permissions.as_ref()) {
            fired.push(CapabilityInvalidation::OsPermission);
        }
        if moved(
            earlier.desktop_generation.as_ref(),
            self.desktop_generation.as_ref(),
        ) {
            fired.push(CapabilityInvalidation::DesktopGeneration);
        }
        if moved(earlier.profile.as_ref(), self.profile.as_ref()) {
            fired.push(CapabilityInvalidation::WorkerProfile);
        }
        fired
    }
}

/// Whether two readings of one field establish that it moved.
fn moved<T: PartialEq>(earlier: Option<&T>, now: Option<&T>) -> bool {
    match (earlier, now) {
        (Some(before), Some(after)) => before != after,
        _ => false,
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
            Check::SyntheticInput if plan.isolated.is_none() => Ran {
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
    let outcome = match read_first_block(path) {
        Ok(count) => Outcome::Performed {
            detail: format!("it read {count} bytes of {}", path.display()),
        },
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            Outcome::PermissionRefused {
                permission: permission_for_path(path).to_owned(),
                detail: format!("the platform refused to open {}: {error}", path.display()),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Outcome::NotAttempted {
            detail: format!("{} is not there", path.display()),
        },
        Err(error) => Outcome::NotAttempted {
            detail: format!("{} could not be read: {error}", path.display()),
        },
    };
    Ran {
        check,
        facility,
        outcome,
    }
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
    /// The application the launch check starts when the caller nominates none.
    ///
    /// The platform's own text editor: it is present on every installation, it opens with an empty
    /// document, and a new instance of it touches nothing the person owns.
    const DEFAULT_APPLICATION: &str = "TextEdit";

    pub(super) fn perform(check: Check, plan: &Plan) -> Ran {
        match check {
            Check::ScreenImage => screen_image(plan),
            Check::AccessibleElement => accessible_element(plan),
            Check::ApplicationLaunch => application_launch(plan),
            Check::SyntheticInput => synthetic_input(plan),
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
        let ran = bounded(
            check,
            CAPTURE,
            &["-x", "-t", "png", &image.to_string_lossy()],
            plan,
        );
        let measured = std::fs::metadata(&image).map(|data| data.len()).ok();
        // Removed whatever happened: the image existing after the check is the one thing this
        // must not leave behind.
        let _ = std::fs::remove_file(&image);
        let outcome = match (&ran.outcome, measured) {
            // The tool exits successfully whether or not the platform let it see the screen, so
            // an image it did not write is the refusal rather than the exit status.
            (Outcome::Performed { .. }, Some(bytes)) if bytes > 0 => Outcome::Performed {
                detail: format!(
                    "it obtained a {bytes}-byte image of the desktop and kept none of it"
                ),
            },
            (Outcome::Performed { .. }, _) => Outcome::PermissionRefused {
                permission: "Screen & System Audio Recording".to_owned(),
                detail: "the capture tool ran and produced no image, which is what this platform \
                         does when the application asking has no recording grant"
                    .to_owned(),
            },
            _ => ran.outcome,
        };
        Ran {
            check,
            facility: ran.facility,
            outcome,
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
        let ran = bounded(
            check,
            AUTOMATION,
            &[
                "-e",
                "tell application \"System Events\" to get name of first application process \
                 whose frontmost is true",
            ],
            plan,
        );
        let outcome = match ran.outcome {
            Outcome::Performed { detail } => {
                let named = detail.trim().to_owned();
                if named.is_empty() {
                    Outcome::NotAttempted {
                        detail: "the accessibility tree answered with no element".to_owned(),
                    }
                } else {
                    Outcome::Performed {
                        detail: format!("it read one element from the accessibility tree: {named}"),
                    }
                }
            }
            Outcome::NotAttempted { detail } => refusal(&detail),
            other => other,
        };
        Ran {
            check,
            facility: ran.facility,
            outcome,
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
        let application = plan.application.as_deref().unwrap_or(DEFAULT_APPLICATION);
        let ran = bounded(
            check,
            LAUNCHER,
            &["-g", "-n", "-W", "-a", application, "--args", "-kr-check"],
            plan,
        );
        Ran {
            check,
            facility: ran.facility,
            outcome: match ran.outcome {
                Outcome::Performed { .. } => Outcome::Performed {
                    detail: format!("it started a new background instance of {application}"),
                },
                other => other,
            },
        }
    }

    /// Delivers one keystroke, and only inside a context that owns its own application.
    fn synthetic_input(plan: &Plan) -> Ran {
        let check = Check::SyntheticInput;
        let Some(isolated) = plan.isolated.as_ref() else {
            return Ran {
                check,
                facility: None,
                outcome: Outcome::WithheldForIsolation,
            };
        };
        if super::installed(AUTOMATION).is_none() {
            return Ran {
                check,
                facility: None,
                outcome: Outcome::FacilityMissing,
            };
        }
        let script = format!(
            "tell application \"System Events\" to tell process \"{}\" to keystroke \"k\"",
            isolated.application.replace('"', "")
        );
        let ran = bounded(check, AUTOMATION, &["-e", &script], plan);
        Ran {
            check,
            facility: ran.facility,
            outcome: match ran.outcome {
                Outcome::Performed { .. } => Outcome::Performed {
                    detail: format!(
                        "it delivered one keystroke to {} inside {}",
                        isolated.application, isolated.described_as
                    ),
                },
                Outcome::NotAttempted { detail } => refusal(&detail),
                other => other,
            },
        }
    }
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
            // by name.
            let _ = child.kill();
            let _ = child.wait();
            Outcome::NotAnswered {
                waited: started.elapsed(),
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
    fn a_reading_this_host_does_not_have_fires_nothing() {
        let taken = Fingerprint {
            permissions: Some("denied".to_owned()),
            ..Fingerprint::default()
        };
        let unreadable = Fingerprint::default();
        assert!(
            unreadable.changes_since(&taken).is_empty(),
            "a permission state this host cannot read has not been established to have changed"
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
