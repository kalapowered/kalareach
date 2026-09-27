//! The desktop this host has, and the capability evidence taken on it.

use std::sync::Arc;

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::desktop::{
    DesktopContext, EnvironmentCapabilitiesParams, EnvironmentCapabilitiesResult,
};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::identity::{BootIdentity, WorkerProfile};
use kr_protocol::ids::CapabilityRevision;
use kr_protocol::scalars::TimestampMs;

use crate::error::{ControllerError, Result};

use super::{Controller, parse};

/// The file this environment's capability revision is recorded in.
///
/// It is durable because a revision must never repeat: a caller compares the revision a record
/// carried with the one it is given now, and a revision that came round again would make a stale
/// record look current.
pub const CAPABILITY_REVISION_FILE: &str = "capabilities";

/// The longest capability-revision record this host reads.
const CAPABILITY_REVISION_LIMIT: u64 = 64;

/// How long a desktop reading is reused before the platform is asked again.
///
/// The reading costs a conversation with the platform's session facilities, and the answer changes
/// only when somebody logs in or out. Nothing waits this out: it is the age at which the next
/// question asks the platform rather than the cache.
pub const DESKTOP_REREAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// The desktop this host has, and how old the reading is.
#[derive(Debug)]
pub(super) struct DesktopReading {
    /// The desktop this machine actually has, labelled with the execution context the
    /// configuration resolves to.
    ///
    /// What a desktop-bound create is checked against, because whether a desktop is there is a
    /// fact about the machine rather than a preference.
    pub(super) context: DesktopContext,
    /// The same reading taken in the resolved execution context, which is what the capability
    /// evidence is about.
    ///
    /// A headless context takes no login session, so it has no desktop session, no display server
    /// and no graphical access. Evidence that said `headless_user` while carrying a desktop's
    /// identity would describe a worker this host never creates.
    pub(super) evidence: DesktopContext,
    /// The revision the capability records of this context are evidence for.
    ///
    /// It advances whenever the evidence changes: a new login, a tool installed or replaced, a
    /// permission that now answers differently, a screen that is now locked. Section 11 requires
    /// evidence to be invalidated when any of those move, and an advancing revision is how a
    /// caller holding the old answer can see that it has been superseded.
    ///
    /// It starts at the moment this daemon began serving rather than at one, so a daemon that
    /// restarts does not hand out a revision it has used before.
    pub(super) revision: CapabilityRevision,
    /// Whether the revision can be kept across a restart.
    ///
    /// A record this host could not read leaves this false, and then the revision stays at zero:
    /// zero claims nothing, where advancing from it would hand out a number this environment may
    /// already have used.
    pub(super) durable_revision: bool,
    /// The records that revision was established for, so a change to any of them can be seen.
    pub(super) records: Vec<kr_protocol::desktop::CapabilityRecord>,
    /// When the platform was last asked.
    pub(super) read_at: std::time::Instant,
}

impl Controller {
    /// Returns the desktop this host has, and the revision its capability evidence belongs to.
    ///
    /// The platform is asked again when the reading is older than [`DESKTOP_REREAD_INTERVAL`].
    pub(super) async fn desktop(&self) -> (DesktopContext, CapabilityRevision) {
        let mut reading = self.desktop.lock().await;
        if reading.read_at.elapsed() >= DESKTOP_REREAD_INTERVAL {
            let (context, evidence) =
                resolved_desktop(self.in_force().worker_profile, &self.boot_identity);
            reading.context = context;
            reading.evidence = evidence;
            reading.read_at = std::time::Instant::now();
        }
        (reading.context.clone(), reading.revision)
    }

    /// Returns the context this host's capability evidence is about, and its revision.
    async fn desktop_evidence(&self) -> (DesktopContext, CapabilityRevision) {
        let _ = self.desktop().await;
        let reading = self.desktop.lock().await;
        (reading.evidence.clone(), reading.revision)
    }

    /// Builds the capability report for this host's desktop, at its current revision.
    ///
    /// The records are compared with the ones the current revision was established for, ignoring
    /// the revision itself and when each was observed. Anything else that has changed is a change
    /// in the evidence, and the revision advances with it: a new login, a tool installed or
    /// replaced, a permission that now answers differently, a desktop that is now locked. A
    /// revision that has moved is how a caller holding an earlier record can tell that the answer
    /// it read has gone stale, which is what section 11 requires of evidence. What this publishes
    /// is the evidence and the revision to compare it against; nothing here refuses an operation,
    /// because no method this daemon serves performs one on a desktop.
    ///
    /// # Errors
    ///
    /// Returns an error when the evidence has changed and the revision it changed to cannot be
    /// recorded. Evidence that has changed is never published under the revision the previous
    /// evidence was described by: one revision would then describe two different answers, and an
    /// action that had bound to the first would find its binding current.
    pub(super) async fn capability_report(
        &self,
    ) -> Result<kr_protocol::desktop::DesktopCapabilityReport> {
        let (context, revision) = self.desktop_evidence().await;
        let mut report =
            crate::desktop::capabilities(self.paths.environment_id(), context, revision);
        // The comparison and the revision it decides are one hold of this lock. Two reports
        // running at once would otherwise both see the old evidence, one would commit the new
        // revision, and the other would hand out records stamped with a revision that no longer
        // describes them.
        let mut reading = self.desktop.lock().await;
        let unchanged = comparable(&report.records) == comparable(&reading.records);
        let revision = if unchanged || !reading.durable_revision {
            // Evidence that has not changed keeps its revision. An environment whose record this
            // host could not read keeps revision zero, which claims nothing: advancing from it
            // would hand out a number this environment may already have used.
            reading.revision
        } else {
            let advanced = CapabilityRevision::new(reading.revision.get().saturating_add(1));
            // The revision outlives this daemon, so a replacement never hands out one it has used
            // before, and a revision that came round again would make a stale record look
            // current. It is therefore published only once it is stored.
            let path = self.paths.state_dir().join(CAPABILITY_REVISION_FILE);
            match kr_ipc::paths::write_owner_only_file(&path, advanced.get().to_string().as_bytes())
            {
                Ok(()) => {
                    reading.revision = advanced;
                    reading.records = report.records.clone();
                    advanced
                }
                // Nothing was recorded, so nothing is published. Handing these records out under
                // the stored revision would describe the tool that was replaced and the one that
                // replaced it with one number, so the answer is the storage failure it is and the
                // next report tries again.
                Err(error) => return Err(ControllerError::Ipc(error)),
            }
        };
        for record in &mut report.records {
            record.revision = revision;
        }
        drop(reading);
        Ok(report)
    }

    /// Returns the execution profile this host creates sessions with when a request chooses none.
    pub async fn default_profile(&self) -> WorkerProfile {
        self.desktop().await.0.worker_profile
    }

    /// Reports what this environment can currently do.
    ///
    /// Capability evidence, never authority: every record says what produced it and what makes it
    /// stale. Nothing here grants anything, and a caller that acts on one of these answers still
    /// needs its own authority for whatever it does and the permissions the operating system
    /// actually granted the tool it uses.
    pub(super) async fn environment_capabilities(
        self: &Arc<Self>,
        params: &ParamsValue,
    ) -> Result<EnvironmentCapabilitiesResult> {
        let params: EnvironmentCapabilitiesParams = parse(params)?;
        if params.environment_id != self.paths.environment_id() {
            return Err(ControllerError::InvalidArgument(format!(
                "this daemon owns environment {}",
                self.paths.environment_id()
            )));
        }
        Ok(EnvironmentCapabilitiesResult {
            environment_id: self.paths.environment_id(),
            // The same answer `host.info` gives: what this host creates a session in when the
            // request chooses nothing, which is what the configuration resolves rather than what
            // the platform alone would say. Two reads of one question must not disagree.
            default_worker_profile: self.default_profile().await,
            desktop: self.capability_report().await?,
            persistence: crate::desktop::persistence(self.supervisor.describe()),
            power: self.power_state().await,
        })
    }
}

/// Returns the sentence a caller is given when a window cannot first-admit a request.
/// Returns the capability revision this environment has already handed out.
///
/// Three answers, and the difference matters. An environment with no record has handed out
/// nothing and starts at zero. A record that reads as a number says what it has handed out. A
/// record that is there and cannot be read says nothing at all, and `None` is that: this host then
/// serves revision zero, which claims nothing, rather than starting again from one and handing out
/// a revision it may already have used.
/// Reads the desktop this host has, and the evidence its resolved execution context has.
///
/// Two readings, because they answer two different questions. The first is what this machine has:
/// a desktop-bound create is refused when there is no desktop, and that is a fact about the
/// machine whatever the configuration prefers. The second is what a session created here would
/// actually get, which is the reading taken in the resolved context rather than the machine's
/// reading with a different label on it: a headless context takes no login session, so it has no
/// desktop session, no display server and no graphical access.
///
/// The platform reading comes first either way, because what the platform offers decides the
/// default the configuration may then override.
pub(super) fn resolved_desktop(
    chosen: Option<kr_protocol::identity::WorkerProfile>,
    boot: &BootIdentity,
) -> (DesktopContext, DesktopContext) {
    let mut physical = crate::desktop::current(boot.clone());
    let platform = crate::desktop::default_profile(&physical);
    // The product default is the platform's own answer, established here; the rungs above it were
    // read when the configuration was accepted, so this is not a second reading of the document.
    let resolved = chosen.unwrap_or(platform);
    let evidence = if resolved == physical.worker_profile {
        physical.clone()
    } else {
        kr_worker::desktop::context(resolved, boot.clone())
    };
    physical.worker_profile = resolved;
    (physical, evidence)
}

pub(super) fn capability_revision(paths: &EnvironmentPaths) -> Option<CapabilityRevision> {
    let path = paths.state_dir().join(CAPABILITY_REVISION_FILE);
    match kr_ipc::paths::read_owner_only_file(&path, CAPABILITY_REVISION_LIMIT) {
        Ok(None) => Some(CapabilityRevision::new(0)),
        Ok(Some(bytes)) => String::from_utf8(bytes)
            .ok()
            .and_then(|text| text.trim().parse::<u64>().ok())
            .map(CapabilityRevision::new),
        Err(_) => None,
    }
}

/// Returns capability records in the form two reports are compared in.
///
/// The revision is what the comparison decides, so it cannot be part of it, and the moment each
/// record was observed changes on every report whether anything else did or not. Everything else
/// is evidence.
fn comparable(
    records: &[kr_protocol::desktop::CapabilityRecord],
) -> Vec<kr_protocol::desktop::CapabilityRecord> {
    records
        .iter()
        .map(|record| {
            let mut record = record.clone();
            record.revision = CapabilityRevision::new(0);
            record.observed_at_ms = TimestampMs::new(0);
            record
        })
        .collect()
}
