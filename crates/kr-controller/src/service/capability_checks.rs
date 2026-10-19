//! The disclosed checks, asked for by a person and performed in a session's own worker.
//!
//! A platform grants a screen image or the accessibility tree to a signed program, and the daemon
//! and a worker are different programs, so the daemon never performs the checks itself. It asks
//! a session's worker over a connection of its own, holds what the worker found, and lets that
//! replace the platform's answer in `environment.capabilities` for as long as nothing has ended it.
//! Nothing here runs on a read: the checks take a screen image and start an application, so a
//! person asks, after being shown what each one does, with `environment.capabilities.check`.
//!
//! What ends the findings is what the records themselves list ([`probe::stale`]): the worker that
//! performed them is gone or replaced, a new login moved the desktop's generation, the execution
//! profile changed, or a tool they use was installed, removed or replaced. A change of permission
//! is not something this host can read; it is found by performing the checks again.

use std::sync::{Arc, PoisonError};
use std::time::Duration;

use kr_protocol::desktop::{
    CapabilityChecks, CapabilityChecksFailure, CapabilityChecksState, CapabilityRecord,
    DesktopChecksAnswer, DesktopChecksRequest, DesktopContext, EnvironmentCapabilitiesCheckParams,
    capabilities,
};
use kr_protocol::digest::mutation_digest;
use kr_protocol::envelope::{ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::ids::{ActorId, EnvironmentId, RequestId, SessionId};
use kr_protocol::local::ControllerConnectionRole;
use kr_protocol::retained::Level;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_worker::desktop::capability::{context_refuses, tools_of};
use kr_worker::desktop::probe::{Fingerprint, stale};

use crate::authority::AdmittedMutation;
use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};

use super::{Controller, parse};

/// How long the daemon waits for a worker's findings before it calls the run failed.
///
/// The checks' own bounds add to about a minute and three quarters in the worst case, and a
/// permission prompt can hold each of them to its bound, so this is a margin over that and not a
/// figure the worker is made to meet.
pub(super) const CHECKS_WAIT: Duration = Duration::from_secs(150);

/// The capabilities a worker's findings may name.
///
/// Synthetic input is not among them: it is never performed, and its record is the platform's.
const FINDINGS: [&str; 4] = [
    capabilities::ACCESSIBILITY,
    capabilities::APPLICATION_LAUNCH,
    capabilities::AUTHORISED_FILE_READ,
    capabilities::SCREEN_CAPTURE,
];

/// A run of the checks that is in progress.
#[derive(Debug)]
struct Running {
    started_at_ms: TimestampMs,
    session_id: SessionId,
    /// What the desktop and the worker were when the run began, which is what its findings are
    /// about: a login or a profile that changes while the run goes on is a change since.
    taken: Fingerprint,
}

/// What a worker found, and what it was found against.
#[derive(Debug)]
struct Held {
    fingerprint: Fingerprint,
    records: Vec<CapabilityRecord>,
}

/// What this daemon holds of the disclosed checks.
///
/// In memory only: a daemon that starts again has asked nothing, and the findings were about a
/// moment, a worker and a login that it has no way to vouch for.
#[derive(Debug)]
pub(super) struct Checks {
    /// The identifier of the latest run, which its answer carries.
    latest_request: u64,
    running: Option<Running>,
    /// How the latest run ended, or that there has been none.
    latest: CapabilityChecks,
    /// The findings, while nothing has ended them.
    held: Option<Held>,
    /// Whether findings were held and something has ended them since.
    ended: bool,
    /// Counts the changes to what is held: it moves when a run replaces the findings and when
    /// something ends them, so a reading made against findings can tell they are no longer those.
    generation: u64,
}

impl Checks {
    pub(super) const fn new() -> Self {
        Self {
            latest_request: 0,
            running: None,
            latest: CapabilityChecks::not_run(),
            held: None,
            ended: false,
            generation: 0,
        }
    }

    /// Where the checks stand, for `environment.capabilities`.
    pub(super) fn view(&self) -> CapabilityChecks {
        if let Some(running) = &self.running {
            return CapabilityChecks {
                state: CapabilityChecksState::Running,
                started_at_ms: Nullable::some(running.started_at_ms),
                finished_at_ms: Nullable::null(),
                session_id: Nullable::some(running.session_id),
                failure: Nullable::null(),
            };
        }
        let mut view = self.latest.clone();
        if self.ended && view.state == CapabilityChecksState::Current {
            view.state = CapabilityChecksState::Stale;
        }
        view
    }

    /// Whether a run is in progress.
    pub(super) const fn is_running(&self) -> bool {
        self.running.is_some()
    }

    /// Decides what an action to run the checks comes to.
    ///
    /// A run already going is not started again, and the answer says that it is going. With no
    /// worker to run them in, the run is refused and the state says why. Otherwise a run begins,
    /// and the request to send the worker is returned.
    fn ask(
        &mut self,
        now_ms: TimestampMs,
        worker: Option<SessionId>,
        taken: Fingerprint,
    ) -> Option<RequestId> {
        if self.is_running() {
            return None;
        }
        let Some(session_id) = worker else {
            self.failed(now_ms, None, CapabilityChecksFailure::NoSession);
            return None;
        };
        Some(self.begin(now_ms, session_id, taken))
    }

    /// Notes that a run began in this session's worker, as seen from the desktop in `taken`, and
    /// returns the identifier the run's request and answer carry. Each run has its own.
    fn begin(
        &mut self,
        started_at_ms: TimestampMs,
        session_id: SessionId,
        taken: Fingerprint,
    ) -> RequestId {
        self.latest_request = self.latest_request.saturating_add(1);
        self.running = Some(Running {
            started_at_ms,
            session_id,
            taken,
        });
        RequestId::new(self.latest_request)
    }

    /// Notes that the run ended with these findings.
    ///
    /// They are held against what the desktop, the tools and the worker were when the run began.
    fn succeeded(&mut self, finished_at_ms: TimestampMs, records: Vec<CapabilityRecord>) {
        let Some(running) = self.running.take() else {
            return;
        };
        self.latest = CapabilityChecks {
            state: CapabilityChecksState::Current,
            started_at_ms: Nullable::some(running.started_at_ms),
            finished_at_ms: Nullable::some(finished_at_ms),
            session_id: Nullable::some(running.session_id),
            failure: Nullable::null(),
        };
        self.held = Some(Held {
            fingerprint: running.taken,
            records,
        });
        self.ended = false;
        self.generation += 1;
    }

    /// Notes that the run, or the attempt to start one, established nothing.
    ///
    /// What was held before stands as long as it stands: a run that failed has not shown that
    /// the earlier findings are wrong.
    fn failed(
        &mut self,
        now_ms: TimestampMs,
        session_id: Option<SessionId>,
        failure: CapabilityChecksFailure,
    ) {
        let started_at_ms = self.running.take().map(|running| running.started_at_ms);
        self.latest = CapabilityChecks {
            state: CapabilityChecksState::Failed,
            started_at_ms: Nullable(started_at_ms.or(Some(now_ms))),
            finished_at_ms: Nullable::some(now_ms),
            session_id: Nullable(session_id),
            failure: Nullable::some(failure),
        };
    }

    /// Returns the findings that still stand, and lets go of the ones that do not.
    ///
    /// A record names its own invalidation triggers, and a fingerprint that moved on a trigger a
    /// record lists ends the record. The triggers are the same for every record of one run, so one
    /// ended is all ended, and they are not kept to be served again if a reading recovers.
    ///
    /// `now` is the desktop, the tools and the worker as they are at this reading.
    pub(super) fn standing(&mut self, now: &Fingerprint) -> Vec<CapabilityRecord> {
        let Some(held) = self.held.as_ref() else {
            return Vec::new();
        };
        let ended = held
            .records
            .iter()
            .any(|record| !stale(record, &held.fingerprint, now).is_empty());
        if ended {
            self.held = None;
            self.ended = true;
            self.generation += 1;
            return Vec::new();
        }
        held.records.clone()
    }

    /// The worker whose findings are held, where findings are, and which findings they are: a
    /// reading made against one stamp is of use only while the stamp is the same.
    pub(super) fn held_stamp(&self) -> (Option<SessionId>, u64) {
        let session = self
            .held
            .as_ref()
            .and_then(|held| held.records.first())
            .and_then(|record| record.subject.session_id.0);
        (session, self.generation)
    }
}

/// What the desktop, the tools and the worker are, for a fingerprint of this moment.
///
/// The host agent is the worker that performed the checks, by the identity the kernel records for
/// its process: a replaced worker is another agent. The generation and the profile are the
/// desktop's. The tools are the ones the checks use, read from the machine as [`tools_of`] reads
/// them, so a lock does not change them and an installed, removed or replaced tool does.
pub(super) fn fingerprint_of(
    context: &DesktopContext,
    worker: Option<&KnownWorker>,
) -> Fingerprint {
    Fingerprint {
        facility: Some(tools_of(context)),
        host_agent: worker.map(|worker| format!("{:?}", worker.descriptor.process_start_identity)),
        desktop_generation: context
            .login_generation
            .as_ref()
            .map(|generation| generation.get()),
        profile: Some(context.worker_profile),
    }
}

/// Puts findings into the platform's records.
///
/// A finding replaces the platform's record of the same capability, because an operation that was
/// performed, refused or left unanswered is a more specific answer than a query, except where the
/// context itself refuses the capability: a screen that has locked since the run is not one that
/// can be captured, and the platform's refusal is the current word. A finding for a capability the
/// platform has no record of is added. The result stays in capability-name order.
pub(super) fn merge(
    platform: &mut Vec<CapabilityRecord>,
    findings: &[CapabilityRecord],
    context: &DesktopContext,
) {
    for finding in findings {
        let name = finding.capability.as_str();
        match platform
            .iter()
            .position(|record| record.capability.as_str() == name)
        {
            Some(_) if context_refuses(name, context) => {}
            Some(at) => platform[at] = finding.clone(),
            None => platform.push(finding.clone()),
        }
    }
    platform.sort_by(|left, right| left.capability.as_str().cmp(right.capability.as_str()));
}

/// Checks that an answer is the findings of the run this daemon asked for, and returns them.
///
/// The worker is trusted to have performed the checks and not to say anything else: what is held
/// is bounded to the capabilities a run can establish, one record each, about this environment and
/// the worker's own session.
pub(super) fn findings_of(
    answer: DesktopChecksAnswer,
    asked: RequestId,
    session_id: SessionId,
    environment_id: EnvironmentId,
) -> Option<Vec<CapabilityRecord>> {
    if answer.request_id != asked
        || answer.session_id != session_id
        || answer.records.len() > FINDINGS.len()
    {
        return None;
    }
    let mut named: Vec<&str> = Vec::new();
    for record in &answer.records {
        let name = record.capability.as_str();
        if !FINDINGS.contains(&name)
            || named.contains(&name)
            || record.subject.session_id.0 != Some(session_id)
            || record.subject.environment_id != environment_id
        {
            return None;
        }
        named.push(name);
    }
    Some(answer.records)
}

/// Chooses the worker the checks are performed in.
///
/// A session of the profile the host creates sessions with, whose worker speaks this release's
/// protocol, so that the request can be written to it; the newest of them, so that the choice is
/// the same each time. A worker started by an earlier release is passed over.
pub(super) fn worker_for(workers: Vec<KnownWorker>, profile: WorkerProfile) -> Option<KnownWorker> {
    workers
        .into_iter()
        .filter(|worker| {
            worker.descriptor.worker_profile == profile && worker.level == Level::this()
        })
        .max_by_key(|worker| worker.descriptor.published_at_ms)
}

impl Controller {
    /// Answers a retry of a request for the checks from the record of what this host answered,
    /// when it holds one.
    ///
    /// The de-duplication key is the actor and the action together, and the digest of the request
    /// decides whether it is the same request or a reused identifier. The record outlives the
    /// daemon, so a repeat on a later connection, after its window or after a restart, is given
    /// the answer it was given; the run that answer describes is not started again.
    pub(super) fn kept_capability_checks(
        &self,
        actor_id: &ActorId,
        mutation: &MutationRequest,
    ) -> Option<ControlFrame> {
        let digest = mutation_digest(mutation, actor_id).ok()?;
        let held =
            self.capability_answers
                .recall(actor_id, mutation.action_id, kr_ipc::now_ms().get());
        let outcome = match held {
            Ok(None) => return None,
            Ok(Some(held)) if held.digest == digest => ParamsValue::from_typed(&held.answer)
                .map_err(|error| ControllerError::InvalidArgument(error.to_string())),
            Ok(Some(_)) => Err(ControllerError::IdConflict {
                token: mutation.action_id.to_string(),
            }),
            Err(error) => Err(error),
        };
        Some(super::respond(mutation.request_id, outcome))
    }

    /// Starts the disclosed checks in a session's worker, once the admission it carries still
    /// stands, and answers where they stand.
    ///
    /// The answer comes back at once: the run takes a screen image and starts an application and
    /// can last about two minutes, which a connection that waits for each call cannot be held for.
    /// Where there is no worker to run them in, the answer says so and nothing is started. A run
    /// already in progress is not started again, and the answer says that it is running.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::WindowExpired`] for an action that carries no freshness, the
    /// admission's refusal, and [`ControllerError::InvalidArgument`] for a request that is not
    /// for this environment.
    pub(super) async fn start_capability_checks(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        carried: AdmittedMutation,
    ) -> Result<ParamsValue> {
        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not perform the disclosed checks"
                    .to_owned(),
            });
        }
        let params: EnvironmentCapabilitiesCheckParams = parse(&mutation.params)?;
        if params.environment_id != self.paths.environment_id() {
            return Err(ControllerError::InvalidArgument(format!(
                "this daemon owns environment {}",
                self.paths.environment_id()
            )));
        }
        let (evidence, _) = self.desktop_evidence().await;
        // A session that has a closure recorded has a worker on its way out, which the directory
        // still lists until its tidying has run. The registry's lock is held for the one read.
        let workers = {
            let registry = self.registry.lock().await;
            let directory = self.directory_workers().await;
            Self::without_a_closure(&registry, directory)?
        };
        let worker = worker_for(workers, evidence.worker_profile);
        let now_ms = kr_ipc::now_ms();
        let taken = fingerprint_of(&evidence, worker.as_ref());
        let digest = mutation_digest(mutation, actor_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let begun = self.under_registration(&carried, || {
            let mut checks = self.checks.lock().unwrap_or_else(PoisonError::into_inner);
            // The lookup before admission and this are two looks: a request of the same actor and
            // action that was answered between them is answered here again, or refused as a reused
            // identifier, under the one hold that also starts a run.
            match self
                .capability_answers
                .recall(actor_id, mutation.action_id, now_ms.get())
            {
                Ok(Some(held)) if held.digest == digest => return Ok(held.answer),
                Ok(Some(_)) => {
                    return Err(ControllerError::IdConflict {
                        token: mutation.action_id.to_string(),
                    });
                }
                Ok(None) => {}
                Err(error) => return Err(error),
            }
            let asked = checks.ask(
                now_ms,
                worker.as_ref().map(|worker| worker.descriptor.session_id),
                taken,
            );
            let view = checks.view();
            // What is answered is written down before it is given, and a record that cannot be
            // written does not change what the start did: the caller is told where the checks
            // stand, and a repeat of this action is then a request like a first one.
            if let Err(unrecorded) = self.capability_answers.remember(
                actor_id,
                mutation.action_id,
                &digest,
                &view,
                now_ms.get(),
            ) {
                eprintln!("kr-controller: an action's receipt could not be kept: {unrecorded}");
            }
            drop(checks);
            if let (Some(request_id), Some(worker)) = (asked, worker) {
                let request = DesktopChecksRequest {
                    request_id,
                    environment_id: params.environment_id,
                    authorised_file: params.authorised_file,
                };
                tokio::spawn(perform(self.me.clone(), worker, request));
            }
            Ok(view)
        })??;
        ParamsValue::from_typed(&begun)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Records how a run ended.
    async fn capability_checks_ended(
        &self,
        worker: &KnownWorker,
        asked: &DesktopChecksRequest,
        outcome: std::result::Result<DesktopChecksAnswer, CapabilityChecksFailure>,
    ) {
        let session_id = worker.descriptor.session_id;
        let now_ms = kr_ipc::now_ms();
        let findings = outcome.and_then(|answer| {
            findings_of(answer, asked.request_id, session_id, asked.environment_id)
                .ok_or(CapabilityChecksFailure::WorkerFailed)
        });
        match findings {
            Ok(records) => self
                .checks
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .succeeded(now_ms, records),
            Err(failure) => self
                .checks
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .failed(now_ms, Some(session_id), failure),
        }
    }
}

/// Performs one run: asks the worker over a connection of its own and waits for its findings.
async fn perform(
    me: std::sync::Weak<Controller>,
    worker: KnownWorker,
    request: DesktopChecksRequest,
) {
    let outcome = tokio::time::timeout(CHECKS_WAIT, exchange(&me, &worker, &request))
        .await
        .unwrap_or(Err(CapabilityChecksFailure::WorkerUnreachable));
    if let Some(controller) = me.upgrade() {
        controller
            .capability_checks_ended(&worker, &request, outcome)
            .await;
    }
}

/// The request and its answer, over one connection that is closed when this ends.
async fn exchange(
    me: &std::sync::Weak<Controller>,
    worker: &KnownWorker,
    request: &DesktopChecksRequest,
) -> std::result::Result<DesktopChecksAnswer, CapabilityChecksFailure> {
    let mut client = Controller::connect_role(me, worker, ControllerConnectionRole::Checks)
        .await
        .map_err(|_| CapabilityChecksFailure::WorkerUnreachable)?;
    client
        .send(&ControlFrame::DesktopChecks(request.clone()))
        .await
        .map_err(|_| CapabilityChecksFailure::WorkerUnreachable)?;
    loop {
        match client.recv().await {
            Ok(ControlFrame::DesktopChecksAnswer(answer)) => return Ok(*answer),
            // The worker answered the request with an error: it was busy, its authority had
            // moved on, it could not make a directory for the run, or the run did not finish.
            Ok(ControlFrame::Response(_)) => return Err(CapabilityChecksFailure::WorkerRefused),
            Ok(_) => {}
            Err(_) => return Err(CapabilityChecksFailure::WorkerUnreachable),
        }
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::desktop::{
        CapabilityEvidenceSource, CapabilityIdentity, CapabilityState, CapabilitySubject,
    };
    use kr_protocol::ids::{CapabilityId, CapabilityRevision};
    use kr_protocol::scalars::{U64, Uuid};

    use super::*;

    /// A desktop of this test's own, unlocked and with a graphical login's access. The tools a
    /// fingerprint reads are the machine's own, so no case here compares one with a fixed value.
    fn context() -> DesktopContext {
        use kr_protocol::desktop::{
            ContainerEnvironment, DesktopAvailability, DesktopGenerationSource, DesktopSessionKind,
            DisplayServer,
        };
        use kr_protocol::identity::{BootIdentity, BootIdentitySource};
        use kr_protocol::ids::DesktopSessionId;
        use kr_protocol::scalars::Bytes;

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

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([5; 16]))
    }

    fn session() -> SessionId {
        SessionId::new(Uuid::from_bytes([6; 16]))
    }

    fn record(
        capability: &str,
        state: CapabilityState,
        evidence: CapabilityEvidenceSource,
        session_id: Option<SessionId>,
    ) -> CapabilityRecord {
        CapabilityRecord {
            capability: CapabilityId::new(capability).expect("a capability"),
            version: U64::new(1),
            subject: CapabilitySubject {
                environment_id: environment(),
                desktop_session_id: Nullable::null(),
                session_id: Nullable(session_id),
                application: Nullable::null(),
                terminal: Nullable::null(),
            },
            revision: CapabilityRevision::new(0),
            state,
            evidence_source: evidence,
            identity: CapabilityIdentity {
                binary: Nullable::null(),
                version: Nullable::null(),
                package: Nullable::null(),
                schema: Nullable::null(),
                profile: Nullable::null(),
            },
            invalidation: kr_worker::desktop::probe::invalidation(),
            disabled_reason: Nullable::null(),
            observed_at_ms: TimestampMs::new(1),
        }
    }

    fn platform() -> Vec<CapabilityRecord> {
        [
            capabilities::ACCESSIBILITY,
            capabilities::APPLICATION_LAUNCH,
            capabilities::DISPLAY_SERVER,
            capabilities::INPUT_INJECTION,
            capabilities::SCREEN_CAPTURE,
        ]
        .into_iter()
        .map(|name| {
            record(
                name,
                CapabilityState::NotTested,
                CapabilityEvidenceSource::PlatformQuery,
                None,
            )
        })
        .collect()
    }

    fn states(records: &[CapabilityRecord]) -> Vec<(&str, CapabilityState)> {
        records
            .iter()
            .map(|record| (record.capability.as_str(), record.state))
            .collect()
    }

    #[test]
    fn a_finding_replaces_the_platform_record_and_a_new_capability_is_added() {
        let mut records = platform();
        let findings = [
            record(
                capabilities::SCREEN_CAPTURE,
                CapabilityState::PermissionRequired,
                CapabilityEvidenceSource::DisclosedProbe,
                Some(session()),
            ),
            record(
                capabilities::AUTHORISED_FILE_READ,
                CapabilityState::QualifiedAvailable,
                CapabilityEvidenceSource::DisclosedProbe,
                Some(session()),
            ),
        ];
        merge(&mut records, &findings, &context());
        let merged = states(&records);
        assert!(merged.contains(&(
            capabilities::SCREEN_CAPTURE,
            CapabilityState::PermissionRequired
        )));
        assert!(merged.contains(&(
            capabilities::AUTHORISED_FILE_READ,
            CapabilityState::QualifiedAvailable
        )));
        assert!(
            merged.contains(&(capabilities::ACCESSIBILITY, CapabilityState::NotTested)),
            "a capability no check was performed for keeps the platform's answer"
        );
        let names: Vec<&str> = records
            .iter()
            .map(|record| record.capability.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "the records stay in capability-name order");
    }

    #[test]
    fn a_finding_does_not_replace_a_refusal_the_context_makes() {
        // The screen locked after the checks were performed.
        let mut locked = context();
        locked.availability = kr_protocol::desktop::DesktopAvailability::Locked;
        let mut records = platform();
        let refusal = record(
            capabilities::SCREEN_CAPTURE,
            CapabilityState::TemporarilyUnavailable,
            CapabilityEvidenceSource::PlatformQuery,
            None,
        );
        let at = records
            .iter()
            .position(|record| record.capability.as_str() == capabilities::SCREEN_CAPTURE)
            .expect("the screen record");
        records[at] = refusal.clone();
        let finding = record(
            capabilities::SCREEN_CAPTURE,
            CapabilityState::QualifiedAvailable,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(session()),
        );
        merge(&mut records, &[finding], &locked);
        assert_eq!(
            records[at], refusal,
            "the platform's word on a locked desktop stands"
        );
    }

    #[test]
    fn findings_are_held_only_as_what_a_run_can_establish() {
        let good = |name: &str| {
            record(
                name,
                CapabilityState::QualifiedAvailable,
                CapabilityEvidenceSource::DisclosedProbe,
                Some(session()),
            )
        };
        let answer = |records: Vec<CapabilityRecord>| DesktopChecksAnswer {
            request_id: RequestId::new(1),
            session_id: session(),
            records,
        };
        let asked = RequestId::new(1);
        assert!(
            findings_of(
                answer(vec![good(capabilities::SCREEN_CAPTURE)]),
                asked,
                session(),
                environment()
            )
            .is_some()
        );
        // Synthetic input is never performed, so a worker has no finding for it.
        assert!(
            findings_of(
                answer(vec![good(capabilities::INPUT_INJECTION)]),
                asked,
                session(),
                environment()
            )
            .is_none()
        );
        // One record each.
        assert!(
            findings_of(
                answer(vec![
                    good(capabilities::SCREEN_CAPTURE),
                    good(capabilities::SCREEN_CAPTURE)
                ]),
                asked,
                session(),
                environment()
            )
            .is_none()
        );
        // About the worker's own session, and the request that was made.
        let mut elsewhere = good(capabilities::SCREEN_CAPTURE);
        elsewhere.subject.session_id = Nullable::some(SessionId::new(Uuid::from_bytes([8; 16])));
        assert!(findings_of(answer(vec![elsewhere]), asked, session(), environment()).is_none());
        assert!(
            findings_of(
                answer(vec![good(capabilities::SCREEN_CAPTURE)]),
                RequestId::new(2),
                session(),
                environment()
            )
            .is_none()
        );
    }

    fn screen_finding() -> CapabilityRecord {
        record(
            capabilities::SCREEN_CAPTURE,
            CapabilityState::QualifiedAvailable,
            CapabilityEvidenceSource::DisclosedProbe,
            Some(session()),
        )
    }

    #[test]
    fn findings_end_when_the_desktop_the_tools_or_the_worker_they_were_taken_against_moves() {
        let taken = Fingerprint {
            facility: Some("tools".to_owned()),
            host_agent: Some("worker".to_owned()),
            desktop_generation: Some(2),
            profile: Some(WorkerProfile::DesktopBound),
        };
        let mut checks = Checks::new();
        assert_eq!(checks.view().state, CapabilityChecksState::NotRun);
        checks.begin(TimestampMs::new(10), session(), taken.clone());
        assert_eq!(checks.view().state, CapabilityChecksState::Running);
        checks.succeeded(TimestampMs::new(20), vec![screen_finding()]);
        assert_eq!(checks.view().state, CapabilityChecksState::Current);
        assert_eq!(checks.standing(&taken).len(), 1, "nothing moved");
        // A tool installed, removed or replaced, the worker gone, a new login and another profile
        // each end them.
        for moved in [
            Fingerprint {
                facility: Some("other tools".to_owned()),
                ..taken.clone()
            },
            Fingerprint {
                facility: Some(String::new()),
                ..taken.clone()
            },
            Fingerprint {
                host_agent: None,
                ..taken.clone()
            },
            Fingerprint {
                desktop_generation: Some(3),
                ..taken.clone()
            },
            Fingerprint {
                profile: Some(WorkerProfile::HeadlessUser),
                ..taken.clone()
            },
        ] {
            let mut checks = Checks::new();
            checks.begin(TimestampMs::new(10), session(), taken.clone());
            checks.succeeded(TimestampMs::new(20), vec![screen_finding()]);
            assert!(checks.standing(&moved).is_empty(), "{moved:?}");
            assert_eq!(checks.view().state, CapabilityChecksState::Stale);
            // And they are gone: a reading that recovers does not bring them back.
            assert!(checks.standing(&taken).is_empty());
        }
    }

    #[test]
    fn a_fingerprint_holds_the_tools_the_machine_has() {
        assert_eq!(
            fingerprint_of(&context(), None).facility,
            Some(tools_of(&context())),
            "the tools in a fingerprint are read from the machine, so one installed since is a change"
        );
    }

    #[test]
    fn findings_are_about_the_desktop_as_the_run_began() {
        // A profile that changes while the run goes on is a change since the run began, so the
        // findings are over at the first reading after they arrive.
        let began = fingerprint_of(&context(), None);
        let mut other = context();
        other.worker_profile = WorkerProfile::HeadlessUser;
        let mut checks = Checks::new();
        checks.begin(TimestampMs::new(10), session(), began);
        checks.succeeded(TimestampMs::new(20), vec![screen_finding()]);
        assert!(checks.standing(&fingerprint_of(&other, None)).is_empty());
        assert_eq!(checks.view().state, CapabilityChecksState::Stale);
    }

    #[test]
    fn a_locked_or_ended_desktop_is_not_a_change_of_what_the_findings_are_about() {
        // The platform's own records name no tool while the desktop is locked, and a lock replaces
        // no tool and starts no login: what was found still stands, and is shown again when the
        // screen unlocks.
        let mut checks = Checks::new();
        checks.begin(
            TimestampMs::new(10),
            session(),
            fingerprint_of(&context(), None),
        );
        checks.succeeded(TimestampMs::new(20), vec![screen_finding()]);
        for availability in [
            kr_protocol::desktop::DesktopAvailability::Locked,
            kr_protocol::desktop::DesktopAvailability::Ended,
            kr_protocol::desktop::DesktopAvailability::Available,
        ] {
            let mut desktop = context();
            desktop.availability = availability;
            assert_eq!(
                checks.standing(&fingerprint_of(&desktop, None)).len(),
                1,
                "{availability:?}"
            );
            assert_eq!(checks.view().state, CapabilityChecksState::Current);
        }
    }

    #[test]
    fn an_action_during_a_run_starts_nothing_and_with_no_worker_the_state_says_why() {
        let taken = Fingerprint::default();
        let mut checks = Checks::new();
        // No session to perform them in.
        assert_eq!(checks.ask(TimestampMs::new(1), None, taken.clone()), None);
        assert_eq!(checks.view().state, CapabilityChecksState::Failed);
        assert_eq!(
            checks.view().failure.as_ref(),
            Some(&CapabilityChecksFailure::NoSession)
        );
        // One goes ahead, and nothing else begins beside it.
        let first = checks
            .ask(TimestampMs::new(2), Some(session()), taken.clone())
            .expect("a run begins");
        assert_eq!(checks.view().state, CapabilityChecksState::Running);
        assert_eq!(
            checks.ask(TimestampMs::new(3), Some(session()), taken.clone()),
            None,
            "a second action during a run starts no second run"
        );
        assert_eq!(checks.view().state, CapabilityChecksState::Running);
        assert_eq!(
            checks.view().started_at_ms.0,
            Some(TimestampMs::new(2)),
            "and the run that is going is the first"
        );
        // The same applies to an action that finds no worker while one is going.
        assert_eq!(checks.ask(TimestampMs::new(4), None, taken.clone()), None);
        assert_eq!(checks.view().state, CapabilityChecksState::Running);
        // A run that has ended makes room for the next, which has an identifier of its own.
        checks.failed(
            TimestampMs::new(5),
            Some(session()),
            CapabilityChecksFailure::WorkerUnreachable,
        );
        let second = checks
            .ask(TimestampMs::new(6), Some(session()), taken)
            .expect("the next run begins");
        assert_ne!(first, second);
    }

    #[test]
    fn a_run_that_ends_in_the_same_session_is_other_findings_to_a_reading_made_before() {
        let taken = Fingerprint::default();
        let mut checks = Checks::new();
        checks.begin(TimestampMs::new(1), session(), taken.clone());
        checks.succeeded(TimestampMs::new(2), vec![screen_finding()]);
        let before = checks.held_stamp();
        assert_eq!(before.0, Some(session()));
        // The next run is of the same session and holds findings of the same worker.
        checks.begin(TimestampMs::new(3), session(), taken);
        checks.succeeded(TimestampMs::new(4), vec![screen_finding()]);
        let after = checks.held_stamp();
        assert_eq!(after.0, before.0, "the same worker");
        assert_ne!(
            after, before,
            "and not the findings a reading was made against"
        );
    }

    #[test]
    fn each_run_has_an_identifier_of_its_own() {
        let mut checks = Checks::new();
        let first = checks.begin(TimestampMs::new(1), session(), Fingerprint::default());
        checks.failed(
            TimestampMs::new(2),
            Some(session()),
            CapabilityChecksFailure::WorkerUnreachable,
        );
        let second = checks.begin(TimestampMs::new(3), session(), Fingerprint::default());
        assert_ne!(first, second, "an answer to the first is not the second's");
    }

    #[test]
    fn a_failed_run_leaves_standing_findings_standing_and_says_why() {
        let taken = Fingerprint::default();
        let mut checks = Checks::new();
        checks.begin(TimestampMs::new(10), session(), taken.clone());
        checks.succeeded(TimestampMs::new(20), vec![screen_finding()]);
        checks.begin(TimestampMs::new(30), session(), taken.clone());
        checks.failed(
            TimestampMs::new(40),
            Some(session()),
            CapabilityChecksFailure::WorkerUnreachable,
        );
        let view = checks.view();
        assert_eq!(view.state, CapabilityChecksState::Failed);
        assert_eq!(
            view.failure.as_ref(),
            Some(&CapabilityChecksFailure::WorkerUnreachable)
        );
        assert_eq!(checks.standing(&taken).len(), 1);
        assert_eq!(checks.held_stamp().0, Some(session()));
    }
}
