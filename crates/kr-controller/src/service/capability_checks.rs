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
//! profile changed, or a tool the worker ran was replaced, or a tool it did not find at an
//! absolute path was installed there. A tool it looked for by a bare name and did not find is not
//! seen: that it is installed shows when the checks run again. A change of permission is not
//! something this host can read either; it is found by performing the checks again.

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
use kr_worker::desktop::capability::{context_refuses, facility_identity};
use kr_worker::desktop::probe::{Fingerprint, stale};

use crate::authority::AdmittedMutation;
use crate::directory::KnownWorker;
use crate::error::{ControllerError, Result};
use crate::given::{Given, Recorded};

use super::{Controller, parse};

/// How long the daemon waits for a worker's findings before it calls the run failed.
///
/// The checks' own bounds add to about a minute and three quarters in the worst case, and a
/// permission prompt can hold each of them to its bound, so this is a margin over that and not a
/// figure the worker is made to meet.
pub(super) const CHECKS_WAIT: Duration = Duration::from_secs(150);

/// The record of answers to the disclosed checks, as a repeat is told of it when it cannot be read:
/// an earlier attempt may have started the checks, so the repeat is not told a transient word that
/// says nothing took effect.
const ANSWERS: &str = "answers to the disclosed checks";

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
#[derive(Clone, Debug)]
struct Running {
    started_at_ms: TimestampMs,
    session_id: SessionId,
    /// What the desktop and the worker were when the run began, which is what its findings are
    /// about: a login or a profile that changes while the run goes on is a change since.
    taken: Fingerprint,
}

/// What a worker found, and what it was found against.
#[derive(Clone, Debug)]
struct Held {
    fingerprint: Fingerprint,
    records: Vec<CapabilityRecord>,
}

/// What this daemon holds of the disclosed checks.
///
/// In memory only: a daemon that starts again has asked nothing, and the findings were about a
/// moment, a worker and a login that it has no way to vouch for.
#[derive(Clone, Debug)]
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
    /// They are held against the desktop and the worker as they were when the run began, and
    /// against the tools the worker's answer names: the files it ran, and the absolute path of a
    /// tool it did not find.
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
        // What they are about is what the worker ran, as its answer names it, and not what this
        // daemon would find on its own search path before the run: the two can be different tools.
        self.held = Some(Held {
            fingerprint: Fingerprint {
                facility: Some(identities_held(&records)),
                ..running.taken
            },
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
    /// `now` is the desktop and the worker as they are at this reading, with the tools the worker
    /// ran as [`identities_now`] reads them. The caller reads them before it takes the lock this
    /// is called under, because reading a file can wait, and a lock held across that wait stops
    /// every other read and every new run.
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

    /// The findings that are held, for a caller that reads what they name before it takes the lock
    /// again.
    pub(super) fn held_records(&self) -> Vec<CapabilityRecord> {
        self.held
            .as_ref()
            .map(|held| held.records.clone())
            .unwrap_or_default()
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

/// What the findings name as run, one line: for each record its capability, the route it took, the
/// program it ran and the digest the answer gave for it. A route that ran no program of its own
/// names none and has no digest.
fn identities(
    records: &[CapabilityRecord],
    version: impl Fn(&CapabilityRecord) -> String,
) -> String {
    let mut lines: Vec<String> = records
        .iter()
        .map(|record| {
            format!(
                "{}|{}|{}|{}",
                record.capability.as_str(),
                record.identity.schema.as_ref().map_or("", String::as_str),
                record.identity.binary.as_ref().map_or("", String::as_str),
                version(record)
            )
        })
        .collect();
    lines.sort();
    lines.join(";")
}

/// The identities the worker's answer gave.
fn identities_held(records: &[CapabilityRecord]) -> String {
    identities(records, |record| {
        record
            .identity
            .version
            .as_ref()
            .map(|identity| identity.as_str().to_owned())
            .unwrap_or_default()
    })
}

/// The identities of the same programs at the same paths as they are now.
///
/// Each file is opened without waiting and refused if it is not a regular file, so a path that
/// something else has made a pipe of does not hold the caller. It still takes the time of reading
/// a file, which is why a caller reads it outside every lock.
pub(super) fn identities_now(records: &[CapabilityRecord]) -> String {
    identities(records, |record| {
        record
            .identity
            .binary
            .as_ref()
            .and_then(|path| facility_identity(path))
            .map(|identity| identity.as_str().to_owned())
            .unwrap_or_default()
    })
}

/// What the desktop and the worker are, for a fingerprint of this moment.
///
/// The host agent is the worker that performed the checks, by the identity the kernel records for
/// its process: a replaced worker is another agent. Its build is the release the worker a run is
/// performed in states, so that the agent is updated when that worker is of another release, and
/// not when another session of the same release starts. `worker` is the one the findings were
/// taken in, and `target` is the one a run asked for now would be performed in. The generation and
/// the profile are the desktop's. The tools are not in it: they are the ones the worker ran,
/// which its answer names, and [`identities_now`] reads them at those paths.
pub(super) fn fingerprint_of(
    context: &DesktopContext,
    worker: Option<&KnownWorker>,
    target: Option<&KnownWorker>,
) -> Fingerprint {
    Fingerprint {
        // The tools are the ones the worker ran, which its answer names: the daemon's own search
        // would find what the worker never ran.
        facility: None,
        host_agent: worker.map(|worker| format!("{:?}", worker.descriptor.process_start_identity)),
        agent_build: target
            .and_then(|target| target.release.as_ref())
            .map(|release| release.as_str().to_owned()),
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

/// How the start of the checks ended, inside the hold on the registration.
enum Begun {
    /// This request started the checks, and this is where they stand.
    Started(CapabilityChecks),
    /// The record answered, and the answer waits for the check the cleanup leaves to be asked.
    Answer(Recorded<Result<CapabilityChecks>>),
    /// An answer that ends the call before the cleanup: another request's identifier, a record
    /// that cannot be read, or a fence that stopped the record's answer, each already asked about
    /// the fence under the hold.
    Given(Given<Result<CapabilityChecks>>),
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
    ) -> Option<Recorded<ControlFrame>> {
        let digest = mutation_digest(mutation, actor_id).ok()?;
        let held = self.capability_answers.recall(actor_id, mutation.action_id);
        let outcome = match held {
            Ok(None) => return None,
            Ok(Some(held)) if held.digest == digest => ParamsValue::from_typed(&held.answer)
                .map_err(|error| ControllerError::InvalidArgument(error.to_string())),
            Ok(Some(_)) => Err(ControllerError::IdConflict {
                token: mutation.action_id.to_string(),
            }),
            Err(error) => Err(error.found_unreadable(ANSWERS)),
        };
        Some(Recorded::read(outcome).respond(mutation.request_id))
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
    /// Returns [`ControllerError::WindowExpired`] for a first start whose window has passed or that
    /// carries no freshness (a copy of an action this host answered is given the answer whatever
    /// its window), the admission's refusal, [`ControllerError::InvalidArgument`] for a request
    /// that is not for this environment, [`ControllerError::IdConflict`] for an identifier the
    /// record holds for another request, an error that answers `OUTCOME_UNKNOWN` for a record of
    /// answers that cannot be read (the action may have run), and the error of the registry or of
    /// writing the answer down, which answers `STORAGE_UNAVAILABLE`.
    pub(super) async fn start_capability_checks(
        self: &Arc<Self>,
        actor_id: &ActorId,
        mutation: &MutationRequest,
        carried: AdmittedMutation,
    ) -> Given<Result<ParamsValue>> {
        let params: EnvironmentCapabilitiesCheckParams = match parse(&mutation.params) {
            Ok(params) => params,
            Err(refusal) => return Given::fresh(Err(refusal)),
        };
        if params.environment_id != self.paths.environment_id() {
            return Given::fresh(Err(ControllerError::InvalidArgument(format!(
                "this daemon owns environment {}",
                self.paths.environment_id()
            ))));
        }
        let (evidence, _) = self.desktop_evidence().await;
        // A session that has a closure recorded has a worker on its way out, which the directory
        // still lists until its tidying has run. The registry's lock is held for the one read.
        let workers = {
            let registry = self.registry.lock().await;
            let directory = self.directory_workers().await;
            match Self::without_a_closure(&registry, directory) {
                Ok(workers) => workers,
                Err(refusal) => return Given::fresh(Err(refusal)),
            }
        };
        let worker = worker_for(workers, evidence.worker_profile);
        let now_ms = kr_ipc::now_ms();
        let taken = fingerprint_of(&evidence, worker.as_ref(), worker.as_ref());
        let digest = match mutation_digest(mutation, actor_id) {
            Ok(digest) => digest,
            Err(error) => {
                return Given::fresh(Err(ControllerError::InvalidArgument(error.to_string())));
            }
        };
        let begun = self.under_registration_until_it_begins(&carried, |begin| -> Result<Begun> {
            let mut checks = self.checks.lock().unwrap_or_else(PoisonError::into_inner);
            #[cfg(test)]
            self.before_a_capability_check_looks.wait();
            // The lookup before admission and this are two looks: a request of the same actor and
            // action that was answered between them is answered here again, or refused as a reused
            // identifier, under the one hold that also starts a run. The hold keeps a revocation
            // and a withdrawn registration out until the closure ends, but not the publication of
            // a fence this host owes, and the check above came before the lock on the checks and
            // the read of the record. So the fence is asked again with what the record gave in
            // hand, whether an answer, a reused identifier or a row that cannot be read: each tells
            // the caller that a record exists.
            match self.capability_answers.recall(actor_id, mutation.action_id) {
                Ok(Some(held)) if held.digest == digest => {
                    let answer = Recorded::read(Ok(held.answer));
                    // A fence stops the record's answer here, before the cleanup, and the answer
                    // it stops is a copy this host withholds.
                    return Ok(match self.check_fence() {
                        Ok(()) => Begun::Answer(answer),
                        Err(refusal) => Begun::Given(answer.refused_by(Err(refusal))),
                    });
                }
                Ok(Some(_)) => {
                    self.check_fence()?;
                    return Ok(Begun::Given(Given::fresh(Err(
                        ControllerError::IdConflict {
                            token: mutation.action_id.to_string(),
                        },
                    ))));
                }
                Ok(None) => {}
                Err(error) => {
                    return Ok(Begun::Given(
                        Recorded::read(Err(error.found_unreadable(ANSWERS)))
                            .checked(|| self.check_fence()),
                    ));
                }
            }
            // No record: this is a first start, which needs the window it was admitted under. A
            // receipt outlives that window, so the deadline is asked only here, after the record
            // was read, and a mutation that carries no freshness is refused here as well.
            begin()?;
            // What the start comes to is worked out on a copy and written down before anything
            // is changed or started: a record that cannot be written refuses the start, with the
            // checks standing as they did, so that no run goes on without its action being the
            // one the record says was answered, and a repeat is then a request like a first one.
            let mut next = (*checks).clone();
            let asked = next.ask(
                now_ms,
                worker.as_ref().map(|worker| worker.descriptor.session_id),
                taken,
            );
            let view = next.view();
            self.capability_answers.remember(
                actor_id,
                mutation.action_id,
                &digest,
                &view,
                self.wall_now_ms(),
            )?;
            *checks = next;
            drop(checks);
            if let (Some(request_id), Some(worker)) = (asked, worker) {
                let request = DesktopChecksRequest {
                    request_id,
                    environment_id: params.environment_id,
                    authorised_file: params.authorised_file,
                };
                tokio::spawn(perform(self.me.clone(), worker, request));
            }
            Ok(Begun::Started(view))
        });
        let begun = match begun {
            Ok(Ok(begun)) => begun,
            Ok(Err(refusal)) | Err(refusal) => return Given::fresh(Err(refusal)),
        };
        let framed = |given: Given<Result<CapabilityChecks>>| {
            given.map(|view| {
                view.and_then(|view| {
                    ParamsValue::from_typed(&view)
                        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
                })
            })
        };
        let given = match begun {
            // A reused identifier, a row that cannot be read and a fence that stopped the record's
            // answer end the call here: the cleanup is for an answer that was written or answered.
            Begun::Given(given) => given,
            Begun::Started(view) => {
                self.forget_old_capability_answers();
                Given::fresh(Ok(view))
            }
            Begun::Answer(recorded) => {
                self.forget_old_capability_answers();
                // The hold ended before the cleanup, which waits for locks and for storage, and
                // nothing in it keeps a fence this host owes, or a registration withdrawn, from
                // landing. The record's answer is checked again with it in hand.
                self.retained_given(&carried, recorded).await
            }
        };
        framed(given)
    }

    /// Lets go of the answers older than the retention section 9 gives a de-duplication record,
    /// when this host can show that its clock has outlived it.
    ///
    /// Forgetting is taken like every forgetting on this host, through the one check they all pass
    /// ([`crate::service::net::lifetimes::GrantLifetimes::may_forget_at`]), and the retention is
    /// counted as the transfer sweep counts its own: from the earlier of the wall reading the
    /// check covers and the wall clock as it stands with the record held, never from the floor,
    /// which only rises and can stand above the clock after an owner has corrected it. The record
    /// is held from that second reading to the delete, so an answer stamped after a correction is
    /// never reached by a reading from before it. An answer that cannot be shown to have outlived
    /// its retention is kept, because forgetting it lets the same action be submitted as a new one.
    /// It is called after an answer is written or answered again, and before the reply; it writes
    /// the floor when the floor has risen, and deletes only once the check has said yes.
    pub(crate) fn forget_old_capability_answers(&self) {
        let asked = self.wall_now_ms();
        // The floor is raised to the reading and written down first, so that the check covers it.
        self.settled_now_ms();
        if !self.lifetimes().may_forget_at(asked) {
            return;
        }
        #[cfg(test)]
        self.after_the_answers_clock_is_proven.wait();
        let retention = kr_protocol::limits::DEDUPLICATION_RETENTION.get();
        let forgotten = self
            .capability_answers
            .forget_before(|| asked.min(self.wall_now_ms()).saturating_sub(retention));
        if let Err(error) = forgotten {
            eprintln!(
                "kr-controller: old answers to the disclosed checks were not forgotten: {error}"
            );
        }
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

#[cfg(feature = "testing")]
impl Controller {
    /// Holds `records` as the findings of a run that a worker has just answered, for a suite that
    /// scripts what the worker found.
    ///
    /// The run begins against the desktop and the worker as they are now, and ends as the answer of
    /// a worker ends it, so the answer is checked and held as one is. No worker is asked. Returns
    /// nothing where no run could begin: no worker of the profile this host creates sessions with,
    /// or a run already in progress.
    pub async fn hold_scripted_findings(
        &self,
        records: Vec<CapabilityRecord>,
    ) -> Option<RequestId> {
        let (evidence, _) = self.desktop_evidence().await;
        let worker = worker_for(self.directory_workers().await, evidence.worker_profile)?;
        let session_id = worker.descriptor.session_id;
        let taken = fingerprint_of(&evidence, Some(&worker), Some(&worker));
        let request_id = self
            .checks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .ask(kr_ipc::now_ms(), Some(session_id), taken)?;
        let asked = DesktopChecksRequest {
            request_id,
            environment_id: self.paths.environment_id(),
            authorised_file: Nullable::null(),
        };
        let answer = DesktopChecksAnswer {
            request_id,
            session_id,
            records,
        };
        self.capability_checks_ended(&worker, &asked, Ok(answer))
            .await;
        Some(request_id)
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
    use crate::service::capabilities::resolved_desktop;
    use kr_protocol::identity::BootIdentity;

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

    /// KR-REQ-03.29: findings taken while the desktop was displayed are not shown for a session that
    /// a user switch has since moved into the background, where the platform's record stands, as it
    /// does for a locked desktop.
    #[test]
    fn kr_req_03_29_a_finding_does_not_replace_the_record_of_a_session_in_the_background() {
        let mut background = context();
        background.availability = kr_protocol::desktop::DesktopAvailability::Background;
        let mut records = platform();
        let before = records.clone();
        let findings = [
            record(
                capabilities::SCREEN_CAPTURE,
                CapabilityState::QualifiedAvailable,
                CapabilityEvidenceSource::DisclosedProbe,
                Some(session()),
            ),
            record(
                capabilities::ACCESSIBILITY,
                CapabilityState::QualifiedAvailable,
                CapabilityEvidenceSource::DisclosedProbe,
                Some(session()),
            ),
        ];
        merge(&mut records, &findings, &background);
        assert_eq!(
            records, before,
            "the platform's records stand for a session that is not displayed"
        );
        // The same findings are shown once the session is displayed again.
        merge(&mut records, &findings, &context());
        let merged = states(&records);
        assert!(merged.contains(&(
            capabilities::SCREEN_CAPTURE,
            CapabilityState::QualifiedAvailable
        )));
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

    /// What the daemon's reading of the held findings does: the tools the worker ran are read at the
    /// paths its answer named, outside the lock, and given to the comparison.
    fn standing_now(checks: &mut Checks, now: &Fingerprint) -> Vec<CapabilityRecord> {
        let now = Fingerprint {
            facility: Some(identities_now(&checks.held_records())),
            ..now.clone()
        };
        checks.standing(&now)
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
            agent_build: Some("release".to_owned()),
            desktop_generation: Some(2),
            profile: Some(WorkerProfile::DesktopBound),
        };
        let mut checks = Checks::new();
        assert_eq!(checks.view().state, CapabilityChecksState::NotRun);
        checks.begin(TimestampMs::new(10), session(), taken.clone());
        assert_eq!(checks.view().state, CapabilityChecksState::Running);
        checks.succeeded(TimestampMs::new(20), vec![screen_finding()]);
        assert_eq!(checks.view().state, CapabilityChecksState::Current);
        assert_eq!(standing_now(&mut checks, &taken).len(), 1, "nothing moved");
        // The worker gone, a new login and another profile each end them. A tool the worker ran
        // replaced ends them too, which the cases of the worker's tools below show.
        for moved in [
            Fingerprint {
                host_agent: None,
                ..taken.clone()
            },
            Fingerprint {
                agent_build: Some("another release".to_owned()),
                ..taken.clone()
            },
            Fingerprint {
                agent_build: None,
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
            assert!(standing_now(&mut checks, &moved).is_empty(), "{moved:?}");
            assert_eq!(checks.view().state, CapabilityChecksState::Stale);
            // And they are gone: a reading that recovers does not bring them back.
            assert!(standing_now(&mut checks, &taken).is_empty());
        }
    }

    /// A finding that names the program the worker ran, by path and with the digest it read.
    #[cfg(unix)]
    fn finding_naming(path: &std::path::Path) -> CapabilityRecord {
        let mut finding = screen_finding();
        finding.identity.binary = Nullable::some(path.display().to_string());
        finding.identity.version = Nullable(facility_identity(&path.display().to_string()));
        finding.identity.schema = Nullable::some("a-route".to_owned());
        finding
    }

    /// KR-REQ-03.29, S-4: the findings are held against the tool the worker ran. With a search
    /// path of the controller's own that finds another tool, replacing the worker's tool ends
    /// them, and replacing the controller's candidate, which the worker never ran, does not.
    #[cfg(unix)]
    #[test]
    fn a_worker_and_a_controller_with_different_search_paths_hold_the_workers_tool() {
        let directory = std::env::temp_dir().join(format!("kr-held-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory of this test's own");
        let worker_tool = directory.join("the-workers-tool");
        let controller_candidate = directory.join("the-controllers-candidate");
        std::fs::write(&worker_tool, b"the first build").expect("the worker's tool");
        std::fs::write(&controller_candidate, b"the first build").expect("the candidate");
        // What the controller's own reading of the tools was before the run: another tool.
        let taken = Fingerprint {
            facility: Some("what the controller found on its own search path".to_owned()),
            host_agent: Some("worker".to_owned()),
            agent_build: None,
            desktop_generation: Some(2),
            profile: Some(WorkerProfile::DesktopBound),
        };
        let held = || {
            let mut checks = Checks::new();
            checks.begin(TimestampMs::new(10), session(), taken.clone());
            checks.succeeded(TimestampMs::new(20), vec![finding_naming(&worker_tool)]);
            checks
        };
        assert_eq!(standing_now(&mut held(), &taken).len(), 1, "nothing moved");

        std::fs::write(&controller_candidate, b"the second build").expect("the replacement");
        assert_eq!(
            standing_now(&mut held(), &taken).len(),
            1,
            "a tool the worker never ran is not what the findings are about"
        );

        let mut checks = held();
        std::fs::write(&worker_tool, b"the second build").expect("the replacement");
        assert!(
            standing_now(&mut checks, &taken).is_empty(),
            "the worker's own tool was replaced"
        );
        assert_eq!(checks.view().state, CapabilityChecksState::Stale);
        std::fs::remove_dir_all(&directory).expect("removes the test's directory");
    }

    /// KR-REQ-03.29, S-12: what a permission withdrawn since the first run comes to. A second run
    /// that is refused replaces the first finding, and with no second run the first stands, which
    /// is the limit the words state.
    #[test]
    fn a_repeat_run_finds_a_permission_withdrawn_since() {
        let taken = Fingerprint {
            facility: None,
            host_agent: Some("worker".to_owned()),
            agent_build: None,
            desktop_generation: Some(2),
            profile: Some(WorkerProfile::DesktopBound),
        };
        let mut checks = Checks::new();
        checks.begin(TimestampMs::new(10), session(), taken.clone());
        checks.succeeded(TimestampMs::new(20), vec![screen_finding()]);
        let read = |checks: &mut Checks| {
            let mut records = platform();
            merge(&mut records, &standing_now(checks, &taken), &context());
            records
                .into_iter()
                .find(|record| record.capability.as_str() == capabilities::SCREEN_CAPTURE)
                .expect("the screen record")
                .state
        };
        assert_eq!(read(&mut checks), CapabilityState::QualifiedAvailable);
        assert_eq!(
            read(&mut checks),
            CapabilityState::QualifiedAvailable,
            "with no second run the first finding stands"
        );
        let mut refused = screen_finding();
        refused.state = CapabilityState::PermissionRequired;
        checks.begin(TimestampMs::new(30), session(), taken.clone());
        checks.succeeded(TimestampMs::new(40), vec![refused]);
        assert_eq!(
            read(&mut checks),
            CapabilityState::PermissionRequired,
            "the second run found the permission withdrawn"
        );
    }

    /// KR-REQ-03.29, KR-REQ-11.17, S-13: findings held against a login go stale when the login
    /// changes, through the controller's own reading of the desktop, which here is scripted.
    #[test]
    fn held_findings_go_stale_when_the_login_changes() {
        struct Scripted(std::sync::atomic::AtomicU64);
        impl crate::desktop::DesktopSource for Scripted {
            fn current(&self, _boot: BootIdentity) -> DesktopContext {
                let mut desktop = context();
                desktop.login_generation =
                    Nullable::some(U64::new(self.0.load(std::sync::atomic::Ordering::SeqCst)));
                desktop
            }
        }
        let source = Scripted(std::sync::atomic::AtomicU64::new(2));
        let boot = context().boot_identity;
        let read = || fingerprint_of(&resolved_desktop(None, &boot, &source).1, None, None);
        let mut checks = Checks::new();
        checks.begin(TimestampMs::new(10), session(), read());
        checks.succeeded(TimestampMs::new(20), vec![screen_finding()]);
        assert_eq!(
            standing_now(&mut checks, &read()).len(),
            1,
            "the same login"
        );
        assert_eq!(checks.view().state, CapabilityChecksState::Current);
        source.0.store(3, std::sync::atomic::Ordering::SeqCst);
        assert!(
            standing_now(&mut checks, &read()).is_empty(),
            "a login that changed ends them"
        );
        assert_eq!(checks.view().state, CapabilityChecksState::Stale);
    }

    /// KR-REQ-03.29, R9: a finding that a tool was not installed names the absolute path it would
    /// be installed at, so that it ends once the tool is there.
    #[cfg(unix)]
    #[test]
    fn a_not_installed_finding_ends_when_the_tool_is_installed() {
        let directory = std::env::temp_dir().join(format!("kr-absent-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory of this test's own");
        let tool = directory.join("the-tool");
        let mut finding = screen_finding();
        finding.state = CapabilityState::MissingInstallation;
        finding.identity.binary = Nullable::some(tool.display().to_string());
        finding.identity.schema = Nullable::some("a-route".to_owned());
        let taken = fingerprint_of(&context(), None, None);
        let mut checks = Checks::new();
        checks.begin(TimestampMs::new(10), session(), taken.clone());
        checks.succeeded(TimestampMs::new(20), vec![finding]);
        assert_eq!(
            standing_now(&mut checks, &taken).len(),
            1,
            "with the tool still not there"
        );
        std::fs::write(&tool, b"installed since").expect("the tool is installed");
        assert!(
            standing_now(&mut checks, &taken).is_empty(),
            "a finding that the tool was not installed outlived its installation"
        );
        std::fs::remove_dir_all(&directory).expect("removes the test's directory");
    }

    /// KR-REQ-03.29, R9: a fingerprint holds no tool of the daemon's own. What the findings are
    /// about is what the worker ran, which its answer names.
    #[test]
    fn a_fingerprint_holds_no_tool_of_the_daemons_own() {
        assert_eq!(fingerprint_of(&context(), None, None).facility, None);
    }

    /// KR-REQ-03.29, R9: the tools are compared as the caller read them, which is outside the
    /// lock: findings held against a file that has not changed end when the reading says it has.
    #[cfg(unix)]
    #[test]
    fn the_comparison_is_made_with_the_tools_the_caller_read() {
        let directory = std::env::temp_dir().join(format!("kr-read-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory of this test's own");
        let tool = directory.join("the-workers-tool");
        std::fs::write(&tool, b"a build").expect("the tool");
        let taken = fingerprint_of(&context(), None, None);
        let mut checks = Checks::new();
        checks.begin(TimestampMs::new(10), session(), taken.clone());
        checks.succeeded(TimestampMs::new(20), vec![finding_naming(&tool)]);
        let read = identities_now(&checks.held_records());
        assert_eq!(
            checks
                .standing(&Fingerprint {
                    facility: Some(read),
                    ..taken.clone()
                })
                .len(),
            1,
            "the reading the caller took says nothing changed"
        );
        let mut checks = Checks::new();
        checks.begin(TimestampMs::new(10), session(), taken.clone());
        checks.succeeded(TimestampMs::new(20), vec![finding_naming(&tool)]);
        assert!(
            checks
                .standing(&Fingerprint {
                    facility: Some("what the caller read, which is another file".to_owned()),
                    ..taken
                })
                .is_empty(),
            "the comparison read the files itself and not the caller's reading"
        );
        std::fs::remove_dir_all(&directory).expect("removes the test's directory");
    }

    /// KR-REQ-03.29, R9: a path a finding names that has become a pipe is not waited for.
    #[cfg(unix)]
    #[test]
    fn a_path_a_finding_names_that_became_a_pipe_is_not_waited_for() {
        let directory = std::env::temp_dir().join(format!("kr-pipe-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a directory of this test's own");
        let pipe = directory.join("a-pipe");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&pipe)
                .status()
                .expect("mkfifo runs")
                .success(),
            "a pipe"
        );
        let records = vec![finding_naming(&pipe)];
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(identities_now(&records));
        });
        let answered = receiver.recv_timeout(Duration::from_secs(5));
        if answered.is_err() {
            // The case's own cleanup: a writer lets the reader that waited for one go.
            drop(std::fs::OpenOptions::new().write(true).open(&pipe));
        }
        assert!(
            answered.is_ok(),
            "reading the finding's file waited for a pipe"
        );
        std::fs::remove_dir_all(&directory).expect("removes the test's directory");
    }

    #[test]
    fn findings_are_about_the_desktop_as_the_run_began() {
        // A profile that changes while the run goes on is a change since the run began, so the
        // findings are over at the first reading after they arrive.
        let began = fingerprint_of(&context(), None, None);
        let mut other = context();
        other.worker_profile = WorkerProfile::HeadlessUser;
        let mut checks = Checks::new();
        checks.begin(TimestampMs::new(10), session(), began);
        checks.succeeded(TimestampMs::new(20), vec![screen_finding()]);
        assert!(standing_now(&mut checks, &fingerprint_of(&other, None, None)).is_empty());
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
            fingerprint_of(&context(), None, None),
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
                standing_now(&mut checks, &fingerprint_of(&desktop, None, None)).len(),
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
        assert_eq!(standing_now(&mut checks, &taken).len(), 1);
        assert_eq!(checks.held_stamp().0, Some(session()));
    }

    /// A worker of `session_id` in `profile` that states `release`, published at `published`.
    fn known(
        controller: &Controller,
        session_id: SessionId,
        number: u8,
        release: &str,
        profile: WorkerProfile,
        published: u64,
    ) -> KnownWorker {
        use kr_protocol::identity::{BootIdentity, BootIdentitySource, ProcessStartSource};
        use kr_protocol::scalars::{AuthorisationKey, Bytes};
        use kr_protocol::session::DisplayNumber;

        let display = DisplayNumber::new(u64::from(number));
        let endpoint = controller
            .paths()
            .worker_endpoint(display)
            .expect("an endpoint");
        KnownWorker {
            level: kr_protocol::retained::Level::this(),
            release: Some(kr_protocol::update::ReleaseName::new(release).expect("a release")),
            descriptor: kr_protocol::worker::WorkerDescriptor {
                session_id,
                session_epoch: kr_protocol::ids::SessionEpoch::V1,
                environment_id: controller.paths().environment_id(),
                display_number: display,
                boot_identity: BootIdentity {
                    source: BootIdentitySource::LinuxBootId,
                    value: Bytes::new(b"boot".to_vec()),
                },
                process_start_identity: kr_protocol::identity::ProcessStartIdentity::new(
                    100 + u64::from(number),
                    ProcessStartSource::LinuxProcStat,
                    22,
                ),
                protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
                endpoint: endpoint.as_text(),
                worker_public_key: AuthorisationKey::from_bytes([number; 32]),
                worker_profile: profile,
                published_at_ms: TimestampMs::new(published),
            },
            endpoint,
        }
    }

    /// KR-REQ-03.29: findings taken in a host agent are no longer current once the worker a run
    /// goes to states a newer release, and not while only another session of the same release
    /// has started.
    ///
    /// This is the daemon's own report: findings are held for the worker that made them, and a
    /// worker is put in the directory the way an update brings one. The release is what the worker
    /// stated when the daemon met it, so a second session of one release is another process and
    /// not another build.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kr_req_03_29_findings_end_when_the_worker_a_run_goes_to_is_of_a_newer_release() {
        let temp = kr_ipc::testing::TempHost::create();
        let controller =
            Controller::start(super::super::a_close_a_worker_never_answers::setup(&temp))
                .await
                .expect("the daemon starts");
        let (context, _) = controller.desktop_evidence().await;
        let profile = context.worker_profile;
        let other = SessionId::new(Uuid::from_bytes([7; 16]));
        let next = SessionId::new(Uuid::from_bytes([8; 16]));

        let earlier = known(&controller, session(), 1, "0.2.0+aaaaaaaaaaaa", profile, 10);
        controller
            .directory
            .lock()
            .await
            .insert(earlier.clone(), None);
        let taken = fingerprint_of(&context, Some(&earlier), Some(&earlier));
        {
            let mut checks = controller
                .checks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            checks.begin(TimestampMs::new(10), session(), taken);
            checks.succeeded(
                TimestampMs::new(20),
                vec![record(
                    capabilities::AUTHORISED_FILE_READ,
                    CapabilityState::QualifiedAvailable,
                    CapabilityEvidenceSource::DisclosedProbe,
                    Some(session()),
                )],
            );
        }
        let (report, checks) = controller
            .capability_report_with_checks()
            .await
            .expect("a report");
        assert_eq!(checks.state, CapabilityChecksState::Current);
        assert!(report.record(capabilities::AUTHORISED_FILE_READ).is_some());

        // Another session of the same release is a newer worker, and the findings stand.
        let same = known(&controller, other, 2, "0.2.0+aaaaaaaaaaaa", profile, 20);
        controller.directory.lock().await.insert(same, None);
        let (report, checks) = controller
            .capability_report_with_checks()
            .await
            .expect("a report");
        assert_eq!(
            checks.state,
            CapabilityChecksState::Current,
            "a second session of the same release is not an update"
        );
        assert!(report.record(capabilities::AUTHORISED_FILE_READ).is_some());

        // A worker of a newer release is where a run goes now, and the findings do not stand.
        let newer = known(&controller, next, 3, "0.3.0+bbbbbbbbbbbb", profile, 30);
        controller.directory.lock().await.insert(newer, None);
        let (report, checks) = controller
            .capability_report_with_checks()
            .await
            .expect("a report");
        assert_eq!(
            checks.state,
            CapabilityChecksState::Stale,
            "the findings were taken in a host agent of an earlier release"
        );
        assert!(
            report.record(capabilities::AUTHORISED_FILE_READ).is_none(),
            "the earlier host agent's finding is not served"
        );
        let chosen = worker_for(controller.directory_workers().await, profile)
            .expect("a worker a run goes to");
        assert_eq!(
            chosen.descriptor.session_id, next,
            "the run asked for next is performed in the worker of the newer release"
        );
    }
}
