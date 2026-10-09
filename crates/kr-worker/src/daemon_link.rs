//! The worker's questions to the control daemon on its rendezvous endpoint.
//!
//! The rendezvous endpoint is owner-only, and the daemon answers a running worker on it only when
//! the kernel names the process asking as the one it recorded for the session. A question is one
//! exchange on a connection of its own: the hello, the question, the answer. Nothing here keeps a
//! connection, so a daemon that restarts is asked again the next time and no state is lost with it.
//!
//! # A draft
//!
//! The daemon owns the drafts. A worker whose agent is to be offered an attachment reads what the
//! draft holds, claims the one binding it is about to offer, and reports what became of the offer
//! ([`Drafts`]). The report is the part that has to arrive: the daemon may be down when the agent
//! answers, so reports wait in a queue with a task of its own that asks again until the daemon
//! records or refuses for good ([`Reporter`]). A worker that dies first is a closed session, which
//! the daemon fails every unreported offer of, so the queue needs no storage of its own.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::split;
use kr_ipc::paths::Endpoint;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::{ErrorCode, ProtocolError, RetryCategory};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{ActorId, DraftId, SessionId};
use kr_protocol::insertion::{
    DraftAnswer, DraftFacts, DraftStep, DraftWanted, InsertionBegin, InsertionClaim,
    InsertionReport, ReportedOutcome,
};
use kr_protocol::local::{LocalClientKind, LocalHello};
use kr_protocol::scalars::CanonicalSet;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

/// How many reports may wait for the daemon at once.
///
/// A place is reserved before an offer is claimed and travels with the claim to its report, so a
/// report is never refused for room and never waits for any. A worker with none left refuses the
/// action that would claim.
pub const MAX_PENDING_REPORTS: usize = 256;

/// How long the reporter waits before it asks again, the first time; each failure doubles it.
const FIRST_RETRY: Duration = Duration::from_millis(250);

/// The longest the reporter waits between two attempts.
const LONGEST_RETRY: Duration = Duration::from_secs(10);

/// How long one report is given to be recorded.
const REPORT_DEADLINE: Duration = Duration::from_secs(30);

/// One exchange on the control daemon's rendezvous endpoint: the hello, `request`, and the answer.
///
/// # Errors
///
/// Returns why, in words for a person, when the daemon could not be reached, did not acknowledge
/// the hello or did not answer inside `within`.
pub async fn exchange(
    rendezvous: &Path,
    request: ControlFrame,
    within: Duration,
) -> Result<ControlFrame, String> {
    let exchange = async {
        let endpoint = Endpoint::from_path(rendezvous).map_err(|error| error.to_string())?;
        let connection = Connection::connect(&endpoint)
            .await
            .map_err(|error| error.to_string())?;
        let (mut reader, mut writer) = split(connection, StreamKind::Control);
        writer
            .write_message(&ControlFrame::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id: crate::build_id(),
                client: LocalClientKind::Worker,
                capabilities: CanonicalSet::new(),
                max_receive: ReceiveLimits::default(),
                origin: None,
            }))
            .await
            .map_err(|error| error.to_string())?;
        let acknowledged: ControlFrame = reader
            .read_message()
            .await
            .map_err(|error| error.to_string())?;
        if !matches!(acknowledged, ControlFrame::HelloAck(_)) {
            return Err("the control daemon did not acknowledge the request".to_owned());
        }
        writer
            .write_message(&request)
            .await
            .map_err(|error| error.to_string())?;
        reader
            .read_message::<ControlFrame>()
            .await
            .map_err(|error| error.to_string())
    };
    match tokio::time::timeout(within, exchange).await {
        Ok(answer) => answer,
        Err(_elapsed) => Err(format!(
            "the control daemon did not answer within {} seconds",
            within.as_secs()
        )),
    }
}

/// Where the control daemon is, and which session this worker serves.
#[derive(Clone, Debug)]
pub struct DaemonLink {
    session_id: SessionId,
    rendezvous: PathBuf,
}

impl DaemonLink {
    /// A link for the worker of `session_id`, reaching the daemon on `rendezvous`.
    #[must_use]
    pub const fn new(session_id: SessionId, rendezvous: PathBuf) -> Self {
        Self {
            session_id,
            rendezvous,
        }
    }

    /// The session this worker serves.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Asks the daemon one question about a draft, for `actor`.
    ///
    /// # Errors
    ///
    /// Returns [`Asked::Unreached`] when the daemon could not be asked, and [`Asked::Refused`] with
    /// the error it gave, whose retry category says whether asking again can help.
    pub async fn ask(
        &self,
        actor: &ActorId,
        step: DraftStep,
        within: Duration,
    ) -> Result<DraftAnswer, Asked> {
        let wanted = ControlFrame::DraftWanted(Box::new(DraftWanted {
            session_id: self.session_id,
            actor_id: actor.clone(),
            step,
        }));
        match exchange(&self.rendezvous, wanted, within).await {
            Ok(ControlFrame::DraftAnswer(answer)) => match *answer {
                DraftAnswer::Refused(error) => Err(Asked::Refused(error)),
                answer => Ok(answer),
            },
            Ok(_) => Err(Asked::Unreached(
                "the control daemon answered with something else".to_owned(),
            )),
            Err(why) => Err(Asked::Unreached(why)),
        }
    }
}

/// Why a question about a draft was not answered.
#[derive(Debug)]
pub enum Asked {
    /// The daemon could not be reached, or did not answer.
    Unreached(String),
    /// The daemon answered that it will not.
    Refused(ProtocolError),
}

impl Asked {
    /// Whether asking again can help: the daemon was not reached, it said the condition passes, or
    /// it could not say what became of the question.
    #[must_use]
    pub fn can_be_asked_again(&self) -> bool {
        self.is_unanswered()
            || matches!(self, Self::Refused(error) if error.retry == RetryCategory::Transient)
    }

    /// Whether the daemon may have acted on the question without saying so: it was not reached or
    /// did not answer, or it answered that it could not report what became of the question.
    #[must_use]
    pub fn is_unanswered(&self) -> bool {
        match self {
            Self::Unreached(_) => true,
            Self::Refused(error) => error.retry == RetryCategory::OutcomeUnknown,
        }
    }

    /// The failure as the broker states it to a caller.
    #[must_use]
    pub fn into_error(self) -> crate::broker::BrokerError {
        use crate::broker::BrokerError;
        match self {
            Self::Unreached(why) => BrokerError::ResourceUnavailable {
                detail: format!("the control daemon could not be asked about the draft: {why}"),
            },
            Self::Refused(error) => match error.code {
                // What cannot be said is asked again, and a person is told the daemon could not be
                // asked, not that the request was wrong.
                ErrorCode::ResourceUnavailable
                | ErrorCode::StorageUnavailable
                | ErrorCode::OutcomeUnknown => BrokerError::ResourceUnavailable {
                    detail: error.message,
                },
                ErrorCode::DraftConflict | ErrorCode::SessionClosed | ErrorCode::StaleSession => {
                    BrokerError::PreconditionFailed {
                        detail: error.message,
                    }
                }
                ErrorCode::PermissionDenied => BrokerError::denied(error.message),
                ErrorCode::UnsupportedCapability => BrokerError::UnsupportedCapability {
                    detail: error.message,
                },
                _ => BrokerError::InvalidArgument(error.message),
            },
        }
    }
}

/// What the worker keeps to ask the daemon about drafts.
#[derive(Debug)]
pub struct Drafts {
    link: Arc<Mutex<Option<Arc<DaemonLink>>>>,
    reporter: Reporter,
}

impl Drafts {
    pub(crate) fn new() -> Self {
        let link = Arc::new(Mutex::new(None));
        Self {
            reporter: Reporter::new(Arc::clone(&link)),
            link,
        }
    }

    /// Gives this worker the daemon to ask. Without one, an action that acts on a draft is
    /// refused.
    pub fn connect(&self, link: DaemonLink) {
        *self.link.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(link));
    }

    /// The daemon this worker asks, where it has one.
    #[must_use]
    pub fn link(&self) -> Option<Arc<DaemonLink>> {
        self.link
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Reserves the place for the report of an offer that is about to be claimed.
    ///
    /// # Errors
    ///
    /// Returns `None` when [`MAX_PENDING_REPORTS`] reports are already waiting for the daemon.
    #[must_use]
    pub fn reserve(&self) -> Option<ReportSlot> {
        Arc::clone(&self.reporter.slots)
            .try_acquire_owned()
            .ok()
            .map(|permit| ReportSlot {
                permit,
                queue: self.reporter.queue.clone(),
                waiting: Arc::clone(&self.reporter.waiting),
            })
    }

    /// Reads what a draft holds, without its text.
    ///
    /// # Errors
    ///
    /// Returns the broker's statement of why the daemon did not answer.
    pub async fn facts(
        &self,
        actor: &ActorId,
        draft_id: DraftId,
        within: Duration,
    ) -> crate::broker::Result<DraftFacts> {
        let link = self.link().ok_or_else(no_daemon)?;
        match link
            .ask(actor, DraftStep::Facts { draft_id }, within)
            .await
            .map_err(Asked::into_error)?
        {
            DraftAnswer::Facts(facts) => Ok(facts),
            _ => Err(wrong_answer()),
        }
    }

    /// Claims one binding for an offer, and holds the claim.
    ///
    /// The place `slot` reserved is the claim's: the report of the offer takes it. A daemon that
    /// refuses the claim made none, and the place is given back. A daemon that was asked and did
    /// not answer may still commit the claim, until the deadline the request carried, so a report
    /// that the offer failed is queued to be made once that deadline has passed (a binding the
    /// daemon marked `inserting` for this action then settles, and one it did not mark refuses the
    /// report, which ends it).
    ///
    /// # Errors
    ///
    /// Returns the broker's statement of why the daemon did not claim.
    pub async fn begin(
        &self,
        actor: &ActorId,
        slot: ReportSlot,
        begin: InsertionBegin,
        within: Duration,
    ) -> crate::broker::Result<(ClaimHold, InsertionClaim)> {
        let link = self.link().ok_or_else(no_daemon)?;
        match link
            .ask(actor, DraftStep::Begin(begin.clone()), within)
            .await
        {
            Ok(DraftAnswer::Claim(claim)) => {
                self.ensure_reporter();
                Ok((ClaimHold::new(slot, actor.clone(), begin), *claim))
            }
            Ok(_) => Err(wrong_answer()),
            Err(asked) if !asked.is_unanswered() => Err(asked.into_error()),
            Err(asked) => {
                self.ensure_reporter();
                let not_before = begin.deadline_boot_ms.get();
                ClaimHold::new(slot, actor.clone(), begin).report_after(
                    not_before,
                    ReportedOutcome::Failed {
                        detail: "the control daemon did not say whether the attachment was \
                                 claimed for the offer"
                            .to_owned(),
                    },
                );
                Err(asked.into_error())
            }
        }
    }
}

fn no_daemon() -> crate::broker::BrokerError {
    crate::broker::BrokerError::UnsupportedCapability {
        detail: "this worker has no control daemon to read drafts from".to_owned(),
    }
}

fn wrong_answer() -> crate::broker::BrokerError {
    crate::broker::BrokerError::ResourceUnavailable {
        detail: "the control daemon answered with something else than was asked".to_owned(),
    }
}

/// A report waiting for the daemon.
#[derive(Debug)]
struct Waiting {
    actor: ActorId,
    report: InsertionReport,
    /// The boot-clock millisecond before which the report is not made, when the claim it settles
    /// may still be committed by a daemon that was asked and did not answer.
    not_before_boot_ms: Option<u64>,
    /// The place the report holds in the queue, given back when it is recorded or refused for good.
    _slot: OwnedSemaphorePermit,
}

/// The queue of reports and the task that delivers them.
#[derive(Debug)]
struct Reporter {
    slots: Arc<Semaphore>,
    queue: mpsc::UnboundedSender<Waiting>,
    /// The receiving end, until the task that delivers takes it.
    receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<Waiting>>>>,
    link: Arc<Mutex<Option<Arc<DaemonLink>>>>,
    /// How many reports have not been recorded or refused for good.
    waiting: Arc<std::sync::atomic::AtomicUsize>,
}

impl Reporter {
    fn new(link: Arc<Mutex<Option<Arc<DaemonLink>>>>) -> Self {
        let (queue, receiver) = mpsc::unbounded_channel();
        Self {
            slots: Arc::new(Semaphore::new(MAX_PENDING_REPORTS)),
            queue,
            receiver: Arc::new(Mutex::new(Some(receiver))),
            link,
            waiting: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

/// The place for one report, reserved before the offer it is for is claimed.
#[derive(Debug)]
pub struct ReportSlot {
    permit: OwnedSemaphorePermit,
    queue: mpsc::UnboundedSender<Waiting>,
    waiting: Arc<std::sync::atomic::AtomicUsize>,
}

/// Where an offer stands from the moment it is claimed, and so what its report says if nothing else
/// does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Standing {
    /// Claimed, and nothing has been sent to the agent: a report says the offer failed.
    Claimed,
    /// The dispatch marker is written, so the agent may have been sent the offer: a report with no
    /// outcome says it is unknown.
    Dispatched,
    /// Reported.
    Reported,
}

/// An offer the daemon has claimed for this worker, until its report is queued.
///
/// The hold owns the place its report will take. Whatever ends the action, the report is made: the
/// outcome the action came to if it came to one, and otherwise (the hold dropped, which is a bug
/// or a task that was cancelled) a report of what is known, so a binding the daemon marked
/// `inserting` does not stay so until the session ends.
#[derive(Debug)]
pub struct ClaimHold {
    slot: Option<ReportSlot>,
    actor: ActorId,
    begin: InsertionBegin,
    standing: Standing,
}

impl ClaimHold {
    pub(crate) fn new(slot: ReportSlot, actor: ActorId, begin: InsertionBegin) -> Self {
        Self {
            slot: Some(slot),
            actor,
            begin,
            standing: Standing::Claimed,
        }
    }

    /// The dispatch marker is written: from here the agent may have been sent the offer.
    pub fn dispatched(&mut self) {
        self.standing = Standing::Dispatched;
    }

    /// Reports `outcome` and ends the hold.
    pub fn report(mut self, outcome: ReportedOutcome) {
        self.send(None, outcome);
    }

    /// Reports `outcome` once the boot clock has reached `not_before_boot_ms`, and ends the hold.
    fn report_after(mut self, not_before_boot_ms: u64, outcome: ReportedOutcome) {
        self.send(Some(not_before_boot_ms), outcome);
    }

    fn send(&mut self, not_before_boot_ms: Option<u64>, outcome: ReportedOutcome) {
        let Some(slot) = self.slot.take() else {
            return;
        };
        self.standing = Standing::Reported;
        let report = InsertionReport {
            action_id: self.begin.action_id,
            draft_id: self.begin.draft_id,
            transfer_id: self.begin.transfer_id,
            attempt: self.begin.attempt,
            outcome,
        };
        slot.waiting
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let waiting = Waiting {
            actor: self.actor.clone(),
            report,
            not_before_boot_ms,
            _slot: slot.permit,
        };
        if slot.queue.send(waiting).is_err() {
            slot.waiting
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl Drop for ClaimHold {
    fn drop(&mut self) {
        match self.standing {
            Standing::Reported => {}
            Standing::Claimed => self.send(
                None,
                ReportedOutcome::Failed {
                    detail: "the action ended before anything was sent to the agent".to_owned(),
                },
            ),
            Standing::Dispatched => self.send(
                None,
                ReportedOutcome::Unknown {
                    detail: "the action ended after the agent may have been sent the attachment, \
                             with no answer from it"
                        .to_owned(),
                },
            ),
        }
    }
}

impl Drafts {
    /// Starts the task that delivers reports, once, where a runtime is running.
    ///
    /// Called with every claim a worker makes; a worker that never claims never starts it.
    fn ensure_reporter(&self) {
        let reporter = &self.reporter;
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let Some(receiver) = reporter
            .receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        let link = Arc::clone(&reporter.link);
        let waiting = Arc::clone(&reporter.waiting);
        runtime.spawn(deliver(receiver, link, waiting));
    }

    /// How many reports have not been recorded or refused for good.
    #[must_use]
    pub fn reports_waiting(&self) -> usize {
        self.reporter
            .waiting
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Delivers the reports in the order they were made, until the queue is dropped.
async fn deliver(
    mut receiver: mpsc::UnboundedReceiver<Waiting>,
    link: Arc<Mutex<Option<Arc<DaemonLink>>>>,
    waiting: Arc<std::sync::atomic::AtomicUsize>,
) {
    let mut pending: VecDeque<Waiting> = VecDeque::new();
    let mut delay = FIRST_RETRY;
    loop {
        if pending.is_empty() {
            match receiver.recv().await {
                Some(next) => pending.push_back(next),
                None => return,
            }
        }
        while let Ok(next) = receiver.try_recv() {
            pending.push_back(next);
        }
        let Some(head) = pending.front() else {
            continue;
        };
        // A report for a claim the daemon may still commit waits for the claim's deadline, after
        // which it cannot.
        // The clock is read again after each sleep, because a sleep can end before the counter it
        // is measured against has passed the time.
        if let Some(not_before) = head.not_before_boot_ms {
            loop {
                let now = kr_ipc::clock::boot_elapsed_ms();
                if now > not_before {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(not_before - now + 1)).await;
            }
        }
        let daemon = link.lock().unwrap_or_else(PoisonError::into_inner).clone();
        let answer = match daemon {
            Some(daemon) => {
                daemon
                    .ask(
                        &head.actor,
                        DraftStep::Report(head.report.clone()),
                        REPORT_DEADLINE,
                    )
                    .await
            }
            None => Err(Asked::Unreached(
                "this worker has no control daemon to report to".to_owned(),
            )),
        };
        match answer {
            // Recorded: it is done, and the place is given back.
            Ok(_) => {}
            // Refused for good, or already settled otherwise: asking again changes nothing.
            Err(asked) if !asked.can_be_asked_again() => {}
            Err(_) => {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(LONGEST_RETRY);
                continue;
            }
        }
        delay = FIRST_RETRY;
        pending.pop_front();
        waiting.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use kr_protocol::hello::ActionWindow;
    use kr_protocol::identity::{BootIdentity, BootIdentitySource};
    use kr_protocol::ids::{
        ActionId, ActionWindowId, BootEpoch, ConnectionId, EnvironmentId, TransferId,
    };
    use kr_protocol::local::{LocalHelloAck, LocalPeer, LocalRole};
    use kr_protocol::scalars::{Bytes, DurationMs, Nullable, TimestampMs, U64, Uuid};
    use kr_protocol::transfer::InsertionState;

    /// What a scripted control daemon does with a claim it is asked.
    #[derive(Clone, Copy)]
    enum Claim {
        /// Reads it and closes the connection: the worker hears nothing.
        Closes,
        /// Answers that it cannot say what became of it.
        CannotSay,
        /// Answers that it will not, for good.
        Refuses,
    }

    /// A control daemon's rendezvous endpoint, scripted: it acknowledges every hello, deals with a
    /// claim as `claim` says, and records the boot-clock reading at which each report arrives.
    fn scripted(
        path: &Path,
        claim: Claim,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::mpsc::UnboundedReceiver<u64>,
    ) {
        let endpoint = Endpoint::from_path(path).expect("an endpoint");
        let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds");
        let (reports, arrived) = tokio::sync::mpsc::unbounded_channel();
        let serving = tokio::spawn(async move {
            loop {
                let Ok((connection, _peer)) = listener.accept().await else {
                    return;
                };
                let reports = reports.clone();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = split(connection, StreamKind::Control);
                    let Ok(ControlFrame::Hello(_)) = reader.read_message().await else {
                        return;
                    };
                    let acknowledgement = LocalHelloAck {
                        selected_version: PROTOCOL_VERSION,
                        role: LocalRole::Controller,
                        connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
                        environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
                        boot_identity: BootIdentity {
                            source: BootIdentitySource::BootTime,
                            value: Bytes::from(vec![3; 8]),
                        },
                        peer: LocalPeer {
                            uid: U64::new(0),
                            gid: U64::new(0),
                            pid: Nullable::null(),
                        },
                        action_window: ActionWindow {
                            action_window_id: ActionWindowId::new("window").expect("an id"),
                            connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
                            boot_epoch: BootEpoch::new(1),
                            issued_at_ms: TimestampMs::new(1),
                            valid_for_ms: DurationMs::new(1000),
                        },
                        capabilities: CanonicalSet::new(),
                        max_receive: ReceiveLimits::default(),
                        build: None,
                    };
                    if writer
                        .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let Ok(ControlFrame::DraftWanted(wanted)) = reader.read_message().await else {
                        return;
                    };
                    let answer = match wanted.step {
                        DraftStep::Report(_) => {
                            let _ = reports.send(kr_ipc::clock::boot_elapsed_ms());
                            DraftAnswer::Reported(InsertionState::Failed)
                        }
                        DraftStep::Begin(_) => match claim {
                            Claim::Closes => return,
                            Claim::CannotSay => DraftAnswer::Refused(ProtocolError::new(
                                ErrorCode::OutcomeUnknown,
                                "the claim may have been made",
                            )),
                            Claim::Refuses => DraftAnswer::Refused(ProtocolError::new(
                                ErrorCode::DraftConflict,
                                "no",
                            )),
                        },
                        DraftStep::Facts { .. } => return,
                    };
                    let _ = writer
                        .write_message(&ControlFrame::DraftAnswer(Box::new(answer)))
                        .await;
                });
            }
        });
        (serving, arrived)
    }

    fn claim_with_deadline(deadline_boot_ms: u64) -> InsertionBegin {
        InsertionBegin {
            action_id: ActionId::new(Uuid::from_bytes([4; 16])),
            draft_id: DraftId::new(Uuid::from_bytes([5; 16])),
            transfer_id: TransferId::new(Uuid::from_bytes([6; 16])),
            attempt: U64::new(0),
            max_count: U64::new(4),
            deadline_boot_ms: U64::new(deadline_boot_ms),
        }
    }

    /// Asks `daemon` for a claim whose deadline is `after_ms` from now, and says when the report
    /// that follows arrives, if one does, together with the deadline.
    async fn claim_and_wait_for_the_report(claim: Claim, after_ms: u64) -> (u64, Option<u64>) {
        let host = kr_ipc::testing::TempHost::create();
        let path = host
            .environment()
            .rendezvous_endpoint()
            .expect("an endpoint")
            .as_path()
            .to_path_buf();
        let (_serving, mut arrived) = scripted(&path, claim);
        let drafts = Drafts::new();
        drafts.connect(DaemonLink::new(
            SessionId::new(Uuid::from_bytes([7; 16])),
            path,
        ));
        let deadline = kr_ipc::clock::boot_elapsed_ms() + after_ms;
        let actor = ActorId::new("local:test").expect("a principal");
        let slot = drafts.reserve().expect("a place for the report");
        let error = drafts
            .begin(
                &actor,
                slot,
                claim_with_deadline(deadline),
                Duration::from_secs(30),
            )
            .await
            .expect_err("the claim was not answered with a claim");
        drop(error);
        let report = if drafts.reports_waiting() == 0 {
            None
        } else {
            tokio::time::timeout(Duration::from_secs(60), arrived.recv())
                .await
                .ok()
                .flatten()
        };
        (deadline, report)
    }

    /// A claim the daemon was asked for and did not answer, because the connection ended or the
    /// answer says it cannot tell, may still be committed by a daemon that was slow to get to it. A
    /// report that the offer failed is made only once the claim's deadline has passed, after which
    /// a daemon commits no claim, so the report cannot meet a claim that commits after it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_report_of_a_claim_nobody_answered_is_made_only_after_the_claims_deadline() {
        for claim in [Claim::Closes, Claim::CannotSay] {
            let (deadline, report) = claim_and_wait_for_the_report(claim, 1500).await;
            let at = report.expect("the report is made");
            assert!(
                at > deadline,
                "the report arrived at {at}, the deadline was {deadline}"
            );
        }
    }

    /// A claim the daemon refused for good was not made, and nothing is reported for it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_claim_the_daemon_refused_for_good_leaves_no_report_to_make() {
        let (_, report) = claim_and_wait_for_the_report(Claim::Refuses, 1500).await;
        assert_eq!(report, None);
    }

    #[test]
    fn a_refusal_that_cannot_say_what_became_of_the_question_is_no_answer() {
        let cannot_say = Asked::Refused(ProtocolError::new(ErrorCode::OutcomeUnknown, "maybe"));
        assert!(cannot_say.is_unanswered());
        assert!(cannot_say.can_be_asked_again());
        let no = Asked::Refused(ProtocolError::new(ErrorCode::DraftConflict, "no"));
        assert!(!no.is_unanswered());
        assert!(!no.can_be_asked_again());
        let later = Asked::Refused(ProtocolError::new(ErrorCode::ResourceUnavailable, "later"));
        assert!(!later.is_unanswered());
        assert!(later.can_be_asked_again());
        assert!(Asked::Unreached("down".to_owned()).is_unanswered());
        assert!(matches!(
            cannot_say.into_error(),
            crate::broker::BrokerError::ResourceUnavailable { .. }
        ));
    }
}
