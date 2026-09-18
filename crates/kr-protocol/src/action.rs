//! Section 9's remaining contracts: observation evidence, the revocation barrier's report and the
//! host time contract.
//!
//! [`receipt`](crate::receipt) holds the execution states a mutation moves through. Three things
//! sit beside that state machine rather than inside it, and they are here because each of them is
//! a contract both ends of the wire have to read the same way.
//!
//! * **Observation is additive evidence, not a competing execution state.** An observation names
//!   its provenance, the subject and version it saw, the cursor it came from and what it claims
//!   happened. [`ActionObservation::resolution`] is the whole rule: an inferred screen can never
//!   turn an uncertain outcome into a confirmed one, because a screen is what the host read, not
//!   what the authoritative interface said.
//! * **A revocation is complete only when every affected worker's barrier holds.** The report is
//!   per worker, and an action whose dispatch transition had already won the serial race is
//!   *named* rather than counted, because "possibly executed" is the only honest thing that can be
//!   said about it.
//! * **Expiry uses one time contract.** The platform time adapter records what the operating
//!   system says about its own clock: the synchronisation source, its status and a bounded
//!   uncertainty. Nothing here invents a universal authenticated-time call. A wall clock that
//!   moved backwards further than the tolerance stops being evidence, and what that does and does
//!   not disable is stated here rather than left to each caller.

use core::fmt;

use kr_cbor::{CanonicalMap, CanonicalValue, CborError, sha256, signing_value};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::envelope::MutationRequest;
use crate::identity::BootIdentity;
use crate::ids::{ActionId, ActorId, AuthorityRevision, DeviceId, SessionId};
use crate::method::MethodName;
use crate::receipt::ReceiptState;
use crate::scalars::{Digest256, Nullable, TimestampMs, U64};

// ---------------------------------------------------------------------------------------------
// Observation
// ---------------------------------------------------------------------------------------------

/// Where an observation's evidence came from.
///
/// Only an authoritative answer can resolve an uncertain outcome. Everything else is evidence a
/// person may read and act on, and nothing more: section 9 says outright that an inferred screen
/// observation cannot change `unknown` to `applied`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ObservationProvenance {
    /// The interface that owns the subject answered for this operation.
    AuthoritativeInterface,
    /// A connector matched its own upstream correlation identifier to this operation.
    UpstreamCorrelation,
    /// The host parsed a screen and inferred what it means. Inference, never confirmation.
    InferredScreen,
    /// A person reported what they saw.
    UserReport,
}

impl ObservationProvenance {
    /// Every provenance, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::AuthoritativeInterface,
        Self::UpstreamCorrelation,
        Self::InferredScreen,
        Self::UserReport,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthoritativeInterface => "authoritative_interface",
            Self::UpstreamCorrelation => "upstream_correlation",
            Self::InferredScreen => "inferred_screen",
            Self::UserReport => "user_report",
        }
    }

    /// Returns true when this provenance can resolve an uncertain outcome.
    ///
    /// An upstream correlation qualifies because section 9 names it: a dispatch marker whose
    /// upstream correlation identifier proves the result is not left uncertain. A screen and a
    /// person's report do not, however confident either looks.
    #[must_use]
    pub const fn is_authoritative(self) -> bool {
        matches!(
            self,
            Self::AuthoritativeInterface | Self::UpstreamCorrelation
        )
    }
}

impl fmt::Display for ObservationProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What an observation claims the operation's result was.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ObservedResult {
    /// The evidence claims the operation took effect.
    Applied,
    /// The evidence claims the operation was refused without the requested effect.
    Refused,
    /// The evidence says something about the subject without settling the operation.
    Indeterminate,
}

impl ObservedResult {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Refused => "refused",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// One piece of additive evidence about an action.
///
/// The word in a user interface is "observed", and it means evidence was observed. It does not
/// mean the mutation is confirmed, which is why every observation carries the provenance a reader
/// needs in order to know which of the two it is looking at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActionObservation {
    /// The action the evidence is about.
    pub action_id: ActionId,
    /// Where the evidence came from.
    pub provenance: ObservationProvenance,
    /// The subject the evidence is about, named the way its own interface names it.
    pub subject: String,
    /// The subject's version at the moment of the observation, when the subject has one.
    pub subject_revision: Nullable<U64>,
    /// The position in the source stream the evidence was read from, when there is one.
    pub source_cursor: Nullable<U64>,
    /// What the evidence claims happened.
    pub claimed_result: ObservedResult,
    /// When the observation was recorded.
    pub observed_at_ms: TimestampMs,
}

impl ActionObservation {
    /// Returns the receipt state this observation may move an action to, if any.
    ///
    /// `None` means the observation is recorded and changes no state, which is the answer for
    /// every observation of an action that already has one, for every inferred or reported
    /// observation, and for evidence that settles nothing.
    #[must_use]
    pub fn resolution(&self, current: ReceiptState) -> Option<ReceiptState> {
        // Only an uncertain outcome is open to reconciliation at all; the receipt contract permits
        // no other edge, and an observation is not a way around it.
        if current != ReceiptState::Unknown || !self.provenance.is_authoritative() {
            return None;
        }
        match self.claimed_result {
            ObservedResult::Applied => Some(ReceiptState::Applied),
            ObservedResult::Refused => Some(ReceiptState::Refused),
            ObservedResult::Indeterminate => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Superseding an uncertain outcome
// ---------------------------------------------------------------------------------------------

/// The precondition key naming the uncertain action a later request supersedes.
///
/// Section 23: an explicit later user request needs a new action identifier and must show the
/// earlier unknown result. Naming that action in the preconditions is how the request shows it,
/// and the host refuses a fresh action for a subject that already carries an uncertain outcome
/// unless it does. A service cannot therefore choose a new identifier quietly to evade
/// de-duplication: the identifier it would have to name is the one whose result it is hiding.
pub const SUPERSEDES_ACTION_KEY: &str = "supersedes_action_id";

/// The precondition key naming the receipt revision at which the caller saw the earlier result.
pub const SUPERSEDES_REVISION_KEY: &str = "supersedes_revision";

/// The domain the subject digest is separated by.
pub const SUBJECT_DOMAIN: &str = "kr-action-subject/1";

/// The fields of one method's request that name what it acts on.
///
/// Section 23's rule is about the *operation*, not the request that carries it: a later request
/// for the same thing must show the earlier uncertain result rather than quietly taking its place.
/// So a subject is the method, its version, the target, and the fields that select the resource -
/// and nothing else. A guard is not one of them. Adding a true precondition such as
/// `expected.session_state` narrows when a request may run; it does not change what the request
/// asks for, and a digest that moved with it would let any service evade the rule by adding one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubjectSelectors {
    /// Parameter keys that name what the mutation acts on.
    pub params: &'static [&'static str],
    /// Precondition keys that name it.
    ///
    /// Section 23's own example is `agent.approval.respond`, whose `expected.approval_request_id`
    /// names *which* upstream approval is being answered. That is subject identity living in the
    /// preconditions, and leaving it out would make two answers to two different approvals the
    /// same subject.
    pub expected: &'static [&'static str],
}

impl SubjectSelectors {
    /// A method whose target is the whole of what it selects.
    const TARGET_ONLY: Self = Self {
        params: &[],
        expected: &[],
    };

    /// A method that acts on one attachment of the target session.
    const ATTACHMENT: Self = Self {
        params: &["attachment_id"],
        expected: &[],
    };
}

/// Returns the fields that name what this method acts on.
///
/// A method this build does not list falls through to the target alone, which is the narrowest
/// subject and therefore the conservative one: a narrower subject makes *more* requests share it,
/// and sharing a subject with an uncertain outcome is what forces a later request to show it.
#[must_use]
pub fn subject_selectors(method: Option<crate::method::Method>) -> SubjectSelectors {
    use crate::method::Method;
    match method {
        // The input lease belongs to the session, not to the attachment asking for it. Two
        // attachments acquiring it are one subject: the second is a takeover of what the first
        // asked for, and an uncertain first attempt is exactly what the second has to show.
        Some(
            Method::SessionAttach
            | Method::SessionClose
            | Method::SessionCreate
            | Method::InputAcquire
            | Method::InputRelease
            | Method::InputInterrupt,
        ) => SubjectSelectors::TARGET_ONLY,
        Some(
            Method::SessionDetach
            | Method::AttachmentConfigure
            | Method::AttachmentViewport
            | Method::TerminalResize
            | Method::TerminalGeometryTransfer,
        ) => SubjectSelectors::ATTACHMENT,
        Some(Method::ActionCancel) => SubjectSelectors {
            params: &["action_id"],
            expected: &[],
        },
        Some(Method::AgentApprovalRespond) => SubjectSelectors {
            params: &[],
            expected: &["approval_request_id"],
        },
        _ => SubjectSelectors::TARGET_ONLY,
    }
}

/// Returns the named keys of a request field, in canonical order.
///
/// A field that is not a map at all contributes nothing: refusing it is the envelope check's job,
/// and a digest that silently normalised it would be describing something the caller did not send.
/// A named key that is absent stays absent, because its absence is part of what was asked for.
fn selected(field: &CanonicalValue, keys: &[&str]) -> Result<CanonicalValue, CborError> {
    let mut kept = CanonicalMap::new();
    if let CanonicalValue::Map(map) = field {
        for (key, value) in map.entries() {
            if keys.contains(&key.as_str()) {
                kept.insert(key.clone(), value.clone())?;
            }
        }
    }
    Ok(CanonicalValue::Map(kept))
}

/// Builds the canonical signing input for a mutation's subject.
///
/// # Errors
///
/// Returns a CBOR error when any covered field cannot be represented in KR-CBOR-1.
pub fn subject_signing_input(request: &MutationRequest) -> Result<Vec<u8>, CborError> {
    Ok(kr_cbor::encode(&subject_signing_value(request)?))
}

/// Builds the subject signing input and returns its SHA-256 digest.
///
/// This is what two mutations have in common when they ask for the same thing: the method and
/// version, the complete target, and the fields [`subject_selectors`] names for that method.
/// Everything else is left out, and the two supersession keys could not be in it whatever a
/// method named, because they are what a later request adds in order to show the earlier result.
///
/// # Errors
///
/// Returns a CBOR error when any covered field cannot be represented in KR-CBOR-1.
pub fn subject_digest(request: &MutationRequest) -> Result<Digest256, CborError> {
    Ok(Digest256::from_bytes(sha256(&subject_signing_input(
        request,
    )?)))
}

/// Builds the subject signing input as a canonical value.
///
/// # Errors
///
/// Returns a CBOR error when any covered field cannot be represented in KR-CBOR-1.
pub fn subject_signing_value(request: &MutationRequest) -> Result<CanonicalValue, CborError> {
    let selectors = subject_selectors(request.method.method());
    let mut covered = CanonicalMap::new();
    covered.insert(
        "expected".to_owned(),
        selected(request.expected.as_value(), selectors.expected)?,
    )?;
    covered.insert(
        "method".to_owned(),
        kr_cbor::to_canonical_value(&request.method)?,
    )?;
    covered.insert(
        "method_version".to_owned(),
        kr_cbor::to_canonical_value(&request.method_version)?,
    )?;
    covered.insert(
        "params".to_owned(),
        selected(request.params.as_value(), selectors.params)?,
    )?;
    covered.insert(
        "target".to_owned(),
        kr_cbor::to_canonical_value(&request.target)?,
    )?;
    Ok(signing_value(
        SUBJECT_DOMAIN,
        vec![CanonicalValue::Map(covered)],
    ))
}

// ---------------------------------------------------------------------------------------------
// The revocation barrier
// ---------------------------------------------------------------------------------------------

/// What one worker's half of a revocation barrier has reached.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BarrierState {
    /// The worker installed the revision and fenced the undispatched actions it affects.
    Acknowledged,
    /// The worker's execution has ended, so it can no longer dispatch anything.
    Ended,
    /// Neither has been established. The revocation is not complete for this worker.
    Pending,
}

impl BarrierState {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acknowledged => "acknowledged",
            Self::Ended => "ended",
            Self::Pending => "pending",
        }
    }

    /// Returns true when this worker's barrier holds.
    #[must_use]
    pub const fn holds(self) -> bool {
        matches!(self, Self::Acknowledged | Self::Ended)
    }
}

impl fmt::Display for BarrierState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// An action whose dispatch transition had already won the serial race when the fence ran.
///
/// The set is defined by the race rather than by the outcome, which is what section 9 says: an
/// action whose dispatch transition already won it is named in the result. [`Self::state`] is what
/// says how much is known about what it did, from `dispatching` through `unknown` to an
/// authoritative `applied` or `refused`, so a person reading a revocation sees which operations
/// went out under the authority that has just been withdrawn and which of them are still
/// uncertain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PossiblyExecutedAction {
    /// The action.
    pub action_id: ActionId,
    /// The actor that submitted it.
    pub actor_id: ActorId,
    /// The method it was submitted under.
    pub method: MethodName,
    /// The receipt state it stood at when the fence ran.
    pub state: ReceiptState,
}

/// How many actions one acknowledgement names.
///
/// The acknowledgement travels in one control frame, and a frame is bounded, so what one carries
/// has to be too. This is the page rather than the whole: a fence that affected more actions than
/// this answers the first announcement with the first page and says how many names remain, and
/// the daemon asks again from where the page ended until nothing remains. A revocation whose
/// evidence could not be encoded would be worse than one delivered in pages.
pub const MAX_NAMED_FENCED_ACTIONS: usize = 256;

/// One action a fence named, with the actor whose action it was.
///
/// The actor is part of the name because the de-duplication key is the actor and the action
/// together: two actors may each have used one identifier, and an identifier on its own would name
/// either of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FencedAction {
    /// The actor whose action it was.
    pub actor_id: ActorId,
    /// The action.
    pub action_id: ActionId,
}

/// What a worker's fence did, as one acknowledgement carries it.
///
/// The lists are the acknowledgement rather than an addition to it: section 9 makes the
/// acknowledgement a statement that the revision is installed **and** that the undispatched
/// actions it affects have been rejected or named. A worker that reports no evidence at all is a
/// different thing from one that reports empty lists, which is why this travels as a whole.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FenceEvidence {
    /// The undispatched intents the fence rejected, in this page.
    pub rejected_actions: Vec<FencedAction>,
    /// The actions whose dispatch transition had already won the serial race, in this page.
    ///
    /// Each one's receipt state says how much is known about what it did; the list is not only the
    /// uncertain ones.
    pub possibly_executed: Vec<PossiblyExecutedAction>,
    /// How many names this worker holds that this page did not carry.
    ///
    /// Nought means the evidence is complete as far as this worker holds it. Anything else is what
    /// the next announcement asks for, from `evidence_from` = the number of names taken so far.
    pub remaining: U64,
    /// How many affected actions this worker could hold no name for at all.
    ///
    /// Nought in every ordinary case. Anything else says the fence affected more actions than one
    /// worker keeps names for, and their receipts are in its journal.
    pub omitted: U64,
}

/// One worker's half of a revocation barrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkerBarrier {
    /// The session the worker owns.
    pub session_id: SessionId,
    /// What this worker's barrier has reached.
    pub state: BarrierState,
    /// The revision the worker has installed, when it has installed one.
    pub acknowledged_revision: Nullable<AuthorityRevision>,
    /// The undispatched intents the fence rejected.
    pub rejected_actions: Vec<FencedAction>,
    /// The actions whose dispatch transition had already won the serial race.
    ///
    /// Each one's receipt state says how much is known about what it did; the list is
    /// not only the uncertain ones.
    pub possibly_executed: Vec<PossiblyExecutedAction>,
    /// How many affected actions the worker could hold no name for.
    ///
    /// Nought in every ordinary case, because the names are kept in the worker's journal and
    /// delivered a page at a time. Anything else is a worker that could not record a name at all.
    pub omitted_actions: U64,
    /// How many names this worker holds that have not reached this daemon yet.
    ///
    /// Nought means the evidence is complete. Anything else says a page exchange has not happened
    /// yet or did not finish; the names are in the worker's journal and the next announcement
    /// continues from where the last page ended.
    pub names_pending: U64,
    /// Why this worker's barrier has not held, or what is still outstanding about one that has.
    pub detail: String,
}

/// The result of installing an authority revision across every affected worker.
///
/// Until every barrier holds, this is `pending` with per-worker status. Cutting a network path or
/// waiting for a lease timer is not completion, because a paused worker could already be inside a
/// dispatch transition, so nothing here treats the absence of an answer as an answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RevocationBarrier {
    /// The revision being installed.
    pub authority_revision: AuthorityRevision,
    /// One entry per affected worker.
    pub workers: Vec<WorkerBarrier>,
}

impl RevocationBarrier {
    /// Returns true when every worker's barrier holds.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.workers.iter().all(|worker| worker.state.holds())
    }

    /// Returns the workers whose barriers have not held.
    #[must_use]
    pub fn pending(&self) -> Vec<SessionId> {
        self.workers
            .iter()
            .filter(|worker| !worker.state.holds())
            .map(|worker| worker.session_id)
            .collect()
    }

    /// Returns every action this revocation could not prove did not happen.
    #[must_use]
    pub fn possibly_executed(&self) -> Vec<&PossiblyExecutedAction> {
        self.workers
            .iter()
            .flat_map(|worker| worker.possibly_executed.iter())
            .collect()
    }
}

// ---------------------------------------------------------------------------------------------
// The host time contract
// ---------------------------------------------------------------------------------------------

/// How far a wall clock may move backwards before this host stops treating it as evidence.
///
/// Section 9: a rollback beyond five seconds marks wall-clock trust unresolved.
pub const MAX_WALL_CLOCK_ROLLBACK_MS: u64 = 5_000;

/// How much uncertainty a platform reading may carry and still qualify as time evidence.
///
/// The operating systems all report a bound rather than a promise, so the question this answers is
/// how loose that bound may be before a deadline measured against it means nothing. Two seconds is
/// below the rollback tolerance above, which is what makes a qualified reading strictly better
/// evidence than the absence of an observed rollback.
pub const MAX_TRUSTED_UNCERTAINTY_US: u64 = 2_000_000;

/// What the operating system says is disciplining its clock.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TimeSyncSource {
    /// The platform's own network time service is disciplining the clock.
    NetworkTimeService,
    /// A pulse-per-second reference is disciplining the clock.
    PulsePerSecond,
    /// Nothing is disciplining the clock.
    Unsynchronised,
    /// The platform answered with a state this build does not classify.
    Unclassified,
}

impl TimeSyncSource {
    /// Every source, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::NetworkTimeService,
        Self::PulsePerSecond,
        Self::Unsynchronised,
        Self::Unclassified,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NetworkTimeService => "network_time_service",
            Self::PulsePerSecond => "pulse_per_second",
            Self::Unsynchronised => "unsynchronised",
            Self::Unclassified => "unclassified",
        }
    }

    /// Returns true when something the platform names is disciplining the clock.
    #[must_use]
    pub const fn is_disciplined(self) -> bool {
        matches!(self, Self::NetworkTimeService | Self::PulsePerSecond)
    }
}

impl fmt::Display for TimeSyncSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What the operating system says the state of that synchronisation is.
///
/// These are the states the platform time services actually report, which is why there is a
/// separate value for the answer never arriving. A host that cannot read its own time service
/// knows less than one whose service says it is unsynchronised, and the two are not the same fact.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum TimeSyncStatus {
    /// The clock is synchronised and no leap second is pending.
    Ok,
    /// A leap second will be inserted.
    InsertLeap,
    /// A leap second will be deleted.
    DeleteLeap,
    /// A leap second is in progress.
    LeapInProgress,
    /// The clock is recovering from a leap second.
    LeapRecovering,
    /// The platform reports its clock as unsynchronised or in error.
    Error,
    /// The platform's time service could not be read.
    Unavailable,
}

impl TimeSyncStatus {
    /// Every status, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Ok,
        Self::InsertLeap,
        Self::DeleteLeap,
        Self::LeapInProgress,
        Self::LeapRecovering,
        Self::Error,
        Self::Unavailable,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InsertLeap => "insert_leap",
            Self::DeleteLeap => "delete_leap",
            Self::LeapInProgress => "leap_in_progress",
            Self::LeapRecovering => "leap_recovering",
            Self::Error => "error",
            Self::Unavailable => "unavailable",
        }
    }

    /// Returns true when the platform reports a clock it is keeping.
    ///
    /// A pending or in-progress leap second is a second the platform is about to move, not a clock
    /// it has stopped keeping, so those states are still usable evidence; the uncertainty bound
    /// beside them is what covers the second itself.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(
            self,
            Self::Ok | Self::InsertLeap | Self::DeleteLeap | Self::LeapInProgress
        )
    }
}

impl fmt::Display for TimeSyncStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One reading of the platform time adapter.
///
/// Every field is what the operating system reported, classified into this build's vocabulary. No
/// field is a measurement of our own, and nothing here contacts a time server: section 9 requires
/// the actual supported platform service and forbids an invented universal authenticated call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TimeAdapterReading {
    /// Which platform adapter produced this reading.
    pub platform: String,
    /// The service or interface the reading came from.
    pub api: String,
    /// What the platform says is disciplining its clock.
    pub source: TimeSyncSource,
    /// What the platform says the state of that synchronisation is.
    pub status: TimeSyncStatus,
    /// The platform's own bound on how wrong its clock may be, in microseconds.
    ///
    /// Null means the platform reported no bound, which is not the same as a bound of zero.
    pub uncertainty_us: Nullable<U64>,
    /// The platform's own estimate of its error, in microseconds, when it reports one.
    pub estimated_error_us: Nullable<U64>,
    /// What the wall clock read when the reading was taken.
    pub wall_clock_ms: TimestampMs,
}

impl TimeAdapterReading {
    /// Returns true when this reading qualifies as time evidence.
    ///
    /// All three conditions are the platform's own answers: something it names is disciplining the
    /// clock, the state of that synchronisation is one it is keeping, and the bound it reports is
    /// present and tight enough for a deadline measured against it to mean something.
    #[must_use]
    pub fn is_qualified(&self) -> bool {
        self.source.is_disciplined()
            && self.status.is_usable()
            && self
                .uncertainty_us
                .as_ref()
                .is_some_and(|bound| bound.get() <= MAX_TRUSTED_UNCERTAINTY_US)
    }
}

/// Whether this host can prove what its wall clock reads.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum WallClockTrust {
    /// The checkpoint stands: the clock has not moved backwards beyond the tolerance.
    Trusted,
    /// A rollback beyond the tolerance was observed, so the wall clock proves nothing.
    Unresolved,
}

impl WallClockTrust {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Unresolved => "unresolved",
        }
    }
}

impl fmt::Display for WallClockTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A durable mark of what this host's wall clock read, and what stood behind it.
///
/// The boot identity is part of it because a continuous reading means nothing outside the boot it
/// was taken in: the clock restarts, so a deadline from another boot reads as long past rather
/// than as time remaining.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TimeCheckpoint {
    /// The boot the mark was taken in.
    pub boot_identity: BootIdentity,
    /// What the wall clock read.
    pub wall_clock_ms: TimestampMs,
    /// The boot-scoped continuous reading at the same moment.
    pub continuous_ms: U64,
    /// The platform reading that stood behind the mark.
    pub reading: TimeAdapterReading,
    /// Whether the wall clock was trusted at the mark.
    pub trust: WallClockTrust,
}

/// Why an object expired.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ExpiryReason {
    /// A continuous deadline in this boot passed.
    ContinuousDeadline,
    /// A trusted UTC deadline passed.
    TrustedUtcDeadline,
}

impl ExpiryReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContinuousDeadline => "continuous_deadline",
            Self::TrustedUtcDeadline => "trusted_utc_deadline",
        }
    }
}

impl fmt::Display for ExpiryReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The record an expired object leaves behind.
///
/// It outlives a retrust deliberately. Section 9 keeps old expiration tombstones when the wall
/// clock becomes trusted again, which is what stops a clock correction from reviving something
/// that had already run out.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpirationTombstone {
    /// The object, named the way its own store names it.
    pub object: String,
    /// Why it expired.
    pub reason: ExpiryReason,
    /// The boot the expiry was observed in.
    pub boot_identity: BootIdentity,
    /// What the wall clock read when the expiry was observed.
    pub expired_at_ms: TimestampMs,
    /// Whether the object could still be presented in another boot.
    ///
    /// An object bounded only by a continuous deadline in one boot is refused in that boot by a
    /// clock that only moves forward, and in any other boot by the boot identity its deadline
    /// belongs to. Nothing but this record refuses one that also carries a trusted UTC deadline,
    /// which is why a host that has to bound its tombstone table can let the first kind go and
    /// never the second.
    ///
    /// A record that does not say defaults to `true`, which is the answer that keeps the
    /// tombstone: a host reading back a tombstone from a build that did not record this cannot
    /// tell which kind it was, and dropping one it should have kept is the failure that matters.
    #[serde(default = "cross_reboot_unknown")]
    pub cross_reboot: bool,
}

/// The furthest point a host could prove its wall clock had reached.
///
/// It is recorded beside the continuous reading it was proved at, because that pair is what lets a
/// later observation project the mark forward. A mark from another boot keeps its wall reading and
/// loses its continuous one: the continuous clock restarted, and anchoring the projection at a
/// reading from a clock that no longer exists would add the whole of the previous uptime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenWallClock {
    /// The boot the pair was recorded in.
    pub boot_identity: BootIdentity,
    /// The furthest the wall clock was proved to have reached.
    pub wall_clock_ms: TimestampMs,
    /// The boot-scoped continuous reading it was proved at.
    pub continuous_ms: U64,
}

/// What a host writes down so a restarted one keeps the promises the running one made.
///
/// Three of the four fields exist because a restarted host cannot reconstruct them. Trust is
/// recorded separately from the checkpoint it was last renewed at: a rollback marks the clock
/// unresolved and deliberately leaves the old mark alone, so reading trust from the mark would
/// start a restarted host trusting a clock the running one had rejected. The proven reading is
/// separate for the same reason: it is the part that never moves backwards, and the checkpoint
/// beside it can. The tombstones are what stops an object that had already expired reviving.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostTimeState {
    /// The last mark taken while the wall clock was still evidence.
    pub checkpoint: Nullable<TimeCheckpoint>,
    /// What the wall clock's trust stood at when this was written.
    pub trust: WallClockTrust,
    /// Whether the owner confirmed this clock explicitly.
    ///
    /// Section 9's owner route exists for a host with no qualified evidence to be had, so what the
    /// owner restored has to survive a restart into the same absence. A host that read this back as
    /// false would undo the owner's confirmation at its first observation.
    #[serde(default)]
    pub owner_confirmed: bool,
    /// The furthest point this host could prove its wall clock had reached.
    pub proven: Nullable<ProvenWallClock>,
    /// The objects this host has already expired.
    pub tombstones: Vec<ExpirationTombstone>,
}

/// Returns what a tombstone that does not say about outliving a boot is read as.
///
/// Keeping it. A host that cannot tell whether the object has another way to be refused must not be
/// the host that drops the only thing refusing it.
const fn cross_reboot_unknown() -> bool {
    true
}

/// What is offered as grounds for returning a host's wall clock to trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RetrustEvidence {
    /// A qualified reading from the configured host time authority.
    HostTimeAuthority {
        /// The authority as the host's configuration names it.
        authority: String,
        /// The reading it produced.
        reading: TimeAdapterReading,
    },
    /// The owner's explicit authenticated retrust, bound to the exact action they confirmed.
    OwnerRetrust {
        /// The digest of the action the owner confirmed.
        action_digest: Digest256,
    },
    /// A paired peer's claim about the time. Never grounds on its own.
    PairedPeer {
        /// The peer that offered it.
        device_id: DeviceId,
    },
}

/// Why a retrust was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RetrustRefusal {
    /// The evidence came from an authority this host is not configured to trust.
    #[error("this host's configured time authority is not the one that offered the evidence")]
    NotTheConfiguredAuthority,
    /// The reading does not qualify: nothing is disciplining the clock, its state is not one the
    /// platform is keeping, or its bound is absent or too loose.
    #[error("the reading does not qualify as time evidence")]
    UnqualifiedReading,
    /// The reading is behind the furthest point this host could prove its clock had reached.
    ///
    /// Time does not go backwards, so a reading behind what is already proved is either a replay
    /// or a worse clock than the one it is offered to correct.
    #[error("the evidence reads behind what this host has already proved")]
    BehindWhatIsProved,
    /// A paired peer's clock is never a time authority.
    #[error("an ordinary paired peer's clock is not a trusted time authority")]
    PairedPeer,
    /// The evidence and this host's own clock do not agree within what either of them claims.
    ///
    /// Section 9 asks for a *new checkpoint* as well as qualified evidence, and a checkpoint is
    /// this host's own reading. Evidence that says the time is something else is evidence about
    /// another clock: what corrects this one is its own time service, and the authority's part is
    /// to confirm the correction rather than to stand in for it.
    #[error("the evidence and this host's own clock do not agree")]
    DisagreesWithThisHost,
}

impl RetrustEvidence {
    /// Decides whether this evidence may return the wall clock to trusted.
    ///
    /// Two things have to hold here, and each one is a separate way to be wrong: the evidence comes
    /// from the authority this host is *configured* to use, and the reading itself qualifies. A
    /// reading from an authority nobody configured is a stranger's claim.
    ///
    /// Freshness is deliberately **not** decided here, and not against the host's own wall clock:
    /// the whole reason for a retrust is that the host's clock is the thing in doubt, so comparing
    /// the evidence against it would refuse exactly the evidence that is needed. What a host can
    /// compare it against is the furthest point it could *prove* its clock had reached, and only
    /// the host knows that; [`crate::action`]'s caller does that check.
    ///
    /// An ordinary paired peer is not a time authority. Section 9 says so, and the reason is that
    /// a peer's clock is exactly as steppable as this host's: accepting it would let anything that
    /// can pair also decide when this host's grants expire.
    ///
    /// The owner's explicit retrust is the other route section 9 gives, and what makes it the
    /// owner's is the authenticated confirmation the caller performed before it got here. This
    /// carries the digest of that action so the two are bound together; the ceremony that produces
    /// it is section 10's.
    ///
    /// # Errors
    ///
    /// Returns the first reason the evidence does not qualify.
    pub fn qualifies_for(&self, configured_authority: &str) -> Result<(), RetrustRefusal> {
        match self {
            Self::HostTimeAuthority { authority, reading } => {
                // An empty configured name is a host with no time authority, so nothing it is
                // offered can be from one. Comparing the two would otherwise make an authority
                // that calls itself nothing the configured one.
                if configured_authority.is_empty() || authority != configured_authority {
                    return Err(RetrustRefusal::NotTheConfiguredAuthority);
                }
                if !reading.is_qualified() {
                    return Err(RetrustRefusal::UnqualifiedReading);
                }
                Ok(())
            }
            Self::OwnerRetrust { .. } => Ok(()),
            Self::PairedPeer { .. } => Err(RetrustRefusal::PairedPeer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::ParamsValue;
    use crate::ids::{ActionWindowId, RequestId};
    use crate::method::{Method, MethodVersion};
    use crate::scalars::{DurationMs, Uuid};

    fn action(byte: u8) -> ActionId {
        ActionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn observation(
        provenance: ObservationProvenance,
        claimed_result: ObservedResult,
    ) -> ActionObservation {
        ActionObservation {
            action_id: action(1),
            provenance,
            subject: "agent.approval:upstream-opaque-request-id".to_owned(),
            subject_revision: Nullable::some(U64::new(3)),
            source_cursor: Nullable::some(U64::new(4_096)),
            claimed_result,
            observed_at_ms: TimestampMs::new(1_700_000_000_000),
        }
    }

    fn mutation(method: Method, params: ParamsValue) -> MutationRequest {
        MutationRequest {
            request_id: RequestId::new(7),
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: action(9),
            grant_id: Nullable::null(),
            target: crate::envelope::ActionTarget {
                environment_id: crate::ids::EnvironmentId::new(Uuid::from_bytes([2; 16])),
                session_id: Nullable::some(crate::ids::SessionId::new(Uuid::from_bytes([3; 16]))),
                session_epoch: Nullable::some(crate::ids::SessionEpoch::new(1)),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("window-1".to_owned()).expect("a valid window"),
            requested_ttl_ms: DurationMs::new(120_000),
            params,
        }
    }

    #[test]
    fn an_inferred_screen_cannot_promote_an_uncertain_outcome() {
        let inferred = observation(
            ObservationProvenance::InferredScreen,
            ObservedResult::Applied,
        );
        assert_eq!(inferred.resolution(ReceiptState::Unknown), None);
        let reported = observation(ObservationProvenance::UserReport, ObservedResult::Applied);
        assert_eq!(reported.resolution(ReceiptState::Unknown), None);
    }

    #[test]
    fn only_an_authoritative_answer_resolves_an_uncertain_outcome() {
        let authoritative = observation(
            ObservationProvenance::AuthoritativeInterface,
            ObservedResult::Applied,
        );
        assert_eq!(
            authoritative.resolution(ReceiptState::Unknown),
            Some(ReceiptState::Applied)
        );
        let correlated = observation(
            ObservationProvenance::UpstreamCorrelation,
            ObservedResult::Refused,
        );
        assert_eq!(
            correlated.resolution(ReceiptState::Unknown),
            Some(ReceiptState::Refused)
        );
        let unsettled = observation(
            ObservationProvenance::AuthoritativeInterface,
            ObservedResult::Indeterminate,
        );
        assert_eq!(unsettled.resolution(ReceiptState::Unknown), None);
    }

    #[test]
    fn an_observation_never_moves_a_state_the_receipt_contract_has_settled() {
        let authoritative = observation(
            ObservationProvenance::AuthoritativeInterface,
            ObservedResult::Applied,
        );
        for state in ReceiptState::ALL
            .iter()
            .copied()
            .filter(|state| *state != ReceiptState::Unknown)
        {
            assert_eq!(authoritative.resolution(state), None, "{state}");
        }
    }

    #[test]
    fn a_resolution_is_always_an_edge_the_receipt_contract_permits() {
        for provenance in ObservationProvenance::ALL {
            for claimed in [
                ObservedResult::Applied,
                ObservedResult::Refused,
                ObservedResult::Indeterminate,
            ] {
                let observation = observation(*provenance, claimed);
                for state in ReceiptState::ALL.iter().copied() {
                    if let Some(next) = observation.resolution(state) {
                        assert!(
                            state.can_transition_to(next),
                            "{state} to {next} is not an edge the contract has"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_subject_digest_ignores_what_a_later_request_has_to_change() {
        let first = mutation(Method::AgentApprovalRespond, ParamsValue::empty());
        let mut later = first.clone();
        later.action_id = action(10);
        later.action_window_id =
            ActionWindowId::new("window-2".to_owned()).expect("a valid window");
        later.requested_ttl_ms = DurationMs::new(60_000);
        later.request_id = RequestId::new(8);
        // The later request keeps the preconditions the first one carried and adds the two keys
        // that show the earlier result. Only those two are outside the subject.
        let mut expected = kr_cbor::CanonicalMap::new();
        expected
            .insert(
                "approval_request_id".to_owned(),
                kr_cbor::CanonicalValue::text("upstream-opaque-request-id"),
            )
            .expect("one key");
        let mut superseding = expected.clone();
        superseding
            .insert(
                SUPERSEDES_ACTION_KEY.to_owned(),
                kr_cbor::to_canonical_value(&action(9)).expect("encodes"),
            )
            .expect("a key");
        superseding
            .insert(
                SUPERSEDES_REVISION_KEY.to_owned(),
                kr_cbor::CanonicalValue::integer(3).expect("a revision"),
            )
            .expect("a key");
        let first = MutationRequest {
            expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
            ..first
        };
        later.expected = ParamsValue::new(kr_cbor::CanonicalValue::Map(superseding));
        assert_eq!(
            subject_digest(&first).expect("a digest"),
            subject_digest(&later).expect("a digest"),
            "a later request for the same thing has the same subject"
        );
    }

    #[test]
    fn the_subject_digest_separates_two_answers_to_two_different_approvals() {
        // Section 23's own example: what makes one approval response a different subject from
        // another is the upstream request its preconditions name.
        let approval = |upstream: &str| {
            let mut expected = kr_cbor::CanonicalMap::new();
            expected
                .insert(
                    "approval_request_id".to_owned(),
                    kr_cbor::CanonicalValue::text(upstream),
                )
                .expect("one key");
            MutationRequest {
                expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
                ..mutation(Method::AgentApprovalRespond, ParamsValue::empty())
            }
        };
        assert_ne!(
            subject_digest(&approval("upstream-one")).expect("a digest"),
            subject_digest(&approval("upstream-two")).expect("a digest"),
            "an uncertain answer to one approval does not stand in another's way"
        );
    }

    #[test]
    fn the_subject_digest_is_what_a_request_asks_of_a_resource_rather_than_how_it_asks() {
        let decision = |decision: &str| {
            let mut expected = kr_cbor::CanonicalMap::new();
            expected
                .insert(
                    "approval_request_id".to_owned(),
                    kr_cbor::CanonicalValue::text("upstream-one"),
                )
                .expect("one key");
            MutationRequest {
                expected: ParamsValue::new(kr_cbor::CanonicalValue::Map(expected)),
                ..mutation(
                    Method::AgentApprovalRespond,
                    ParamsValue::from_typed(&std::collections::BTreeMap::from([(
                        "decision".to_owned(),
                        decision.to_owned(),
                    )]))
                    .expect("parameters"),
                )
            }
        };
        // Two answers to the same approval are one subject, whichever way they answer it. Section
        // 23 is about the operation: if the first answer's outcome is uncertain, the upstream
        // approval may already have been denied, and a later request to allow it has to show that
        // rather than going out as though nothing had been tried.
        assert_eq!(
            subject_digest(&decision("deny")).expect("a digest"),
            subject_digest(&decision("allow")).expect("a digest"),
        );

        // An ordinary guard is not part of what the request asks for. A subject that moved with
        // one would let any service evade the rule by adding a precondition that happens to hold.
        let mut guarded = decision("deny");
        let kr_cbor::CanonicalValue::Map(existing) = guarded.expected.as_value().clone() else {
            panic!("the preconditions are a map");
        };
        let mut with_guard = kr_cbor::CanonicalMap::new();
        for (key, value) in existing.entries() {
            with_guard
                .insert(key.clone(), value.clone())
                .expect("a key");
        }
        with_guard
            .insert(
                "session_state".to_owned(),
                kr_cbor::CanonicalValue::text("live"),
            )
            .expect("a guard");
        guarded.expected = ParamsValue::new(kr_cbor::CanonicalValue::Map(with_guard));
        assert_eq!(
            subject_digest(&decision("deny")).expect("a digest"),
            subject_digest(&guarded).expect("a digest"),
            "a guard narrows when a request may run, not what it asks for"
        );

        // What does separate two subjects is the resource. A different session is a different
        // thing being acted on.
        let mut other_session = decision("deny");
        other_session.target.session_id =
            Nullable::some(crate::ids::SessionId::new(Uuid::from_bytes([4; 16])));
        assert_ne!(
            subject_digest(&decision("deny")).expect("a digest"),
            subject_digest(&other_session).expect("a digest")
        );
    }

    #[test]
    fn one_lease_is_one_subject_whichever_attachment_asks_for_it() {
        // The input lease belongs to the session. Two attachments acquiring it are one subject,
        // so an uncertain first attempt is something the second has to show rather than something
        // a different parameter value hides.
        let acquire = |attachment: u8| {
            mutation(
                Method::InputAcquire,
                ParamsValue::from_typed(&std::collections::BTreeMap::from([(
                    "attachment_id".to_owned(),
                    format!("attachment-{attachment}"),
                )]))
                .expect("parameters"),
            )
        };
        assert_eq!(
            subject_digest(&acquire(1)).expect("a digest"),
            subject_digest(&acquire(2)).expect("a digest"),
        );
        // A resize, by contrast, acts on the attachment it names: one terminal's size is not
        // another's.
        let resize = |attachment: u8| {
            mutation(
                Method::TerminalResize,
                ParamsValue::from_typed(&std::collections::BTreeMap::from([(
                    "attachment_id".to_owned(),
                    format!("attachment-{attachment}"),
                )]))
                .expect("parameters"),
            )
        };
        assert_ne!(
            subject_digest(&resize(1)).expect("a digest"),
            subject_digest(&resize(2)).expect("a digest"),
        );
    }

    #[test]
    fn the_subject_digest_is_domain_separated_from_the_mutation_digest() {
        let request = mutation(Method::AgentApprovalRespond, ParamsValue::empty());
        let actor = ActorId::new("local:501").expect("a principal");
        assert_ne!(
            subject_digest(&request).expect("a digest").as_bytes(),
            crate::digest::mutation_digest(&request, &actor)
                .expect("a digest")
                .as_bytes()
        );
        assert_ne!(SUBJECT_DOMAIN, crate::digest::MUTATION_DOMAIN);
    }

    #[test]
    fn a_barrier_holds_only_when_every_worker_acknowledged_or_ended() {
        let session = |byte: u8| SessionId::new(Uuid::from_bytes([byte; 16]));
        let worker = |byte: u8, state: BarrierState| WorkerBarrier {
            session_id: session(byte),
            state,
            acknowledged_revision: Nullable::null(),
            rejected_actions: Vec::new(),
            possibly_executed: Vec::new(),
            omitted_actions: U64::new(0),
            names_pending: U64::new(0),
            detail: String::new(),
        };
        let mut barrier = RevocationBarrier {
            authority_revision: AuthorityRevision::new(4),
            workers: vec![
                worker(1, BarrierState::Acknowledged),
                worker(2, BarrierState::Ended),
            ],
        };
        assert!(barrier.holds());
        assert!(barrier.pending().is_empty());
        barrier.workers.push(worker(3, BarrierState::Pending));
        assert!(!barrier.holds());
        assert_eq!(barrier.pending(), vec![session(3)]);
    }

    #[test]
    fn a_barrier_names_every_action_it_could_not_take_back() {
        let barrier = RevocationBarrier {
            authority_revision: AuthorityRevision::new(4),
            workers: vec![WorkerBarrier {
                session_id: SessionId::new(Uuid::from_bytes([1; 16])),
                state: BarrierState::Acknowledged,
                acknowledged_revision: Nullable::some(AuthorityRevision::new(4)),
                rejected_actions: vec![FencedAction {
                    actor_id: ActorId::new("device:phone").expect("a principal"),
                    action_id: action(1),
                }],
                possibly_executed: vec![PossiblyExecutedAction {
                    action_id: action(2),
                    actor_id: ActorId::new("device:phone").expect("a principal"),
                    method: Method::AgentApprovalRespond.into(),
                    state: ReceiptState::Unknown,
                }],
                omitted_actions: U64::new(0),
                names_pending: U64::new(0),
                detail: String::new(),
            }],
        };
        assert!(
            barrier.holds(),
            "the barrier holds and still names the action"
        );
        let named = barrier.possibly_executed();
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].action_id, action(2));
    }

    const CONFIGURED: &str = "time.example";
    const NOW: TimestampMs = TimestampMs::new(1_700_000_000_000);

    #[test]
    fn a_paired_peer_is_never_a_time_authority() {
        let peer = RetrustEvidence::PairedPeer {
            device_id: DeviceId::new(Uuid::from_bytes([5; 16])),
        };
        assert_eq!(
            peer.qualifies_for(CONFIGURED),
            Err(RetrustRefusal::PairedPeer)
        );
    }

    #[test]
    fn evidence_from_an_authority_this_host_did_not_configure_is_a_strangers_claim() {
        let stranger = RetrustEvidence::HostTimeAuthority {
            authority: "time.somebody-else".to_owned(),
            reading: TimeAdapterReading {
                platform: "macos".to_owned(),
                api: "ntp_gettime(3)".to_owned(),
                source: TimeSyncSource::NetworkTimeService,
                status: TimeSyncStatus::Ok,
                uncertainty_us: Nullable::some(U64::new(1_000)),
                estimated_error_us: Nullable::null(),
                wall_clock_ms: NOW,
            },
        };
        assert_eq!(
            stranger.qualifies_for(CONFIGURED),
            Err(RetrustRefusal::NotTheConfiguredAuthority)
        );
    }

    #[test]
    fn host_time_authority_evidence_qualifies_only_when_the_reading_does() {
        let reading = |source: TimeSyncSource, status: TimeSyncStatus, bound: Option<u64>| {
            TimeAdapterReading {
                platform: "macos".to_owned(),
                api: "ntp_gettime(3)".to_owned(),
                source,
                status,
                uncertainty_us: Nullable(bound.map(U64::new)),
                estimated_error_us: Nullable::null(),
                wall_clock_ms: NOW,
            }
        };
        let qualified = RetrustEvidence::HostTimeAuthority {
            authority: CONFIGURED.to_owned(),
            reading: reading(
                TimeSyncSource::NetworkTimeService,
                TimeSyncStatus::Ok,
                Some(62_192),
            ),
        };
        assert_eq!(qualified.qualifies_for(CONFIGURED), Ok(()));
        for unqualified in [
            reading(TimeSyncSource::Unsynchronised, TimeSyncStatus::Ok, Some(10)),
            reading(
                TimeSyncSource::NetworkTimeService,
                TimeSyncStatus::Error,
                Some(10),
            ),
            reading(
                TimeSyncSource::NetworkTimeService,
                TimeSyncStatus::Unavailable,
                Some(10),
            ),
            reading(TimeSyncSource::NetworkTimeService, TimeSyncStatus::Ok, None),
            reading(
                TimeSyncSource::NetworkTimeService,
                TimeSyncStatus::Ok,
                Some(MAX_TRUSTED_UNCERTAINTY_US + 1),
            ),
        ] {
            assert_eq!(
                RetrustEvidence::HostTimeAuthority {
                    authority: CONFIGURED.to_owned(),
                    reading: unqualified.clone(),
                }
                .qualifies_for(CONFIGURED),
                Err(RetrustRefusal::UnqualifiedReading),
                "{unqualified:?}"
            );
        }
    }

    #[test]
    fn the_owner_can_retrust_explicitly() {
        let owner = RetrustEvidence::OwnerRetrust {
            action_digest: Digest256::from_bytes([7; 32]),
        };
        assert_eq!(owner.qualifies_for(CONFIGURED), Ok(()));
    }

    #[test]
    fn the_rollback_tolerance_and_the_uncertainty_bound_are_what_section_nine_states() {
        assert_eq!(MAX_WALL_CLOCK_ROLLBACK_MS, 5_000);
        // A qualified reading is tighter than the rollback this host would notice anyway, which is
        // what makes it better evidence than the absence of an observed rollback.
        const { assert!(MAX_TRUSTED_UNCERTAINTY_US < MAX_WALL_CLOCK_ROLLBACK_MS * 1_000) };
    }
}
