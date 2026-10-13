//! Sharing a session from this application: the four actions that change who holds one, and how
//! this application keeps its word about each.
//!
//! Inviting a device, accepting an invitation, taking a share back and handing a session's control
//! to another device are each one mutation, and the answer to one can be lost: the connection
//! ends, the application stops, the host answers "has not finished". The host performs an action at
//! most once and keeps its answer, so what this application owes the person is the truth about
//! what became of it. The rules are the client library's ([`kr_client::attempt`]); what is here is
//! the connection they run over, the place the attempts are kept, and what the page is told.
//!
//! * **The record comes first.** The request is composed and kept, with the host and the standing
//!   it is for, before anything is sent. A restart between any two steps still has it.
//! * **A repeat is a question.** The host answers it from the record it kept, on a connection
//!   opened for it, and never as a first admission.
//! * **Absence proves nothing until nothing more can happen.** A read of the host that finds
//!   nothing counts only after the bound the window sets, measured on a clock that cannot be
//!   stepped; after a restart the whole bound runs again.
//!
//! An attempt the host answers at once is over before the command returns. One whose answer is lost
//! goes on in a task of its own, and the page reads where it stands from [`attempts`]. A hand-over
//! starts earlier: an owner device is asked to confirm the plan, and only a confirmed plan is sent.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_client::attempt::{
    Armed, Attempt, AttemptStore, Found, Gate, Kept, Kind, Next, Outcome, Phase, REPEAT_DELAYS,
    REPEATS, ReadAt, Reply,
};
use kr_client::session::ComposedMutation;
use kr_client::{ClientError, Settled};
use kr_protocol::confirmation::{
    ConfirmationSubject, OwnerConfirmationPendingParams, OwnerConfirmationPendingResult,
    OwnerConfirmationRequestParams, OwnerConfirmationRequestResult, TransferControlPlan,
    TransferControlSubject,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, DeviceId, EnvironmentId, GrantId, InvitationId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::pairing::OwnerConfirmationRequest;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::sharing::{
    DeviceListParams, DeviceListResult, GrantCreateParams, GrantCreateResult, GrantHeldParams,
    GrantHeldResult, GrantListParams, GrantListResult, GrantRedeemParams, GrantRedeemResult,
    GrantRevokeParams, GrantTransferParams, GrantTransferResult, HeldShare, OfferKey,
    RevocationResult, RoleSelection, SessionScreenPreviewParams, SessionScreenPreviewResult,
    ShareKey, ShareOffer, share_identities, transfer_identity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent::WorkerLinks;
use crate::commands::{MUTATION_TTL, NoPreconditions};
use crate::connection::{Connection, Standing};
use crate::error::{CommandError, Result};
use crate::state::AppState;
use crate::target::Subject;

/// The place the attempts are kept under an application data directory.
#[must_use]
pub fn kept_in(data: &Path) -> PathBuf {
    data.join("kept-attempts")
}

/// How long a state check waits before it reads the host again.
const CHECK_EVERY: Duration = Duration::from_secs(5);

/// The most pages one read of what a device holds follows, in each of its lists.
const MAX_HELD_PAGES: usize = 64;

/// The waits between the steps of an attempt, which a test sets to nothing.
#[derive(Clone, Copy, Debug)]
pub struct Pace {
    /// How long to wait before each repeat of a request whose answer was lost.
    pub repeats: [Duration; REPEATS],
    /// How long to wait before the host's state is read again.
    pub check_every: Duration,
}

impl Default for Pace {
    fn default() -> Self {
        Self {
            repeats: REPEAT_DELAYS,
            check_every: CHECK_EVERY,
        }
    }
}

/// What this process knows of an attempt that its record does not.
struct Running {
    /// When this process began to count the attempt's bound.
    armed: Armed,
    /// What the host said when it refused the request, or when it could not say what became of it,
    /// in its words.
    refusal: Option<String>,
    /// Whether a task of this process is carrying the attempt on.
    driving: bool,
}

/// A hand-over between the owner device's confirmation being asked for and the transfer being sent.
#[derive(Clone)]
struct Handover {
    /// The action the transfer will be sent under, which is also the attempt's name.
    action_id: ActionId,
    /// What the page asked for.
    params: GrantTransferParams,
    /// The target the transfer is sent to: the session at its epoch.
    target: ActionTarget,
    /// The challenge the owner device answers.
    challenge: OwnerConfirmationRequest,
    /// When this process had the challenge, which its lifetime is counted from.
    received: Armed,
    /// The plan the host described, once it was seen.
    plan: Option<TransferControlPlan>,
    /// The connection the confirmation was asked on, and so the host and standing it is for.
    environment_id: EnvironmentId,
}

/// The attempts this application keeps, and what it is carrying on.
#[derive(Default)]
pub struct ShareDesk {
    root: Mutex<Option<PathBuf>>,
    pace: Mutex<Option<Pace>>,
    /// Time a test has added to the clock that counts an attempt's bound.
    #[cfg(feature = "testing")]
    skew: Mutex<Duration>,
    running: Mutex<HashMap<ActionId, Running>>,
    /// The hand-overs being asked about, by the reference the page holds. A hand-over leaves this
    /// table once, either abandoned or committed to a send ([`ShareDesk::commit`]); whoever takes it
    /// owns its record, and the lock these two share is what orders them.
    handovers: Mutex<HashMap<String, Handover>>,
    /// Held while a record is read and written back, so that what a person did to an attempt and
    /// what a task carrying it on learned are never written over one another.
    records: Mutex<()>,
    /// What the host answered to an attempt that was carried on after the command that sent it
    /// returned, kept until the page has read it and removed the attempt. A restart loses it, and
    /// the host's record of the action still has it ([`ask_the_host`]).
    results: Mutex<HashMap<ActionId, Value>>,
}

impl std::fmt::Debug for ShareDesk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ShareDesk { .. }")
    }
}

impl ShareDesk {
    /// Names the directory the attempts are kept in.
    pub fn keep_at(&self, root: PathBuf) {
        *self.root.lock().unwrap_or_else(PoisonError::into_inner) = Some(root);
    }

    /// Sets the waits between the steps of an attempt. A test sets them to nothing.
    pub fn pace_at(&self, pace: Pace) {
        *self.pace.lock().unwrap_or_else(PoisonError::into_inner) = Some(pace);
    }

    /// Makes the clock that counts an attempt's bound read `by` later than it does. A test uses
    /// it to pass a bound it cannot wait out; a shipped build has no such thing, since time added
    /// makes a read count sooner than it should.
    #[cfg(feature = "testing")]
    pub fn advance(&self, by: Duration) {
        let mut skew = self.skew.lock().unwrap_or_else(PoisonError::into_inner);
        *skew = skew.saturating_add(by);
    }

    fn pace(&self) -> Pace {
        self.pace
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unwrap_or_default()
    }

    fn store(&self, environment_id: EnvironmentId) -> Result<AttemptStore> {
        let root = self
            .root
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                CommandError::unsupported(
                    "sharing cannot be kept on this device: it has no place for its records",
                )
            })?;
        AttemptStore::open(root.join(environment_id.to_string())).map_err(failed_store)
    }

    /// Begins to count an attempt's bound, unless it is being counted already.
    fn arm(&self, action_id: ActionId) {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(action_id)
            .or_insert_with(|| Running {
                armed: Armed::now(),
                refusal: None,
                driving: false,
            });
    }

    /// The clock that counts an attempt's bound, on the test's skew when it set one.
    fn clock(&self, action_id: ActionId) -> Armed {
        self.arm(action_id);
        let armed = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&action_id)
            .map_or_else(Armed::now, |running| running.armed);
        #[cfg(feature = "testing")]
        let armed = armed.skewed(*self.skew.lock().unwrap_or_else(PoisonError::into_inner));
        armed
    }

    /// How long ago the attempt's bound began to be counted.
    fn elapsed(&self, action_id: ActionId) -> Duration {
        self.clock(action_id).elapsed()
    }

    /// Starts counting an attempt's bound afresh, now: a hand-over's clock counts from the moment
    /// the transfer is composed, since the bound is shortened by what its challenge had left then.
    fn rearm(&self, action_id: ActionId) {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                action_id,
                Running {
                    armed: Armed::now(),
                    refusal: None,
                    driving: false,
                },
            );
    }

    /// The moment a read of the host is about to be sent, on the clock that counts the attempt's
    /// bound (and on the test's skew, when it set one).
    fn read_begins(&self, action_id: ActionId) -> ReadAt {
        self.clock(action_id).read_begins()
    }

    /// Takes the right to carry an attempt on. False when a task of this process has it.
    fn take(&self, action_id: ActionId) -> bool {
        self.arm(action_id);
        let mut running = self.running.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(held) = running.get_mut(&action_id) else {
            return false;
        };
        if held.driving {
            return false;
        }
        held.driving = true;
        true
    }

    fn release(&self, action_id: ActionId) {
        if let Some(held) = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&action_id)
        {
            held.driving = false;
        }
    }

    fn forget(&self, action_id: ActionId) {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&action_id);
    }

    fn note_refusal(&self, action_id: ActionId, refusal: &ProtocolError) {
        self.arm(action_id);
        if let Some(held) = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&action_id)
        {
            held.refusal = Some(refusal.message.clone());
        }
    }

    fn refusal(&self, action_id: ActionId) -> Option<String> {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&action_id)
            .and_then(|running| running.refusal.clone())
    }

    fn view(&self, attempt: &Attempt) -> AttemptView {
        let remaining = attempt
            .bound()
            .saturating_sub(self.elapsed(attempt.action_id));
        let mut view = AttemptView::of(
            attempt,
            self.refusal(attempt.action_id),
            kr_ipc::now_ms().get(),
            remaining,
        );
        view.result = self
            .results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&attempt.action_id)
            .cloned();
        view
    }

    fn keep_result(&self, action_id: ActionId, result: Value) {
        self.results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(action_id, result);
    }

    fn drop_result(&self, action_id: ActionId) {
        self.results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&action_id);
    }

    /// Writes what a task learned of an attempt.
    ///
    /// Whether the person hid the attempt is theirs and not the task's, and the task holds an
    /// earlier copy of the record: so it is carried forward from the record as it is now, never
    /// from the copy. An attempt that is over is written unhidden, since its end is what the
    /// person is owed.
    fn save(&self, store: &AttemptStore, attempt: &Attempt) -> Result<()> {
        let _writing = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let mut next = attempt.clone();
        next.hidden =
            !next.is_closed() && find(store, next.action_id)?.is_some_and(|stored| stored.hidden);
        store.keep(&next).map_err(failed_store)
    }

    /// Removes the record of an attempt. Like every other write of a record it is made under the
    /// records lock, so a Hide that read the record before it went cannot write it back after.
    fn drop_record(&self, store: &AttemptStore, action_id: ActionId) -> Result<()> {
        let _writing = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        store.remove(action_id).map_err(failed_store)
    }

    /// Hides an attempt or shows it again, leaving everything else in its record as it is.
    fn set_hidden(
        &self,
        store: &AttemptStore,
        action_id: ActionId,
        hidden: bool,
    ) -> Result<Attempt> {
        let _writing = self.records.lock().unwrap_or_else(PoisonError::into_inner);
        let mut attempt = find(store, action_id)?
            .ok_or_else(|| CommandError::invalid("no such attempt is kept"))?;
        if hidden && attempt.phase == Phase::Asking {
            return Err(CommandError::invalid(
                "a hand-over still being confirmed is cancelled, not hidden",
            ));
        }
        if hidden && attempt.is_closed() {
            return Err(CommandError::invalid(
                "an attempt that is over is removed, not hidden",
            ));
        }
        attempt.hidden = hidden;
        store.keep(&attempt).map_err(failed_store)?;
        Ok(attempt)
    }

    /// What the hand-over a reference names stands at, while it is still being asked about.
    fn handover(&self, reference: &str) -> Result<Handover> {
        self.handovers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(reference)
            .cloned()
            .ok_or_else(not_asking_about)
    }

    /// Takes a hand-over out of the table to be sent, in one step with `write`, which keeps the
    /// record that says so. Nothing else can take it meanwhile: an abandon that comes after finds
    /// it gone, and one that came before took it, so `write` is not run.
    fn commit(
        &self,
        reference: &str,
        write: impl FnOnce(&Handover) -> Result<()>,
    ) -> Result<Handover> {
        let mut held = self
            .handovers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let handover = held.get(reference).ok_or_else(not_asking_about)?;
        write(handover)?;
        held.remove(reference).ok_or_else(|| {
            CommandError::local_failure("the hand-over left the table while it was being kept")
        })
    }

    /// Takes a hand-over out of the table without sending it, and removes the record that held its
    /// place, in one step. False when it is no longer in the table: a send took it, or another
    /// abandon did, and whoever took it owns the record.
    fn abandon(&self, reference: &str) -> Result<bool> {
        let mut held = self
            .handovers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let Some(handover) = held.get(reference) else {
            return Ok(false);
        };
        let action_id = handover.action_id;
        let store = self.store(handover.environment_id)?;
        self.drop_record(&store, action_id)?;
        held.remove(reference);
        drop(held);
        self.forget(action_id);
        Ok(true)
    }

    /// Removes the record of a hand-over that is still being confirmed, and its place in the table
    /// when this process has it. The record is looked at again under the table's lock: a send that
    /// committed since the caller looked has changed it, and what is being sent is never removed.
    fn withdraw_asking(&self, store: &AttemptStore, action_id: ActionId) -> Result<()> {
        let mut held = self
            .handovers
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match find(store, action_id)? {
            Some(attempt) if attempt.phase == Phase::Asking => {}
            Some(_) => {
                return Err(CommandError::refused(
                    "that can still happen, so its record stays until it is over",
                ));
            }
            None => return Ok(()),
        }
        self.drop_record(store, action_id)?;
        held.retain(|_, handover| handover.action_id != action_id);
        drop(held);
        self.forget(action_id);
        Ok(())
    }
}

/// What a reference that names no hand-over this application is asking about is told: one that was
/// cancelled, ended, or sent.
fn not_asking_about() -> CommandError {
    CommandError::invalid("that hand-over is not one this application is asking about")
}

/// The record kept for an action, when there is one this build reads.
fn find(store: &AttemptStore, action_id: ActionId) -> Result<Option<Attempt>> {
    Ok(store
        .attempts()
        .map_err(failed_store)?
        .into_iter()
        .find_map(|kept| match kept {
            Kept::Known(attempt) if attempt.action_id == action_id => Some(*attempt),
            _ => None,
        }))
}

fn failed_store(error: kr_client::attempt::AttemptError) -> CommandError {
    CommandError::local_failure(format!(
        "the records of sharing on this device could not be used: {error}"
    ))
}

// ---------------------------------------------------------------------------------------------
// What the page is told
// ---------------------------------------------------------------------------------------------

/// One attempt, as the page reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AttemptView {
    /// The action, which names the attempt.
    pub action_id: String,
    /// What it does.
    pub kind: Kind,
    /// Where it stands: `asking`, `composed`, `unfinished`, `checking` or `closed`.
    pub phase: &'static str,
    /// How it ended, once it has.
    pub outcome: Option<Outcome>,
    /// One line that says what it was.
    pub label: String,
    /// Whether the person hid it. Hiding releases nothing, and an attempt that is over is shown.
    pub hidden: bool,
    /// Whether it closed with something still owed to the person that the host's result carries
    /// (the screen the host kept with a live invitation, how far the workers have got with a
    /// revocation), and the host can be asked for it until the page removes the record.
    pub follow_up: bool,
    /// The session it is about, when it names one.
    pub session_id: Option<String>,
    /// The device it is about: the one invited, or the one that receives control.
    pub device_id: Option<String>,
    /// The grant it writes, revokes or accepts.
    pub grant_id: Option<String>,
    /// The grant it takes away: the one a revocation names, the one a hand-over gives up.
    pub revoked_grant_id: Option<String>,
    /// When it was composed, by this computer's clock. For display only.
    pub composed_at_ms: TimestampMs,
    /// The earliest moment by this computer's clock at which a read of the host that finds nothing
    /// can close it, while it can still happen. Null once it is over, and once that moment has
    /// passed without a read the host answered: the attempt can then be asked about, and nothing
    /// says until when it might still happen.
    pub can_happen_until_ms: Option<TimestampMs>,
    /// How many times the host has been asked again.
    pub repeats: u8,
    /// What the host said when it refused, or when it could not say what became of the request, in
    /// its words, while that is known.
    pub refusal: Option<String>,
    /// The host's result, in the method's own shape, for an attempt that was carried on after the
    /// command that sent it returned and ended with the result. Null once the page has removed the
    /// attempt, and after a restart; the host's record still has it.
    pub result: Option<Value>,
}

impl AttemptView {
    fn of(attempt: &Attempt, refusal: Option<String>, now_ms: u64, remaining: Duration) -> Self {
        let (phase, outcome) = match attempt.phase {
            Phase::Asking => ("asking", None),
            Phase::Composed => ("composed", None),
            Phase::Unfinished => ("unfinished", None),
            Phase::Checking => ("checking", None),
            Phase::Closed(outcome) => ("closed", Some(outcome)),
        };
        let about = About::of(attempt);
        Self {
            action_id: attempt.action_id.to_string(),
            kind: attempt.kind,
            phase,
            outcome,
            label: attempt.label.clone(),
            hidden: attempt.hidden,
            follow_up: attempt.follow_up,
            session_id: about.session.map(|session| session.to_string()),
            device_id: about.device.map(|device| device.to_string()),
            grant_id: attempt.grant_id.0.map(|grant| grant.to_string()),
            revoked_grant_id: about.revokes.map(|grant| grant.to_string()),
            composed_at_ms: attempt.composed_at_ms,
            can_happen_until_ms: (!attempt.is_closed() && !remaining.is_zero()).then(|| {
                TimestampMs::new(
                    now_ms.saturating_add(u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX)),
                )
            }),
            repeats: attempt.repeats,
            refusal,
            result: None,
        }
    }
}

/// What an attempt is about, read from the request it keeps.
struct About {
    session: Option<SessionId>,
    device: Option<DeviceId>,
    revokes: Option<GrantId>,
}

impl About {
    fn of(attempt: &Attempt) -> Self {
        let params = &attempt.request.params;
        let method = &attempt.request.method;
        if *method == Method::GrantCreate.into() {
            if let Ok(invited) = params.to_typed::<GrantCreateParams>() {
                return Self {
                    session: Some(invited.session_id),
                    device: Some(invited.recipient_device_id),
                    revokes: None,
                };
            }
        } else if *method == Method::GrantRevoke.into() {
            if let Ok(revoked) = params.to_typed::<GrantRevokeParams>() {
                return Self {
                    session: None,
                    device: None,
                    revokes: Some(revoked.grant_id),
                };
            }
        } else if *method == Method::GrantTransfer.into() {
            if let Ok(handed) = params.to_typed::<GrantTransferParams>() {
                return Self::handing(&handed);
            }
        } else if *method == Method::OwnerConfirmationRequest.into()
            && let Ok(asked) = params.to_typed::<OwnerConfirmationRequestParams>()
            && let ConfirmationSubject::TransferControl(subject) = asked.subject
        {
            return Self::handing(&subject.params);
        }
        Self {
            session: None,
            device: None,
            revokes: None,
        }
    }

    fn handing(handed: &GrantTransferParams) -> Self {
        Self {
            session: Some(handed.session_id),
            device: Some(handed.to_device_id),
            revokes: Some(handed.from_grant_id),
        }
    }
}

/// What a command that sends one of the four actions answers with.
#[derive(Debug, Serialize)]
pub struct Attempted {
    /// Where the attempt stands.
    pub attempt: AttemptView,
    /// The host's result, in the method's own shape, when the host gave it.
    pub value: Option<Value>,
}

/// The attempts kept for the host this application is connected to.
#[derive(Debug, Serialize)]
pub struct Attempts {
    /// The attempts, oldest first.
    pub attempts: Vec<AttemptView>,
    /// How many files in the store this build does not read: of a later release, or not an
    /// attempt. They are never sent, changed or removed.
    pub unreadable: usize,
}

// ---------------------------------------------------------------------------------------------
// What a connection is for
// ---------------------------------------------------------------------------------------------

/// A connection that issues shares: the host on this machine, over its own socket.
fn issuing(state: &AppState) -> Result<Connection> {
    let connection = state.connection()?;
    match connection.standing() {
        Standing::Owner => Ok(connection),
        Standing::Paired { .. } => Err(CommandError::refused(
            "a share is issued on the machine that runs the host; this application is connected \
             to a host it is paired with",
        )),
    }
}

/// A connection that holds shares: a device paired with the host.
fn holding(state: &AppState) -> Result<Connection> {
    let connection = state.connection()?;
    match connection.standing() {
        Standing::Paired { .. } => Ok(connection),
        Standing::Owner => Err(CommandError::refused(
            "this application is the owner of the host it is connected to; it holds no share of it",
        )),
    }
}

fn host_refusal(error: &ClientError) -> Option<&ProtocolError> {
    match error {
        ClientError::Host(refusal)
        | ClientError::Refused { error: refusal, .. }
        | ClientError::OutcomeUnknown { error: refusal, .. } => Some(refusal),
        _ => None,
    }
}

fn decoded<R: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> Result<R> {
    value.to_typed().map_err(|error| {
        CommandError::local_failure(format!(
            "the host's answer was not the method's own result: {error}"
        ))
    })
}

async fn read<P, R>(connection: &Connection, method: Method, params: &P) -> Result<R>
where
    P: Serialize + ?Sized,
    R: kr_protocol::wire::WireMessage,
{
    Ok(connection.session().read(method, params).await?)
}

async fn devices(connection: &Connection) -> Result<DeviceListResult> {
    read(
        connection,
        Method::DeviceList,
        &DeviceListParams {
            include_revoked: true,
        },
    )
    .await
}

fn device_name(listed: &DeviceListResult, device_id: DeviceId) -> String {
    listed
        .devices
        .iter()
        .find(|device| device.device_id == device_id)
        .map_or_else(|| "a paired device".to_owned(), |d| d.display_name.clone())
}

// ---------------------------------------------------------------------------------------------
// Reading a screen
// ---------------------------------------------------------------------------------------------

/// The page's request for a preview: the session, and the selection the invitation would carry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewParams {
    /// The session whose screen is read.
    pub session_id: SessionId,
    /// The choices the invitation would carry, which decide how much history the preview is cut
    /// to.
    pub selection: RoleSelection,
}

/// Reads the lines on a session's screen, as an invitation that includes the live view would carry
/// them.
///
/// # Errors
///
/// Refuses on a host this device is paired with (the worker is on the machine that runs the
/// session), and returns the worker's own refusal.
pub async fn preview(
    state: &AppState,
    links: &WorkerLinks,
    params: PreviewParams,
) -> Result<SessionScreenPreviewResult> {
    issuing(state)?;
    let typed = SessionScreenPreviewParams {
        session_id: params.session_id,
        history: params.selection.history(),
    };
    links
        .read(
            state,
            params.session_id,
            None,
            Method::SessionScreenPreview,
            &typed,
        )
        .await
}

// ---------------------------------------------------------------------------------------------
// Sending one action and carrying it on
// ---------------------------------------------------------------------------------------------

/// What the host said to a request, kept while the attempt goes on.
#[derive(Default)]
struct Said {
    result: Option<ParamsValue>,
    refusal: Option<ProtocolError>,
}

impl Said {
    fn take(&mut self, outcome: &std::result::Result<Settled, ClientError>) {
        match outcome {
            Ok(Settled::Result(value)) => self.result = Some(value.clone()),
            Err(error) => {
                if let Some(refusal) = host_refusal(error)
                    && self.refusal.is_none()
                {
                    self.refusal = Some(refusal.clone());
                }
            }
            Ok(Settled::Receipt(_)) => {}
        }
    }
}

/// Whether a connection reaches the host, and acts as the actor, an attempt was composed for: a
/// repeat to another host, or as another actor, finds no record and is not made.
fn belongs_to(connection: &Connection, attempt: &Attempt) -> bool {
    let reach = connection.session().reach();
    reach.is_some() && reach == attempt.reach()
}

/// Everything one attempt needs to be carried on, in this process or after a restart.
struct Carry {
    desk: Arc<ShareDesk>,
    connection: Connection,
    store: AttemptStore,
}

impl Carry {
    fn keep(&self, attempt: &Attempt) -> Result<()> {
        self.desk.save(&self.store, attempt)
    }

    /// Sends a composed request for the first time and does what its first answer settles.
    ///
    /// An answer that closes the attempt closes it here. Anything else goes on in a task of its
    /// own, and the page reads where it stands.
    async fn begin(
        self: Arc<Self>,
        mut attempt: Attempt,
        composed: ComposedMutation,
    ) -> Result<Attempted> {
        let action_id = attempt.action_id;
        let sent_action = attempt.request.action_id;
        self.desk.arm(action_id);
        let taken = self.desk.take(action_id);
        debug_assert!(taken, "a new attempt is carried by one task");
        let outcome = self.connection.session().send(&composed).await;
        let mut said = Said::default();
        said.take(&outcome);
        if let Some(refusal) = &said.refusal {
            self.desk.note_refusal(action_id, refusal);
        }
        let next = attempt.after_first_send(Reply::of(&outcome));
        match next {
            Next::NotSent => {
                // Nothing left this computer, so nothing is owed and nothing is kept.
                self.finish_record(&attempt, sent_action).await;
                return Err(match outcome {
                    Err(error) => CommandError::from(error),
                    Ok(_) => CommandError::local_failure("the request was not sent"),
                });
            }
            Next::Closed(Outcome::Refused) => {
                self.finish_record(&attempt, sent_action).await;
                let refusal = said.refusal.map_or_else(
                    || CommandError::local_failure("the host refused the request"),
                    CommandError::from,
                );
                return Err(refusal);
            }
            Next::Closed(Outcome::Happened) => {
                self.finish_record(&attempt, sent_action).await;
                let view = self.desk.view(&attempt);
                return Ok(Attempted {
                    attempt: view,
                    value: Some(self.result_json(attempt.kind, said.result.as_ref())?),
                });
            }
            Next::Closed(_) | Next::Repeat | Next::Check | Next::Wait => {}
        }
        // The first answer was lost, or is not one that closes it: the record says so before
        // anything else happens.
        if let Err(error) = self.keep(&attempt) {
            self.desk.release(action_id);
            return Err(error);
        }
        let view = self.desk.view(&attempt);
        let task = Arc::clone(&self);
        tauri::async_runtime::spawn(async move {
            task.carry_on(attempt, composed, next, said).await;
        });
        Ok(Attempted {
            attempt: view,
            value: None,
        })
    }

    /// Carries an attempt that is not over on until it is, in a task of its own.
    async fn carry_on(
        self: Arc<Self>,
        mut attempt: Attempt,
        composed: ComposedMutation,
        mut next: Next,
        mut said: Said,
    ) {
        let action_id = attempt.action_id;
        let sent_action = attempt.request.action_id;
        let pace = self.desk.pace();
        let mut reading: Option<Connection> = None;
        loop {
            match next {
                Next::Closed(_) => break,
                Next::NotSent => break,
                Next::Repeat => {
                    let wait = pace.repeats[usize::from(attempt.repeats).min(REPEATS - 1)];
                    tokio::time::sleep(wait).await;
                    let reply = self.repeat_once(&attempt, &composed, &mut said).await;
                    next = attempt.after_repeat(reply);
                    // The host's result is kept for the page before the record says the attempt is
                    // over, so a page that sees the one finds the other.
                    if matches!(next, Next::Closed(Outcome::Happened))
                        && let Some(result) = said.result.as_ref()
                        && let Ok(json) = self.result_json(attempt.kind, Some(result))
                    {
                        self.desk.keep_result(action_id, json);
                    }
                }
                Next::Check | Next::Wait => {
                    tokio::time::sleep(pace.check_every).await;
                    let found = self.found(&attempt, &mut reading).await;
                    next = match found {
                        Some((found, began)) => attempt.after_read(found, began),
                        // A read that fails leaves the attempt as it was.
                        None => Next::Wait,
                    };
                }
            }
            if let Phase::Closed(outcome) = attempt.phase {
                // The record that says the attempt is over also says what is still owed, so a
                // page that reads the end finds both, and no later write can bring back a record
                // the page has removed.
                attempt.follow_up = outcome == Outcome::Happened && owes(&attempt);
            }
            if let Err(error) = self.keep(&attempt) {
                tracing::warn!(%error, "the state of an attempt could not be kept");
            }
        }
        if let Some(reading) = reading {
            reading.session().close();
        }
        // Letting the clock go also lets go of the right to carry the attempt on: a task that took
        // that right since is not one this end can release.
        self.conclude(&attempt, sent_action).await;
    }

    /// One exact repeat of a request, on a connection opened for it.
    async fn repeat_once(
        &self,
        attempt: &Attempt,
        composed: &ComposedMutation,
        said: &mut Said,
    ) -> Reply {
        if !belongs_to(&self.connection, attempt) {
            return Reply::NotSent;
        }
        let Ok(second) = self.connection.another().await else {
            return Reply::Lost;
        };
        let outcome = second.session().repeat(composed).await;
        said.take(&outcome);
        if let Some(refusal) = &said.refusal {
            self.desk.note_refusal(attempt.action_id, refusal);
        }
        second.session().settle(composed.action_id()).await;
        second.session().close();
        Reply::of(&outcome)
    }

    /// Reads what the host shows of the grant an attempt is about, and when the read began, or none
    /// when it could not be read.
    ///
    /// The moment is taken just before the first request of the read is sent, so what the read
    /// found is judged by when it began and not by when its answer arrived.
    async fn found(
        &self,
        attempt: &Attempt,
        reading: &mut Option<Connection>,
    ) -> Option<(Found, ReadAt)> {
        if reading.is_none() {
            *reading = self.connection.another().await.ok();
        }
        let connection = reading.as_ref()?;
        let grant_id = attempt.grant_id.0?;
        let began = self.desk.read_begins(attempt.action_id);
        let found = match attempt.kind {
            Kind::Invite | Kind::Transfer | Kind::Revoke => {
                let about = About::of(attempt);
                let listed: Result<GrantListResult> = read(
                    connection,
                    Method::GrantList,
                    &GrantListParams {
                        session_id: Nullable(about.session),
                        include_resolved: true,
                    },
                )
                .await;
                let Ok(listed) = listed else {
                    // The connection may be the reason; the next read opens another.
                    *reading = None;
                    return None;
                };
                let entry = listed
                    .grants
                    .iter()
                    .find(|summary| summary.grant.grant_id == grant_id);
                match (attempt.kind, entry) {
                    (Kind::Revoke, Some(summary)) => {
                        Found::Grant(summary.state, summary.revoked_at_ms.is_present())
                    }
                    (Kind::Revoke, None) => Found::Gone,
                    (_, Some(_)) => Found::Present,
                    (_, None) => Found::Absent,
                }
            }
            Kind::Redeem => {
                let Ok((offers, shares)) = held_all(connection).await else {
                    *reading = None;
                    return None;
                };
                if shares.iter().any(|share| share.grant.grant_id == grant_id) {
                    Found::Present
                } else if offers.iter().any(|offer| offer.grant_id == grant_id) {
                    Found::Offered
                } else {
                    Found::Neither
                }
            }
        };
        Some((found, began))
    }

    /// Lets go of what an attempt that was carried on needed once it is over: its clock, and the
    /// request in the connection's book. Its record is already as the page is to read it, and the
    /// host's result stays in memory until the page has read it.
    ///
    /// The page removes the record once it has shown the end ([`remove`]). Until then the record
    /// stays a follow-up when the host's result carries something the person is owed ([`owes`]),
    /// whether or not this process holds it: the result in memory is lost with a restart, and the
    /// host's record of the action still has it for the person to ask for.
    async fn conclude(&self, attempt: &Attempt, sent_action: ActionId) {
        self.desk.forget(attempt.action_id);
        self.settle(sent_action).await;
    }

    async fn settle(&self, sent_action: ActionId) {
        self.connection.session().settle(sent_action).await;
    }

    /// The end of an attempt the page is answered at once: its record goes (`remove`), and the
    /// request is settled in the book.
    async fn finish_record(&self, attempt: &Attempt, sent_action: ActionId) {
        let _ = self.desk.drop_record(&self.store, attempt.action_id);
        self.desk.forget(attempt.action_id);
        self.settle(sent_action).await;
    }

    /// The host's result in the method's own JSON.
    fn result_json(&self, kind: Kind, result: Option<&ParamsValue>) -> Result<Value> {
        let Some(result) = result else {
            return Ok(Value::Null);
        };
        match kind {
            Kind::Invite => json_of::<GrantCreateResult>(result),
            Kind::Redeem => json_of::<GrantRedeemResult>(result),
            Kind::Revoke => json_of::<RevocationResult>(result),
            Kind::Transfer => json_of::<GrantTransferResult>(result),
        }
    }
}

/// A result read into the method's own type and written as that type's JSON.
fn json_of<R: kr_protocol::wire::WireMessage + Serialize>(result: &ParamsValue) -> Result<Value> {
    serde_json::to_value(decoded::<R>(result)?).map_err(|error| {
        CommandError::local_failure(format!("the result could not be read: {error}"))
    })
}

/// Whether an invitation includes the live view of the screen.
fn includes_live_screen(attempt: &Attempt) -> bool {
    attempt
        .request
        .params
        .to_typed::<GrantCreateParams>()
        .is_ok_and(|invited| invited.selection.include_live_screen)
}

/// Whether the host's result for an attempt carries something the person is owed, which the
/// attempt's end alone does not tell: the screen the host kept with a live invitation, to compare
/// with the one the person saw, and how far the session workers have got with a revocation.
fn owes(attempt: &Attempt) -> bool {
    match attempt.kind {
        Kind::Invite => includes_live_screen(attempt),
        Kind::Revoke | Kind::Transfer => true,
        Kind::Redeem => false,
    }
}

// ---------------------------------------------------------------------------------------------
// What a device holds
// ---------------------------------------------------------------------------------------------

/// Everything a device is offered and holds, every page of both lists read.
async fn held_all(connection: &Connection) -> Result<(Vec<ShareOffer>, Vec<HeldShare>)> {
    let mut offers: Vec<ShareOffer> = Vec::new();
    let mut shares: Vec<HeldShare> = Vec::new();
    let mut offers_after: Option<OfferKey> = None;
    let mut shares_after: Option<ShareKey> = None;
    let (mut offers_more, mut shares_more) = (true, true);
    for _ in 0..MAX_HELD_PAGES {
        let page: GrantHeldResult = read(
            connection,
            Method::GrantHeld,
            &GrantHeldParams {
                offers_after: Nullable(offers_after.clone()),
                shares_after: Nullable(shares_after.clone()),
            },
        )
        .await?;
        if offers_more {
            offers_more = page.offers_more;
            if let Some(last) = page.offers.last() {
                offers_after = Some(OfferKey {
                    issued_at_ms: last.issued_at_ms,
                    invitation_id: last.invitation_id,
                });
            }
            offers.extend(page.offers);
        }
        if shares_more {
            shares_more = page.shares_more;
            if let Some(last) = page.shares.last() {
                shares_after = Some(ShareKey {
                    issued_at_ms: last.issued_at_ms,
                    grant_id: last.grant.grant_id,
                });
            }
            shares.extend(page.shares);
        }
        if !offers_more && !shares_more {
            return Ok((offers, shares));
        }
    }
    Err(CommandError::unavailable(
        "what this device is offered did not fit the pages one read follows",
    ))
}

/// What a device is offered and holds.
#[derive(Debug, Serialize)]
pub struct Held {
    /// The invitations that name this device, not yet accepted.
    pub offers: Vec<ShareOffer>,
    /// The shares this device holds.
    pub shares: Vec<HeldShare>,
}

/// Reads what this device is offered and holds, following every page.
///
/// A read that fails on any page fails: a list with a page missing is never answered, so nothing
/// that is absent from it can be taken for ended.
///
/// # Errors
///
/// Refuses on the host on this machine, and returns the host's own refusal.
pub async fn held(state: &AppState) -> Result<Held> {
    let connection = holding(state)?;
    let (offers, shares) = held_all(&connection).await?;
    Ok(Held { offers, shares })
}

// ---------------------------------------------------------------------------------------------
// The four actions
// ---------------------------------------------------------------------------------------------

fn carry(state: &AppState, connection: Connection) -> Result<Arc<Carry>> {
    let desk = state.shares();
    let store = desk.store(connection.environment_id())?;
    Ok(Arc::new(Carry {
        desk,
        connection,
        store,
    }))
}

/// Refuses early, before anything is read of the host, when an attempt that can still happen
/// holds `gate`. [`AttemptStore::keep_unless_gated`] is the check that cannot be raced; this one
/// says so before the host's own state, which the first attempt may already have changed, answers
/// instead.
fn gate_is_free(store: &AttemptStore, gate: Gate, what: &str) -> Result<()> {
    for kept in store.attempts().map_err(failed_store)? {
        if let Kept::Known(blocker) = kept
            && blocker.gate() == Some(gate)
        {
            return Err(under_way(&blocker, what));
        }
    }
    Ok(())
}

/// What a person is told when a second action would race the first.
fn under_way(blocker: &Attempt, what: &str) -> CommandError {
    CommandError::refused(format!(
        "{what} is still under way ({}), so a second is not started until it is over",
        blocker.label
    ))
}

/// Invites a device to a session.
///
/// # Errors
///
/// Returns the host's refusal, and refuses when this application is connected to a host it is
/// paired with, when the subject and the parameters name different sessions, and when another
/// invitation of the same session to the same device is still under way.
pub async fn create(
    state: &AppState,
    subject: Subject,
    params: GrantCreateParams,
) -> Result<Attempted> {
    let connection = issuing(state)?;
    let environment_id = connection.environment_id();
    let target = subject.target(environment_id)?;
    if target.session_id.0 != Some(params.session_id) {
        return Err(CommandError::invalid(
            "the invitation and the session it is for are not the same session",
        ));
    }
    let actor = connection.actor().ok_or_else(|| {
        CommandError::local_failure("the host did not say which user this application is")
    })?;
    gate_is_free(
        &state.shares().store(environment_id)?,
        Gate::Invite {
            recipient: params.recipient_device_id,
            session: params.session_id,
        },
        "An invitation of this session to this device",
    )?;
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let (grant_id, _) = share_identities(&actor, action_id.get());
    let listed = devices(&connection).await?;
    let number = session_number(&connection, params.session_id).await;
    let label = format!(
        "Invitation of {} to {}",
        session_words(number),
        device_name(&listed, params.recipient_device_id)
    );
    let composed = connection
        .session()
        .compose(
            Method::GrantCreate,
            action_id,
            target,
            None,
            &NoPreconditions {},
            &params,
            MUTATION_TTL,
        )
        .await?;
    let attempt = Attempt::new(
        Kind::Invite,
        &composed,
        Some(grant_id),
        kr_ipc::now_ms().get(),
        label,
    );
    let carry = carry(state, connection)?;
    if let Some(blocker) = carry
        .store
        .keep_unless_gated(&attempt)
        .map_err(failed_store)?
    {
        return Err(under_way(
            &blocker,
            "An invitation of this session to this device",
        ));
    }
    carry.begin(attempt, composed).await
}

/// The number the host gives a session, when it says. A label that names it is a courtesy: an
/// action does not wait on a read that fails.
async fn session_number(connection: &Connection, session_id: SessionId) -> Option<u64> {
    let read: Result<kr_protocol::session::SessionReadResult> = read(
        connection,
        Method::SessionRead,
        &kr_protocol::session::SessionReadParams { session_id },
    )
    .await;
    read.ok().map(|read| read.session.display_number.get())
}

fn session_words(number: Option<u64>) -> String {
    number.map_or_else(
        || "the session".to_owned(),
        |number| format!("session {number}"),
    )
}

/// Takes a share back, or withdraws an invitation that has not been accepted.
///
/// # Errors
///
/// Returns the host's refusal, and refuses when the host holds no such grant.
pub async fn revoke(state: &AppState, params: GrantRevokeParams) -> Result<Attempted> {
    let connection = issuing(state)?;
    let environment_id = connection.environment_id();
    let known: GrantListResult = read(
        &connection,
        Method::GrantList,
        &GrantListParams {
            session_id: Nullable::null(),
            include_resolved: true,
        },
    )
    .await?;
    let Some(entry) = known
        .grants
        .iter()
        .find(|summary| summary.grant.grant_id == params.grant_id)
    else {
        return Err(CommandError::new(
            ErrorCode::ResourceUnavailable,
            "the host holds no such share, so nothing was revoked",
        ));
    };
    let listed = devices(&connection).await?;
    let label = format!(
        "Taking back the access of {}",
        device_name(&listed, entry.grant.recipient_device_id)
    );
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let composed = connection
        .session()
        .compose(
            Method::GrantRevoke,
            action_id,
            ActionTarget::environment(environment_id),
            None,
            &NoPreconditions {},
            &params,
            MUTATION_TTL,
        )
        .await?;
    let attempt = Attempt::new(
        Kind::Revoke,
        &composed,
        Some(params.grant_id),
        kr_ipc::now_ms().get(),
        label,
    );
    let carry = carry(state, connection)?;
    carry.keep(&attempt)?;
    carry.begin(attempt, composed).await
}

/// Accepts an invitation that names this device.
///
/// # Errors
///
/// Returns the host's refusal, and refuses when the host no longer offers the invitation to this
/// device.
pub async fn redeem(state: &AppState, params: GrantRedeemParams) -> Result<Attempted> {
    let connection = holding(state)?;
    let environment_id = connection.environment_id();
    let (offers, _) = held_all(&connection).await?;
    let Some(offer) = offers
        .iter()
        .find(|offer| offer.invitation_id == params.invitation_id)
    else {
        return Err(CommandError::new(
            ErrorCode::ResourceUnavailable,
            "that invitation is no longer offered to this device",
        ));
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let composed = connection
        .session()
        .compose(
            Method::GrantRedeem,
            action_id,
            ActionTarget::environment(environment_id),
            None,
            &NoPreconditions {},
            &params,
            MUTATION_TTL,
        )
        .await?;
    let attempt = Attempt::new(
        Kind::Redeem,
        &composed,
        Some(offer.grant_id),
        kr_ipc::now_ms().get(),
        format!("Accepting session {}", offer.display_number.get()),
    );
    let carry = carry(state, connection)?;
    carry.keep(&attempt)?;
    carry.begin(attempt, composed).await
}

// ---------------------------------------------------------------------------------------------
// Handing a session over
// ---------------------------------------------------------------------------------------------

/// What the sheet is told once the host has put the hand-over to the owner devices.
#[derive(Debug, Serialize)]
pub struct HandoverAsked {
    /// Names the hand-over in the commands that follow. Everything else stays here.
    pub reference: String,
    /// When the owner devices' chance to confirm ends.
    pub expires_at_ms: TimestampMs,
    /// The attempt that holds the hand-over's place.
    pub attempt: AttemptView,
    /// The device that gives control up.
    pub from_device_id: String,
    /// What it calls itself.
    pub from_device_name: String,
    /// The device that receives it.
    pub to_device_id: String,
    /// What it calls itself.
    pub to_device_name: String,
    /// The session's number on the host, when the host said.
    pub session_number: Option<u64>,
}

/// Where a hand-over stands.
#[derive(Debug, Serialize)]
pub struct HandoverState {
    /// `waiting` for an owner device, `answered`, or `gone`: ran out or was swept.
    pub state: &'static str,
    /// When the owner devices' chance to confirm ends.
    pub expires_at_ms: TimestampMs,
    /// What the host describes the plan as, once it has: the names it shows on the owner device.
    pub plan: Option<PlanView>,
}

/// The plan an owner device is shown, as the sheet repeats it.
#[derive(Debug, Serialize)]
pub struct PlanView {
    /// The device that gives control up, and what it calls itself.
    pub from_device_name: String,
    /// The device that receives it, and what it calls itself.
    pub to_device_name: String,
}

/// Asks the host to put a hand-over of a session's control to the owner devices.
///
/// Nothing that changes who holds the session is sent: the host describes the plan from its own
/// records, and an owner device confirms exactly that.
///
/// # Errors
///
/// Refuses when no owner device is paired with the host, when the grant is not an active share of
/// the session, when the receiver cannot take it, and when a hand-over of the session is still under
/// way.
pub async fn transfer_ask(
    state: &AppState,
    subject: Subject,
    params: GrantTransferParams,
) -> Result<HandoverAsked> {
    let connection = issuing(state)?;
    let environment_id = connection.environment_id();
    let target = subject.target(environment_id)?;
    if target.session_id.0 != Some(params.session_id) {
        return Err(CommandError::invalid(
            "the hand-over and the session it is for are not the same session",
        ));
    }
    gate_is_free(
        &state.shares().store(environment_id)?,
        Gate::Transfer {
            session: params.session_id,
        },
        "A hand-over of this session",
    )?;
    let listed = devices(&connection).await?;
    if !listed
        .devices
        .iter()
        .any(|device| device.manages_host && !device.revoked && !device.grant_expired)
    {
        return Err(CommandError::new(
            ErrorCode::OwnerConfirmationRequired,
            "no owner device is paired with this host, so nobody can confirm a hand-over of \
             control; pair one first",
        ));
    }
    let Some(receiver) = listed
        .devices
        .iter()
        .find(|device| device.device_id == params.to_device_id)
    else {
        return Err(CommandError::invalid(
            "that device is not paired with this host",
        ));
    };
    let held: GrantListResult = read(
        &connection,
        Method::GrantList,
        &GrantListParams {
            session_id: Nullable::some(params.session_id),
            include_resolved: false,
        },
    )
    .await?;
    let Some(giving) = held
        .grants
        .iter()
        .find(|summary| summary.grant.grant_id == params.from_grant_id)
    else {
        return Err(CommandError::new(
            ErrorCode::ResourceUnavailable,
            "the host holds no such share of that session",
        ));
    };
    if giving.state != kr_protocol::sharing::GrantState::Active {
        return Err(CommandError::new(
            ErrorCode::PermissionDenied,
            "only a share its device has accepted, and that still stands, can be handed over",
        ));
    }
    let from_device_id = giving.grant.recipient_device_id;
    let from_name = device_name(&listed, from_device_id);
    let to_name = receiver.display_name.clone();
    let number = session_number(&connection, params.session_id).await;

    let actor = connection.actor().ok_or_else(|| {
        CommandError::local_failure("the host did not say which user this application is")
    })?;
    let transfer_action = ActionId::new(kr_ipc::new_uuid());
    let new_grant_id = transfer_identity(&actor, transfer_action);
    let asking = OwnerConfirmationRequestParams {
        subject: ConfirmationSubject::TransferControl(Box::new(TransferControlSubject {
            params: params.clone(),
            action_id: transfer_action,
        })),
    };
    let composed = connection
        .session()
        .compose(
            Method::OwnerConfirmationRequest,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(environment_id),
            None,
            &NoPreconditions {},
            &asking,
            MUTATION_TTL,
        )
        .await?;
    // The attempt is named for the transfer it will become, and holds the confirmation request
    // until then.
    let attempt = Attempt::asking(
        &composed,
        transfer_action,
        new_grant_id,
        kr_ipc::now_ms().get(),
        format!("Handing over {} to {to_name}", session_words(number)),
    );
    let carry = carry(state, connection)?;
    if let Some(blocker) = carry
        .store
        .keep_unless_gated(&attempt)
        .map_err(failed_store)?
    {
        return Err(under_way(&blocker, "A hand-over of this session"));
    }
    let challenge = match carry.ask_for_confirmation(&composed).await {
        Ok(challenge) => challenge,
        Err(error) => {
            let _ = carry.desk.drop_record(&carry.store, attempt.action_id);
            return Err(error);
        }
    };
    if challenge.initial_bootstrap {
        let _ = carry.desk.drop_record(&carry.store, attempt.action_id);
        return Err(CommandError::new(
            ErrorCode::OwnerConfirmationRequired,
            "this host has no owner device yet, so nobody can confirm a hand-over of control",
        ));
    }
    let reference = kr_ipc::new_uuid().to_string();
    let expires_at_ms = challenge.request.expires_at_ms;
    carry
        .desk
        .handovers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(
            reference.clone(),
            Handover {
                action_id: transfer_action,
                params,
                target,
                challenge: challenge.request,
                received: Armed::now(),
                plan: None,
                environment_id,
            },
        );
    carry.desk.arm(transfer_action);
    Ok(HandoverAsked {
        reference,
        expires_at_ms,
        attempt: carry.desk.view(&attempt),
        from_device_id: from_device_id.to_string(),
        from_device_name: from_name,
        to_device_id: receiver.device_id.to_string(),
        to_device_name: to_name,
        session_number: number,
    })
}

impl Carry {
    /// Sends the confirmation request, and asks again with the same request, on a connection
    /// opened for it, when the answer is lost. The host keeps its answer, so the owner device shows
    /// one request however often it is asked.
    ///
    /// Only the host's answer to the first send is final when it refuses. A refusal to a repeat can
    /// be the host saying it has no record of an action it never read, so it is asked about again
    /// like a lost answer; when the repeats are used up, whether an owner device was asked is not
    /// known.
    async fn ask_for_confirmation(
        &self,
        composed: &ComposedMutation,
    ) -> Result<OwnerConfirmationRequestResult> {
        let pace = self.desk.pace();
        let mut said = Said::default();
        let sent_action = composed.action_id();
        let mut outcome = self.connection.session().send(composed).await;
        said.take(&outcome);
        // The host's own refusal of the first send, which a repeat's refusal never replaces.
        let first_refusal = said.refusal.clone();
        let mut asked_again = 0;
        let challenge = loop {
            match Reply::of(&outcome) {
                Reply::Result => {
                    break said
                        .result
                        .as_ref()
                        .map(decoded::<OwnerConfirmationRequestResult>)
                        .transpose()?
                        .ok_or_else(|| CommandError::local_failure("the host gave no challenge"));
                }
                Reply::Refused(
                    kr_protocol::error::RetryCategory::NoRetry
                    | kr_protocol::error::RetryCategory::ConfigurationChange,
                ) if asked_again == 0 => {
                    break Err(first_refusal.clone().map_or_else(
                        || CommandError::local_failure("the host refused the request"),
                        CommandError::from,
                    ));
                }
                Reply::NotSent => {
                    break Err(match outcome {
                        Err(error) => CommandError::from(error),
                        Ok(_) => CommandError::local_failure("the request was not sent"),
                    });
                }
                Reply::Refused(_) | Reply::Lost if asked_again < REPEATS => {
                    tokio::time::sleep(pace.repeats[asked_again]).await;
                    asked_again += 1;
                    outcome = match self.connection.another().await {
                        Ok(second) => {
                            let outcome = second.session().repeat(composed).await;
                            second.session().settle(sent_action).await;
                            second.session().close();
                            outcome
                        }
                        Err(_) => Err(ClientError::ConnectionEnded),
                    };
                    said.take(&outcome);
                }
                Reply::Refused(_) | Reply::Lost => {
                    break Err(CommandError::unavailable(
                        "the host did not answer, so it is not known whether an owner device was \
                         asked; one can still be shown the request for up to two minutes, and \
                         nothing this application sends will hand anything over",
                    ));
                }
            }
        };
        self.connection.session().settle(sent_action).await;
        challenge
    }
}

/// Where a hand-over stands: waiting for an owner device, answered, or gone.
///
/// The first time the host's description of the plan is seen it is checked against what was asked
/// for: the session, the grant given up, the receiver and the grant that would be written.
///
/// # Errors
///
/// Returns the host's refusal, and refuses a plan that is not the one asked for, which ends the
/// hand-over.
pub async fn transfer_answered(state: &AppState, reference: &str) -> Result<HandoverState> {
    let connection = issuing(state)?;
    let desk = state.shares();
    let handover = desk.handover(reference)?;
    let pending: OwnerConfirmationPendingResult = read(
        &connection,
        Method::OwnerConfirmationPending,
        &OwnerConfirmationPendingParams {},
    )
    .await?;
    let expires_at_ms = handover.challenge.expires_at_ms;
    let Some(waiting) = pending
        .pending
        .iter()
        .find(|waiting| waiting.request == handover.challenge)
    else {
        // The challenge is no longer the host's: nothing was sent for it, and the record that holds
        // the session's place goes, so the person can ask again. A send that began since took the
        // hand-over, and the challenge is gone because the send used it: that is not an answer
        // that nothing was handed over.
        if !desk.abandon(reference)? {
            return Err(not_asking_about());
        }
        return Ok(HandoverState {
            state: "gone",
            expires_at_ms,
            plan: None,
        });
    };
    let mut plan = handover.plan.clone();
    if plan.is_none() {
        let seen = TransferControlPlan::of_display(&waiting.display).cloned();
        if let Some(seen) = &seen {
            let actor = connection.actor();
            let expected = actor.map(|actor| transfer_identity(&actor, handover.action_id));
            let asked = &handover.params;
            if seen.session_id != asked.session_id
                || seen.source_grant_id != asked.from_grant_id
                || seen.to_device_id != asked.to_device_id
                || Some(seen.new_grant_id) != expected
            {
                desk.abandon(reference)?;
                return Err(CommandError::new(
                    ErrorCode::OwnerConfirmationRequired,
                    "the host described a different hand-over than the one asked for, so nothing \
                     was handed over",
                ));
            }
            if let Some(held) = desk
                .handovers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_mut(reference)
            {
                held.plan = Some(seen.clone());
            }
        }
        plan = seen;
    }
    let state_word = if waiting.answered {
        "answered"
    } else if kr_ipc::now_ms().get() < expires_at_ms.get() {
        "waiting"
    } else {
        "gone"
    };
    if state_word == "gone" && !desk.abandon(reference)? {
        return Err(not_asking_about());
    }
    Ok(HandoverState {
        state: state_word,
        expires_at_ms,
        plan: plan.map(|plan| PlanView {
            from_device_name: plan.from_device_name.to_string(),
            to_device_name: plan.to_device_name.to_string(),
        }),
    })
}

/// Sends the transfer an owner device has confirmed, once.
///
/// The hand-over leaves the table in the same step that keeps the record of the transfer, so
/// a cancel either came first, and nothing is sent, or comes after, and finds nothing to cancel.
///
/// # Errors
///
/// Refuses when the confirmation has not been answered, and returns the host's refusal.
pub async fn transfer_finish(state: &AppState, reference: &str) -> Result<Attempted> {
    let connection = issuing(state)?;
    let desk = state.shares();
    let answered = transfer_answered(state, reference).await?;
    if answered.state != "answered" {
        return Err(CommandError::new(
            ErrorCode::OwnerConfirmationRequired,
            "no owner device has confirmed this hand-over, so it is not sent",
        ));
    }
    // Looked at again: reading the answer may have recorded the plan.
    let handover = desk.handover(reference)?;
    let Some(plan) = handover.plan.clone() else {
        return Err(CommandError::local_failure(
            "the host's description of the plan was not read, so the hand-over is not sent",
        ));
    };
    let environment_id = connection.environment_id();
    let store = desk.store(environment_id)?;
    let composed = connection
        .session()
        .compose(
            Method::GrantTransfer,
            handover.action_id,
            handover.target.clone(),
            None,
            &NoPreconditions {},
            &handover.params,
            MUTATION_TTL,
        )
        .await?;
    let mut sending = None;
    desk.commit(reference, |held| {
        let mut attempt = find(&store, held.action_id)?
            .filter(|kept| kept.phase == Phase::Asking)
            .ok_or_else(|| {
                CommandError::local_failure("the record of this hand-over is no longer kept")
            })?;
        // The bound counts the challenge's life from its reply, on the clock that started then; the
        // attempt's own clock is armed anew below.
        if !attempt.confirmed(&composed, plan, held.received) {
            return Err(CommandError::local_failure(
                "the record of this hand-over is not one waiting for its confirmation",
            ));
        }
        desk.save(&store, &attempt)?;
        desk.rearm(held.action_id);
        sending = Some(attempt);
        Ok(())
    })?;
    let attempt = sending.ok_or_else(|| {
        CommandError::local_failure("the hand-over was taken without a record of it")
    })?;
    let carry = Arc::new(Carry {
        desk,
        connection,
        store,
    });
    carry.begin(attempt, composed).await
}

/// Stops asking for a hand-over's confirmation. The challenge is left to run out; it authorises
/// nothing by itself.
///
/// # Errors
///
/// Refuses a reference this application is not asking about, which includes one whose transfer
/// has been sent.
pub async fn transfer_cancel(state: &AppState, reference: &str) -> Result<()> {
    issuing(state)?;
    if state.shares().abandon(reference)? {
        Ok(())
    } else {
        Err(not_asking_about())
    }
}

// ---------------------------------------------------------------------------------------------
// What was left unfinished
// ---------------------------------------------------------------------------------------------

/// The attempts kept for the host this application is connected to.
///
/// An attempt whose repeats are over, and which a restart interrupted while its host was being
/// read, is carried on from here: its reads send no action.
///
/// # Errors
///
/// Returns why the store could not be read.
pub fn attempts(state: &AppState) -> Result<Attempts> {
    let connection = state.connection()?;
    let desk = state.shares();
    let store = desk.store(connection.environment_id())?;
    let mut views = Vec::new();
    let mut unreadable = 0;
    for kept in store.attempts().map_err(failed_store)? {
        match kept {
            Kept::Unknown { .. } => unreadable += 1,
            Kept::Known(listed) => {
                views.push(desk.view(&listed));
                if listed.phase == Phase::Checking
                    && belongs_to(&connection, &listed)
                    && desk.take(listed.action_id)
                {
                    // Read again now that the right to carry it on is held: a task that ended
                    // since the listing has written its end, and a copy from before is not
                    // written over it.
                    let Ok(Some(attempt)) = find(&store, listed.action_id) else {
                        desk.release(listed.action_id);
                        continue;
                    };
                    if attempt.phase != Phase::Checking {
                        desk.release(listed.action_id);
                        continue;
                    }
                    let carrying = Arc::new(Carry {
                        desk: Arc::clone(&desk),
                        connection: connection.clone(),
                        store: store.clone(),
                    });
                    tauri::async_runtime::spawn(async move {
                        let composed = attempt.composed();
                        carrying
                            .carry_on(attempt, composed, Next::Check, Said::default())
                            .await;
                    });
                }
            }
        }
    }
    Ok(Attempts {
        attempts: views,
        unreadable,
    })
}

fn known(store: &AttemptStore, action_id: ActionId) -> Result<Attempt> {
    find(store, action_id)?.ok_or_else(|| CommandError::invalid("no such attempt is kept"))
}

/// Asks the host what became of an attempt, once, with the exact request that was sent, on a
/// connection opened for it. It is the person's choice and never made by itself.
///
/// The host answers from the record it kept, or not at all: an answer that is not the result moves
/// the attempt to a read of the host's state.
///
/// # Errors
///
/// Refuses an attempt that is over without a follow-up, one made on another host or as another
/// user, and one this application is already carrying on.
pub async fn ask_the_host(state: &AppState, action_id: ActionId) -> Result<Attempted> {
    let connection = state.connection()?;
    let desk = state.shares();
    let store = desk.store(connection.environment_id())?;
    // The right to carry an attempt on is taken before its record is read, so the copy read is
    // the one nothing else is writing from.
    if !desk.take(action_id) {
        let attempt = known(&store, action_id)?;
        return Ok(Attempted {
            attempt: desk.view(&attempt),
            value: None,
        });
    }
    let mut attempt = match known(&store, action_id) {
        Ok(attempt) => attempt,
        Err(error) => {
            desk.forget(action_id);
            return Err(error);
        }
    };
    if attempt.phase == Phase::Asking {
        desk.release(action_id);
        return Err(CommandError::invalid(
            "a hand-over still being confirmed is not asked about",
        ));
    }
    if attempt.is_closed() && !attempt.follow_up {
        desk.release(action_id);
        return Err(CommandError::invalid("that attempt is over"));
    }
    if !belongs_to(&connection, &attempt) {
        desk.release(action_id);
        return Err(CommandError::refused(
            "that was made on another host, or as another user, and is asked about only there",
        ));
    }
    let carry = Arc::new(Carry {
        desk: Arc::clone(&desk),
        connection,
        store,
    });
    let composed = attempt.composed();
    let sent_action = attempt.request.action_id;
    let mut said = Said::default();
    let reply = carry.repeat_once(&attempt, &composed, &mut said).await;
    if attempt.is_closed() {
        // A follow-up: only the host's result ends it.
        if reply == Reply::Result {
            let value = match carry.result_json(attempt.kind, said.result.as_ref()) {
                Ok(value) => value,
                Err(error) => {
                    // The record stays for another ask, and this one no longer holds it.
                    desk.release(action_id);
                    return Err(error);
                }
            };
            let _ = desk.drop_record(&carry.store, attempt.action_id);
            let view = desk.view(&attempt);
            desk.forget(action_id);
            desk.drop_result(action_id);
            return Ok(Attempted {
                attempt: view,
                value: Some(value),
            });
        }
        desk.release(action_id);
        return Ok(Attempted {
            attempt: desk.view(&attempt),
            value: None,
        });
    }
    let next = attempt.after_repeat(reply);
    // An attempt that closed is not written: its record goes with the answer, and a closed record
    // written first would be one without what the result owes.
    if !matches!(next, Next::Closed(_))
        && let Err(error) = carry.keep(&attempt)
    {
        desk.release(action_id);
        return Err(error);
    }
    match next {
        Next::NotSent => {
            desk.release(action_id);
            Err(CommandError::local_failure(
                "the host could not be asked, so nothing is known of it yet",
            ))
        }
        Next::Closed(_) => {
            // Only the host's result closes an attempt that was asked about again: the page is
            // answered with it here, and has no use for a record of it.
            let value = match carry.result_json(attempt.kind, said.result.as_ref()) {
                Ok(value) => value,
                Err(error) => {
                    desk.release(action_id);
                    return Err(error);
                }
            };
            let _ = desk.drop_record(&carry.store, action_id);
            desk.forget(action_id);
            desk.drop_result(action_id);
            carry.settle(sent_action).await;
            Ok(Attempted {
                attempt: desk.view(&attempt),
                value: Some(value),
            })
        }
        Next::Repeat => {
            desk.release(action_id);
            Ok(Attempted {
                attempt: desk.view(&attempt),
                value: None,
            })
        }
        Next::Check | Next::Wait => {
            let view = desk.view(&attempt);
            let task = Arc::clone(&carry);
            tauri::async_runtime::spawn(async move {
                task.carry_on(attempt, composed, next, said).await;
            });
            Ok(Attempted {
                attempt: view,
                value: None,
            })
        }
    }
}

/// Takes an attempt out of view, or shows it again. Hiding releases nothing: while the attempt can
/// still happen, its record, its reads and the gate on a second one stay.
///
/// # Errors
///
/// Refuses to hide a hand-over still being confirmed, which is cancelled, and an attempt that is
/// over, which is removed. Returns why the record could not be kept.
pub fn set_hidden(state: &AppState, action_id: ActionId, hidden: bool) -> Result<AttemptView> {
    let connection = state.connection()?;
    let desk = state.shares();
    let store = desk.store(connection.environment_id())?;
    let attempt = desk.set_hidden(&store, action_id, hidden)?;
    Ok(desk.view(&attempt))
}

/// Deletes the record of an attempt that is over, a follow-up included, or of a hand-over that was
/// never sent.
///
/// # Errors
///
/// Refuses an attempt that can still happen.
pub fn remove(state: &AppState, action_id: ActionId) -> Result<()> {
    let connection = state.connection()?;
    let desk = state.shares();
    let store = desk.store(connection.environment_id())?;
    let attempt = known(&store, action_id)?;
    if attempt.phase == Phase::Asking {
        return desk.withdraw_asking(&store, action_id);
    }
    if !attempt.is_closed() {
        return Err(CommandError::refused(
            "that can still happen, so its record stays until it is over",
        ));
    }
    desk.forget(action_id);
    desk.drop_result(action_id);
    desk.drop_record(&store, action_id)
}

/// The ids of the attempts a process is carrying on, for a test to wait on.
#[must_use]
pub fn carried_on(state: &AppState) -> HashSet<ActionId> {
    state
        .shares()
        .running
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(_, running)| running.driving)
        .map(|(id, _)| *id)
        .collect()
}

#[allow(dead_code, reason = "the types a page's parameters are parsed into")]
const _: fn(&GrantCreateParams, &InvitationId, &GrantId) = |_, _, _| {};

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use kr_crypto::keys::DeviceKeys;
    use kr_protocol::envelope::MutationRequest;
    use kr_protocol::ids::{ActionWindowId, ConfirmationId, RequestId};
    use kr_protocol::pairing::SensitiveAction;
    use kr_protocol::scalars::{CanonicalSet, Digest256, DurationMs, Nonce256, Uuid};
    use kr_protocol::sharing::{AuthorityNotice, SessionRole};

    use super::*;

    /// An attempt for a request of `method` with `params`, as a record of it holds one.
    fn attempt_of(kind: Kind, method: Method, params: &impl Serialize) -> Attempt {
        let composed = ComposedMutation::restored(
            MutationRequest {
                request_id: RequestId::new(0),
                method: method.into(),
                method_version: method.entry().version,
                action_id: ActionId::new(Uuid::from_bytes([1; 16])),
                grant_id: Nullable::null(),
                target: ActionTarget::environment(EnvironmentId::new(Uuid::from_bytes([7; 16]))),
                expected: ParamsValue::from_typed(&NoPreconditions {}).expect("encodes"),
                action_window_id: ActionWindowId::new("window-1").expect("an identifier"),
                requested_ttl_ms: DurationMs::new(1_000),
                params: ParamsValue::from_typed(params).expect("encodes"),
            },
            0,
            60_000,
            None,
        );
        Attempt::new(kind, &composed, None, 0, "an attempt")
    }

    /// An invitation, with the live view of the screen or without it.
    fn an_invitation(live: bool) -> Attempt {
        let mut selection = kr_protocol::sharing::RoleSelection::plain(SessionRole::Viewer);
        selection.include_live_screen = live;
        attempt_of(
            Kind::Invite,
            Method::GrantCreate,
            &GrantCreateParams {
                session_id: SessionId::new(Uuid::from_bytes([2; 16])),
                recipient_device_id: DeviceId::new(Uuid::from_bytes([4; 16])),
                parent_grant_id: Nullable::null(),
                accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                selection,
                lifetime_ms: Nullable::null(),
                owner_confirmation: Nullable::null(),
            },
        )
    }

    /// KR-REQ-23.49: an attempt owes the person what the host's result carries that its end does not
    /// say: the screen kept with a live invitation, and how far the workers have got with a
    /// revocation or a hand-over. An invitation without the live view and an acceptance owe nothing,
    /// so their records go with their end. A live invitation cannot be made by the product's own
    /// harness, which has no session worker behind its sessions, so the rule is read off the
    /// request a record holds.
    #[test]
    fn an_attempt_owes_the_screen_of_a_live_invitation_and_the_workers_of_a_revocation() {
        assert!(owes(&an_invitation(true)));
        assert!(!owes(&an_invitation(false)));
        let grant = GrantId::new(Uuid::from_bytes([3; 16]));
        assert!(owes(&attempt_of(
            Kind::Revoke,
            Method::GrantRevoke,
            &GrantRevokeParams { grant_id: grant },
        )));
        assert!(owes(&attempt_of(
            Kind::Transfer,
            Method::GrantTransfer,
            &GrantTransferParams {
                session_id: SessionId::new(Uuid::from_bytes([2; 16])),
                from_grant_id: grant,
                to_device_id: DeviceId::new(Uuid::from_bytes([4; 16])),
            },
        )));
        assert!(!owes(&attempt_of(
            Kind::Redeem,
            Method::GrantRedeem,
            &GrantRedeemParams {
                invitation_id: InvitationId::new(Uuid::from_bytes([6; 16])),
            },
        )));
    }

    /// A revocation and a hand-over say which grant they take away, which the page checks again
    /// by: the protocol's list of the grants a revocation reached is sorted by identity and can be
    /// cut, so it does not say which one was named.
    #[test]
    fn a_revocation_and_a_hand_over_say_which_grant_they_take_away() {
        let grant = GrantId::new(Uuid::from_bytes([3; 16]));
        let revoke = attempt_of(
            Kind::Revoke,
            Method::GrantRevoke,
            &GrantRevokeParams { grant_id: grant },
        );
        let view = AttemptView::of(&revoke, None, 0, Duration::from_secs(1));
        assert_eq!(view.revoked_grant_id, Some(grant.to_string()));
        let hand_over = attempt_of(
            Kind::Transfer,
            Method::GrantTransfer,
            &GrantTransferParams {
                session_id: SessionId::new(Uuid::from_bytes([2; 16])),
                from_grant_id: grant,
                to_device_id: DeviceId::new(Uuid::from_bytes([4; 16])),
            },
        );
        let view = AttemptView::of(&hand_over, None, 0, Duration::from_secs(1));
        assert_eq!(view.revoked_grant_id, Some(grant.to_string()));
        assert_eq!(
            AttemptView::of(&an_invitation(false), None, 0, Duration::from_secs(1))
                .revoked_grant_id,
            None
        );
    }

    /// KR-REQ-23.49: an attempt whose bound has passed without a read the host answered does not
    /// say it can still happen until a moment that is now; it says nothing of when.
    #[test]
    fn an_attempt_past_its_bound_says_no_time_until_which_it_can_happen() {
        let attempt = an_invitation(false);
        let before = AttemptView::of(&attempt, None, 1_000, Duration::from_secs(5));
        assert!(before.can_happen_until_ms.is_some());
        let past = AttemptView::of(&attempt, None, 1_000, Duration::ZERO);
        assert!(past.can_happen_until_ms.is_none());
    }

    /// A hand-over as the table holds it, for a reference.
    fn desk_holding(reference: &str) -> ShareDesk {
        let keys = DeviceKeys::generate().expect("keys").public_keys();
        let environment_id = EnvironmentId::new(Uuid::from_bytes([7; 16]));
        let desk = ShareDesk::default();
        desk.handovers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                reference.to_owned(),
                Handover {
                    action_id: ActionId::new(Uuid::from_bytes([1; 16])),
                    params: GrantTransferParams {
                        session_id: SessionId::new(Uuid::from_bytes([2; 16])),
                        from_grant_id: GrantId::new(Uuid::from_bytes([3; 16])),
                        to_device_id: DeviceId::new(Uuid::from_bytes([4; 16])),
                    },
                    target: ActionTarget::environment(environment_id),
                    challenge: OwnerConfirmationRequest {
                        confirmation_id: ConfirmationId::new(Uuid::from_bytes([5; 16])),
                        action: SensitiveAction::ConfirmDevice,
                        action_digest: Digest256::from_bytes([6; 32]),
                        destination_keys: Nullable::null(),
                        destination_rights: std::iter::empty().collect::<CanonicalSet<_>>(),
                        host_device_id: DeviceId::new(Uuid::from_bytes([8; 16])),
                        host_endpoint_id: keys.transport,
                        nonce: Nonce256::from_bytes([9; 32]),
                        expires_at_ms: TimestampMs::new(1),
                    },
                    received: Armed::now(),
                    plan: None,
                    environment_id,
                },
            );
        desk.keep_at(tempfile::tempdir().expect("a directory").keep());
        desk
    }

    /// KR-REQ-18.15: a hand-over is abandoned or sent, never both. Once it has been taken to be
    /// sent, a cancel finds nothing to cancel and removes nothing of what is being sent; once it
    /// has been cancelled, nothing is written for a send.
    #[test]
    fn a_hand_over_is_abandoned_or_sent_and_never_both() {
        let sent = desk_holding("a");
        let mut written = false;
        sent.commit("a", |_| {
            written = true;
            Ok(())
        })
        .map(|_| ())
        .expect("taken to be sent");
        assert!(written);
        assert!(
            !sent.abandon("a").expect("looked at"),
            "it is the send's now"
        );

        let cancelled = desk_holding("b");
        assert!(cancelled.abandon("b").expect("abandoned"));
        let mut written = false;
        let refused = cancelled.commit("b", |_| {
            written = true;
            Ok(())
        });
        assert!(refused.is_err(), "a cancelled hand-over is not sent");
        assert!(!written, "and nothing is kept for it");
    }

    /// KR-REQ-18.15: taking a hand-over to be sent keeps its record in the same step. A cancel that
    /// begins while the record is being kept waits for the step to end, and then finds the
    /// hand-over gone, so it can never remove the record a send is relying on.
    #[test]
    fn a_cancel_begun_while_a_send_keeps_its_record_waits_and_finds_nothing() {
        let desk = Arc::new(desk_holding("c"));
        let (inside, inside_wait) = mpsc::channel();
        let (go, go_wait) = mpsc::channel::<()>();
        let sending = {
            let desk = Arc::clone(&desk);
            std::thread::spawn(move || {
                desk.commit("c", |_| {
                    inside.send(()).expect("told");
                    go_wait.recv().expect("let go");
                    Ok(())
                })
                .map(|_| ())
            })
        };
        inside_wait.recv().expect("the send is keeping its record");
        let cancelling = {
            let desk = Arc::clone(&desk);
            std::thread::spawn(move || desk.abandon("c"))
        };
        go.send(()).expect("let go");
        sending
            .join()
            .expect("the send ended")
            .expect("it was sent");
        assert!(
            !cancelling
                .join()
                .expect("the cancel ended")
                .expect("it looked"),
            "the cancel found the hand-over already taken"
        );
    }

    /// What the host says of an answer it could not give is kept with the attempt as what it says
    /// of a refusal is, because the person can act on its words; a connection that ended says
    /// nothing of the host's.
    #[test]
    fn the_hosts_words_for_an_unknown_outcome_are_kept_as_its_words_for_a_refusal() {
        let mut said = Said::default();
        said.take(&Err(ClientError::OutcomeUnknown {
            action_id: ActionId::new(Uuid::from_bytes([1; 16])),
            error: ProtocolError::new(ErrorCode::OutcomeUnknown, "unknown"),
        }));
        assert_eq!(
            said.refusal.map(|refusal| refusal.code),
            Some(ErrorCode::OutcomeUnknown)
        );
        let mut lost = Said::default();
        lost.take(&Err(ClientError::ConnectionEnded));
        assert!(lost.refusal.is_none());
    }
}
