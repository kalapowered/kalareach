//! The task that owns one call from the moment it is asked for to the moment it is over.
//!
//! One task, so that nothing about a call is decided in two places: it reads the news native code
//! tells, the control's news, the person's commands and the clock, and it ends the call by one
//! procedure whatever the cause. The steps of a start run in it too, so a page that is loaded
//! again, a command that is dropped or a news item that arrives in the middle of a step changes
//! nothing about who ends the call.
//!
//! # What a start does, in order
//!
//! The account's token for the voice scope is checked before anything is created or asked. Native
//! code opens the call (the microphone question), makes the offer, and the host is asked to start
//! the call with it. **From the moment the host answers that a call exists, every way out goes
//! through the end procedure**, which stops the media, revokes the grant at the host and finalises
//! the call at the voice service. Then the answer is applied, the call is permitted, and the
//! control is opened at the service the account is signed in at.
//!
//! # What an end does, whatever the cause
//!
//! The media stops and the host is asked to revoke the call's grant, both at once and each with
//! its own bound: a native stop that does not return never holds a revocation, and a revocation
//! that is not answered never holds the media. The host's answer, a refusal and a silence are
//! kept apart in what the screen reads: only an answer says the grant is revoked, and a silence
//! leaves the revocation owed until the moment the call would have closed. The control is asked to
//! close the call at the voice service as the end begins, and its news is read meanwhile; the
//! service's own HTTP route is the fallback once the host has answered. The screen does not wait
//! for the service.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use companion_platform::call::{
    CallEvent, CallEvents, CallFailure, CallId, CallPlatform, CaptureProof, CaptureState,
    ConnectionState, FailureKind, Heard, Held, Mute,
};
use kr_client::ClientError;
use kr_client::Session;
use kr_client::Settled;
use kr_client::pairing::owner::CeremonyOutcome;
use kr_client::services::AccountTokenSource;
use kr_client::services::account::{AccountStatus, SignedInAccount};
use kr_client::services::voice::{VOICE_SCOPE, VoiceCommand, same_origin};
use kr_client::services::voice_control::{
    ControlEnd, ControlEvents, ControlNews, ControlTarget, OpeningContextSent, SendError,
    VoiceControl,
};
use kr_client::session::ComposedMutation;
use kr_protocol::ids::{ActionId, VoiceSessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::voice::{
    FragmentText, TranscriptFragment, VoiceContextParams, VoiceDelegateParams, VoiceDelegateResult,
    VoiceDelegationId, VoiceDelegationOutcome, VoiceSessionDescriptor, VoiceStartOutcome,
    VoiceStartParams, VoiceStartResult,
};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant;

mod ceremony;

use super::advice::MuteAdvice;
use super::cause::Cause;
use super::delegation::{Cause as Why, Frozen, Gate, Record, Told};
use super::host::{
    CallHost, Delivered, Exchange, Handover, HostReach, Pairing, ask_again, hand_over, has_ended,
    revoke,
};
use super::provider;
use super::view::{DelegationRow, EndedView, HostEnd, OwedView, ProblemKind, VoiceCallState};
use super::{Closed, Cmd, NoteKey, ServiceCall, Shared, StartRequest, Started, now_ms};
use crate::commands::{MUTATION_TTL, NoPreconditions};
use crate::error::{CommandError, Result};

/// What the model is told, once, as the call is attached: this version does not act on the host.
const HOST_ACTIONS_UNAVAILABLE: &str = "In this version the phone cannot act on the person's \
    computer. If the person asks for something to be done there, say that nothing can be done \
    from this call. Do not say or imply that anything was done.";

/// What the model is told, once, as the call is attached, when spoken requests may reach the host.
const HOST_ACTIONS_AVAILABLE: &str = "The phone can ask the person's computer to read some things \
    when the person says so clearly. What you are told about each such request is all that is \
    known of it: do not say or imply that anything was done that you were not told was done.";

/// What the model is told of a spoken request this device would not hand to the host.
const DELEGATION_REFUSED: &str = "Nothing was done on the person's computer: what was said could \
    not be used as a request. Say so, and ask the person to say it again.";

/// What the model is told of a spoken request that was not written to the host.
const DELEGATION_NOT_SENT: &str = "Nothing was done on the person's computer: the request was not \
    sent. Say so, and ask the person to say it again.";

/// What the model is told of a request that may have been written to the host.
const DELEGATION_UNKNOWN: &str = "It is not known whether this was done on the person's \
    computer. Do not say it was done and do not say it was not. Say that it is not known.";

/// What the model is told of a request the host took and did not say it carried out.
const DELEGATION_ADMITTED: &str = "The person's computer accepted the request. Whether it was \
    carried out is not known. Do not say it was done.";

/// What the model is told of a request that needs the person's confirmation on the phone, once
/// the phone is asking for it.
const DELEGATION_CONFIRMATION: &str = "This needs the person's confirmation on the phone's unlocked \
    screen, which the phone is asking for now. Nothing was done yet. Do not say it was done.";

/// What the model is told when the person did not confirm.
const DELEGATION_NOT_CONFIRMED: &str = "The person did not confirm it on the phone, so nothing was \
    done. Say so, and say it can be asked for again.";

/// What the model is told when the phone could not ask the person to confirm.
const DELEGATION_NO_CEREMONY: &str = "Nothing was done: this phone cannot ask the person to confirm \
    on its unlocked screen. Say so.";

/// What the model is told when the computer's request for a confirmation was not one the phone
/// could put to the person.
const DELEGATION_CHALLENGE_MISMATCH: &str = "Nothing was done: what the computer asked the person to \
    confirm was not what was said, so the person was not asked. Say so, and ask the person to say it \
    again.";

/// What the model is told when the phone's own clock says the confirmation ran out.
const DELEGATION_CONFIRMATION_EXPIRED: &str = "Nothing was done: this phone's clock says the \
    confirmation ran out. Say so, and ask the person to say it again.";

/// What the model is told when the confirmation was dropped before it was sent.
const DELEGATION_CONFIRMATION_DROPPED: &str = "Nothing was done: the confirmation was not sent. Say \
    so, and ask the person to say it again.";

/// What the model is told of a request the host refused.
const DELEGATION_HOST_REFUSED: &str = "The person's computer refused the request. Nothing was \
    done. Say so.";

/// What the model is told of a request that more speech then showed was not complete.
const DELEGATION_LATE: &str = "More was said that belongs to this request after it was read, so \
    the request is not carried out. Say so, and ask the person to say it again.";

/// What the model is told, once, when the call can no longer hand a spoken request to the host.
const SPEECH_TAINTED: &str = "This call can no longer act on what the person says: part of it \
    may not have been heard or recorded here. Nothing is done on the person's computer from this \
    call. Say so if asked.";

/// What a person is told, once, of the same.
const SPEECH_TAINTED_PERSON: &str = "This call can no longer act on spoken requests: part of what \
    was said may not have been heard or read. Nothing more is asked of the computer by voice in \
    this call.";

/// What leads a result the host performed, which is then the host's own bounded summary.
const DELEGATION_PERFORMED: &str = "The person's computer read it. Say what it reports:";

/// What an end says of requests that may have been written and not answered.
pub(super) const REQUESTS_UNSETTLED: &str = "A request you spoke may or may not have been carried out: look \
    at the session list.";

/// What the model is told when the host is back and spoken requests may reach it: it does not say
/// that nothing was done, since a request written before the loss may have been.
const HOST_BACK_ACCEPTING: &str = "The phone is in contact with the person's computer again.";

/// What the model is told of a delegation: nothing was done.
const NOTHING_WAS_DONE: &str = "Nothing was done on the person's computer: this version does not \
    act on spoken requests. Say so.";

/// What the model is told when the phone has lost the host.
const HOST_LOST: &str = "The phone has lost contact with the person's computer. The call goes on, \
    but nothing can be read from or done on the computer until it is back. Do not say or imply \
    that anything was done there.";

/// What the model is told when the host is back.
const HOST_BACK: &str = "The phone is in contact with the person's computer again. Nothing was \
    done there while it was away.";

/// What a person is told of a revocation a process left owed while a call ran: it ended, and may
/// not have told the host.
const STANDING_WORDS: &str = "This device was in this call when it last ran, and may not have told \
    the host the call was over.";

/// The most delegation identifiers a call remembers having answered.
const ANSWERED: usize = 256;

/// What a task that the owner started tells it.
enum Internal {
    /// The answer to a sign of life.
    Alive(std::result::Result<Held, CallFailure>),
    /// What the host path came to: back on this connection, or what the host said.
    Probed(Probe),
    /// What native code's capture proof said, when the delegation `id` asked for it with a marker.
    Proof {
        id: String,
        result: std::result::Result<CaptureProof, CallFailure>,
    },
    /// What came of handing the delegation `id` to the host.
    Delivered { id: String, exchange: Box<Exchange> },
    /// What the person's ceremony came to, for the confirmation `generation` of the delegation `id`.
    Ceremony {
        id: String,
        generation: u64,
        outcome: CeremonyOutcome,
    },
    /// What native code's capture proof said, when the confirmation `generation` of the delegation
    /// `id` asked for it with a marker after the ceremony.
    SealProof {
        id: String,
        generation: u64,
        result: std::result::Result<CaptureProof, CallFailure>,
    },
    /// What the host answered when asked again about the delegation `id`, if it did.
    Asked {
        id: String,
        result: Option<Box<VoiceDelegateResult>>,
    },
    /// Whether the model was told a delegation was not acted on.
    Told { delegation_id: String, told: bool },
    /// What came of giving the call the host's default context.
    Opened(Opened),
}

/// How giving a call the host's default context came out.
enum Opened {
    /// The call was given all of it.
    Given,
    /// The host did not give the selection.
    NotRead,
    /// The voice service confirmed `accepted` of the `total` parts of it, and the next was
    /// refused or not sent, or, when `uncertain`, was sent and never answered: the service may or
    /// may not have taken it.
    Sent {
        accepted: usize,
        total: usize,
        uncertain: bool,
    },
    /// The call ended before it was all given.
    Cut,
}

impl Opened {
    /// What giving the context came to, from what the control sent of it.
    fn of(sent: &OpeningContextSent) -> Self {
        let Some(stopped_by) = &sent.stopped_by else {
            return Self::Given;
        };
        Self::Sent {
            accepted: sent.accepted,
            total: sent.total,
            // An answer that never came is not a refusal: the part may have reached the model.
            uncertain: matches!(stopped_by, SendError::Lost | SendError::Unanswered),
        }
    }

    /// What is logged and what a person is told when the call was not given all of the context,
    /// and nothing when it was.
    fn problem(&self) -> Option<(&'static str, String)> {
        match self {
            Self::Given => None,
            Self::NotRead => Some((
                "the host did not give it",
                "This call was not given all of the host's context for its session: the host did \
                 not give it."
                    .to_owned(),
            )),
            Self::Sent {
                accepted,
                total,
                uncertain: true,
            } => Some((
                "the voice service did not say whether it took the next part",
                format!(
                    "This call may not have been given all of the host's context for its session: \
                     the voice service confirmed {accepted} of its {total} parts, and did not say \
                     whether it took the next."
                ),
            )),
            Self::Sent { accepted: 0, .. } => Some((
                "the voice service did not take any of it",
                "This call was not given all of the host's context for its session: the voice \
                 service did not take any of it."
                    .to_owned(),
            )),
            Self::Sent {
                accepted, total, ..
            } => Some((
                "the voice service took part of it",
                format!(
                    "This call was given part of the host's context for its session: the voice \
                     service took {accepted} of its {total} parts and not the next."
                ),
            )),
            Self::Cut => Some((
                "the call ended while it was being given",
                "This call ended while it was being given the host's context for its session, so \
                 it was not given all of it."
                    .to_owned(),
            )),
        }
    }
}

/// What the check of a host path that was lost came to.
enum Probe {
    /// The host answered on this connection.
    Back(Arc<Session>),
    /// The host answered with a refusal.
    Refused(String),
    /// The host could not be reached yet.
    Unreached,
}

/// What a call is started with.
pub(super) struct Launch {
    pub(super) id: u64,
    pub(super) request: StartRequest,
    pub(super) reach: Arc<dyn HostReach>,
    pub(super) tokens: Arc<SignedInAccount>,
    pub(super) inbox: mpsc::Receiver<Cmd>,
    pub(super) reply: oneshot::Sender<Result<Started>>,
}

/// Owns one call from its start to its end.
pub(super) async fn drive(shared: Arc<Shared>, launch: Launch) {
    let Launch {
        id,
        request,
        reach,
        tokens,
        inbox,
        reply,
    } = launch;
    let mut owner = Owner::new(id, shared, reach, tokens, inbox);
    // The record of this call begins when the start is taken, so that whatever the start comes to,
    // from the first step on, is this call's and not the one before it.
    owner.view(|state| state.begin(id));
    match owner.start(request).await {
        Ok(Outcome::Live(started)) => {
            // A start whose asker is gone is a call nobody will hang up: it is ended.
            if reply.send(Ok(started)).is_err() {
                owner
                    .end(Cause::Step(
                        "the page that asked for the call went away before it began".to_owned(),
                    ))
                    .await;
            } else {
                owner.running().await;
            }
        }
        Ok(Outcome::Over(started)) => {
            owner.finish_without_call(declined_words(&started));
            let _ = reply.send(Ok(started));
        }
        Err(error) => {
            owner.finish_without_call(Some(plain_words(&error)));
            let _ = reply.send(Err(error));
        }
    }
    // However the owner came to be done, nobody is left waiting on it: what is queued is answered,
    // and a command sent from now on is turned away at once.
    owner.close_inbox(&Closed {
        local: true,
        host: HostEnd::NotNeeded,
    });
    owner.shared.release(owner.id);
    owner.shared.forget_emergency(owner.id);
}

/// A failure's words without the protocol code that a host's message begins with: a person reads
/// the words, and the code is for the page's own branching.
fn plain_words(error: &CommandError) -> String {
    let prefix = format!("{}: ", error.code.as_str());
    error
        .message
        .strip_prefix(&prefix)
        .unwrap_or(&error.message)
        .to_owned()
}

/// What a person is told of a start that ended with no call, when the answer was not one the owner
/// wrote an end for: the service's or the host's own words.
fn declined_words(started: &Started) -> Option<String> {
    match started {
        Started::Result(result) => match &result.outcome {
            VoiceStartOutcome::Started { .. } => None,
            VoiceStartOutcome::Unavailable { message, .. }
            | VoiceStartOutcome::CreationUnknown { message, .. }
            | VoiceStartOutcome::PreparationChanged { message }
            | VoiceStartOutcome::RateChanged { message, .. } => Some(message.clone()),
        },
        // A receipt does not show whether the host made a call, so no more is said than that this
        // device holds none.
        Started::Receipt(_) => Some(
            "This device holds no call: the host answered with a receipt and not with a call."
                .to_owned(),
        ),
        // The owner wrote what an unknown start left.
        Started::Unknown { .. } => None,
    }
}

/// What `start` came to.
pub(super) enum Outcome {
    /// A call runs.
    Live(Started),
    /// Nothing runs: the host declined, or could not say.
    Over(Started),
}

/// The task's whole state.
pub(super) struct Owner {
    id: u64,
    shared: Arc<Shared>,
    reach: Arc<dyn HostReach>,
    tokens: Arc<SignedInAccount>,
    inbox: mpsc::Receiver<Cmd>,
    account: watch::Receiver<AccountStatus>,
    internal_tx: mpsc::UnboundedSender<Internal>,
    internal: mpsc::UnboundedReceiver<Internal>,
    /// The grant generation the call started under.
    generation: Option<String>,
    host: Option<CallHost>,
    call: Option<CallId>,
    events: Option<CallEvents>,
    descriptor: Option<VoiceSessionDescriptor>,
    control: Option<VoiceControl>,
    control_events: Option<ControlEvents>,
    /// Tells the voice service the person's mute, whichever control changed it.
    advice: Option<MuteAdvice>,
    attached_before: bool,
    answered: VecDeque<String>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    host_closed: Pin<Box<dyn Future<Output = ()> + Send + Sync>>,
    host_lost: bool,
    silent_signs: u32,
    stops: Vec<oneshot::Sender<Closed>>,
    /// Seconds of call the start asked for.
    requested: u32,
    /// When the start was taken: the figure for the first audio runs from it.
    started: Instant,
    /// When the owner gives native code a sign while a step runs.
    signs: tokio::time::Interval,
    /// What would have ended the call while the host was still being asked what became of its
    /// start: the first of them, acted on when the host's answer is known.
    cancelled: Option<Cause>,
    /// Whether native code stopped the call's media before the end procedure ran.
    media_stopped: Option<bool>,
    /// Whether the inbox is closed: nothing more can be read from it.
    inbox_gone: bool,
    /// Whether a look at the host path is under way.
    probing: bool,
    /// Not before when the host path is looked at again, after the host refused to vouch.
    probe_after: Option<Instant>,
    /// The task that gives the call the host's context, from the moment it starts until its
    /// outcome is taken: one that is still here when the call ends was cut short by the end.
    opening: Option<tokio::task::JoinHandle<()>>,
    /// Whether this call hands spoken delegations to the host: fixed as the call begins.
    accepting: bool,
    /// What the provider's data channel said, and whether it lets a request through.
    gate: Gate,
    /// The delegations the provider announced, in order, that are waiting for their time or for
    /// native code's news to be read up to a marker.
    collections: VecDeque<Collection>,
    /// When the first of them is next due.
    collection_due: Pin<Box<tokio::time::Sleep>>,
    /// The markers read in the news, newest last.
    barriers: VecDeque<u64>,
    /// What the voice service announced of each delegation: the offset when it said, with the moment
    /// this device read it, and none when it only listed the identifier.
    announced: VecDeque<(String, Option<(u64, Instant)>)>,
    /// What was written to the host and not answered, by delegation, which a later look at the
    /// host asks about again.
    attempts: HashMap<String, Attempt>,
    /// The delegations whose request was, or may have been, written to the host and has no answer
    /// that says it was done or not done. Kept apart from the rows the screen shows, which a long
    /// call lets go of.
    unsettled: HashSet<String>,
    /// The delegations whose answer was a challenge the host awaits a confirmation for, and where
    /// each confirmation is: the person is being asked, or the news is being read before the
    /// signature is made.
    confirming: HashMap<String, ceremony::Confirming>,
    /// The confirmations whose ceremony is done and that wait for the news to be read up to the
    /// marker of their capture proof.
    sealing: Vec<ceremony::Sealing>,
    /// The delegations whose confirmation was signed and sent, which a second challenge for the
    /// same delegation is not answered by asking the person again.
    signed: HashSet<String>,
    /// The number the next confirmation is given, so that what a ceremony or a proof says of one
    /// that was dropped is not taken for what it says of the one that followed.
    next_confirmation: u64,
    /// Set when nothing not yet written may be written: the path to the host was lost, or the call
    /// can no longer hand a request over. A fresh one is made when the host is back.
    unsent: Arc<AtomicBool>,
    /// Whether the person and the model were told the call is tainted.
    taint_told: bool,
}

/// A delegation waiting for what was said before it to be read.
struct Collection {
    id: String,
    offset_ms: u64,
    /// When it is due, while it waits.
    due: Instant,
    stage: Stage,
}

/// Where a collection is.
enum Stage {
    /// It waits for the fragments said before it to arrive.
    Waiting,
    /// A capture proof with a marker was asked, and the news is read up to the marker.
    Draining {
        /// The marker the proof answered, when it has.
        token: Option<u64>,
        /// What the proof's record showed, when it has.
        record: Option<Record>,
        /// When the set is refused as not drained.
        until: Instant,
    },
}

impl Stage {
    /// Whether the set can be frozen at `now`: the proof's record and its marker are in hand, the
    /// news was read up to the marker, and the time the news may be read until has not come. A
    /// completion that is handled at or after that time is none, whichever of it and the deadline
    /// the owner handles first: the set is then refused as not drained.
    fn may_freeze(&self, barriers: &VecDeque<u64>, now: Instant) -> bool {
        matches!(
            self,
            Self::Draining {
                token: Some(token),
                record: Some(_),
                until,
            } if barriers.contains(token) && now < *until
        )
    }
}

/// A request written to the host whose answer did not come.
struct Attempt {
    /// The connection that wrote it.
    session: Arc<Session>,
    /// The request as it was composed.
    composed: ComposedMutation,
    /// Whether the host is being asked about it now.
    asking: bool,
}

/// Waits for the next news of the call, or for ever when there is no call.
async fn next_heard(events: &mut Option<CallEvents>) -> Option<Heard> {
    match events {
        Some(events) => events.recv().await,
        None => std::future::pending().await,
    }
}

/// Waits for the control's next news, or for ever when there is no control.
async fn next_news(events: &mut Option<ControlEvents>) -> Option<ControlNews> {
    match events {
        Some(events) => events.next().await,
        None => std::future::pending().await,
    }
}

fn far_future() -> Pin<Box<tokio::time::Sleep>> {
    Box::pin(tokio::time::sleep_until(
        Instant::now() + Duration::from_secs(60 * 60 * 24 * 365),
    ))
}

/// The word the screen draws a capture state by.
fn capture_word(state: CaptureState) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unavailable".to_owned())
}

impl Drop for Owner {
    /// An owner that is gone, however it went, hands nothing more to the host: a request still
    /// waiting for the connection's turn to be written is not written for a call nobody holds.
    fn drop(&mut self) {
        self.unsent.store(true, Ordering::SeqCst);
    }
}

impl Owner {
    pub(super) fn new(
        id: u64,
        shared: Arc<Shared>,
        reach: Arc<dyn HostReach>,
        tokens: Arc<SignedInAccount>,
        inbox: mpsc::Receiver<Cmd>,
    ) -> Self {
        let (internal_tx, internal) = mpsc::unbounded_channel();
        let account = tokens.subscribe();
        let timings = shared.timings;
        let accepting = shared.accepts_host_delegations();
        Self {
            id,
            shared,
            reach,
            tokens,
            inbox,
            account,
            internal_tx,
            internal,
            generation: None,
            host: None,
            call: None,
            events: None,
            descriptor: None,
            control: None,
            control_events: None,
            advice: None,
            attached_before: false,
            answered: VecDeque::new(),
            deadline: far_future(),
            host_closed: Box::pin(std::future::pending()),
            host_lost: false,
            silent_signs: 0,
            stops: Vec::new(),
            requested: 0,
            started: Instant::now(),
            signs: {
                let mut signs = tokio::time::interval(timings.tick);
                signs.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                signs
            },
            cancelled: None,
            media_stopped: None,
            inbox_gone: false,
            probing: false,
            probe_after: None,
            opening: None,
            accepting,
            gate: Gate::new(),
            collections: VecDeque::new(),
            collection_due: far_future(),
            barriers: VecDeque::new(),
            announced: VecDeque::new(),
            attempts: HashMap::new(),
            unsettled: HashSet::new(),
            confirming: HashMap::new(),
            sealing: Vec::new(),
            signed: HashSet::new(),
            next_confirmation: 0,
            unsent: Arc::new(AtomicBool::new(false)),
            taint_told: false,
        }
    }

    fn platform(&self) -> Arc<dyn CallPlatform> {
        Arc::clone(&self.shared.platform)
    }

    /// Finishes a start that ended with no call: how it ended is written, what is queued is
    /// answered, and the slot is freed, in that order, so that nothing reads a free device with no
    /// end for the start that held it.
    fn finish_without_call(&mut self, words: Option<String>) {
        self.note_not_started(words);
        let closed = Closed {
            local: self.media_stopped.unwrap_or(true),
            host: HostEnd::NotNeeded,
        };
        self.close_inbox(&closed);
        self.shared.record_end(self.id, Vec::new());
        self.shared.release(self.id);
    }

    /// Writes how a start that ended with no call ended, unless the owner already wrote an end for
    /// it: a screen that was loaded again while the start ran finds that answer, in the words the
    /// start's own asker was given, and not the end of the call before.
    fn note_not_started(&self, words: Option<String>) {
        let Some(words) = words else {
            return;
        };
        let (id, local) = (self.id, self.media_stopped.unwrap_or(true));
        self.view(|state| {
            if state.owner != id || state.ended.as_ref().is_some_and(|ended| ended.owner == id) {
                return;
            }
            state.ended = Some(EndedView {
                owner: id,
                cause: "not_started".to_owned(),
                words,
                closed_locally: local,
                host: HostEnd::NotNeeded,
                broker: "not_needed".to_owned(),
            });
        });
    }

    fn view(&self, change: impl FnOnce(&mut VoiceCallState)) {
        change(
            &mut self
                .shared
                .view
                .lock()
                .expect("the view lock is not poisoned"),
        );
    }

    /* ------------------------------------------------------------------------------------- */
    /* Waiting for a step while the call is watched                                          */
    /* ------------------------------------------------------------------------------------- */

    /// Runs `step`, and keeps hearing the person, native code and the account while it runs.
    /// Returns what the step came to, or why the call has to end instead.
    async fn wait<T>(&mut self, step: impl Future<Output = T>) -> std::result::Result<T, Cause> {
        tokio::pin!(step);
        loop {
            tokio::select! {
                out = &mut step => return Ok(out),
                cmd = self.inbox.recv() => {
                    if let Some(cause) = self.before_running(cmd) {
                        return Err(cause);
                    }
                }
                heard = next_heard(&mut self.events) => {
                    if let Some(cause) = self.on_heard(heard).await {
                        return Err(cause);
                    }
                }
                changed = self.account.changed() => {
                    if let Some(cause) = self.on_account(changed.is_ok()) {
                        return Err(cause);
                    }
                }
                // Native code ends a call whose owner gives no sign, and a setup can take long.
                _ = self.signs.tick() => self.give_a_sign(),
            }
        }
    }

    /// Runs `step` to its end while the person, native code and the account are still heard.
    ///
    /// What would end the call is acted on at once for what only this device can do, and the step
    /// goes on: the media stops and a stop is answered, and the first cause is kept for when the
    /// step is over. For a step that must be seen through whatever the person does, such as asking
    /// the host what became of a start.
    async fn wait_through<T>(&mut self, step: impl Future<Output = T>) -> T {
        tokio::pin!(step);
        loop {
            let cause = tokio::select! {
                out = &mut step => return out,
                cmd = self.inbox.recv(), if !self.inbox_gone => {
                    if cmd.is_none() {
                        self.inbox_gone = true;
                    }
                    self.before_running(cmd)
                }
                heard = next_heard(&mut self.events) => self.on_heard(heard).await,
                changed = self.account.changed() => self.on_account(changed.is_ok()),
                _ = self.signs.tick() => {
                    self.give_a_sign();
                    None
                }
            };
            if let Some(cause) = cause {
                self.give_up(cause).await;
            }
        }
    }

    /// Stops the media for a cause that arrived while the host was still being asked, answers the
    /// stops waiting for it, and keeps the cause.
    async fn give_up(&mut self, cause: Cause) {
        if self.cancelled.is_none() {
            self.cancelled = Some(cause);
        }
        self.stop_native(HostEnd::NotTold {
            words: "The host has not said whether it made the call. This device is still asking \
                    it, and ends the call if it did."
                .to_owned(),
        })
        .await;
    }

    /// Tells native code the owner is there, on a task of its own; what it answers is read when the
    /// call runs.
    fn give_a_sign(&self) {
        if let Some(call) = self.call.clone() {
            let platform = self.platform();
            tokio::spawn(async move {
                let _ = platform.alive(&call).await;
            });
        }
    }

    /// What a command means while the call is being set up: a stop gives it up, and nothing else
    /// can be done yet.
    fn before_running(&mut self, cmd: Option<Cmd>) -> Option<Cause> {
        match cmd {
            Some(Cmd::Stop(reply)) => {
                self.stops.push(reply);
                Some(Cause::Requested)
            }
            Some(Cmd::Mute { reply, .. }) => {
                let _ = reply.send(Err(CommandError::refused(
                    "this device is not holding a running voice call yet",
                )));
                None
            }
            None => Some(Cause::Requested),
        }
    }

    /// Looks at what the inbox holds without waiting for it.
    fn pending_cause(&mut self) -> Option<Cause> {
        while let Ok(cmd) = self.inbox.try_recv() {
            if let Some(cause) = self.before_running(Some(cmd)) {
                return Some(cause);
            }
        }
        None
    }

    /* ------------------------------------------------------------------------------------- */
    /* The start                                                                             */
    /* ------------------------------------------------------------------------------------- */

    pub(super) async fn start(&mut self, request: StartRequest) -> Result<Outcome> {
        self.started = Instant::now();
        self.requested = request.duration_seconds;
        let host = self.reach.in_use()?;
        self.host = Some(host.clone());
        self.generation = Some(self.pre_check().await?);
        // A stop that came while the token was checked gives the call up before anything is made.
        if self.pending_cause().is_some() {
            self.stop_native(HostEnd::NotNeeded).await;
            return Err(CommandError::unavailable(
                "The call was given up before it began.",
            ));
        }

        // The call is opened, which asks the person for the microphone.
        // Not interrupted: native code makes the call it is asked for, and a call made after the
        // caller gave up would have no owner. A stop that comes meanwhile waits in the inbox.
        let opened = match self.platform().open().await {
            Ok(opened) => opened,
            Err(failure) => return Err(self.open_failed(failure).await),
        };
        let call = opened.call.clone();
        self.call = Some(call.clone());
        self.events = Some(opened.events);
        self.shared.keep_for_emergency(
            self.id,
            Some(call.clone()),
            Some(&host),
            None,
            &self.reach,
            &self.tokens,
        );
        if let Some(cause) = self.pending_cause() {
            return self.abandon(cause).await;
        }

        let platform = self.platform();
        let offered = {
            let call = call.clone();
            self.wait(async move { platform.offer(&call).await }).await
        };
        let offer = match offered {
            Ok(Ok(offer)) => offer,
            Ok(Err(failure)) => {
                return self
                    .abandon(Cause::Step(format!(
                        "the offer could not be made ({failure})"
                    )))
                    .await;
            }
            Err(cause) => return self.abandon(cause).await,
        };
        if let Some(cause) = self.pending_cause() {
            return self.abandon(cause).await;
        }

        let params = VoiceStartParams {
            session_ids: request.session_ids.iter().copied().collect(),
            offer_sdp: offer,
            duration_seconds: request.duration_seconds,
            reasoning_budget_minor: Nullable::from(request.reasoning_budget_minor.map(U64::new)),
            prepared: request.prepared,
            expected_rate_version: Nullable::from(request.expected_rate_version.clone()),
        };
        let target = match request.subject.target(host.environment_id) {
            Ok(target) => target,
            Err(error) => {
                return self
                    .abandon_with(Cause::Step(error.message.clone()), error)
                    .await;
            }
        };
        let action_id = ActionId::new(kr_ipc::new_uuid());
        let composed = match host
            .session
            .compose(
                Method::VoiceStart,
                action_id,
                target,
                None,
                &NoPreconditions {},
                &params,
                MUTATION_TTL,
            )
            .await
        {
            Ok(composed) => composed,
            Err(error) => {
                return self
                    .abandon_with(
                        Cause::Step("the start could not be composed".to_owned()),
                        CommandError::from(error),
                    )
                    .await;
            }
        };

        // The send waits for the host for a bound of its own, after which its answer is taken as
        // lost and the host is asked what became of it. A stop that comes meanwhile waits in the
        // inbox and is read as soon as the answer is.
        // A grant the host made for this start ends by itself, at the latest, a call's length after
        // the last moment the host could still first admit the request: the end of the action
        // window it carries, on the host's own clock. A repeat can only be answered from the
        // host's record and is never an admission, so nothing later than that can create one.
        let until_ms = composed
            .window_issued_at_ms()
            .saturating_add(composed.window_valid_for_ms())
            .saturating_add(u64::from(self.requested) * 1000)
            .saturating_add(MAX_CLOCK_SKEW_MS);
        self.shared.keep_start_pending(self.id, action_id, until_ms);
        // From here the host may make a call, and a process that ends before the host answers
        // leaves it owed: the start, under the action it was sent under.
        self.shared
            .stand_open(self.id, OwedView::start_unknown(action_id, until_ms, &host));
        let start_within = self.shared.timings.start_within;
        let sent = match self
            .wait_through(tokio::time::timeout(
                start_within,
                host.session.send(&composed),
            ))
            .await
        {
            Ok(sent) => sent,
            Err(_) => Err(ClientError::SubmissionUncertain { action_id }),
        };
        let created = match sent {
            Ok(Settled::Result(value)) => {
                host.session.settle(action_id).await;
                match value.to_typed::<VoiceStartResult>() {
                    Ok(result) => Reached::Result(result),
                    Err(_) => Reached::Unknown,
                }
            }
            Ok(Settled::Receipt(receipt)) => {
                host.session.settle(action_id).await;
                Reached::Receipt(receipt)
            }
            Err(ClientError::SubmissionUncertain { .. } | ClientError::OutcomeUnknown { .. }) => {
                self.reconcile(&composed, &host, action_id).await
            }
            Err(error) => {
                host.session.settle(action_id).await;
                self.shared.answered(self.id);
                self.stop_native(HostEnd::NotNeeded).await;
                return Err(CommandError::from(error));
            }
        };

        let result = match created {
            Reached::Receipt(receipt) => {
                self.shared.answered(self.id);
                self.stop_native(HostEnd::NotNeeded).await;
                return Ok(Outcome::Over(Started::Receipt(receipt)));
            }
            Reached::Unknown => {
                let local = self
                    .stop_native(HostEnd::NotTold {
                        words: "The host never said whether it created the call, so a grant it \
                                made may still be open until the moment the call was to close."
                            .to_owned(),
                    })
                    .await;
                let owner = self.id;
                self.view(|state| {
                    state.running = false;
                    state.ended = Some(EndedView {
                        owner,
                        cause: "start_unknown".to_owned(),
                        words: if local {
                            "The host never said whether it created the call. Nothing is running \
                             on this device."
                                .to_owned()
                        } else {
                            "The host never said whether it created the call, and this device \
                             could not confirm that the call's media stopped."
                                .to_owned()
                        },
                        closed_locally: local,
                        host: HostEnd::NotTold {
                            words: "The host never said whether it created the call.".to_owned(),
                        },
                        // The service may hold a call this device cannot name.
                        broker: "unknown".to_owned(),
                    });
                });
                self.shared.record_end(
                    self.id,
                    vec![OwedView::start_unknown(action_id, until_ms, &host)],
                );
                self.shared.start_was_answered(self.id);
                return Ok(Outcome::Over(Started::Unknown { action_id }));
            }
            Reached::Result(result) => result,
        };
        let VoiceStartOutcome::Started { session } = &result.outcome else {
            self.shared.answered(self.id);
            self.stop_native(HostEnd::NotNeeded).await;
            return Ok(Outcome::Over(Started::Result(result)));
        };
        let descriptor = (**session).clone();
        self.descriptor = Some(descriptor.clone());
        self.shared.keep_for_emergency(
            self.id,
            Some(call.clone()),
            self.host.as_ref(),
            Some(&descriptor),
            &self.reach,
            &self.tokens,
        );
        // The host has made the call and named it: what the process owes the host is now the
        // revocation of its grant, for as long as the call runs.
        self.shared.stand_open(
            self.id,
            OwedView::revocation(
                // A process that stops while a call that may act runs cannot know whether a request
                // was written, so what it left says so.
                if self.accepting {
                    format!("{STANDING_WORDS} {REQUESTS_UNSETTLED}")
                } else {
                    STANDING_WORDS.to_owned()
                },
                descriptor.voice_session_id,
                owed_until(descriptor.closes_at_ms.get()),
                &host,
            ),
        );
        // The call can be named from here on: a stop that names it reaches this owner.
        let mut shown = descriptor.clone();
        shown.answer_sdp = String::new();
        self.view(|state| state.session = Some(shown));
        if let Some(cause) = self.cancelled.take().or_else(|| self.pending_cause()) {
            return self.abandon(cause).await;
        }
        self.go_live(descriptor, result).await
    }

    /// The setup after the host created the call: every way out of here ends the call.
    async fn go_live(
        &mut self,
        descriptor: VoiceSessionDescriptor,
        result: VoiceStartResult,
    ) -> Result<Outcome> {
        let call = self.call.clone().expect("a call is held");
        let service = self.shared.service.clone();

        // The service the control is opened at is the one the account is signed in at, whatever
        // the host said.
        let target = match ControlTarget::at(
            &service.origin,
            &descriptor.broker_origin,
            &descriptor.control_path,
            &descriptor.call_id,
        ) {
            Ok(target) => target,
            Err(_) if !same_origin(&service.origin, &descriptor.broker_origin) => {
                return self.abandon(Cause::ForeignService).await;
            }
            Err(_) => {
                return self
                    .abandon(Cause::Step(
                        "the host named a control address that is not the voice service's for this \
                         call"
                            .to_owned(),
                    ))
                    .await;
            }
        };
        // The device holds the call to the time it asked for, with room for a clock that is not
        // its own: a later closing time than that is held to, and one that is long past is not a
        // call to carry.
        let Some(closes) = hold_until(descriptor.closes_at_ms.get(), self.requested, now_ms())
        else {
            return self
                .abandon(Cause::Step(
                    "the host gave the call a closing time that has already passed".to_owned(),
                ))
                .await;
        };

        let platform = self.platform();
        let accepted = {
            let (call, sdp) = (call.clone(), descriptor.answer_sdp.clone());
            self.wait(async move { platform.accept(&call, &sdp).await })
                .await
        };
        match accepted {
            Ok(Ok(answered)) => {
                // The provider's encoder can hold back quiet speech while capture is on: a call
                // whose answer says so cannot vouch for what it did not hear.
                if self.accepting && answered.uses_dtx {
                    self.gate.dtx();
                    self.note_taint();
                }
            }
            Ok(Err(failure)) => {
                return self
                    .abandon(Cause::Step(format!(
                        "the answer could not be applied ({failure})"
                    )))
                    .await;
            }
            Err(cause) => return self.abandon(cause).await,
        }

        // What came meanwhile is heard before native code is allowed to carry the person's voice.
        if let Some(cause) = self.pending_cause() {
            return self.abandon(cause).await;
        }
        let platform = self.platform();
        let permitted = {
            let (call, id) = (call.clone(), descriptor.voice_session_id.to_string());
            self.wait(async move { platform.permit(&call, &id, closes).await })
                .await
        };
        match permitted {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => {
                return self
                    .abandon(Cause::Step("the call could not be permitted".to_owned()))
                    .await;
            }
            Ok(Err(failure)) => {
                return self
                    .abandon(Cause::Step(format!(
                        "the call could not be permitted ({failure})"
                    )))
                    .await;
            }
            Err(cause) => return self.abandon(cause).await,
        }

        let (control, control_events) = VoiceControl::open(
            &service.connector,
            target,
            Arc::clone(&self.tokens) as Arc<dyn AccountTokenSource>,
        );
        self.advice = Some(MuteAdvice::start(self.platform(), control.clone()));
        self.control = Some(control);
        self.control_events = Some(control_events);
        let remaining = Duration::from_millis(closes.saturating_sub(now_ms()));
        self.deadline = Box::pin(tokio::time::sleep_until(Instant::now() + remaining));
        if let Some(host) = &self.host {
            let session = Arc::clone(&host.session);
            self.host_closed = Box::pin(async move { session.closed().await });
        }
        let mut shown = descriptor.clone();
        shown.answer_sdp = String::new();
        self.view(|state| {
            state.running = true;
            state.session = Some(shown);
            // The control is opening its first socket: `unreachable` follows the first attempt that
            // fails, and `connected` the attachment.
            state.control = "connecting".to_owned();
            state.host = "reachable".to_owned();
            state.capture = "idle".to_owned();
        });
        // Whatever the page asked while the call was set up has been heard by now.
        if let Some(cause) = self.pending_cause() {
            return self.abandon(cause).await;
        }
        let mut answer = result;
        if let VoiceStartOutcome::Started { session } = &mut answer.outcome {
            session.answer_sdp = String::new();
        }
        Ok(Outcome::Live(Started::Result(answer)))
    }

    /// Checks that the account can give the voice token the control will present, before anything
    /// is created or asked, and returns which grant that is.
    async fn pre_check(&self) -> Result<String> {
        let tokens = Arc::clone(&self.tokens);
        // On a task of its own: a refresh that the caller going away interrupted could lose the
        // token it rotated.
        let asked = tokio::spawn(async move { tokens.token(VOICE_SCOPE).await.map(|_| ()) });
        match tokio::time::timeout(self.shared.timings.token_within, asked).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                return Err(
                    if error.code() == kr_protocol::error::ErrorCode::UpstreamUnavailable {
                        CommandError::unavailable(
                            "This device could not reach the account service, so it cannot tell \
                         whether it could control a call. No call was started.",
                        )
                    } else {
                        CommandError::refused(format!(
                            "This device has no account token for voice, so it could not control a \
                         call. No call was started. {error}"
                        ))
                    },
                );
            }
            Ok(Err(_)) | Err(_) => {
                return Err(CommandError::unavailable(
                    "This device could not get its account's voice token in time. No call was \
                     started.",
                ));
            }
        }
        match self.tokens.status() {
            Ok(AccountStatus::SignedIn { generation, .. }) => Ok(generation),
            _ => Err(CommandError::refused(
                "No account is signed in on this device, so no call was started.",
            )),
        }
    }

    /// What a call that native code would not open is told as, and whatever native code may have
    /// made after all is stopped.
    async fn open_failed(&mut self, failure: CallFailure) -> CommandError {
        // Cleaning up has begun, and the screen is told so before native code is asked anything.
        let id = self.id;
        self.view(|state| state.begin_ending(id));
        let error = match failure.kind {
            FailureKind::MicrophoneRefused => CommandError::refused(
                "Kala Reach has no permission to use the microphone, so no call was started. \
                 Allow it in this device's settings.",
            ),
            FailureKind::AlreadyRunning => CommandError::refused(
                "This device already holds a voice call, so no other was started.",
            ),
            _ => CommandError::unavailable(format!(
                "The call could not be opened on this device ({failure})"
            )),
        };
        let mut local = true;
        if matches!(failure.kind, FailureKind::Unavailable | FailureKind::Engine) {
            // Native code may yet make the call it was asked for: whatever it holds is stopped.
            // What it holds that cannot be read is not known to be nothing.
            match self.platform().held().await {
                Ok(held) => {
                    if let Some(call) = held.call {
                        local = self.stop_media(&call).await;
                    }
                }
                Err(_) => local = false,
            }
        }
        self.media_stopped = Some(local);
        error
    }

    /// Ends the call for `cause` and says why to whoever started it.
    async fn abandon(&mut self, cause: Cause) -> Result<Outcome> {
        let error = match &cause {
            Cause::Requested => CommandError::unavailable("The call was given up before it began."),
            other => CommandError::unavailable(other.words()),
        };
        self.abandon_with(cause, error).await
    }

    async fn abandon_with(&mut self, cause: Cause, error: CommandError) -> Result<Outcome> {
        self.end(cause).await;
        Err(error)
    }

    /// Stops the call's media before the end procedure has anything to revoke, and answers the
    /// stops waiting with `host` as what the host did. Says whether native code stopped the media:
    /// a stop it does not return from, or refuses, is not a stop. A call native code has already
    /// ended is stopped.
    async fn stop_native(&mut self, host: HostEnd) -> bool {
        self.view(|state| state.begin_ending(self.id));
        let local = match self.call.take() {
            Some(call) => self.stop_media(&call).await,
            None => self.media_stopped.unwrap_or(true),
        };
        self.media_stopped = Some(local);
        self.events = None;
        let closed = Closed { local, host };
        for reply in self.stops.drain(..) {
            let _ = reply.send(closed.clone());
        }
        self.close_inbox(&closed);
        local
    }

    /// Closes the inbox, so that a command sent from now on is turned away at once and a sender
    /// waiting for room is let go, and answers what it holds: a stop gets what the end came to, and
    /// a mute is told there is no call.
    fn close_inbox(&mut self, closed: &Closed) {
        self.inbox_gone = true;
        answer_and_close(&mut self.inbox, closed);
    }

    /// Learns what became of a start whose answer was lost, under the action it was sent under.
    ///
    /// A repeat is a question and not a second request: the host answers it from the record it
    /// kept of the action, on a connection other than the one that sent it, or does not answer
    /// it. What an answer other than a result says proves nothing about the original, which the
    /// host can still read until its window ends, so only a result settles a start; anything else
    /// leaves it unknown, and the person is told so.
    ///
    /// The questions are asked through to the end whatever the person does meanwhile: a stop
    /// stops the media at once and is answered, and the question goes on, because the host may
    /// have made a call that only its answer can name.
    async fn reconcile(
        &mut self,
        composed: &ComposedMutation,
        host: &CallHost,
        action_id: ActionId,
    ) -> Reached {
        let delays = self.shared.timings.repeat_delays;
        let within = self.shared.timings.host_within;
        let mut reached = Reached::Unknown;
        'asking: for delay in delays {
            self.wait_through(tokio::time::sleep(delay)).await;
            let reach = Arc::clone(&self.reach);
            let paired = host.paired.clone();
            let original = Arc::clone(&host.session);
            let session = match self
                .wait_through(async move { reach.session_to(&paired, Some(&original)).await })
                .await
            {
                Ok(session) => session,
                Err(_) => continue,
            };
            let asking = session.repeat(composed);
            let answered = self
                .wait_through(async move { tokio::time::timeout(within, asking).await })
                .await;
            match answered {
                Ok(Ok(Settled::Result(value))) => {
                    if let Ok(result) = value.to_typed::<VoiceStartResult>() {
                        // The call the host made goes on under the connection that heard of it.
                        if let Some(held) = self.host.as_mut() {
                            held.session = Arc::clone(&session);
                        }
                        session.settle(action_id).await;
                        reached = Reached::Result(result);
                        break 'asking;
                    }
                }
                // A receipt is a lost answer again, and a refusal says nothing of the original.
                Ok(Ok(Settled::Receipt(_)) | Err(_)) | Err(_) => {}
            }
            session.settle(action_id).await;
        }
        host.session.settle(action_id).await;
        reached
    }

    /* ------------------------------------------------------------------------------------- */
    /* The running call                                                                      */
    /* ------------------------------------------------------------------------------------- */

    pub(super) async fn running(&mut self) {
        let mut tick = tokio::time::interval(self.shared.timings.tick);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tick.tick().await;
        loop {
            let cause = tokio::select! {
                cmd = self.inbox.recv() => self.on_command(cmd),
                heard = next_heard(&mut self.events) => self.on_heard(heard).await,
                news = next_news(&mut self.control_events) => self.on_news(news),
                internal = self.internal.recv() => self.on_internal(internal),
                _ = tick.tick() => self.on_tick(),
                () = &mut self.collection_due, if !self.collections.is_empty() || !self.sealing.is_empty() => {
                    self.on_collection_due();
                    None
                }
                () = &mut self.deadline => Some(Cause::Deadline),
                changed = self.account.changed() => self.on_account(changed.is_ok()),
                () = &mut self.host_closed => self.on_host_closed(),
            };
            if let Some(cause) = cause {
                self.end(cause).await;
                return;
            }
        }
    }

    fn on_command(&mut self, cmd: Option<Cmd>) -> Option<Cause> {
        match cmd {
            Some(Cmd::Stop(reply)) => {
                self.stops.push(reply);
                Some(Cause::Requested)
            }
            Some(Cmd::Mute { what, muted, reply }) => {
                self.mute(what, muted, reply);
                None
            }
            None => Some(Cause::Requested),
        }
    }

    /// Silences the microphone or the model's voice on this device; the voice service is told of a
    /// microphone's mute as well, which is advice to the provider and not the mute itself, and which
    /// follows the mute whichever control made it ([`MuteAdvice`]).
    fn mute(&self, what: Mute, muted: bool, reply: oneshot::Sender<Result<VoiceCallState>>) {
        let Some(call) = self.call.clone() else {
            let _ = reply.send(Err(CommandError::refused(
                "this device is not holding a voice call",
            )));
            return;
        };
        let platform = self.platform();
        let shared = Arc::clone(&self.shared);
        let advice = self.advice.as_ref().map(MuteAdvice::waker);
        tokio::spawn(async move {
            match platform.mute(&call, what, muted).await {
                Err(failure) => {
                    let _ = reply.send(Err(CommandError::unavailable(format!(
                        "that could not be done to the call ({failure})"
                    ))));
                }
                Ok(()) => {
                    if let Ok(held) = platform.held().await {
                        let mut view = shared.view.lock().expect("the view lock is not poisoned");
                        view.capture = capture_word(held.capture);
                        view.playing = held.playing;
                    }
                    let _ = reply.send(Ok(shared
                        .view
                        .lock()
                        .expect("the view lock is not poisoned")
                        .clone()));
                    // The service is told after the person has their answer: it is advice to the
                    // provider, and the mute does not wait for it.
                    if what == Mute::Microphone
                        && let Some(advice) = advice
                    {
                        advice.notify_one();
                    }
                }
            }
        });
    }

    /// What native code's news says of the call, and whether it ends it.
    async fn on_heard(&mut self, heard: Option<Heard>) -> Option<Cause> {
        match heard {
            None | Some(Heard::Event(CallEvent::Ended)) => Some(Cause::NativeEnded),
            Some(Heard::Event(CallEvent::Connection { state })) => {
                if state == ConnectionState::Failed {
                    return Some(Cause::NativeFailed);
                }
                None
            }
            Some(Heard::Event(CallEvent::Capture { state })) => {
                if self.accepting {
                    if state == CaptureState::Capturing {
                        self.gate.capture_is_on();
                    } else {
                        let told = self.gate.capture_is_off();
                        self.after_gate(told);
                    }
                }
                self.view(|view| view.capture = capture_word(state));
                // The change may be the person's own mute from a control of the phone.
                if let Some(advice) = &self.advice {
                    advice.changed();
                }
                None
            }
            Some(Heard::Event(CallEvent::Playout)) => {
                // The first audio played out, from the start of the call to this receipt.
                let elapsed = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
                self.view(|state| {
                    state.first_audio_ms.get_or_insert(elapsed);
                });
                None
            }
            // What the provider's data channel said reaches the gate when spoken requests may reach
            // the host, and is not read at all otherwise.
            Some(Heard::Event(CallEvent::ProviderEvent { bytes })) => {
                if self.accepting {
                    let read = provider::read(&bytes);
                    if let provider::Provider::Other { kind } = &read {
                        tracing::debug!(%kind, "the provider sent an event the gate does not read");
                    }
                    let told = self.gate.provider(read);
                    self.after_gate(told);
                }
                None
            }
            // A barrier marks a place in the news for whoever asked for a capture proof. It says
            // nothing of the call.
            Some(Heard::Event(CallEvent::Barrier { token })) => {
                if self.accepting {
                    self.barrier_read(token);
                }
                None
            }
            Some(Heard::Event(CallEvent::Lost)) => None,
            // News was lost, and what was lost can be the end of the call: ask native code what
            // it holds rather than carry on as if nothing had been missed.
            Some(Heard::Lost) => {
                if self.accepting {
                    let told = self.gate.lost();
                    self.after_gate(told);
                }
                self.verify_native().await
            }
        }
    }

    async fn verify_native(&self) -> Option<Cause> {
        let call = self.call.clone()?;
        match self.platform().held().await {
            Ok(held) if held.call.as_ref() == Some(&call) => None,
            Ok(_) => Some(Cause::NativeGone),
            Err(failure)
                if matches!(failure.kind, FailureKind::Ended | FailureKind::NoSuchCall) =>
            {
                Some(Cause::NativeGone)
            }
            Err(_) => None,
        }
    }

    fn on_account(&mut self, open: bool) -> Option<Cause> {
        if !open {
            return None;
        }
        match self.tokens.status() {
            Ok(AccountStatus::SignedIn { generation, .. })
                if Some(&generation) == self.generation.as_ref() =>
            {
                None
            }
            // A store that cannot be read says nothing of the account.
            Err(_) => None,
            Ok(_) => Some(Cause::AccountChanged),
        }
    }

    fn on_news(&mut self, news: Option<ControlNews>) -> Option<Cause> {
        match news {
            None => Some(Cause::Control(ControlEnd::Unreachable)),
            Some(ControlNews::Ended(end)) => Some(Cause::Control(end)),
            Some(ControlNews::Detached) => {
                self.view(|state| state.control = "unreachable".to_owned());
                None
            }
            Some(ControlNews::Attached { delegations, .. }) => {
                self.view(|state| state.control = "connected".to_owned());
                // A mute told while no socket was open was lost, and the service starts unmuted.
                if let Some(advice) = &self.advice {
                    advice.changed();
                }
                self.shared.clear_note();
                if !self.attached_before {
                    self.attached_before = true;
                    self.tell_model(
                        VoiceCommand::Instructions,
                        None,
                        if self.accepting {
                            HOST_ACTIONS_AVAILABLE
                        } else {
                            HOST_ACTIONS_UNAVAILABLE
                        },
                    );
                    self.give_the_host_context();
                    // A call that was tainted before its control attached tells the model now.
                    if self.taint_told {
                        self.tell_model(VoiceCommand::Instructions, None, SPEECH_TAINTED);
                    }
                }
                for delegation_id in delegations {
                    self.answer_delegation(delegation_id, None);
                }
                None
            }
            Some(ControlNews::Event(
                kr_client::services::voice::VoiceControlEvent::Delegation {
                    delegation_id,
                    offset_ms,
                },
            )) => {
                self.answer_delegation(delegation_id, Some(offset_ms));
                None
            }
            Some(ControlNews::Event(_)) => None,
        }
    }

    /// Says to the model, once for each delegation, that nothing was done about it, and keeps a
    /// row the screen shows.
    fn answer_delegation(&mut self, delegation_id: String, offset_ms: Option<u64>) {
        // The voice service's announcement only says which delegations it knows, and where: the
        // answer to the person and to the model is what the data channel's delegation comes to.
        if self.accepting {
            #[cfg(any(test, feature = "testing"))]
            let read = delegation_id.clone();
            self.announce(delegation_id, offset_ms);
            #[cfg(any(test, feature = "testing"))]
            self.shared.handled.announcement(read, offset_ms);
            return;
        }
        if self.answered.contains(&delegation_id) {
            return;
        }
        self.answered.push_back(delegation_id.clone());
        if self.answered.len() > ANSWERED {
            self.answered.pop_front();
        }
        self.view(|state| {
            state.delegations.push(DelegationRow {
                delegation_id: delegation_id.clone(),
                offset_ms,
                state: "not_done".to_owned(),
                told: false,
                cause: None,
            });
            if state.delegations.len() > ANSWERED {
                state.delegations.remove(0);
            }
        });
        let Some(control) = self.control.clone() else {
            return;
        };
        let internal = self.internal_tx.clone();
        tokio::spawn(async move {
            let told = control
                .send(
                    VoiceCommand::Commentary,
                    Some(&delegation_id),
                    Some(NOTHING_WAS_DONE),
                )
                .await
                .is_ok();
            let _ = internal.send(Internal::Told {
                delegation_id,
                told,
            });
        });
    }

    /// Gives the call the host's default context, once, as the control first attaches.
    ///
    /// The host selects it (capped, with what is excluded left out, secrets replaced) and the
    /// control sends exactly that selection as the call's opening context, as project text and not
    /// as instructions. A call over several sessions is given the first session's. On a task of
    /// its own so that nothing waits for the host or the service.
    fn give_the_host_context(&mut self) {
        let (Some(control), Some(host), Some(descriptor)) = (
            self.control.clone(),
            self.host.clone(),
            self.descriptor.clone(),
        ) else {
            return;
        };
        let Some(session_id) = descriptor.session_ids.iter().next().copied() else {
            return;
        };
        let (internal, within) = (self.internal_tx.clone(), self.shared.timings.host_within);
        self.opening = Some(tokio::spawn(async move {
            let params = VoiceContextParams {
                voice_session_id: descriptor.voice_session_id,
                session_id,
                selected: kr_protocol::scalars::CanonicalSet::new(),
                delegation_id: Nullable::null(),
            };
            let opened = match tokio::time::timeout(
                within,
                host.session
                    .read::<_, kr_protocol::voice::VoiceContextResult>(
                        Method::VoiceContext,
                        &params,
                    ),
            )
            .await
            {
                Ok(Ok(read)) => Opened::of(&control.send_call_start_context(&read.selection).await),
                _ => Opened::NotRead,
            };
            let _ = internal.send(Internal::Opened(opened));
        }));
    }

    /// Takes what giving the call the host's context came to: it goes on without what it was not
    /// given, and the call's record says so, for the person who reads it while the call runs and
    /// after it.
    fn note_the_opening(&mut self, opened: &Opened) {
        self.opening = None;
        if let Some((why, words)) = opened.problem() {
            tracing::warn!("the call was not given its opening context: {why}");
            self.view(|state| state.meet(ProblemKind::OpeningContext, words));
        }
    }

    /// Settles the opening context as the call ends. A task that is still running is stopped and
    /// awaited first, so that what it reported is in the channel and nothing follows it; then what
    /// was reported is taken, and a task that had not reported was cut short by the end.
    async fn settle_the_opening(&mut self) {
        for opened in what_the_opening_came_to(&mut self.opening, &mut self.internal).await {
            self.note_the_opening(&opened);
        }
    }

    /// Tells the model a fixed sentence, on a task of its own so that nothing waits for it.
    fn tell_model(&self, command: VoiceCommand, delegation: Option<String>, text: &'static str) {
        let Some(control) = self.control.clone() else {
            return;
        };
        tokio::spawn(async move {
            let _ = control
                .send(command, delegation.as_deref(), Some(text))
                .await;
        });
    }

    fn on_internal(&mut self, message: Option<Internal>) -> Option<Cause> {
        match message? {
            Internal::Alive(Ok(held)) => {
                self.silent_signs = 0;
                if held.call.as_ref() != self.call.as_ref() {
                    return Some(Cause::NativeGone);
                }
                self.view(|state| {
                    state.capture = capture_word(held.capture);
                    state.playing = held.playing;
                });
                None
            }
            Internal::Alive(Err(failure)) => {
                if matches!(failure.kind, FailureKind::Ended | FailureKind::NoSuchCall) {
                    return Some(Cause::NativeGone);
                }
                self.silent_signs += 1;
                (self.silent_signs >= self.shared.timings.silent_signs)
                    .then_some(Cause::NativeSilent)
            }
            Internal::Told {
                delegation_id,
                told,
            } => {
                self.view(|state| {
                    if let Some(row) = state
                        .delegations
                        .iter_mut()
                        .find(|row| row.delegation_id == delegation_id)
                    {
                        row.told = told;
                    }
                });
                None
            }
            Internal::Opened(opened) => {
                // The call goes on without what it was not given.
                self.note_the_opening(&opened);
                None
            }
            Internal::Proof { id, result } => {
                self.on_proof(&id, result);
                #[cfg(any(test, feature = "testing"))]
                self.shared.handled.proof(&id);
                None
            }
            Internal::Delivered { id, exchange } => {
                self.on_delivered(&id, *exchange);
                None
            }
            Internal::Ceremony {
                id,
                generation,
                outcome,
            } => {
                self.on_ceremony(&id, generation, outcome);
                None
            }
            Internal::SealProof {
                id,
                generation,
                result,
            } => {
                self.on_seal_proof(&id, generation, result);
                #[cfg(any(test, feature = "testing"))]
                self.shared.handled.seal(&id);
                None
            }
            Internal::Asked { id, result } => {
                self.on_asked(&id, result.map(|boxed| *boxed));
                None
            }
            Internal::Probed(probe) => {
                match probe {
                    Probe::Back(session) => {
                        self.host_back(&session);
                    }
                    // The host answered a refusal: it may not know the call, or may not let this
                    // device read what the probe reads. It is reached, and not known to be back.
                    Probe::Refused(words) => {
                        let problem = format!(
                            "The host answered but would not say the call is still its own: {words}"
                        );
                        self.probe_after =
                            Some(Instant::now() + self.shared.timings.tick * PROBE_PAUSE_TICKS);
                        self.view(|state| state.meet(ProblemKind::HostPath, problem));
                    }
                    Probe::Unreached => {}
                }
                self.probing = false;
                None
            }
        }
    }

    /// The host is reached again, on `session`.
    fn host_back(&mut self, session: &Arc<Session>) {
        if let Some(host) = self.host.as_mut() {
            host.session = Arc::clone(session);
        }
        let watched = Arc::clone(session);
        self.host_closed = Box::pin(async move { watched.closed().await });
        self.host_lost = false;
        self.probe_after = None;
        // The refusal that stood while the host was out of reach is over with it.
        self.view(|state| {
            state.host = "reachable".to_owned();
            state.pass(ProblemKind::HostPath);
        });
        if self.accepting {
            // What was not written before the loss stays unwritten; what may have been is asked
            // about again, now that there is a connection to ask on.
            self.unsent = Arc::new(AtomicBool::new(self.gate.taint().is_some()));
            self.tell_model(VoiceCommand::Instructions, None, HOST_BACK_ACCEPTING);
            self.ask_after_attempts();
        } else {
            self.tell_model(VoiceCommand::Instructions, None, HOST_BACK);
        }
    }

    fn on_host_closed(&mut self) -> Option<Cause> {
        self.host_closed = Box::pin(std::future::pending());
        if !self.host_lost {
            self.host_lost = true;
            self.view(|state| state.host = "lost".to_owned());
            self.tell_model(VoiceCommand::Instructions, None, HOST_LOST);
            if self.accepting {
                self.host_path_lost();
            }
        }
        None
    }

    fn on_tick(&mut self) -> Option<Cause> {
        if let Some(host) = &self.host {
            // A call belongs to the host that made it: it ends when this device forgets that host
            // and when the person chooses another.
            if self.reach.pairing(&host.paired) == Pairing::Gone {
                return Some(Cause::HostForgotten);
            }
            if self.reach.another_host_in_use(&host.paired) {
                return Some(Cause::HostChanged);
            }
        }
        if let Some(call) = self.call.clone() {
            let (platform, internal) = (self.platform(), self.internal_tx.clone());
            tokio::spawn(async move {
                let _ = internal.send(Internal::Alive(platform.alive(&call).await));
            });
        }
        let paused = self.probe_after.is_some_and(|after| Instant::now() < after);
        if self.host_lost
            && !self.probing
            && !paused
            && let (Some(host), Some(descriptor)) = (self.host.clone(), self.descriptor.clone())
        {
            self.probing = true;
            let (reach, internal) = (Arc::clone(&self.reach), self.internal_tx.clone());
            let within = self.shared.timings.host_within;
            tokio::spawn(async move {
                let probe = probe_host(reach, host, descriptor, within).await;
                let _ = internal.send(Internal::Probed(probe));
            });
        }
        None
    }

    /* ------------------------------------------------------------------------------------- */
    /* Spoken delegations                                                                    */
    /* ------------------------------------------------------------------------------------- */

    /// Acts on what the gate made of one message of the provider's data channel.
    fn after_gate(&mut self, told: Told) {
        self.note_taint();
        match told {
            Told::Delegation { id, offset_ms } => self.begin_collection(id, offset_ms),
            Told::Late => self.cancel_challenges(),
            Told::Nothing | Told::Tainted(_) => {}
        }
    }

    /// Ends what the call can still hand to the host, once the gate says it is tainted: each
    /// delegation still waiting is refused for the cause, nothing not yet written is written, and
    /// the person and the model are told once.
    fn note_taint(&mut self) {
        let Some(why) = self.gate.taint() else {
            return;
        };
        self.unsent.store(true, Ordering::SeqCst);
        let waiting: Vec<Collection> = self.collections.drain(..).collect();
        for collection in waiting {
            self.refuse(&collection.id, why);
        }
        self.cancel_confirmations(why);
        self.arm_collection();
        if self.taint_told {
            return;
        }
        self.taint_told = true;
        self.view(|state| {
            state.meet(
                ProblemKind::SpokenRequests,
                SPEECH_TAINTED_PERSON.to_owned(),
            )
        });
        self.tell_model(VoiceCommand::Instructions, None, SPEECH_TAINTED);
    }

    /// Changes the row of the delegation `id`: what became of it, and why.
    fn set_row(&self, id: &str, what: &str, cause: Option<&str>) {
        let (id, what, cause) = (id.to_owned(), what.to_owned(), cause.map(str::to_owned));
        self.view(|state| {
            if let Some(row) = state
                .delegations
                .iter_mut()
                .find(|row| row.delegation_id == id)
            {
                row.state = what;
                row.cause = cause;
                row.told = false;
            }
        });
    }

    /// Tells the model what became of the delegation `id`, by a request of its own.
    fn tell_delegation(&self, id: &str, text: String) {
        let Some(control) = self.control.clone() else {
            return;
        };
        let (id, internal) = (id.to_owned(), self.internal_tx.clone());
        tokio::spawn(async move {
            let told = control
                .send(VoiceCommand::Commentary, Some(&id), Some(&text))
                .await
                .is_ok();
            let _ = internal.send(Internal::Told {
                delegation_id: id,
                told,
            });
        });
    }

    /// This device would not hand the delegation `id` to the host, for `why`.
    fn refuse(&self, id: &str, why: Why) {
        self.set_row(id, "refused", Some(why.word()));
        self.tell_delegation(
            id,
            if why.taints() {
                SPEECH_TAINTED
            } else {
                DELEGATION_REFUSED
            }
            .to_owned(),
        );
    }

    /// Nothing of the delegation `id` was written to the host, for `why`.
    fn not_sent(&self, id: &str, why: Why) {
        self.set_row(id, "not_sent", Some(why.word()));
        self.tell_delegation(
            id,
            if why.taints() {
                SPEECH_TAINTED
            } else {
                DELEGATION_NOT_SENT
            }
            .to_owned(),
        );
    }

    /// The voice service says it announced the delegation `id`, at `offset_ms` when it said where.
    fn announce(&mut self, id: String, offset_ms: Option<u64>) {
        let now = Instant::now();
        if let Some(known) = self.announced.iter_mut().find(|(known, _)| *known == id) {
            // A list that names no offset never takes one away, and the same offset said again is
            // the one read first: it is not later for being said twice.
            if let Some(offset) = offset_ms
                && known.1.is_none_or(|(held, _)| held != offset)
            {
                known.1 = Some((offset, now));
            }
            return;
        }
        self.announced
            .push_back((id, offset_ms.map(|offset| (offset, now))));
        if self.announced.len() > ANSWERED {
            self.announced.pop_front();
        }
    }

    /// The offset the voice service announced the delegation `id` at, when it did so by `due`: an
    /// announcement read after the wait ended is not one the set was vouched for within.
    fn announced_offset(&self, id: &str, due: Instant) -> Option<u64> {
        self.announced
            .iter()
            .find(|(known, _)| known == id)
            .and_then(|(_, said)| *said)
            .and_then(|(offset, read)| (read <= due).then_some(offset))
    }

    /// The provider announced a delegation on its data channel: a row for it, and the wait for what
    /// was said before it to arrive.
    fn begin_collection(&mut self, id: String, offset_ms: u64) {
        let shown = id.clone();
        self.view(|state| {
            state.delegations.push(DelegationRow {
                delegation_id: shown,
                offset_ms: Some(offset_ms),
                state: "collecting".to_owned(),
                told: false,
                cause: None,
            });
            if state.delegations.len() > ANSWERED {
                state.delegations.remove(0);
            }
        });
        if let Some(why) = self.gate.taint() {
            self.refuse(&id, why);
            return;
        }
        if self.host_lost {
            self.gate.abandon(offset_ms);
            self.not_sent(&id, Why::HostLost);
            return;
        }
        let due = Instant::now() + self.shared.timings.delegation_wait;
        self.collections.push_back(Collection {
            id,
            offset_ms,
            due,
            stage: Stage::Waiting,
        });
        self.arm_collection();
    }

    /// Sets the timer to the moment the first collection needs the owner next.
    fn arm_collection(&mut self) {
        let next = self
            .collections
            .front()
            .map(|collection| match collection.stage {
                Stage::Waiting => collection.due,
                Stage::Draining { until, .. } => until,
            })
            .into_iter()
            .chain(self.sealing.iter().map(|sealing| sealing.until))
            .min();
        self.collection_due.as_mut().reset(
            next.unwrap_or_else(|| Instant::now() + Duration::from_secs(60 * 60 * 24 * 365)),
        );
    }

    /// The first collection's time has come: it asks native code for a capture proof with a marker,
    /// or, when it has been waiting for the marker too long, is refused as not drained.
    fn on_collection_due(&mut self) {
        let (platform, internal, drain) = (
            self.platform(),
            self.internal_tx.clone(),
            self.shared.timings.drain_within,
        );
        let call = self.call.clone();
        self.expire_sealing();
        let Some(head) = self.collections.front_mut() else {
            self.arm_collection();
            return;
        };
        let now = Instant::now();
        match head.stage {
            Stage::Waiting if now >= head.due => {
                head.stage = Stage::Draining {
                    token: None,
                    record: None,
                    until: now + drain,
                };
                if let Some(call) = call {
                    let id = head.id.clone();
                    tokio::spawn(async move {
                        let result = platform.capture_proof(&call, true).await;
                        let _ = internal.send(Internal::Proof { id, result });
                    });
                }
            }
            Stage::Draining { until, .. } if now >= until => {
                if let Some(late) = self.collections.pop_front() {
                    self.gate.abandon(late.offset_ms);
                    self.refuse(&late.id, Why::NotDrained);
                }
            }
            _ => {}
        }
        self.arm_collection();
    }

    /// Native code answered the proof the first collection asked for.
    fn on_proof(&mut self, id: &str, result: std::result::Result<CaptureProof, CallFailure>) {
        // What a proof of this call shows of capture taints the call at once, whether or not the
        // delegation that asked for it still waits, and before the news is read up to its marker:
        // a request waiting for the connection's turn under an earlier, clean proof is then never
        // written. The marker is what a set is accepted by, not what a break is refused by.
        if let Ok(proof) = &result
            && Some(&proof.call) == self.call.as_ref()
        {
            let told = self.gate.note_record(Record::of(proof));
            self.after_gate(told);
        }
        let Some(position) = self.collections.iter().position(|collection| {
            collection.id == id && matches!(collection.stage, Stage::Draining { .. })
        }) else {
            return;
        };
        match result {
            Ok(proof) if Some(&proof.call) == self.call.as_ref() && proof.barrier.is_some() => {
                if let Stage::Draining { token, record, .. } = &mut self.collections[position].stage
                {
                    *token = proof.barrier;
                    *record = Some(Record::of(&proof));
                }
                self.try_finish();
            }
            _ => {
                if let Some(collection) = self.collections.remove(position) {
                    self.gate.abandon(collection.offset_ms);
                    self.refuse(&collection.id, Why::NoProof);
                }
                self.arm_collection();
            }
        }
    }

    /// The news was read up to the marker `token`.
    fn barrier_read(&mut self, token: u64) {
        self.barriers.push_back(token);
        if self.barriers.len() > 16 {
            self.barriers.pop_front();
        }
        self.try_finish();
        self.try_seal();
    }

    /// Freezes the first collection's set once its proof's record and the news up to its marker are
    /// both in hand: everything native code had told before the proof was read has been read.
    fn try_finish(&mut self) {
        let now = Instant::now();
        let ready = self
            .collections
            .front()
            .is_some_and(|collection| collection.stage.may_freeze(&self.barriers, now));
        if !ready {
            return;
        }
        if let Some(Collection {
            id,
            offset_ms,
            due,
            stage:
                Stage::Draining {
                    record: Some(record),
                    ..
                },
        }) = self.collections.pop_front()
        {
            self.finish(&id, offset_ms, due, record);
        }
        self.arm_collection();
    }

    /// Freezes the set of the delegation `id`, and hands it to the host or refuses it.
    fn finish(&mut self, id: &str, offset_ms: u64, due: Instant, record: Record) {
        let announced = self.announced_offset(id, due);
        let frozen = self.gate.freeze(offset_ms, record, announced);
        self.note_taint();
        match frozen {
            Frozen::Refused(why) => self.refuse(id, why),
            Frozen::Set(fragments) => self.hand_over(id, offset_ms, &fragments),
        }
    }

    /// Hands a frozen set to the host on a task of its own, so that nothing waits for it.
    fn hand_over(&mut self, id: &str, offset_ms: u64, fragments: &[provider::Fragment]) {
        let (Some(host), Some(descriptor), Some(call)) = (
            self.host.clone(),
            self.descriptor.clone(),
            self.call.clone(),
        ) else {
            self.not_sent(id, Why::NotComposed);
            return;
        };
        let built: Option<VoiceDelegateParams> = (|| {
            let fragments = fragments
                .iter()
                .map(|fragment| {
                    Some(TranscriptFragment {
                        start_ms: U64::new(fragment.start_ms),
                        end_ms: U64::new(fragment.end_ms),
                        text: FragmentText::new(fragment.text.clone()).ok()?,
                    })
                })
                .collect::<Option<Vec<_>>>()?;
            Some(VoiceDelegateParams {
                voice_session_id: descriptor.voice_session_id,
                delegation_id: VoiceDelegationId::new(id).ok()?,
                offset_ms: U64::new(offset_ms),
                fragments,
                confirmation: Nullable::null(),
            })
        })();
        let Some(params) = built.filter(|params| params.check_fragments().is_ok()) else {
            self.refuse(id, Why::TooLarge);
            return;
        };
        self.set_row(id, "asking", None);
        self.unsettled.insert(id.to_owned());
        let handover = Handover {
            host,
            platform: self.platform(),
            call,
            action_id: None,
            params,
            age_bound: self.shared.timings.proof_age,
            within: self.shared.timings.host_within,
            lost: Arc::clone(&self.unsent),
        };
        let (internal, id) = (self.internal_tx.clone(), id.to_owned());
        tokio::spawn(async move {
            let exchange = hand_over(handover).await;
            let _ = internal.send(Internal::Delivered {
                id,
                exchange: Box::new(exchange),
            });
        });
    }

    /// What came of handing the delegation `id` to the host.
    fn on_delivered(&mut self, id: &str, exchange: Exchange) {
        let Exchange {
            session,
            composed,
            delivered,
            ..
        } = exchange;
        match delivered {
            Delivered::Result(result) => self.host_answered(id, *result, composed),
            Delivered::Refused => {
                self.unsettled.remove(id);
                self.set_row(id, "host_refused", Some("host_answer"));
                self.tell_delegation(id, DELEGATION_HOST_REFUSED.to_owned());
            }
            // A receipt shows that the host holds the action and never what became of it, so it is
            // no decision: the person and the model are told it is not known.
            Delivered::Receipt => {
                self.set_row(id, "unknown", Some("receipt"));
                self.tell_delegation(id, DELEGATION_UNKNOWN.to_owned());
            }
            Delivered::Withheld(why) => {
                self.unsettled.remove(id);
                let why = self.gate.taint().unwrap_or(why);
                self.not_sent(id, why);
            }
            Delivered::Tainted(why) => {
                self.unsettled.remove(id);
                self.gate.taint_with(why);
                self.note_taint();
                self.not_sent(id, why);
            }
            Delivered::Unknown => {
                self.set_row(id, "unknown", None);
                self.tell_delegation(id, DELEGATION_UNKNOWN.to_owned());
                if let Some(composed) = composed {
                    self.attempts.insert(
                        id.to_owned(),
                        Attempt {
                            session,
                            composed,
                            asking: false,
                        },
                    );
                    self.ask_about(id);
                }
            }
        }
    }

    /// The host answered, once, with a result. `composed` is the request the answer is to, as it
    /// was composed, when there is one.
    fn host_answered(
        &mut self,
        id: &str,
        result: VoiceDelegateResult,
        composed: Option<ComposedMutation>,
    ) {
        if let VoiceDelegationOutcome::ConfirmationRequired { request, .. } = &result.outcome {
            let request = request.as_ref().clone();
            self.on_challenge(id, result, request, composed);
            return;
        }
        let (what, cause, told) = answered_as(&result.outcome);
        if may_have_been_carried_out(what) {
            self.unsettled.insert(id.to_owned());
        } else {
            self.unsettled.remove(id);
        }
        self.set_row(id, what, cause);
        self.tell_delegation(id, told);
    }

    /// Asks the host what became of the delegation `id`, on a task of its own, with the request
    /// as it was composed and on a connection other than the one that wrote it.
    fn ask_about(&mut self, id: &str) {
        let Some(host) = self.host.clone() else {
            return;
        };
        let Some(attempt) = self.attempts.get_mut(id) else {
            return;
        };
        if attempt.asking {
            return;
        }
        attempt.asking = true;
        let mut host = host;
        host.session = Arc::clone(&attempt.session);
        let composed = attempt.composed.clone();
        let (reach, internal, id) = (
            Arc::clone(&self.reach),
            self.internal_tx.clone(),
            id.to_owned(),
        );
        let (delays, within) = (
            self.shared.timings.repeat_delays,
            self.shared.timings.host_within,
        );
        tokio::spawn(async move {
            let result = ask_again(reach, host, composed, delays, within).await;
            let _ = internal.send(Internal::Asked {
                id,
                result: result.map(Box::new),
            });
        });
    }

    /// What the host said when asked again, if it said anything: a result settles the delegation,
    /// and anything less leaves it unknown.
    fn on_asked(&mut self, id: &str, result: Option<VoiceDelegateResult>) {
        match result {
            Some(result) => {
                let composed = self.attempts.remove(id).map(|attempt| attempt.composed);
                self.host_answered(id, result, composed);
            }
            None => {
                if let Some(attempt) = self.attempts.get_mut(id) {
                    attempt.asking = false;
                }
            }
        }
    }

    /// The host is reached again: what was written and not answered is asked about once more.
    fn ask_after_attempts(&mut self) {
        let waiting: Vec<String> = self
            .attempts
            .iter()
            .filter(|(_, attempt)| !attempt.asking)
            .map(|(id, _)| id.clone())
            .collect();
        for id in waiting {
            self.ask_about(&id);
        }
    }

    /// The path to the host is lost: what was not written is not written, and what was stays
    /// unknown, since the host goes on with a request after its connection ends.
    fn host_path_lost(&mut self) {
        self.unsent.store(true, Ordering::SeqCst);
        let waiting: Vec<Collection> = self.collections.drain(..).collect();
        for collection in waiting {
            self.gate.abandon(collection.offset_ms);
            self.not_sent(&collection.id, Why::HostLost);
        }
        self.cancel_confirmations(Why::HostLost);
        self.arm_collection();
    }

    /// A fragment that belongs to a request arrived after it was read: a challenge the host awaits
    /// a confirmation for is not one to answer.
    fn cancel_challenges(&mut self) {
        self.cancel_confirmations(Why::LateFragment);
    }

    /// Whether a request was written to the host and has no answer: it may have been carried out.
    fn requests_unsettled(&self) -> bool {
        !self.unsettled.is_empty()
    }

    /* ------------------------------------------------------------------------------------- */
    /* The end                                                                               */
    /* ------------------------------------------------------------------------------------- */

    /// Stops a call's media, and says whether the media is stopped: native code returned from the
    /// stop in time, or answered that the call has ended already, as it does for a call it ended
    /// itself.
    async fn stop_media(&self, call: &CallId) -> bool {
        self.shared.stop_media(call).await
    }

    /// Frees the slot, so another call can be started.
    fn release(&self) {
        self.shared.release(self.id);
    }

    /// Ends the call, whatever the cause.
    pub(super) async fn end(&mut self, cause: Cause) -> Closed {
        let timings = self.shared.timings;
        let id = self.id;
        // Nothing not yet written to the host is written from here on.
        self.unsent.store(true, Ordering::SeqCst);
        // What the opening context came to is in the record before the call is said to have ended,
        // so that a person who reads the end reads it too.
        self.settle_the_opening().await;
        self.view(|state| {
            state.running = false;
            state.begin_ending(id);
        });
        // The mute is no longer advice to anyone once the call is ending.
        self.advice = None;
        // The control closes the call at the service while the media and the host are dealt with,
        // and its news is read meanwhile: a control that nobody reads stops reading its socket.
        let closing = match (&self.control, cause.service_closed()) {
            (Some(control), false) => {
                let control = control.clone();
                Some(tokio::spawn(async move { control.close().await }))
            }
            _ => None,
        };
        let draining = self.control_events.take().map(|mut events| {
            tokio::spawn(async move {
                let mut last = None;
                while let Some(news) = events.next().await {
                    if let ControlNews::Ended(end) = news {
                        last = Some(end);
                    }
                }
                last
            })
        });

        let call = self.call.take();
        let already = self.media_stopped.unwrap_or(false);
        let this = &*self;
        let local = async {
            match call {
                // Native code that does not return from a stop never holds the revocation.
                Some(call) => this.stop_media(&call).await,
                None => already,
            }
        };
        let host = self.host.clone();
        let descriptor = self.descriptor.clone();
        let reach = Arc::clone(&self.reach);
        let toward_host = async {
            match (host, descriptor) {
                (Some(host), Some(descriptor)) => Some(
                    stop_at_host(
                        &reach,
                        &host,
                        descriptor.voice_session_id,
                        timings.host_within,
                    )
                    .await,
                ),
                _ => None,
            }
        };
        let (closed_locally, host_end) = tokio::join!(local, toward_host);
        self.events = None;
        self.media_stopped = Some(closed_locally);
        let host_end = host_end.unwrap_or(HostEnd::NotNeeded);
        let closed = Closed {
            local: closed_locally,
            host: host_end.clone(),
        };

        let needs_broker = self.descriptor.is_some();
        // A request written to the host and not answered may have been carried out, and the aftermath
        // never says nothing was done.
        let unsettled = self.accepting && self.requests_unsettled();
        self.view(|state| {
            state.running = false;
            state.session = None;
            state.control = "none".to_owned();
            state.host = "none".to_owned();
            state.ended = Some(EndedView {
                owner: id,
                cause: cause.word().to_owned(),
                words: if unsettled {
                    format!("{} {REQUESTS_UNSETTLED}", cause.words())
                } else {
                    cause.words()
                },
                closed_locally,
                host: host_end.clone(),
                broker: if needs_broker {
                    "pending"
                } else {
                    "not_needed"
                }
                .to_owned(),
            });
            // What the voice service did about the call arrives after this record may be another
            // call's, and the screen is told so until it has.
            if needs_broker {
                state.finalising_owners.insert(id);
            }
        });
        // What the end owes is recorded with the host being told, in one step. The grant may be
        // live at the host until the moment the call was to close, by the host's reading of the
        // clock.
        let owed = match (host_end.owed_reason(), &self.descriptor, &self.host) {
            (Some(words), Some(descriptor), Some(host)) => vec![OwedView::revocation(
                words,
                descriptor.voice_session_id,
                owed_until(descriptor.closes_at_ms.get()),
                host,
            )],
            _ => Vec::new(),
        };
        self.shared.record_end(self.id, owed);
        if matches!(cause, Cause::Control(ControlEnd::NoSuchCall)) {
            self.shared.remember_no_such_call(self.note_key());
        }
        // Another call can be started from here; this one is only finalising at the service.
        self.release();
        for reply in self.stops.drain(..) {
            let _ = reply.send(closed.clone());
        }
        self.close_inbox(&closed);

        if needs_broker {
            let broker = self.finalise(&cause, closing, &host_end).await;
            let service =
                self.descriptor
                    .as_ref()
                    .zip(self.host.as_ref())
                    .map(|(descriptor, host)| ServiceCall {
                        call_id: descriptor.call_id.clone(),
                        voice_session_id: descriptor.voice_session_id,
                        until_ms: owed_until(descriptor.closes_at_ms.get()),
                        host: host.clone(),
                    });
            self.shared.record_service(id, broker, service.as_ref());
        }
        if let Some(control) = self.control.take() {
            control.stop();
        }
        if let Some(draining) = draining {
            draining.abort();
        }
        self.shared.forget_emergency(self.id);
        closed
    }

    fn note_key(&self) -> NoteKey {
        NoteKey {
            environment: self
                .host
                .as_ref()
                .map(|host| host.environment_id.to_string()),
            generation: self.generation.clone(),
            origin: self.shared.service.origin.clone(),
        }
    }

    /// Finalises the call at the voice service, and says how that went.
    async fn finalise(
        &mut self,
        cause: &Cause,
        closing: Option<
            tokio::task::JoinHandle<
                std::result::Result<
                    kr_client::services::voice_control::Closure,
                    kr_client::services::voice_control::SendError,
                >,
            >,
        >,
        host: &HostEnd,
    ) -> &'static str {
        if cause.service_closed() {
            return "closed_by_service";
        }
        if let Some(closing) = closing
            && matches!(closing.await, Ok(Ok(_)))
        {
            return "closed";
        }
        // The control could not close it. The host tells the service when it revokes, and when it
        // says it did there is nothing to add; otherwise the service's own route can close it.
        if matches!(
            host,
            HostEnd::Revoked {
                broker_notified: true,
                ..
            }
        ) {
            return "closed_by_host";
        }
        let Some(descriptor) = self.descriptor.as_ref() else {
            return "not_confirmed";
        };
        if self
            .shared
            .close_over_http(&self.tokens, &descriptor.call_id)
            .await
        {
            return "closed_over_http";
        }
        "not_confirmed"
    }
}

/// Whether a row in this state is a request that was, or may have been, written to the host and has
/// no answer that says it was done or not done: the host took it and said no more, or what became of
/// it is not known.
fn may_have_been_carried_out(state: &str) -> bool {
    matches!(state, "asking" | "admitted" | "unknown")
}

/// What the host's result says of a delegation: the state its row takes, the cause when the host
/// gave one, and what the model is told. A request the host only accepted is told as accepted and
/// never as done: an acknowledgement proves admission, not execution.
fn answered_as(outcome: &VoiceDelegationOutcome) -> (&'static str, Option<&'static str>, String) {
    match outcome {
        VoiceDelegationOutcome::Performed { summary, .. } => (
            "performed",
            None,
            format!("{DELEGATION_PERFORMED} {summary}"),
        ),
        VoiceDelegationOutcome::Admitted { .. } => {
            ("admitted", None, DELEGATION_ADMITTED.to_owned())
        }
        VoiceDelegationOutcome::ConfirmationRequired { .. } => (
            "confirmation_required",
            None,
            DELEGATION_CONFIRMATION.to_owned(),
        ),
        VoiceDelegationOutcome::Refused { reason, .. } => (
            "host_refused",
            Some(reason.as_str()),
            DELEGATION_HOST_REFUSED.to_owned(),
        ),
    }
}

/// The moment this device holds a call to, in milliseconds since the epoch, or none when the call
/// is not one to carry.
///
/// The host says when the call closes. This device holds the call to that, and to no more than it
/// asked for, with room for a clock that is not its own: a closing time later than that is held
/// down to what was asked for, and one that is long past (further than the clock may differ) is
/// not a call to carry. A host whose clock is a little behind gives a time that is a little past,
/// which native code ends the call at.
fn hold_until(host_closes_ms: u64, requested_seconds: u32, now_ms: u64) -> Option<u64> {
    if host_closes_ms.saturating_add(MAX_CLOCK_SKEW_MS) <= now_ms {
        return None;
    }
    let latest = now_ms
        .saturating_add(u64::from(requested_seconds) * 1000)
        .saturating_add(MAX_CLOCK_SKEW_MS);
    Some(host_closes_ms.min(latest))
}

/// What the opening task came to as the call ends, in the order to note it: what it reported, or,
/// when it was still running and reported nothing, that the end cut it short.
///
/// A running task is stopped and awaited before the channel is read, so that a report it makes in
/// the poll the stop cannot cut is in the channel and is the one that stands; read first, that
/// report would be missed and the call said to have been cut short that was given all of it.
async fn what_the_opening_came_to(
    opening: &mut Option<tokio::task::JoinHandle<()>>,
    internal: &mut mpsc::UnboundedReceiver<Internal>,
) -> Vec<Opened> {
    let running = match opening.take() {
        Some(task) => {
            task.abort();
            // Cancelled or finished: either way it is over when this returns.
            let _ = task.await;
            true
        }
        None => false,
    };
    let mut came = Vec::new();
    while let Ok(message) = internal.try_recv() {
        if let Internal::Opened(opened) = message {
            came.push(opened);
        }
    }
    if running && came.is_empty() {
        came.push(Opened::Cut);
    }
    came
}

/// How many ticks the host path is left alone after the host refused to vouch for the call.
const PROBE_PAUSE_TICKS: u32 = 6;

/// Closes `inbox` and answers what it holds: a stop gets `closed`, and a mute is told there is no
/// call. A command sent afterwards fails at once, and a sender waiting for room is let go, so
/// nobody is left waiting on a task that is done.
fn answer_and_close(inbox: &mut mpsc::Receiver<Cmd>, closed: &Closed) {
    inbox.close();
    while let Ok(cmd) = inbox.try_recv() {
        match cmd {
            Cmd::Stop(reply) => {
                let _ = reply.send(closed.clone());
            }
            Cmd::Mute { reply, .. } => {
                let _ = reply.send(Err(CommandError::refused(
                    "this device is not holding a voice call",
                )));
            }
        }
    }
}

/// What a start learned.
enum Reached {
    /// The host's answer.
    Result(VoiceStartResult),
    /// The host answered with a receipt.
    Receipt(Box<kr_protocol::receipt::Receipt>),
    /// The host never said.
    Unknown,
}

/// How far from the clock this device's idea of the moment a call closes may be, in milliseconds.
const MAX_CLOCK_SKEW_MS: u64 = 120_000;

/// The moment a grant the host made for a call that closes at `closes_at_ms` is certain to have
/// ended by itself: the host's closing time is the host's reading of its own clock, so it is held
/// back by what the two clocks may differ by.
pub(super) fn owed_until(closes_at_ms: u64) -> u64 {
    closes_at_ms.saturating_add(MAX_CLOCK_SKEW_MS)
}

/// Asks `host` to revoke the call's grant, over a connection to that host.
pub(super) async fn stop_at_host(
    reach: &Arc<dyn HostReach>,
    host: &CallHost,
    voice_session_id: VoiceSessionId,
    within: Duration,
) -> HostEnd {
    let session = if has_ended(&host.session).await {
        match tokio::time::timeout(within, reach.session_to(&host.paired, Some(&host.session)))
            .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(error)) => {
                return HostEnd::NotTold {
                    words: format!("The host could not be reached: {}", error.message),
                };
            }
            Err(_) => {
                return HostEnd::NotTold {
                    words: "The host could not be reached in time.".to_owned(),
                };
            }
        }
    } else {
        Arc::clone(&host.session)
    };
    revoke(&session, host.environment_id, voice_session_id, within).await
}

/// Reaches a host that was lost, and asks whether it still knows the call.
///
/// The read is the context of the call's first session, which the host answers only for a voice
/// session it holds: an answer is "the host is back", and a refusal is reported and ends nothing.
async fn probe_host(
    reach: Arc<dyn HostReach>,
    host: CallHost,
    descriptor: VoiceSessionDescriptor,
    within: Duration,
) -> Probe {
    let Ok(Ok(session)) = tokio::time::timeout(within, reach.session_to(&host.paired, None)).await
    else {
        return Probe::Unreached;
    };
    let Some(session_id) = descriptor.session_ids.iter().next().copied() else {
        return Probe::Back(session);
    };
    let params = VoiceContextParams {
        voice_session_id: descriptor.voice_session_id,
        session_id,
        selected: kr_protocol::scalars::CanonicalSet::new(),
        delegation_id: Nullable::null(),
    };
    match tokio::time::timeout(
        within,
        session.read::<_, kr_protocol::voice::VoiceContextResult>(Method::VoiceContext, &params),
    )
    .await
    {
        Ok(Ok(_)) => Probe::Back(session),
        Ok(Err(ClientError::Host(error))) => Probe::Refused(error.message),
        _ => Probe::Unreached,
    }
}

#[cfg(test)]
mod tests {
    /// A request the host took and did not say it carried out is one the end cannot say nothing was
    /// done for, as one it asked about and was not answered, or has not yet written.
    #[test]
    fn a_request_the_host_took_and_did_not_carry_out_is_not_one_nothing_was_done_for() {
        for state in ["asking", "admitted", "unknown"] {
            assert!(may_have_been_carried_out(state), "{state}");
        }
        for state in [
            "collecting",
            "refused",
            "not_sent",
            "cancelled",
            "performed",
            "host_refused",
            "confirmation_required",
        ] {
            assert!(!may_have_been_carried_out(state), "{state}");
        }
    }

    /// A set whose proof and marker are in hand is frozen only before the time the news may be read
    /// until: handled at that time or after it, with the owner's deadline due as well, the
    /// completion is none and the set is refused as not drained.
    #[test]
    fn a_completion_handled_at_or_after_the_deadline_freezes_nothing() {
        let record = Record {
            openings: 1,
            breaks: 0,
            capturing: true,
        };
        let stage = |until: Instant| Stage::Draining {
            token: Some(7),
            record: Some(record),
            until,
        };
        let read = VecDeque::from([7_u64]);
        let now = Instant::now();
        let later = now + Duration::from_millis(1);
        assert!(stage(later).may_freeze(&read, now), "before the deadline");
        assert!(!stage(now).may_freeze(&read, now), "at the deadline");
        assert!(!stage(now).may_freeze(&read, later), "after the deadline");
        assert!(
            !stage(later).may_freeze(&VecDeque::new(), now),
            "no marker read"
        );
        assert!(
            !Stage::Draining {
                token: Some(7),
                record: None,
                until: later,
            }
            .may_freeze(&read, now),
            "no proof"
        );
        assert!(!Stage::Waiting.may_freeze(&read, now), "still waiting");
    }

    /// What the host says of a delegation is what the row and the model are told: a request the host
    /// only accepted is never told as done, a refusal carries the host's reason, and what the host
    /// performed is told with its own summary.
    #[test]
    fn what_the_host_answers_is_told_as_it_answered() {
        let action_id = ActionId::new(kr_ipc::new_uuid());
        let (state, cause, told) = answered_as(&VoiceDelegationOutcome::Admitted {
            action_id,
            note: "accepted".to_owned(),
        });
        assert_eq!((state, cause), ("admitted", None));
        assert!(told.contains("not known"), "{told}");
        assert!(!told.starts_with(DELEGATION_PERFORMED), "{told}");

        let (state, _, told) = answered_as(&VoiceDelegationOutcome::Performed {
            action_id,
            summary: "session one is running".to_owned(),
        });
        assert_eq!(state, "performed");
        assert!(told.starts_with(DELEGATION_PERFORMED), "{told}");
        assert!(told.ends_with("session one is running"), "{told}");

        let (state, cause, _) = answered_as(&VoiceDelegationOutcome::Refused {
            reason: kr_protocol::voice::VoiceRefusal::NotUnderstood,
            message: "not read".to_owned(),
        });
        assert_eq!((state, cause), ("host_refused", Some("not_understood")));
    }

    use super::*;

    /// The closing time this device holds a call to is the host's, held down to what was asked
    /// for with room for a clock that is not its own, and a call that closed long ago is not
    /// carried.
    #[test]
    fn a_call_is_held_to_the_host_s_closing_time_within_what_was_asked_for() {
        const NOW: u64 = 1_000_000_000;
        // As asked: ten minutes.
        assert_eq!(hold_until(NOW + 600_000, 600, NOW), Some(NOW + 600_000));
        // A host whose clock is ahead gives a later time than was asked for: the call is held to
        // what was asked for, with the room for clocks, and not ended for it.
        assert_eq!(
            hold_until(NOW + 100_000_000, 600, NOW),
            Some(NOW + 600_000 + MAX_CLOCK_SKEW_MS)
        );
        // A host whose clock is a little behind gives a time a little past, and the call is
        // carried: native code ends it at that moment.
        assert_eq!(hold_until(NOW - 5_000, 600, NOW), Some(NOW - 5_000));
        // One that closed longer ago than clocks differ is not a call to carry.
        assert_eq!(hold_until(NOW - MAX_CLOCK_SKEW_MS, 600, NOW), None);
    }

    /// The call ends while the opening task is inside a poll, before it publishes what it came to:
    /// the poll cannot be cut, so the task publishes as the end waits for it, and the report is not
    /// lost to a call that says it was cut short. The task is held where it stands by a channel the
    /// test lets it go through after the end has been polled once.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_report_the_opening_task_publishes_as_the_call_ends_is_not_recorded_as_cut_short() {
        let (internal_tx, mut internal) = mpsc::unbounded_channel();
        let (entered_tx, entered) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let mut opening = Some(tokio::spawn(async move {
            entered_tx.send(()).expect("the test waits");
            // Inside this poll until the test lets it go: abort takes effect at the next await.
            released.recv().expect("the test lets it go");
            let _ = internal_tx.send(Internal::Opened(Opened::Given));
        }));
        entered.await.expect("the task is inside its poll");

        let mut settling = std::pin::pin!(what_the_opening_came_to(&mut opening, &mut internal));
        let early = tokio::select! {
            biased;
            came = &mut settling => Some(came),
            () = async {} => None,
        };
        release.send(()).expect("the task waits");
        let came = match early {
            Some(came) => came,
            None => settling.await,
        };

        assert!(
            matches!(came.as_slice(), [Opened::Given]),
            "the report the task made as the call ended is the one that stands: {}",
            came.len()
        );
    }

    /// An opening task that never reports was cut short by the end, and says so once.
    #[tokio::test]
    async fn an_opening_task_that_never_reports_is_recorded_as_cut_short() {
        let (_internal_tx, mut internal) = mpsc::unbounded_channel();
        let mut opening = Some(tokio::spawn(std::future::pending::<()>()));

        let came = what_the_opening_came_to(&mut opening, &mut internal).await;

        assert!(matches!(came.as_slice(), [Opened::Cut]));
    }

    /// A service that confirmed some parts of the opening context and never said whether it took
    /// the next has not refused it: what the person reads says how many it confirmed and that it did
    /// not say, and says nothing of a refusal. A refusal is still one.
    #[test]
    fn a_part_the_service_never_answered_is_not_said_to_have_been_refused() {
        let stopped = |stopped_by| OpeningContextSent {
            accepted: 1,
            total: 3,
            stopped_by: Some(stopped_by),
        };
        for lost in [SendError::Lost, SendError::Unanswered] {
            let Opened::Sent { uncertain, .. } = Opened::of(&stopped(lost)) else {
                panic!("a part stopped it");
            };
            assert!(uncertain);
        }
        let Opened::Sent {
            uncertain: refused, ..
        } = Opened::of(&stopped(SendError::Busy))
        else {
            panic!("a part stopped it");
        };
        assert!(!refused, "control: a request turned away is not uncertain");

        let (_, words) = Opened::of(&stopped(SendError::Lost))
            .problem()
            .expect("a problem");
        assert!(words.contains("confirmed 1 of its 3 parts"), "{words}");
        assert!(words.contains("did not say whether it took"), "{words}");
        assert!(!words.contains("and not the next"), "{words}");
        let (_, refused_words) = Opened::of(&stopped(SendError::Busy))
            .problem()
            .expect("a problem");
        assert!(
            refused_words.contains("and not the next"),
            "{refused_words}"
        );
    }

    /// Nobody is left waiting on an owner that is done: what its inbox holds is answered, and a
    /// command sent afterwards is turned away at once instead of waiting for an answer that no one
    /// will give.
    #[tokio::test]
    async fn a_closed_inbox_answers_what_it_holds_and_turns_later_senders_away() {
        let (commands, mut inbox) = mpsc::channel(8);
        let (stop, stopped) = oneshot::channel();
        let (mute, muted) = oneshot::channel();
        commands.send(Cmd::Stop(stop)).await.expect("room");
        commands
            .send(Cmd::Mute {
                what: Mute::Microphone,
                muted: true,
                reply: mute,
            })
            .await
            .expect("room");

        answer_and_close(
            &mut inbox,
            &Closed {
                local: true,
                host: HostEnd::NotNeeded,
            },
        );

        assert!(stopped.await.expect("the stop is answered").local);
        muted
            .await
            .expect("the mute is answered")
            .expect_err("there is no call to mute");
        let (late, _) = oneshot::channel();
        assert!(
            commands.send(Cmd::Stop(late)).await.is_err(),
            "a command sent after the end is turned away"
        );
    }
}
