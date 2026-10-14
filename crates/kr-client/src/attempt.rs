//! An attempt: one grant action a client sent, and what it knows of how it ended.
//!
//! A client that shares a session, accepts a share, takes one back or hands control over sends
//! one mutation, and the answer can be lost: the connection ends, the process stops, the host
//! answers "has not finished". The host performs an action at most once and keeps its answer for
//! thirty days, so the client's question is only what became of it, and this module is how a client
//! asks and what it may conclude. Four rules make the conclusions safe.
//!
//! * **The record comes first.** An [`Attempt`] holds the composed request whole ([`Attempt::new`]),
//!   and is kept ([`AttemptStore::keep`]) before the request is sent, so a restart between any two
//!   steps still has the request, the host and standing it was sent under, and the identity of
//!   what it would have written.
//! * **A repeat is a question.** The state machine allows an exact repeat only on a connection
//!   other than the one that sent the request ([`crate::session::Session::repeat`]), so the host
//!   answers it from its record or not at all, and at most [`REPEATS`] of them. Nothing an answer
//!   to a repeat says, other than the result, closes the attempt: a refusal can mean the host will
//!   not give back a kept answer now, and "has not finished" means the effect is still running.
//! * **Absence proves nothing until nothing more can happen.** The host takes an action's deadline
//!   as the earlier of its window's expiry and its own receipt time plus the requested lifetime, and
//!   it reads a connection's requests one at a time, so a request can be read long after it was
//!   sent. After the window it was sent under has ended, no transaction of the action passes its
//!   admission check, and one that passed it earlier holds the store's lock until it commits, which
//!   every read of the store waits for. A read of the host that finds nothing therefore counts only
//!   after [`Attempt::bound`] has passed, measured as time elapsed on a clock that cannot be
//!   stepped, never on the wall clock, and measured when the read *began* ([`Armed::read_begins`]):
//!   the host takes the store's lock for a read when it reads the request, which is no earlier
//!   than the client sent it, so a read that began after the bound was read after any commit of
//!   the action, whatever the client did while it waited for the answer. After a restart, when no
//!   such clock survives, the whole bound runs again from the restart. A read that blocks or
//!   fails leaves the attempt as it was.
//! * **A found grant is proof, an absent one is not.** What a read finds closes the attempt as
//!   happened. What it does not find closes it as not done only where nothing but the action could
//!   have put it there and taken it away: an invitation or a transfer. A revocation whose grant is
//!   absent, and a redemption whose offer and share are both gone, are unknown, because a grant
//!   that was revoked or redeemed can have ended and left the list.
//!
//! The store is a directory the caller names, one for each host, readable only by its owner, with
//! one file for each attempt and one lock for the writers of every window of the application.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_protocol::confirmation::TransferControlPlan;
use kr_protocol::envelope::MutationRequest;
use kr_protocol::error::RetryCategory;
use kr_protocol::ids::{ActionId, GrantId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::sharing::{GrantState, GrantTransferParams};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::session::{ComposedMutation, Settled};
use crate::shown::{IoFault, Shown};
use crate::transport::Reach;

/// The format of an attempt this build writes, recorded in it as `version`. An attempt of a later
/// format is shown as unknown and never sent or changed.
pub const ATTEMPT_FORMAT: u32 = 1;

/// The most repeats of one request a client asks for by itself.
pub const REPEATS: usize = 3;

/// How long a client waits before each repeat: a parameter of the machine, which a test sets to
/// nothing.
pub const REPEAT_DELAYS: [Duration; REPEATS] = [
    Duration::from_secs(2),
    Duration::from_secs(8),
    Duration::from_secs(30),
];

/// What is added to the window's validity before a read that finds nothing counts: the host's
/// reading of the clock and the commit that follows its last admission check take time of their
/// own.
const MARGIN_MS: u64 = 30_000;

/// What an attempt does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// An invitation to share a session (`grant.create`).
    Invite,
    /// Accepting one (`grant.redeem`).
    Redeem,
    /// Taking a share back, or withdrawing an invitation (`grant.revoke`).
    Revoke,
    /// Handing a session's control to another device (`grant.transfer`).
    Transfer,
}

/// How an attempt ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// It happened: the host gave its result, or what the action writes is there.
    Happened,
    /// The host refused it and kept its refusal as the action's answer.
    Refused,
    /// It did not happen, as far as the host shows, and can no longer.
    NotDone,
    /// An invitation was not accepted, as far as the host shows, and can no longer be.
    NotAccepted,
    /// A revoked grant had already ended before the revocation. It does not show that this
    /// revocation did anything.
    HadEnded,
    /// What became of it cannot be told from what the host shows.
    Unknown,
}

/// Where an attempt stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// A transfer's owner confirmation is being asked for. Nothing that changes authority has been
    /// sent.
    Asking,
    /// The request is composed and kept, and has not been sent.
    Composed,
    /// It was sent and its answer is not known. Repeats may be asked.
    Unfinished,
    /// The repeats are over. The host's state is read until it shows what became of the action.
    Checking,
    /// It is over, and this is how.
    Closed(Outcome),
}

/// What came back from sending a request, or repeating it, in terms every client maps its own errors
/// into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// The method's result.
    Result,
    /// The host refused, in this category of retry.
    Refused(RetryCategory),
    /// The answer was lost: the connection ended, or the host's answer did not arrive. The request
    /// may have reached the host, and asking about it is what settles that.
    Lost,
    /// The client refused before anything was sent. It is not the host's answer.
    NotSent,
}

impl Reply {
    /// What a [`crate::session::Session`] call came to.
    ///
    /// The code of a [`ClientError`] is not used: `ClientError::code()` maps a lost answer to an
    /// unknown outcome. A receipt is not the method's result for these methods, so it counts as an
    /// answer not yet known.
    #[must_use]
    pub fn of(outcome: &std::result::Result<Settled, ClientError>) -> Self {
        match outcome {
            Ok(Settled::Result(_)) => Self::Result,
            Ok(Settled::Receipt(_)) => Self::Lost,
            Err(ClientError::Host(error) | ClientError::Refused { error, .. }) => {
                Self::Refused(error.retry)
            }
            Err(
                ClientError::SubmissionUncertain { .. }
                | ClientError::Transport(_)
                | ClientError::Ipc(_)
                // A connection that ended before the request was answered ended after it was
                // sent, or before it could be: the same as a lost answer, which a repeat settles.
                | ClientError::ConnectionEnded,
            ) => Self::Lost,
            // Refused here, before anything was sent.
            Err(
                ClientError::Cbor(_)
                | ClientError::WrongEffect { .. }
                | ClientError::UnsupportedVersion { .. }
                | ClientError::TooManyOutstandingMutations { .. }
                | ClientError::TooManyUnresolvedActions { .. }
                | ClientError::NoActionWindow
                | ClientError::Misdirected { .. }
                | ClientError::OtherHost
                | ClientError::StillAccounting
                | ClientError::ServiceNotConfigured(_)
                | ClientError::Draft(_),
            ) => Self::NotSent,
            // Anything else may have reached the host, and asking is what settles it.
            Err(_) => Self::Lost,
        }
    }
}

/// What a client does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// The attempt is over.
    Closed(Outcome),
    /// Ask the host again, on a connection opened for it, after the delay for this repeat.
    Repeat,
    /// Read the host's state, and judge what it shows ([`Attempt::after_read`]).
    Check,
    /// Read again later: nothing counts before [`Attempt::bound`].
    Wait,
    /// The call did not go out, and the attempt stays as it was. From a first send the request is
    /// kept, unsent. From a repeat the attempt stays unfinished: the caller asks again on another
    /// connection, or reads the host. A first send that went out and was not answered is
    /// [`Reply::Lost`], never this.
    NotSent,
}

/// What a read of the host found, for the kind of attempt it was made for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// The grant the attempt would have written is listed, in any state (an invitation, a
    /// transfer), or the offer's share is held (a redemption).
    Present,
    /// The grant the attempt would have written is not listed (an invitation, a transfer).
    Absent,
    /// The grant an attempt revokes is listed in this state, with whether its revocation time is
    /// set.
    Grant(GrantState, bool),
    /// The grant an attempt revokes is not listed.
    Gone,
    /// The invitation an attempt redeems is still offered.
    Offered,
    /// Neither the invitation an attempt redeems nor its share is listed.
    Neither,
}

/// One attempt, as a client keeps it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    /// The format of the record: [`ATTEMPT_FORMAT`].
    pub version: u32,
    /// What it does.
    pub kind: Kind,
    /// Where it stands.
    pub phase: Phase,
    /// The action this record is kept under, and the one a caller settles. The host keys its record
    /// of the request by this and the actor, except while the attempt is [`Phase::Asking`]: the
    /// request held then is the confirmation request, which the host keys by its own action.
    pub action_id: ActionId,
    /// The request, whole, window included: the host answers a repeat only when it is exactly the
    /// request that was sent. For an attempt still [`Phase::Asking`] it is the confirmation
    /// request.
    pub request: MutationRequest,
    /// When the host issued the window the request carries, in UTC milliseconds.
    pub window_issued_at_ms: u64,
    /// How long that window stays valid, in milliseconds.
    pub window_valid_for_ms: u64,
    /// The host the request was sent to. A repeat to any other finds no record.
    pub host: String,
    /// Who the request was sent as. The host keys its record by actor, so a repeat as anyone else
    /// finds none.
    pub standing: String,
    /// The grant a read looks for: the one an invitation or a transfer would write, the one a
    /// revocation names, the share a redemption would hold.
    pub grant_id: Nullable<GrantId>,
    /// How long a read that finds nothing waits to count, in milliseconds of elapsed time.
    pub bound_ms: u64,
    /// When the attempt was started, on this device's wall clock. It is shown to a person and
    /// decides nothing. A hand-over keeps the time it was first asked for, not the transfer's.
    pub composed_at_ms: TimestampMs,
    /// How many repeats have been asked.
    pub repeats: u8,
    /// Whether the person hid it. Hiding releases nothing.
    pub hidden: bool,
    /// Whether it closed without the host's result and a person may still ask the host for it.
    pub follow_up: bool,
    /// One line that says what it was, for a person.
    pub label: String,
    /// A transfer's plan, as the owner confirmed it.
    pub plan: Nullable<TransferControlPlan>,
}

crate::debug_fields!(Attempt {
    kind,
    phase,
    action_id,
    repeats
});

impl Attempt {
    /// A new attempt for a composed request, kept before the request is sent.
    ///
    /// The host and the actor the request is for are the composed request's own. `grant_id` is
    /// what a read looks for, and `composed_at_ms` the wall clock's reading, for display.
    #[must_use]
    pub fn new(
        kind: Kind,
        composed: &ComposedMutation,
        grant_id: Option<GrantId>,
        composed_at_ms: u64,
        label: impl Into<String>,
    ) -> Self {
        let (host, standing) = composed.reach().map_or_else(Default::default, |reach| {
            (reach.host.clone(), reach.actor.clone())
        });
        Self {
            version: ATTEMPT_FORMAT,
            kind,
            phase: Phase::Composed,
            action_id: composed.action_id(),
            request: composed.request().clone(),
            window_issued_at_ms: composed.window_issued_at_ms(),
            window_valid_for_ms: composed.window_valid_for_ms(),
            host,
            standing,
            grant_id: Nullable(grant_id),
            bound_ms: composed.window_valid_for_ms().saturating_add(MARGIN_MS),
            composed_at_ms: TimestampMs::new(composed_at_ms),
            repeats: 0,
            hidden: false,
            follow_up: false,
            label: label.into(),
            plan: Nullable::null(),
        }
    }

    /// Shortens the bound to what is left of a challenge's lifetime, for a transfer a client
    /// sends in one process: the host refuses an expired confirmation inside the transaction, so
    /// once the challenge has run out nothing can commit, whatever the window says.
    ///
    /// `challenge_answered` is the clock the caller started when the challenge's reply arrived,
    /// and the bound counts what is left of the challenge's lifetime on it. The bound itself is
    /// counted from the moment the attempt's clock is armed, which is when the transfer is
    /// composed, after the reply, so the bound never ends before the challenge does. A caller
    /// cannot give a duration of its own: the lifetime is the host's own.
    pub fn bound_by_challenge(&mut self, challenge_answered: Armed) {
        self.shortened_to(Self::challenge_left(challenge_answered.elapsed()));
    }

    /// What a challenge has left, `since_challenge` after its reply arrived.
    fn challenge_left(since_challenge: Duration) -> Duration {
        Duration::from_millis(kr_pairing::confirm::CONFIRMATION_LIFETIME_MS)
            .saturating_sub(since_challenge)
    }

    fn shortened_to(&mut self, left: Duration) {
        let by_challenge = u64::try_from(left.as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(MARGIN_MS);
        self.bound_ms = self.bound_ms.min(by_challenge);
    }

    /// A new hand-over, kept before an owner device is asked to confirm it.
    ///
    /// The record is named for the transfer's action from the start, because that is the action the
    /// host keys the transfer by and the one the caller settles; what it holds until the owner has
    /// confirmed is the *confirmation request*, which is another action. The caller sends and
    /// repeats that request itself, and the state machine does not judge its answers: while the
    /// attempt is asking, every call answers [`Next::NotSent`] or [`Next::Wait`], and only
    /// [`Self::confirmed`] moves it on, to the transfer. `grant_id` is the grant the transfer would
    /// write, which the host derives from the actor and `transfer_action`.
    #[must_use]
    pub fn asking(
        confirmation: &ComposedMutation,
        transfer_action: ActionId,
        grant_id: GrantId,
        composed_at_ms: u64,
        label: impl Into<String>,
    ) -> Self {
        let mut attempt = Self::new(
            Kind::Transfer,
            confirmation,
            Some(grant_id),
            composed_at_ms,
            label,
        );
        attempt.action_id = transfer_action;
        attempt.phase = Phase::Asking;
        attempt
    }

    /// Moves a hand-over from asking for its confirmation to sending the transfer.
    ///
    /// `transfer` is the `grant.transfer` request composed under the action this record is named
    /// for. It replaces the confirmation request, with its window and the host and actor it is for
    /// (cleared when it states none, so a request that cannot say whom it is for is never
    /// repeated), and `plan` is what the owner confirmed. `challenge_answered` is the clock the
    /// caller started when the challenge's reply arrived: the bound is the window's, shortened to
    /// what the challenge has left, which is its lifetime less the time on that clock. **The caller
    /// arms a new clock for the attempt now**: the one that counted the confirmation's request
    /// counted from before the challenge existed.
    ///
    /// Returns false, changing nothing, for an attempt that is not a hand-over being asked for, for
    /// a request that is not a `grant.transfer` under this record's action, for one whose
    /// parameters or target name another session, grant or device than the plan the owner
    /// confirmed, for one that states another host or actor than the record's, and for a plan that
    /// would write another grant than this record looks for.
    #[must_use]
    pub fn confirmed(
        &mut self,
        transfer: &ComposedMutation,
        plan: TransferControlPlan,
        challenge_answered: Armed,
    ) -> bool {
        self.confirmed_after(transfer, plan, challenge_answered.elapsed())
    }

    fn confirmed_after(
        &mut self,
        transfer: &ComposedMutation,
        plan: TransferControlPlan,
        since_challenge: Duration,
    ) -> bool {
        if self.kind != Kind::Transfer
            || self.phase != Phase::Asking
            || transfer.action_id() != self.action_id
            || transfer.request().method != Method::GrantTransfer.into()
            || self.grant_id != Nullable::some(plan.new_grant_id)
            || !Self::is_the_plan(transfer.request(), &plan)
            || self
                .reach()
                .zip(transfer.reach())
                .is_some_and(|(was, is)| was != *is)
        {
            return false;
        }
        let left = Self::challenge_left(since_challenge);
        self.request = transfer.request().clone();
        self.window_issued_at_ms = transfer.window_issued_at_ms();
        self.window_valid_for_ms = transfer.window_valid_for_ms();
        let (host, standing) = transfer.reach().map_or_else(Default::default, |reach| {
            (reach.host.clone(), reach.actor.clone())
        });
        self.host = host;
        self.standing = standing;
        self.bound_ms = transfer.window_valid_for_ms().saturating_add(MARGIN_MS);
        self.shortened_to(left);
        self.plan = Nullable::some(plan);
        self.repeats = 0;
        self.phase = Phase::Composed;
        true
    }

    /// Whether a `grant.transfer` request is for exactly what the owner confirmed: its target and
    /// its parameters name the plan's environment, session, giving grant and receiving device.
    fn is_the_plan(request: &MutationRequest, plan: &TransferControlPlan) -> bool {
        request.target.environment_id == plan.environment_id
            && request.target.session_id == Nullable::some(plan.session_id)
            && request
                .params
                .to_typed::<GrantTransferParams>()
                .is_ok_and(|params| {
                    params.session_id == plan.session_id
                        && params.from_grant_id == plan.source_grant_id
                        && params.to_device_id == plan.to_device_id
                })
    }

    /// The request, to send again.
    #[must_use]
    pub fn composed(&self) -> ComposedMutation {
        ComposedMutation::restored(
            self.request.clone(),
            self.window_issued_at_ms,
            self.window_valid_for_ms,
            self.reach(),
        )
    }

    /// The host and the actor the request was composed for, when the record says.
    #[must_use]
    pub fn reach(&self) -> Option<Reach> {
        (!self.host.is_empty() && !self.standing.is_empty()).then(|| Reach {
            host: self.host.clone(),
            actor: self.standing.clone(),
        })
    }

    /// How long, measured on a clock that cannot be stepped, a read that finds nothing waits to
    /// count.
    #[must_use]
    pub const fn bound(&self) -> Duration {
        Duration::from_millis(self.bound_ms)
    }

    /// Whether the attempt is over.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        matches!(self.phase, Phase::Closed(_))
    }

    /// Whether the attempt still gates a second action for the same target: it is not over.
    #[must_use]
    pub const fn gates_a_second(&self) -> bool {
        !self.is_closed()
    }

    /// What a client does after the request was sent for the first time and this came back.
    ///
    /// A result closes it as happened. A refusal in a category that never retries or that needs a
    /// change is the host's kept answer to the action (nothing committed, because every failure
    /// after a commit in these methods is a transient one, or is answered as an unknown outcome,
    /// as the local door answers a result it withholds because the local owner's lease ended), and
    /// closes it as refused. Anything else leaves it unfinished.
    ///
    /// A redemption is the exception: the paired door can replace the result of a redemption that
    /// committed with a refusal, when the bounds of its decision end before it writes the answer,
    /// and the redemption's effect runs on a task that can outlive the request. So a kept refusal to
    /// a redemption's first send is a reason to read what the host shows, not the end: a share the
    /// device holds closes it as happened, and an offer still listed is not accepted only once the
    /// bound has passed, as for any other absent write. Any paired client's action has the same
    /// property, and would need the same rule.
    ///
    /// An attempt still asking for a confirmation has nothing to send ([`Self::confirmed`]).
    pub fn after_first_send(&mut self, reply: Reply) -> Next {
        if let Phase::Closed(outcome) = self.phase {
            return Next::Closed(outcome);
        }
        if self.phase == Phase::Asking {
            return Next::NotSent;
        }
        match reply {
            Reply::Result => self.close(Outcome::Happened),
            Reply::Refused(RetryCategory::NoRetry | RetryCategory::ConfigurationChange)
                if self.kind == Kind::Redeem =>
            {
                self.check()
            }
            Reply::Refused(RetryCategory::NoRetry | RetryCategory::ConfigurationChange) => {
                self.close(Outcome::Refused)
            }
            Reply::Refused(_) | Reply::Lost => {
                self.phase = Phase::Unfinished;
                Next::Repeat
            }
            Reply::NotSent => Next::NotSent,
        }
    }

    /// What a client does after an exact repeat and this came back.
    ///
    /// Only a result closes it. A refusal moves it to a read of the host: it can mean the host owes
    /// a fence before it gives back its kept answer, or that the effect is still running. A lost
    /// answer leaves it unfinished until the repeats are used up.
    pub fn after_repeat(&mut self, reply: Reply) -> Next {
        if let Phase::Closed(outcome) = self.phase {
            return Next::Closed(outcome);
        }
        if self.phase == Phase::Asking {
            return Next::NotSent;
        }
        match reply {
            Reply::Result => self.close(Outcome::Happened),
            Reply::Refused(_) => self.check(),
            Reply::Lost => {
                self.repeats = self.repeats.saturating_add(1);
                if usize::from(self.repeats) >= REPEATS {
                    self.check()
                } else {
                    self.phase = Phase::Unfinished;
                    Next::Repeat
                }
            }
            Reply::NotSent => Next::NotSent,
        }
    }

    /// What a client concludes from a read of the host that began `began` after the attempt's clock
    /// was armed.
    ///
    /// `began` is when the read was *sent* ([`Armed::read_begins`]), not when its answer was
    /// judged: a read that began before the bound can have found nothing and been judged after it,
    /// and the action can be admitted and commit in between.
    pub fn after_read(&mut self, found: Found, began: ReadAt) -> Next {
        if let Phase::Closed(outcome) = self.phase {
            // What an attempt closed as stays what it closed as.
            return Next::Closed(outcome);
        }
        if self.phase == Phase::Asking {
            return Next::Wait;
        }
        let counts = began.0 >= self.bound();
        let outcome = match (self.kind, found) {
            (Kind::Invite | Kind::Transfer, Found::Present) | (Kind::Redeem, Found::Present) => {
                Some(Outcome::Happened)
            }
            (Kind::Invite | Kind::Transfer, Found::Absent) if counts => Some(Outcome::NotDone),
            (Kind::Revoke, Found::Grant(GrantState::Revoked, true)) => Some(Outcome::Happened),
            (Kind::Revoke, Found::Grant(GrantState::Active | GrantState::Pending, _)) if counts => {
                Some(Outcome::NotDone)
            }
            (Kind::Revoke, Found::Grant(GrantState::Expired, _)) => Some(Outcome::HadEnded),
            (Kind::Revoke, Found::Gone) if counts => Some(Outcome::Unknown),
            (Kind::Redeem, Found::Offered) if counts => Some(Outcome::NotAccepted),
            (Kind::Redeem, Found::Neither) if counts => Some(Outcome::Unknown),
            _ => None,
        };
        outcome.map_or(Next::Wait, |outcome| self.close(outcome))
    }

    fn check(&mut self) -> Next {
        self.phase = Phase::Checking;
        Next::Check
    }

    fn close(&mut self, outcome: Outcome) -> Next {
        self.phase = Phase::Closed(outcome);
        Next::Closed(outcome)
    }
}

/// A clock for the safety decision of one running attempt: elapsed time since it was armed, on a
/// clock the wall clock cannot step.
///
/// It is not kept. A restart arms a new one, so the whole bound runs again from the restart, which
/// can only make a read that finds nothing wait longer.
#[derive(Clone, Copy, Debug)]
pub struct Armed {
    from: Instant,
    /// Time added to what the clock reads, by a caller that has to pass a bound without waiting.
    ahead: Duration,
}

impl Armed {
    /// Arms a clock now.
    #[must_use]
    pub fn now() -> Self {
        Self {
            from: Instant::now(),
            ahead: Duration::ZERO,
        }
    }

    /// The same clock reading `by` more than it does. Added time makes a read count sooner than
    /// it should, so no shipped build has it: a test that has to pass a bound without waiting is
    /// the one caller that needs it.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub fn skewed(self, by: Duration) -> Self {
        Self {
            ahead: self.ahead.saturating_add(by),
            ..self
        }
    }

    /// The time since it was armed.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.from.elapsed().saturating_add(self.ahead)
    }

    /// The moment a read of the host is about to be sent. Take it before the read leaves, and give
    /// it to [`Attempt::after_read`] with what the read found.
    #[must_use]
    pub fn read_begins(&self) -> ReadAt {
        ReadAt(self.elapsed())
    }
}

/// When a read of the host began, counted from the moment the attempt's clock was armed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadAt(Duration);

#[cfg(test)]
impl ReadAt {
    /// A read that began `elapsed` after the clock was armed, for a test. A client takes the moment
    /// from [`Armed::read_begins`], and nothing else makes one.
    pub(crate) const fn after(elapsed: Duration) -> Self {
        Self(elapsed)
    }
}

// ---------------------------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------------------------

/// The extension every kept attempt carries.
const EXTENSION: &str = "attempt";

/// The file in the store's directory whose lock a write holds.
const LOCK_NAME: &str = "attempts.lock";

/// How long a write waits for another that is under way.
const LOCK_PATIENCE: Duration = Duration::from_secs(2);

/// The most a kept attempt can hold.
const KEPT_LIMIT: u64 = 256 * 1024;

/// A failure of the store.
#[derive(thiserror::Error)]
pub enum AttemptError {
    /// The store on this device refused.
    #[error("the attempts kept at {path} cannot be used: {fault}")]
    Store {
        /// The file or directory.
        path: Shown,
        /// What the operating system said.
        fault: IoFault,
    },
    /// An attempt could not be encoded to be kept.
    #[error("the attempt cannot be kept: {0}")]
    Encode(Shown),
    /// The file kept for an action is one this build does not read, and is left as it is.
    #[error(
        "the attempt kept at {path} is of a later release, or cannot be read, and is left as it is"
    )]
    Unreadable {
        /// The file.
        path: Shown,
    },
}

crate::debug_as_display!(AttemptError);

/// What a listing found.
#[derive(Clone, PartialEq, Eq)]
pub enum Kept {
    /// An attempt this build reads.
    Known(Box<Attempt>),
    /// A file this build does not read: of a later format, or not an attempt. It is never sent,
    /// changed or removed by this build.
    Unknown {
        /// The file's name.
        name: String,
    },
}

impl std::fmt::Debug for Kept {
    /// Which kind of file it is and, for an attempt, what its own rendering says; never a name.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Known(attempt) => formatter.debug_tuple("Known").field(attempt).finish(),
            Self::Unknown { .. } => formatter.write_str("Unknown { .. }"),
        }
    }
}

/// The attempts one host's clients keep on this device.
#[derive(Clone)]
pub struct AttemptStore {
    directory: PathBuf,
}

crate::debug_as_name!(AttemptStore);

impl AttemptStore {
    /// Opens the store, creating its directory, readable only by its owner, when it is missing.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptError::Store`] when the directory cannot be created.
    pub fn open(directory: impl Into<PathBuf>) -> std::result::Result<Self, AttemptError> {
        let directory = directory.into();
        crate::drafts::private_directory(&directory).map_err(|error| AttemptError::Store {
            path: Shown::root(&directory),
            fault: IoFault::from(error),
        })?;
        Ok(Self { directory })
    }

    /// Keeps an attempt, in place of any kept for the same action.
    ///
    /// It is written to a file of its own, flushed and renamed over the name, and the directory
    /// flushed after, under a lock every window of the application holds, so a reader never sees
    /// half of one. A file kept for the action that this build does not read is left as it is.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptError::Store`] when it cannot be written, [`AttemptError::Encode`] when it
    /// does not encode or is larger than a kept attempt may be, and [`AttemptError::Unreadable`]
    /// when the file already kept for the action is not one this build reads.
    pub fn keep(&self, attempt: &Attempt) -> std::result::Result<(), AttemptError> {
        let _lock = self.locked()?;
        self.write(attempt)
    }

    fn locked(&self) -> std::result::Result<std::fs::File, AttemptError> {
        let lock_path = self.directory.join(LOCK_NAME);
        lock(&lock_path).map_err(|error| AttemptError::Store {
            path: stored(&lock_path),
            fault: IoFault::from(error),
        })
    }

    /// Writes an attempt, with the store's lock held.
    fn write(&self, attempt: &Attempt) -> std::result::Result<(), AttemptError> {
        let bytes = kr_cbor::to_canonical_vec(attempt)
            .map_err(|error| AttemptError::Encode(Shown::cbor(&error)))?;
        // A record this build could not read back is one it must not keep.
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > KEPT_LIMIT {
            return Err(AttemptError::Encode(Shown::said(
                "the attempt is larger than a kept attempt may be",
            )));
        }
        // A record that does not read back with this build's own limits is one it must not keep.
        match kr_cbor::from_canonical_slice::<Attempt>(&bytes, &kr_cbor::Limits::DEFAULT) {
            Ok(back) if back == *attempt => {}
            _ => {
                return Err(AttemptError::Encode(Shown::said(
                    "the attempt does not read back as it was written",
                )));
            }
        }
        let path = self.path(attempt.action_id);
        self.refuse_unreadable(&path)?;
        let store = |error| AttemptError::Store {
            path: stored(&path),
            fault: IoFault::from(error),
        };
        let unique = crate::drafts::fresh_uuid()
            .map_err(|error| store(std::io::Error::other(crate::shown!("{}", error))))?;
        let partial = self
            .directory
            .join(format!(".{}.{unique}.partial", attempt.action_id));
        crate::drafts::write_whole(&partial, &bytes).map_err(store)?;
        if let Err(error) = kr_flush::retry_while_held(|| std::fs::rename(&partial, &path)) {
            let _ = std::fs::remove_file(&partial);
            return Err(store(error));
        }
        kr_flush::flush_directory(&self.directory, kr_flush::NameKind::File).map_err(store)
    }

    /// Every attempt kept, oldest first, and every file this build does not read.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptError::Store`] when the directory cannot be read.
    pub fn attempts(&self) -> std::result::Result<Vec<Kept>, AttemptError> {
        let entries = std::fs::read_dir(&self.directory).map_err(|error| AttemptError::Store {
            path: Shown::root(&self.directory),
            fault: IoFault::from(error),
        })?;
        let mut kept = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| AttemptError::Store {
                path: Shown::root(&self.directory),
                fault: IoFault::from(error),
            })?;
            let path = entry.path();
            // A partial write whose process did not live to rename it is not an attempt.
            if path.extension().and_then(|extension| extension.to_str()) != Some(EXTENSION) {
                continue;
            }
            kept.push(read(&path));
        }
        kept.sort_by_key(|kept| match kept {
            Kept::Known(attempt) => (attempt.composed_at_ms.get(), attempt.action_id.to_string()),
            Kept::Unknown { name } => (u64::MAX, name.clone()),
        });
        Ok(kept)
    }

    /// Forgets the attempt kept for one action, when there is one. A file kept for the action that
    /// this build does not read is left as it is.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptError::Store`] when it cannot be removed and [`AttemptError::Unreadable`]
    /// when the file kept for the action is not one this build reads.
    pub fn remove(&self, action_id: ActionId) -> std::result::Result<(), AttemptError> {
        let path = self.path(action_id);
        let _lock = self.locked()?;
        self.refuse_unreadable(&path)?;
        match std::fs::remove_file(&path) {
            Ok(()) => kr_flush::flush_directory(&self.directory, kr_flush::NameKind::File).map_err(
                |error| AttemptError::Store {
                    path: Shown::root(&self.directory),
                    fault: IoFault::from(error),
                },
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AttemptError::Store {
                path: stored(&path),
                fault: IoFault::from(error),
            }),
        }
    }

    /// Refuses to replace or delete a file this build does not read: of a later release, or not an
    /// attempt at all. Another release may hold it open, and this one cannot tell what it keeps.
    /// Called with the store's lock held, so a file cannot change between the look and the change.
    fn refuse_unreadable(&self, path: &Path) -> std::result::Result<(), AttemptError> {
        // The entry itself, not what a link points at: a link whose target is gone is an entry
        // this build does not read, and is left as it is.
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(AttemptError::Store {
                path: stored(path),
                fault: IoFault::from(error),
            }),
            Ok(_) => match read(path) {
                Kept::Known(_) => Ok(()),
                Kept::Unknown { .. } => Err(AttemptError::Unreadable { path: stored(path) }),
            },
        }
    }

    fn path(&self, action_id: ActionId) -> PathBuf {
        self.directory.join(format!("{action_id}.{EXTENSION}"))
    }
}

/// An attempt's file as a failure may name it: whole when this store wrote its name.
fn stored(path: &Path) -> Shown {
    Shown::stored(path, &[LOCK_NAME], &[EXTENSION, "partial"])
}

/// Reads one kept file: an attempt this build reads, or the name of what it does not.
fn read(path: &Path) -> Kept {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
        .to_owned();
    let Ok(Some(bytes)) = kr_ipc::paths::read_owner_only_file(path, KEPT_LIMIT) else {
        return Kept::Unknown { name };
    };
    match kr_cbor::from_canonical_slice::<Attempt>(&bytes, &kr_cbor::Limits::DEFAULT) {
        // A file is the attempt its name says it is: one that holds another action's is not read,
        // so a change made to the name's action never lands on it.
        Ok(attempt)
            if attempt.version == ATTEMPT_FORMAT
                && name == format!("{}.{EXTENSION}", attempt.action_id) =>
        {
            Kept::Known(Box::new(attempt))
        }
        _ => Kept::Unknown { name },
    }
}

/// Takes the store's lock for a write, waiting [`LOCK_PATIENCE`] for another that is under way.
/// Closing the file releases it.
fn lock(path: &Path) -> std::io::Result<std::fs::File> {
    let file = kr_ipc::paths::open_lock_file(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidInput {
            std::io::Error::other(Shown::said("the lock is not a regular file"))
        } else {
            error
        }
    })?;
    let deadline = Instant::now() + LOCK_PATIENCE;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::envelope::{ActionTarget, ParamsValue};
    use kr_protocol::ids::{ActionWindowId, EnvironmentId, RequestId};
    use kr_protocol::ids::{DeviceId, SessionId};
    use kr_protocol::scalars::{DurationMs, Uuid};

    fn request() -> MutationRequest {
        MutationRequest {
            request_id: RequestId::new(0),
            method: Method::GrantRedeem.into(),
            method_version: Method::GrantRedeem.entry().version,
            action_id: ActionId::new(Uuid::from_bytes([0xa1; 16])),
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id: EnvironmentId::new(Uuid::from_bytes([0xe1; 16])),
                session_id: Nullable::null(),
                session_epoch: Nullable::null(),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("window-1").expect("a window"),
            requested_ttl_ms: DurationMs::new(120_000),
            params: ParamsValue::empty(),
        }
    }

    fn reach() -> Reach {
        Reach {
            host: "host-1".to_owned(),
            actor: "device:phone".to_owned(),
        }
    }

    /// A read that began `secs` after the attempt's clock was armed.
    fn at(secs: u64) -> ReadAt {
        ReadAt::after(Duration::from_secs(secs))
    }

    fn attempt(kind: Kind) -> Attempt {
        let composed = ComposedMutation::restored(request(), 1_000, 300_000, Some(reach()));
        Attempt::new(
            kind,
            &composed,
            Some(GrantId::new(Uuid::from_bytes([0xb2; 16]))),
            2_000,
            "Accept session 3",
        )
    }

    /// A read that finds nothing counts only once the window the request was sent under, and the
    /// margin after it, have passed on the clock that cannot be stepped: before that the host may
    /// not have read the request, and no commit of it can be ruled out.
    #[test]
    fn a_read_that_finds_nothing_waits_for_the_window_and_the_margin() {
        for kind in [Kind::Invite, Kind::Transfer] {
            let mut waiting = attempt(kind);
            assert_eq!(waiting.after_read(Found::Absent, at(329)), Next::Wait);
            assert!(!waiting.is_closed());
            assert_eq!(
                waiting.after_read(Found::Absent, at(330)),
                Next::Closed(Outcome::NotDone)
            );
        }
        let mut challenge = attempt(Kind::Transfer);
        challenge.shortened_to(Duration::from_secs(120));
        assert_eq!(challenge.bound(), Duration::from_secs(150));
        assert_eq!(
            challenge.after_read(Found::Absent, at(150)),
            Next::Closed(Outcome::NotDone)
        );
    }

    /// What a read finds closes an attempt at once, and an absent grant proves nothing for a
    /// revocation or a redemption: the grant can have been revoked, or redeemed, and ended since.
    #[test]
    fn what_a_read_finds_closes_the_attempt_and_an_absent_grant_proves_nothing_of_a_revocation() {
        let late = at(10_000);
        let early = at(0);
        let mut invite = attempt(Kind::Invite);
        assert_eq!(
            invite.after_read(Found::Present, early),
            Next::Closed(Outcome::Happened)
        );
        let mut revoke = attempt(Kind::Revoke);
        assert_eq!(
            revoke.after_read(Found::Grant(GrantState::Revoked, false), late),
            Next::Wait,
            "a revoked grant with no revocation time is not proof"
        );
        assert_eq!(
            revoke.after_read(Found::Grant(GrantState::Revoked, true), early),
            Next::Closed(Outcome::Happened)
        );
        let mut active = attempt(Kind::Revoke);
        assert_eq!(
            active.after_read(Found::Grant(GrantState::Active, false), early),
            Next::Wait
        );
        assert_eq!(
            active.after_read(Found::Grant(GrantState::Active, false), late),
            Next::Closed(Outcome::NotDone)
        );
        let mut expired = attempt(Kind::Revoke);
        assert_eq!(
            expired.after_read(Found::Grant(GrantState::Expired, false), early),
            Next::Closed(Outcome::HadEnded),
            "an expired grant does not show that this revocation did anything"
        );
        let mut gone = attempt(Kind::Revoke);
        assert_eq!(
            gone.after_read(Found::Gone, late),
            Next::Closed(Outcome::Unknown)
        );
        let mut redeem = attempt(Kind::Redeem);
        assert_eq!(redeem.after_read(Found::Neither, early), Next::Wait);
        assert_eq!(
            redeem.after_read(Found::Neither, late),
            Next::Closed(Outcome::Unknown),
            "a redemption that happened can have ended and left the list"
        );
        let mut offered = attempt(Kind::Redeem);
        assert_eq!(
            offered.after_read(Found::Offered, late),
            Next::Closed(Outcome::NotAccepted)
        );
        let mut accepted = attempt(Kind::Redeem);
        assert_eq!(
            accepted.after_read(Found::Present, early),
            Next::Closed(Outcome::Happened)
        );
    }

    /// Only a result, or a refusal the host keeps as the action's answer, closes an attempt by
    /// itself; no answer to a repeat but a result does, and a lost answer to a repeat asks again
    /// until the repeats are used up.
    #[test]
    fn only_a_result_or_a_kept_refusal_closes_an_attempt_and_no_repeat_does_but_with_a_result() {
        let mut kept = attempt(Kind::Invite);
        assert_eq!(
            kept.after_first_send(Reply::Refused(RetryCategory::ConfigurationChange)),
            Next::Closed(Outcome::Refused)
        );
        for other in [
            Reply::Refused(RetryCategory::Transient),
            Reply::Refused(RetryCategory::OutcomeUnknown),
            Reply::Lost,
        ] {
            let mut unfinished = attempt(Kind::Invite);
            assert_eq!(unfinished.after_first_send(other), Next::Repeat);
            assert_eq!(unfinished.phase, Phase::Unfinished);
        }
        let mut sent = attempt(Kind::Invite);
        assert_eq!(sent.after_first_send(Reply::NotSent), Next::NotSent);
        assert_eq!(sent.phase, Phase::Composed);

        // A refusal to a repeat, whatever its category, is a read of the host, never a closure.
        for refusal in [
            RetryCategory::NoRetry,
            RetryCategory::ConfigurationChange,
            RetryCategory::Transient,
        ] {
            let mut repeated = attempt(Kind::Transfer);
            repeated.after_first_send(Reply::Lost);
            assert_eq!(
                repeated.after_repeat(Reply::Refused(refusal)),
                Next::Check,
                "{refusal:?}"
            );
            assert_eq!(repeated.phase, Phase::Checking);
        }
        let mut lost = attempt(Kind::Revoke);
        lost.after_first_send(Reply::Lost);
        assert_eq!(lost.after_repeat(Reply::Lost), Next::Repeat);
        assert_eq!(lost.after_repeat(Reply::Lost), Next::Repeat);
        assert_eq!(lost.after_repeat(Reply::Lost), Next::Check);
        let mut result = attempt(Kind::Revoke);
        result.after_first_send(Reply::Lost);
        assert_eq!(
            result.after_repeat(Reply::Result),
            Next::Closed(Outcome::Happened)
        );
    }

    /// The record is the format this build writes, and a record of any other format, or none, is
    /// shown as unknown and left as it is. The bytes of one attempt are the format's definition:
    /// this fails when a member of the record changes while its version stays.
    #[test]
    fn an_attempts_kept_bytes_are_the_format_and_an_unknown_file_is_not_read() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let store = AttemptStore::open(directory.path().join("attempts")).expect("opens");
        let mut kept = attempt(Kind::Redeem);
        kept.after_first_send(Reply::Lost);
        kept.hidden = true;
        kept.follow_up = true;
        let bytes = kr_cbor::to_canonical_vec(&kept).expect("encodes");
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex, GOLDEN,
            "the record's bytes changed: raise ATTEMPT_FORMAT"
        );
        store.keep(&kept).expect("kept");
        let other = Attempt {
            version: ATTEMPT_FORMAT + 1,
            action_id: ActionId::new(Uuid::from_bytes([0xa2; 16])),
            ..kept.clone()
        };
        std::fs::write(
            directory
                .path()
                .join("attempts")
                .join(format!("{}.attempt", other.action_id)),
            kr_cbor::to_canonical_vec(&other).expect("encodes"),
        )
        .expect("a later release's file");
        let listed = store.attempts().expect("listed");
        assert_eq!(listed.len(), 2);
        assert!(
            listed
                .iter()
                .any(|entry| matches!(entry, Kept::Known(attempt) if **attempt == kept))
        );
        assert!(
            listed
                .iter()
                .any(|entry| matches!(entry, Kept::Unknown { .. })),
            "a record of a later format is shown as unknown"
        );
        store.remove(kept.action_id).expect("removed");
        assert_eq!(store.attempts().expect("listed").len(), 1);
    }

    /// A link in the store whose target is gone is an entry this build does not read, and is
    /// neither replaced nor removed: the guard looks at the entry itself.
    #[cfg(unix)]
    #[test]
    fn a_link_with_no_target_is_neither_replaced_nor_removed() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let root = directory.path().join("attempts");
        let store = AttemptStore::open(&root).expect("opens");
        let kept = attempt(Kind::Redeem);
        let path = root.join(format!("{}.attempt", kept.action_id));
        std::os::unix::fs::symlink(directory.path().join("nowhere"), &path).expect("a link");
        assert!(matches!(
            store.keep(&kept),
            Err(AttemptError::Unreadable { .. })
        ));
        assert!(matches!(
            store.remove(kept.action_id),
            Err(AttemptError::Unreadable { .. })
        ));
        assert!(path.symlink_metadata().is_ok(), "the link is still there");
    }

    /// The transfer of control a host describes, with keys that do not change between runs.
    fn plan() -> TransferControlPlan {
        use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope};
        use kr_protocol::ids::DeviceKeyRevision;
        use kr_protocol::pairing::{DeviceName, DevicePublicKeys};
        use kr_protocol::rights::ActionRight;
        use kr_protocol::scalars::{
            AuthorisationKey, CanonicalSet, EndpointKey, NotificationPreviewKey, StoredEnvelopeKey,
        };

        TransferControlPlan {
            environment_id: EnvironmentId::new(Uuid::from_bytes([0xe1; 16])),
            session_id: SessionId::new(Uuid::from_bytes([10; 16])),
            source_grant_id: GrantId::new(Uuid::from_bytes([11; 16])),
            parent_grant_id: Nullable::null(),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([1; 16])),
            from_device_id: DeviceId::new(Uuid::from_bytes([12; 16])),
            from_device_name: DeviceName::new("laptop").expect("a name"),
            to_device_id: DeviceId::new(Uuid::from_bytes([13; 16])),
            to_device_name: DeviceName::new("phone").expect("a name"),
            to_keys: DevicePublicKeys {
                transport: EndpointKey::from_bytes([21; 32]),
                authorisation: AuthorisationKey::from_bytes([22; 32]),
                stored_envelope: StoredEnvelopeKey::from_bytes([23; 32]),
                notification_preview: NotificationPreviewKey::from_bytes([24; 32]),
            },
            to_key_revision: DeviceKeyRevision::new(1),
            new_grant_id: GrantId::new(Uuid::from_bytes([14; 16])),
            environment_selector: EnvironmentSelector::Any,
            actions: [ActionRight::SessionView, ActionRight::SessionShare]
                .into_iter()
                .collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: false,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::At {
                expires_at_ms: TimestampMs::new(4_000_000),
            },
            organisation: Nullable::null(),
        }
    }

    /// A redemption's kept refusal is not the end of it, since the paired door can replace the
    /// result of one that committed with a refusal, and the effect can outlive the request. The
    /// share the device holds decides: a share closes it as accepted at once, and an offer still
    /// listed or nothing listed counts only once the bound has passed, as for any absent write.
    /// Every other kind still closes as refused.
    #[test]
    fn a_kept_refusal_to_a_redemption_leaves_the_shares_to_decide_and_the_bound_to_wait() {
        let kept = Reply::Refused(RetryCategory::ConfigurationChange);
        let mut accepted = attempt(Kind::Redeem);
        assert_eq!(accepted.after_first_send(kept), Next::Check);
        assert_eq!(accepted.phase, Phase::Checking);
        assert_eq!(
            accepted.after_read(Found::Present, at(0)),
            Next::Closed(Outcome::Happened),
            "a share the device holds shows the redemption happened, whatever the refusal said"
        );
        let mut offered = attempt(Kind::Redeem);
        offered.after_first_send(kept);
        assert_eq!(
            offered.after_read(Found::Offered, at(0)),
            Next::Wait,
            "an offer still listed proves nothing while the effect can still commit"
        );
        assert_eq!(
            offered.after_read(Found::Offered, ReadAt::after(offered.bound())),
            Next::Closed(Outcome::NotAccepted)
        );
        let mut neither = attempt(Kind::Redeem);
        neither.after_first_send(Reply::Refused(RetryCategory::NoRetry));
        assert_eq!(neither.after_read(Found::Neither, at(0)), Next::Wait);
        assert_eq!(
            neither.after_read(Found::Neither, ReadAt::after(neither.bound())),
            Next::Closed(Outcome::Unknown)
        );
        // A refusal in a category that can be retried is unfinished, as for every kind.
        let mut transient = attempt(Kind::Redeem);
        assert_eq!(
            transient.after_first_send(Reply::Refused(RetryCategory::Transient)),
            Next::Repeat
        );
        assert!(transient.bound() > Duration::from_secs(300));
        for other in [Kind::Invite, Kind::Revoke, Kind::Transfer] {
            let mut refused = attempt(other);
            assert_eq!(
                refused.after_first_send(kept),
                Next::Closed(Outcome::Refused),
                "{other:?}"
            );
        }
    }

    /// A request for `method` under `action`, as the tests below compose them. A transfer is for
    /// what `plan()` describes.
    fn request_of(method: Method, action: ActionId) -> MutationRequest {
        let mut request = MutationRequest {
            method: method.into(),
            method_version: method.entry().version,
            action_id: action,
            ..request()
        };
        if method == Method::GrantTransfer {
            request.target.session_id = Nullable::some(plan().session_id);
            request.params = ParamsValue::from_typed(&GrantTransferParams {
                session_id: plan().session_id,
                from_grant_id: plan().source_grant_id,
                to_device_id: plan().to_device_id,
            })
            .expect("parameters");
        }
        request
    }

    /// A hand-over still asking for its confirmation has nothing to send, so no answer moves it;
    /// a confirmed one is sent under the window of the transfer, bounded by what its challenge
    /// had left when the transfer was composed, which is less than its lifetime when the owner
    /// device was slow. The transfer takes over the record whole, and what is not the transfer
    /// leaves it as it was.
    #[test]
    fn a_hand_over_being_asked_for_moves_only_when_it_is_confirmed_and_is_bounded_by_what_is_left()
    {
        let transfer_action = ActionId::new(Uuid::from_bytes([0xc7; 16]));
        let confirmation = ComposedMutation::restored(
            request_of(
                Method::OwnerConfirmationRequest,
                ActionId::new(Uuid::from_bytes([0xc1; 16])),
            ),
            1_000,
            300_000,
            Some(reach()),
        );
        let mut asking = Attempt::asking(
            &confirmation,
            transfer_action,
            plan().new_grant_id,
            2_000,
            "Handing over",
        );
        assert_eq!(asking.phase, Phase::Asking);
        assert_eq!(
            asking.action_id, transfer_action,
            "the record is named for the transfer"
        );
        assert_ne!(asking.request.action_id, transfer_action);
        assert_eq!(asking.after_first_send(Reply::Result), Next::NotSent);
        assert_eq!(asking.after_repeat(Reply::Result), Next::NotSent);
        assert_eq!(asking.after_read(Found::Present, at(10_000)), Next::Wait);
        assert_eq!(
            asking.phase,
            Phase::Asking,
            "the challenge is not the transfer"
        );

        // What is not the transfer under this record's action, for this record's plan, changes
        // nothing: a transfer for another action, a request for another method under this
        // action (the confirmation request itself among them), and a plan that writes another
        // grant than the one a read looks for.
        let before = asking.clone();
        let composed = |method, action| {
            ComposedMutation::restored(request_of(method, action), 5_000, 300_000, None)
        };
        let someone_elses = ActionId::new(Uuid::from_bytes([0xc2; 16]));
        let other_plan = TransferControlPlan {
            new_grant_id: GrantId::new(Uuid::from_bytes([0x15; 16])),
            ..plan()
        };
        let waited = Duration::from_secs(50);
        assert!(!asking.confirmed_after(
            &composed(Method::GrantTransfer, someone_elses),
            plan(),
            waited
        ));
        assert!(!asking.confirmed_after(
            &composed(Method::GrantRedeem, transfer_action),
            plan(),
            waited
        ));
        assert!(!asking.confirmed_after(
            &composed(Method::OwnerConfirmationRequest, transfer_action),
            plan(),
            waited
        ));
        assert!(!asking.confirmed_after(
            &composed(Method::GrantTransfer, transfer_action),
            other_plan,
            waited
        ));
        // A transfer, validly encoded, of another session, another giving grant or another
        // receiving device than the plan the owner confirmed.
        let of_the_params = |change: &dyn Fn(&mut GrantTransferParams)| {
            let mut request = request_of(Method::GrantTransfer, transfer_action);
            let mut params = request
                .params
                .to_typed::<GrantTransferParams>()
                .expect("params");
            change(&mut params);
            request.params = ParamsValue::from_typed(&params).expect("parameters");
            ComposedMutation::restored(request, 5_000, 300_000, None)
        };
        for other in [
            of_the_params(&|params| {
                params.session_id = SessionId::new(Uuid::from_bytes([0x77; 16]))
            }),
            of_the_params(&|params| {
                params.from_grant_id = GrantId::new(Uuid::from_bytes([0x78; 16]))
            }),
            of_the_params(&|params| {
                params.to_device_id = DeviceId::new(Uuid::from_bytes([0x79; 16]))
            }),
        ] {
            assert!(!asking.confirmed_after(&other, plan(), waited));
        }
        let mut elsewhere = request_of(Method::GrantTransfer, transfer_action);
        elsewhere.target.session_id = Nullable::some(SessionId::new(Uuid::from_bytes([0x7a; 16])));
        assert!(!asking.confirmed_after(
            &ComposedMutation::restored(elsewhere, 5_000, 300_000, None),
            plan(),
            waited
        ));
        // One that states a host or an actor other than the confirmation's.
        assert!(!asking.confirmed_after(
            &ComposedMutation::restored(
                request_of(Method::GrantTransfer, transfer_action),
                5_000,
                300_000,
                Some(Reach {
                    host: "host-1".to_owned(),
                    actor: "device:another".to_owned(),
                }),
            ),
            plan(),
            waited
        ));
        assert_eq!(asking, before);

        // The challenge, 120 seconds long, was answered 50 seconds before the transfer was
        // composed, so 70 seconds of it are left then. A transfer that states a reach is repeated
        // as that reach.
        let stated_reach = reach();
        let transfer = ComposedMutation::restored(
            request_of(Method::GrantTransfer, transfer_action),
            5_000,
            300_000,
            Some(stated_reach.clone()),
        );
        let mut stated = asking.clone();
        assert!(stated.confirmed_after(&transfer, plan(), waited));
        assert_eq!(stated.reach(), Some(stated_reach));
        assert!(asking.confirmed_after(
            &composed(Method::GrantTransfer, transfer_action),
            plan(),
            waited
        ));
        assert_eq!(asking.phase, Phase::Composed);
        assert_eq!(asking.action_id, transfer_action);
        assert_eq!(asking.request.action_id, transfer_action);
        assert_eq!(asking.composed().action_id(), asking.action_id);
        assert_eq!(asking.window_issued_at_ms, 5_000);
        assert_eq!(asking.plan, Nullable::some(plan()));
        assert_eq!(
            asking.grant_id,
            Nullable::some(plan().new_grant_id),
            "a read looks for the grant the plan writes"
        );
        assert_eq!(
            asking.reach(),
            None,
            "a request that states no reach is never repeated, not repeated as the confirmation was"
        );
        assert_eq!(
            asking.bound(),
            Duration::from_secs(100),
            "what the challenge has left, and the margin, from the moment the clock is armed"
        );
        assert_eq!(
            asking.after_read(Found::Absent, at(99)),
            Next::Wait,
            "a read that began before the challenge could no longer commit proves nothing"
        );
        assert_eq!(
            asking.after_read(Found::Absent, at(100)),
            Next::Closed(Outcome::NotDone)
        );
        // Only a hand-over being asked for is confirmed.
        let again = composed(Method::GrantTransfer, transfer_action);
        let mut other = attempt(Kind::Transfer);
        assert!(!other.confirmed_after(&again, plan(), waited));
        let mut invite = attempt(Kind::Invite);
        invite.phase = Phase::Asking;
        assert!(!invite.confirmed_after(&again, plan(), waited));
    }

    /// The clock the caller hands over is the one that counts the time since the challenge's
    /// reply: a challenge answered just now has nearly its whole lifetime left.
    #[test]
    fn a_confirmed_hand_over_counts_the_time_since_the_challenge_on_the_clock_it_is_given() {
        let transfer_action = ActionId::new(Uuid::from_bytes([0xc7; 16]));
        let confirmation = ComposedMutation::restored(
            request_of(
                Method::OwnerConfirmationRequest,
                ActionId::new(Uuid::from_bytes([0xc1; 16])),
            ),
            1_000,
            300_000,
            Some(reach()),
        );
        let mut asking = Attempt::asking(
            &confirmation,
            transfer_action,
            plan().new_grant_id,
            2_000,
            "Handing over",
        );
        let transfer = ComposedMutation::restored(
            request_of(Method::GrantTransfer, transfer_action),
            5_000,
            300_000,
            None,
        );
        assert!(asking.confirmed(&transfer, plan(), Armed::now()));
        assert!(asking.bound() <= Duration::from_secs(150));
        assert!(asking.bound() > Duration::from_secs(149));
    }

    /// A transfer a client sends in one process is bounded by what is left of the challenge on the
    /// clock started when its reply arrived, and the lifetime is the host's own.
    #[test]
    fn a_transfer_sent_in_one_process_is_bounded_by_the_challenge_on_the_clock_it_is_given() {
        let mut transfer = attempt(Kind::Transfer);
        assert_eq!(transfer.bound(), Duration::from_secs(330));
        transfer.bound_by_challenge(Armed::now());
        assert!(transfer.bound() <= Duration::from_secs(150));
        assert!(transfer.bound() > Duration::from_secs(149));
        // A challenge answered long ago leaves only the margin.
        let mut late = attempt(Kind::Transfer);
        late.bound_by_challenge(Armed::now().skewed(Duration::from_secs(500)));
        assert_eq!(late.bound(), Duration::from_secs(30));
    }

    /// A hand-over still asking is kept under the transfer's action and read back as it was,
    /// though the request it holds is for another action; once confirmed, it is the same file.
    #[test]
    fn a_hand_over_being_asked_for_is_kept_under_the_transfers_action_and_read_back() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let store = AttemptStore::open(directory.path().join("attempts")).expect("opens");
        let transfer_action = ActionId::new(Uuid::from_bytes([0xc7; 16]));
        let confirmation = ComposedMutation::restored(
            request_of(
                Method::OwnerConfirmationRequest,
                ActionId::new(Uuid::from_bytes([0xc1; 16])),
            ),
            1_000,
            300_000,
            Some(reach()),
        );
        let mut asking = Attempt::asking(
            &confirmation,
            transfer_action,
            plan().new_grant_id,
            2_000,
            "Handing over",
        );
        store.keep(&asking).expect("kept while asking");
        assert_eq!(
            store.attempts().expect("listed"),
            vec![Kept::Known(Box::new(asking.clone()))]
        );
        let transfer = ComposedMutation::restored(
            request_of(Method::GrantTransfer, transfer_action),
            5_000,
            300_000,
            Some(reach()),
        );
        assert!(asking.confirmed_after(&transfer, plan(), Duration::from_secs(1)));
        store.keep(&asking).expect("kept once confirmed");
        assert_eq!(
            store.attempts().expect("listed"),
            vec![Kept::Known(Box::new(asking.clone()))],
            "one file, under the same action"
        );
        store.remove(transfer_action).expect("removed");
    }

    /// An attempt that is over stays over whatever a late call says: a send, a repeat or a read
    /// cannot open it again or close it another way, and so cannot gate a second action again.
    #[test]
    fn a_closed_attempt_stays_as_it_closed_whatever_is_said_after() {
        let mut closed = attempt(Kind::Invite);
        assert_eq!(
            closed.after_read(Found::Present, at(0)),
            Next::Closed(Outcome::Happened)
        );
        for reply in [
            Reply::Result,
            Reply::Lost,
            Reply::NotSent,
            Reply::Refused(RetryCategory::NoRetry),
            Reply::Refused(RetryCategory::Transient),
        ] {
            assert_eq!(
                closed.after_first_send(reply),
                Next::Closed(Outcome::Happened)
            );
            assert_eq!(closed.after_repeat(reply), Next::Closed(Outcome::Happened));
        }
        assert_eq!(
            closed.after_read(Found::Absent, at(10_000)),
            Next::Closed(Outcome::Happened)
        );
        assert_eq!(closed.phase, Phase::Closed(Outcome::Happened));
    }

    /// What the host answered, and what the client refused to send, are told apart for every
    /// error: a variant that may have reached the host is a lost answer, which a repeat settles.
    #[test]
    fn each_error_is_told_as_the_host_s_answer_a_lost_answer_or_a_refusal_made_here() {
        use kr_protocol::error::ErrorCode;
        let reply = |error: ClientError| Reply::of(&Err(error));
        assert_eq!(reply(ClientError::ConnectionEnded), Reply::Lost);
        assert_eq!(reply(ClientError::ResyncRequired), Reply::Lost);
        for local in [
            ClientError::NoActionWindow,
            ClientError::OtherHost,
            ClientError::StillAccounting,
            ClientError::Misdirected { repeating: true },
            ClientError::TooManyUnresolvedActions { limit: 1 },
        ] {
            assert_eq!(reply(local), Reply::NotSent);
        }
        assert_eq!(
            reply(ClientError::Host(kr_protocol::error::ProtocolError::new(
                ErrorCode::PermissionDenied,
                "no"
            ))),
            Reply::Refused(ErrorCode::PermissionDenied.retry_category())
        );
    }

    /// The moment a read began is read off the clock when the read is about to be sent, and it
    /// moves on as time does. What a read began at is all `after_read` is given: it reads no clock
    /// of its own, so an answer that arrives long after the bound judges a read that began before it
    /// as one that did (`a_read_that_finds_nothing_waits_for_the_window_and_the_margin`).
    #[test]
    fn a_read_begins_when_it_is_taken_and_not_when_it_is_judged() {
        let armed = Armed::now();
        let first = armed.read_begins();
        std::thread::sleep(Duration::from_millis(5));
        let second = armed.read_begins();
        assert!(second.0 > first.0);
        let mut waiting = attempt(Kind::Invite);
        waiting.bound_ms = 1_000;
        assert_eq!(
            waiting.after_read(Found::Absent, first),
            Next::Wait,
            "a read begun a moment after the clock was armed is long before the bound, however \
             late its answer is judged"
        );
    }

    /// A file this build does not read is neither replaced nor deleted, whatever else is asked of
    /// the store: a later release may hold it open. A file that holds another action's attempt
    /// under this action's name is such a file, and so is one larger than a kept attempt may be.
    #[test]
    fn a_file_the_store_does_not_read_is_neither_replaced_nor_deleted() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let root = directory.path().join("attempts");
        let store = AttemptStore::open(&root).expect("opens");
        let kept = attempt(Kind::Redeem);
        let path = root.join(format!("{}.attempt", kept.action_id));

        // A later release's file for the action.
        let later = Attempt {
            version: ATTEMPT_FORMAT + 1,
            ..kept.clone()
        };
        let bytes = kr_cbor::to_canonical_vec(&later).expect("encodes");
        std::fs::write(&path, &bytes).expect("a later release's file");
        assert!(matches!(
            store.keep(&kept),
            Err(AttemptError::Unreadable { .. })
        ));
        assert!(matches!(
            store.remove(kept.action_id),
            Err(AttemptError::Unreadable { .. })
        ));
        assert_eq!(std::fs::read(&path).expect("still there"), bytes);

        // A file that is not an attempt at all.
        std::fs::write(&path, b"not an attempt").expect("a malformed file");
        assert!(store.keep(&kept).is_err());
        assert!(store.remove(kept.action_id).is_err());
        assert_eq!(
            std::fs::read(&path).expect("still there"),
            b"not an attempt"
        );

        // Another action's attempt under this action's name is not read either.
        let elsewhere = Attempt {
            action_id: ActionId::new(Uuid::from_bytes([0xa7; 16])),
            ..kept.clone()
        };
        std::fs::write(
            &path,
            kr_cbor::to_canonical_vec(&elsewhere).expect("encodes"),
        )
        .expect("a misnamed file");
        assert!(matches!(
            store.attempts().expect("listed").as_slice(),
            [Kept::Unknown { .. }]
        ));
        assert!(store.remove(kept.action_id).is_err());

        // With the file gone the action's attempt is kept and removed as usual.
        std::fs::remove_file(&path).expect("removed by hand");
        store.keep(&kept).expect("kept");
        store.remove(kept.action_id).expect("removed");

        // One larger than a kept attempt may be is refused rather than kept unreadably.
        let mut large = kept.clone();
        large.label = "x".repeat(300 * 1024);
        assert!(matches!(store.keep(&large), Err(AttemptError::Encode(_))));
        assert!(store.attempts().expect("listed").is_empty());
    }

    /// A record this build could not read back is refused, whatever its size, and the record kept
    /// for the action before it is left as it was: a request whose parameters hold a list longer
    /// than the reader's bound encodes in a few kilobytes and would be kept unreadably.
    #[test]
    fn a_record_that_does_not_read_back_is_refused_and_leaves_the_earlier_one() {
        let directory = kr_ipc::testing::PrivateTempDir::create();
        let store = AttemptStore::open(directory.path().join("attempts")).expect("opens");
        let kept = attempt(Kind::Redeem);
        store.keep(&kept).expect("kept");

        let mut unreadable = kept.clone();
        unreadable.request.params = kr_protocol::envelope::ParamsValue::new(
            kr_cbor::CanonicalValue::Array(vec![kr_cbor::CanonicalValue::Null; 5_000]),
        );
        assert!(matches!(
            store.keep(&unreadable),
            Err(AttemptError::Encode(_))
        ));
        assert_eq!(
            store.attempts().expect("listed"),
            vec![Kept::Known(Box::new(kept))]
        );
    }

    /// A hand-over's record holds its plan, and a closed attempt its outcome: the second record
    /// pins both, with the first, so a member added to the plan changes these bytes and raises
    /// the version instead of leaving kept hand-overs unreadable.
    #[test]
    fn a_closed_hand_over_with_its_plan_is_the_format_too() {
        let mut kept = attempt(Kind::Transfer);
        kept.plan = Nullable::some(plan());
        kept.shortened_to(Duration::from_secs(70));
        kept.after_first_send(Reply::Lost);
        kept.after_repeat(Reply::Refused(RetryCategory::Transient));
        kept.after_read(Found::Present, at(0));
        assert_eq!(kept.phase, Phase::Closed(Outcome::Happened));
        let bytes = kr_cbor::to_canonical_vec(&kept).expect("encodes");
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex, GOLDEN_HAND_OVER,
            "the record's bytes changed: raise ATTEMPT_FORMAT"
        );
        let read = kr_cbor::from_canonical_slice::<Attempt>(&bytes, &kr_cbor::Limits::DEFAULT)
            .expect("reads back");
        assert_eq!(read, kept);
    }

    const GOLDEN_HAND_OVER: &str = "\
        b164686f737466686f73742d31646b696e64687472616e7366657264706c616eb166657870697279a1626174a16d\
        657870697265735f61745f6d731a003d090067616374696f6e73826d73657373696f6e2e73686172656c73657373\
        696f6e2e7669657767686973746f7279a46e6c6f7765725f626f756e645f6d73f66f6e616d65645f617070726f76\
        616c73806f6e616d65645f7175657374696f6e738073696e636c7564655f6c6976655f73637265656ef467746f5f\
        6b657973a4697472616e73706f727458201515151515151515151515151515151515151515151515151515151515\
        1515156d617574686f7269736174696f6e5820161616161616161616161616161616161616161616161616161616\
        16161616166f73746f7265645f656e76656c6f706558201717171717171717171717171717171717171717171717\
        171717171717171717746e6f74696669636174696f6e5f7072657669657758201818181818181818181818181818\
        1818181818181818181818181818181818186a73657373696f6e5f6964500a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\
        6c6e65775f6772616e745f6964500e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e6c6f7267616e69736174696f6ef66c74\
        6f5f6465766963655f6964500d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d6e656e7669726f6e6d656e745f696450e1e1\
        e1e1e1e1e1e1e1e1e1e1e1e1e1e16e66726f6d5f6465766963655f6964500c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c\
        6e746f5f6465766963655f6e616d656570686f6e656f706172656e745f6772616e745f6964f66f736f757263655f\
        6772616e745f6964500b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b6f746f5f6b65795f7265766973696f6e017066726f\
        6d5f6465766963655f6e616d65666c6170746f70706973737565725f6465766963655f6964500101010101010101\
        010101010101010174656e7669726f6e6d656e745f73656c6563746f7263616e79656c6162656c70416363657074\
        2073657373696f6e2033657068617365a166636c6f7365646868617070656e65646668696464656ef46772657065\
        617473006772657175657374aa666d6574686f646c6772616e742e72656465656d66706172616d73a06674617267\
        6574a56a73657373696f6e5f6964f66d73657373696f6e5f65706f6368f66e656e7669726f6e6d656e745f696450\
        e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1766167656e745f62696e64696e675f7265766973696f6ef6776170706c69\
        636174696f6e5f696e7374616e63655f6964f6686578706563746564a0686772616e745f6964f669616374696f6e\
        5f696450a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a16a726571756573745f6964006e6d6574686f645f76657273696f\
        6e0170616374696f6e5f77696e646f775f69646877696e646f772d31707265717565737465645f74746c5f6d731a\
        0001d4c06776657273696f6e0168626f756e645f6d731a000186a0686772616e745f696450b2b2b2b2b2b2b2b2b2\
        b2b2b2b2b2b2b2687374616e64696e676c6465766963653a70686f6e6569616374696f6e5f696450a1a1a1a1a1a1\
        a1a1a1a1a1a1a1a1a1a169666f6c6c6f775f7570f46e636f6d706f7365645f61745f6d731907d07377696e646f77\
        5f6973737565645f61745f6d731903e87377696e646f775f76616c69645f666f725f6d731a000493e0\
    ";

    const GOLDEN: &str = "\
        b164686f737466686f73742d31646b696e646672656465656d64706c616ef6656c6162656c7041636365707420\
        73657373696f6e20336570686173656a756e66696e69736865646668696464656ef56772657065617473006772\
        657175657374aa666d6574686f646c6772616e742e72656465656d66706172616d73a066746172676574a56a73\
        657373696f6e5f6964f66d73657373696f6e5f65706f6368f66e656e7669726f6e6d656e745f696450e1e1e1e1\
        e1e1e1e1e1e1e1e1e1e1e1e1766167656e745f62696e64696e675f7265766973696f6ef6776170706c69636174\
        696f6e5f696e7374616e63655f6964f6686578706563746564a0686772616e745f6964f669616374696f6e5f69\
        6450a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a16a726571756573745f6964006e6d6574686f645f76657273696f6e\
        0170616374696f6e5f77696e646f775f69646877696e646f772d31707265717565737465645f74746c5f6d731a\
        0001d4c06776657273696f6e0168626f756e645f6d731a00050910686772616e745f696450b2b2b2b2b2b2b2b2\
        b2b2b2b2b2b2b2b2687374616e64696e676c6465766963653a70686f6e6569616374696f6e5f696450a1a1a1a1\
        a1a1a1a1a1a1a1a1a1a1a1a169666f6c6c6f775f7570f56e636f6d706f7365645f61745f6d731907d07377696e\
        646f775f6973737565645f61745f6d731903e87377696e646f775f76616c69645f666f725f6d731a000493e0\
    ";
}
