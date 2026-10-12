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
//!   stepped, never on the wall clock; after a restart, when no such clock survives, the whole
//!   bound runs again from the restart. A read that blocks or fails leaves the attempt as it was.
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
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::sharing::GrantState;
use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::session::{ComposedMutation, Settled};
use crate::shown::{IoFault, Shown};

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
    /// The answer was lost: the connection ended, or the host's answer did not arrive, after the
    /// request was sent.
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
                | ClientError::Ipc(_),
            ) => Self::Lost,
            // A connection that ended before the request was answered ended after it was sent, or
            // before it could be: the same as a lost answer, which a repeat settles.
            Err(ClientError::ConnectionEnded) => Self::Lost,
            Err(_) => Self::NotSent,
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
    /// Nothing was sent. The request is kept, unsent.
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
    /// The action. The host keys its record by this and the actor.
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
    /// When the request was composed, on this device's wall clock. It is shown to a person and
    /// decides nothing.
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
    /// `grant_id` is what a read looks for, `host` and `standing` what the request was composed
    /// for, and `composed_at_ms` the wall clock's reading, for display.
    #[must_use]
    pub fn new(
        kind: Kind,
        composed: &ComposedMutation,
        host: impl Into<String>,
        standing: impl Into<String>,
        grant_id: Option<GrantId>,
        composed_at_ms: u64,
        label: impl Into<String>,
    ) -> Self {
        Self {
            version: ATTEMPT_FORMAT,
            kind,
            phase: Phase::Composed,
            action_id: composed.action_id(),
            request: composed.request().clone(),
            window_issued_at_ms: composed.window_issued_at_ms(),
            window_valid_for_ms: composed.window_valid_for_ms(),
            host: host.into(),
            standing: standing.into(),
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

    /// Shortens the bound to a challenge's lifetime, for a transfer: the host refuses an expired
    /// confirmation inside the transaction, so after the challenge's lifetime from the moment its
    /// reply was received nothing can commit, whatever the window says.
    pub fn bound_by_challenge(&mut self, lifetime: Duration) {
        let by_challenge = u64::try_from(lifetime.as_millis())
            .unwrap_or(u64::MAX)
            .saturating_add(MARGIN_MS);
        self.bound_ms = self.bound_ms.min(by_challenge);
    }

    /// The request, to send again.
    #[must_use]
    pub fn composed(&self) -> ComposedMutation {
        ComposedMutation::restored(
            self.request.clone(),
            self.window_issued_at_ms,
            self.window_valid_for_ms,
        )
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
    /// after a commit in these methods is a transient one), and closes it as refused. Anything else
    /// leaves it unfinished.
    pub fn after_first_send(&mut self, reply: Reply) -> Next {
        match reply {
            Reply::Result => self.close(Outcome::Happened),
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

    /// What a client concludes from a read of the host, `elapsed` after the attempt's clock was
    /// armed.
    ///
    /// `elapsed` is measured on a clock that cannot be stepped, from the moment the request was
    /// composed, or from the restart that read the record back.
    pub fn after_read(&mut self, found: Found, elapsed: Duration) -> Next {
        let counts = elapsed >= self.bound();
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
pub struct Armed(Instant);

impl Armed {
    /// Arms a clock now.
    #[must_use]
    pub fn now() -> Self {
        Self(Instant::now())
    }

    /// The time since it was armed.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.0.elapsed()
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
}

crate::debug_as_display!(AttemptError);

/// What a listing found.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// The attempts one host's clients keep on this device.
#[derive(Clone, Debug)]
pub struct AttemptStore {
    directory: PathBuf,
}

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
    /// half of one.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptError::Store`] when it cannot be written and [`AttemptError::Encode`] when
    /// it does not encode.
    pub fn keep(&self, attempt: &Attempt) -> std::result::Result<(), AttemptError> {
        let bytes = kr_cbor::to_canonical_vec(attempt)
            .map_err(|error| AttemptError::Encode(Shown::cbor(&error)))?;
        let path = self.path(attempt.action_id);
        let store = |error| AttemptError::Store {
            path: stored(&path),
            fault: IoFault::from(error),
        };
        let lock_path = self.directory.join(LOCK_NAME);
        let _lock = lock(&lock_path).map_err(|error| AttemptError::Store {
            path: stored(&lock_path),
            fault: IoFault::from(error),
        })?;
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

    /// Forgets the attempt kept for one action, when there is one.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptError::Store`] when it cannot be removed.
    pub fn remove(&self, action_id: ActionId) -> std::result::Result<(), AttemptError> {
        let path = self.path(action_id);
        let lock_path = self.directory.join(LOCK_NAME);
        let _lock = lock(&lock_path).map_err(|error| AttemptError::Store {
            path: stored(&lock_path),
            fault: IoFault::from(error),
        })?;
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
        Ok(attempt) if attempt.version == ATTEMPT_FORMAT => Kept::Known(Box::new(attempt)),
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
    use kr_protocol::method::Method;
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

    fn attempt(kind: Kind) -> Attempt {
        let composed = ComposedMutation::restored(request(), 1_000, 300_000);
        Attempt::new(
            kind,
            &composed,
            "host-1",
            "device:phone",
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
            assert_eq!(
                waiting.after_read(Found::Absent, Duration::from_secs(329)),
                Next::Wait
            );
            assert!(!waiting.is_closed());
            assert_eq!(
                waiting.after_read(Found::Absent, Duration::from_secs(330)),
                Next::Closed(Outcome::NotDone)
            );
        }
        let mut challenge = attempt(Kind::Transfer);
        challenge.bound_by_challenge(Duration::from_secs(120));
        assert_eq!(challenge.bound(), Duration::from_secs(150));
        assert_eq!(
            challenge.after_read(Found::Absent, Duration::from_secs(150)),
            Next::Closed(Outcome::NotDone)
        );
    }

    /// What a read finds closes an attempt at once, and an absent grant proves nothing for a
    /// revocation or a redemption: the grant can have been revoked, or redeemed, and ended since.
    #[test]
    fn what_a_read_finds_closes_the_attempt_and_an_absent_grant_proves_nothing_of_a_revocation() {
        let late = Duration::from_secs(10_000);
        let early = Duration::ZERO;
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
