//! The draft a device keeps on a host it is paired with: one for each host, principal and session.
//!
//! The device makes the draft at the first bind and never before, keeps its identifier and its last
//! known revision in the folder of open transfers (`<hash>.draft`, JSON, version 1, written before
//! the call that uses it), and uses it again for a new window and after a restart.
//!
//! * **A lost answer is asked again exactly.** A `draft.create` or `draft.discard` is composed once;
//!   the whole request, window included, is kept in the entry before it is sent, and a later attempt
//!   sends that request again with `Session::repeat` on the next connection, so the host answers
//!   from its record. A request the host has no record of is refused for its window; only once that
//!   window and a margin have passed, on a clock that cannot be stepped, is the action known not to
//!   have happened, and a new one is made. Until then the entry keeps it and says so.
//! * **One operation at a time for a draft.** Binds, texts, ends, the start's sweep and the prompt
//!   that uses the draft take a turn for the host, principal and session until their last write.
//! * **The revision is known or it is not.** It is written as unknown before a bind goes out and as
//!   the host's answer after it, so a stop in between leaves a draft that is ended and not guessed
//!   at. A refusal for a stale revision names the revision the draft is at; it is taken from the
//!   message and the call goes on.
//! * **Another layout is left alone.** An entry of another version is never read or overwritten; the
//!   operations that would need it say so.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use kr_client::services::AccountMark;
use kr_client::session::ComposedMutation;
use kr_client::transport::Reach;
use kr_client::{ClientError, Settled as Answered};
use kr_protocol::envelope::{ActionTarget, MutationRequest};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ActionId, ApplicationInstanceId, DeviceId, DraftId, DraftRevision, EnvironmentId, SessionId,
    TransferId,
};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AgentDraftAddAttachmentResult, AttachmentContribution,
    DraftAttachment, DraftCreateParams, DraftCreateResult, DraftDiscardParams, DraftUpdateParams,
    DraftUpdateResult,
};
use serde::{Deserialize, Serialize};

use crate::commands::{MUTATION_TTL, NoPreconditions};
use crate::error::{CommandError, Result};
use crate::open_transfers::{Paired, host_words};

/// The format of a draft entry this build writes, recorded in it as `version`.
pub const DRAFT_VERSION: u32 = 1;

/// What a refused end of a draft by an older host is told as, once the host's own bound is reached.
pub const UPDATE_THE_HOST: &str =
    "update the host: it cannot end a draft this device no longer needs";

/// What a bind is told when the session or the draft this file was for is gone on the host.
pub const GONE: &str =
    "the session or the draft this file was for is gone on the host: the file was not added to it";

/// What a text is told when the session or the draft it was for is gone on the host.
pub const GONE_FOR_TEXT: &str =
    "the session or the draft this message was for is gone on the host: the message was not sent";

/// What a text is told when this device keeps no draft for the session.
pub const NO_DRAFT: &str = "this device keeps no draft for this session: add a file to it first";

/// What a bind is told when the draft changed twice while the file was being added.
pub const CHANGED_AGAIN: &str =
    "the draft changed again while the file was being added: the file was not added";

/// What an operation is told when the draft kept for the session is of a later release.
pub const NEWER_DRAFT: &str = "this device keeps a draft for this session in a format this release does not read: update the application to use it";

/// What an operation is told when the host's answer to the creation of the draft has not been
/// received and the creation is not known to have failed.
pub const CREATE_PENDING: &str = "the host was asked to make a draft for this session and its answer has not been received: try again later";

/// What an operation is told when the host's answer to the end of the draft has not been received.
pub const DISCARD_PENDING: &str = "the host was asked to end the draft for this session and its answer has not been received: try again later";

const EXTENSION: &str = "draft";

/// The time after a window has ended that an absent record is waited out, as the grant attempts do.
const MARGIN_MS: u64 = 30_000;

/// The revision a stale-revision refusal says the draft is at.
///
/// The host writes "this draft is at revision N and the update expects M" to an update and "this draft
/// is at revision N and the binding expects M" to a bind. Anything else gives nothing, and the draft
/// is ended and not guessed at.
#[must_use]
pub fn revision_in(message: &str) -> Option<DraftRevision> {
    let rest = message.strip_prefix("this draft is at revision ")?;
    let (current, expected) = rest.split_once(" and the ")?;
    let expected = expected
        .strip_prefix("update expects ")
        .or_else(|| expected.strip_prefix("binding expects "))?;
    let digits = |text: &str| {
        (!text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| text.parse::<u64>().ok())
            .flatten()
    };
    digits(expected)?;
    digits(current).map(DraftRevision::new)
}

/// A request kept whole, to be sent again exactly: canonical CBOR as hex, with the window and the
/// host and actor it was composed for.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KeptRequest {
    action_id: ActionId,
    request: String,
    window_issued_at_ms: u64,
    window_valid_for_ms: u64,
    host: String,
    actor: String,
}

fn hex_of(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

fn bytes_of(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

impl KeptRequest {
    fn of(composed: &ComposedMutation) -> Result<Self> {
        let request = kr_cbor::to_canonical_vec(composed.request())
            .map_err(|error| CommandError::local_failure(error.to_string()))?;
        let (host, actor) = composed.reach().map_or_else(Default::default, |reach| {
            (reach.host.clone(), reach.actor.clone())
        });
        Ok(Self {
            action_id: composed.action_id(),
            request: hex_of(&request),
            window_issued_at_ms: composed.window_issued_at_ms(),
            window_valid_for_ms: composed.window_valid_for_ms(),
            host,
            actor,
        })
    }

    fn composed(&self) -> Result<ComposedMutation> {
        let unread = || CommandError::local_failure("the request this device kept cannot be read");
        let bytes = bytes_of(&self.request).ok_or_else(unread)?;
        let request: MutationRequest =
            kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                .map_err(|_| unread())?;
        let reach = (!self.host.is_empty() && !self.actor.is_empty()).then(|| Reach {
            host: self.host.clone(),
            actor: self.actor.clone(),
        });
        Ok(ComposedMutation::restored(
            request,
            self.window_issued_at_ms,
            self.window_valid_for_ms,
            reach,
        ))
    }

    /// How long an absent record is waited out, from the first time this process sent the request.
    fn bound(&self) -> Duration {
        Duration::from_millis(self.window_valid_for_ms.saturating_add(MARGIN_MS))
    }
}

/// One draft, as the folder keeps it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DraftFile {
    version: u32,
    environment_id: EnvironmentId,
    device_id: DeviceId,
    /// The account signed in when the draft was made, on a host whose grant answers to an
    /// organisation (the mark of the account, as text); none on a host with no organisation.
    account: Option<String>,
    session_id: SessionId,
    /// What the draft's calls are made on, as the creation named it.
    target: ActionTarget,
    draft_id: Option<DraftId>,
    /// The revision the host last gave, or none while it is not known.
    revision: Option<DraftRevision>,
    /// The `draft.create` that went out, kept until the host answers it.
    create: Option<KeptRequest>,
    /// The `draft.discard` that went out, kept until the host answers it.
    discard: Option<KeptRequest>,
    attachments: Vec<DraftAttachment>,
}

/// What the page sends to bind an uploaded file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bind {
    /// The session the draft is for.
    pub session_id: SessionId,
    /// The application instance the draft is for, when the draft is made.
    #[serde(default)]
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// The draft's text, when the draft is made.
    #[serde(default)]
    pub text: String,
    /// The published upload.
    pub transfer_id: TransferId,
    /// What the agent offered for the file.
    pub contribution: AttachmentContribution,
}

/// What a bind answers.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bound {
    /// The draft.
    pub draft_id: DraftId,
    /// Its revision after the bind.
    pub revision: DraftRevision,
    /// The binding.
    pub attachment: DraftAttachment,
}

/// What a text update answers: the draft after it.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Updated {
    /// The draft.
    pub draft_id: DraftId,
    /// Its revision after the update.
    pub revision: DraftRevision,
    /// The text the host holds, from its answer.
    pub text: String,
}

/// What `draft_create` answers on a paired host: the draft this device keeps for the session.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeptView {
    /// Whether a draft is made for the session.
    pub made: bool,
    /// The draft, when one is.
    pub draft_id: Option<DraftId>,
    /// Its last known revision.
    pub revision: Option<DraftRevision>,
    /// The files this device bound to it.
    pub attachments: Vec<DraftAttachment>,
}

/// What a read of a draft entry found.
enum Read {
    Absent,
    Entry(Box<DraftFile>),
    /// A file is there that this release does not read: another version, or unreadable.
    Other,
}

/// How the host answered a request that was sent or sent again.
enum Sent {
    /// The method's own result.
    Done(Answered),
    /// A refusal the host decided or a client refusal that proves the request did not take effect.
    Refused(ClientError),
    /// The request never left this client.
    NeverLeft(ClientError),
    /// The answer was lost or the host could not say.
    Uncertain(ClientError),
    /// Nothing is known and nothing was asked: this client is still accounting for the action, or the
    /// request is not for this connection.
    Unresolved,
}

/// What a discard step came to.
enum Step {
    Ended,
    Anew,
}

/// The drafts this device keeps on the hosts it is paired with.
#[derive(Default)]
pub struct Drafts {
    root: Mutex<Option<PathBuf>>,
    /// The hosts, by environment and this device's principal, that refused `draft.discard` by name.
    discard_refused: Mutex<HashSet<(EnvironmentId, DeviceId)>>,
    /// The turn each draft's operations take.
    turns: Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
    /// When this process first sent or repeated each kept request.
    armed: Mutex<HashMap<String, Instant>>,
    /// How many times a freeing of other accounts' drafts freed something, so that a creation that
    /// was refused while another creation's freeing ran knows a place may be free.
    places_freed: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for Drafts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Drafts").finish_non_exhaustive()
    }
}

/// The entry's name: a draft of another account of the same host is another entry, so one account
/// never reads or extends the draft another left.
fn key_of(paired: &Paired, session_id: SessionId) -> Uuid {
    let text = format!(
        "{}|{}|{}|{}",
        paired.environment_id,
        paired.device_id,
        session_id,
        paired.account_id().unwrap_or_default()
    );
    let digest = kr_cbor::sha256(text.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

/// What the host's answer to a `draft.discard` means for the entry kept for the draft.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Ended {
    /// The draft is ended, or the host has no such draft, or it was used and is the session's.
    Done,
    /// The host does not list the method: it is of an earlier build.
    OlderHost,
    /// Anything else: the draft may still stand.
    Failed,
}

fn discard_outcome(error: &ClientError) -> Ended {
    if gone(error) || error.code() == ErrorCode::DraftConflict {
        Ended::Done
    } else if host_cannot_discard(error) {
        Ended::OlderHost
    } else {
        Ended::Failed
    }
}

/// Whether the host refused a draft creation for the device's count of open drafts. The host gives
/// that refusal the code of a quota and words that name the bound; a draft that is too large has
/// the same code and other words, and no discard of another account's draft could help it.
fn is_the_count_refusal(error: &ClientError) -> bool {
    error.code() == ErrorCode::QuotaExceeded
        && host_words(error).is_some_and(|words| words.contains("drafts it may keep open"))
}

/// What a refused create is told as: when the host's own bound on drafts is reached and its build
/// cannot end one, the person is told to update the host. Otherwise nothing is added.
fn at_the_bound(discard_refused: bool, error: &ClientError) -> Option<CommandError> {
    (discard_refused && error.code() == ErrorCode::QuotaExceeded)
        .then(|| CommandError::unsupported(UPDATE_THE_HOST))
}

/// Whether the host answered that the draft or its session is gone: its own words for no such
/// draft or no such session, and the code for a session that ended. No other refusal says so.
fn gone(error: &ClientError) -> bool {
    error.code() == ErrorCode::SessionClosed
        || (error.code() == ErrorCode::InvalidArgument
            && host_words(error).is_some_and(|words| {
                words.starts_with("no draft ") || words.starts_with("no session ")
            }))
}

fn host_cannot_discard(error: &ClientError) -> bool {
    matches!(error, ClientError::Host(refused)
        if refused.message == kr_transport::actor::METHOD_NOT_AVAILABLE)
}

/// What a send or a repeat came to.
fn sent_as(answered: kr_client::Result<Answered>, repeating: bool) -> Sent {
    match answered {
        Ok(settled @ Answered::Result(_)) => Sent::Done(settled),
        Ok(Answered::Receipt(_)) => Sent::Unresolved,
        Err(error @ ClientError::SubmissionUncertain { .. }) => Sent::Uncertain(error),
        Err(error @ ClientError::ConnectionEnded) if repeating => Sent::Uncertain(error),
        Err(error @ ClientError::ConnectionEnded) => Sent::NeverLeft(error),
        Err(error) if error.code() == ErrorCode::OutcomeUnknown => Sent::Uncertain(error),
        Err(
            ClientError::StillAccounting | ClientError::Misdirected { .. } | ClientError::OtherHost,
        ) => Sent::Unresolved,
        Err(error) => Sent::Refused(error),
    }
}

impl Drafts {
    /// Names the folder the entries live in.
    pub fn keep_at(&self, root: PathBuf) {
        *self.root.lock().unwrap_or_else(PoisonError::into_inner) = Some(root);
    }

    fn root(&self) -> Result<PathBuf> {
        self.root
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                CommandError::unavailable("this application has no place to keep a draft")
            })
    }

    fn path(&self, key: Uuid) -> Result<PathBuf> {
        Ok(self.root()?.join(format!("{key}.{EXTENSION}")))
    }

    /// The turn of the operations on one draft: held until the last write of the operation.
    async fn turn(
        &self,
        paired: &Paired,
        session_id: SessionId,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut turns = self.turns.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(turns.entry(key_of(paired, session_id)).or_default())
        };
        lock.lock_owned().await
    }

    /// The turn of the draft when no operation holds it, and none otherwise.
    fn try_turn(
        &self,
        paired: &Paired,
        session_id: SessionId,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let lock = {
            let mut turns = self.turns.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(turns.entry(key_of(paired, session_id)).or_default())
        };
        lock.try_lock_owned().ok()
    }

    fn read(&self, paired: &Paired, session_id: SessionId) -> Result<Read> {
        let path = self.path(key_of(paired, session_id))?;
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Read::Absent),
            Err(_) => return Ok(Read::Other),
        };
        Ok(
            match serde_json::from_slice::<DraftFile>(&bytes)
                .ok()
                .filter(|file| file.version == DRAFT_VERSION && file.session_id == session_id)
            {
                Some(file) => Read::Entry(Box::new(file)),
                None => Read::Other,
            },
        )
    }

    /// The entry kept for the session, none when there is none; a file of another layout is refused.
    fn entry(&self, paired: &Paired, session_id: SessionId) -> Result<Option<DraftFile>> {
        match self.read(paired, session_id)? {
            Read::Absent => Ok(None),
            Read::Entry(file) => Ok(Some(*file)),
            Read::Other => Err(CommandError::refused(NEWER_DRAFT)),
        }
    }

    fn write(&self, paired: &Paired, file: &DraftFile) -> Result<()> {
        let path = self.path(key_of(paired, file.session_id))?;
        if let Some(root) = path.parent() {
            std::fs::create_dir_all(root).map_err(unkept)?;
        }
        let bytes =
            serde_json::to_vec(file).map_err(|error| unkept(std::io::Error::other(error)))?;
        crate::drafts::publish(&path, &bytes, || Ok(())).map_err(|fault| unkept(fault.error))
    }

    fn remove(&self, paired: &Paired, session_id: SessionId) {
        if let Ok(path) = self.path(key_of(paired, session_id)) {
            let _ = crate::drafts::remove_durably(&path);
        }
    }

    fn refused_discard(&self, paired: &Paired) -> bool {
        self.discard_refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(paired.environment_id, paired.device_id))
    }

    /// When this process first sent or repeated `action`.
    fn arm(&self, action: ActionId) -> Instant {
        *self
            .armed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(action.to_string())
            .or_insert_with(Instant::now)
    }

    fn fresh(&self, paired: &Paired, session_id: SessionId, target: &ActionTarget) -> DraftFile {
        DraftFile {
            version: DRAFT_VERSION,
            environment_id: paired.environment_id,
            device_id: paired.device_id,
            account: paired.account_id(),
            session_id,
            target: target.clone(),
            draft_id: None,
            revision: None,
            create: None,
            discard: None,
            attachments: Vec::new(),
        }
    }

    /// The draft kept for `session_id`: none when this device keeps none for the session.
    ///
    /// # Errors
    ///
    /// The refusal [`NEWER_DRAFT`] when the entry is there and cannot be read, because it was
    /// written by another release or is damaged: a draft this device may hold is never taken for
    /// none, so the page does not make a second one over it.
    pub fn kept(&self, paired: &Paired, session_id: SessionId) -> Result<KeptView> {
        let none = KeptView {
            made: false,
            draft_id: None,
            revision: None,
            attachments: Vec::new(),
        };
        match self.entry(paired, session_id)? {
            Some(file) if file.draft_id.is_some() => Ok(KeptView {
                made: true,
                draft_id: file.draft_id,
                revision: file.revision,
                attachments: file.attachments,
            }),
            _ => Ok(none),
        }
    }

    /// The prompt that named `draft_id` was answered with a result: the draft is the session's now,
    /// and the entry ends with nothing asked of the host. An entry kept for another draft stays.
    pub async fn sent(&self, paired: &Paired, session_id: SessionId, draft_id: DraftId) {
        let _turn = self.turn(paired, session_id).await;
        if let Ok(Read::Entry(file)) = self.read(paired, session_id)
            && file.draft_id == Some(draft_id)
        {
            self.remove(paired, session_id);
        }
    }

    /// Binds a published upload to the draft kept for the session, making the draft at the first
    /// bind.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, and [`GONE`] when the host has no such session or draft.
    pub async fn bind(&self, paired: Paired, target: ActionTarget, bind: Bind) -> Result<Bound> {
        let _turn = self.turn(&paired, bind.session_id).await;
        let mut file = match self.entry(&paired, bind.session_id)? {
            Some(file) => file,
            None => self.fresh(&paired, bind.session_id, &target),
        };
        if file.create.is_some() {
            self.resolve_create(&paired, &mut file).await?;
        }
        if file.discard.is_some() || (file.draft_id.is_some() && file.revision.is_none()) {
            // A draft whose end was begun, or whose revision is not known, is ended first.
            self.finish_ending(&paired, &mut file).await?;
            file = self.fresh(&paired, bind.session_id, &target);
        }
        if file.draft_id.is_none() {
            self.make(&paired, &target, &bind, &mut file).await?;
        }
        // One stale revision is read from the host's own words and the bind goes on; a second ends.
        let mut expected = file.revision;
        for attempt in 0..2 {
            let (Some(draft_id), Some(expected_revision)) = (file.draft_id, expected) else {
                break;
            };
            // The revision is not known while the call is out: a stop here leaves a draft that is
            // ended, and not one whose revision is guessed.
            file.revision = None;
            self.write(&paired, &file)?;
            let asked = paired
                .session
                .mutate(
                    Method::AgentDraftAddAttachment,
                    target.clone(),
                    None,
                    &NoPreconditions {},
                    &AgentDraftAddAttachmentParams {
                        draft_id,
                        expected_revision,
                        transfer_id: bind.transfer_id,
                        contribution: bind.contribution.clone(),
                    },
                    MUTATION_TTL,
                )
                .await;
            match asked {
                Ok(settled) => {
                    let result: AgentDraftAddAttachmentResult = settled.to_typed()?;
                    file.revision = Some(result.draft.revision);
                    file.attachments.push(result.attachment.clone());
                    self.write(&paired, &file)?;
                    return Ok(Bound {
                        draft_id,
                        revision: result.draft.revision,
                        attachment: result.attachment,
                    });
                }
                Err(error) if error.code() == ErrorCode::DraftConflict => {
                    let said = host_words(&error).map_or_else(|| error.to_string(), str::to_owned);
                    let Some(revision) = revision_in(&said) else {
                        // The host's words do not carry the revision: the draft is ended.
                        let _ = self.finish_ending(&paired, &mut file).await;
                        return Err(error.into());
                    };
                    file.revision = Some(revision);
                    if attempt == 0 {
                        expected = Some(revision);
                    } else {
                        self.write(&paired, &file)?;
                        return Err(CommandError::unavailable(CHANGED_AGAIN));
                    }
                }
                Err(error) if gone(&error) => {
                    self.remove(&paired, bind.session_id);
                    return Err(CommandError::refused(GONE));
                }
                Err(
                    error @ (ClientError::SubmissionUncertain { .. }
                    | ClientError::OutcomeUnknown { .. }),
                ) => {
                    // The answer is lost: the revision stays unknown, so the draft is ended.
                    let _ = self.finish_ending(&paired, &mut file).await;
                    return Err(error.into());
                }
                // Anything else did not change the draft: its revision is the one it was.
                Err(error) => {
                    file.revision = Some(expected_revision);
                    self.write(&paired, &file)?;
                    return Err(error.into());
                }
            }
        }
        Err(CommandError::unavailable(CHANGED_AGAIN))
    }

    /// Sets the text of the draft kept for the session, with `draft.update` at the kept revision.
    ///
    /// The prompt that names a draft carries no text of its own, so the draft holds what the person
    /// typed. A stale revision is read from the host's own words and the update goes on once; a
    /// lost answer leaves the revision unknown, and the draft is ended.
    ///
    /// # Errors
    ///
    /// Returns [`NO_DRAFT`] when no draft is kept for the session, [`GONE_FOR_TEXT`] when the host
    /// has no such session or draft, and the host's refusal otherwise.
    pub async fn set_text(
        &self,
        paired: Paired,
        target: ActionTarget,
        session_id: SessionId,
        text: String,
    ) -> Result<Updated> {
        let _turn = self.turn(&paired, session_id).await;
        let Some(mut file) = self.entry(&paired, session_id)? else {
            return Err(CommandError::refused(NO_DRAFT));
        };
        if file.discard.is_some() || file.draft_id.is_none() {
            return Err(CommandError::refused(NO_DRAFT));
        }
        for attempt in 0..2 {
            let (Some(draft_id), Some(expected_revision)) = (file.draft_id, file.revision) else {
                break;
            };
            let asked = paired
                .session
                .mutate(
                    Method::DraftUpdate,
                    target.clone(),
                    None,
                    &NoPreconditions {},
                    &DraftUpdateParams {
                        draft_id,
                        expected_revision,
                        text: text.clone(),
                    },
                    MUTATION_TTL,
                )
                .await;
            match asked {
                Ok(settled) => {
                    let result: DraftUpdateResult = settled.to_typed()?;
                    file.revision = Some(result.draft.revision);
                    self.write(&paired, &file)?;
                    return Ok(Updated {
                        draft_id,
                        revision: result.draft.revision,
                        text: result.draft.text,
                    });
                }
                Err(error) if error.code() == ErrorCode::DraftConflict && attempt == 0 => {
                    let said = host_words(&error).map_or_else(|| error.to_string(), str::to_owned);
                    if let Some(revision) = revision_in(&said) {
                        file.revision = Some(revision);
                        self.write(&paired, &file)?;
                    } else {
                        // The host's words do not carry the revision: the draft is ended.
                        file.revision = None;
                        self.write(&paired, &file)?;
                        let _ = self.finish_ending(&paired, &mut file).await;
                        return Err(error.into());
                    }
                }
                Err(error) if gone(&error) => {
                    self.remove(&paired, session_id);
                    return Err(CommandError::refused(GONE_FOR_TEXT));
                }
                Err(
                    error @ (ClientError::SubmissionUncertain { .. }
                    | ClientError::OutcomeUnknown { .. }),
                ) => {
                    // The answer is lost: the revision is not known, so the draft is ended.
                    file.revision = None;
                    self.write(&paired, &file)?;
                    let _ = self.finish_ending(&paired, &mut file).await;
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CommandError::unavailable(
            "the draft changed again while the message was being set: the message was not sent",
        ))
    }

    /// Makes the draft: the request is composed once and kept whole before it is sent, and kept until
    /// the host answers it, so that a lost answer is asked again exactly and the host's record
    /// answers it.
    async fn make(
        &self,
        paired: &Paired,
        target: &ActionTarget,
        bind: &Bind,
        file: &mut DraftFile,
    ) -> Result<()> {
        let freed_before = self.places_freed.load(std::sync::atomic::Ordering::Acquire);
        let mut asked_for_places = false;
        loop {
            let composed = paired
                .session
                .compose(
                    Method::DraftCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    target.clone(),
                    None,
                    &NoPreconditions {},
                    &DraftCreateParams {
                        environment_id: paired.environment_id,
                        device_id: Nullable::null(),
                        session_id: Nullable::some(bind.session_id),
                        application_instance_id: bind
                            .application_instance_id
                            .map_or_else(Nullable::null, Nullable::some),
                        text: bind.text.clone(),
                    },
                    MUTATION_TTL,
                )
                .await?;
            file.target = target.clone();
            file.create = Some(KeptRequest::of(&composed)?);
            self.write(paired, file)?;
            let action = composed.action_id();
            self.arm(action);
            return match sent_as(paired.session.send(&composed).await, false) {
                Sent::Done(settled) => self.made(paired, file, action, &settled).await,
                Sent::Refused(error) => {
                    // The host decided, so nothing was made.
                    file.create = None;
                    paired.session.settle(action).await;
                    if gone(&error) {
                        self.remove(paired, bind.session_id);
                        return Err(CommandError::refused(GONE));
                    }
                    // The host counts open drafts for every account of this device, and an account
                    // cannot see the drafts another left. A refusal for the count frees those, once,
                    // and the creation is tried once more. A freeing that another creation made
                    // meanwhile counts: the place it freed may be this one's.
                    if is_the_count_refusal(&error)
                        && !asked_for_places
                        && (self.free_places(paired).await
                            || self.places_freed.load(std::sync::atomic::Ordering::Acquire)
                                != freed_before)
                    {
                        asked_for_places = true;
                        continue;
                    }
                    self.write(paired, file)?;
                    let flag = self.refused_discard(paired);
                    Err(at_the_bound(flag, &error).unwrap_or_else(|| error.into()))
                }
                Sent::NeverLeft(error) => {
                    file.create = None;
                    paired.session.settle(action).await;
                    self.write(paired, file)?;
                    Err(error.into())
                }
                Sent::Uncertain(error) => Err(error.into()),
                Sent::Unresolved => Err(CommandError::unavailable(CREATE_PENDING)),
            };
        }
    }

    /// Discards the drafts that other accounts of this device keep for this host, one at a time, for
    /// a creation the host refused for the device's count of open drafts, and says whether a place
    /// was freed. Each draft is taken by its own account's key, in its turn, and read again there: a
    /// draft that is gone, or whose creation was not answered, is left, and so is one whose turn
    /// another operation holds. The discard goes on the connection in force, whose principal is the
    /// device's, and the file goes with the host's answer. A host of an earlier build, which cannot
    /// discard a draft, frees nothing.
    async fn free_places(&self, paired: &Paired) -> bool {
        if self.refused_discard(paired) {
            return false;
        }
        let Ok(root) = self.root() else {
            return false;
        };
        let Ok(listing) = std::fs::read_dir(&root) else {
            return false;
        };
        let mut others: Vec<(Paired, SessionId)> = Vec::new();
        for item in listing.flatten() {
            let path = item.path();
            if path.extension().is_none_or(|ext| ext != EXTENSION) {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(file) = serde_json::from_slice::<DraftFile>(&bytes) else {
                continue;
            };
            if file.version != DRAFT_VERSION
                || file.environment_id != paired.environment_id
                || file.device_id != paired.device_id
                || file.account == paired.account_id()
                || file.draft_id.is_none()
                || file.create.is_some()
            {
                continue;
            }
            let account = match &file.account {
                Some(text) => match AccountMark::from_hex(text) {
                    Some(mark) => Some(mark),
                    None => continue,
                },
                None => None,
            };
            others.push((
                Paired {
                    account,
                    ..paired.clone()
                },
                file.session_id,
            ));
        }
        let mut freed = false;
        for (theirs, session_id) in others {
            let Some(_turn) = self.try_turn(&theirs, session_id) else {
                continue;
            };
            let Ok(Some(mut file)) = self.entry(&theirs, session_id) else {
                continue;
            };
            if file.draft_id.is_none() || file.create.is_some() {
                continue;
            }
            // The storage is the draft's own account's: `theirs` names it, and carries the
            // connection in force.
            match self.discard_once(&theirs, &mut file).await {
                Ok(Step::Ended) if !self.refused_discard(paired) => freed = true,
                Ok(Step::Ended) => break,
                _ => {}
            }
        }
        if freed {
            self.places_freed
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        }
        freed
    }

    /// The host's answer to the creation is kept, and the action leaves the client's book.
    async fn made(
        &self,
        paired: &Paired,
        file: &mut DraftFile,
        action: ActionId,
        settled: &Answered,
    ) -> Result<()> {
        let created: DraftCreateResult = settled.to_typed()?;
        file.draft_id = Some(created.draft.draft_id);
        file.revision = Some(created.draft.revision);
        file.create = None;
        self.write(paired, file)?;
        paired.session.settle(action).await;
        Ok(())
    }

    /// Asks the host again, exactly, about the creation whose answer was lost. It ends with the
    /// draft made, or with the creation known not to have happened, or with an error that leaves it
    /// kept.
    async fn resolve_create(&self, paired: &Paired, file: &mut DraftFile) -> Result<()> {
        let Some(kept) = file.create.clone() else {
            return Ok(());
        };
        let composed = kept.composed()?;
        let action = kept.action_id;
        let armed = self.arm(action);
        let began = Instant::now();
        match sent_as(paired.session.repeat(&composed).await, true) {
            Sent::Done(settled) => self.made(paired, file, action, &settled).await,
            // A refusal for the window of another connection is the host having no record; it
            // counts only once the window and a margin have passed since this process first asked.
            Sent::Refused(error)
                if error.code() == ErrorCode::PermissionDenied
                    && began.duration_since(armed) >= kept.bound() =>
            {
                file.create = None;
                self.write(paired, file)?;
                paired.session.settle(action).await;
                Ok(())
            }
            Sent::Refused(_) => {
                paired.session.settle(action).await;
                Err(CommandError::unavailable(CREATE_PENDING))
            }
            Sent::NeverLeft(_) | Sent::Uncertain(_) | Sent::Unresolved => {
                Err(CommandError::unavailable(CREATE_PENDING))
            }
        }
    }

    /// Ends the draft of the session by `draft.discard`, because the composer dropped its files
    /// unsent. A draft the host has no record of, or that was used, is dropped from the folder.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal; a host of an earlier build that cannot end a draft is gone on
    /// without, and [`UPDATE_THE_HOST`] is told only when its bound on drafts is reached.
    pub async fn end(
        &self,
        paired: Paired,
        _target: ActionTarget,
        session_id: SessionId,
    ) -> Result<()> {
        let _turn = self.turn(&paired, session_id).await;
        let Some(mut file) = self.entry(&paired, session_id)? else {
            return Ok(());
        };
        self.finish_ending(&paired, &mut file).await
    }

    /// Asks the host to discard the draft, on the target the draft was made on, with a request kept
    /// whole until the host answers it. A creation whose answer is not known is resolved first.
    async fn finish_ending(&self, paired: &Paired, file: &mut DraftFile) -> Result<()> {
        if file.create.is_some() {
            self.resolve_create(paired, file).await?;
        }
        for _ in 0..2 {
            if file.draft_id.is_none() {
                self.remove(paired, file.session_id);
                return Ok(());
            }
            if let Step::Ended = self.discard_once(paired, file).await? {
                return Ok(());
            }
        }
        Err(CommandError::unavailable(DISCARD_PENDING))
    }

    async fn discard_once(&self, paired: &Paired, file: &mut DraftFile) -> Result<Step> {
        let Some(draft_id) = file.draft_id else {
            return Ok(Step::Ended);
        };
        let (composed, kept) = match file.discard.clone() {
            Some(kept) => (kept.composed()?, Some(kept)),
            None => {
                let composed = paired
                    .session
                    .compose(
                        Method::DraftDiscard,
                        ActionId::new(kr_ipc::new_uuid()),
                        file.target.clone(),
                        None,
                        &NoPreconditions {},
                        &DraftDiscardParams { draft_id },
                        MUTATION_TTL,
                    )
                    .await?;
                file.discard = Some(KeptRequest::of(&composed)?);
                self.write(paired, file)?;
                (composed, None)
            }
        };
        let action = composed.action_id();
        let armed = self.arm(action);
        let began = Instant::now();
        let repeating = kept.is_some();
        let answered = if repeating {
            paired.session.repeat(&composed).await
        } else {
            paired.session.send(&composed).await
        };
        match sent_as(answered, repeating) {
            Sent::Done(_) => {
                self.remove(paired, file.session_id);
                paired.session.settle(action).await;
                Ok(Step::Ended)
            }
            Sent::Refused(error) => {
                paired.session.settle(action).await;
                match discard_outcome(&error) {
                    Ended::Done => {
                        self.remove(paired, file.session_id);
                        Ok(Step::Ended)
                    }
                    // The client goes on without ending drafts, and says so only at the bound.
                    Ended::OlderHost => {
                        self.discard_refused
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .insert((paired.environment_id, paired.device_id));
                        self.remove(paired, file.session_id);
                        Ok(Step::Ended)
                    }
                    Ended::Failed => match kept {
                        Some(kept)
                            if error.code() == ErrorCode::PermissionDenied
                                && began.duration_since(armed) >= kept.bound() =>
                        {
                            file.discard = None;
                            self.write(paired, file)?;
                            Ok(Step::Anew)
                        }
                        Some(_) => Err(CommandError::unavailable(DISCARD_PENDING)),
                        None => {
                            // The host decided not to end it: the draft stands, and so does the file.
                            file.discard = None;
                            self.write(paired, file)?;
                            Err(error.into())
                        }
                    },
                }
            }
            Sent::NeverLeft(error) => {
                file.discard = None;
                paired.session.settle(action).await;
                self.write(paired, file)?;
                Err(error.into())
            }
            Sent::Uncertain(error) if !repeating => Err(error.into()),
            Sent::Uncertain(_) | Sent::Unresolved => {
                Err(CommandError::unavailable(DISCARD_PENDING))
            }
        }
    }

    /// Reads the sessions the host lists, and ends the drafts of the ones it does not.
    pub async fn sweep_after_reach(&self, paired: Paired) {
        let listed: kr_protocol::session::SessionListResult = match paired
            .session
            .read(
                Method::SessionList,
                &kr_protocol::session::SessionListParams {
                    environment_id: Nullable::null(),
                    include_closed: false,
                },
            )
            .await
        {
            Ok(listed) => listed,
            Err(_) => return,
        };
        let ids: Vec<SessionId> = listed
            .sessions
            .iter()
            .map(|summary| summary.session_id)
            .collect();
        self.sweep(paired, &ids).await;
    }

    /// At each reach: the drafts of another principal on this host are dropped, and the drafts of this
    /// account whose session the host no longer lists are ended on the target they were made on. A
    /// draft of another account is left alone. A draft the host has already ended is harmless to end
    /// again.
    pub async fn sweep(&self, paired: Paired, listed: &[SessionId]) {
        let Ok(root) = self.root() else { return };
        let Ok(listing) = std::fs::read_dir(&root) else {
            return;
        };
        for item in listing.flatten() {
            let path = item.path();
            if path.extension().is_none_or(|ext| ext != EXTENSION) {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            let Ok(file) = serde_json::from_slice::<DraftFile>(&bytes) else {
                continue;
            };
            if file.version != DRAFT_VERSION || file.environment_id != paired.environment_id {
                continue;
            }
            if file.device_id != paired.device_id {
                // Kept for a pairing that is not the one in force.
                let _ = crate::drafts::remove_durably(&path);
                continue;
            }
            if file.account != paired.account_id() {
                // Another account's: hidden, left as it is, and found again when its account reaches
                // the host.
                continue;
            }
            if listed.contains(&file.session_id) {
                continue;
            }
            let _turn = self.turn(&paired, file.session_id).await;
            // Read again under the turn: another operation may have changed it meanwhile.
            if let Ok(Some(mut file)) = self.entry(&paired, file.session_id) {
                let _ = self.finish_ending(&paired, &mut file).await;
            }
        }
    }

    /// The host this device knows as `device_id` was forgotten: every draft kept for it goes.
    pub fn forgotten(&self, device_id: DeviceId) {
        let Ok(root) = self.root() else { return };
        let Ok(listing) = std::fs::read_dir(&root) else {
            return;
        };
        for item in listing.flatten() {
            let path = item.path();
            if path.extension().is_none_or(|ext| ext != EXTENSION) {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if serde_json::from_slice::<DraftFile>(&bytes)
                .is_ok_and(|file| file.device_id == device_id)
            {
                let _ = crate::drafts::remove_durably(&path);
            }
        }
    }
}

fn unkept(error: std::io::Error) -> CommandError {
    CommandError::local_failure(format!("this device could not keep the draft: {error}"))
}

/// What a suite keeps in the folder to stand for a draft that an earlier process left.
#[cfg(feature = "testing")]
impl Drafts {
    /// Keeps an entry for the draft of `session_id`, as an earlier process left it.
    ///
    /// # Panics
    ///
    /// Panics when the entry cannot be written.
    pub fn keep_for_test(
        &self,
        paired: &Paired,
        session_id: SessionId,
        target: &ActionTarget,
        draft_id: Option<DraftId>,
        revision: Option<DraftRevision>,
    ) {
        let mut file = self.fresh(paired, session_id, target);
        file.draft_id = draft_id;
        file.revision = revision;
        self.write(paired, &file).expect("the entry is kept");
    }

    /// Keeps an entry whose `draft.create` went out as `composed` and whose answer was lost.
    ///
    /// # Panics
    ///
    /// Panics when the entry cannot be written.
    pub fn keep_create_for_test(
        &self,
        paired: &Paired,
        session_id: SessionId,
        target: &ActionTarget,
        composed: &ComposedMutation,
    ) {
        let mut file = self.fresh(paired, session_id, target);
        file.create = Some(KeptRequest::of(composed).expect("the request encodes"));
        self.write(paired, &file).expect("the entry is kept");
    }

    /// Makes this process's first send of `action` `age` ago, so that a case reaches the end of the
    /// wait for a lost answer without waiting for it.
    ///
    /// # Panics
    ///
    /// Panics when the clock has not run for as long as `age`.
    pub fn armed_ago_for_test(&self, action: ActionId, age: Duration) {
        let then = Instant::now()
            .checked_sub(age)
            .expect("the clock has run for that long");
        self.armed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(action.to_string(), then);
    }

    /// Keeps the entry of a made draft whose `draft.discard` went out as `composed` and whose answer
    /// was lost.
    ///
    /// # Panics
    ///
    /// Panics when the entry cannot be written.
    pub fn keep_discard_for_test(
        &self,
        paired: &Paired,
        session_id: SessionId,
        target: &ActionTarget,
        draft_id: DraftId,
        revision: DraftRevision,
        composed: &ComposedMutation,
    ) {
        let mut file = self.fresh(paired, session_id, target);
        file.draft_id = Some(draft_id);
        file.revision = Some(revision);
        file.discard = Some(KeptRequest::of(composed).expect("the request encodes"));
        self.write(paired, &file).expect("the entry is kept");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::error::ProtocolError;

    fn refused(code: ErrorCode, message: &str) -> ClientError {
        ClientError::Host(ProtocolError::new(code, message))
    }

    /// KR-REQ-23.41: only the host's refusal of a creation for the device's count of open drafts
    /// frees another account's drafts: a draft that is too large has the same code and other words.
    #[test]
    fn only_the_count_refusal_of_a_creation_frees_other_accounts_drafts() {
        assert!(is_the_count_refusal(&refused(
            ErrorCode::QuotaExceeded,
            "this device holds 64 of the 64 drafts it may keep open: end a draft it no longer uses"
        )));
        assert!(!is_the_count_refusal(&refused(
            ErrorCode::QuotaExceeded,
            "this draft is larger than a result may be"
        )));
        assert!(!is_the_count_refusal(&refused(
            ErrorCode::ResourceUnavailable,
            "this device holds 64 of the 64 drafts it may keep open"
        )));
    }

    /// KR-REQ-23.41: a host that refuses `draft.discard` by name is read as of an earlier build; a
    /// draft the host does not know or that was used is read as ended; anything else is not.
    #[test]
    fn a_refusal_of_a_discard_is_read_as_ended_older_or_failed() {
        let older = refused(
            ErrorCode::PermissionDenied,
            kr_transport::actor::METHOD_NOT_AVAILABLE,
        );
        assert_eq!(discard_outcome(&older), Ended::OlderHost);
        assert_eq!(
            discard_outcome(&refused(ErrorCode::InvalidArgument, "no draft 7")),
            Ended::Done
        );
        assert_eq!(
            discard_outcome(&refused(ErrorCode::DraftConflict, "the draft was sent")),
            Ended::Done
        );
        assert_eq!(
            discard_outcome(&refused(ErrorCode::PermissionDenied, "not yours")),
            Ended::Failed
        );
    }

    /// KR-REQ-23.41: the approved sentence is told only when an earlier-build host's bound on drafts
    /// is reached, and not for any other refusal.
    #[test]
    fn update_the_host_is_told_only_at_the_bound_of_a_host_that_cannot_end_a_draft() {
        let bound = refused(ErrorCode::QuotaExceeded, "64 drafts");
        let told = at_the_bound(true, &bound).expect("told at the bound");
        assert_eq!(told.message, UPDATE_THE_HOST);
        assert!(
            at_the_bound(false, &bound).is_none(),
            "a host that can end drafts"
        );
        assert!(
            at_the_bound(true, &refused(ErrorCode::InvalidArgument, "x")).is_none(),
            "no other refusal"
        );
    }
}
