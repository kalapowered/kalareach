//! The draft a device keeps on a host it is paired with: one for each host, principal and session.
//!
//! The device makes the draft at the first bind and never before, keeps its identifier and its last
//! known revision in the folder of open transfers (`<key>.draft`, JSON, version 1, written before the
//! call that uses it), and uses it again for a new window and after a restart. A `draft.create`
//! whose answer is lost is asked again under its own action identifier, which is kept until the host
//! answers. A refusal for a stale revision names the revision the draft is at; it is taken from the
//! message and the call goes on. A draft the device will not use is ended with `draft.discard`.

use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};

use kr_client::ClientError;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ActionId, ApplicationInstanceId, DeviceId, DraftId, DraftRevision, EnvironmentId, SessionId,
    TransferId,
};
use kr_protocol::method::Method;
use kr_protocol::receipt::ActionReadParams;
use kr_protocol::scalars::{Nullable, Uuid};
use kr_protocol::transfer::{
    AgentDraftAddAttachmentParams, AgentDraftAddAttachmentResult, AttachmentContribution,
    DraftAttachment, DraftCreateParams, DraftCreateResult, DraftDiscardParams,
};
use serde::{Deserialize, Serialize};

use crate::commands::{MUTATION_TTL, NoPreconditions};
use crate::error::{CommandError, Result};
use crate::open_transfers::Paired;

/// The format of a draft entry this build writes, recorded in it as `version`.
pub const DRAFT_VERSION: u32 = 1;

/// What a refused end of a draft by an older host is told as, once the host's own bound is reached.
pub const UPDATE_THE_HOST: &str =
    "update the host: it cannot end a draft this device no longer needs";

/// What a bind is told when the session or the draft is gone on the host.
pub const GONE: &str =
    "the session or the draft this file was for is gone on the host: the file was not added to it";

const EXTENSION: &str = "draft";

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

/// One draft, as the folder keeps it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DraftFile {
    version: u32,
    environment_id: EnvironmentId,
    device_id: DeviceId,
    session_id: SessionId,
    draft_id: Option<DraftId>,
    revision: Option<DraftRevision>,
    /// The action a `draft.create` went out under, kept until the host answers it.
    create_action: Option<ActionId>,
    /// The action a `draft.discard` went out under, kept until the host answers it.
    discard_action: Option<ActionId>,
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

/// The drafts this device keeps on the hosts it is paired with.
#[derive(Default)]
pub struct Drafts {
    root: Mutex<Option<PathBuf>>,
    /// A host of an earlier build refused `draft.discard` by name.
    discard_refused: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for Drafts {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Drafts").finish_non_exhaustive()
    }
}

fn key_of(paired: &Paired, session_id: SessionId) -> Uuid {
    let text = format!(
        "{}|{}|{}",
        paired.environment_id, paired.device_id, session_id
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
    if unknown_draft(error) || error.code() == ErrorCode::DraftConflict {
        Ended::Done
    } else if host_cannot_discard(error) {
        Ended::OlderHost
    } else {
        Ended::Failed
    }
}

/// What a refused create is told as: when the host's own bound on drafts is reached and its build
/// cannot end one, the person is told to update the host. Otherwise nothing is added.
fn at_the_bound(discard_refused: bool, error: &ClientError) -> Option<CommandError> {
    (discard_refused && error.code() == ErrorCode::QuotaExceeded)
        .then(|| CommandError::unsupported(UPDATE_THE_HOST))
}

/// Whether the host answered that it has no such draft.
fn unknown_draft(error: &ClientError) -> bool {
    error.code() == ErrorCode::InvalidArgument
}

fn host_cannot_discard(error: &ClientError) -> bool {
    matches!(error, ClientError::Host(refused)
        if refused.message == kr_transport::actor::METHOD_NOT_AVAILABLE)
}

impl Drafts {
    /// Names the folder the entries live in.
    pub fn keep_at(&self, root: PathBuf) {
        *self.root.lock().unwrap_or_else(PoisonError::into_inner) = Some(root);
    }

    fn path(&self, key: Uuid) -> Result<PathBuf> {
        let root = self
            .root
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                CommandError::unavailable("this application has no place to keep a draft")
            })?;
        Ok(root.join(format!("{key}.{EXTENSION}")))
    }

    fn read(&self, paired: &Paired, session_id: SessionId) -> Result<Option<DraftFile>> {
        let path = self.path(key_of(paired, session_id))?;
        let Ok(bytes) = std::fs::read(&path) else {
            return Ok(None);
        };
        Ok(serde_json::from_slice::<DraftFile>(&bytes)
            .ok()
            .filter(|file| file.version == DRAFT_VERSION && file.session_id == session_id))
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

    /// The draft kept for `session_id`.
    #[must_use]
    pub fn kept(&self, paired: &Paired, session_id: SessionId) -> KeptView {
        match self.read(paired, session_id) {
            Ok(Some(file)) if file.draft_id.is_some() => KeptView {
                made: true,
                draft_id: file.draft_id,
                revision: file.revision,
                attachments: file.attachments,
            },
            _ => KeptView {
                made: false,
                draft_id: None,
                revision: None,
                attachments: Vec::new(),
            },
        }
    }

    /// The prompt that named the draft was answered: the draft is the session's now, and the entry
    /// ends with nothing asked of the host.
    pub fn sent(&self, paired: &Paired, session_id: SessionId) {
        self.remove(paired, session_id);
    }

    /// Binds a published upload to the draft kept for the session, making the draft at the first
    /// bind.
    ///
    /// # Errors
    ///
    /// Returns the host's refusal, and [`GONE`] when the host has no such session or draft.
    pub async fn bind(&self, paired: Paired, target: ActionTarget, bind: Bind) -> Result<Bound> {
        let mut file = match self.read(&paired, bind.session_id)? {
            Some(file) => file,
            None => DraftFile {
                version: DRAFT_VERSION,
                environment_id: paired.environment_id,
                device_id: paired.device_id,
                session_id: bind.session_id,
                draft_id: None,
                revision: None,
                create_action: None,
                discard_action: None,
                attachments: Vec::new(),
            },
        };
        if file.discard_action.is_some() || (file.draft_id.is_some() && file.revision.is_none()) {
            // A draft whose end was begun, or whose revision is not known, is ended first.
            self.finish_ending(&paired, &target, &mut file).await?;
            file = self.fresh(&paired, bind.session_id);
        }
        if file.draft_id.is_none() {
            self.make(&paired, &target, &bind, &mut file).await?;
        }
        // One stale revision is read from the host's own words and the bind goes on; a second ends.
        for attempt in 0..2 {
            let (Some(draft_id), Some(expected_revision)) = (file.draft_id, file.revision) else {
                break;
            };
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
                Err(error) if error.code() == ErrorCode::DraftConflict && attempt == 0 => {
                    let message = match &error {
                        ClientError::Host(refused) => refused.message.clone(),
                        ClientError::Refused { error, .. } => error.message.clone(),
                        other => other.to_string(),
                    };
                    match revision_in(&message) {
                        Some(revision) => {
                            file.revision = Some(revision);
                            self.write(&paired, &file)?;
                        }
                        None => {
                            // The host's words do not carry the revision: the draft is ended.
                            file.revision = None;
                            self.write(&paired, &file)?;
                            let _ = self.finish_ending(&paired, &target, &mut file).await;
                            return Err(error.into());
                        }
                    }
                }
                Err(error) if unknown_draft(&error) => {
                    self.remove(&paired, bind.session_id);
                    return Err(CommandError::refused(GONE));
                }
                Err(
                    error
                    @ (ClientError::SubmissionUncertain { .. } | ClientError::ConnectionEnded),
                ) => {
                    // The answer is lost: the revision is not known, so the draft is ended.
                    file.revision = None;
                    self.write(&paired, &file)?;
                    let _ = self.finish_ending(&paired, &target, &mut file).await;
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(CommandError::unavailable(
            "the draft changed again while the file was being added: the file was not added",
        ))
    }

    fn fresh(&self, paired: &Paired, session_id: SessionId) -> DraftFile {
        DraftFile {
            version: DRAFT_VERSION,
            environment_id: paired.environment_id,
            device_id: paired.device_id,
            session_id,
            draft_id: None,
            revision: None,
            create_action: None,
            discard_action: None,
            attachments: Vec::new(),
        }
    }

    /// Makes the draft: under an action identifier that is kept first, and kept until the host
    /// answers it, so that a lost answer is asked again and the host's record answers it.
    async fn make(
        &self,
        paired: &Paired,
        target: &ActionTarget,
        bind: &Bind,
        file: &mut DraftFile,
    ) -> Result<()> {
        let action_id = match file.create_action {
            Some(action_id) => action_id,
            None => {
                let action_id = ActionId::new(kr_ipc::new_uuid());
                file.create_action = Some(action_id);
                self.write(paired, file)?;
                action_id
            }
        };
        // A create that went out earlier is read from the host's record before it is sent again.
        let recorded = paired
            .session
            .read_receipt(&ActionReadParams {
                action_id,
                session_id: None,
            })
            .await
            .ok()
            .and_then(|read| read.result.as_ref().cloned());
        let created: DraftCreateResult = match recorded {
            Some(value) => value
                .to_typed()
                .map_err(|error| CommandError::local_failure(error.to_string()))?,
            None => {
                let composed = paired
                    .session
                    .compose(
                        Method::DraftCreate,
                        action_id,
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
                match paired.session.send(&composed).await {
                    Ok(settled) => settled.to_typed()?,
                    Err(error) if unknown_draft(&error) => {
                        file.create_action = None;
                        self.remove(paired, bind.session_id);
                        return Err(CommandError::refused(GONE));
                    }
                    // Not answered: the action is kept, and the next bind asks about it.
                    Err(error) => {
                        let flag = self
                            .discard_refused
                            .load(std::sync::atomic::Ordering::Acquire);
                        return Err(at_the_bound(flag, &error).unwrap_or_else(|| error.into()));
                    }
                }
            }
        };
        file.draft_id = Some(created.draft.draft_id);
        file.revision = Some(created.draft.revision);
        file.create_action = None;
        self.write(paired, file)
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
        target: ActionTarget,
        session_id: SessionId,
    ) -> Result<()> {
        let Some(mut file) = self.read(&paired, session_id)? else {
            return Ok(());
        };
        self.finish_ending(&paired, &target, &mut file).await
    }

    /// Asks the host to discard the draft, under an action identifier kept until it answers.
    async fn finish_ending(
        &self,
        paired: &Paired,
        target: &ActionTarget,
        file: &mut DraftFile,
    ) -> Result<()> {
        let Some(draft_id) = file.draft_id else {
            self.remove(paired, file.session_id);
            return Ok(());
        };
        let action_id = match file.discard_action {
            Some(action_id) => action_id,
            None => {
                let action_id = ActionId::new(kr_ipc::new_uuid());
                file.discard_action = Some(action_id);
                self.write(paired, file)?;
                action_id
            }
        };
        let composed = paired
            .session
            .compose(
                Method::DraftDiscard,
                action_id,
                target.clone(),
                None,
                &NoPreconditions {},
                &DraftDiscardParams { draft_id },
                MUTATION_TTL,
            )
            .await?;
        match paired.session.send(&composed).await {
            Ok(_) => {
                self.remove(paired, file.session_id);
                Ok(())
            }
            Err(error) => match discard_outcome(&error) {
                Ended::Done => {
                    self.remove(paired, file.session_id);
                    Ok(())
                }
                // The client goes on without ending drafts, and says so only at the bound.
                Ended::OlderHost => {
                    self.discard_refused
                        .store(true, std::sync::atomic::Ordering::Release);
                    self.remove(paired, file.session_id);
                    Ok(())
                }
                Ended::Failed => Err(error.into()),
            },
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
        let target = ActionTarget::environment(paired.environment_id);
        self.sweep(paired, target, &ids).await;
    }

    /// At each start: the drafts whose session the host no longer lists are ended. A draft the host
    /// has already ended is harmless to end again.
    pub async fn sweep(&self, paired: Paired, target: ActionTarget, listed: &[SessionId]) {
        let Ok(path) = self.path(Uuid::from_bytes([0; 16])) else {
            return;
        };
        let Some(root) = path.parent() else { return };
        let Ok(listing) = std::fs::read_dir(root) else {
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
            let Ok(mut file) = serde_json::from_slice::<DraftFile>(&bytes) else {
                continue;
            };
            if file.version != DRAFT_VERSION
                || file.environment_id != paired.environment_id
                || file.device_id != paired.device_id
                || listed.contains(&file.session_id)
            {
                continue;
            }
            let _ = self.finish_ending(&paired, &target, &mut file).await;
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
        draft_id: Option<DraftId>,
        revision: Option<DraftRevision>,
        create_action: Option<ActionId>,
    ) {
        let mut file = self.fresh(paired, session_id);
        file.draft_id = draft_id;
        file.revision = revision;
        file.create_action = create_action;
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
            discard_outcome(&refused(ErrorCode::InvalidArgument, "no such draft")),
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
