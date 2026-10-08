//! What a reader is shown of an action's retained result.
//!
//! A worker keeps what each action produced, so that a duplicate request, and `action.read`, can
//! answer from it. What is kept does not change: its digest, the receipt's revision and settle-once
//! all rest on it. What a reader is **shown** of it is decided here, for the reader and at the
//! moment it reads, because section 23 has the host check present authority before it returns a
//! retained receipt, and section 10 has the shared history filter hold content to the grant's
//! bound however it was reached: a later read of old content does not make it newly authorised.
//!
//! Three kinds of reader exist ([`Disclosure`]). The local owner is shown everything. A caller
//! acting under a grant whose history scope came with its frame is shown what the scope reaches. Any
//! other caller is shown the state of its action and no content: the absence of a scope never
//! widens what is shown.
//!
//! Which results carry content is the table in [`result_content`], not something derived from the
//! method registry: a result whose method says "no history filter" can still quote a session, so
//! every write method is listed and a test fails on one that is not.

use kr_protocol::envelope::ParamsValue;
use kr_protocol::method::Method;
use kr_protocol::question::{Question, QuestionResolveResult, QuestionState};
use kr_protocol::receipt::{ActionCancelResult, Receipt};

use crate::error::{Result, WorkerError};
use crate::history_filter::HistoryFilter;
use crate::questions::Resolution;

/// What one reader may be shown of a retained result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Disclosure {
    /// The local owner: the operating-system user the listener authenticated, acting under no
    /// grant. Everything is shown.
    Whole,
    /// A caller acting under a grant whose history scope came with its frame.
    Scoped {
        /// The scope's reach over content, decided as the question's own dates decide it. It is
        /// built as though the caller held `session.view`, so that *whether a caller may answer
        /// something* is decided by its history and its names alone, as the registry says
        /// `question.respond` is the one right answering needs.
        reach: HistoryFilter,
        /// Whether the caller holds `session.view` over the session: content is shown only to a
        /// caller that does, however far its history reaches.
        view: bool,
    },
    /// Any other caller: the state of its action, never content.
    StateOnly,
}

impl Disclosure {
    /// Returns whether this reader's history reaches a question as it stands now, which is what
    /// decides whether it may resolve the question.
    ///
    /// The question's own creation date decides it, and a question a grant names is reached only
    /// while it is open ([`HistoryFilter::admit_question`]).
    #[must_use]
    pub fn reaches_question(&self, question: &Question) -> bool {
        match self {
            Self::Whole => true,
            Self::StateOnly => false,
            Self::Scoped { reach, .. } => reach
                .admit_question(
                    question.question_id,
                    question.created_at_ms.get(),
                    question.state,
                )
                .is_ok(),
        }
    }
}

/// When a result is shown: as the answer to the request that performed the action, or as the
/// answer to a later read of what it kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Occasion {
    /// The first answer, given while the action was admitted. A question the caller's grant names
    /// was open when it was answered, which is the moment the grant's named exception covers.
    First,
    /// A later read: a duplicate of the action, or `action.read`. The question is resolved by
    /// now, so the exception no longer applies and the grant's lower bound decides.
    Replay,
}

/// What kind of content a method's retained result carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResultContent {
    /// Identifiers, states, keys, revisions and counts, and nothing a session or a person wrote.
    Identifiers,
    /// A record of an operation on the environment, which no session's history is part of: a
    /// repository, a catalogue, a workflow, a pairing, a device. It is held by the selector and
    /// the right the method named, as its read twin is, and not by a history bound.
    Environment,
    /// A question, as it stands after the action: what an application asked, the context it gave,
    /// its choices, who asked and what was answered. It follows the question's own dates.
    Question,
    /// A receipt, whose error message can quote an upstream or a session and has no date of its
    /// own.
    Receipt,
    /// A summary of the session itself: the directory and shell it was created with. It is the
    /// session's present metadata, shown to every reader that holds `session.view`, as
    /// `session.read` shows it.
    SessionMetadata,
    /// A close's description of the session, which the control daemon keeps whole for its own use
    /// and shows a requester only as far as the requester's history reaches back to the session's
    /// start.
    SessionDescription,
    /// A result an application source reads about its own question or alert. Only the local caller
    /// that created it is shown it.
    Source,
    /// A result that quotes questions, approvals or a session's description, which is shown to the
    /// owner and kept for no one else.
    Owner,
    /// A method this table does not name. It is shown to the owner alone.
    Unclassified,
}

/// Returns the kind of content `method`'s retained result carries.
///
/// A method is listed here by name. A new method is [`ResultContent::Unclassified`], and so is not
/// shown to anyone but the owner, until it is placed.
#[must_use]
pub const fn result_content(method: Method) -> ResultContent {
    use ResultContent::{
        Environment, Identifiers, Owner, Question, Receipt, SessionDescription, SessionMetadata,
        Source, Unclassified,
    };
    match method {
        // Terminals, input, attachments and agents: what each does is recorded as identifiers,
        // revisions and states. The agent mutations are answered with the upstream's own request
        // identifier and the turn it applies to. A machine group step is answered with the
        // environment's identifier and the group it now records: its identifier, revision, change
        // and the group it left.
        Method::SessionAttach
        | Method::SessionDetach
        | Method::AttachmentConfigure
        | Method::AttachmentViewport
        | Method::TerminalResize
        | Method::TerminalGeometryTransfer
        | Method::TerminalPaletteSet
        | Method::InputAcquire
        | Method::InputRelease
        | Method::InputInterrupt
        | Method::InputWrite
        | Method::RootEditorEnter
        | Method::RootEditorLeave
        | Method::RootEditorFence
        | Method::RootEofDetach
        | Method::RootCommandAccepted
        | Method::ShellLaunch
        | Method::AgentPromptSubmit
        | Method::AgentPromptQueue
        | Method::AgentTurnSteer
        | Method::AgentTurnCancel
        | Method::AgentApprovalRespond
        | Method::PluginActionInvoke
        | Method::MachineJoin
        | Method::MachineMerge
        | Method::MachineSplit => Identifiers,
        Method::QuestionAnswer | Method::QuestionCancel => Question,
        Method::ActionCancel => Receipt,
        Method::SessionCreate | Method::SessionRename => SessionMetadata,
        Method::SessionClose => SessionDescription,
        Method::QuestionCreate | Method::QuestionCancelOwn | Method::AlertCreate => Source,
        Method::GrantCreate | Method::VoiceDelegate => Owner,
        Method::EnvironmentEnrol
        | Method::EnvironmentForget
        | Method::EnvironmentRefresh
        | Method::DeliveryDestinationSecretSet
        | Method::PrivacySet
        | Method::PairInvite
        | Method::PairRedeem
        | Method::PairFinish
        | Method::PairConfirm
        | Method::PairCancel
        | Method::DeviceRevoke
        | Method::DevicePreviewKeyUpdate
        | Method::DeviceKeysComplete
        | Method::CatalogueAdd
        | Method::CatalogueSync
        | Method::CataloguePin
        | Method::CatalogueRemove
        | Method::PluginInstall
        | Method::PluginRemove
        | Method::PluginPin
        | Method::PluginEnable
        | Method::PluginDisable
        | Method::PluginGrant
        | Method::AgentToolsInstall
        | Method::AgentToolsRemove
        | Method::DraftCreate
        | Method::DraftUpdate
        | Method::AgentDraftAddAttachment
        | Method::UploadBegin
        | Method::UploadChunk
        | Method::UploadFinish
        | Method::UploadCancel
        | Method::ProjectInit
        | Method::ProjectClone
        | Method::ProjectAdopt
        | Method::ProjectLocationAuthorise
        | Method::ProjectLocationWithdraw
        | Method::ProjectLocationAttach
        | Method::ProjectOperationCancel
        | Method::WorkspaceCreate
        | Method::WorkspaceRemove
        | Method::DiffApply
        | Method::DiffRevert
        | Method::ChangesetCapture
        | Method::ChangesetMaterialize
        | Method::ReviewAcknowledge
        | Method::AttentionAcknowledge
        | Method::AttentionQuietHours
        | Method::VisitAcknowledge
        | Method::OwnerConfirmationRequest
        | Method::OwnerConfirmationComplete
        | Method::GrantRevoke
        | Method::GrantRedeem
        | Method::PushInstallationRegister
        | Method::PushSenderIssue
        | Method::PushSenderRenew
        | Method::PushSenderRevoke
        | Method::MailboxDeliver
        | Method::MailboxAcknowledge
        | Method::AuthoritySync
        | Method::SyncCompareExchange
        | Method::BackupManifest
        | Method::StorageRetentionSet
        | Method::StorageUploadCreate
        | Method::StorageUploadPart
        | Method::StorageUploadComplete
        | Method::StorageUploadAbort
        | Method::StorageObjectDelete
        | Method::VoiceStart
        | Method::VoiceStop
        | Method::VoiceGrant
        | Method::WorkflowInstall
        | Method::WorkflowEnable
        | Method::WorkflowPause
        | Method::WorkflowRun
        | Method::HostUpdateHandover
        | Method::HostClockEstablish
        | Method::DescriptionConfigure
        | Method::DescriptionDownload => Environment,
        _ => Unclassified,
    }
}

/// Returns the receipt as `disclosure` shows it: whole to the owner, and to anybody else with its
/// error's text replaced.
#[must_use]
pub fn shown_receipt(disclosure: &Disclosure, receipt: Receipt) -> Receipt {
    match disclosure {
        Disclosure::Whole => receipt,
        Disclosure::Scoped { .. } | Disclosure::StateOnly => receipt.with_error_withheld(),
    }
}

/// Returns the retained result of `method` as `disclosure` shows it, built from the bytes the
/// journal kept, which are not changed.
///
/// # Errors
///
/// Returns [`WorkerError::PermissionDenied`] for a result that reader is not shown at all, and
/// [`WorkerError::InvalidArgument`] for a kept result that cannot be read back as the shape its
/// method stores.
pub fn shown_result(
    disclosure: &Disclosure,
    method: Method,
    result: ParamsValue,
    occasion: Occasion,
) -> Result<ParamsValue> {
    let content = result_content(method);
    if matches!(disclosure, Disclosure::Whole) {
        // The owner is shown everything, and a question's answer is built from what was kept in
        // the one form every reader's is built from.
        return match content {
            ResultContent::Question => question_result(disclosure, result, occasion),
            _ => Ok(result),
        };
    }
    match content {
        ResultContent::Identifiers
        | ResultContent::Environment
        | ResultContent::SessionMetadata => Ok(result),
        // A scoped reader is shown the whole of a close's description by the worker: the control
        // daemon is the one that holds it to the requester's reach, because it keeps the whole
        // description for its own use.
        ResultContent::SessionDescription => Ok(match disclosure {
            Disclosure::Scoped { .. } => result,
            _ => without_description(&result),
        }),
        ResultContent::Question => question_result(disclosure, result, occasion),
        ResultContent::Receipt => {
            let cancelled: ActionCancelResult = result.to_typed().map_err(unreadable)?;
            ParamsValue::from_typed(&ActionCancelResult {
                receipt: shown_receipt(disclosure, cancelled.receipt),
            })
            .map_err(unreadable)
        }
        ResultContent::Source | ResultContent::Owner | ResultContent::Unclassified => {
            Err(withheld_entirely())
        }
    }
}

/// The member of a close's result that holds the worker's description of the session.
pub const DESCRIPTION_MEMBER: &str = "session";

/// The member of an answer to a question's resolution that holds the question.
pub const QUESTION_MEMBER: &str = "question";

/// Returns one member of a result that is a map, as the worker wrote it.
///
/// The members are read from the encoded value rather than through a typed shape, so an answer
/// this build cannot decode, as one from a worker built after it may be, is still opened.
#[must_use]
pub fn member<'a>(result: &'a ParamsValue, name: &str) -> Option<&'a kr_cbor::CanonicalValue> {
    match result.as_value() {
        kr_cbor::CanonicalValue::Map(map) => map.get(name),
        _ => None,
    }
}

/// Returns a result with one member taken out, and every other member as it was.
///
/// A result that is not a map, or has no such member, is returned as it is.
#[must_use]
pub fn without_member(result: &ParamsValue, name: &str) -> ParamsValue {
    use kr_cbor::{CanonicalMap, CanonicalValue};

    let CanonicalValue::Map(answer) = result.as_value() else {
        return result.clone();
    };
    if answer.get(name).is_none() {
        return result.clone();
    }
    let kept = answer
        .entries()
        .iter()
        .filter(|(key, _)| key != name)
        .cloned()
        .collect();
    // Taking one entry out of a canonical map leaves it ordered and free of duplicates, so this
    // does not fail; were it ever to, the member stays out and so does the rest.
    CanonicalMap::from_sorted_entries(kept).map_or_else(
        |_| ParamsValue::empty(),
        |members| ParamsValue::new(CanonicalValue::Map(members)),
    )
}

/// Returns a result with one member set to null where it has it, and every other member as it
/// was. A member the result does not have is not added: a receipt that holds no question stays a
/// receipt.
#[must_use]
pub fn with_member_nulled(result: &ParamsValue, name: &str) -> ParamsValue {
    use kr_cbor::{CanonicalMap, CanonicalValue};

    let CanonicalValue::Map(answer) = result.as_value() else {
        return result.clone();
    };
    if answer.get(name).is_none() {
        return result.clone();
    }
    let replaced = answer
        .entries()
        .iter()
        .map(|(key, value)| {
            if key == name {
                (key.clone(), CanonicalValue::Null)
            } else {
                (key.clone(), value.clone())
            }
        })
        .collect();
    CanonicalMap::from_sorted_entries(replaced).map_or_else(
        |_| ParamsValue::empty(),
        |members| ParamsValue::new(CanonicalValue::Map(members)),
    )
}

/// Returns a close's result without the worker's description of the session.
#[must_use]
pub fn without_description(result: &ParamsValue) -> ParamsValue {
    without_member(result, DESCRIPTION_MEMBER)
}

/// Builds the answer to `question.answer` or `question.cancel` that `disclosure` is shown.
fn question_result(
    disclosure: &Disclosure,
    result: ParamsValue,
    occasion: Occasion,
) -> Result<ParamsValue> {
    let Resolution { question } =
        kr_cbor::from_canonical_value(result.as_value()).map_err(unreadable)?;
    let shown = QuestionResolveResult::whole(question);
    let shown = match disclosure {
        Disclosure::Whole => shown,
        Disclosure::StateOnly => shown.withheld(),
        Disclosure::Scoped { reach, view } => {
            let reached = shown.question().is_some_and(|question| {
                // The first answer is decided as the caller was admitted: the question was open.
                // A later read sees it as it ended.
                let state = match occasion {
                    Occasion::First => QuestionState::Pending,
                    Occasion::Replay => question.state,
                };
                reach
                    .admit_question(question.question_id, question.created_at_ms.get(), state)
                    .is_ok()
            });
            if *view && reached {
                shown
            } else {
                shown.withheld()
            }
        }
    };
    ParamsValue::from_typed(&shown).map_err(unreadable)
}

fn unreadable(error: impl std::fmt::Display) -> WorkerError {
    WorkerError::InvalidArgument(format!(
        "a retained result could not be read back as the shape its method keeps: {error}"
    ))
}

/// The refusal for a result that this reader is not shown at all.
///
/// It says what the host holds and what it does not do, never that the action did not happen: the
/// action did, and the reader may well have caused it.
#[must_use]
pub fn withheld_entirely() -> WorkerError {
    WorkerError::PermissionDenied {
        detail: "the host holds what this action produced and does not show it to this caller"
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history_filter::ViewerScope;
    use kr_protocol::authority::{EffectClass, HistoryFilter as RegistryHistory};
    use kr_protocol::describe::{DescriptionDownload, DescriptionSetup, DescriptionState};
    use kr_protocol::grant::HistoryScope;
    use kr_protocol::ids::{
        ActorId, ApplicationInstanceId, ConnectionId, QuestionId, QuestionRevision, SessionEpoch,
        SessionId,
    };
    use kr_protocol::question::{
        AnswerRecord, QuestionAnswer, QuestionChoice, QuestionKind, QuestionSource,
    };
    use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, U64, Uuid};

    const ASKED_AT: u64 = 1_000;

    fn question_id() -> QuestionId {
        QuestionId::new(Uuid::from_bytes([1; 16]))
    }

    /// An answered question, asked at [`ASKED_AT`], with a word of content in every place a
    /// person or an application wrote one.
    fn answered() -> Question {
        Question {
            question_id: question_id(),
            revision: QuestionRevision::new(2),
            state: QuestionState::Answered,
            session_id: SessionId::new(Uuid::from_bytes([2; 16])),
            session_epoch: SessionEpoch::V1,
            kind: QuestionKind::Select,
            context: "the nightly build is green".to_owned(),
            question: "which environment?".to_owned(),
            choices: vec![QuestionChoice {
                choice_id: "staging".to_owned(),
                label: "Staging".to_owned(),
            }],
            source: QuestionSource {
                application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([3; 16])),
                process: kr_protocol::identity::ProcessStartIdentity::new(
                    7,
                    kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                    11,
                ),
                executable: Nullable::some("/opt/agent/bin/agent".to_owned()),
                agent_label: Nullable::some("the release agent".to_owned()),
                connection_id: ConnectionId::new(Uuid::from_bytes([4; 16])),
                launch_channel: false,
                session_member: true,
                ancestry: true,
                agent_binding_revision: Nullable::null(),
            },
            created_at_ms: TimestampMs::new(ASKED_AT),
            expires_at_ms: TimestampMs::new(ASKED_AT + 60_000),
            answer: Nullable::some(AnswerRecord {
                answer: QuestionAnswer::Other {
                    text: "ship it after lunch".to_owned(),
                },
                actor_id: ActorId::new("device:phone").expect("a principal"),
                device_id: Nullable::null(),
                question_revision: QuestionRevision::new(1),
                answered_at_ms: TimestampMs::new(ASKED_AT + 5_000),
            }),
            resolved_at_ms: Nullable::some(TimestampMs::new(ASKED_AT + 5_000)),
        }
    }

    fn kept() -> ParamsValue {
        ParamsValue::from_typed(&Resolution {
            question: answered(),
        })
        .expect("encodes")
    }

    fn scope(bound: Option<u64>, named: &[QuestionId]) -> HistoryScope {
        HistoryScope {
            lower_bound_ms: Nullable(bound.map(TimestampMs::new)),
            include_live_screen: false,
            named_questions: named.iter().copied().collect(),
            named_approvals: CanonicalSet::new(),
        }
    }

    fn scoped(bound: Option<u64>, named: &[QuestionId], view: bool) -> Disclosure {
        Disclosure::Scoped {
            reach: HistoryFilter::new(ViewerScope::from_history(&scope(bound, named), true)),
            view,
        }
    }

    fn shown(disclosure: &Disclosure, occasion: Occasion) -> QuestionResolveResult {
        shown_result(disclosure, Method::QuestionAnswer, kept(), occasion)
            .expect("shown")
            .to_typed()
            .expect("a resolution result")
    }

    /// KR-REQ-10.49: the owner is shown the whole question, built from what the journal kept.
    #[test]
    fn the_owner_is_shown_the_whole_question() {
        let result = shown(&Disclosure::Whole, Occasion::Replay);
        assert_eq!(result.question(), Some(&answered()));
        assert_eq!(result.state, QuestionState::Answered);
    }

    /// KR-REQ-10.49: a caller with no scope gets the state of its action and not one word of the
    /// question, the choices, the answer or who asked.
    #[test]
    fn a_caller_with_no_scope_is_shown_the_state_and_no_content() {
        for occasion in [Occasion::First, Occasion::Replay] {
            let result = shown(&Disclosure::StateOnly, occasion);
            assert_eq!(result.question(), None);
            assert_eq!(result.state, QuestionState::Answered);
            assert_eq!(result.question_id, question_id());
            assert_eq!(result.revision, QuestionRevision::new(2));
            let text = serde_json::to_string(&result).expect("encodes");
            for content in [
                "which environment?",
                "the nightly build is green",
                "Staging",
                "ship it after lunch",
                "the release agent",
                "/opt/agent/bin/agent",
            ] {
                assert!(!text.contains(content), "{content:?} in {text}");
            }
        }
    }

    /// KR-REQ-10.49: a replay is decided by the question's own date against the bound: one asked
    /// at or after the bound is shown, one asked before it is not, whatever the receipt's date.
    #[test]
    fn a_replay_is_held_to_the_questions_own_date() {
        let reaching = shown(&scoped(Some(ASKED_AT), &[], true), Occasion::Replay);
        assert_eq!(reaching.question(), Some(&answered()));
        let late = shown(&scoped(Some(ASKED_AT + 1), &[], true), Occasion::Replay);
        assert_eq!(late.question(), None, "asked before the bound");
        assert_eq!(late.state, QuestionState::Answered);
        let none = shown(&scoped(None, &[], true), Occasion::Replay);
        assert_eq!(none.question(), None, "a grant with no retained history");
    }

    /// KR-REQ-10.49: reaching a question is not viewing it. A caller that holds no
    /// `session.view` is shown none of it, however far its history reaches.
    #[test]
    fn a_caller_without_view_is_shown_no_content_however_far_its_history_reaches() {
        let result = shown(&scoped(Some(0), &[], false), Occasion::First);
        assert_eq!(result.question(), None);
        assert_eq!(result.state, QuestionState::Answered);
    }

    /// KR-REQ-10.51: a grant that names a question reaches it while it is open. The first answer
    /// to the caller that was admitted then is shown the question, although it was asked before the
    /// grant's bound; a later read sees it resolved, so the bound decides and it is not shown.
    #[test]
    fn a_named_question_is_shown_to_its_first_answer_and_not_to_a_replay() {
        let disclosure = scoped(Some(ASKED_AT + 10_000), &[question_id()], true);
        let first = shown(&disclosure, Occasion::First);
        assert_eq!(first.question(), Some(&answered()), "the first answer");
        let replay = shown(&disclosure, Occasion::Replay);
        assert_eq!(replay.question(), None, "the replay");
        assert_eq!(replay.state, QuestionState::Answered);

        // A grant that does not name it is shown it by neither.
        let unnamed = scoped(Some(ASKED_AT + 10_000), &[], true);
        assert_eq!(shown(&unnamed, Occasion::Replay).question(), None);
    }

    /// KR-REQ-10.49: a receipt's error text is withheld from everybody but the owner, and the
    /// state, the code and the revision stay.
    #[test]
    fn a_receipts_error_text_is_shown_to_the_owner_alone() {
        use kr_protocol::error::{ErrorCode, ProtocolError};
        use kr_protocol::ids::ActionId;
        use kr_protocol::method::MethodVersion;
        use kr_protocol::receipt::ReceiptState;
        use kr_protocol::scalars::{Digest256, U64};

        let receipt = Receipt {
            action_id: ActionId::new(Uuid::from_bytes([5; 16])),
            actor_id: ActorId::new("device:phone").expect("a principal"),
            method: Method::AgentPromptSubmit.into(),
            method_version: MethodVersion::V1,
            revision: U64::new(3),
            state: ReceiptState::Refused,
            reason: Nullable::null(),
            payload_digest: Digest256::from_bytes([0; 32]),
            accepted_deadline_ms: Nullable::null(),
            error: Nullable::some(ProtocolError::new(
                ErrorCode::InvalidArgument,
                "the agent said: the prompt quoted /home/person/notes",
            )),
            error_withheld: false,
            updated_at_ms: TimestampMs::new(9),
        };
        assert_eq!(shown_receipt(&Disclosure::Whole, receipt.clone()), receipt);
        for disclosure in [Disclosure::StateOnly, scoped(Some(0), &[], true)] {
            let shown = shown_receipt(&disclosure, receipt.clone());
            assert!(shown.error_withheld);
            assert_eq!(shown.state, ReceiptState::Refused);
            assert_eq!(shown.revision, receipt.revision);
            let text = serde_json::to_string(&shown).expect("encodes");
            assert!(!text.contains("/home/person"), "{text}");
        }
    }

    /// KR-REQ-10.49: a cancelled action's result carries a receipt, which is shown as a receipt is.
    #[test]
    fn a_cancelled_actions_result_withholds_its_receipts_error_from_a_non_owner() {
        use kr_protocol::error::{ErrorCode, ProtocolError};
        use kr_protocol::ids::ActionId;
        use kr_protocol::method::MethodVersion;
        use kr_protocol::receipt::ReceiptState;
        use kr_protocol::scalars::{Digest256, U64};

        let receipt = Receipt {
            action_id: ActionId::new(Uuid::from_bytes([6; 16])),
            actor_id: ActorId::new("device:phone").expect("a principal"),
            method: Method::AgentPromptSubmit.into(),
            method_version: MethodVersion::V1,
            revision: U64::new(2),
            state: ReceiptState::Rejected,
            reason: Nullable::null(),
            payload_digest: Digest256::from_bytes([0; 32]),
            accepted_deadline_ms: Nullable::null(),
            error: Nullable::some(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "secret detail",
            )),
            error_withheld: false,
            updated_at_ms: TimestampMs::new(9),
        };
        let kept = ParamsValue::from_typed(&ActionCancelResult {
            receipt: receipt.clone(),
        })
        .expect("encodes");
        let owner = shown_result(
            &Disclosure::Whole,
            Method::ActionCancel,
            kept.clone(),
            Occasion::Replay,
        )
        .expect("shown");
        assert_eq!(owner, kept);
        let device = shown_result(
            &Disclosure::StateOnly,
            Method::ActionCancel,
            kept,
            Occasion::Replay,
        )
        .expect("shown");
        let device: ActionCancelResult = device.to_typed().expect("a cancel result");
        assert!(device.receipt.error_withheld);
        assert!(
            !serde_json::to_string(&device)
                .expect("encodes")
                .contains("secret detail")
        );
    }

    /// KR-REQ-23.34: a close's description of the session is shown whole to a scoped reader, whom
    /// the control daemon holds to its reach, and is never shown to a reader that has no scope.
    #[test]
    fn a_closes_description_is_withheld_from_a_caller_with_no_scope() {
        use kr_cbor::{CanonicalMap, CanonicalValue};

        let answer = ParamsValue::new(CanonicalValue::Map(
            CanonicalMap::from_entries(vec![
                (
                    "session".to_owned(),
                    CanonicalValue::Text("described".to_owned()),
                ),
                (
                    "state".to_owned(),
                    CanonicalValue::Text("closing".to_owned()),
                ),
            ])
            .expect("a map"),
        ));
        let whole = |disclosure: &Disclosure| {
            shown_result(
                disclosure,
                Method::SessionClose,
                answer.clone(),
                Occasion::Replay,
            )
            .expect("shown")
        };
        assert_eq!(whole(&Disclosure::Whole), answer);
        assert_eq!(whole(&scoped(Some(0), &[], true)), answer);
        let bare = whole(&Disclosure::StateOnly);
        let CanonicalValue::Map(map) = bare.as_value() else {
            panic!("a map");
        };
        assert!(map.get("session").is_none());
        assert!(map.get("state").is_some());
    }

    /// KR-REQ-10.49: a result that is shown to the owner alone is withheld whole from everybody
    /// else, and so is one this table does not name.
    #[test]
    fn a_result_shown_to_the_owner_alone_is_withheld_from_everybody_else() {
        let kept = ParamsValue::empty();
        for method in [
            Method::GrantCreate,
            Method::VoiceDelegate,
            Method::QuestionCreate,
            Method::AlertCreate,
            Method::SessionList,
        ] {
            assert_eq!(
                shown_result(&Disclosure::Whole, method, kept.clone(), Occasion::Replay)
                    .expect("the owner's"),
                kept
            );
            for disclosure in [Disclosure::StateOnly, scoped(Some(0), &[], true)] {
                let refused = shown_result(&disclosure, method, kept.clone(), Occasion::Replay)
                    .expect_err("withheld");
                assert!(
                    matches!(refused, WorkerError::PermissionDenied { .. }),
                    "{method:?}"
                );
            }
        }
    }

    /// KR-REQ-10.49: the two writes that change how a host describes its sessions are records of an
    /// operation on the environment. A retained answer of either is shown as it was kept, whole or
    /// to a reader who may see state only or a scoped history, because it carries the host's
    /// setup and no session's text (KR-REQ-22.09).
    #[test]
    fn the_description_writes_are_records_of_an_operation_on_the_environment() {
        let kept = ParamsValue::from_typed(&DescriptionSetup {
            offered: true,
            enabled: true,
            on_battery: false,
            profile_id: Nullable::some("tiny-default".to_owned()),
            asset_bytes: U64::new(27),
            sources: vec!["127.0.0.1:1".to_owned()],
            download: DescriptionDownload::Failed,
            fetched_bytes: U64::new(0),
            failure: Nullable::some("a file was not the profile's".to_owned()),
            can_cancel: false,
            can_disable: true,
            needs_hosted_account: false,
            unavailable: Nullable::null(),
            state: DescriptionState::Ready,
            paused: Nullable::null(),
        })
        .expect("encodes");
        for method in [Method::DescriptionConfigure, Method::DescriptionDownload] {
            assert_eq!(result_content(method), ResultContent::Environment);
            for disclosure in [
                Disclosure::Whole,
                Disclosure::StateOnly,
                scoped(Some(0), &[], false),
            ] {
                assert_eq!(
                    shown_result(&disclosure, method, kept.clone(), Occasion::Replay)
                        .expect("shown"),
                    kept,
                    "{method:?}"
                );
            }
        }
    }

    /// KR-REQ-10.49: every write method is placed in the table, so a result that carries content
    /// cannot go unnoticed because nobody classified it; and a question is always held to the
    /// registry's named-resource rule.
    #[test]
    fn every_write_method_is_classified_and_a_question_follows_the_named_resource_rule() {
        for method in Method::ALL {
            let entry = method.entry();
            if entry.effect != EffectClass::Write {
                continue;
            }
            let content = result_content(*method);
            assert_ne!(
                content,
                ResultContent::Unclassified,
                "{} is a write the table does not place",
                method.as_str()
            );
            if content == ResultContent::Question {
                assert_eq!(
                    entry.history_filter,
                    RegistryHistory::NamedCurrentResources,
                    "{}",
                    method.as_str()
                );
            }
        }
        // And the two methods that show a question are the two the registry holds to the rule.
        let questions: Vec<&str> = Method::ALL
            .iter()
            .filter(|method| result_content(**method) == ResultContent::Question)
            .map(|method| method.as_str())
            .collect();
        assert_eq!(questions, ["question.answer", "question.cancel"]);
    }
}
