//! What the worker asks of the reader thread, and what the reader answers.
//!
//! Three questions, all answered on the reader's own thread because that is the only place the
//! answers are true:
//!
//! * `root.editor.fence` asks whether prior input is resolved. Its answer is evidence: which queues
//!   are clear and the atomically read state behind that claim.
//! * A launch asks the reader to install a command. The reader checks its actual buffer state and
//!   revision and then accepts or rejects atomically, so a command cannot be installed into a
//!   buffer that changed between the check and the install. Nothing is ever written into the
//!   pseudo-terminal: there is no wake marker and no launch string, because the process reading the
//!   terminal may not be the shell.
//! * A cancellation ends an operation that is waiting for another key, and keeps the edit buffer.
//!   Without it, a takeover during a partial escape sequence, a quoted insertion, a vi motion, an
//!   incomplete chord or a macro would wait for a key that is never coming.

use core::fmt;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::InputLeaseEpoch;
use kr_protocol::ids::SessionId;
use kr_protocol::root::{
    CwdRevision, EditorBufferRevision, EditorState, FenceId, KeyQueueSnapshot, LaunchCommand,
    PromptGeneration, ReaderContext, ReaderRevision, RootEditorFenceParams, RootEditorFenceResult,
};
use kr_protocol::scalars::{DurationMs, U64, Uuid};
use serde::{Deserialize, Serialize};

/// One launch transaction.
///
/// A fence cannot identify a transaction: the same fence stays valid after a transaction has timed
/// out, so a second launch would reserve the same fence and a late answer to the first would look
/// like an answer to the second. Each transaction gets its own identity, and an answer naming a
/// transaction the worker has finished with installs nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LaunchTransactionId(pub Uuid);

impl LaunchTransactionId {
    /// Wraps a raw identifier.
    #[must_use]
    pub const fn new(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn get(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for LaunchTransactionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

/// A launch the worker put in the reader's mailbox.
///
/// It names the transaction and the fence it was reserved against, so a reader that has moved on
/// rejects it rather than installing a command the caller asked for under different circumstances.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchMailboxRequest {
    /// The session.
    pub session_id: SessionId,
    /// This transaction.
    pub transaction: LaunchTransactionId,
    /// The fence reserved for it.
    pub fence_id: FenceId,
    /// What to install.
    pub command: LaunchCommand,
    /// The prompt generation the caller expects.
    pub expected_prompt_generation: PromptGeneration,
    /// The buffer revision the caller expects an empty buffer to be at.
    pub expected_buffer_revision: EditorBufferRevision,
    /// The working-directory revision the worker recorded at the reader boundary.
    ///
    /// Section 23 lists the working directory among this method's preconditions. The caller names
    /// the prompt and the buffer; the worker adds what it recorded, so a launch decided against one
    /// directory is not installed in another.
    pub expected_cwd_revision: CwdRevision,
    /// How long the reader has to decide, measured from when it receives this request.
    ///
    /// The reader is bound by the same 250 ms as the worker: past it, the reader installs nothing
    /// and answers `timeout`. That is what makes "install no command" true on a timeout, rather
    /// than the worker hoping its own answer arrives first.
    pub deadline_ms: DurationMs,
}

/// The reader installed and submitted the command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAccepted {
    /// The transaction being answered.
    pub transaction: LaunchTransactionId,
    /// What the reader installed, exactly as the request carried it.
    ///
    /// An argument vector is quoted by the integration for its own shell and installed as those
    /// literal arguments: nothing is assembled by interpolation, and the caller can see from the
    /// answer that what it asked for is what went in.
    pub installed: LaunchCommand,
    /// The fence it was installed under.
    pub fence_id: FenceId,
    /// The prompt generation at acceptance.
    pub prompt_generation: PromptGeneration,
    /// The buffer revision after the command was installed.
    pub buffer_revision: EditorBufferRevision,
    /// The reader revision that accepted it.
    pub reader_revision: ReaderRevision,
}

/// Why the reader did not install the command.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchRejectionReason {
    /// The reader left before the mailbox was checked.
    EditorLeft,
    /// Input was already queued ahead of the launch.
    QueuedPriorInput,
    /// The input lease changed.
    LeaseChanged,
    /// The fence the transaction reserved is no longer valid.
    FenceInvalid,
    /// This is not the primary reader.
    NotPrimaryReader,
    /// The worker's hold expired before an answer arrived.
    Timeout,
    /// The buffer is not empty.
    BufferNotEmpty,
    /// The buffer revision is not the expected one.
    BufferRevisionMismatch,
    /// The prompt generation is not the expected one.
    PromptGenerationMismatch,
    /// The working directory has changed since the caller decided what to run.
    CwdRevisionMismatch,
    /// The worker revoked the transaction before the reader installed anything.
    ///
    /// The reader's confirmation, rather than the worker's own timer, is what makes "install no
    /// command" a fact: the frames on this endpoint are ordered, so a revocation the worker sent
    /// before the reader's atomic step is one the reader sees in that step.
    Revoked,
    /// The bridge ended before it confirmed what it had done with the transaction.
    ///
    /// The command may or may not be in the editor, and nothing left can say which. This is the one
    /// launch outcome a caller must never retry under the same action identifier.
    ConfirmationLost,
    /// The session is closing and installs nothing.
    SessionClosing,
}

impl LaunchRejectionReason {
    /// Every reason, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::EditorLeft,
        Self::QueuedPriorInput,
        Self::LeaseChanged,
        Self::FenceInvalid,
        Self::NotPrimaryReader,
        Self::Timeout,
        Self::BufferNotEmpty,
        Self::BufferRevisionMismatch,
        Self::PromptGenerationMismatch,
        Self::CwdRevisionMismatch,
        Self::Revoked,
        Self::ConfirmationLost,
        Self::SessionClosing,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EditorLeft => "editor_left",
            Self::QueuedPriorInput => "queued_prior_input",
            Self::LeaseChanged => "lease_changed",
            Self::FenceInvalid => "fence_invalid",
            Self::NotPrimaryReader => "not_primary_reader",
            Self::Timeout => "timeout",
            Self::BufferNotEmpty => "buffer_not_empty",
            Self::BufferRevisionMismatch => "buffer_revision_mismatch",
            Self::PromptGenerationMismatch => "prompt_generation_mismatch",
            Self::CwdRevisionMismatch => "cwd_revision_mismatch",
            Self::Revoked => "revoked",
            Self::ConfirmationLost => "confirmation_lost",
            Self::SessionClosing => "session_closing",
        }
    }

    /// Returns the error the `shell.launch` caller receives.
    ///
    /// An editor the transaction could not hold is `EDITOR_BUSY`, which is transient and invites the
    /// caller to try again. An editor whose own state had moved is `DRAFT_CONFLICT`: something was
    /// typed or changed locally, and repeating the same request would install a command against a
    /// buffer the person is using.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::EditorLeft
            | Self::QueuedPriorInput
            | Self::LeaseChanged
            | Self::FenceInvalid
            | Self::NotPrimaryReader
            | Self::Timeout
            | Self::Revoked => ErrorCode::EditorBusy,
            // Dispatch may have happened: the command could be in the editor and nothing left can
            // say. Never retried under the same action identifier.
            Self::ConfirmationLost => ErrorCode::OutcomeUnknown,
            Self::BufferNotEmpty
            | Self::BufferRevisionMismatch
            | Self::PromptGenerationMismatch
            | Self::CwdRevisionMismatch => ErrorCode::DraftConflict,
            Self::SessionClosing => ErrorCode::SessionClosed,
        }
    }
}

/// The reader refused the launch, and installed nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRejection {
    /// The transaction being refused.
    pub transaction: LaunchTransactionId,
    /// The fence it was reserved against.
    pub fence_id: FenceId,
    /// Why.
    pub reason: LaunchRejectionReason,
    /// The prompt generation the reader is actually at.
    pub prompt_generation: PromptGeneration,
    /// The buffer revision it actually has.
    pub buffer_revision: EditorBufferRevision,
}

/// The reader thread's answer to a launch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchDecision {
    /// Installed and submitted.
    Accepted(LaunchAccepted),
    /// Refused, with nothing installed.
    Rejected(LaunchRejection),
}

impl LaunchDecision {
    /// Returns the rejection's reason, or `None` when the launch was installed.
    #[must_use]
    pub const fn rejection(&self) -> Option<LaunchRejectionReason> {
        match self {
            Self::Accepted(_) => None,
            Self::Rejected(rejection) => Some(rejection.reason),
        }
    }
}

/// What the reader knows when it opens its mailbox.
///
/// Every field is read on the reader thread, at the moment it decides. That is the point of a
/// mailbox rather than a message: the check and the install happen with nothing in between.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderLaunchState {
    /// The prompt the reader is at.
    pub prompt_generation: PromptGeneration,
    /// The reader's revision.
    pub reader_revision: ReaderRevision,
    /// Which reader is asking.
    pub reader_context: ReaderContext,
    /// Its buffer and pending operation.
    pub editor: EditorState,
    /// Its key queues at the same instant.
    pub snapshot: KeyQueueSnapshot,
    /// The shell's working-directory revision.
    pub cwd_revision: CwdRevision,
    /// Whether the fence the request names is still the reader's own.
    pub fence_live: bool,
    /// Whether a revocation for this transaction was in the frames this step read.
    ///
    /// The endpoint delivers frames in order, so a revocation the worker sent before this step is
    /// one this step sees. Checking it here is what puts the decision between installing and
    /// cancelling inside the reader's own atomic step rather than across two clocks.
    pub revoked: bool,
    /// How long the request has been in the mailbox, on the reader's own clock.
    pub waited_ms: DurationMs,
}

/// Decides one launch on the reader thread.
///
/// The order is the order the reasons matter in. Identity first: this reader, this fence, inside its
/// deadline. Then input the person typed before the launch arrived, which is theirs and goes first.
/// Then what the caller expected, where a mismatch is an intervening local edit rather than a busy
/// editor.
#[must_use]
pub fn decide_launch(request: &LaunchMailboxRequest, state: &ReaderLaunchState) -> LaunchDecision {
    let reject = |reason: LaunchRejectionReason| {
        LaunchDecision::Rejected(LaunchRejection {
            transaction: request.transaction,
            fence_id: request.fence_id,
            reason,
            prompt_generation: state.prompt_generation,
            buffer_revision: state.editor.buffer_revision,
        })
    };
    if state.revoked {
        // The revocation was in the queue this step read, so the reader installs nothing and says
        // so. That confirmation, not the worker's timer, is what the caller's answer rests on.
        return reject(LaunchRejectionReason::Revoked);
    }
    if !state.fence_live {
        return reject(LaunchRejectionReason::FenceInvalid);
    }
    if !state.reader_context.is_primary() {
        return reject(LaunchRejectionReason::NotPrimaryReader);
    }
    if state.waited_ms.get() >= request.deadline_ms.get() {
        return reject(LaunchRejectionReason::Timeout);
    }
    if !state.snapshot.is_drained() || state.editor.pending.macro_input {
        return reject(LaunchRejectionReason::QueuedPriorInput);
    }
    if state.prompt_generation != request.expected_prompt_generation {
        return reject(LaunchRejectionReason::PromptGenerationMismatch);
    }
    if state.cwd_revision != request.expected_cwd_revision {
        return reject(LaunchRejectionReason::CwdRevisionMismatch);
    }
    if !state.editor.buffer_empty {
        return reject(LaunchRejectionReason::BufferNotEmpty);
    }
    if state.editor.buffer_revision != request.expected_buffer_revision {
        return reject(LaunchRejectionReason::BufferRevisionMismatch);
    }
    LaunchDecision::Accepted(LaunchAccepted {
        transaction: request.transaction,
        installed: request.command.clone(),
        fence_id: request.fence_id,
        prompt_generation: state.prompt_generation,
        // Installing the command changes the buffer once.
        buffer_revision: EditorBufferRevision::new(state.editor.buffer_revision.get() + 1),
        reader_revision: state.reader_revision,
    })
}

/// End the reader's pending key wait without losing the edit buffer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelKeyWait {
    /// The session.
    pub session_id: SessionId,
    /// This cancellation's position in the session's own sequence of them.
    ///
    /// Neither the reader's identity nor the epoch tells every cancellation from the next: a
    /// takeover and a departure can both cancel at one prompt in one reader, and a departure can
    /// happen at the epoch a takeover just produced. The sequence is what a report is matched on.
    pub sequence: U64,
    /// The input-lease epoch this cancellation belongs to.
    ///
    /// Two takeovers can happen at one prompt in one reader, so the reader's identity cannot tell
    /// one cancellation from the next. The epoch can: it is what the takeover produced, and it is
    /// what the report's own discards belong to.
    pub epoch: InputLeaseEpoch,
    /// The prompt generation the worker is cancelling at.
    pub prompt_generation: PromptGeneration,
    /// The reader revision it is cancelling.
    pub reader_revision: ReaderRevision,
}

/// Which incomplete operations a cancellation ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelledOperations {
    /// A partial escape sequence in the decoder.
    pub partial_escape: bool,
    /// A quoted insertion waiting for its character.
    pub quoted_insertion: bool,
    /// A vi motion waiting for its target.
    pub vi_motion: bool,
    /// An incomplete multikey sequence or chord.
    pub multikey_sequence: bool,
    /// A macro that was still feeding the reader.
    pub macro_input: bool,
}

impl CancelledOperations {
    /// Nothing was in progress.
    pub const NONE: Self = Self {
        partial_escape: false,
        quoted_insertion: false,
        vi_motion: false,
        multikey_sequence: false,
        macro_input: false,
    };

    /// Returns true when at least one operation was ended.
    #[must_use]
    pub const fn any(self) -> bool {
        self.partial_escape
            || self.quoted_insertion
            || self.vi_motion
            || self.multikey_sequence
            || self.macro_input
    }
}

/// What a cancellation did.
///
/// `buffer_preserved` is the qualifying claim. A bridge that can end a key wait only by discarding
/// what the person has typed has no non-destructive cancellation path, and a report that says so is
/// treated as a refusal rather than as a completed transition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationReport {
    /// The cancellation being answered.
    pub sequence: U64,
    /// The epoch it was asked for.
    pub epoch: InputLeaseEpoch,
    /// The prompt the cancellation was asked for.
    pub prompt_generation: PromptGeneration,
    /// The reader revision it was asked for.
    ///
    /// A report from a reader the worker did not ask says nothing about the one it did, so it is
    /// ignored rather than acted on.
    pub reader_revision: ReaderRevision,
    /// What was ended.
    pub cancelled: CancelledOperations,
    /// Whether the edit buffer survived.
    pub buffer_preserved: bool,
    /// Bytes of unread reader input that were discarded with the cancelled operations.
    pub discarded_bytes: U64,
}

/// What the worker asks the reader thread.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerRequest {
    /// Resolve prior input so a fence can be published.
    Fence(RootEditorFenceParams),
    /// Install and submit a command.
    Launch(LaunchMailboxRequest),
    /// End a pending key wait and keep the buffer.
    Cancel(CancelKeyWait),
}

/// What the reader thread answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeAnswer {
    /// The answer to a fence exchange.
    Fence(RootEditorFenceResult),
    /// The answer to a launch.
    Launch(LaunchDecision),
    /// The answer to a cancellation.
    Cancel(CancellationReport),
}

impl LaunchDecision {
    /// Returns the transaction this answer belongs to.
    #[must_use]
    pub const fn transaction(&self) -> LaunchTransactionId {
        match self {
            Self::Accepted(accepted) => accepted.transaction,
            Self::Rejected(rejected) => rejected.transaction,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_editor_is_transient_and_a_changed_buffer_is_a_conflict() {
        for reason in [
            LaunchRejectionReason::EditorLeft,
            LaunchRejectionReason::QueuedPriorInput,
            LaunchRejectionReason::LeaseChanged,
            LaunchRejectionReason::FenceInvalid,
            LaunchRejectionReason::NotPrimaryReader,
            LaunchRejectionReason::Timeout,
        ] {
            assert_eq!(reason.code(), ErrorCode::EditorBusy, "{}", reason.as_str());
        }
        for reason in [
            LaunchRejectionReason::BufferNotEmpty,
            LaunchRejectionReason::BufferRevisionMismatch,
            LaunchRejectionReason::PromptGenerationMismatch,
        ] {
            assert_eq!(
                reason.code(),
                ErrorCode::DraftConflict,
                "{}",
                reason.as_str()
            );
        }
    }

    #[test]
    fn a_closing_session_installs_nothing() {
        assert_eq!(
            LaunchRejectionReason::SessionClosing.code(),
            ErrorCode::SessionClosed
        );
    }

    #[test]
    fn every_rejection_reason_has_a_distinct_wire_string() {
        let mut names: Vec<&str> = LaunchRejectionReason::ALL
            .iter()
            .map(|reason| reason.as_str())
            .collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    fn epoch() -> InputLeaseEpoch {
        InputLeaseEpoch::new(4)
    }

    fn request() -> LaunchMailboxRequest {
        LaunchMailboxRequest {
            session_id: SessionId::new(Uuid::from_bytes([0x11; 16])),
            transaction: LaunchTransactionId::new(Uuid::from_bytes([0x71; 16])),
            fence_id: FenceId::new(Uuid::from_bytes([0xF1; 16])),
            command: LaunchCommand::Arguments(vec!["codex".to_owned()]),
            expected_prompt_generation: PromptGeneration::new(4),
            expected_buffer_revision: EditorBufferRevision::new(9),
            expected_cwd_revision: CwdRevision::new(2),
            deadline_ms: DurationMs::new(200),
        }
    }

    fn reader() -> ReaderLaunchState {
        ReaderLaunchState {
            prompt_generation: PromptGeneration::new(4),
            reader_revision: ReaderRevision::new(1),
            reader_context: ReaderContext::Primary,
            editor: EditorState {
                buffer_revision: EditorBufferRevision::new(9),
                buffer_empty: true,
                keymap: kr_protocol::root::EditorKeymap::Emacs,
                pending: kr_protocol::root::PendingReaderInput::NONE,
            },
            snapshot: KeyQueueSnapshot::drained(),
            cwd_revision: CwdRevision::new(2),
            fence_live: true,
            revoked: false,
            waited_ms: DurationMs::new(3),
        }
    }

    #[test]
    fn the_reader_installs_only_what_the_caller_asked_for() {
        let decision = decide_launch(&request(), &reader());
        let LaunchDecision::Accepted(accepted) = decision else {
            panic!("an empty primary prompt at the expected revisions installs the command");
        };
        assert_eq!(accepted.transaction, request().transaction);
        assert_eq!(accepted.buffer_revision, EditorBufferRevision::new(10));
        // The literal arguments the caller named, not a string something reassembled.
        assert_eq!(
            accepted.installed,
            LaunchCommand::Arguments(vec!["codex".to_owned()])
        );
    }

    #[test]
    fn a_cancellation_report_names_the_epoch_its_discards_belong_to() {
        let report = CancellationReport {
            sequence: U64::new(1),
            epoch: epoch(),
            prompt_generation: PromptGeneration::new(4),
            reader_revision: ReaderRevision::new(1),
            cancelled: CancelledOperations {
                partial_escape: true,
                ..CancelledOperations::NONE
            },
            buffer_preserved: true,
            discarded_bytes: U64::new(2),
        };
        assert_eq!(report.epoch, epoch());
        assert!(report.cancelled.any());
    }

    #[test]
    fn a_revocation_the_reader_saw_installs_nothing() {
        let decision = decide_launch(
            &request(),
            &ReaderLaunchState {
                revoked: true,
                ..reader()
            },
        );
        assert_eq!(decision.rejection(), Some(LaunchRejectionReason::Revoked));
        assert_eq!(LaunchRejectionReason::Revoked.code(), ErrorCode::EditorBusy);
        // The one launch outcome nobody can retry under the same action identifier.
        assert_eq!(
            LaunchRejectionReason::ConfirmationLost.code(),
            ErrorCode::OutcomeUnknown
        );
    }

    #[test]
    fn the_reader_names_the_first_reason_it_cannot_install() {
        let cases: Vec<(LaunchRejectionReason, ReaderLaunchState)> = vec![
            (
                LaunchRejectionReason::FenceInvalid,
                ReaderLaunchState {
                    fence_live: false,
                    ..reader()
                },
            ),
            (
                LaunchRejectionReason::NotPrimaryReader,
                ReaderLaunchState {
                    reader_context: ReaderContext::Continuation,
                    ..reader()
                },
            ),
            (
                LaunchRejectionReason::Timeout,
                ReaderLaunchState {
                    waited_ms: DurationMs::new(200),
                    ..reader()
                },
            ),
            (
                LaunchRejectionReason::QueuedPriorInput,
                ReaderLaunchState {
                    snapshot: KeyQueueSnapshot {
                        queued_keys: U64::new(2),
                        ..KeyQueueSnapshot::drained()
                    },
                    ..reader()
                },
            ),
            (
                LaunchRejectionReason::PromptGenerationMismatch,
                ReaderLaunchState {
                    prompt_generation: PromptGeneration::new(5),
                    ..reader()
                },
            ),
            (
                LaunchRejectionReason::CwdRevisionMismatch,
                ReaderLaunchState {
                    cwd_revision: CwdRevision::new(3),
                    ..reader()
                },
            ),
            (
                LaunchRejectionReason::BufferNotEmpty,
                ReaderLaunchState {
                    editor: EditorState {
                        buffer_empty: false,
                        ..reader().editor
                    },
                    ..reader()
                },
            ),
            (
                LaunchRejectionReason::BufferRevisionMismatch,
                ReaderLaunchState {
                    editor: EditorState {
                        buffer_revision: EditorBufferRevision::new(11),
                        ..reader().editor
                    },
                    ..reader()
                },
            ),
        ];
        for (expected, state) in cases {
            assert_eq!(
                decide_launch(&request(), &state).rejection(),
                Some(expected),
                "{}",
                expected.as_str()
            );
        }
    }

    #[test]
    fn a_cancellation_that_ended_nothing_is_visible_as_such() {
        assert!(!CancelledOperations::NONE.any());
        assert!(
            CancelledOperations {
                partial_escape: true,
                ..CancelledOperations::NONE
            }
            .any()
        );
    }
}
