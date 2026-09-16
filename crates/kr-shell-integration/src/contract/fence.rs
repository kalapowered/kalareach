//! The fence and detach state machine.
//!
//! One pure machine over the five states of section 7. It holds no clock, no socket and no
//! terminal: every entry point takes the caller's own continuous-clock reading, and every
//! consequence comes back as an [`Action`] for the caller to carry out. The worker drives it with
//! its real clock and its real endpoints; the cross-shell fixtures drive it with numbers and
//! compare the actions, and both are then exercising the same rules.
//!
//! # The states
//!
//! | State | What it means |
//! | --- | --- |
//! | `outside` | No root editor is registered. Input forwards immediately and a lease change waits for nothing. |
//! | `unfenced` | A root editor is registered and nothing proves who owns its input. |
//! | `fenced` | A root editor is registered and its fence is valid. |
//! | `launch_reserved` | A launch transaction holds that fence while the reader's mailbox decides. |
//! | `closing` | The session is closing. |
//!
//! # The rules that are easy to get wrong
//!
//! * **A fence publishes only after an acknowledged drain.** An acknowledgement that does not report
//!   every queue clear withholds the fence, and so does one that arrives after the hold expired.
//! * **A hold is 250 ms and the lease change stands either way.** On expiry the held input is
//!   released in its original order, the editor stays `unfenced`, and an `EDITOR_BUSY` attachment
//!   event says so. It is not a failed `input.acquire`.
//! * **A retry never discards the mixed queues.** After a release the machine waits for a drained
//!   acknowledgement before it publishes anything, and it asks again at the reader's next entry or
//!   idle callback.
//! * **Outside a registered root editor nothing waits.** An application does not have a reader
//!   bridge, so no end-of-file candidate queue delays a Ctrl-D inside one.
//! * **An interrupt bypasses the hold.** It needs the current epoch and accepts only the configured
//!   native interrupt action; there is no variant of it that carries command bytes.
//! * **A failed fence never restarts the shell.** There is no action in this vocabulary that
//!   restarts anything.

use kr_protocol::error::ErrorCode;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{AttachmentId, InputLeaseEpoch, SessionId};
use kr_protocol::input::InterruptAction;
use kr_protocol::root::{
    AcceptedOrigin, CwdRevision, EditorBufferRevision, EditorBusyEvent, EditorBusyReason,
    EditorFence, FENCE_EXCHANGE_TIMEOUT, FenceAcknowledgement, FenceCause, FenceId, FenceRefusal,
    FenceState, LAUNCH_READER_BUDGET, LaunchCommand, PromptGeneration, ReaderContext,
    ReaderRevision, RootCommandAcceptedParams, RootEditorEnterParams, RootEditorFenceParams,
    RootEditorLeaveParams, RootEofDetachParams, RootEofDetachResult, ShellLaunchParams,
    ShellLaunchResult, WithheldReason,
};
use kr_protocol::scalars::{DurationMs, U64};
use serde::{Deserialize, Serialize};

use crate::contract::events::ReaderIdle;
use crate::contract::qualification::IntegrationLoss;
use crate::contract::requests::{
    CancelKeyWait, CancellationReport, LaunchDecision, LaunchMailboxRequest, LaunchRejectionReason,
    LaunchTransactionId,
};

/// A reading of the driver's own suspend-aware continuous clock, in milliseconds.
///
/// Not a wall clock: a deadline measured on a clock that can step backwards could extend a hold.
/// Not a process-anchored instant either, because the fixtures have to be able to state one as a
/// number and get the same answer the worker gets.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(transparent)]
pub struct ContinuousMs(pub U64);

impl ContinuousMs {
    /// Wraps a reading.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(U64::new(value))
    }

    /// Returns the reading.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns this reading advanced by a number of milliseconds.
    #[must_use]
    pub const fn plus(self, millis: u64) -> Self {
        Self::new(self.get().saturating_add(millis))
    }
}

/// One batch of input, named so that order can be asserted.
///
/// The machine never looks inside a batch. What matters is which batches are held, that they are
/// released in the order they arrived, and which of them a takeover or a removed attachment
/// discards.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct InputRef(pub String);

impl InputRef {
    /// Names a batch.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }
}

/// Who holds the input lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseView {
    /// The current epoch.
    pub epoch: InputLeaseEpoch,
    /// The attachment that holds it, when one does.
    pub holder: Option<AttachmentId>,
}

impl LeaseView {
    /// An unheld lease at an epoch.
    #[must_use]
    pub const fn unheld(epoch: InputLeaseEpoch) -> Self {
        Self {
            epoch,
            holder: None,
        }
    }

    /// A lease held by an attachment.
    #[must_use]
    pub const fn held(epoch: InputLeaseEpoch, holder: AttachmentId) -> Self {
        Self {
            epoch,
            holder: Some(holder),
        }
    }
}

/// A root editor was registered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EditorEntered {
    /// What the bridge reported.
    pub params: RootEditorEnterParams,
    /// The identity the worker will give the fence if the exchange it starts is acknowledged in
    /// time.
    pub candidate_fence: FenceId,
}

/// The input lease changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseChanged {
    /// The lease after the change.
    pub lease: LeaseView,
    /// Bytes the previous epoch lost inside the worker's own input queue, which the machine adds
    /// its held batches to for the takeover receipt.
    pub discarded_bytes: U64,
    /// The identity for the exchange this change starts, when it starts one.
    pub candidate_fence: FenceId,
}

/// The reader is idle, which is one of the points a withheld fence is retried at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReaderIdled {
    /// What the bridge reported.
    pub idle: ReaderIdle,
    /// The identity for the retry, when one is started.
    pub candidate_fence: FenceId,
}

/// A batch of input arrived from a client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputArrived {
    /// The batch.
    pub input: InputRef,
    /// The attachment that sent it.
    pub attachment_id: AttachmentId,
    /// The epoch it was sent under.
    pub epoch: InputLeaseEpoch,
    /// How many bytes it carries.
    pub bytes: U64,
}

/// A client asked for an interrupt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterruptRequested {
    /// The attachment asking.
    pub attachment_id: AttachmentId,
    /// The epoch it holds.
    pub epoch: InputLeaseEpoch,
    /// The action. Only the configured native interrupt exists.
    pub action: InterruptAction,
}

/// A launch was authorised and reached the worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequested {
    /// What the caller asked for.
    pub params: ShellLaunchParams,
    /// The attachment the launch is attributed to, which is what a line accepted from it belongs to
    /// rather than whoever holds the lease when the command starts.
    pub requester: AttachmentId,
    /// The identity the worker gives this transaction.
    pub transaction: LaunchTransactionId,
}

/// Something that happened to the worker.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stimulus {
    /// A root editor was registered.
    EditorEntered(EditorEntered),
    /// A root editor stopped.
    EditorLeft(RootEditorLeaveParams),
    /// The input lease changed.
    LeaseChanged(LeaseChanged),
    /// The bridge acknowledged a fence exchange.
    FenceAcknowledged(FenceAcknowledgement),
    /// The bridge refused one.
    FenceRefused(FenceRefusal),
    /// The reader reported what a cancellation did.
    CancellationReported(CancellationReport),
    /// The reader reported itself idle.
    ReaderIdled(ReaderIdled),
    /// Input arrived from a client.
    InputArrived(InputArrived),
    /// A client asked for an interrupt.
    InterruptRequested(InterruptRequested),
    /// An attachment was removed, by `kr detach` with an identifier or by losing its connection.
    AttachmentRemoved(AttachmentId),
    /// The bridge submitted an end-of-file detach.
    DetachSubmitted(RootEofDetachParams),
    /// A launch was authorised.
    LaunchRequested(LaunchRequested),
    /// The reader thread answered a launch.
    LaunchDecided(LaunchDecision),
    /// The reader accepted a line.
    CommandAccepted(RootCommandAcceptedParams),
    /// The driver's hold timer fired.
    HoldExpired,
    /// The integration lost its hooks, its reader or its root shell.
    IntegrationLost(IntegrationLoss),
    /// The session began closing.
    SessionClosing,
}

/// Why input was discarded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscardReason {
    /// It arrived under an epoch that is no longer current.
    StaleEpoch,
    /// It belonged to a lease that has been taken over or released.
    OldLease,
    /// Its attachment is gone.
    AttachmentRemoved,
    /// The session is closing.
    SessionClosing,
}

/// Why a fence was invalidated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FenceInvalidation {
    /// A root editor was registered.
    EditorEntered,
    /// The reader left.
    EditorLeft,
    /// The input lease changed.
    LeaseChanged,
    /// The reader this fence proved something about was replaced.
    ReaderMoved,
    /// A detach was accepted.
    DetachAccepted,
    /// The fence's own attachment was removed.
    AttachmentRemoved,
    /// The integration lost the ground the fence stood on.
    IntegrationLost,
    /// The session is closing.
    SessionClosing,
}

/// A message that no longer belongs to anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleMessage {
    /// An acknowledgement for an exchange that has ended.
    FenceAcknowledgement,
    /// A refusal for an exchange that has ended.
    FenceRefusal,
    /// A decision for a launch transaction that has ended.
    LaunchDecision,
    /// An acceptance for a launch transaction the worker is not holding.
    ///
    /// The command is in the editor and the transaction it belonged to is over. The worker cannot
    /// un-submit it, so it records the installation rather than discarding the answer.
    LateLaunchInstallation,
    /// A reader event from a reader that is not registered.
    ReaderEvent,
}

/// Why a client's input was refused outright.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputRefusal {
    /// The session is closing and no longer accepts input.
    SessionClosing,
}

/// Why an interrupt was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseFault {
    /// The epoch is not the current one.
    LeaseLost,
    /// The caller does not hold the lease.
    NotHolder,
    /// The session is closing.
    SessionClosing,
}

impl LeaseFault {
    /// Returns the error code the refusal carries.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::LeaseLost | Self::NotHolder => ErrorCode::LeaseLost,
            Self::SessionClosing => ErrorCode::SessionClosed,
        }
    }
}

/// Why a detach was not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetachRejection {
    /// No fence is published, so nothing says whose gesture it was.
    FenceMissing,
    /// The fence named is not the current one, or its prompt or epoch has moved.
    FenceStale,
    /// The session is closing.
    SessionClosing,
}

impl DetachRejection {
    /// Returns the error code the refusal carries.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        match self {
            Self::FenceMissing | Self::FenceStale => ErrorCode::EditorBusy,
            Self::SessionClosing => ErrorCode::SessionClosed,
        }
    }
}

/// What the worker acknowledges a lease change with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseAcknowledgement {
    /// The lease after the change.
    pub lease: LeaseView,
    /// Accepted input that was discarded rather than delivered, which is what the takeover receipt
    /// reports.
    pub discarded_bytes: U64,
    /// The batches behind that count.
    pub discarded_input: Vec<InputRef>,
    /// Whether the reader's own discards are still to come.
    ///
    /// True when this change asked the reader to cancel something. The receipt is completed by
    /// [`Action::CloseTakeoverReceipt`], inside the hold or not at all.
    pub reader_discards_pending: bool,
}

/// Something the worker must do.
///
/// The order inside one [`Outcome`] is the order it must happen in. Two orderings are contractual
/// rather than incidental: a fence is invalidated before a lease change or a detach is
/// acknowledged, and held input is released before the `EDITOR_BUSY` event that explains why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Ask the reader thread to resolve prior input.
    AskFence(RootEditorFenceParams),
    /// Hold this batch until the transition resolves.
    Hold(InputRef),
    /// Write this batch to the terminal now.
    Forward(InputRef),
    /// Release these batches to the terminal, in this order.
    Release(Vec<InputRef>),
    /// Drop these batches without delivering them.
    Discard {
        /// The batches.
        input: Vec<InputRef>,
        /// Why.
        reason: DiscardReason,
    },
    /// Refuse this batch.
    RefuseInput(InputRefusal),
    /// End the reader's pending key wait, keeping its edit buffer.
    CancelNativeOperations(CancelKeyWait),
    /// Publish this fence, and tell the bridge it is live.
    PublishFence(EditorFence),
    /// Tell the bridge no fence was published.
    WithholdFence(WithheldReason),
    /// Drop the current fence.
    InvalidateFence(FenceInvalidation),
    /// Emit the `EDITOR_BUSY` attachment event.
    EmitEditorBusy(EditorBusyEvent),
    /// Acknowledge the lease change.
    AcknowledgeLeaseChange(LeaseAcknowledgement),
    /// Remove this attachment.
    RemoveAttachment(AttachmentId),
    /// Answer the detach.
    AcknowledgeDetach(RootEofDetachResult),
    /// Refuse the detach.
    RejectDetach(DetachRejection),
    /// Put this launch in the reader's mailbox.
    SendLaunch(LaunchMailboxRequest),
    /// Tell the bridge this transaction is over and nothing may be installed for it.
    RevokeLaunch {
        /// The transaction.
        transaction: LaunchTransactionId,
        /// Why it ended.
        reason: LaunchRejectionReason,
    },
    /// Answer the `shell.launch` caller: the command was installed and submitted.
    InstallLaunch(ShellLaunchResult),
    /// Answer the `shell.launch` caller with the refusal. Nothing was installed.
    RejectLaunch {
        /// Why.
        reason: LaunchRejectionReason,
        /// The error code the caller receives.
        code: ErrorCode,
    },
    /// Interrupt the foreground process group with the configured native action.
    Interrupt(InterruptAction),
    /// Refuse the interrupt.
    RefuseInterrupt(LeaseFault),
    /// Record where an accepted line came from.
    RecordAcceptance(AcceptedOrigin),
    /// Complete the takeover receipt for this epoch.
    ///
    /// The lease change is acknowledged the moment it happens, because it stands whatever the
    /// reader says, and its acknowledgement says whether the reader's own discards are still
    /// outstanding. This is where they arrive, exactly once per takeover that asked for a
    /// cancellation: the count when the reader reported it inside the hold, and nothing when the
    /// hold expired first, which the receipt states rather than a zero it cannot stand behind.
    CloseTakeoverReceipt {
        /// The epoch the receipt belongs to.
        epoch: InputLeaseEpoch,
        /// The bytes the reader discarded from its own queues, when it said so in time.
        reader_discards: Option<U64>,
    },
    /// Record a command the reader installed after its transaction had been revoked.
    ///
    /// It proves nothing against the package: the revocation and the install can cross on the wire,
    /// and a cancellation before the hold expired gives the reader no deadline to have missed. What
    /// it does mean is that the editor now holds a command the worker had given up on, which the
    /// session records beside whatever the caller is told.
    LateInstallation(ShellLaunchResult),
    /// Ignore a message that belongs to something that has ended.
    IgnoreStale(StaleMessage),
}

/// One action reduced to what a scenario asserts.
///
/// A fixture states every field the contract decides and leaves out only what it supplied in the
/// same step: the session identifier, and the command of a launch it asked for. Everything a worker
/// would act on, including the whole published fence proof, is asserted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionShape {
    /// [`Action::AskFence`].
    AskFence {
        /// The identity the fence will have if the exchange is acknowledged in time.
        fence_id: FenceId,
        /// The prompt generation the worker is asking about.
        prompt_generation: PromptGeneration,
        /// The reader revision it is asking about.
        reader_revision: ReaderRevision,
        /// The hold.
        deadline_ms: DurationMs,
        /// Why it is asking.
        cause: FenceCause,
    },
    /// [`Action::Hold`].
    Hold(InputRef),
    /// [`Action::Forward`].
    Forward(InputRef),
    /// [`Action::Release`], in order.
    Release(Vec<InputRef>),
    /// [`Action::Discard`].
    Discard {
        /// The batches.
        input: Vec<InputRef>,
        /// Why.
        reason: DiscardReason,
    },
    /// [`Action::RefuseInput`].
    RefuseInput(InputRefusal),
    /// [`Action::CancelNativeOperations`].
    CancelNativeOperations {
        /// Which cancellation this is, in the session's own sequence of them.
        sequence: U64,
        /// The epoch it belongs to.
        epoch: InputLeaseEpoch,
        /// The prompt it is asked for.
        prompt_generation: PromptGeneration,
        /// The reader revision it is asked for.
        reader_revision: ReaderRevision,
    },
    /// [`Action::PublishFence`], with the whole proof.
    PublishFence(EditorFence),
    /// [`Action::WithholdFence`].
    WithholdFence(WithheldReason),
    /// [`Action::InvalidateFence`].
    InvalidateFence(FenceInvalidation),
    /// [`Action::EmitEditorBusy`].
    EmitEditorBusy {
        /// Why the editor could not be fenced.
        reason: EditorBusyReason,
        /// The attachment the event goes to.
        attachment_id: AttachmentId,
        /// The epoch that stands.
        input_epoch: InputLeaseEpoch,
        /// The bytes released in their original order.
        released_input_bytes: U64,
        /// The state the editor is in now.
        state: FenceState,
    },
    /// [`Action::AcknowledgeLeaseChange`].
    AcknowledgeLeaseChange {
        /// The lease after the change.
        lease: LeaseView,
        /// Accepted input that was discarded rather than delivered.
        discarded_bytes: U64,
        /// The batches behind that count.
        discarded_input: Vec<InputRef>,
        /// Whether the reader's own discards are still outstanding.
        reader_discards_pending: bool,
    },
    /// [`Action::RemoveAttachment`].
    RemoveAttachment(AttachmentId),
    /// [`Action::AcknowledgeDetach`].
    AcknowledgeDetach {
        /// The attachment that went away.
        detached_attachment: AttachmentId,
        /// The state afterwards.
        state: FenceState,
        /// Its undelivered bytes that were discarded.
        discarded_input_bytes: U64,
    },
    /// [`Action::RejectDetach`].
    RejectDetach(DetachRejection),
    /// [`Action::SendLaunch`].
    SendLaunch {
        /// The transaction.
        transaction: LaunchTransactionId,
        /// What the reader is to install, exactly as the caller named it.
        command: LaunchCommand,
        /// The fence reserved for it.
        fence_id: FenceId,
        /// The prompt generation the caller expects.
        expected_prompt_generation: PromptGeneration,
        /// The buffer revision it expects.
        expected_buffer_revision: EditorBufferRevision,
        /// The working-directory revision the worker recorded.
        expected_cwd_revision: CwdRevision,
        /// The reader's deadline.
        deadline_ms: DurationMs,
    },
    /// [`Action::RevokeLaunch`].
    RevokeLaunch {
        /// The transaction.
        transaction: LaunchTransactionId,
        /// Why it ended.
        reason: LaunchRejectionReason,
    },
    /// [`Action::InstallLaunch`].
    InstallLaunch {
        /// The fence it was installed under.
        fence_id: FenceId,
        /// The prompt generation at acceptance.
        prompt_generation: PromptGeneration,
        /// The buffer revision after the install.
        buffer_revision: EditorBufferRevision,
    },
    /// [`Action::RejectLaunch`].
    RejectLaunch {
        /// Why.
        reason: LaunchRejectionReason,
        /// The error code the caller receives.
        code: ErrorCode,
    },
    /// [`Action::Interrupt`].
    Interrupt(InterruptAction),
    /// [`Action::RefuseInterrupt`].
    RefuseInterrupt(LeaseFault),
    /// [`Action::RecordAcceptance`].
    RecordAcceptance(AcceptedOrigin),
    /// [`Action::CloseTakeoverReceipt`].
    CloseTakeoverReceipt {
        /// The epoch the receipt belongs to.
        epoch: InputLeaseEpoch,
        /// The reader's own discards, when it said so in time.
        reader_discards: Option<U64>,
    },
    /// [`Action::LateInstallation`].
    LateInstallation {
        /// The fence it was installed under.
        fence_id: FenceId,
        /// The prompt generation it was installed at.
        prompt_generation: PromptGeneration,
    },
    /// [`Action::IgnoreStale`].
    IgnoreStale(StaleMessage),
}

impl Action {
    /// Reduces this action to what a scenario asserts.
    #[must_use]
    pub fn shape(&self) -> ActionShape {
        match self {
            Self::AskFence(params) => ActionShape::AskFence {
                fence_id: params.fence_id,
                prompt_generation: params.prompt_generation,
                reader_revision: params.reader_revision,
                deadline_ms: params.deadline_ms,
                cause: params.cause,
            },
            Self::Hold(input) => ActionShape::Hold(input.clone()),
            Self::Forward(input) => ActionShape::Forward(input.clone()),
            Self::Release(input) => ActionShape::Release(input.clone()),
            Self::Discard { input, reason } => ActionShape::Discard {
                input: input.clone(),
                reason: *reason,
            },
            Self::RefuseInput(refusal) => ActionShape::RefuseInput(*refusal),
            Self::CancelNativeOperations(cancel) => ActionShape::CancelNativeOperations {
                sequence: cancel.sequence,
                epoch: cancel.epoch,
                prompt_generation: cancel.prompt_generation,
                reader_revision: cancel.reader_revision,
            },
            Self::PublishFence(fence) => ActionShape::PublishFence(fence.clone()),
            Self::WithholdFence(reason) => ActionShape::WithholdFence(*reason),
            Self::InvalidateFence(reason) => ActionShape::InvalidateFence(*reason),
            Self::EmitEditorBusy(event) => ActionShape::EmitEditorBusy {
                reason: event.reason,
                attachment_id: event.attachment_id,
                input_epoch: event.input_epoch,
                released_input_bytes: event.released_input_bytes,
                state: event.state,
            },
            Self::AcknowledgeLeaseChange(acknowledgement) => ActionShape::AcknowledgeLeaseChange {
                lease: acknowledgement.lease,
                discarded_bytes: acknowledgement.discarded_bytes,
                discarded_input: acknowledgement.discarded_input.clone(),
                reader_discards_pending: acknowledgement.reader_discards_pending,
            },
            Self::RemoveAttachment(attachment) => ActionShape::RemoveAttachment(*attachment),
            Self::AcknowledgeDetach(result) => ActionShape::AcknowledgeDetach {
                detached_attachment: result.detached_attachment,
                state: result.state,
                discarded_input_bytes: result.discarded_input_bytes,
            },
            Self::RejectDetach(rejection) => ActionShape::RejectDetach(*rejection),
            Self::SendLaunch(request) => ActionShape::SendLaunch {
                transaction: request.transaction,
                command: request.command.clone(),
                fence_id: request.fence_id,
                expected_prompt_generation: request.expected_prompt_generation,
                expected_buffer_revision: request.expected_buffer_revision,
                expected_cwd_revision: request.expected_cwd_revision,
                deadline_ms: request.deadline_ms,
            },
            Self::RevokeLaunch {
                transaction,
                reason,
            } => ActionShape::RevokeLaunch {
                transaction: *transaction,
                reason: *reason,
            },
            Self::InstallLaunch(result) => ActionShape::InstallLaunch {
                fence_id: result.fence_id,
                prompt_generation: result.prompt_generation,
                buffer_revision: result.buffer_revision,
            },
            Self::RejectLaunch { reason, code } => ActionShape::RejectLaunch {
                reason: *reason,
                code: *code,
            },
            Self::Interrupt(action) => ActionShape::Interrupt(*action),
            Self::RefuseInterrupt(fault) => ActionShape::RefuseInterrupt(*fault),
            Self::RecordAcceptance(origin) => ActionShape::RecordAcceptance(origin.clone()),
            Self::CloseTakeoverReceipt {
                epoch,
                reader_discards,
            } => ActionShape::CloseTakeoverReceipt {
                epoch: *epoch,
                reader_discards: *reader_discards,
            },
            Self::LateInstallation(result) => ActionShape::LateInstallation {
                fence_id: result.fence_id,
                prompt_generation: result.prompt_generation,
            },
            Self::IgnoreStale(message) => ActionShape::IgnoreStale(*message),
        }
    }
}

/// What one stimulus produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    /// The state afterwards.
    pub state: FenceState,
    /// The fence afterwards, when one is valid.
    pub fence: Option<FenceId>,
    /// The batches still held, in arrival order.
    pub held: Vec<InputRef>,
    /// What the worker must do, in order.
    pub actions: Vec<Action>,
}

impl Outcome {
    /// Returns the actions reduced to what a scenario asserts.
    #[must_use]
    pub fn shapes(&self) -> Vec<ActionShape> {
        self.actions.iter().map(Action::shape).collect()
    }
}

/// Why an unqualified `kr detach` cannot pick a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbiguityReason {
    /// No line has been accepted through a fenced context, so there is no recorded origin.
    NoAcceptedCommand,
    /// The accepted line's input came from more than one attachment or epoch.
    MixedContext,
    /// There was no valid fence when the line was accepted.
    Unverifiable,
}

/// What `kr detach` without an attachment identifier resolves to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetachTarget {
    /// The recorded origin of the accepted line.
    Attachment(AttachmentId),
    /// Nothing that can be named, so the caller must name one.
    Ambiguous(AmbiguityReason),
}

impl DetachTarget {
    /// Returns the error code an ambiguous target is reported with.
    #[must_use]
    pub const fn code(self) -> Option<ErrorCode> {
        match self {
            Self::Attachment(_) => None,
            Self::Ambiguous(_) => Some(ErrorCode::AmbiguousAttachment),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RegisteredEditor {
    root_process: ProcessStartIdentity,
    prompt_generation: PromptGeneration,
    reader_revision: ReaderRevision,
    reader_context: ReaderContext,
    cwd_revision: CwdRevision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Exchange {
    fence_id: FenceId,
    deadline: ContinuousMs,
    attachment_id: AttachmentId,
    epoch: InputLeaseEpoch,
    prompt_generation: PromptGeneration,
    reader_revision: ReaderRevision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Held {
    input: InputRef,
    attachment_id: AttachmentId,
    epoch: InputLeaseEpoch,
    bytes: U64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LaunchTransaction {
    transaction: LaunchTransactionId,
    fence_id: FenceId,
    deadline: ContinuousMs,
    requester: AttachmentId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InstalledLaunch {
    prompt_generation: PromptGeneration,
    requester: AttachmentId,
}

/// The worker's side of the root-editor contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FenceMachine {
    session_id: SessionId,
    state: FenceState,
    editor: Option<RegisteredEditor>,
    fence: Option<EditorFence>,
    exchange: Option<Exchange>,
    launch: Option<LaunchTransaction>,
    installed: Option<InstalledLaunch>,
    hold: Vec<Held>,
    /// The moment the current hold must end, carried across a reader that replaces another inside
    /// it. The hold belongs to the input, not to the reader, so a replacement does not restart it.
    hold_deadline: Option<ContinuousMs>,
    /// The cancellation the worker is waiting on, by its own sequence number.
    cancellation: Option<U64>,
    /// How many cancellations this session has asked for.
    cancellations: u64,
    /// The takeover receipt a lease change left open, and when it is completed whatever the reader
    /// says. A departure cancels the reader's wait too, and opens no receipt: nothing asked for a
    /// takeover.
    receipt: Option<(U64, InputLeaseEpoch)>,
    receipt_deadline: Option<ContinuousMs>,
    /// Every dispatched transaction whose caller is still waiting for the reader to say what it did.
    ///
    /// More than one can be outstanding: a transaction that timed out is still unresolved when the
    /// next is reserved, and losing the first's result would leave a caller with no answer at all
    /// about a command that may be in the editor.
    awaiting_confirmation: Vec<LaunchTransaction>,
    lease: LeaseView,
    acceptance: Option<AcceptedOrigin>,
}

impl FenceMachine {
    /// Builds a machine outside any root editor.
    #[must_use]
    pub const fn new(session_id: SessionId, lease: LeaseView) -> Self {
        Self {
            session_id,
            state: FenceState::Outside,
            editor: None,
            fence: None,
            exchange: None,
            launch: None,
            installed: None,
            hold: Vec::new(),
            hold_deadline: None,
            cancellation: None,
            cancellations: 0,
            receipt: None,
            receipt_deadline: None,
            awaiting_confirmation: Vec::new(),
            lease,
            acceptance: None,
        }
    }

    /// Returns the current state.
    #[must_use]
    pub const fn state(&self) -> FenceState {
        self.state
    }

    /// Returns the current fence.
    #[must_use]
    pub const fn fence(&self) -> Option<&EditorFence> {
        self.fence.as_ref()
    }

    /// Returns the batches still held, in arrival order.
    #[must_use]
    pub fn held(&self) -> Vec<InputRef> {
        self.hold.iter().map(|held| held.input.clone()).collect()
    }

    /// Returns the moment the driver must call [`Stimulus::HoldExpired`] at.
    #[must_use]
    pub fn deadline(&self) -> Option<ContinuousMs> {
        let fence = self.exchange.as_ref().map(|exchange| exchange.deadline);
        let launch = self.launch.as_ref().map(|launch| launch.deadline);
        [fence, launch, self.receipt_deadline]
            .into_iter()
            .flatten()
            .min()
    }

    /// Returns what `kr detach` without an attachment identifier targets.
    ///
    /// It is the origin recorded when the line was accepted, never whichever client holds the lease
    /// when the child command later starts.
    #[must_use]
    pub fn detach_target(&self) -> DetachTarget {
        match &self.acceptance {
            None => DetachTarget::Ambiguous(AmbiguityReason::NoAcceptedCommand),
            Some(AcceptedOrigin::Mixed) => DetachTarget::Ambiguous(AmbiguityReason::MixedContext),
            Some(AcceptedOrigin::Unverifiable) => {
                DetachTarget::Ambiguous(AmbiguityReason::Unverifiable)
            }
            Some(AcceptedOrigin::Fenced { attachment_id, .. }) => {
                DetachTarget::Attachment(*attachment_id)
            }
        }
    }

    /// Applies one stimulus at one clock reading.
    ///
    /// Every entry point sweeps the hold first. A deadline is a fact about the clock, not about
    /// which message happens to arrive next, so an acknowledgement or a launch answer that reaches
    /// the worker after its hold expired finds the hold already released and publishes nothing.
    pub fn apply(&mut self, at: ContinuousMs, stimulus: &Stimulus) -> Outcome {
        let mut actions = Vec::new();
        // A stimulus that discards the held input itself keeps it through the sweep: releasing it
        // here and discarding it there would deliver a client's keystrokes on the way to throwing
        // them away.
        let discards_hold = matches!(
            stimulus,
            Stimulus::AttachmentRemoved(_)
                | Stimulus::DetachSubmitted(_)
                | Stimulus::LeaseChanged(_)
                | Stimulus::SessionClosing
        );
        self.expire_keeping(at, discards_hold, &mut actions);
        match stimulus {
            Stimulus::EditorEntered(entered) => self.editor_entered(at, entered, &mut actions),
            Stimulus::EditorLeft(left) => self.editor_left(left, &mut actions),
            Stimulus::LeaseChanged(changed) => self.lease_changed(at, changed, &mut actions),
            Stimulus::FenceAcknowledged(ack) => self.fence_acknowledged(ack, &mut actions),
            Stimulus::FenceRefused(refusal) => self.fence_refused(refusal, &mut actions),
            Stimulus::CancellationReported(report) => {
                self.cancellation_reported(report, &mut actions);
            }
            Stimulus::ReaderIdled(idled) => self.reader_idled(at, idled, &mut actions),
            Stimulus::InputArrived(arrival) => self.input_arrived(arrival, &mut actions),
            Stimulus::InterruptRequested(request) => {
                self.interrupt_requested(request, &mut actions)
            }
            Stimulus::AttachmentRemoved(attachment) => {
                self.attachment_removed(at, *attachment, &mut actions);
            }
            Stimulus::DetachSubmitted(params) => self.detach_submitted(at, params, &mut actions),
            Stimulus::LaunchRequested(request) => self.launch_requested(at, request, &mut actions),
            Stimulus::LaunchDecided(decision) => self.launch_decided(decision, &mut actions),
            Stimulus::CommandAccepted(params) => self.command_accepted(params, &mut actions),
            Stimulus::IntegrationLost(loss) => self.integration_lost(*loss, &mut actions),
            // The sweep above has already done it.
            Stimulus::HoldExpired => {}
            Stimulus::SessionClosing => self.session_closing(&mut actions),
        }
        Outcome {
            state: self.state,
            fence: self.fence.as_ref().map(|fence| fence.fence_id),
            held: self.held(),
            actions,
        }
    }

    fn editor_entered(
        &mut self,
        at: ContinuousMs,
        entered: &EditorEntered,
        actions: &mut Vec<Action>,
    ) {
        if self.state == FenceState::Closing {
            actions.push(Action::IgnoreStale(StaleMessage::ReaderEvent));
            return;
        }
        self.cancel_launch(LaunchRejectionReason::EditorLeft, actions);
        self.invalidate_fence(FenceInvalidation::EditorEntered, actions);
        if self.exchange.take().is_some() {
            // The exchange the previous reader was to answer dies with it. The hold stays: a retry
            // waits for the mixed queues to drain rather than discarding what a client typed.
            actions.push(Action::WithholdFence(WithheldReason::ReaderMoved));
        }
        self.editor = Some(RegisteredEditor {
            root_process: entered.params.root_process.clone(),
            prompt_generation: entered.params.prompt_generation,
            reader_revision: entered.params.reader_revision,
            reader_context: entered.params.reader_context,
            cwd_revision: entered.params.cwd_revision,
        });
        if self.installed.is_some_and(|installed| {
            installed.prompt_generation != entered.params.prompt_generation
        }) {
            self.installed = None;
        }
        self.state = FenceState::Unfenced;
        self.start_exchange(
            at,
            entered.candidate_fence,
            FenceCause::EditorEntry,
            actions,
        );
    }

    fn editor_left(&mut self, left: &RootEditorLeaveParams, actions: &mut Vec<Action>) {
        if self.state == FenceState::Closing {
            actions.push(Action::IgnoreStale(StaleMessage::ReaderEvent));
            return;
        }
        let Some(editor) = self.editor.clone() else {
            actions.push(Action::IgnoreStale(StaleMessage::ReaderEvent));
            return;
        };
        if (left.prompt_generation, left.reader_revision)
            < (editor.prompt_generation, editor.reader_revision)
        {
            // A leave from a reader this one has already replaced. Acting on it would deregister
            // the reader that is running now.
            actions.push(Action::IgnoreStale(StaleMessage::ReaderEvent));
            return;
        }
        self.cancel_launch(LaunchRejectionReason::EditorLeft, actions);
        self.invalidate_fence(FenceInvalidation::EditorLeft, actions);
        if self.exchange.take().is_some() {
            actions.push(Action::WithholdFence(WithheldReason::EditorLeft));
        }
        // The reader that was to answer is gone, so there is nothing left to wait for, whether the
        // hold began for a fence exchange or for a launch. Outside a registered root editor input
        // does not wait for a fence: the batches go to whatever is reading the terminal now, in the
        // order they arrived, and no EDITOR_BUSY event is owed because nothing is busy.
        self.release_hold(actions);
        self.editor = None;
        self.installed = None;
        self.state = FenceState::Outside;
    }

    fn lease_changed(
        &mut self,
        at: ContinuousMs,
        changed: &LeaseChanged,
        actions: &mut Vec<Action>,
    ) {
        if self.state == FenceState::Closing {
            actions.push(Action::RefuseInput(InputRefusal::SessionClosing));
            return;
        }
        let previous = self.lease;
        self.lease = changed.lease;
        if self.editor.is_none() {
            // Outside a registered root editor the lease changes and input forwards immediately: an
            // application does not have a reader bridge to ask.
            self.state = FenceState::Outside;
            let discarded = self.take_hold_of_epoch(previous.epoch);
            self.acknowledge_lease_change(changed, discarded, actions);
            return;
        }
        self.cancel_launch(LaunchRejectionReason::LeaseChanged, actions);
        self.invalidate_fence(FenceInvalidation::LeaseChanged, actions);
        if self.exchange.take().is_some() {
            actions.push(Action::WithholdFence(WithheldReason::LeaseChanged));
        }
        if previous.holder.is_some() {
            // A takeover or a release can leave the reader waiting for the rest of a sequence that
            // will never arrive: a partial escape sequence, a quoted insertion, a vi motion, an
            // incomplete chord or a macro. The cancellation ends the wait and keeps the buffer.
            self.cancel_native_operations(at, true, actions);
        }
        let discarded = self.take_hold_of_epoch(previous.epoch);
        self.state = FenceState::Unfenced;
        self.acknowledge_lease_change(changed, discarded, actions);
        self.start_exchange(
            at,
            changed.candidate_fence,
            FenceCause::LeaseChange,
            actions,
        );
    }

    fn acknowledge_lease_change(
        &mut self,
        changed: &LeaseChanged,
        discarded: Vec<Held>,
        actions: &mut Vec<Action>,
    ) {
        let held_bytes: u64 = discarded.iter().map(|held| held.bytes.get()).sum();
        let discarded_input = refs(&discarded);
        if !discarded_input.is_empty() {
            actions.push(Action::Discard {
                input: discarded_input.clone(),
                reason: DiscardReason::OldLease,
            });
        }
        actions.push(Action::AcknowledgeLeaseChange(LeaseAcknowledgement {
            lease: changed.lease,
            discarded_bytes: U64::new(changed.discarded_bytes.get().saturating_add(held_bytes)),
            discarded_input,
            reader_discards_pending: self
                .receipt
                .is_some_and(|(_, epoch)| epoch == changed.lease.epoch),
        }));
    }

    fn fence_acknowledged(&mut self, ack: &FenceAcknowledgement, actions: &mut Vec<Action>) {
        let Some(exchange) = self.exchange.clone() else {
            // The exchange this answers has already ended, at its deadline or because what it was
            // to name went away. The bridge was told so when it ended, and publishing from this
            // would be a fence nobody held input for.
            actions.push(Action::IgnoreStale(StaleMessage::FenceAcknowledgement));
            return;
        };
        if ack.fence_id != exchange.fence_id {
            actions.push(Action::IgnoreStale(StaleMessage::FenceAcknowledgement));
            return;
        }
        self.exchange = None;
        let Some(editor) = self.editor.clone() else {
            // The reader left while its answer was in flight. Outside a registered root editor no
            // fence is needed and none can be published.
            actions.push(Action::WithholdFence(WithheldReason::EditorLeft));
            self.release_hold(actions);
            return;
        };
        if ack.prompt_generation != exchange.prompt_generation
            || ack.reader_revision != exchange.reader_revision
        {
            self.withhold(WithheldReason::ReaderMoved, actions);
            return;
        }
        if !ack.queues.all_drained() || !ack.snapshot.is_drained() {
            // A retry never discards the mixed queues; it waits for them to drain.
            self.withhold(WithheldReason::QueuesNotDrained, actions);
            return;
        }
        let fence = EditorFence {
            fence_id: exchange.fence_id,
            root_process: editor.root_process.clone(),
            prompt_generation: ack.prompt_generation,
            reader_revision: ack.reader_revision,
            input_epoch: exchange.epoch,
            originating_attachment: exchange.attachment_id,
        };
        if let Some(registered) = &mut self.editor {
            registered.reader_context = ack.reader_context;
            // The reader has just told the worker where the shell is. A launch reserved after this
            // expects that revision, not the one entry recorded.
            registered.cwd_revision = ack.cwd_revision;
        }
        self.fence = Some(fence.clone());
        self.state = FenceState::Fenced;
        actions.push(Action::PublishFence(fence));
        self.release_hold(actions);
    }

    fn fence_refused(&mut self, refusal: &FenceRefusal, actions: &mut Vec<Action>) {
        let Some(exchange) = self.exchange.clone() else {
            actions.push(Action::IgnoreStale(StaleMessage::FenceRefusal));
            return;
        };
        if refusal.fence_id != exchange.fence_id {
            actions.push(Action::IgnoreStale(StaleMessage::FenceRefusal));
            return;
        }
        self.exchange = None;
        self.withhold(WithheldReason::Refused, actions);
    }

    fn cancellation_reported(&mut self, report: &CancellationReport, actions: &mut Vec<Action>) {
        let asked = self.cancellation == Some(report.sequence);
        if !asked {
            // A report for a cancellation the worker is not waiting on. The sequence is what tells
            // one from the next: a takeover and a departure can both cancel at one prompt in one
            // reader, and a departure can happen at the epoch a takeover just produced.
            actions.push(Action::IgnoreStale(StaleMessage::ReaderEvent));
            return;
        }
        self.cancellation = None;
        if self.receipt == Some((report.sequence, report.epoch)) {
            // What the reader discarded from its own queues completes the takeover receipt this
            // cancellation was holding open.
            self.close_takeover_receipt(Some(report.discarded_bytes), actions);
        }
        if report.buffer_preserved {
            // The transition is otherwise unaffected: the fence still waits for the acknowledged
            // drain.
            return;
        }
        // A cancellation that could only end the key wait by destroying what the person had typed
        // is not the non-destructive path this contract requires. The reader's state is no longer
        // one the worker can attribute input through, so the fence is withheld rather than
        // published over it.
        if self.exchange.take().is_some() {
            self.withhold(WithheldReason::Refused, actions);
        }
    }

    fn reader_idled(&mut self, at: ContinuousMs, idled: &ReaderIdled, actions: &mut Vec<Action>) {
        if self.editor.is_none() || self.state == FenceState::Closing {
            actions.push(Action::IgnoreStale(StaleMessage::ReaderEvent));
            return;
        }
        if self.editor.as_ref().is_some_and(|editor| {
            (idled.idle.prompt_generation, idled.idle.reader_revision)
                < (editor.prompt_generation, editor.reader_revision)
        }) {
            // An idle report from a reader this one has already replaced. Acting on it would
            // deregister what is running now and cancel its exchange.
            actions.push(Action::IgnoreStale(StaleMessage::ReaderEvent));
            return;
        }
        let moved = self.editor.as_ref().is_some_and(|editor| {
            editor.prompt_generation != idled.idle.prompt_generation
                || editor.reader_revision != idled.idle.reader_revision
        });
        if let Some(editor) = &mut self.editor {
            editor.prompt_generation = idled.idle.prompt_generation;
            editor.reader_revision = idled.idle.reader_revision;
            editor.reader_context = idled.idle.reader_context;
            editor.cwd_revision = idled.idle.cwd_revision;
        }
        if moved {
            // The reader this fence proved something about is not the one running now. Whatever the
            // fence said about who owns its input is no longer true of it.
            self.cancel_launch(LaunchRejectionReason::FenceInvalid, actions);
            self.invalidate_fence(FenceInvalidation::ReaderMoved, actions);
            if self.exchange.take().is_some() {
                actions.push(Action::WithholdFence(WithheldReason::ReaderMoved));
            }
            self.state = FenceState::Unfenced;
        }
        if self.state != FenceState::Unfenced || self.exchange.is_some() {
            return;
        }
        self.start_exchange(at, idled.candidate_fence, FenceCause::Retry, actions);
    }

    fn input_arrived(&mut self, arrival: &InputArrived, actions: &mut Vec<Action>) {
        if self.state == FenceState::Closing {
            actions.push(Action::RefuseInput(InputRefusal::SessionClosing));
            return;
        }
        if arrival.epoch != self.lease.epoch {
            actions.push(Action::Discard {
                input: vec![arrival.input.clone()],
                reason: DiscardReason::StaleEpoch,
            });
            return;
        }
        if self.lease.holder != Some(arrival.attachment_id) {
            // The epoch is current but its holder is not this attachment: it has been removed or
            // detached and the worker has not advanced the epoch yet. Its keystrokes go nowhere.
            actions.push(Action::Discard {
                input: vec![arrival.input.clone()],
                reason: DiscardReason::OldLease,
            });
            return;
        }
        if self.exchange.is_some() || self.launch.is_some() {
            self.hold.push(Held {
                input: arrival.input.clone(),
                attachment_id: arrival.attachment_id,
                epoch: arrival.epoch,
                bytes: arrival.bytes,
            });
            actions.push(Action::Hold(arrival.input.clone()));
            return;
        }
        actions.push(Action::Forward(arrival.input.clone()));
    }

    fn interrupt_requested(&mut self, request: &InterruptRequested, actions: &mut Vec<Action>) {
        // An interrupt bypasses the reader-transition hold: it is how a person stops a program that
        // is not reading, and a held interrupt would be no interrupt at all.
        if self.state == FenceState::Closing {
            actions.push(Action::RefuseInterrupt(LeaseFault::SessionClosing));
            return;
        }
        if request.epoch != self.lease.epoch {
            actions.push(Action::RefuseInterrupt(LeaseFault::LeaseLost));
            return;
        }
        if self.lease.holder != Some(request.attachment_id) {
            actions.push(Action::RefuseInterrupt(LeaseFault::NotHolder));
            return;
        }
        actions.push(Action::Interrupt(request.action));
    }

    fn attachment_removed(
        &mut self,
        at: ContinuousMs,
        attachment: AttachmentId,
        actions: &mut Vec<Action>,
    ) {
        let discarded = self.take_hold_of_attachment(attachment);
        if !discarded.is_empty() {
            actions.push(Action::Discard {
                input: refs(&discarded),
                reason: DiscardReason::AttachmentRemoved,
            });
        }
        if self
            .exchange
            .as_ref()
            .is_some_and(|exchange| exchange.attachment_id == attachment)
        {
            // The exchange was to name this attachment as the fence's one origin. There is no
            // origin left, so the exchange goes with it rather than publishing a fence for an
            // attachment that is gone.
            self.exchange = None;
            actions.push(Action::WithholdFence(WithheldReason::LeaseChanged));
        }
        if self
            .fence
            .as_ref()
            .is_some_and(|fence| fence.originating_attachment == attachment)
        {
            self.cancel_launch(LaunchRejectionReason::FenceInvalid, actions);
            self.invalidate_fence(FenceInvalidation::AttachmentRemoved, actions);
            if self.state != FenceState::Closing {
                self.state = FenceState::Unfenced;
            }
        }
        if self.lease.holder == Some(attachment) {
            // Its lease went with it. The worker's own lease change follows and advances the epoch;
            // until it does, nothing here may treat the removed attachment as a holder. Whatever it
            // left the reader waiting for can never be completed, so that wait ends too.
            self.lease.holder = None;
            self.cancel_native_operations(at, false, actions);
        }
        self.release_hold_for_departure(actions);
    }

    fn cancel_native_operations(
        &mut self,
        at: ContinuousMs,
        opens_receipt: bool,
        actions: &mut Vec<Action>,
    ) {
        let Some(editor) = self.editor.clone() else {
            return;
        };
        self.cancellations += 1;
        let sequence = U64::new(self.cancellations);
        // One cancellation is outstanding at a time, and it is matched on its own sequence: a
        // takeover and a departure can both cancel at one prompt in one reader.
        self.cancellation = Some(sequence);
        if opens_receipt {
            // Only a takeover has a receipt to fill. It is completed inside the hold or not at all,
            // so a reader that never answers cannot leave one open for the life of the session.
            self.close_takeover_receipt(None, actions);
            self.receipt = Some((sequence, self.lease.epoch));
            self.receipt_deadline = Some(at.plus(FENCE_EXCHANGE_TIMEOUT.get()));
        } else {
            // A departure supersedes the takeover's cancellation, so the answer that would have
            // filled its receipt can no longer be told from this one's.
            self.close_takeover_receipt(None, actions);
        }
        actions.push(Action::CancelNativeOperations(CancelKeyWait {
            session_id: self.session_id,
            sequence,
            epoch: self.lease.epoch,
            prompt_generation: editor.prompt_generation,
            reader_revision: editor.reader_revision,
        }));
    }

    /// Releases a hold that nothing can resolve any more.
    ///
    /// A hold exists only while an exchange or a launch is in flight. When the last of them has
    /// gone, whatever is held goes to the terminal in the order it arrived.
    fn release_hold_for_departure(&mut self, actions: &mut Vec<Action>) {
        if self.exchange.is_none() && self.launch.is_none() {
            self.release_hold(actions);
        }
    }

    fn detach_submitted(
        &mut self,
        at: ContinuousMs,
        params: &RootEofDetachParams,
        actions: &mut Vec<Action>,
    ) {
        if self.state == FenceState::Closing {
            actions.push(Action::RejectDetach(DetachRejection::SessionClosing));
            return;
        }
        let Some(fence) = self.fence.clone() else {
            actions.push(Action::RejectDetach(DetachRejection::FenceMissing));
            // The sweep kept the hold for a detach that would have discarded it. This one does not,
            // so whatever an expired hold was keeping goes to the terminal in order.
            self.release_hold_for_departure(actions);
            return;
        };
        if params.fence_id != fence.fence_id
            || params.prompt_generation != fence.prompt_generation
            || params.input_epoch != fence.input_epoch
            || fence.input_epoch != self.lease.epoch
        {
            actions.push(Action::RejectDetach(DetachRejection::FenceStale));
            self.release_hold_for_departure(actions);
            return;
        }
        let attachment = fence.originating_attachment;
        // A launch holding this fence loses it: the attachment the fence names is going away, so
        // there is nothing left for the transaction to be installed under. The caller is told, and
        // the reader is told to install nothing.
        self.cancel_launch(LaunchRejectionReason::FenceInvalid, actions);
        let discarded = self.take_hold_of_attachment(attachment);
        let discarded_bytes = U64::new(discarded.iter().map(|held| held.bytes.get()).sum());
        // The fence is invalidated before the detach is acknowledged, so nothing can quote it
        // afterwards, and the removed attachment's undelivered input goes with it.
        self.invalidate_fence(FenceInvalidation::DetachAccepted, actions);
        if !discarded.is_empty() {
            actions.push(Action::Discard {
                input: refs(&discarded),
                reason: DiscardReason::AttachmentRemoved,
            });
        }
        self.state = FenceState::Unfenced;
        if self.lease.holder == Some(attachment) {
            // The detached attachment's lease goes with it, so nothing here treats it as a holder
            // again. The worker's own lease change follows and advances the epoch. Whatever the
            // departing client left the reader waiting for can never be completed either, so the
            // wait ends here rather than hanging until somebody else types.
            self.lease.holder = None;
            self.cancel_native_operations(at, false, actions);
        }
        self.installed = None;
        actions.push(Action::RemoveAttachment(attachment));
        actions.push(Action::AcknowledgeDetach(RootEofDetachResult {
            detached_attachment: attachment,
            state: self.state,
            discarded_input_bytes: discarded_bytes,
        }));
        self.release_hold_for_departure(actions);
    }

    fn launch_requested(
        &mut self,
        at: ContinuousMs,
        request: &LaunchRequested,
        actions: &mut Vec<Action>,
    ) {
        if self.state == FenceState::Closing {
            refuse_launch(LaunchRejectionReason::SessionClosing, actions);
            return;
        }
        if self.state != FenceState::Fenced {
            // Nothing is installed anywhere else: outside a fenced root editor the worker has no
            // proof that the shell, rather than an application, is the thing reading.
            refuse_launch(LaunchRejectionReason::FenceInvalid, actions);
            return;
        }
        let Some(fence) = self.fence.clone() else {
            refuse_launch(LaunchRejectionReason::FenceInvalid, actions);
            return;
        };
        let Some(editor) = self.editor.clone() else {
            refuse_launch(LaunchRejectionReason::FenceInvalid, actions);
            return;
        };
        if !editor.reader_context.is_primary() {
            // A launch belongs at the primary prompt. A continuation line and the `read` builtin
            // are somebody's unfinished input, not a place to install a command.
            refuse_launch(LaunchRejectionReason::NotPrimaryReader, actions);
            return;
        }
        if request.params.expected_prompt_generation != fence.prompt_generation {
            refuse_launch(LaunchRejectionReason::PromptGenerationMismatch, actions);
            return;
        }
        let deadline = at.plus(FENCE_EXCHANGE_TIMEOUT.get());
        self.hold_deadline = Some(deadline);
        self.launch = Some(LaunchTransaction {
            transaction: request.transaction,
            fence_id: fence.fence_id,
            deadline,
            requester: request.requester,
        });
        self.state = FenceState::LaunchReserved;
        actions.push(Action::SendLaunch(LaunchMailboxRequest {
            session_id: self.session_id,
            transaction: request.transaction,
            fence_id: fence.fence_id,
            command: request.params.command.clone(),
            expected_prompt_generation: request.params.expected_prompt_generation,
            expected_buffer_revision: request.params.expected_buffer_revision,
            expected_cwd_revision: editor.cwd_revision,
            // The reader's own budget, which ends before the worker gives up. What is left of it
            // rather than the whole of it, so a worker that has already spent part of its hold
            // shortens the reader's window and never extends it.
            deadline_ms: DurationMs::new(
                LAUNCH_READER_BUDGET
                    .get()
                    .min(deadline.get().saturating_sub(at.get())),
            ),
        }));
    }

    fn launch_decided(&mut self, decision: &LaunchDecision, actions: &mut Vec<Action>) {
        if let Some(index) = self
            .awaiting_confirmation
            .iter()
            .position(|awaited| awaited.transaction == decision.transaction())
        {
            // The confirmation this caller's answer was waiting for.
            let awaited = self.awaiting_confirmation.remove(index);
            match decision {
                LaunchDecision::Accepted(accepted) => {
                    // The reader installed it before it saw the revocation. The command is in the
                    // editor, so the caller is told what happened rather than told it failed, and
                    // the session records the installation.
                    self.installed = Some(InstalledLaunch {
                        prompt_generation: accepted.prompt_generation,
                        requester: awaited.requester,
                    });
                    actions.push(Action::LateInstallation(ShellLaunchResult {
                        fence_id: accepted.fence_id,
                        prompt_generation: accepted.prompt_generation,
                        buffer_revision: accepted.buffer_revision,
                    }));
                    actions.push(Action::InstallLaunch(ShellLaunchResult {
                        fence_id: accepted.fence_id,
                        prompt_generation: accepted.prompt_generation,
                        buffer_revision: accepted.buffer_revision,
                    }));
                }
                LaunchDecision::Rejected(rejected) => refuse_launch(rejected.reason, actions),
            }
            return;
        }
        let Some(live) = self.launch.clone() else {
            // Nobody is waiting for this one: neither a live transaction nor a revoked one. A
            // rejection for it is nothing. An acceptance means the editor holds a command whose
            // transaction is over, which the session records rather than discards; it says nothing
            // about the package, because the answer may simply have crossed the revocation.
            match decision {
                LaunchDecision::Accepted(accepted) => {
                    actions.push(Action::LateInstallation(ShellLaunchResult {
                        fence_id: accepted.fence_id,
                        prompt_generation: accepted.prompt_generation,
                        buffer_revision: accepted.buffer_revision,
                    }));
                    actions.push(Action::IgnoreStale(StaleMessage::LateLaunchInstallation));
                }
                LaunchDecision::Rejected(_) => {
                    actions.push(Action::IgnoreStale(StaleMessage::LaunchDecision));
                }
            }
            return;
        };
        if decision.transaction() != live.transaction {
            let message = match decision {
                LaunchDecision::Accepted(_) => StaleMessage::LateLaunchInstallation,
                LaunchDecision::Rejected(_) => StaleMessage::LaunchDecision,
            };
            if let LaunchDecision::Accepted(accepted) = decision {
                actions.push(Action::LateInstallation(ShellLaunchResult {
                    fence_id: accepted.fence_id,
                    prompt_generation: accepted.prompt_generation,
                    buffer_revision: accepted.buffer_revision,
                }));
            }
            actions.push(Action::IgnoreStale(message));
            return;
        }
        self.launch = None;
        if self.state == FenceState::LaunchReserved {
            self.state = FenceState::Fenced;
        }
        match decision {
            LaunchDecision::Accepted(accepted) => {
                self.installed = Some(InstalledLaunch {
                    prompt_generation: accepted.prompt_generation,
                    requester: live.requester,
                });
                actions.push(Action::InstallLaunch(ShellLaunchResult {
                    fence_id: accepted.fence_id,
                    prompt_generation: accepted.prompt_generation,
                    buffer_revision: accepted.buffer_revision,
                }));
            }
            LaunchDecision::Rejected(rejected) => {
                refuse_launch(rejected.reason, actions);
            }
        }
        self.release_hold(actions);
    }

    fn command_accepted(&mut self, params: &RootCommandAcceptedParams, actions: &mut Vec<Action>) {
        if self.state == FenceState::Closing {
            actions.push(Action::IgnoreStale(StaleMessage::ReaderEvent));
            return;
        }
        let origin = self.resolve_origin(params);
        self.acceptance = Some(origin.clone());
        actions.push(Action::RecordAcceptance(origin));
    }

    fn resolve_origin(&self, params: &RootCommandAcceptedParams) -> AcceptedOrigin {
        let Some(fence) = self.fence.as_ref() else {
            return AcceptedOrigin::Unverifiable;
        };
        if params.fence_id.as_ref() != Some(&fence.fence_id)
            || params.prompt_generation != fence.prompt_generation
        {
            return AcceptedOrigin::Unverifiable;
        }
        if let Some(installed) = self.installed
            && installed.prompt_generation == params.prompt_generation
        {
            // The line was installed by a launch, so it belongs to the client that asked for it.
            // The reader cannot know that: it only ever sees the line appear.
            return AcceptedOrigin::Fenced {
                attachment_id: installed.requester,
                input_epoch: fence.input_epoch,
            };
        }
        match &params.origin {
            AcceptedOrigin::Mixed => AcceptedOrigin::Mixed,
            AcceptedOrigin::Unverifiable => AcceptedOrigin::Unverifiable,
            AcceptedOrigin::Fenced {
                attachment_id,
                input_epoch,
            } => {
                if *attachment_id == fence.originating_attachment
                    && *input_epoch == fence.input_epoch
                {
                    AcceptedOrigin::Fenced {
                        attachment_id: *attachment_id,
                        input_epoch: *input_epoch,
                    }
                } else {
                    AcceptedOrigin::Mixed
                }
            }
        }
    }

    fn expire_keeping(&mut self, at: ContinuousMs, keep_hold: bool, actions: &mut Vec<Action>) {
        if let Some(deadline) = self.receipt_deadline
            && at >= deadline
        {
            // The reader never said what its cancellation discarded. The receipt says so rather
            // than reporting a zero nobody measured.
            self.close_takeover_receipt(None, actions);
        }
        // A fence exchange and a launch transaction never overlap: an exchange leaves the editor
        // unfenced, and a launch is reserved only from a fence. So one deadline serves both.
        if let Some(exchange) = self.exchange.clone()
            && at >= exchange.deadline
        {
            self.exchange = None;
            self.close_takeover_receipt(None, actions);
            self.state = FenceState::Unfenced;
            actions.push(Action::WithholdFence(WithheldReason::ExchangeTimedOut));
            let released = if keep_hold {
                U64::ZERO
            } else {
                self.release_hold(actions)
            };
            self.emit_editor_busy(EditorBusyReason::FenceExchangeTimedOut, released, actions);
            return;
        }
        if let Some(transaction) = self.launch.clone()
            && at >= transaction.deadline
        {
            // The hold is over, so the input goes to the terminal and the reader is told the
            // transaction is. The caller's answer waits for the reader's confirmation: only the
            // reader knows whether it installed anything, and a worker that answered from its own
            // timer would be guessing about a command that may be in the editor.
            self.launch = None;
            self.awaiting_confirmation.push(transaction.clone());
            if self.state == FenceState::LaunchReserved {
                self.state = FenceState::Fenced;
            }
            actions.push(Action::RevokeLaunch {
                transaction: transaction.transaction,
                reason: LaunchRejectionReason::Timeout,
            });
            let released = if keep_hold {
                U64::ZERO
            } else {
                self.release_hold(actions)
            };
            self.emit_editor_busy(
                EditorBusyReason::LaunchReservationTimedOut,
                released,
                actions,
            );
        }
    }

    /// Completes the takeover receipt a lease change left open, exactly once.
    ///
    /// A receipt belongs to the cancellation that opened it. Only that cancellation's own report
    /// can fill it; anything else closes it saying the reader's discards are unknown, because a
    /// departure's count is not the takeover's.
    fn close_takeover_receipt(&mut self, reader_discards: Option<U64>, actions: &mut Vec<Action>) {
        self.receipt_deadline = None;
        if let Some((_, epoch)) = self.receipt.take() {
            actions.push(Action::CloseTakeoverReceipt {
                epoch,
                reader_discards,
            });
        }
    }

    fn integration_lost(&mut self, loss: IntegrationLoss, actions: &mut Vec<Action>) {
        if self.state == FenceState::Closing {
            actions.push(Action::IgnoreStale(StaleMessage::ReaderEvent));
            return;
        }
        // Everything in this contract rests on a reader the session can speak for. Without it there
        // is no fence to hold and no transaction to install, and the held input goes to whatever is
        // reading the terminal rather than waiting for an answer that is not coming.
        self.cancel_launch(LaunchRejectionReason::FenceInvalid, actions);
        if matches!(
            loss,
            IntegrationLoss::BridgeDisconnected | IntegrationLoss::UnqualifiedRootReplacement
        ) {
            // The reader that would have said what it did is gone, so nothing left can say whether
            // those commands reached the editor.
            self.lose_confirmations(actions);
        }
        self.invalidate_fence(FenceInvalidation::IntegrationLost, actions);
        if self.exchange.take().is_some() {
            actions.push(Action::WithholdFence(WithheldReason::IntegrationLost));
        }
        self.close_takeover_receipt(None, actions);
        self.release_hold(actions);
        self.installed = None;
        self.state = match loss {
            // An unqualified replacement is not a managed root editor at all, so there is nothing
            // left to register: the session is terminal-only and its input forwards like any
            // application's.
            IntegrationLoss::UnqualifiedRootReplacement => {
                self.editor = None;
                FenceState::Outside
            }
            IntegrationLoss::PostStartupFailure
            | IntegrationLoss::SemanticHookLoss
            | IntegrationLoss::BridgeDisconnected => {
                if self.editor.is_some() {
                    FenceState::Unfenced
                } else {
                    FenceState::Outside
                }
            }
        };
    }

    fn session_closing(&mut self, actions: &mut Vec<Action>) {
        self.cancel_launch(LaunchRejectionReason::SessionClosing, actions);
        self.lose_confirmations(actions);
        self.invalidate_fence(FenceInvalidation::SessionClosing, actions);
        if self.exchange.take().is_some() {
            actions.push(Action::WithholdFence(WithheldReason::SessionClosing));
        }
        self.close_takeover_receipt(None, actions);
        self.hold_deadline = None;
        let held: Vec<InputRef> = std::mem::take(&mut self.hold)
            .into_iter()
            .map(|held| held.input)
            .collect();
        if !held.is_empty() {
            actions.push(Action::Discard {
                input: held,
                reason: DiscardReason::SessionClosing,
            });
        }
        self.editor = None;
        self.installed = None;
        self.state = FenceState::Closing;
    }

    fn start_exchange(
        &mut self,
        at: ContinuousMs,
        candidate: FenceId,
        cause: FenceCause,
        actions: &mut Vec<Action>,
    ) {
        let Some(editor) = self.editor.clone() else {
            return;
        };
        let Some(holder) = self.lease.holder else {
            // A fence names exactly one originating attachment. With no attachment holding input
            // there is nothing for a fence to prove, so the exchange waits for the lease.
            return;
        };
        // A reader that replaces another inside the same hold does not restart it: the hold
        // belongs to the input a client has already sent, and a succession of restarts would
        // otherwise keep somebody's keystrokes waiting indefinitely. The bridge is told what is
        // left of it rather than the whole of it.
        let deadline = match self.hold_deadline {
            Some(carried) if !self.hold.is_empty() => carried,
            _ => at.plus(FENCE_EXCHANGE_TIMEOUT.get()),
        };
        self.hold_deadline = Some(deadline);
        let params = RootEditorFenceParams {
            session_id: self.session_id,
            fence_id: candidate,
            prompt_generation: editor.prompt_generation,
            reader_revision: editor.reader_revision,
            deadline_ms: DurationMs::new(deadline.get().saturating_sub(at.get())),
            cause,
        };
        self.exchange = Some(Exchange {
            fence_id: candidate,
            deadline,
            attachment_id: holder,
            epoch: self.lease.epoch,
            prompt_generation: editor.prompt_generation,
            reader_revision: editor.reader_revision,
        });
        actions.push(Action::AskFence(params));
    }

    fn withhold(&mut self, reason: WithheldReason, actions: &mut Vec<Action>) {
        self.state = FenceState::Unfenced;
        actions.push(Action::WithholdFence(reason));
        let released = self.release_hold(actions);
        self.emit_editor_busy(busy_reason(reason), released, actions);
    }

    fn emit_editor_busy(&self, reason: EditorBusyReason, released: U64, actions: &mut Vec<Action>) {
        let Some(attachment_id) = self.lease.holder else {
            return;
        };
        actions.push(Action::EmitEditorBusy(EditorBusyEvent {
            session_id: self.session_id,
            attachment_id,
            input_epoch: self.lease.epoch,
            reason,
            released_input_bytes: released,
            state: self.state,
        }));
    }

    fn release_hold(&mut self, actions: &mut Vec<Action>) -> U64 {
        self.hold_deadline = None;
        if self.hold.is_empty() {
            return U64::ZERO;
        }
        let held = std::mem::take(&mut self.hold);
        let bytes: u64 = held.iter().map(|entry| entry.bytes.get()).sum();
        actions.push(Action::Release(
            held.into_iter().map(|entry| entry.input).collect(),
        ));
        U64::new(bytes)
    }

    fn cancel_launch(&mut self, reason: LaunchRejectionReason, actions: &mut Vec<Action>) {
        if let Some(transaction) = self.launch.take() {
            // The request is already with the reader, and only the reader knows whether it has
            // installed anything. So the revocation goes out and the caller's answer waits for the
            // reader's word: a refusal that claimed no effect would be claiming something the
            // worker cannot see.
            actions.push(Action::RevokeLaunch {
                transaction: transaction.transaction,
                reason,
            });
            self.awaiting_confirmation.push(transaction);
        }
    }

    /// Answers every caller still waiting for a reader that cannot answer any more.
    fn lose_confirmations(&mut self, actions: &mut Vec<Action>) {
        for _ in std::mem::take(&mut self.awaiting_confirmation) {
            refuse_launch(LaunchRejectionReason::ConfirmationLost, actions);
        }
    }

    fn invalidate_fence(&mut self, reason: FenceInvalidation, actions: &mut Vec<Action>) {
        if self.fence.take().is_some() {
            actions.push(Action::InvalidateFence(reason));
        }
    }

    fn take_hold_of_epoch(&mut self, epoch: InputLeaseEpoch) -> Vec<Held> {
        let mut kept = Vec::new();
        let mut taken = Vec::new();
        for held in std::mem::take(&mut self.hold) {
            if held.epoch == epoch {
                taken.push(held);
            } else {
                kept.push(held);
            }
        }
        self.hold = kept;
        taken
    }

    fn take_hold_of_attachment(&mut self, attachment: AttachmentId) -> Vec<Held> {
        let mut kept = Vec::new();
        let mut taken = Vec::new();
        for held in std::mem::take(&mut self.hold) {
            if held.attachment_id == attachment {
                taken.push(held);
            } else {
                kept.push(held);
            }
        }
        self.hold = kept;
        taken
    }
}

fn refs(held: &[Held]) -> Vec<InputRef> {
    held.iter().map(|entry| entry.input.clone()).collect()
}

fn refuse_launch(reason: LaunchRejectionReason, actions: &mut Vec<Action>) {
    actions.push(Action::RejectLaunch {
        reason,
        code: reason.code(),
    });
}

/// Returns the attachment event's reason for a withheld fence.
///
/// The event is a coarse category by design: what a client can do about it is the same in every
/// case, and the exact reason belongs in the host's own diagnostics.
const fn busy_reason(reason: WithheldReason) -> EditorBusyReason {
    match reason {
        WithheldReason::ExchangeTimedOut => EditorBusyReason::FenceExchangeTimedOut,
        WithheldReason::QueuesNotDrained => EditorBusyReason::QueuesNotDrained,
        WithheldReason::Refused
        | WithheldReason::ReaderMoved
        | WithheldReason::LeaseChanged
        | WithheldReason::EditorLeft
        | WithheldReason::EditorEntered
        | WithheldReason::DetachAccepted
        | WithheldReason::AttachmentRemoved
        | WithheldReason::IntegrationLost
        | WithheldReason::SessionClosing => EditorBusyReason::FenceRefused,
    }
}
