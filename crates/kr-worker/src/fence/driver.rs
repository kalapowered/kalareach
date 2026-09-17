//! The driver around the fence and detach state machine.
//!
//! One `apply` call per stimulus, every action carried out in the order the outcome lists it, and
//! one timer armed at the machine's own deadline. What the driver holds beyond the machine is the
//! things the contract cannot: a clock, the bytes behind each named batch, the channel to the
//! reader's mailbox, and the caller waiting for each launch.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{AttachmentId, InputLeaseEpoch, RequestId, SessionId};
use kr_protocol::input::InterruptAction;
use kr_protocol::root::{
    AcceptedOrigin, EditorBusyEvent, EditorFence, EditorLeaveReason, FenceId, FencePublication,
    FenceState, PromptGeneration, ReaderRevision, RootCommandAcceptedParams,
    RootCommandAcceptedResult, RootEditorEnterParams, RootEditorEnterResult, RootEditorLeaveParams,
    RootEditorLeaveResult, RootEofDetachParams, ShellLaunchParams, ShellLaunchResult,
    WithheldReason,
};
use kr_protocol::scalars::{Nullable, U64};
use kr_shell_integration::contract::events::{BridgeEvent, ReaderIdle};
use kr_shell_integration::contract::fence::{
    Action, ContinuousMs, DetachRejection, DetachTarget, EditorEntered, FenceInvalidation,
    FenceMachine, InputArrived, InputRef, InputRefusal, InterruptRequested, LaunchRequested,
    LeaseAcknowledgement, LeaseFault, LeaseView, ReaderIdled, Stimulus,
};
use kr_shell_integration::contract::qualification::{IntegrationLoss, ShellKind};
use kr_shell_integration::contract::requests::{
    BridgeAnswer, LaunchRejectionReason, LaunchTransactionId, WorkerRequest,
};
use kr_shell_integration::contract::transport::EventOutcome;
use kr_shell_integration::host::phase::PhaseGate;
use kr_transport::clock::{ContinuousClock, ContinuousInstant};

use crate::session::InputBatch;

/// What the driver sends the bridge.
///
/// The frames themselves are written by the connection's own task. Queueing them here keeps the
/// session boundary free of socket writes: a reader that has stopped reading its own socket must
/// not be able to hold the worker's input path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outbound {
    /// Something the reader thread must decide.
    Request(Box<WorkerRequest>),
    /// The answer to one bridge event, correlated by the identifier the bridge allocated for it.
    EventResult {
        /// The event being answered.
        id: RequestId,
        /// The answer.
        result: Box<EventOutcome>,
    },
    /// Whether a fence was published.
    Publication(FencePublication),
    /// A launch transaction is over.
    Revocation {
        /// The transaction.
        transaction: LaunchTransactionId,
        /// Why it ended.
        reason: LaunchRejectionReason,
    },
}

/// What the reader discarded from its own queues during a takeover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderDiscards {
    /// The reader was asked and has not answered yet.
    Pending,
    /// It answered inside the hold, and this is what it discarded.
    Known(U64),
    /// The hold ended first, or a departure superseded the cancellation. Nobody measured it, and
    /// the receipt says so rather than reporting a zero.
    Unknown,
}

/// What one takeover cost, as the receipt records it.
///
/// Two counts, because they are two different things. The worker's own is what it accepted from a
/// client and never delivered; the reader's is what its own queues held. A receipt that added them
/// into one number would be claiming a total nobody can check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TakeoverReceipt {
    /// The epoch this receipt belongs to.
    pub epoch: InputLeaseEpoch,
    /// Accepted input the worker discarded rather than delivering.
    pub worker_discarded_bytes: U64,
    /// What the reader discarded, when it said.
    pub reader_discards: ReaderDiscards,
}

/// The answer one `shell.launch` caller receives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchAnswer {
    /// The command was installed in the editor and submitted.
    Installed(ShellLaunchResult),
    /// It was not, and this is why.
    Refused {
        /// The reason the contract named.
        reason: LaunchRejectionReason,
        /// The error code the caller receives.
        code: ErrorCode,
    },
}

impl LaunchAnswer {
    /// Returns this answer as a protocol error, when it is one.
    #[must_use]
    pub fn error(&self) -> Option<ProtocolError> {
        match self {
            Self::Installed(_) => None,
            Self::Refused { reason, code } => Some(ProtocolError::new(
                *code,
                format!("the launch was not installed: {}", reason.as_str()),
            )),
        }
    }
}

/// Everything one stimulus left for the worker to do.
///
/// The fields are in the order the caller applies them, which is the order the machine listed the
/// actions in: held input is released before the event that explains why it waited, and a fence is
/// invalidated before a detach is acknowledged.
#[derive(Debug, Default)]
pub struct Effects {
    /// Batches to queue for the pseudo-terminal, in order.
    pub write: Vec<InputBatch>,
    /// Accepted input that was dropped rather than delivered.
    pub discarded_bytes: u64,
    /// Bytes the machine has taken into its hold.
    pub held_added: usize,
    /// Bytes the machine has let go of, by writing them or dropping them.
    pub held_removed: usize,
    /// The `editor_busy` events to deliver to their attachments.
    pub editor_busy: Vec<EditorBusyEvent>,
    /// Attachments to remove.
    pub remove_attachments: Vec<AttachmentId>,
    /// True when the configured native interrupt is to be sent to the foreground group.
    pub interrupt: Option<InterruptAction>,
    /// The refusal an interrupt request is owed.
    pub interrupt_refused: Option<LeaseFault>,
    /// The refusal a client's input is owed.
    pub input_refused: Option<InputRefusal>,
    /// The launch answers that became final, with the caller each belongs to.
    pub launch_answers: Vec<(LaunchTransactionId, LaunchAnswer)>,
    /// Commands the reader installed after their transaction had been revoked.
    pub late_installations: Vec<ShellLaunchResult>,
    /// The origin recorded for an accepted line.
    pub acceptance: Option<AcceptedOrigin>,
    /// The lease change the worker acknowledges.
    pub lease_acknowledged: Option<LeaseAcknowledgement>,
    /// The takeover receipts this stimulus completed.
    pub receipts: Vec<TakeoverReceipt>,
    /// The loss that closes the creating session, when one does.
    pub close_session: Option<IntegrationLoss>,
}

impl Effects {
    fn merge(&mut self, other: Self) {
        self.write.extend(other.write);
        self.discarded_bytes = self.discarded_bytes.saturating_add(other.discarded_bytes);
        self.held_added = self.held_added.saturating_add(other.held_added);
        self.held_removed = self.held_removed.saturating_add(other.held_removed);
        self.editor_busy.extend(other.editor_busy);
        self.remove_attachments.extend(other.remove_attachments);
        self.interrupt = other.interrupt.or(self.interrupt);
        self.interrupt_refused = other.interrupt_refused.or(self.interrupt_refused);
        self.input_refused = other.input_refused.or(self.input_refused);
        self.launch_answers.extend(other.launch_answers);
        self.late_installations.extend(other.late_installations);
        self.acceptance = other.acceptance.or_else(|| self.acceptance.take());
        self.lease_acknowledged = other
            .lease_acknowledged
            .or_else(|| self.lease_acknowledged.take());
        self.receipts.extend(other.receipts);
        self.close_session = other.close_session.or(self.close_session);
    }
}

/// Which stimulus produced an outcome, for the answers the machine does not name itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Context {
    /// A launch request from a client, whose own refusal belongs to this transaction.
    LaunchRequested(LaunchTransactionId),
    /// A reader's decision, whose answer belongs to the transaction it names.
    LaunchDecided(LaunchTransactionId),
    /// Anything else. A launch answer here is a confirmation the reader can no longer give, and
    /// they arrive in the order the transactions were revoked.
    Other,
}

/// One batch the worker is holding for a reader transition.
#[derive(Debug)]
struct Held {
    batch: InputBatch,
    bytes: u64,
    /// Whether these bytes are charged against the session's input budget.
    ///
    /// A batch is charged when the machine holds it and released when the machine lets go. A batch
    /// the machine forwarded or discarded on arrival was never held, so it is never charged and
    /// never released: it goes straight to the writer's own counter or nowhere at all.
    charged: bool,
}

/// The worker's side of the root-editor contract, driven against a real clock.
pub struct FenceDriver {
    session_id: SessionId,
    machine: FenceMachine,
    phase: PhaseGate,
    clock: std::sync::Arc<dyn ContinuousClock>,
    anchor: ContinuousInstant,
    hold: BTreeMap<InputRef, Held>,
    next_batch: u64,
    /// Where a frame for the bridge goes.
    ///
    /// The connection's writer owns the other end. Queueing rather than writing is what keeps the
    /// session boundary free of socket writes: a reader that has stopped reading its own socket
    /// must not be able to hold the worker's input path or its one timer.
    outbound: Option<tokio::sync::mpsc::UnboundedSender<Outbound>>,
    /// The fence the bridge currently holds, so an invalidation can name it.
    published: Option<FenceId>,
    /// The transaction the reader is deciding now, and the ones whose callers are still waiting
    /// for a confirmation that may never come. Both follow the machine's own actions.
    live_launch: Option<LaunchTransactionId>,
    awaiting: VecDeque<LaunchTransactionId>,
    /// The receipt a lease change left open.
    receipt: Option<TakeoverReceipt>,
    /// The bridge event being answered, while one is.
    answering: Option<RequestId>,
    /// The reader the bridge last reported, so a loss that costs the fence can say which reader
    /// went. It is what the bridge said, kept to be quoted back, not a second view of the machine.
    reader: Option<(PromptGeneration, ReaderRevision)>,
    /// What the connection's own task waits on when the deadline or the queue may have moved.
    waker: std::sync::Arc<tokio::sync::Notify>,
}

impl std::fmt::Debug for FenceDriver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FenceDriver")
            .field("state", &self.machine.state())
            .field("phase", &self.phase.phase())
            .field("held", &self.hold.len())
            .field("connected", &self.outbound.is_some())
            .finish()
    }
}

impl FenceDriver {
    /// Builds a driver for a managed session whose bridge has not registered yet.
    #[must_use]
    pub fn new(
        session_id: SessionId,
        lease: LeaseView,
        clock: std::sync::Arc<dyn ContinuousClock>,
    ) -> Self {
        let anchor = clock.now();
        Self {
            session_id,
            machine: FenceMachine::new(session_id, lease),
            phase: PhaseGate::unauthenticated(),
            clock,
            anchor,
            hold: BTreeMap::new(),
            next_batch: 0,
            outbound: None,
            published: None,
            live_launch: None,
            awaiting: VecDeque::new(),
            receipt: None,
            answering: None,
            reader: None,
            waker: std::sync::Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Returns what the connection's task waits on.
    ///
    /// A stimulus that reaches the driver from the session's own side — a client's input, a lease
    /// change, a launch — can arm the timer or queue a frame while the connection's task is waiting
    /// on the socket. This is how it is woken to look again.
    #[must_use]
    pub fn waker(&self) -> std::sync::Arc<tokio::sync::Notify> {
        std::sync::Arc::clone(&self.waker)
    }

    /// Returns the phase this session's integration has reached.
    #[must_use]
    pub const fn phase(&self) -> &PhaseGate {
        &self.phase
    }

    /// Returns the state the machine is in.
    #[must_use]
    pub const fn state(&self) -> FenceState {
        self.machine.state()
    }

    /// Returns the fence the bridge currently holds, when one is published.
    #[must_use]
    pub const fn fence(&self) -> Option<&EditorFence> {
        self.machine.fence()
    }

    /// Returns the batches still held, in arrival order.
    #[must_use]
    pub fn held(&self) -> Vec<InputRef> {
        self.machine.held()
    }

    /// Returns what a `kr detach` with no attachment identifier targets.
    #[must_use]
    pub fn detach_target(&self) -> DetachTarget {
        self.machine.detach_target()
    }

    /// Returns the open takeover receipt, when a lease change left one.
    #[must_use]
    pub const fn open_receipt(&self) -> Option<&TakeoverReceipt> {
        self.receipt.as_ref()
    }

    /// Sends this connection's frames through `outbound` from now on.
    pub fn send_through(&mut self, outbound: tokio::sync::mpsc::UnboundedSender<Outbound>) {
        self.outbound = Some(outbound);
    }

    /// Stops queueing frames, because the connection they would travel on has ended.
    pub fn stop_sending(&mut self) {
        self.outbound = None;
    }

    /// Queues one frame for the bridge, when a connection is there to carry it.
    fn send(&self, frame: Outbound) {
        if let Some(outbound) = self.outbound.as_ref() {
            let _ = outbound.send(frame);
        }
    }

    /// Returns how long the driver's timer should wait, when it has a deadline.
    ///
    /// One timer, at the machine's own deadline. A deadline that has already passed returns a zero
    /// duration rather than `None`, so the caller fires the sweep instead of waiting for the next
    /// message to carry it.
    #[must_use]
    pub fn deadline(&self) -> Option<Duration> {
        let deadline = self.machine.deadline()?;
        let now = self.reading();
        Some(Duration::from_millis(
            deadline.get().saturating_sub(now.get()),
        ))
    }

    /// Records an accepted handshake.
    ///
    /// Returns false when this session had already authenticated one, which is not a promotion: a
    /// session that lost its integration does not get it back by registering again.
    pub const fn registered(&mut self, kind: ShellKind) -> bool {
        self.phase.authenticated(kind)
    }

    /// Returns the current reading of the session's continuous clock.
    fn reading(&self) -> ContinuousMs {
        let elapsed = self.clock.now().saturating_duration_since(self.anchor);
        ContinuousMs::new(u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
    }

    /// Names the next batch of input.
    fn name_batch(&mut self) -> InputRef {
        self.next_batch += 1;
        InputRef::new(format!("input-{}", self.next_batch))
    }

    /// Fires the hold timer.
    pub fn expire(&mut self) -> Effects {
        self.apply(&Stimulus::HoldExpired, Context::Other)
    }

    /// Offers one client's batch to the terminal.
    ///
    /// The batch is written, held or dropped; which of those is the machine's answer rather than
    /// this function's.
    pub fn input_arrived(
        &mut self,
        attachment_id: AttachmentId,
        epoch: InputLeaseEpoch,
        batch: InputBatch,
    ) -> Effects {
        let bytes = batch.len() as u64;
        let input = self.name_batch();
        self.hold.insert(
            input.clone(),
            Held {
                batch,
                bytes,
                charged: false,
            },
        );
        self.apply(
            &Stimulus::InputArrived(InputArrived {
                input,
                attachment_id,
                epoch,
                bytes: U64::new(bytes),
            }),
            Context::Other,
        )
    }

    /// Reports a lease change the worker has already made.
    ///
    /// The change stands whatever the reader says. What the machine decides is what happens to the
    /// input the previous holder had already sent, and whether a fence exchange starts.
    pub fn lease_changed(
        &mut self,
        lease: LeaseView,
        discarded_bytes: u64,
        candidate_fence: FenceId,
    ) -> Effects {
        self.apply(
            &Stimulus::LeaseChanged(kr_shell_integration::contract::fence::LeaseChanged {
                lease,
                discarded_bytes: U64::new(discarded_bytes),
                candidate_fence,
            }),
            Context::Other,
        )
    }

    /// Reports an attachment that has gone.
    pub fn attachment_removed(&mut self, attachment_id: AttachmentId) -> Effects {
        self.apply(&Stimulus::AttachmentRemoved(attachment_id), Context::Other)
    }

    /// Asks for the configured native interrupt.
    ///
    /// It bypasses the reader-transition hold: a held interrupt would be no interrupt at all.
    pub fn interrupt_requested(
        &mut self,
        attachment_id: AttachmentId,
        epoch: InputLeaseEpoch,
        action: InterruptAction,
    ) -> Effects {
        self.apply(
            &Stimulus::InterruptRequested(InterruptRequested {
                attachment_id,
                epoch,
                action,
            }),
            Context::Other,
        )
    }

    /// Reports that the session has begun closing.
    pub fn session_closing(&mut self) -> Effects {
        self.apply(&Stimulus::SessionClosing, Context::Other)
    }

    /// Reports a loss of the integration the worker inferred for itself.
    ///
    /// A bridge whose connection ends reports nothing; this is how the session hears about it.
    pub fn integration_lost(&mut self, loss: IntegrationLoss) -> Effects {
        let mut effects = self.apply(&Stimulus::IntegrationLost(loss), Context::Other);
        let decision = self.phase.lost(loss);
        if decision.closes_session {
            effects.close_session = Some(loss);
        }
        // A session that can no longer hold a fence has no reader it can speak for, so the machine
        // is told the reader has gone. Without it the machine would keep a registered editor and
        // start another exchange at the next lease change, and a session the phase says is degraded
        // would publish a fence and hand out a detach proof it cannot stand behind.
        if !decision.closes_session
            && !self.phase.retains_fence()
            && let Some((prompt_generation, reader_revision)) = self.reader.take()
        {
            let left = self.apply(
                &Stimulus::EditorLeft(RootEditorLeaveParams {
                    session_id: self.session_id,
                    prompt_generation,
                    reader_revision,
                    reason: match loss {
                        IntegrationLoss::UnqualifiedRootReplacement => EditorLeaveReason::RootExit,
                        IntegrationLoss::PostStartupFailure
                        | IntegrationLoss::SemanticHookLoss
                        | IntegrationLoss::BridgeDisconnected => EditorLeaveReason::Cancellation,
                    },
                }),
                Context::Other,
            );
            effects.merge(left);
        }
        effects
    }

    /// Admits a launch, or refuses it before the machine sees it.
    ///
    /// The phase gate is the first check: a session that is not qualified installs nothing, whatever
    /// its editor happens to be doing. Everything after that is the machine's.
    pub fn launch_requested(
        &mut self,
        params: ShellLaunchParams,
        requester: AttachmentId,
        transaction: LaunchTransactionId,
    ) -> Effects {
        if !self.phase.permits_launch() {
            let reason = LaunchRejectionReason::FenceInvalid;
            return Effects {
                launch_answers: vec![(
                    transaction,
                    LaunchAnswer::Refused {
                        reason,
                        code: reason.code(),
                    },
                )],
                ..Effects::default()
            };
        }
        self.apply(
            &Stimulus::LaunchRequested(LaunchRequested {
                params,
                requester,
                transaction,
            }),
            Context::LaunchRequested(transaction),
        )
    }

    /// Feeds one event the bridge reported, and answers it.
    ///
    /// The identifier is the bridge's own: an answer belongs to the event it answers rather than to
    /// whatever is currently in flight.
    pub fn bridge_event(&mut self, id: RequestId, event: &BridgeEvent) -> Effects {
        self.answering = Some(id);
        let effects = self.event(event);
        self.answering = None;
        effects
    }

    fn event(&mut self, event: &BridgeEvent) -> Effects {
        match event {
            BridgeEvent::EditorEnter(params) => self.editor_entered(params),
            BridgeEvent::EditorLeave(params) => self.editor_left(params),
            BridgeEvent::ReaderIdle(idle) => self.reader_idled(idle),
            BridgeEvent::EofDetach(params) => self.detach_submitted(params),
            BridgeEvent::CommandAccepted(params) => self.command_accepted(params),
            BridgeEvent::HooksActivated(_) => {
                let _ = self.phase.qualified();
                self.answer(EventOutcome::Received);
                Effects::default()
            }
            BridgeEvent::GestureChanged(_) | BridgeEvent::PreEofConsumed(_) => {
                self.answer(EventOutcome::Received);
                Effects::default()
            }
            BridgeEvent::IntegrationLost(report) => {
                self.answer(EventOutcome::Received);
                self.integration_lost(report.loss)
            }
        }
    }

    /// Feeds one answer the reader thread gave.
    pub fn bridge_answer(&mut self, answer: &BridgeAnswer) -> Effects {
        match answer {
            BridgeAnswer::Fence(result) => match result {
                kr_protocol::root::RootEditorFenceResult::Acknowledged(acknowledgement) => self
                    .apply(
                        &Stimulus::FenceAcknowledged(acknowledgement.clone()),
                        Context::Other,
                    ),
                kr_protocol::root::RootEditorFenceResult::Refused(refusal) => {
                    self.apply(&Stimulus::FenceRefused(refusal.clone()), Context::Other)
                }
            },
            BridgeAnswer::Launch(decision) => self.apply(
                &Stimulus::LaunchDecided(decision.clone()),
                Context::LaunchDecided(decision.transaction()),
            ),
            BridgeAnswer::Cancel(report) => self.apply(
                &Stimulus::CancellationReported(report.clone()),
                Context::Other,
            ),
        }
    }

    fn editor_entered(&mut self, params: &RootEditorEnterParams) -> Effects {
        if !self.phase.retains_fence() {
            // Below a qualified session there is no fence to hold. The reader is answered so it
            // does not wait, and nothing starts an exchange: a startup profile that asks a question
            // reads its input in its own context, exactly as section 7 paragraph 4 requires.
            self.answer(EventOutcome::EditorEntered(RootEditorEnterResult {
                state: self.machine.state(),
                fence_exchange: Nullable::null(),
            }));
            return Effects::default();
        }
        self.reader = Some((params.prompt_generation, params.reader_revision));
        let candidate_fence = FenceId::new(kr_ipc::new_uuid());
        let effects = self.apply(
            &Stimulus::EditorEntered(EditorEntered {
                params: params.clone(),
                candidate_fence,
            }),
            Context::Other,
        );
        // The exchange the entry started, when the machine started one: a fence a client is told
        // about is one the reader has actually been asked for.
        let started = self.machine.deadline().is_some();
        self.answer(EventOutcome::EditorEntered(RootEditorEnterResult {
            state: self.machine.state(),
            fence_exchange: if started {
                Nullable::some(candidate_fence)
            } else {
                Nullable::null()
            },
        }));
        effects
    }

    fn editor_left(&mut self, params: &RootEditorLeaveParams) -> Effects {
        self.reader = None;
        let effects = self.apply(&Stimulus::EditorLeft(params.clone()), Context::Other);
        self.answer(EventOutcome::EditorLeft(RootEditorLeaveResult {
            state: self.machine.state(),
        }));
        effects
    }

    fn reader_idled(&mut self, idle: &ReaderIdle) -> Effects {
        if !self.phase.retains_fence() {
            self.answer(EventOutcome::Received);
            return Effects::default();
        }
        self.reader = Some((idle.prompt_generation, idle.reader_revision));
        let effects = self.apply(
            &Stimulus::ReaderIdled(ReaderIdled {
                idle: idle.clone(),
                candidate_fence: FenceId::new(kr_ipc::new_uuid()),
            }),
            Context::Other,
        );
        self.answer(EventOutcome::Received);
        effects
    }

    fn detach_submitted(&mut self, params: &RootEofDetachParams) -> Effects {
        self.apply(&Stimulus::DetachSubmitted(params.clone()), Context::Other)
    }

    fn command_accepted(&mut self, params: &RootCommandAcceptedParams) -> Effects {
        let params = if self.phase.permits_attribution() {
            params.clone()
        } else {
            // A session that cannot speak for its reader cannot attribute a line to a client. It
            // records the acceptance as unverifiable rather than naming an attachment on the
            // strength of a reader it no longer qualifies.
            RootCommandAcceptedParams {
                origin: AcceptedOrigin::Unverifiable,
                ..params.clone()
            }
        };
        self.apply(&Stimulus::CommandAccepted(params), Context::Other)
    }

    /// Answers the event being processed.
    ///
    /// An action that answers an event can only ever run while one is being processed: a detach is
    /// acknowledged or refused because a detach arrived, and an acceptance is recorded because an
    /// acceptance arrived. Outside that there is nothing to correlate an answer with, and none is
    /// sent.
    fn answer(&mut self, outcome: EventOutcome) {
        if let Some(id) = self.answering {
            self.send(Outbound::EventResult {
                id,
                result: Box::new(outcome),
            });
        }
    }

    fn apply(&mut self, stimulus: &Stimulus, context: Context) -> Effects {
        let at = self.reading();
        let outcome = self.machine.apply(at, stimulus);
        let mut effects = Effects::default();
        for action in &outcome.actions {
            let produced = self.carry_out(action, context, outcome.state);
            effects.merge(produced);
        }
        self.waker.notify_one();
        effects
    }

    #[allow(clippy::too_many_lines)]
    fn carry_out(&mut self, action: &Action, context: Context, state: FenceState) -> Effects {
        let mut effects = Effects::default();
        match action {
            Action::AskFence(params) => {
                self.send(Outbound::Request(Box::new(WorkerRequest::Fence(
                    params.clone(),
                ))));
            }
            Action::Hold(input) => {
                if let Some(held) = self.hold.get_mut(input) {
                    held.charged = true;
                    effects.held_added = effects.held_added.saturating_add(held.batch.len());
                }
            }
            Action::Forward(input) => {
                if let Some(held) = self.hold.remove(input) {
                    effects.write.push(held.batch);
                }
            }
            Action::Release(order) => {
                for input in order {
                    if let Some(held) = self.hold.remove(input) {
                        if held.charged {
                            effects.held_removed =
                                effects.held_removed.saturating_add(held.batch.len());
                        }
                        effects.write.push(held.batch);
                    }
                }
            }
            Action::Discard { input, .. } => {
                for name in input {
                    if let Some(held) = self.hold.remove(name) {
                        if held.charged {
                            effects.held_removed =
                                effects.held_removed.saturating_add(held.batch.len());
                        }
                        effects.discarded_bytes =
                            effects.discarded_bytes.saturating_add(held.bytes);
                    }
                }
            }
            Action::RefuseInput(refusal) => effects.input_refused = Some(*refusal),
            Action::CancelNativeOperations(cancel) => {
                self.send(Outbound::Request(Box::new(WorkerRequest::Cancel(
                    cancel.clone(),
                ))));
            }
            Action::PublishFence(fence) => {
                self.published = Some(fence.fence_id);
                self.send(Outbound::Publication(FencePublication::Published(
                    fence.clone(),
                )));
            }
            Action::WithholdFence(reason) => {
                self.send(Outbound::Publication(FencePublication::Withheld {
                    reason: *reason,
                    state,
                }));
            }
            Action::InvalidateFence(reason) => {
                if let Some(fence_id) = self.published.take() {
                    self.send(Outbound::Publication(FencePublication::Invalidated {
                        fence_id,
                        reason: withheld_for(*reason),
                        state,
                    }));
                }
            }
            Action::EmitEditorBusy(event) => effects.editor_busy.push(event.clone()),
            Action::AcknowledgeLeaseChange(acknowledgement) => {
                self.receipt = Some(TakeoverReceipt {
                    epoch: acknowledgement.lease.epoch,
                    worker_discarded_bytes: acknowledgement.discarded_bytes,
                    reader_discards: if acknowledgement.reader_discards_pending {
                        ReaderDiscards::Pending
                    } else {
                        ReaderDiscards::Unknown
                    },
                });
                effects.lease_acknowledged = Some(acknowledgement.clone());
            }
            Action::RemoveAttachment(attachment) => effects.remove_attachments.push(*attachment),
            Action::AcknowledgeDetach(result) => {
                self.answer(EventOutcome::Detached(result.clone()));
            }
            Action::RejectDetach(rejection) => {
                self.answer(EventOutcome::Refused(detach_error(*rejection)));
            }
            Action::SendLaunch(request) => {
                self.live_launch = Some(request.transaction);
                self.send(Outbound::Request(Box::new(WorkerRequest::Launch(
                    request.clone(),
                ))));
            }
            Action::RevokeLaunch {
                transaction,
                reason,
            } => {
                if self.live_launch == Some(*transaction) {
                    self.live_launch = None;
                }
                self.awaiting.push_back(*transaction);
                self.send(Outbound::Revocation {
                    transaction: *transaction,
                    reason: *reason,
                });
            }
            Action::InstallLaunch(result) => {
                if let Some(transaction) = self.resolve_launch(context) {
                    effects
                        .launch_answers
                        .push((transaction, LaunchAnswer::Installed(result.clone())));
                }
            }
            Action::RejectLaunch { reason, code } => {
                if let Some(transaction) = self.resolve_launch(context) {
                    effects.launch_answers.push((
                        transaction,
                        LaunchAnswer::Refused {
                            reason: *reason,
                            code: *code,
                        },
                    ));
                }
            }
            Action::Interrupt(action) => effects.interrupt = Some(*action),
            Action::RefuseInterrupt(fault) => effects.interrupt_refused = Some(*fault),
            Action::RecordAcceptance(origin) => {
                effects.acceptance = Some(origin.clone());
                self.answer(EventOutcome::CommandRecorded(RootCommandAcceptedResult {
                    origin: origin.clone(),
                    state,
                }));
            }
            Action::CloseTakeoverReceipt {
                epoch,
                reader_discards,
            } => {
                let mut receipt = self.receipt.take().unwrap_or(TakeoverReceipt {
                    epoch: *epoch,
                    worker_discarded_bytes: U64::ZERO,
                    reader_discards: ReaderDiscards::Unknown,
                });
                receipt.epoch = *epoch;
                receipt.reader_discards =
                    reader_discards.map_or(ReaderDiscards::Unknown, ReaderDiscards::Known);
                effects.receipts.push(receipt);
            }
            Action::LateInstallation(result) => effects.late_installations.push(result.clone()),
            Action::IgnoreStale(_) => {}
        }
        effects
    }

    /// Returns the caller an answer belongs to.
    ///
    /// The machine names a transaction only where more than one could be meant. Everywhere else
    /// the stimulus says it: a refusal produced by a launch request belongs to that request, and an
    /// answer produced by a reader's decision belongs to the transaction the decision names. What
    /// is left is a confirmation the reader can no longer give, and those are answered in the order
    /// their transactions were revoked.
    fn resolve_launch(&mut self, context: Context) -> Option<LaunchTransactionId> {
        match context {
            Context::LaunchRequested(transaction) => Some(transaction),
            Context::LaunchDecided(transaction) => {
                if self.live_launch == Some(transaction) {
                    self.live_launch = None;
                }
                if let Some(index) = self
                    .awaiting
                    .iter()
                    .position(|awaited| *awaited == transaction)
                {
                    self.awaiting.remove(index);
                }
                Some(transaction)
            }
            Context::Other => self.awaiting.pop_front(),
        }
    }
}

/// Returns the reason a bridge is told a fence went away for.
const fn withheld_for(reason: FenceInvalidation) -> WithheldReason {
    match reason {
        FenceInvalidation::EditorEntered => WithheldReason::EditorEntered,
        FenceInvalidation::EditorLeft => WithheldReason::EditorLeft,
        FenceInvalidation::LeaseChanged => WithheldReason::LeaseChanged,
        FenceInvalidation::ReaderMoved => WithheldReason::ReaderMoved,
        FenceInvalidation::DetachAccepted => WithheldReason::DetachAccepted,
        FenceInvalidation::AttachmentRemoved => WithheldReason::AttachmentRemoved,
        FenceInvalidation::IntegrationLost => WithheldReason::IntegrationLost,
        FenceInvalidation::SessionClosing => WithheldReason::SessionClosing,
    }
}

/// Returns the error a refused detach carries.
///
/// The bridge acts on it: the gesture has already been taken from the reader, so a refusal is what
/// tells it to consume the gesture and print the hint, at most once per prompt.
fn detach_error(rejection: DetachRejection) -> ProtocolError {
    let detail = match rejection {
        DetachRejection::FenceMissing => {
            "no fence is published, so nothing says whose gesture this was"
        }
        DetachRejection::FenceStale => {
            "the fence named is not the one this session holds, or its prompt or epoch has moved"
        }
        DetachRejection::SessionClosing => "this session is closing",
    };
    ProtocolError::new(rejection.code(), detail)
}
