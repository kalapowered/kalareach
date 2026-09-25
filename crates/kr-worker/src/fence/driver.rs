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
    AcceptedOrigin, EditorBusyEvent, EditorFence, EditorLeaveReason, FenceId, FenceState,
    PromptGeneration, ReaderRevision, RootCommandAcceptedParams, RootCommandAcceptedResult,
    RootEditorEnterParams, RootEditorEnterResult, RootEditorLeaveParams, RootEditorLeaveResult,
    RootEofDetachParams, ShellLaunchParams, ShellLaunchResult, WithheldReason,
};
use kr_protocol::scalars::{Nullable, U64};
use kr_shell_integration::contract::events::{BridgeEvent, ReaderIdle};
use kr_shell_integration::contract::fence::{
    Action, ContinuousMs, DetachRejection, DetachTarget, EditorEntered, FenceInvalidation,
    FenceMachine, InputArrived, InputRef, InputRefusal, InterruptRequested, LaunchRequested,
    LeaseAcknowledgement, LeaseFault, LeaseView, ReaderIdled, StaleMessage, Stimulus,
};
use kr_shell_integration::contract::qualification::{IntegrationLoss, ShellKind};
use kr_shell_integration::contract::requests::{
    BridgeAnswer, LaunchRejectionReason, LaunchTransactionId, WorkerRequest,
};
use kr_shell_integration::contract::transport::EventOutcome;
use kr_shell_integration::host::phase::PhaseGate;
use kr_transport::clock::{ContinuousClock, ContinuousInstant};

use crate::session::InputBatch;

/// How long a published fence may wait for the connection's writer before the connection is
/// treated as lost.
///
/// The keys the fence released wait behind it, so a reader that has stopped reading its own
/// socket would otherwise hold the terminal's input for as long as it stayed away. A reader that
/// is working takes the fence at once: it has just answered the exchange the fence came from, and
/// it reads its endpoint whenever it waits for a key. So this bound is for one that is not working,
/// and it is long beside anything a working one takes, because what follows is what follows any
/// lost bridge: the fence is dropped, the session is degraded, and the keys go to the terminal as
/// input nothing is attributed to.
pub const FENCE_WRITE_LIMIT: Duration = Duration::from_secs(5);

/// One published fence, numbered in the order the connection's writer was handed them.
///
/// The session puts it in its queue for the terminal where the fence was published, and nothing
/// queued behind it goes to the terminal until the writer has written the fence or the connection
/// has ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FenceFrame(u64);

/// What the driver sends the bridge.
///
/// The frames themselves are written by the connection's own task. Queueing them here keeps the
/// session boundary free of socket writes: a reader that has stopped reading its own socket must
/// not be able to hold the worker's input path. The one thing that waits for the writer is input
/// behind a published fence, and for no longer than [`FENCE_WRITE_LIMIT`].
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
    /// A published fence, which the writer reports once it has written it.
    ///
    /// This is the only way a published fence reaches the bridge, and only
    /// [`FenceDriver::publish`] can number one, so there is no fence the session's queue for the
    /// terminal does not know to wait for.
    Published {
        /// The fence.
        fence: Box<EditorFence>,
        /// What the writer reports.
        frame: FenceFrame,
    },
    /// That no fence was published for the exchange.
    Withheld {
        /// Why.
        reason: WithheldReason,
        /// The state the editor is in.
        state: FenceState,
    },
    /// That the fence published before has gone.
    Invalidated {
        /// The fence.
        fence_id: FenceId,
        /// Why.
        reason: WithheldReason,
        /// The state the editor is in.
        state: FenceState,
    },
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
                match *code {
                    ErrorCode::OutcomeUnknown => format!(
                        "nothing can say whether the launch installed a command: {}",
                        reason.as_str()
                    ),
                    _ => format!("the launch installed no command: {}", reason.as_str()),
                },
            )),
        }
    }
}

/// One thing the machine asked the worker to do.
///
/// A step per action, kept in the order the outcome listed them. The order is the contract's, not
/// a convenience: a fence published before the input it lets go of, held input released before the
/// `editor_busy` event that explains why it waited, a revocation before the interrupt that caused
/// it, and a detach acknowledged only once the attachment is gone.
#[derive(Debug)]
pub enum Step {
    /// Queue a batch for the pseudo-terminal.
    Write(InputBatch),
    /// Publish a fence to the bridge.
    ///
    /// Everything the session queues for the terminal after it waits until the connection's writer
    /// has written it. A reader takes what is on its endpoint before it acts on a key, and only
    /// what is there: a key that reached the shell ahead of its fence would be accepted without
    /// it, and the line it made would run without the capability the fence exists to mint.
    Publish(Box<EditorFence>),
    /// Deliver an `editor_busy` event to the attachment it names.
    EditorBusy(Box<EditorBusyEvent>),
    /// Remove an attachment.
    RemoveAttachment(AttachmentId),
    /// Send the configured native interrupt to the foreground process group.
    Interrupt(InterruptAction),
    /// Close a takeover receipt.
    Receipt(TakeoverReceipt),
    /// Record a command the reader installed after its transaction had been revoked.
    LateInstallation(Box<ShellLaunchResult>),
    /// Answer the client waiting on one launch.
    Launch(LaunchTransactionId, Box<LaunchAnswer>),
    /// Send one frame to the bridge.
    Send(Outbound),
    /// Answer a command hook the session decides rather than the fence machine.
    ///
    /// Resolving an invocation and recording a command block are both about the session's own
    /// configuration and history, not about the reader's state, so the machine sweeps its clock
    /// and hands the question on. The step keeps its place in the machine's order, so the answer
    /// still goes out after everything the same stimulus released.
    CommandHook(RequestId, Box<CommandHook>),
}

/// A command hook the session answers.
#[derive(Clone, Debug)]
pub enum CommandHook {
    /// What an interactive invocation resolves to, asked before the command runs.
    Resolve(kr_protocol::root::RootCommandResolveParams),
    /// One command block, with its status, duration and directory.
    Block(Box<kr_protocol::root::RootCommandBlockParams>),
}

/// Everything one stimulus left for the worker to do.
///
/// `steps` is the machine's own action list, in its own order, and the caller walks it from front
/// to back. The rest is what the stimulus says about itself rather than something to carry out: an
/// accounting total, a refusal the caller owes its own client, or a decision for the runtime.
#[derive(Debug, Default)]
pub struct Effects {
    /// What to do, in the order the machine said to do it.
    pub steps: Vec<Step>,
    /// Accepted input that was dropped rather than delivered.
    pub discarded_bytes: u64,
    /// Bytes the machine has taken into its hold.
    pub held_added: usize,
    /// Bytes the machine has let go of, by writing them or dropping them.
    pub held_removed: usize,
    /// The refusal an interrupt request is owed.
    pub interrupt_refused: Option<LeaseFault>,
    /// The refusal a client's input is owed.
    pub input_refused: Option<InputRefusal>,
    /// The origin recorded for an accepted line.
    pub acceptance: Option<AcceptedOrigin>,
    /// The lease change the worker acknowledges.
    pub lease_acknowledged: Option<LeaseAcknowledgement>,
    /// The loss that closes the creating session, when one does.
    pub close_session: Option<IntegrationLoss>,
}

impl Effects {
    /// Returns the native interrupt this stimulus admitted, when it admitted one.
    #[must_use]
    pub fn interrupt(&self) -> Option<InterruptAction> {
        self.steps.iter().find_map(|step| match step {
            Step::Interrupt(action) => Some(*action),
            _ => None,
        })
    }

    fn merge(&mut self, other: Self) {
        self.steps.extend(other.steps);
        self.discarded_bytes = self.discarded_bytes.saturating_add(other.discarded_bytes);
        self.held_added = self.held_added.saturating_add(other.held_added);
        self.held_removed = self.held_removed.saturating_add(other.held_removed);
        self.interrupt_refused = other.interrupt_refused.or(self.interrupt_refused);
        self.input_refused = other.input_refused.or(self.input_refused);
        self.acceptance = other.acceptance.or_else(|| self.acceptance.take());
        self.lease_acknowledged = other
            .lease_acknowledged
            .or_else(|| self.lease_acknowledged.take());
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

/// The capability one accepted line holds while that line is still running.
///
/// The generation is the line's own, and it is what says whether the line is still the one this
/// capability was minted for. A capability whose line has ended names nothing, because the
/// question `kr detach` asks — which terminal typed the line I am running from — has no answer
/// once that line is over: the shell is back at its prompt and the next line has not been typed.
#[derive(Debug)]
struct LineCapability {
    /// The minted secret, compared against what a caller presents.
    token: String,
    /// The attachment the line was typed in.
    attachment_id: AttachmentId,
    /// The prompt generation the line was accepted at.
    prompt_generation: PromptGeneration,
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
    /// The published fences the connection's writer has been handed and has not written, oldest
    /// first, each with the reading it was handed over at.
    ///
    /// The writer takes its frames in order, so these are always the newest frames handed over:
    /// one written is every one before it written too.
    unwritten: VecDeque<(FenceFrame, ContinuousMs)>,
    /// How many published fences have been handed to a writer, on any connection.
    handed: u64,
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
    /// The reader the machine last accepted, so a loss that costs the fence can say which reader
    /// went. It is updated only when the machine acted on the event that named it, so a stale
    /// report cannot replace it with a reader that is not running.
    reader: Option<(PromptGeneration, ReaderRevision)>,
    /// Whether the last stimulus was one the machine ignored as belonging to something that ended.
    ignored: bool,
    /// The prompt generation of the acceptance being applied, while one is.
    ///
    /// The machine's record-acceptance action carries the origin alone, and a capability is about
    /// one line, so the generation the event named is kept here for the length of that apply and
    /// taken by the action that mints the capability.
    accepting: Option<PromptGeneration>,
    /// The capability the live accepted line holds, and the attachment it names.
    ///
    /// One line, one token. It is minted where the acceptance is recorded, it goes to the bridge
    /// in the answer to the event that recorded it, and it lasts exactly as long as that line runs.
    /// It outlives the fence, because the line does: a client taking the keys while the command
    /// runs invalidates the fence and changes nothing about which terminal that line was typed in.
    /// Nothing about a caller's own process says which line it belongs to; this does.
    line_token: Option<LineCapability>,
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
            .field("unwritten", &self.unwritten.len())
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
            unwritten: VecDeque::new(),
            handed: 0,
            published: None,
            live_launch: None,
            awaiting: VecDeque::new(),
            receipt: None,
            answering: None,
            reader: None,
            ignored: false,
            accepting: None,
            line_token: None,
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

    /// Returns the attachment one line's own capability names, while that line is still running.
    ///
    /// The comparison takes the same time for every token of the same length, because a caller
    /// that can ask repeatedly could otherwise learn one a byte at a time.
    #[must_use]
    pub fn detach_for_token(&self, presented: &str) -> Option<AttachmentId> {
        let held = self.line_token.as_ref()?;
        if held.token.len() != presented.len() {
            return None;
        }
        let same = held
            .token
            .bytes()
            .zip(presented.bytes())
            .fold(0_u8, |difference, (minted, presented)| {
                difference | (minted ^ presented)
            });
        (same == 0).then_some(held.attachment_id)
    }

    /// Ends the capability the accepted line holds, because that line is over.
    ///
    /// Called wherever the line this host recorded stops running: its own command block reports a
    /// status, the reader comes back at a later prompt, or the integration is lost and nothing it
    /// says can be attributed any more. A lease change is deliberately not one of them: the line
    /// goes on running and goes on belonging to the terminal it was typed in.
    fn end_line(&mut self) {
        self.line_token = None;
    }

    /// Ends the capability when the reader is at a prompt the accepted line is no longer at.
    ///
    /// A reader that enters or idles at a later generation is the shell back at its next prompt,
    /// which it reaches only once the line before it has finished. The same generation is the same
    /// prompt — a continuation, a reader that idled before the line was submitted — and leaves the
    /// capability alone.
    fn end_line_before(&mut self, prompt_generation: PromptGeneration) {
        if self
            .line_token
            .as_ref()
            .is_some_and(|held| held.prompt_generation < prompt_generation)
        {
            self.end_line();
        }
    }

    /// Ends the capability when it belongs to the line at this generation.
    ///
    /// A command block that reports a status names the generation its line was accepted at, so it
    /// ends exactly that capability and never a later one.
    fn end_line_at(&mut self, prompt_generation: PromptGeneration) {
        if self
            .line_token
            .as_ref()
            .is_some_and(|held| held.prompt_generation == prompt_generation)
        {
            self.end_line();
        }
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
    ///
    /// A fence that connection's writer was handed and did not write never will be, so nothing
    /// waits for it any more. The caller records the connection's loss on the same step, which
    /// drops the fence: the keys that were waiting then go to the terminal as input of a session
    /// that has lost its integration, not as input behind a fence.
    pub fn stop_sending(&mut self) {
        self.outbound = None;
        self.unwritten.clear();
    }

    /// Puts one frame on the connection, once everything before it has happened.
    ///
    /// Called by the session at the end of the step that produced it, never by the machine's own
    /// translation, so a frame can never overtake the session action it answers.
    pub fn send(&self, frame: Outbound) {
        if let Some(outbound) = self.outbound.as_ref() {
            let _ = outbound.send(frame);
        }
    }

    /// Hands a published fence to the connection's writer, and returns the frame everything queued
    /// for the terminal after it waits for.
    ///
    /// Called by the session on the step the machine published it, like [`Self::send`]. Nothing is
    /// returned when no connection is live, because there is then no reader for the fence to reach
    /// ahead of anything. A writer that has already ended still counts as handed the fence: its
    /// connection is over, and the loss that ends it is what lets the keys behind the fence go.
    #[must_use]
    pub fn publish(&mut self, fence: EditorFence) -> Option<FenceFrame> {
        let outbound = self.outbound.as_ref()?;
        self.handed += 1;
        let frame = FenceFrame(self.handed);
        let _ = outbound.send(Outbound::Published {
            fence: Box::new(fence),
            frame,
        });
        self.unwritten.push_back((frame, self.reading()));
        // The connection's task times the write as well as the machine, so it looks again.
        self.waker.notify_one();
        Some(frame)
    }

    /// Records that the connection's writer has written `frame`, and so every fence before it.
    ///
    /// It returns no effects of its own. What it changes is what the session's queue for the
    /// terminal may let go of, and the flush that ends every stimulus lets it go.
    pub fn fence_written(&mut self, frame: FenceFrame) -> Effects {
        while self
            .unwritten
            .front()
            .is_some_and(|(unwritten, _)| *unwritten <= frame)
        {
            self.unwritten.pop_front();
        }
        self.waker.notify_one();
        Effects::default()
    }

    /// Returns the oldest published fence the connection's writer has not written, if any.
    ///
    /// It and every fence handed over after it are unwritten, and every fence before it has been
    /// written or has gone with its connection.
    #[must_use]
    pub fn unwritten_fence(&self) -> Option<FenceFrame> {
        self.unwritten.front().map(|(frame, _)| *frame)
    }

    /// Returns how long the oldest unwritten fence may still wait for the writer, when there is one.
    ///
    /// Zero once [`FENCE_WRITE_LIMIT`] has passed, and the connection's task then ends the
    /// connection. It is read on the same clock as the machine's own deadline.
    #[must_use]
    pub fn fence_write_deadline(&self) -> Option<Duration> {
        let (_, handed) = self.unwritten.front()?;
        let limit = u64::try_from(FENCE_WRITE_LIMIT.as_millis()).unwrap_or(u64::MAX);
        Some(Duration::from_millis(
            handed
                .plus(limit)
                .get()
                .saturating_sub(self.reading().get()),
        ))
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
        // Nothing this session says about its lines can be relied on after a loss: the hooks, the
        // reader or the root shell itself has gone, so the host would never learn that the line
        // the capability names had ended. It ends here instead, and a detach that names nothing
        // is answered with the hint.
        self.end_line();
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
                steps: vec![Step::Launch(
                    transaction,
                    Box::new(LaunchAnswer::Refused {
                        reason,
                        code: reason.code(),
                    }),
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
            // Neither is a fence question. The clock is still swept, for the reason `received`
            // gives, and the answer is the session's to make.
            BridgeEvent::CommandResolve(params) => {
                self.command_hook(CommandHook::Resolve(params.clone()))
            }
            BridgeEvent::CommandBlock(params) => {
                // A block that reports a status is its line's own ending, said by the integration
                // that ran it. A block for a line still running says nothing about the capability,
                // and one for another generation is not about this line at all.
                if params.finished() {
                    self.end_line_at(params.prompt_generation);
                }
                self.command_hook(CommandHook::Block(params.clone()))
            }
            BridgeEvent::HooksActivated(_) => {
                let _ = self.phase.qualified();
                self.received()
            }
            BridgeEvent::GestureChanged(_) | BridgeEvent::PreEofConsumed(_) => self.received(),
            BridgeEvent::IntegrationLost(report) => {
                let mut effects = self.integration_lost(report.loss);
                self.answer(&mut effects, EventOutcome::Received);
                effects
            }
        }
    }

    /// Sweeps the clock and hands one command hook to the session to answer.
    fn command_hook(&mut self, hook: CommandHook) -> Effects {
        let mut effects = self.apply(&Stimulus::HoldExpired, Context::Other);
        if let Some(id) = self.answering {
            effects.steps.push(Step::CommandHook(id, Box::new(hook)));
        }
        effects
    }

    /// Answers an event the machine has no stimulus for, sweeping the clock on the way.
    ///
    /// The sweep is the point: a deadline is a fact about the clock rather than about which message
    /// arrives next, and a reader that keeps sending events the machine does not act on must not be
    /// able to postpone a hold's expiry by keeping this task busy.
    fn received(&mut self) -> Effects {
        let mut effects = self.apply(&Stimulus::HoldExpired, Context::Other);
        self.answer(&mut effects, EventOutcome::Received);
        effects
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
        // The reader back at a later prompt is the line before it finished, whatever else this
        // entry decides. A capability for a line that is over names nothing.
        self.end_line_before(params.prompt_generation);
        if !self.phase.retains_fence() {
            // Below a qualified session there is no fence to hold. The reader is answered so it
            // does not wait, and nothing starts an exchange: a startup profile that asks a question
            // reads its input in its own context, exactly as section 7 paragraph 4 requires.
            let mut effects = self.apply(&Stimulus::HoldExpired, Context::Other);
            self.answer(
                &mut effects,
                EventOutcome::EditorEntered(RootEditorEnterResult {
                    state: self.machine.state(),
                    fence_exchange: Nullable::null(),
                }),
            );
            return effects;
        }
        let candidate_fence = FenceId::new(kr_ipc::new_uuid());
        let mut effects = self.apply(
            &Stimulus::EditorEntered(EditorEntered {
                params: params.clone(),
                candidate_fence,
            }),
            Context::Other,
        );
        // The reader the machine accepted, remembered so a loss that costs the fence can name the
        // reader it deregisters. An event the machine ignored as stale leaves it alone.
        if !self.ignored {
            self.reader = Some((params.prompt_generation, params.reader_revision));
        }
        // The exchange the entry started, when the machine started one: a fence a client is told
        // about is one the reader has actually been asked for.
        let started = self.machine.deadline().is_some();
        self.answer(
            &mut effects,
            EventOutcome::EditorEntered(RootEditorEnterResult {
                state: self.machine.state(),
                fence_exchange: if started {
                    Nullable::some(candidate_fence)
                } else {
                    Nullable::null()
                },
            }),
        );
        effects
    }

    fn editor_left(&mut self, params: &RootEditorLeaveParams) -> Effects {
        let mut effects = self.apply(&Stimulus::EditorLeft(params.clone()), Context::Other);
        if !self.ignored {
            self.reader = None;
        }
        self.answer(
            &mut effects,
            EventOutcome::EditorLeft(RootEditorLeaveResult {
                state: self.machine.state(),
            }),
        );
        effects
    }

    fn reader_idled(&mut self, idle: &ReaderIdle) -> Effects {
        // Idle at a later prompt is the same statement an entry makes: the line before it is over.
        self.end_line_before(idle.prompt_generation);
        if !self.phase.retains_fence() {
            return self.received();
        }
        let mut effects = self.apply(
            &Stimulus::ReaderIdled(ReaderIdled {
                idle: idle.clone(),
                candidate_fence: FenceId::new(kr_ipc::new_uuid()),
            }),
            Context::Other,
        );
        if !self.ignored {
            self.reader = Some((idle.prompt_generation, idle.reader_revision));
        }
        self.answer(&mut effects, EventOutcome::Received);
        effects
    }

    fn detach_submitted(&mut self, params: &RootEofDetachParams) -> Effects {
        self.apply(&Stimulus::DetachSubmitted(params.clone()), Context::Other)
    }

    fn command_accepted(&mut self, params: &RootCommandAcceptedParams) -> Effects {
        // The line this acceptance is about, for the capability the record-acceptance action
        // mints. It is taken there and dropped here if the machine records nothing.
        self.accepting = Some(params.prompt_generation);
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
        let effects = self.apply(&Stimulus::CommandAccepted(params), Context::Other);
        // An acceptance the machine ignored as stale records nothing, so nothing took this.
        self.accepting = None;
        effects
    }

    /// Answers the event being processed.
    ///
    /// An action that answers an event can only ever run while one is being processed: a detach is
    /// acknowledged or refused because a detach arrived, and an acceptance is recorded because an
    /// acceptance arrived. Outside that there is nothing to correlate an answer with, and none is
    /// sent.
    fn answer(&mut self, effects: &mut Effects, outcome: EventOutcome) {
        if let Some(id) = self.answering {
            effects.steps.push(Step::Send(Outbound::EventResult {
                id,
                result: Box::new(outcome),
            }));
        }
    }

    fn apply(&mut self, stimulus: &Stimulus, context: Context) -> Effects {
        let at = self.reading();
        let outcome = self.machine.apply(at, stimulus);
        let mut effects = Effects::default();
        // What the machine did with it. A reader event it ignored belongs to something that has
        // ended, and nothing this driver remembers may be updated from one. The machine sweeps its
        // own deadlines before it reads the stimulus, so an expiry can put actions of its own in
        // front of the refusal: the refusal is looked for anywhere in the list, not only alone.
        self.ignored = outcome
            .actions
            .iter()
            .any(|action| matches!(action, Action::IgnoreStale(StaleMessage::ReaderEvent)));
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
                effects.steps.push(Step::Send(Outbound::Request(Box::new(
                    WorkerRequest::Fence(params.clone()),
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
                    effects.steps.push(Step::Write(held.batch));
                }
            }
            Action::Release(order) => {
                for input in order {
                    if let Some(held) = self.hold.remove(input) {
                        if held.charged {
                            effects.held_removed =
                                effects.held_removed.saturating_add(held.batch.len());
                        }
                        effects.steps.push(Step::Write(held.batch));
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
                effects.steps.push(Step::Send(Outbound::Request(Box::new(
                    WorkerRequest::Cancel(cancel.clone()),
                ))));
            }
            Action::PublishFence(fence) => {
                self.published = Some(fence.fence_id);
                effects.steps.push(Step::Publish(Box::new(fence.clone())));
            }
            Action::WithholdFence(reason) => {
                effects.steps.push(Step::Send(Outbound::Withheld {
                    reason: *reason,
                    state,
                }));
            }
            Action::InvalidateFence(reason) => {
                if let Some(fence_id) = self.published.take() {
                    effects.steps.push(Step::Send(Outbound::Invalidated {
                        fence_id,
                        reason: withheld_for(*reason),
                        state,
                    }));
                }
            }
            Action::EmitEditorBusy(event) => effects
                .steps
                .push(Step::EditorBusy(Box::new(event.clone()))),
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
            Action::RemoveAttachment(attachment) => {
                effects.steps.push(Step::RemoveAttachment(*attachment));
            }
            Action::AcknowledgeDetach(result) => {
                self.answer(&mut effects, EventOutcome::Detached(result.clone()));
            }
            Action::RejectDetach(rejection) => {
                self.answer(
                    &mut effects,
                    EventOutcome::Refused(detach_error(*rejection)),
                );
            }
            Action::SendLaunch(request) => {
                self.live_launch = Some(request.transaction);
                effects.steps.push(Step::Send(Outbound::Request(Box::new(
                    WorkerRequest::Launch(request.clone()),
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
                effects.steps.push(Step::Send(Outbound::Revocation {
                    transaction: *transaction,
                    reason: *reason,
                }));
            }
            Action::InstallLaunch(result) => {
                if let Some(transaction) = self.resolve_launch(context) {
                    effects.steps.push(Step::Launch(
                        transaction,
                        Box::new(LaunchAnswer::Installed(result.clone())),
                    ));
                }
            }
            Action::RejectLaunch { reason, code } => {
                if let Some(transaction) = self.resolve_launch(context) {
                    effects.steps.push(Step::Launch(
                        transaction,
                        Box::new(LaunchAnswer::Refused {
                            reason: *reason,
                            code: *code,
                        }),
                    ));
                }
            }
            Action::Interrupt(action) => effects.steps.push(Step::Interrupt(*action)),
            Action::RefuseInterrupt(fault) => effects.interrupt_refused = Some(*fault),
            Action::RecordAcceptance(origin) => {
                effects.acceptance = Some(origin.clone());
                // A capability for this line and for no other. A line this host could not
                // attribute gets none, because there is nothing for a token to name, and the one
                // the line before it held ends here either way.
                let prompt_generation = self.accepting.take();
                self.line_token = match (&origin, prompt_generation) {
                    (AcceptedOrigin::Fenced { attachment_id, .. }, Some(prompt_generation)) => {
                        Some(LineCapability {
                            token: kr_ipc::new_uuid().to_string(),
                            attachment_id: *attachment_id,
                            prompt_generation,
                        })
                    }
                    _ => None,
                };
                self.answer(
                    &mut effects,
                    EventOutcome::CommandRecorded(RootCommandAcceptedResult {
                        origin: origin.clone(),
                        detach_token: Nullable(
                            self.line_token.as_ref().map(|held| held.token.clone()),
                        ),
                        state,
                    }),
                );
            }
            Action::RetainAcceptance(origin) => {
                // Input a running command read through the editor. The record and the capability
                // both belong to the line that started that command and neither is touched; the
                // bridge is told what still stands and is given no capability, because nothing is
                // about to run that one would belong to.
                self.accepting = None;
                self.answer(
                    &mut effects,
                    EventOutcome::CommandRecorded(RootCommandAcceptedResult {
                        origin: origin.clone().unwrap_or(AcceptedOrigin::Unverifiable),
                        detach_token: Nullable::null(),
                        state,
                    }),
                );
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
                effects.steps.push(Step::Receipt(receipt));
            }
            Action::LateInstallation(result) => effects
                .steps
                .push(Step::LateInstallation(Box::new(result.clone()))),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kr_protocol::ids::AttachmentId;
    use kr_protocol::root::{
        CwdRevision, EditorBufferRevision, EditorKeymap, EditorState, FenceAcknowledgement,
        KeyQueueSnapshot, LaunchCommand, PendingReaderInput, ReaderContext,
    };
    use kr_protocol::scalars::Uuid;
    use kr_shell_integration::contract::events::HooksActivated;
    use kr_transport::clock::ManualClock;

    use super::*;

    fn session() -> SessionId {
        SessionId::new(Uuid::from_bytes([0x37; 16]))
    }

    fn lease() -> LeaseView {
        LeaseView {
            epoch: InputLeaseEpoch::new(1),
            holder: Some(AttachmentId::new(Uuid::from_bytes([0x41; 16]))),
        }
    }

    fn editor() -> EditorState {
        EditorState {
            buffer_empty: true,
            buffer_revision: EditorBufferRevision::new(1),
            keymap: EditorKeymap::Emacs,
            pending: PendingReaderInput::NONE,
        }
    }

    fn entered(prompt: u64, revision: u64) -> BridgeEvent {
        BridgeEvent::EditorEnter(RootEditorEnterParams {
            session_id: session(),
            root_process: kr_ipc::identity::current_process_start_identity().expect("this process"),
            prompt_generation: PromptGeneration::new(prompt),
            reader_revision: ReaderRevision::new(revision),
            reader_context: ReaderContext::Primary,
            editor: editor(),
            cwd_revision: CwdRevision::new(1),
        })
    }

    fn left(prompt: u64, revision: u64) -> BridgeEvent {
        BridgeEvent::EditorLeave(RootEditorLeaveParams {
            session_id: session(),
            prompt_generation: PromptGeneration::new(prompt),
            reader_revision: ReaderRevision::new(revision),
            reason: EditorLeaveReason::Cancellation,
        })
    }

    fn idled(prompt: u64, revision: u64) -> BridgeEvent {
        BridgeEvent::ReaderIdle(ReaderIdle {
            session_id: session(),
            prompt_generation: PromptGeneration::new(prompt),
            reader_revision: ReaderRevision::new(revision),
            reader_context: ReaderContext::Primary,
            snapshot: KeyQueueSnapshot::drained(),
            editor: editor(),
            cwd_revision: CwdRevision::new(1),
        })
    }

    /// A driver whose bridge has registered, whose hooks are live and whose reader is in an
    /// exchange that has not been answered.
    fn qualified(clock: &Arc<ManualClock>) -> FenceDriver {
        let mut driver = FenceDriver::new(session(), lease(), Arc::clone(clock) as Arc<_>);
        assert!(driver.registered(ShellKind::Zsh));
        let _ = driver.bridge_event(
            RequestId::new(1),
            &BridgeEvent::HooksActivated(HooksActivated {
                session_id: session(),
                prompt_generation: PromptGeneration::new(1),
            }),
        );
        assert!(driver.phase().retains_fence());
        driver
    }

    #[test]
    fn a_stale_report_that_arrives_after_a_deadline_does_not_take_the_reader_with_it() {
        // The machine sweeps its own deadlines before it reads a message, so a stale report that
        // arrives late produces the expiry's actions and then the refusal. Both belong to the same
        // outcome, and the refusal is what says the reader named in the report is not the running
        // one: nothing the driver remembers may be replaced from it.
        let clock = Arc::new(ManualClock::new());
        let mut driver = qualified(&clock);
        let _ = driver.bridge_event(RequestId::new(2), &entered(2, 2));
        clock.advance(Duration::from_millis(400));
        let _ = driver.bridge_event(RequestId::new(3), &left(1, 1));

        // The reader entered at (2, 2) is still the one running, so a loss that costs the fence
        // deregisters it and the machine leaves the editor behind.
        let _ = driver.integration_lost(IntegrationLoss::SemanticHookLoss);
        assert_eq!(driver.state(), FenceState::Outside);
    }

    #[test]
    fn a_stale_idle_that_arrives_after_a_deadline_does_not_become_the_remembered_reader() {
        let clock = Arc::new(ManualClock::new());
        let mut driver = qualified(&clock);
        let _ = driver.bridge_event(RequestId::new(2), &entered(3, 3));
        clock.advance(Duration::from_millis(400));
        let _ = driver.bridge_event(RequestId::new(3), &idled(1, 1));
        let _ = driver.integration_lost(IntegrationLoss::SemanticHookLoss);
        assert_eq!(driver.state(), FenceState::Outside);
    }

    #[test]
    fn the_steps_stay_in_the_order_the_machine_listed_its_actions() {
        // One list, in the machine's own order. An interrupt that revokes a launch revokes it
        // first.
        let clock = Arc::new(ManualClock::new());
        let mut driver = qualified(&clock);
        let effects = driver.bridge_event(RequestId::new(2), &entered(1, 1));
        let fence_id = effects
            .steps
            .iter()
            .find_map(|step| match step {
                Step::Send(Outbound::Request(request)) => match request.as_ref() {
                    WorkerRequest::Fence(params) => Some(params.fence_id),
                    _ => None,
                },
                _ => None,
            })
            .expect("the reader was asked for a fence");
        let _ = driver.bridge_answer(&BridgeAnswer::Fence(
            kr_protocol::root::RootEditorFenceResult::Acknowledged(FenceAcknowledgement {
                fence_id,
                reader_context: ReaderContext::Primary,
                prompt_generation: PromptGeneration::new(1),
                reader_revision: ReaderRevision::new(1),
                queues: kr_protocol::root::QueueDrainReport::CLEAR,
                snapshot: KeyQueueSnapshot::drained(),
                editor: editor(),
                cwd_revision: CwdRevision::new(1),
            }),
        ));
        assert!(driver.fence().is_some(), "the fence is published");
        let requester = lease().holder.expect("a holder");
        let transaction = LaunchTransactionId::new(kr_ipc::new_uuid());
        let effects = driver.launch_requested(
            ShellLaunchParams {
                session_id: session(),
                command: LaunchCommand::Arguments(vec!["ls".to_owned()]),
                expected_prompt_generation: PromptGeneration::new(1),
                expected_buffer_revision: EditorBufferRevision::new(1),
            },
            requester,
            transaction,
        );
        assert!(
            effects
                .steps
                .iter()
                .any(|step| matches!(step, Step::Send(Outbound::Request(_)))),
            "the launch reached the reader: {:?}",
            effects.steps
        );

        // The reader never answers. The interrupt arrives after the transaction's deadline, so the
        // same outcome revokes the launch and then interrupts.
        clock.advance(Duration::from_millis(400));
        let effects = driver.interrupt_requested(
            requester,
            InputLeaseEpoch::new(1),
            InterruptAction::NativeInterrupt,
        );
        let revoked = effects
            .steps
            .iter()
            .position(|step| matches!(step, Step::Send(Outbound::Revocation { .. })));
        let interrupted = effects
            .steps
            .iter()
            .position(|step| matches!(step, Step::Interrupt(_)));
        let (Some(revoked), Some(interrupted)) = (revoked, interrupted) else {
            panic!("both the revocation and the interrupt: {:?}", effects.steps);
        };
        assert!(
            revoked < interrupted,
            "the launch is revoked before the interrupt that revoked it: {:?}",
            effects.steps
        );
    }

    /// The acknowledged fence and the held keys, as the steps the session carries out.
    fn acknowledged(driver: &mut FenceDriver) -> Effects {
        let effects = driver.bridge_event(RequestId::new(2), &entered(1, 1));
        let fence_id = effects
            .steps
            .iter()
            .find_map(|step| match step {
                Step::Send(Outbound::Request(request)) => match request.as_ref() {
                    WorkerRequest::Fence(params) => Some(params.fence_id),
                    _ => None,
                },
                _ => None,
            })
            .expect("the reader was asked for a fence");
        let held = driver.input_arrived(
            lease().holder.expect("a holder"),
            InputLeaseEpoch::new(1),
            InputBatch::Lease {
                epoch: 1,
                bytes: b"held".to_vec(),
                paste: crate::session::PasteTransition::default(),
                authority_deadline_boot_ms: None,
            },
        );
        assert_eq!(
            held.held_added, 4,
            "the keys wait while the reader is asked"
        );
        driver.bridge_answer(&BridgeAnswer::Fence(
            kr_protocol::root::RootEditorFenceResult::Acknowledged(FenceAcknowledgement {
                fence_id,
                reader_context: ReaderContext::Primary,
                prompt_generation: PromptGeneration::new(1),
                reader_revision: ReaderRevision::new(1),
                queues: kr_protocol::root::QueueDrainReport::CLEAR,
                snapshot: KeyQueueSnapshot::drained(),
                editor: editor(),
                cwd_revision: CwdRevision::new(1),
            }),
        ))
    }

    #[test]
    fn a_fence_is_published_before_the_keys_it_lets_go_of_and_waited_for_until_written() {
        let clock = Arc::new(ManualClock::new());
        let mut driver = qualified(&clock);
        let (outbound, mut writer) = tokio::sync::mpsc::unbounded_channel();
        driver.send_through(outbound);

        let effects = acknowledged(&mut driver);
        let published = effects
            .steps
            .iter()
            .position(|step| matches!(step, Step::Publish(_)));
        let released = effects
            .steps
            .iter()
            .position(|step| matches!(step, Step::Write(_)));
        let (Some(published), Some(released)) = (published, released) else {
            panic!("both the fence and the keys: {:?}", effects.steps);
        };
        assert!(
            published < released,
            "the fence is published before the keys it lets go of: {:?}",
            effects.steps
        );
        let fence = driver.fence().cloned().expect("a published fence");

        // Handed to the writer, the fence is numbered and waited for until the writer says it is
        // written, and for no longer than the limit.
        let frame = driver
            .publish(fence.clone())
            .expect("a live connection takes it");
        assert_eq!(
            writer.try_recv().expect("the writer has it"),
            Outbound::Published {
                fence: Box::new(fence.clone()),
                frame,
            }
        );
        assert_eq!(driver.unwritten_fence(), Some(frame));
        assert_eq!(driver.fence_write_deadline(), Some(FENCE_WRITE_LIMIT));
        clock.advance(FENCE_WRITE_LIMIT);
        assert_eq!(driver.fence_write_deadline(), Some(Duration::ZERO));
        let _ = driver.fence_written(frame);
        assert_eq!(driver.unwritten_fence(), None);
        assert_eq!(driver.fence_write_deadline(), None);

        // Written in order, so a later frame written is every earlier one written too.
        let first = driver.publish(fence.clone()).expect("taken");
        let second = driver.publish(fence.clone()).expect("taken");
        assert!(first < second);
        assert_eq!(driver.unwritten_fence(), Some(first));
        let _ = driver.fence_written(second);
        assert_eq!(driver.unwritten_fence(), None);

        // One the connection never writes stops being waited for when the connection ends.
        let _ = driver.publish(fence.clone()).expect("taken");
        driver.stop_sending();
        assert_eq!(driver.unwritten_fence(), None);
        // With no connection there is no reader for a fence to reach ahead of anything.
        assert_eq!(driver.publish(fence), None);
    }
}
