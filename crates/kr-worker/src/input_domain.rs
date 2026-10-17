//! The input domain: everything a keystroke, and the recogniser's timer, touch.
//!
//! A keystroke has one rule to keep, section 27's: a lone Escape and every partial paste prefix are
//! held no longer than the recogniser's deadline, measured from the write's arrival. Whatever the
//! session is busy with, a journalled mutation's commits, a pass of maintenance, a read of the
//! history, the application is waiting for that key. So the state that decides what becomes of a
//! keystroke does not live in the session. It lives here, behind a lock of its own that nothing
//! holds across a disk call, and the session reaches it the way everything else does.
//!
//! What is in it: the recogniser, with the prefix it holds and the deadlines of the authority
//! behind that prefix; the input lease with its epoch; the queue of what is on its way to the
//! terminal and the accounting for it; the root editor's fence machine with the batches it holds;
//! the lifecycle's answer to whether input is accepted; the capabilities each attachment was
//! granted and which of them were granted under a grant; and the places the terminal's writer
//! shares with all of it. The fields are in [`InputDomain`] and nowhere else, so the compiler sends
//! every access through the lock.
//!
//! # Lock order
//!
//! The dispatch barrier, then the session, then this, then the terminal writer's gate. The session
//! may be held while this is taken; this is never held while the session is taken. Nothing is done
//! under this lock that waits: no disk call, no journal or ledger commit, no process call, no
//! `await`, no waiting for another lock but the writer's gate, which is held for one non-blocking
//! write.
//!
//! # What waits for the session
//!
//! Some steps the root editor's machine asks for need the session: an `editor_busy` event for an
//! attachment's subscription, the removal of an attachment, the interrupt of the foreground
//! process group, and the answer to a command hook. [`InputDomain::apply_effects`] carries out
//! every other step in the machine's order and hands these back, with whatever the machine ordered
//! after one of them (an `editor_busy` event holds nothing back, because it only tells a
//! subscriber what happened), for the session to carry out with this lock let go.
//!
//! What a keystroke or the timer leaves for the session is only ever an `editor_busy` event. It
//! waits in the domain until the next stimulus the session applies, which hands it back in front of
//! its own steps in the same hold, or until the pump takes it, so the events a subscriber is told
//! are told in the order the machine produced them.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use kr_protocol::attachment::AttachmentCapability;
use kr_protocol::ids::{AttachmentId, AuthorityRevision, ConnectionId, InputLeaseEpoch, SessionId};
use kr_protocol::input::InputLeaseState;
use kr_protocol::scalars::CanonicalSet;
use kr_protocol::session::SessionState;
use kr_shell_integration::contract::fence::LeaseView;
use kr_shell_integration::contract::requests::LaunchTransactionId;

use crate::error::{Result, WorkerError};
use crate::fence::{Effects, FenceDriver, FenceFrame, Outbound, Step, TakeoverReceipt};
use crate::input::{InputLease, LeaseRefusal, PASTE_END, PasteFramer, TakeoverFraming};
use crate::session::{
    FenceOutcome, GrantedBy, InputAccepted, InputAuthority, InputBatch, Interrupted, LeaseEnded,
    MAX_PENDING_REPLY_BYTES, MAX_QUEUED_INPUT_BYTES, PasteTransition,
};

/// One entry in a session's queue for the pseudo-terminal.
#[derive(Debug)]
pub(crate) enum Queued {
    /// A batch for the writer.
    Batch(InputBatch),
    /// A fence published to the bridge at this point.
    ///
    /// What is queued behind it waits until the bridge's writer has written the fence, or until the
    /// connection it was handed to has ended and the session has recorded the loss.
    Fence(FenceFrame),
}

/// The lock a session's input domain sits behind, and what wakes the pump that serves it.
#[derive(Debug)]
pub struct InputShared {
    domain: Mutex<InputDomain>,
    /// Woken when something is owed that only the session can do: a reply the gate now lets out,
    /// or a step the root editor's machine asked for that needs the session.
    pump: tokio::sync::Notify,
}

impl InputShared {
    /// Wraps a domain.
    pub(crate) fn new(domain: InputDomain) -> Arc<Self> {
        Arc::new(Self {
            domain: Mutex::new(domain),
            pump: tokio::sync::Notify::new(),
        })
    }

    /// Takes the input domain.
    ///
    /// # Panics
    ///
    /// Panics when an earlier holder panicked, which means the state can no longer be trusted.
    pub fn lock(&self) -> InputGuard<'_> {
        // The lock is not re-entrant: a thread that takes it again while it holds it waits for
        // itself for ever. In a build that checks, that is a panic that names the mistake.
        #[cfg(debug_assertions)]
        assert!(
            HELD.with(std::cell::Cell::get) == 0,
            "the input domain was taken by a thread that already holds it"
        );
        InputGuard::new(
            self.domain
                .lock()
                .expect("the input domain is not poisoned"),
        )
    }

    /// Returns the lifecycle state when the domain is free to be looked at, for a `Debug` that
    /// must not wait for it.
    #[must_use]
    pub fn try_state(&self) -> Option<SessionState> {
        self.domain.try_lock().ok().map(|domain| domain.state())
    }

    /// Returns what the terminal's writer has written to the pseudo-terminal, for this host's own
    /// tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn terminal_writes(&self) -> Vec<crate::testing::TerminalWrite> {
        let writes = Arc::clone(&self.lock().writer().terminal_writes);
        writes.all()
    }

    /// Asks the pump to take the session and do what is owed.
    pub fn wake_pump(&self) {
        self.pump.notify_one();
    }

    /// Waits until the pump is asked for.
    pub(crate) async fn pump_asked(&self) {
        self.pump.notified().await;
    }
}

#[cfg(debug_assertions)]
thread_local! {
    /// How many times this thread holds an input domain.
    static HELD: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Fails in a debug build when this thread holds an input domain.
///
/// The domain is never held across a disk call, a journal, spool, question or ledger commit, a
/// process call or a wait, and the session is never taken while it is held. The places that begin
/// one of those call this first, so a change that breaks the rule fails where it is made and not
/// as a keystroke that is late on a machine with a busy disk.
#[cfg(debug_assertions)]
pub fn assert_not_held(what: &str) {
    assert!(
        HELD.with(std::cell::Cell::get) == 0,
        "{what} was begun with the input domain held, which a keystroke would wait behind"
    );
}

/// The same, in a build that does not check.
#[cfg(not(debug_assertions))]
pub const fn assert_not_held(_what: &str) {}

/// The input domain, taken.
#[derive(Debug)]
pub struct InputGuard<'a> {
    guard: MutexGuard<'a, InputDomain>,
}

impl<'a> InputGuard<'a> {
    fn new(guard: MutexGuard<'a, InputDomain>) -> Self {
        #[cfg(debug_assertions)]
        HELD.with(|held| held.set(held.get() + 1));
        Self { guard }
    }
}

#[cfg(debug_assertions)]
impl Drop for InputGuard<'_> {
    fn drop(&mut self) {
        HELD.with(|held| held.set(held.get() - 1));
    }
}

impl std::ops::Deref for InputGuard<'_> {
    type Target = InputDomain;

    fn deref(&self) -> &InputDomain {
        &self.guard
    }
}

impl std::ops::DerefMut for InputGuard<'_> {
    fn deref_mut(&mut self) -> &mut InputDomain {
        &mut self.guard
    }
}

/// The root editor's driver to look at, with the input domain held for as long as it is looked at.
///
/// Only a session held mutably steps the machine, through [`FenceGuard`].
#[derive(Debug)]
pub struct FenceView<'a> {
    guard: InputGuard<'a>,
}

impl<'a> FenceView<'a> {
    /// Looks at the driver of a managed session; `None` for one that has none.
    pub(crate) fn of(guard: InputGuard<'a>) -> Option<Self> {
        guard.fence.is_some().then_some(Self { guard })
    }
}

impl std::ops::Deref for FenceView<'_> {
    type Target = FenceDriver;

    fn deref(&self) -> &FenceDriver {
        self.guard
            .fence
            .as_ref()
            .expect("a view is made only for a session that has a driver")
    }
}

/// The root editor's driver to step, with the input domain held for as long as it is.
#[derive(Debug)]
pub struct FenceGuard<'a> {
    guard: InputGuard<'a>,
}

impl<'a> FenceGuard<'a> {
    /// Looks at the driver of a managed session; `None` for one that has none.
    pub(crate) fn of(guard: InputGuard<'a>) -> Option<Self> {
        guard.fence.is_some().then_some(Self { guard })
    }
}

impl std::ops::Deref for FenceGuard<'_> {
    type Target = FenceDriver;

    fn deref(&self) -> &FenceDriver {
        self.guard
            .fence
            .as_ref()
            .expect("a guard is made only for a session that has a driver")
    }
}

impl std::ops::DerefMut for FenceGuard<'_> {
    fn deref_mut(&mut self) -> &mut FenceDriver {
        self.guard
            .fence
            .as_mut()
            .expect("a guard is made only for a session that has a driver")
    }
}

/// What one stimulus to the root editor's machine left for the session.
#[derive(Debug, Default)]
pub struct Applied {
    /// What the stimulus says about itself.
    pub outcome: FenceOutcome,
    /// The steps that need the session, in the machine's order.
    pub owed: Vec<Step>,
}

/// What accepting a batch of a client's input produced.
#[derive(Debug)]
pub struct Accepted {
    /// What the caller is told.
    pub accepted: InputAccepted,
    /// The steps that need the session.
    pub owed: Vec<Step>,
    /// Whether this input opened the gate the response lane was waiting on.
    pub opened_the_gate: bool,
}

/// The handles the terminal's writer shares with the domain.
///
/// The writer thread holds clones of them. They are the one place a thread other than a holder of
/// the domain reads or writes its state, and each is an atomic or the writer's own gate.
#[derive(Debug)]
pub(crate) struct WriterHandles {
    /// The boundary the writer and a lease change share.
    pub(crate) gate: Arc<Mutex<()>>,
    /// Set by the writer on its way out, when the terminal will take nothing more.
    pub(crate) terminal_gone: Arc<AtomicBool>,
    /// Every byte queued for the pseudo-terminal, across every producer, released by the writer.
    pub(crate) queued_input_bytes: Arc<AtomicUsize>,
    /// The part of that which belongs to the current lease.
    pub(crate) queued_lease_bytes: Arc<crate::runtime::LeaseBytes>,
    /// How many answers the writer has dropped because their lane deadline passed.
    pub(crate) dropped_replies: Arc<AtomicU64>,
    /// How many bytes of the host's own answers are queued and neither written nor dropped.
    pub(crate) unwritten_replies: Arc<AtomicUsize>,
    /// Whether the application is inside a bracketed paste, as the writer has delivered it.
    pub(crate) delivered_paste_open: Arc<AtomicU64>,
    /// The lease epoch the writer compares every queued batch against.
    pub(crate) input_fence: Arc<AtomicU64>,
    /// Set while a lease change is queued for the writer and not yet taken.
    pub(crate) lease_change_queued: Arc<AtomicBool>,
    /// What the writer wrote to the pseudo-terminal, for this host's own tests.
    #[cfg(feature = "testing")]
    pub(crate) terminal_writes: Arc<crate::testing::TerminalWrites>,
}

impl WriterHandles {
    fn new() -> Self {
        Self {
            gate: Arc::new(Mutex::new(())),
            terminal_gone: Arc::new(AtomicBool::new(false)),
            queued_input_bytes: Arc::new(AtomicUsize::new(0)),
            queued_lease_bytes: Arc::new(crate::runtime::LeaseBytes::new()),
            dropped_replies: Arc::new(AtomicU64::new(0)),
            unwritten_replies: Arc::new(AtomicUsize::new(0)),
            delivered_paste_open: Arc::new(AtomicU64::new(0)),
            input_fence: Arc::new(AtomicU64::new(0)),
            lease_change_queued: Arc::new(AtomicBool::new(false)),
            #[cfg(feature = "testing")]
            terminal_writes: Arc::default(),
        }
    }
}

/// Everything a keystroke and the recogniser's timer touch.
#[derive(Debug)]
pub struct InputDomain {
    /// The session's lifecycle state. Whether input is accepted is a question about it, so it lives
    /// here: the admission of a close and the refusal of the next keystroke are one step.
    state: SessionState,
    /// The session this domain belongs to, which a keystroke's request names.
    session_id: SessionId,
    lease: InputLease,
    framer: PasteFramer,
    /// What a lease that ended without anybody asking left behind, waiting to be reported.
    ///
    /// A takeover reports what the lease it displaced lost, in its own answer. A lease the host
    /// ends by itself - because the application changed the keyboard negotiation to one that holder
    /// cannot produce - has no such answer to be reported in, and dropping the count would make the
    /// interruption unreportable. It is carried here until the next acquire, which reports it with
    /// its own.
    interrupted: Interrupted,
    /// When the authority behind the bytes the recogniser is still holding runs out.
    ///
    /// A held delimiter prefix is queued later than the write that produced it: by its own
    /// deadline, by the paste mode being turned off, or by the next write completing it. It is
    /// still that write's authority that admitted it. The tightest deadline of the writes whose
    /// bytes are in the prefix is what it carries, so a prefix that outlived the grant behind it
    /// is fenced with everything else that grant sent.
    held_input_deadline: Option<u64>,
    /// The same, in UTC milliseconds: the end of the membership lease a local owner's bytes were
    /// accepted under, which a wall clock set forward passes while the continuous clock does not.
    held_input_utc_deadline: Option<u64>,
    /// What each attachment was granted. Written by the attach and the detach, which take the
    /// session and then this, and read by a keystroke, which takes only this.
    capabilities: BTreeMap<AttachmentId, CanonicalSet<AttachmentCapability>>,
    /// The attachments made under a grant: by every caller but the local owner, whichever socket
    /// it came in on.
    ///
    /// An authority revision fences what those attachments were admitted to do, and an attachment
    /// identifier is the only thing the input lease records about who holds it. The local owner's
    /// attachments are not in here, because its authority is the operating-system identity the
    /// socket authenticated and no revision replaces that.
    ///
    /// Each is kept with the grant and the device its caller carried, which is what a revision's
    /// reach is read against.
    granted_attachments: BTreeMap<AttachmentId, GrantedBy>,
    /// What is queued for the pseudo-terminal and not yet handed to its writer, in order.
    ///
    /// Only [`InputDomain::take_pending`] takes from it, and it stops at a published fence the
    /// bridge's writer has not written yet.
    pending: VecDeque<Queued>,
    /// Accepted bytes the root editor's machine is holding for a reader transition.
    held_input_bytes: usize,
    writer: WriterHandles,
    /// The root editor's fence and detach machine, for a managed session.
    ///
    /// `None` is a session that claims none of that contract: a `native_compat` shell, where input
    /// forwards like any application's, Ctrl-D is the shell's own and nothing is ever installed in
    /// an editor.
    fence: Option<FenceDriver>,
    /// The authority revision this worker last installed and acknowledged.
    ///
    /// It is here, with the lease and the input fence, because installing a revision and fencing
    /// the input granted under what it removed are one step: a keystroke that was validated under
    /// an earlier revision is refused from the moment this moves, and the lease of a caller the
    /// revision reaches is gone in the same hold.
    revision: Option<AuthorityRevision>,
    /// Steps of the root editor's machine that need the session, left here by a keystroke or the
    /// timer, which cannot take it: events, nothing else. The next stimulus the session applies
    /// hands them back in front of its own steps, or the pump carries them out.
    owed: Vec<Step>,
    /// Whether the response lane held replies the gate allows out after the last time it was
    /// drained. A keystroke that sees this asks the pump to look again, because the lane is the
    /// session's and a keystroke does not take the session.
    replies_waiting: bool,
    /// The last takeover receipt the machine completed.
    takeover_receipt: Option<TakeoverReceipt>,
    /// The callers waiting for a reader to say what it did with their launch.
    ///
    /// They live beside the machine, because every answer is produced by a step of the machine: an
    /// answer that arrives with a closure, a lost bridge or a reader's decision is delivered on
    /// the same step that produced it, and none can be dropped on the way out.
    launches: BTreeMap<
        LaunchTransactionId,
        tokio::sync::oneshot::Sender<crate::fence::driver::LaunchAnswer>,
    >,
    /// Commands a reader installed after their transaction had been revoked.
    late_installations: Vec<kr_protocol::root::ShellLaunchResult>,
}

/// Returns whichever of two authority deadlines ends first.
///
/// A null deadline is authority that does not expire, so it never shortens the other one and never
/// replaces one that does expire.
const fn tightest(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left < right { left } else { right }),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    }
}

/// The refusal an unauthenticated managed session owes a client's bytes.
fn unauthenticated() -> WorkerError {
    WorkerError::PreconditionFailed {
        detail: "this session's root integration has not been authenticated, so it accepts no \
                 external input yet"
            .to_owned(),
    }
}

impl InputDomain {
    /// Creates the domain of a session that has not started its shell.
    pub(crate) fn new(session_id: SessionId) -> Self {
        Self {
            state: SessionState::Creating,
            session_id,
            lease: InputLease::new(),
            framer: PasteFramer::new(),
            interrupted: Interrupted::default(),
            held_input_deadline: None,
            held_input_utc_deadline: None,
            capabilities: BTreeMap::new(),
            granted_attachments: BTreeMap::new(),
            pending: VecDeque::new(),
            held_input_bytes: 0,
            writer: WriterHandles::new(),
            fence: None,
            revision: None,
            owed: Vec::new(),
            replies_waiting: false,
            takeover_receipt: None,
            launches: BTreeMap::new(),
            late_installations: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------------------------
    // The lifecycle.
    // -----------------------------------------------------------------------------------------

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Moves the lifecycle.
    pub(crate) const fn set_state(&mut self, state: SessionState) {
        self.state = state;
    }

    /// Returns the session this domain belongs to.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    // -----------------------------------------------------------------------------------------
    // What the terminal's writer shares.
    // -----------------------------------------------------------------------------------------

    /// Returns the handles the terminal's writer is started with.
    pub(crate) const fn writer(&self) -> &WriterHandles {
        &self.writer
    }

    /// Returns the boundary the writer and a lease change share.
    ///
    /// Inside it are the fence, one write that refuses to wait, and the accounting for what that
    /// write sent; outside it is the waiting for a terminal with no room. A lease change takes the
    /// same boundary, which is what makes "this lease's bytes are no longer wanted" and "these bytes
    /// have just been written" one order rather than two races.
    #[must_use]
    pub fn input_gate(&self) -> Arc<Mutex<()>> {
        Arc::clone(&self.writer.gate)
    }

    /// Returns the latch the writer sets when the terminal will take nothing more.
    ///
    /// The writer holds it for the one moment it ends: a terminal that has gone. From then on this
    /// session refuses input rather than acknowledging bytes nothing will write.
    #[must_use]
    pub fn terminal_gone_latch(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.writer.terminal_gone)
    }

    /// Returns the counter the writer releases as the application takes its input.
    #[must_use]
    pub fn queued_input_bytes(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.writer.queued_input_bytes)
    }

    /// Returns the counter holding the current lease's share of the queue.
    #[must_use]
    pub fn queued_lease_bytes(&self) -> Arc<crate::runtime::LeaseBytes> {
        Arc::clone(&self.writer.queued_lease_bytes)
    }

    /// Returns the counter the writer takes each answer's bytes off as they reach the terminal or
    /// are dropped.
    #[must_use]
    pub fn unwritten_replies(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.writer.unwritten_replies)
    }

    /// Returns the flag the writer clears when it has answered a lease change.
    #[must_use]
    pub fn lease_change_queued(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.writer.lease_change_queued)
    }

    /// Returns the writer's record of whether the application is inside a bracketed paste.
    #[must_use]
    pub fn delivered_paste_open(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.writer.delivered_paste_open)
    }

    /// Returns the published fence the writer compares every queued batch against.
    #[must_use]
    pub fn input_fence_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.writer.input_fence)
    }

    /// Returns the epoch a batch must carry to still be written.
    ///
    /// Everything queued under an earlier epoch is stale. A takeover, a release, a detach or a
    /// close moves this, and the writer drops whatever it is still holding from before.
    #[must_use]
    pub const fn input_fence(&self) -> u64 {
        self.lease.epoch()
    }

    /// Returns how many answers the writer has dropped, because the response lane's deadline for
    /// each passed while it waited for a terminal that would not take it.
    #[must_use]
    pub fn replies_dropped(&self) -> u64 {
        self.writer.dropped_replies.load(Ordering::Acquire)
    }

    // -----------------------------------------------------------------------------------------
    // The lease.
    // -----------------------------------------------------------------------------------------

    /// Returns the input lease.
    #[must_use]
    pub fn lease(&self) -> InputLeaseState {
        self.lease.to_wire()
    }

    /// Returns the attachment holding the input lease.
    #[must_use]
    pub const fn holder(&self) -> Option<AttachmentId> {
        self.lease.holder()
    }

    /// Returns the lease's epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.lease.epoch()
    }

    /// Returns the lease as the root-editor machine reads it.
    fn lease_view(&self) -> LeaseView {
        LeaseView {
            epoch: InputLeaseEpoch::new(self.lease.epoch()),
            holder: self.lease.holder(),
        }
    }

    /// Takes the lease for an attachment, and returns what the ending lease had queued.
    pub(crate) fn acquire(
        &mut self,
        attachment_id: AttachmentId,
        connection_id: ConnectionId,
    ) -> u64 {
        self.lease.acquire(attachment_id, connection_id)
    }

    /// Releases the lease held by an attachment at an epoch, and returns what it had queued, or
    /// nothing when the caller does not hold it.
    pub(crate) fn release(&mut self, attachment_id: AttachmentId, epoch: u64) -> Option<u64> {
        self.lease.release(attachment_id, epoch)
    }

    /// Releases the lease when the attachment holds it, and returns what it had queued.
    pub(crate) fn release_attachment(&mut self, attachment_id: AttachmentId) -> u64 {
        self.lease.release_attachment(attachment_id)
    }

    /// Closes the framing a takeover leaves, and the deadlines of the prefix it discards.
    ///
    /// The held delimiter prefix goes with it, so the deadline that prefix was carrying goes too.
    /// Leaving it would put an ended actor's authority on the next actor's first keystrokes: the
    /// bytes it belonged to have been discarded, and the deadline is a fact about those bytes.
    pub(crate) fn close_framing_for_takeover(&mut self) -> TakeoverFraming {
        self.held_input_deadline = None;
        self.held_input_utc_deadline = None;
        self.framer.close_for_takeover()
    }

    /// Ends the lease that was in force and returns what it left the writer holding.
    ///
    /// The fence and the count are one step, taken on the boundary the writer also takes: after
    /// this returns, no write of that lease's bytes can begin, and none was part way through while
    /// the count was taken. That is what makes the number a receipt can quote exact rather than an
    /// estimate of what a writer might still be doing.
    pub(crate) fn end_lease(&mut self) -> LeaseEnded {
        let gate = Arc::clone(&self.writer.gate);
        let boundary = gate.lock().expect("the input boundary is not poisoned");
        // Read before the fence goes out. The writer clears this latch when it sees the fence
        // change, so a read afterwards can find the zero the writer wrote for this very change and
        // report that no paste was interrupted when one was. Before the fence, no writer can have
        // seen it, and a latch an *earlier* change left set was reported by that change.
        let paste_open_for = self.writer.delivered_paste_open.load(Ordering::Acquire);
        self.publish_lease();
        let left = self.writer.queued_lease_bytes.take(self.lease.epoch()) as u64;
        drop(boundary);
        LeaseEnded {
            left,
            paste_open_for,
        }
    }

    /// Publishes the lease as it now stands to the writer.
    ///
    /// The fence goes out here, with the change itself. Everything that reads what the lease that
    /// just ended left behind reads it afterwards, so the writer can no longer be adding to that
    /// count or writing from it while it is being counted.
    pub(crate) fn publish_lease(&mut self) {
        self.writer
            .input_fence
            .store(self.lease.epoch(), Ordering::Release);
        // The writer is told the lease moved, so a paste the old lease left open at the
        // application is closed even when nothing follows it. One outstanding notice answers every
        // change that happens before the writer takes it, because what the writer then reads is
        // the fence as it stands rather than the change that queued the notice.
        if !self.writer.lease_change_queued.swap(true, Ordering::AcqRel) {
            self.pending
                .push_back(Queued::Batch(InputBatch::LeaseChanged));
        }
    }

    /// Records what a lease the host ended by itself left behind, to be reported by the next
    /// acquire.
    pub(crate) fn carry_interrupted(
        &mut self,
        discarded_queue: u64,
        ended: &LeaseEnded,
        framing: &TakeoverFraming,
        paste_was_ours: bool,
    ) {
        self.interrupted.bytes = self
            .interrupted
            .bytes
            .saturating_add(discarded_queue)
            .saturating_add(ended.left)
            .saturating_add(framing.discarded_prefix.len() as u64);
        self.interrupted.closed_open_paste |= framing.terminator.is_some() || paste_was_ours;
    }

    /// Adds bytes to what a lease the host ended by itself left behind.
    pub(crate) fn carry_bytes(&mut self, bytes: u64) {
        self.interrupted.bytes = self.interrupted.bytes.saturating_add(bytes);
    }

    /// Takes what a lease the host ended by itself left behind.
    pub(crate) fn take_interrupted(&mut self) -> Interrupted {
        std::mem::take(&mut self.interrupted)
    }

    /// Returns what a lease the host ended by itself left behind and nobody has been told about.
    #[must_use]
    pub const fn interrupted_input(&self) -> Interrupted {
        self.interrupted
    }

    // -----------------------------------------------------------------------------------------
    // The authority revision.
    // -----------------------------------------------------------------------------------------

    /// Returns the authority revision this worker last installed and acknowledged.
    #[must_use]
    pub const fn revision(&self) -> Option<AuthorityRevision> {
        self.revision
    }

    /// Installs the revision the controller now holds.
    pub(crate) const fn install_revision(&mut self, revision: AuthorityRevision) {
        self.revision = Some(revision);
    }

    /// Refuses an action validated under a revision this worker has installed past.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::PermissionDenied`] when a later revision is installed.
    pub fn check_validated_revision(&self, validated: Option<AuthorityRevision>) -> Result<()> {
        let Some(validated) = validated else {
            return Ok(());
        };
        if self
            .revision
            .is_some_and(|held| held.get() > validated.get())
        {
            return Err(WorkerError::PermissionDenied {
                detail: format!(
                    "this action was admitted under authority revision {validated}, and this \
                     worker holds a later one"
                ),
            });
        }
        Ok(())
    }

    /// Leaves steps for the session to carry out: the pump, or the next stimulus it applies.
    ///
    /// A keystroke and the timer leave only `editor_busy` events: the stimuli they make cannot
    /// order the removal of an attachment, an interrupt or the answer to a command hook, which are
    /// the steps whose order against bytes matters.
    pub(crate) fn owe(&mut self, steps: Vec<Step>) {
        debug_assert!(
            steps.iter().all(|step| matches!(step, Step::EditorBusy(_))),
            "a keystroke or the timer left a step for the session that is not an event: {steps:?}"
        );
        self.owed.extend(steps);
    }

    /// Takes the steps left for the pump.
    pub(crate) fn take_owed(&mut self) -> Vec<Step> {
        std::mem::take(&mut self.owed)
    }

    /// Returns whether steps are left for the pump.
    #[must_use]
    pub fn is_owed(&self) -> bool {
        !self.owed.is_empty()
    }

    /// Records whether the response lane still holds replies after a drain.
    pub(crate) const fn set_replies_waiting(&mut self, waiting: bool) {
        self.replies_waiting = waiting;
    }

    /// Returns whether the response lane held replies the gate allows out when it was last
    /// drained, which the next keystroke asks the pump to take.
    #[must_use]
    pub const fn replies_waiting(&self) -> bool {
        self.replies_waiting
    }

    // -----------------------------------------------------------------------------------------
    // What each attachment was granted.
    // -----------------------------------------------------------------------------------------

    /// Records what an attachment was granted.
    pub(crate) fn grant(
        &mut self,
        attachment_id: AttachmentId,
        capabilities: CanonicalSet<AttachmentCapability>,
    ) {
        self.capabilities.insert(attachment_id, capabilities);
    }

    /// Returns the capabilities one attachment was granted.
    #[must_use]
    pub fn capabilities(
        &self,
        attachment_id: AttachmentId,
    ) -> Option<&CanonicalSet<AttachmentCapability>> {
        self.capabilities.get(&attachment_id)
    }

    /// Records that an attachment was admitted under a grant.
    pub(crate) fn note_granted_attachment(&mut self, attachment_id: AttachmentId, by: GrantedBy) {
        self.granted_attachments.insert(attachment_id, by);
    }

    /// Returns whether the attachment was admitted under a grant.
    #[must_use]
    pub fn holds_granted_attachment(&self, attachment_id: AttachmentId) -> bool {
        self.granted_attachments.contains_key(&attachment_id)
    }

    /// Returns whether an attachment made under a grant is within the reach of a revision.
    #[must_use]
    pub fn granted_attachment_within(
        &self,
        attachment_id: AttachmentId,
        reach: &kr_protocol::worker::RevisionReach,
    ) -> bool {
        self.granted_attachments
            .get(&attachment_id)
            .is_some_and(|by| reach.names(by.grant_id, by.device_id))
    }

    /// Forgets an attachment: what it was granted, and that it was made under a grant.
    pub(crate) fn forget_attachment(&mut self, attachment_id: AttachmentId) {
        self.capabilities.remove(&attachment_id);
        self.granted_attachments.remove(&attachment_id);
    }

    // -----------------------------------------------------------------------------------------
    // The queue for the terminal.
    // -----------------------------------------------------------------------------------------

    /// Queues one batch for the pseudo-terminal, counted against the session's input budget.
    ///
    /// Every producer goes through here, because the writer releases every piece it writes against
    /// the same counter: charging only some of them would make the count drift down until it
    /// stopped bounding anything.
    pub(crate) fn queue_input(&mut self, batch: InputBatch) {
        self.writer
            .queued_input_bytes
            .fetch_add(batch.len(), Ordering::AcqRel);
        if let InputBatch::Lease { epoch, .. } = batch {
            self.writer.queued_lease_bytes.add(epoch, batch.len());
        }
        self.pending.push_back(Queued::Batch(batch));
    }

    /// Takes the batches that may be written to the pseudo-terminal now, in the order they were
    /// queued.
    ///
    /// It stops at a published fence the bridge's writer has not written yet, while the machine
    /// still holds that fence, and leaves it and everything behind it queued. A reader takes what is
    /// on its endpoint before it acts on a key, and only what is already there, so a key that
    /// reached the shell ahead of the fence it was released under would be accepted without it: the
    /// line it made would run without the capability the fence exists to mint. This is the only way
    /// out of the queue, and every batch for the terminal, the host's own replies included, goes
    /// through the queue, so no batch reaches the terminal around a fence. The one thing the
    /// terminal's writer writes of its own accord is the terminator that closes a paste a lease
    /// that has ended left open; it belongs to input queued before that lease ended, and it goes
    /// ahead of the batch whose taking showed the writer the change.
    ///
    /// When the writer reports the fence written, its connection ends and the loss has been
    /// recorded, or the machine drops the fence, the next flush takes what was waiting.
    pub fn take_pending(&mut self) -> Vec<InputBatch> {
        let mut taken = Vec::new();
        while let Some(queued) = self.pending.pop_front() {
            match queued {
                Queued::Batch(batch) => taken.push(batch),
                Queued::Fence(frame)
                    if self
                        .fence
                        .as_ref()
                        .is_some_and(|driver| driver.holds_back(frame)) =>
                {
                    self.pending.push_front(Queued::Fence(frame));
                    break;
                }
                // Written, gone with the connection it was handed to, or no longer the machine's.
                Queued::Fence(_) => {}
            }
        }
        taken
    }

    /// Returns how many batches wait in the queue for the terminal behind a published fence that
    /// still holds them back, for this host's own tests.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn waiting_for_fence(&self) -> usize {
        self.pending
            .iter()
            .skip_while(|queued| match queued {
                Queued::Batch(_) => true,
                Queued::Fence(frame) => !self
                    .fence
                    .as_ref()
                    .is_some_and(|driver| driver.holds_back(*frame)),
            })
            .filter(|queued| matches!(queued, Queued::Batch(_)))
            .count()
    }

    /// Queues the host's own answers for the application, up to what one may wait for.
    ///
    /// The response lane bounds what it holds; this bounds what has left the lane and is waiting
    /// for an application that has stopped reading its input. One that asks questions and never
    /// reads the answers stops being answered here rather than growing this queue without limit.
    ///
    /// The root editor's machine hears of them once, after the whole batch is queued, in the order
    /// the terminal will get them: what the machine publishes because of them goes behind the bytes
    /// they are. Every byte the host puts into the terminal is accounted, not only a person's. What
    /// the machine said is returned when it was told; applying its answer drains the lane again,
    /// which must find this batch already in the queue rather than put the rest of the lane in
    /// front of it.
    pub(crate) fn queue_replies(
        &mut self,
        replies: Vec<crate::projection::LaneReply>,
    ) -> Option<Applied> {
        let mut queued_bytes = 0_u64;
        for reply in replies {
            let queued = self.writer.queued_input_bytes.load(Ordering::Acquire);
            let held = queued.saturating_sub(self.writer.queued_lease_bytes.load());
            // Two bounds, both of them this reply's: its own share, so an application that asks
            // questions without reading the answers cannot fill the terminal by itself, and the
            // whole budget, so its share cannot be spent on top of a full queue. What the root
            // editor's machine is holding counts towards the second, because it is accepted input
            // on its way to the same terminal.
            let outstanding = queued.saturating_add(self.held_input_bytes);
            if held.saturating_add(reply.bytes.len()) > MAX_PENDING_REPLY_BYTES
                || outstanding.saturating_add(reply.bytes.len()) > MAX_QUEUED_INPUT_BYTES
            {
                break;
            }
            queued_bytes = queued_bytes.saturating_add(reply.bytes.len() as u64);
            self.writer
                .unwritten_replies
                .fetch_add(reply.bytes.len(), Ordering::AcqRel);
            self.queue_input(InputBatch::Reply {
                bytes: reply.bytes,
                expires_at_ms: reply.expires_at_ms,
            });
        }
        if queued_bytes > 0
            && let Some(driver) = self.fence.as_mut()
        {
            let effects = driver.host_reply_queued(queued_bytes);
            return Some(self.apply_effects(effects));
        }
        None
    }

    // -----------------------------------------------------------------------------------------
    // The recogniser.
    // -----------------------------------------------------------------------------------------

    /// Returns what the response lane is allowed to write right now.
    ///
    /// A reply must not land in the middle of a bracketed paste or a recognised human input frame,
    /// because the application would read it as part of what the person was typing.
    #[must_use]
    pub const fn lane_gate(&self) -> kr_term::lane::LaneGate {
        kr_term::lane::LaneGate {
            paste_open: self.framer.paste_open(),
            // No backend this host drives is qualified to take a reply inside an open paste.
            backend_handles_paste_interleave: false,
            // A delimiter this framer is still holding is the first bytes of a frame the person is
            // part way through sending. A reply written in the middle of it would arrive inside
            // what the application reads as one key.
            human_frame_open: self.framer.held_len() > 0,
        }
    }

    /// A gate that lets nothing out, for a pass that parses without answering.
    #[must_use]
    pub const fn shut_gate() -> kr_term::lane::LaneGate {
        kr_term::lane::LaneGate {
            paste_open: true,
            backend_handles_paste_interleave: false,
            human_frame_open: true,
        }
    }

    const fn gate_is_open(&self) -> bool {
        !self.framer.paste_open() && self.framer.held_len() == 0
    }

    /// Returns the deadline of a held delimiter prefix, if there is one.
    #[must_use]
    pub fn paste_deadline(&self) -> Option<Instant> {
        self.framer.deadline()
    }

    /// Returns whether a bracketed paste has been started and not yet ended.
    #[must_use]
    pub const fn paste_open(&self) -> bool {
        self.framer.paste_open()
    }

    /// Returns whether the session's integration admits bytes from outside it.
    ///
    /// A session with no managed reader always does. A managed one does only once its private
    /// reader and pre-EOF bridge have been authenticated and ABI-checked, and stops again if that
    /// integration is lost.
    fn accepts_external_input(&self) -> bool {
        self.fence
            .as_ref()
            .is_none_or(|driver| driver.phase().accepts_external_input())
    }

    /// Accepts ordered input for the pseudo-terminal.
    ///
    /// The bytes are forwarded unchanged. Nothing here decodes, re-encodes or normalises them; the
    /// only thing the domain tracks is where a bracketed paste begins and ends.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::LeaseLost`] for a stale epoch or a caller that does not hold the
    /// lease, and an invalid-argument failure when the sequence does not follow.
    pub(crate) fn accept(
        &mut self,
        attachment_id: AttachmentId,
        epoch: u64,
        sequence: u64,
        bytes: &[u8],
        authority: InputAuthority,
        now: Instant,
    ) -> Result<Accepted> {
        let authority_deadline_boot_ms = authority.boot_ms;
        if !self.state.accepts_input() {
            return Err(WorkerError::SessionClosed);
        }
        // A terminal that has gone takes nothing, and an acknowledgement here would say the
        // opposite. The session itself is still open - what happened to the shell is the child
        // monitor's question, not this one's - so this is the resource it is rather than a closure.
        if self.writer.terminal_gone.load(Ordering::Acquire) {
            return Err(WorkerError::ResourceUnavailable {
                detail: "this session's terminal has gone, so nothing can be written to it"
                    .to_owned(),
            });
        }
        match self.lease.accept_write(attachment_id, epoch, sequence) {
            Ok(()) => {}
            Err(LeaseRefusal::LeaseLost) => return Err(WorkerError::LeaseLost),
            Err(LeaseRefusal::OutOfOrder { expected, received }) => {
                return Err(WorkerError::InvalidArgument(format!(
                    "input sequence {received} does not follow {expected}"
                )));
            }
        }
        // The budget is checked before the recogniser is fed, so a refused frame leaves the
        // framing exactly as it was: what is refused is the whole frame, not part of it. A push
        // can also release a prefix it was holding, which is at most one delimiter short of a
        // whole one, so that is counted too.
        let claimed = bytes.len().saturating_add(PASTE_END.len());
        let queued = self
            .writer
            .queued_input_bytes
            .load(Ordering::Acquire)
            // What the root editor's machine is holding for a reader transition has been accepted
            // and not delivered, so it is against the same bound. Leaving it out would let a client
            // that keeps typing through a hold exceed the bound without limit.
            .saturating_add(self.held_input_bytes);
        if queued.saturating_add(claimed) > MAX_QUEUED_INPUT_BYTES {
            return Err(WorkerError::ResourceUnavailable {
                detail: format!(
                    "the application is not reading its input and {MAX_QUEUED_INPUT_BYTES} bytes \
                     are already waiting for it, so these bytes were not accepted"
                ),
            });
        }
        if !self.accepts_external_input() {
            // Section 7 paragraph 4: in managed mode nothing external reaches the terminal until
            // the private reader and pre-EOF bridge are authenticated and ABI-checked. The refusal
            // is decided before the recogniser is fed, so a refused frame leaves no half-open paste
            // behind it and no prefix waiting on a timer.
            return Err(unauthenticated());
        }
        let gate_was_open = self.gate_is_open();
        let outcome = self.framer.push(bytes, now);
        let mut owed = Vec::new();
        // The recogniser can hold bytes back, so what this push forwards may carry bytes an
        // earlier write handed over. Whichever authority ends first is the one that decides: an
        // earlier write's deadline never gets extended by a later write, and a later write's
        // never gets extended by an earlier one.
        let admitted = tightest(self.held_input_deadline, authority_deadline_boot_ms);
        let admitted_utc = tightest(self.held_input_utc_deadline, authority.utc_ms);
        if !outcome.forward.is_empty() {
            // The framer's own state after the push is what these bytes leave the application in,
            // because `forward` carries every delimiter the push completed and no part of one it
            // did not. Whether a start is among them is the separate question the writer asks when
            // it has delivered only part of the batch.
            let paste = PasteTransition {
                delimiters: outcome.delimiters.clone(),
            };
            let batch = InputBatch::Lease {
                epoch,
                bytes: outcome.forward.clone(),
                paste,
                authority_deadline_boot_ms: admitted,
                authority_utc_deadline_ms: admitted_utc,
            };
            self.offer(attachment_id, epoch, batch, &mut owed)?;
        }
        // What is still held is a suffix of the prefix that was held and the bytes this write
        // added. Longer than this write means it still carries bytes an earlier one handed over,
        // and then the earlier authority is part of it; no longer than this write means every
        // byte in it is this write's, and an earlier deadline has nothing to do with it. Nothing
        // held means nothing to fence later.
        self.held_input_deadline = if outcome.held == 0 {
            None
        } else if outcome.held > bytes.len() {
            admitted
        } else {
            authority_deadline_boot_ms
        };
        self.held_input_utc_deadline = if outcome.held == 0 {
            None
        } else if outcome.held > bytes.len() {
            admitted_utc
        } else {
            authority.utc_ms
        };
        // A paste that has just closed, or a frame that has just completed, opens the gate the
        // response lane was waiting on. An application that asked a question during one of those
        // and then sat still would otherwise wait for its answer until the next byte of output.
        Ok(Accepted {
            accepted: InputAccepted {
                forwarded_bytes: outcome.forward.len() as u64,
                held_prefix_bytes: outcome.held as u64,
                deadline: outcome.deadline,
            },
            owed,
            opened_the_gate: !gate_was_open && self.gate_is_open(),
        })
    }

    /// Offers one batch of a client's bytes to the terminal.
    ///
    /// Every client byte goes through here, whether it arrived in a frame or was released by the
    /// paste recogniser's own timer. A managed session asks the root editor's machine what becomes
    /// of it: written now, held for at most 250 ms while a reader transition resolves, or dropped
    /// because its lease has moved. Queueing one of them anywhere else would let a later byte reach
    /// the application in front of an earlier one the machine is still holding.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::SessionClosed`] when the machine refuses the batch outright.
    fn offer(
        &mut self,
        attachment_id: AttachmentId,
        epoch: u64,
        batch: InputBatch,
        owed: &mut Vec<Step>,
    ) -> Result<()> {
        let Some(driver) = self.fence.as_mut() else {
            self.queue_input(batch);
            return Ok(());
        };
        if !driver.phase().accepts_external_input() {
            // The same gate again, for the bytes that reach this path without passing through a
            // frame: a prefix the recogniser's own timer released, or one a mode change let go of.
            // Those were accepted while the integration was authenticated and may arrive after a
            // loss took the phase back, and the terminal is owed no external byte after that.
            return Err(unauthenticated());
        }
        let effects = driver.input_arrived(attachment_id, InputLeaseEpoch::new(epoch), batch);
        if effects.input_refused.is_some() {
            return Err(WorkerError::SessionClosed);
        }
        owed.extend(self.apply_effects(effects).owed);
        Ok(())
    }

    /// Forwards a held delimiter prefix whose deadline has passed.
    ///
    /// The timer runs whether or not more input arrives, so a lone Escape is never waiting for
    /// another keystroke. Returns how many bytes were forwarded, and the steps that need the
    /// session.
    pub(crate) fn expire_paste_prefix(&mut self, now: Instant) -> (usize, Vec<Step>) {
        let epoch = self.lease.epoch();
        let mut owed = Vec::new();
        let expired = match self.framer.expire(now) {
            Some(bytes) if !bytes.is_empty() => {
                let len = bytes.len();
                // The prefix was accepted when it arrived and counted against the budget then, so
                // it goes through whatever the budget says now: forwarding it unchanged is what
                // the recogniser promised, and it is at most one delimiter long. It still goes
                // through the machine, because a reader transition that is holding what came before
                // it must hold this too, and it still carries the authority it was accepted under.
                if let Some(holder) = self.lease.holder() {
                    let _ = self.offer(
                        holder,
                        epoch,
                        InputBatch::Lease {
                            epoch,
                            bytes,
                            paste: PasteTransition::default(),
                            authority_deadline_boot_ms: self.held_input_deadline,
                            authority_utc_deadline_ms: self.held_input_utc_deadline,
                        },
                        &mut owed,
                    );
                }
                self.held_input_deadline = None;
                self.held_input_utc_deadline = None;
                len
            }
            _ => 0,
        };
        (expired, owed)
    }

    /// Records that the application has enabled or disabled bracketed-paste mode.
    ///
    /// Turning it off with a mere delimiter prefix held releases those bytes at once: the framing
    /// they were being held for no longer exists, so waiting out a deadline that now guards nothing
    /// would delay a keystroke for no reason. A prefix held inside an open paste keeps waiting,
    /// because that paste still has to be closed before another actor writes.
    ///
    /// Returns the steps that need the session, and whether a prefix was forwarded, which closes a
    /// frame that was open and so opens the gate the response lane was waiting on.
    pub(crate) fn set_bracketed_paste(&mut self, enabled: bool) -> (Vec<Step>, bool) {
        let released = self.framer.set_bracketed_paste(enabled);
        self.release_prefix(released)
    }

    /// Queues bytes the recogniser has stopped holding, under the lease that sent them.
    fn release_prefix(&mut self, released: Vec<u8>) -> (Vec<Step>, bool) {
        let mut owed = Vec::new();
        if released.is_empty() {
            return (owed, false);
        }
        let Some(holder) = self.lease.holder() else {
            // Nothing holds the keys, so these bytes belong to a lease that has ended and went
            // with it. Writing them now would put an ended actor's input in front of the next one.
            self.held_input_deadline = None;
            self.held_input_utc_deadline = None;
            return (owed, false);
        };
        let epoch = self.lease.epoch();
        let _ = self.offer(
            holder,
            epoch,
            InputBatch::Lease {
                epoch,
                bytes: released,
                paste: PasteTransition::default(),
                authority_deadline_boot_ms: self.held_input_deadline,
                authority_utc_deadline_ms: self.held_input_utc_deadline,
            },
            &mut owed,
        );
        self.held_input_deadline = None;
        self.held_input_utc_deadline = None;
        (owed, true)
    }

    // -----------------------------------------------------------------------------------------
    // The root editor's machine.
    // -----------------------------------------------------------------------------------------

    /// Installs the root-editor driver this session was created with.
    pub(crate) fn install_fence(&mut self, mut driver: FenceDriver) {
        driver.watch_unwritten_replies(Arc::clone(&self.writer.unwritten_replies));
        self.fence = Some(driver);
    }

    /// Returns the root-editor driver, for a managed session.
    #[must_use]
    pub const fn fence(&self) -> Option<&FenceDriver> {
        self.fence.as_ref()
    }

    /// Returns the root-editor driver for a stimulus.
    pub(crate) const fn fence_mut(&mut self) -> Option<&mut FenceDriver> {
        self.fence.as_mut()
    }

    /// Returns the last completed takeover receipt.
    #[must_use]
    pub const fn last_takeover_receipt(&self) -> Option<TakeoverReceipt> {
        self.takeover_receipt
    }

    /// Registers a caller waiting for a launch the reader is deciding.
    pub(crate) fn register_launch(
        &mut self,
        transaction: LaunchTransactionId,
    ) -> tokio::sync::oneshot::Receiver<crate::fence::driver::LaunchAnswer> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.launches.insert(transaction, sender);
        receiver
    }

    /// Forgets a caller that is no longer waiting.
    pub(crate) fn forget_launch(&mut self, transaction: LaunchTransactionId) {
        self.launches.remove(&transaction);
    }

    /// Returns how many callers wait for a launch the reader is deciding, for a managed session.
    #[must_use]
    pub fn outstanding_launches(&self) -> Option<u64> {
        self.fence.as_ref().map(|_| self.launches.len() as u64)
    }

    /// Returns the commands a reader installed after their transaction had been revoked.
    #[must_use]
    pub fn late_installations(&self) -> &[kr_protocol::root::ShellLaunchResult] {
        &self.late_installations
    }

    /// Sends one frame to the bridge.
    pub(crate) fn send(&self, frame: Outbound) {
        if let Some(driver) = self.fence.as_ref() {
            driver.send(frame);
        }
    }

    /// Answers the caller waiting on one launch, and says what the answer was.
    pub(crate) fn answer_launch(
        &mut self,
        transaction: LaunchTransactionId,
        answer: crate::fence::driver::LaunchAnswer,
        outcome: &mut FenceOutcome,
    ) {
        // Every caller waiting for one of these is answered here, on the step that produced the
        // answer. A closure, a lost bridge and a reader's decision all reach this line.
        if let Some(sender) = self.launches.remove(&transaction) {
            let _ = sender.send(answer.clone());
        }
        outcome.launch_answers.push((transaction, answer));
    }

    /// Tells the root editor's machine that the lease has moved.
    ///
    /// The change has already happened; what this decides is what becomes of the input the previous
    /// holder had sent and whether a fence exchange starts. A session with no managed editor has
    /// nothing to tell. Returns the count to report as discarded, and the steps that need the
    /// session.
    pub(crate) fn note_lease_change(&mut self, discarded_bytes: u64) -> (u64, Vec<Step>) {
        let lease = self.lease_view();
        let Some(driver) = self.fence.as_mut() else {
            return (discarded_bytes, Vec::new());
        };
        let effects = driver.lease_changed(
            lease,
            discarded_bytes,
            kr_protocol::root::FenceId::new(kr_ipc::new_uuid()),
        );
        let applied = self.apply_effects(effects);
        (
            applied
                .outcome
                .lease_acknowledged
                .map_or(discarded_bytes, |acknowledgement| {
                    acknowledgement.discarded_bytes.get()
                }),
            applied.owed,
        )
    }

    /// Carries out what one stimulus left for the input domain to do.
    ///
    /// One pass over the machine's own action list, front to back, carrying out each step where the
    /// machine put it. Nothing is grouped and nothing is reordered: a fence goes to the bridge
    /// before the input it lets go of is queued, held input is released before the `editor_busy`
    /// event that explains why it waited, and a launch is revoked before the interrupt that revoked
    /// it. The fence and the input travel on two writers, so the queue also records where the
    /// fence was published, and nothing behind that point leaves it until the bridge's writer has
    /// written the fence.
    ///
    /// The steps that need the session are handed back. An `editor_busy` event is handed back
    /// alone: it only tells a subscriber what happened, and no step behind it waits for it, so the
    /// bytes the machine ordered after it are queued now. A keystroke that expires a hold would
    /// otherwise leave its own bytes behind the session, and the next keystroke would pass them.
    /// The removal of an attachment, the interrupt and the answer to a command hook are handed back
    /// with every step the machine ordered after them, so that the session carries them out in the
    /// machine's order: a detach is acknowledged only once its attachment is gone. The stimuli a
    /// keystroke and the recogniser's timer make never order one of those.
    pub(crate) fn apply_effects(&mut self, effects: Effects) -> Applied {
        self.held_input_bytes = self
            .held_input_bytes
            .saturating_add(effects.held_added)
            .saturating_sub(effects.held_removed);
        if effects.discarded_bytes > 0 && effects.lease_acknowledged.is_none() {
            // Input this session accepted and never delivered, with no answer to report it in. It
            // is carried until an acquire has somewhere to put it. A lease change *does* have an
            // answer, and its own acknowledgement carries the total, so it is not counted twice.
            self.interrupted.bytes = self
                .interrupted
                .bytes
                .saturating_add(effects.discarded_bytes);
        }
        let mut applied = Applied {
            outcome: FenceOutcome {
                acceptance: effects.acceptance,
                lease_acknowledged: effects.lease_acknowledged,
                close_session: effects.close_session,
                ..FenceOutcome::default()
            },
            // What an earlier keystroke or pass of the timer left for the session goes first: the
            // machine produced it first. A caller that is a keystroke or the timer leaves the
            // whole list again, in the same order, in the same hold.
            owed: std::mem::take(&mut self.owed),
        };
        // Set by the first step that later steps must wait for.
        let mut behind_a_session_step = false;
        for step in effects.steps {
            if behind_a_session_step {
                applied.owed.push(step);
            } else if let Err(step) = self.carry_out_step(step, &mut applied.outcome) {
                behind_a_session_step = !matches!(step, Step::EditorBusy(_));
                // An attachment that is going is not typed at from this moment, whoever else takes
                // the domain before the session removes it.
                if let Step::RemoveAttachment(attachment_id) = &step {
                    self.capabilities.remove(attachment_id);
                }
                applied.owed.push(step);
            }
        }
        applied
    }

    /// Carries out one step of the machine's action list that the input domain can, and hands the
    /// step back when it needs the session.
    ///
    /// # Errors
    ///
    /// Returns the step itself when it is an `editor_busy` event, the removal of an attachment, an
    /// interrupt of the foreground process group or the answer to a command hook, which need the
    /// session.
    pub(crate) fn carry_out_step(
        &mut self,
        step: Step,
        outcome: &mut FenceOutcome,
    ) -> std::result::Result<(), Step> {
        match step {
            Step::Write(batch) => self.queue_input(batch),
            Step::Publish(fence) => {
                if let Some(frame) = self
                    .fence
                    .as_mut()
                    .and_then(|driver| driver.publish(*fence))
                {
                    self.pending.push_back(Queued::Fence(frame));
                }
            }
            Step::Receipt(receipt) => {
                self.takeover_receipt = Some(receipt);
                outcome.receipts.push(receipt);
            }
            Step::LateInstallation(result) => self.late_installations.push(*result),
            Step::Launch(transaction, answer) => {
                self.answer_launch(transaction, *answer, outcome);
            }
            Step::Send(frame) => self.send(frame),
            step @ (Step::EditorBusy(_)
            | Step::RemoveAttachment(_)
            | Step::Interrupt(_)
            | Step::CommandHook(..)) => return Err(step),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::SessionId;

    fn domain() -> InputDomain {
        InputDomain::new(SessionId::new(kr_ipc::new_uuid()))
    }

    fn batch(bytes: &[u8]) -> InputBatch {
        InputBatch::Reply {
            bytes: bytes.to_vec(),
            expires_at_ms: None,
        }
    }

    /// The machine's order is the contract's: a step that needs the session is carried out by the
    /// session, and so is everything the machine ordered after it, so nothing runs ahead of what
    /// the machine put before it. What came before it is carried out here, in order.
    #[test]
    fn nothing_the_machine_ordered_after_a_session_step_is_carried_out_ahead_of_it() {
        let mut input = domain();
        let removed = AttachmentId::new(kr_ipc::new_uuid());
        let effects = Effects {
            steps: vec![
                Step::Write(batch(b"before")),
                Step::RemoveAttachment(removed),
                Step::Write(batch(b"after")),
                Step::Interrupt(kr_protocol::input::InterruptAction::NativeInterrupt),
            ],
            ..Effects::default()
        };

        let applied = input.apply_effects(effects);

        assert_eq!(
            input.take_pending(),
            vec![batch(b"before")],
            "only what the machine ordered before the session's step is queued here"
        );
        let order: Vec<&str> = applied
            .owed
            .iter()
            .map(|step| match step {
                Step::RemoveAttachment(_) => "remove",
                Step::Write(_) => "write",
                Step::Interrupt(_) => "interrupt",
                _ => "other",
            })
            .collect();
        assert_eq!(
            order,
            ["remove", "write", "interrupt"],
            "the session carries out the rest in the machine's order"
        );
    }

    fn editor_busy(attachment_id: AttachmentId) -> Step {
        Step::EditorBusy(Box::new(kr_protocol::root::EditorBusyEvent {
            session_id: SessionId::new(kr_ipc::new_uuid()),
            attachment_id,
            input_epoch: InputLeaseEpoch::new(1),
            reason: kr_protocol::root::EditorBusyReason::QueuesNotDrained,
            released_input_bytes: kr_protocol::scalars::U64::new(0),
            state: kr_protocol::root::FenceState::Unfenced,
        }))
    }

    /// An `editor_busy` event only tells a subscriber what happened. The bytes the machine ordered
    /// after it are queued at once, because a keystroke that expires a hold has no session to wait
    /// for them with, and the keystroke after it must not pass them.
    #[test]
    fn an_editor_busy_event_does_not_hold_back_the_bytes_ordered_after_it() {
        let mut input = domain();
        let holder = AttachmentId::new(kr_ipc::new_uuid());
        let effects = Effects {
            steps: vec![
                Step::Write(batch(b"released")),
                editor_busy(holder),
                Step::Write(batch(b"typed")),
            ],
            ..Effects::default()
        };

        let applied = input.apply_effects(effects);

        assert_eq!(
            input.take_pending(),
            vec![batch(b"released"), batch(b"typed")],
            "every byte is queued in the machine's order"
        );
        assert!(
            matches!(applied.owed.as_slice(), [Step::EditorBusy(_)]),
            "the event is the only thing left for the session"
        );
    }

    /// An event a keystroke left for the session is told before the events the next stimulus the
    /// session applies produces, and a keystroke after that leaves its event behind them.
    #[test]
    fn events_are_told_in_the_order_the_machine_produced_them() {
        let (first, second, third) = (
            AttachmentId::new(kr_ipc::new_uuid()),
            AttachmentId::new(kr_ipc::new_uuid()),
            AttachmentId::new(kr_ipc::new_uuid()),
        );
        let mut input = domain();
        // A keystroke sweeps an exchange that timed out: its event waits for the session.
        let keystroke = input.apply_effects(Effects {
            steps: vec![editor_busy(first)],
            ..Effects::default()
        });
        input.owe(keystroke.owed);

        // The next stimulus the session applies produces an event of its own.
        let applied = input.apply_effects(Effects {
            steps: vec![editor_busy(second)],
            ..Effects::default()
        });
        let told = |steps: &[Step]| -> Vec<AttachmentId> {
            steps
                .iter()
                .map(|step| match step {
                    Step::EditorBusy(event) => event.attachment_id,
                    other => panic!("not an event: {other:?}"),
                })
                .collect()
        };
        assert_eq!(
            told(&applied.owed),
            [first, second],
            "the older event is told first"
        );
        assert!(!input.is_owed(), "and nothing is left to be told twice");

        // A keystroke after that leaves its event behind the ones already handed over.
        let keystroke = input.apply_effects(Effects {
            steps: vec![editor_busy(third)],
            ..Effects::default()
        });
        assert_eq!(told(&keystroke.owed), [third]);
    }

    /// A step that must wait for a session step still does when an event came before it.
    #[test]
    fn a_session_step_behind_an_event_still_holds_back_what_follows_it() {
        let mut input = domain();
        let removed = AttachmentId::new(kr_ipc::new_uuid());
        let effects = Effects {
            steps: vec![
                editor_busy(removed),
                Step::RemoveAttachment(removed),
                Step::Write(batch(b"after")),
            ],
            ..Effects::default()
        };

        let applied = input.apply_effects(effects);

        assert!(
            input.take_pending().is_empty(),
            "nothing runs ahead of the removal"
        );
        assert!(
            matches!(
                applied.owed.as_slice(),
                [
                    Step::EditorBusy(_),
                    Step::RemoveAttachment(_),
                    Step::Write(_)
                ]
            ),
            "the event, the removal and the write are the session's, in the machine's order"
        );
    }

    /// An attachment whose removal is owed is not typed at from the moment the machine orders it,
    /// whoever takes the domain before the session carries the removal out.
    #[test]
    fn an_attachment_whose_removal_is_owed_holds_no_capability_in_the_meantime() {
        let mut input = domain();
        let removed = AttachmentId::new(kr_ipc::new_uuid());
        let mut granted = CanonicalSet::new();
        granted.insert(AttachmentCapability::Input);
        input.grant(removed, granted);
        assert!(input.capabilities(removed).is_some());

        let applied = input.apply_effects(Effects {
            steps: vec![Step::RemoveAttachment(removed)],
            ..Effects::default()
        });

        assert_eq!(applied.owed.len(), 1, "the removal itself is the session's");
        assert!(
            input.capabilities(removed).is_none(),
            "and a keystroke from it is refused before the session removes it"
        );
    }
}
