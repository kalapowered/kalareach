//! The session: one pseudo-terminal, one root shell, and the state every attachment reads.
//!
//! Everything mutable about a session lives in [`Session`] and changes through its methods, one at
//! a time. Ownership changes, resize operations and output cursors therefore share one order, which
//! is what section 8 requires and what makes a cursor mean the same thing to every attachment.
//!
//! # Closure
//!
//! `session.close` is not a request to exit; it is a state. It sets `closing` atomically, stops
//! accepting input, asks the owned process group to stop, and allows five seconds before forcing
//! the remainder. Output drains for up to two more seconds so the last lines are not lost. The
//! caller's acceptance is returned before any of that, because the caller may itself be inside the
//! process group about to be signalled.
//!
//! Storage failure never blocks a stop. If the journal is unavailable the closure proceeds on the
//! worker's current in-memory authority and identities, and the reply says `durability=volatile`
//! rather than pretending it was recorded.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_protocol::attachment::{
    AttachmentCapability, AttachmentSummary, GeometryState, SessionAttachParams,
    SessionAttachResult, SessionDetachResult, TerminalPresentationMode,
};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    AttachmentId, ConnectionId, EnvironmentId, SessionEpoch, SessionId, StreamCursor,
};
use kr_protocol::input::{InputAcquireResult, InputLeaseState};
use kr_protocol::projection::ProjectionResetReason;
use kr_protocol::recovery::{EventsSnapshotResult, HistoryPageResult, ResyncReason};
use kr_protocol::scalars::{CanonicalSet, Nullable, TimestampMs, U64};
use kr_protocol::session::{
    ApplicationState, ClosureReason, ClosureRecord, Dimensions, Durability, OwnershipCoverage,
    SessionState, SessionSummary, ShellMode,
};

use crate::attachments::AttachmentTable;
use crate::error::{Result, WorkerError};
use crate::history::{OutputHistory, SpoolLayout};
use crate::input::{InputLease, LeaseRefusal, PasteFramer};
use crate::journal::Journal;
use crate::output::{OutputHub, OutputStream};
use crate::ownership::OwnedProcesses;
use crate::pty::{Pty, RootShell, ShellCommand, ShellExit};

/// How long an owned process group has to stop before it is forced.
pub const GRACE_PERIOD: Duration = Duration::from_secs(5);

/// How long output drains after the processes have stopped.
pub const DRAIN_PERIOD: Duration = Duration::from_secs(2);

/// Everything a worker needs to bring one session up.
#[derive(Clone, Debug)]
pub struct SessionConfig {
    /// The session identity.
    pub session_id: SessionId,
    /// The epoch. Fixed at 1 in this version.
    pub session_epoch: SessionEpoch,
    /// The environment that owns it.
    pub environment_id: EnvironmentId,
    /// The local alias.
    pub display_number: kr_protocol::session::DisplayNumber,
    /// The root shell to launch.
    pub shell: ShellCommand,
    /// How the shell is integrated.
    pub shell_mode: ShellMode,
    /// How long the execution context lasts.
    pub worker_profile: WorkerProfile,
    /// The login session a desktop-bound worker is tied to.
    pub desktop: DesktopBinding,
    /// The starting geometry.
    pub dimensions: Dimensions,
    /// The private journal, or `None` for a session whose receipts are not retained on disk.
    pub journal_path: Option<std::path::PathBuf>,
    /// The output spool directory.
    pub spool_directory: Option<std::path::PathBuf>,
    /// The bound on one attachment's queued output.
    pub send_queue_bytes: usize,
    /// The resident output cache.
    pub resident_bytes: usize,
}

/// What a close request produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseAcceptance {
    /// The state at the moment of the reply.
    pub state: SessionState,
    /// Whether the closure is being recorded durably.
    pub durability: Durability,
    /// The final record, when closure has already finished.
    pub closure: Option<ClosureRecord>,
    /// True when this request began the closure rather than joining one already running.
    pub initiated: bool,
}

/// What ending a lease established, read on the boundary the writer shares.
///
/// Both answers have to be taken there and taken together: the bytes the ending lease handed over
/// and the writer has not written, and whether the writer was holding a paste of that lease's open.
/// Reading either one outside the boundary, or after the fence, reads an answer about a different
/// moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LeaseEnded {
    /// Bytes that lease had queued and the writer had not written.
    left: u64,
    /// The lease whose delivered paste was open, as one more than its epoch; zero for none.
    paste_open_for: u64,
}

/// What a lease the host ended by itself left behind, waiting to be reported.
///
/// Section 8 requires an interrupted paste and the input that never arrived to be reported. A
/// takeover has an answer to report them in; a release the host performed on its own does not, so
/// they are carried until the next acquire and reported with its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Interrupted {
    /// Bytes that were accepted and never reached the application.
    pub bytes: u64,
    /// Whether a paste the application was inside was closed on its way out.
    pub closed_open_paste: bool,
}

/// The screen one attachment joins on.
///
/// Only a terminal the session's own size that can take the stream has one here. A projected
/// client holds the canonical grid as state and draws it itself, and its screen is queued through
/// its own subscription so that it is charged to that subscriber's bound.
#[derive(Clone, Debug, Default)]
pub struct Joined {
    /// The cursor the screen was taken at. Live output continues from here.
    pub cursor: u64,
    /// The bytes that put a terminal into the session's state.
    ///
    /// Empty for a projected attachment: its screen is state rather than bytes, and it is queued
    /// through its own subscription by [`Session::install_projection`].
    pub bytes: Vec<u8>,
}

/// One live session.
pub struct Session {
    config: SessionConfig,
    state: SessionState,
    pty: Pty,
    shell: Option<RootShell>,
    attachments: AttachmentTable,
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
    history: OutputHistory,
    hub: OutputHub,
    journal: Option<Journal>,
    journal_failure: Option<String>,
    /// The one time contract every expiry in this session is decided by.
    ///
    /// Retention is the consumer that exists today: section 9 stops expiry-based collection while
    /// the wall clock cannot be proved, and this is what answers that. A signed object that
    /// outlives a reboot is the other consumer, and no store holds one yet.
    time: Arc<crate::action::time::TimeContract>,
    closure: Option<ClosureRecord>,
    application_state: Option<ApplicationState>,
    closing_reason: Option<ClosureReason>,
    created_at_ms: TimestampMs,
    pending_input: Vec<InputBatch>,
    owned: Option<OwnedProcesses>,
    root_exit: Option<ShellExit>,
    /// The desktop this session is bound to, where it is bound to one.
    ///
    /// A desktop-bound session belongs to one graphical login and closes with `desktop_lost` when
    /// that login ends. The watch is what answers the question, and it answers it from a recorded
    /// process identity rather than from this worker's own environment, which cannot change.
    desktop: crate::desktop::Watch,
    /// The canonical grid. Every byte the terminal produces passes through it.
    engine: crate::projection::TerminalEngine,
    /// What the renderings this session has produced could not carry.
    restoration_losses: crate::render::Carried,
    /// How much of the screen each attachment's caller may be shown.
    ///
    /// Section 10's live-screen exception is the currently visible screen and never the buffer
    /// that is not showing, so a caller whose authority is that exception is drawn the active
    /// buffer alone. It is recorded per attachment because every repaint asks the same question
    /// and the caller is not there to be asked again.
    content_scopes: std::collections::BTreeMap<AttachmentId, crate::render::Scope>,
    /// The attachments the host would serve directly and is holding in projected mode.
    ///
    /// Section 8: a transition into live byte forwarding must use a parser-ground boundary with no
    /// incomplete UTF-8 scalar and no incomplete control sequence, and if none is available within
    /// 250 ms the attachment stays projected until one is. Output does not stop for the handoff, so
    /// the wait is recorded here and the attachment is served a projection meanwhile. It never
    /// starts forwarding the middle of an escape sequence.
    forwarding_held:
        std::collections::BTreeMap<AttachmentId, kr_term::snapshot::LiveForwardingHandoff>,
    /// The screen each projected attachment holds, so its next update continues from it.
    ///
    /// Section 8 forbids redrawing ordinary output after every batch. A projected attachment is
    /// therefore installed once and then sent one bounded update per batch, and this is what makes
    /// that possible: an update names the base it continues from, and the base is what the client
    /// was last actually sent.
    projections: crate::snapshot::Bases,
    /// The host's own answers that have been queued for the application and not yet written.
    ///
    /// The response lane bounds what it holds; this bounds what has left the lane. Counting only
    /// what is in `pending_input` would count nothing, because every flush hands that vector to
    /// the writer, so the counter is shared with the writer and comes down as each batch is
    /// written.
    /// Every byte queued for the pseudo-terminal, across every producer, released by the writer.
    queued_input_bytes: Arc<std::sync::atomic::AtomicUsize>,
    /// The part of that which belongs to the **current** lease, and which a lease change discards.
    ///
    /// What is left is the response lane's share, so the two bounds section 8 and section 9 name
    /// are read from one pair of counters rather than three. The lease's epoch travels with the
    /// count in one word, because the two have to move together: a lease change takes the word and
    /// leaves the next epoch with nothing, and a writer still finishing the previous lease's bytes
    /// finds an epoch that is no longer its own and subtracts nothing. That is what makes the bytes
    /// a takeover reports as discarded that lease's own, counted once.
    queued_lease_bytes: Arc<crate::runtime::LeaseBytes>,
    /// Whether the application is inside a bracketed paste, as the writer has actually delivered
    /// it. The framer says what the accepted stream means; this says what arrived.
    delivered_paste_open: Arc<std::sync::atomic::AtomicU64>,
    /// The boundary the writer and a lease change share, described at [`Session::input_gate`].
    input_gate: Arc<std::sync::Mutex<()>>,
    /// Set by the writer on its way out, when the terminal will take nothing more.
    ///
    /// Input accepted after that would be acknowledged and never written, which is the one thing an
    /// acknowledgement must not mean. The writer ends only for a terminal that has actually gone:
    /// it waits out an application that has merely paused.
    terminal_gone: Arc<std::sync::atomic::AtomicBool>,
    /// When the authority behind the bytes the recogniser is still holding runs out.
    ///
    /// A held delimiter prefix is queued later than the write that produced it: by its own
    /// deadline, by the paste mode being turned off, or by the next write completing it. It is
    /// still that write's authority that admitted it. The tightest deadline of the writes whose
    /// bytes are in the prefix is what it carries, so a prefix that outlived the grant behind it
    /// is fenced with everything else that grant sent.
    held_input_deadline: Option<u64>,
    /// The lease epoch the writer compares every queued batch against.
    ///
    /// The session publishes it the moment the lease changes, which is what lets the count of what
    /// that lease left behind be taken *after* the writer can no longer add to it or write from it.
    input_fence: Arc<std::sync::atomic::AtomicU64>,
    /// Set while a lease change is queued for the writer and not yet taken.
    ///
    /// One is enough: the writer looks at the fence when it takes a batch, so a second would ask
    /// the same question again. It is what keeps a caller that takes and releases the lease in a
    /// loop from queueing without bound.
    lease_change_queued: Arc<std::sync::atomic::AtomicBool>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Session")
            .field("session_id", &self.config.session_id)
            .field("state", &self.state)
            .field("attachments", &self.attachments.len())
            .field("cursor", &self.history.next_cursor())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Creates the pseudo-terminal and opens the durable stores, without starting a shell.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal cannot be created. A journal that cannot be opened is
    /// recorded rather than fatal: an authorised stop must still work without one.
    pub fn open(config: SessionConfig) -> Result<Self> {
        // The creation geometry is admitted here rather than only inside the terminal, so a
        // request that breaks more than one of section 8's three constraints is told about all of
        // them at once instead of one refusal at a time.
        crate::attachments::admit(config.dimensions)?;
        let pty = Pty::open(config.dimensions)?;
        let engine = crate::projection::TerminalEngine::new(config.dimensions)?;
        let history = match config.spool_directory.as_ref() {
            Some(directory) => {
                OutputHistory::with_spool(config.resident_bytes, directory, SpoolLayout::DEFAULT)?
            }
            None => OutputHistory::in_memory(config.resident_bytes),
        };
        let boot_identity = kr_ipc::identity::boot_identity().map_err(|error| {
            WorkerError::ResourceUnavailable {
                detail: error.to_string(),
            }
        })?;
        let (mut journal, mut journal_failure) = match config.journal_path.as_ref() {
            Some(path) => match Journal::open(path) {
                Ok(journal) => (Some(journal), None),
                Err(error) => (None, Some(error.to_string())),
            },
            None => (Journal::in_memory().ok(), None),
        };
        // The host time contract, over this machine's own clocks and its own time service, built
        // from what the host wrote down before it restarted. The trust, the furthest reading it
        // could prove and the objects it had already expired are what a restarted host cannot
        // work out again, so they are read back before anything expiry-dependent is served.
        //
        // A recorded state that cannot be read is not the same as nothing recorded. Nothing
        // recorded is a host with no history, and its own time service decides; this is a host
        // whose history is unreadable, and the only safe reading of that is a clock it cannot
        // prove. Fresh actions bounded by this boot's continuous clock keep working either way.
        //
        // The configured time authority is empty until a host configuration carries one, and an
        // empty name is a host with none: no automatic retrust qualifies, and the owner's explicit
        // one is the only route left. That is the conservative reading of section 9's "configured
        // host time authority" rather than accepting whatever calls itself one.
        let recorded = match journal.as_ref().map(Journal::read_host_time) {
            Some(Ok(recorded)) => recorded,
            Some(Err(error)) => {
                journal_failure.get_or_insert_with(|| error.to_string());
                Some(kr_protocol::action::HostTimeState {
                    checkpoint: kr_protocol::scalars::Nullable::null(),
                    trust: kr_protocol::action::WallClockTrust::Unresolved,
                    owner_confirmed: false,
                    proven: kr_protocol::scalars::Nullable::null(),
                    tombstones: Vec::new(),
                })
            }
            None => None,
        };
        let time = Arc::new(crate::action::time::TimeContract::restore(
            boot_identity,
            String::new(),
            crate::action::time::TimeSources::system(),
            recorded,
        ));
        if let Some(journal) = journal.as_mut() {
            // Recovery, in the order section 9 gives it. The clocks are looked at first, because
            // everything after it depends on what they say: a dispatch marker with no
            // authoritative answer is unresolvable from here, so it becomes unknown and is never
            // dispatched again; an accepted intent with no marker is rejected, because the
            // freshness it was admitted under cannot be proved after a restart. A failure here is
            // recorded rather than swallowed: a journal that could not be recovered is one whose
            // receipts do not say what happened.
            //
            // Retention is not part of recovery. It is maintenance, it runs on the host's own
            // cadence while it serves, and running it here as well would only mean collecting
            // against a clock that had just been read for the first time.
            time.observe();
            let (state, generation) = time.durable_state();
            let recovery = journal
                .resolve_unfinished_dispatches(kr_ipc::now_ms())
                .and_then(|_| journal.reject_unrevalidated_intents(kr_ipc::now_ms()))
                .and_then(|_| journal.record_host_time(&state));
            match recovery {
                Ok(()) => time.note_saved(generation),
                Err(error) => {
                    journal_failure.get_or_insert_with(|| error.to_string());
                }
            }
        }
        Ok(Self {
            attachments: AttachmentTable::new(config.dimensions),
            state: SessionState::Creating,
            pty,
            shell: None,
            lease: InputLease::new(),
            framer: PasteFramer::new(),
            interrupted: Interrupted::default(),
            history,
            hub: OutputHub::new(),
            journal,
            journal_failure,
            time,
            closure: None,
            application_state: None,
            closing_reason: None,
            created_at_ms: kr_ipc::now_ms(),
            pending_input: Vec::new(),
            owned: None,
            root_exit: None,
            content_scopes: std::collections::BTreeMap::new(),
            // Bound before the shell starts, from the desktop the create request recorded. A
            // desktop that has already gone by now is a session that never had one, and the watch
            // says so from the first question rather than from a change it would never see.
            desktop: crate::desktop::Watch::bind(config.worker_profile, &config.desktop),
            engine,
            restoration_losses: crate::render::Carried::default(),
            forwarding_held: std::collections::BTreeMap::new(),
            projections: crate::snapshot::Bases::new(),
            queued_input_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            queued_lease_bytes: Arc::new(crate::runtime::LeaseBytes::new()),
            input_gate: Arc::new(std::sync::Mutex::new(())),
            terminal_gone: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            held_input_deadline: None,
            input_fence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            delivered_paste_open: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            lease_change_queued: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            config,
        })
    }

    /// Starts the root shell and moves the session to `live`.
    ///
    /// # Errors
    ///
    /// Returns an error when the shell cannot be started. The session is closed with
    /// `root_launch_failed` so a failed creation leaves a record rather than a stuck `creating`.
    pub fn launch(&mut self) -> Result<()> {
        if self.state != SessionState::Creating {
            return Err(WorkerError::InvalidArgument(
                "a root shell starts once, during creation".to_owned(),
            ));
        }
        let command = self.config.shell.clone();
        match self.pty.launch(&command) {
            Ok(shell) => {
                // Ownership is established with the shell, not at closure: a process that started
                // and ended while the session ran is still one this session owned, and a boundary
                // created afterwards would never have seen it.
                self.owned = Some(OwnedProcesses::establish(
                    crate::ownership::boundary_for(shell.foreground_group(), shell.identity()),
                    shell.identity().clone(),
                ));
                self.shell = Some(shell);
                self.state = SessionState::Live;
                self.application_state = Some(ApplicationState::ShellReady);
                // What the session is, written where a reader can find it after this worker is
                // gone. Without it a closed session is only a closure record, and the shell it ran,
                // the directory it ran in and when it started are lost with the process.
                let summary = self.summary();
                if let Some(journal) = self.journal.as_mut()
                    && let Err(error) = journal.record_session(&summary)
                {
                    self.journal_failure = Some(error.to_string());
                }
                Ok(())
            }
            Err(error) => {
                self.record_closure(ClosureReason::RootLaunchFailed, None);
                Err(error)
            }
        }
    }

    /// Returns the session's identity.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.config.session_id
    }

    /// Returns the lifecycle state.
    #[must_use]
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Returns the session epoch.
    #[must_use]
    pub const fn epoch(&self) -> SessionEpoch {
        self.config.session_epoch
    }

    /// Returns the cursor after the last output byte.
    #[must_use]
    pub const fn output_cursor(&self) -> u64 {
        self.history.next_cursor()
    }

    /// Records every process the session's ownership boundary currently holds.
    ///
    /// The set is built up while the session runs. A process that appears once and is gone by the
    /// next look was still this session's, and is accounted for in its closure record.
    pub fn observe_owned(&mut self) {
        if let Some(owned) = self.owned.as_mut() {
            owned.observe();
        }
    }

    /// Returns whether the login session a desktop-bound worker was bound to has ended.
    ///
    /// A headless worker is bound to nothing and answers false: outliving a logout is what that
    /// profile is for. A desktop-bound one is bound to one graphical login, and a login that has
    /// ended means the desktop this session belongs to is gone with it.
    ///
    /// The supervision asks this on every wake, so the answer costs one kernel query about the
    /// process that owns the login session, taken at most once a second. Once the desktop has
    /// gone the answer stays: a new login is a different desktop and nothing is ever rebound to
    /// it.
    pub fn desktop_lost(&mut self) -> bool {
        self.desktop.lost(std::time::Instant::now())
    }

    /// Returns what the session owns, once its shell has started.
    #[must_use]
    pub const fn owned(&self) -> Option<&OwnedProcesses> {
        self.owned.as_ref()
    }

    /// Returns the root shell's process identity while one is running.
    #[must_use]
    pub fn root_identity(&self) -> Option<kr_protocol::identity::ProcessStartIdentity> {
        self.shell.as_ref().map(|shell| shell.identity().clone())
    }

    /// Returns a reader for the terminal's output.
    ///
    /// # Errors
    ///
    /// Returns an error when the reader cannot be cloned.
    pub fn output_reader(&self) -> Result<Box<dyn std::io::Read + Send>> {
        self.pty.reader()
    }

    /// Returns the writer for terminal input.
    ///
    /// # Errors
    ///
    /// Returns an error when the writer has already been taken.
    pub fn input_writer(&self) -> Result<Box<dyn std::io::Write + Send>> {
        self.pty.writer()
    }

    /// Returns the handle the writer waits on before it hands the terminal more input.
    #[must_use]
    pub fn input_waiter(&self) -> Option<crate::pty::InputWaiter> {
        self.pty.input_waiter()
    }

    /// Returns the handle the read loop waits on when the application has written nothing.
    #[must_use]
    pub fn output_waiter(&self) -> Option<crate::pty::OutputWaiter> {
        self.pty.output_waiter()
    }

    /// Discards the framing the lease that is ending left behind.
    ///
    /// The held delimiter prefix goes with it, so the deadline that prefix was carrying goes too.
    /// Leaving it would put an ended actor's authority on the next actor's first keystrokes: the
    /// bytes it belonged to have been discarded, and the deadline is a fact about those bytes.
    fn close_framing_for_takeover(&mut self) -> crate::input::TakeoverFraming {
        self.held_input_deadline = None;
        self.framer.close_for_takeover()
    }

    /// Ends the lease that was in force and returns what it left the writer holding.
    ///
    /// The fence and the count are one step, taken on the boundary the writer also takes: after
    /// this returns, no write of that lease's bytes can begin, and none was part way through while
    /// the count was taken. That is what makes the number a receipt can quote exact rather than an
    /// estimate of what a writer might still be doing.
    fn end_lease(&mut self) -> LeaseEnded {
        let gate = Arc::clone(&self.input_gate);
        let boundary = gate.lock().expect("the input boundary is not poisoned");
        // Read before the fence goes out. The writer clears this latch when it sees the fence
        // change, so a read afterwards can find the zero the writer wrote for this very change and
        // report that no paste was interrupted when one was. Before the fence, no writer can have
        // seen it, and a latch an *earlier* change left set was reported by that change.
        let paste_open_for = self
            .delivered_paste_open
            .load(std::sync::atomic::Ordering::Acquire);
        self.note_lease_holder();
        let left = self.queued_lease_bytes.take(self.lease.epoch()) as u64;
        drop(boundary);
        LeaseEnded {
            left,
            paste_open_for,
        }
    }

    /// Returns the boundary the writer and a lease change share.
    ///
    /// Inside it are the fence, one write that refuses to wait, and the accounting for what that
    /// write sent; outside it is the waiting for a terminal with no room. A lease change takes the
    /// same boundary, which is what makes "this lease's bytes are no longer wanted" and "these
    /// bytes have just been written" one order rather than two races.
    #[must_use]
    pub fn input_gate(&self) -> Arc<std::sync::Mutex<()>> {
        Arc::clone(&self.input_gate)
    }

    /// Returns the latch the writer sets when the terminal will take nothing more.
    ///
    /// The writer holds it for the one moment it ends: a terminal that has gone. From then on this
    /// session refuses input rather than acknowledging bytes nothing will write.
    #[must_use]
    pub fn terminal_gone_latch(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.terminal_gone)
    }

    /// Renders the session for the wire.
    #[must_use]
    pub fn summary(&self) -> SessionSummary {
        SessionSummary {
            session_id: self.config.session_id,
            session_epoch: self.config.session_epoch,
            environment_id: self.config.environment_id,
            display_number: self.config.display_number,
            state: self.state,
            shell_mode: self.config.shell_mode,
            shell_path: self.config.shell.program.clone(),
            cwd: self.config.shell.cwd.clone(),
            worker_profile: self.config.worker_profile,
            desktop: self.config.desktop.clone(),
            created_at_ms: self.created_at_ms,
            dimensions: self.attachments.dimensions(),
            attachment_count: U64::new(self.attachments.len() as u64),
            application_state: Nullable(self.application_state),
            root_process: Nullable(self.root_identity()),
            closure: Nullable(self.closure.clone()),
        }
    }

    /// Returns the geometry and its owner.
    #[must_use]
    pub fn geometry(&self) -> GeometryState {
        self.attachments.geometry()
    }

    /// Returns the input lease.
    #[must_use]
    pub fn lease(&self) -> InputLeaseState {
        self.lease.to_wire()
    }

    /// Moves the session's canonical size, in the kernel and in the grid together.
    ///
    /// They are one size. A terminal whose kernel size and canonical grid disagreed would place
    /// its cursor by one and wrap by the other, so neither is moved without the other.
    ///
    /// Telling the subscribers is the caller's, not this function's. A resize advances the
    /// engine's projection, so every client's screen is at the old size and nothing continues from
    /// it - but the screen each one is then given is drawn for the window that attachment has, and
    /// that window is in the attachment table, which the caller commits after this returns.
    /// Installing here would draw the new grid through the old window.
    fn resize_canonical(&mut self, dimensions: Dimensions) -> Result<()> {
        // The kernel moves first, and the reason is which failure can be undone. A grid that
        // resized has reflowed: rows moved between the screen and the history, and putting the
        // size back would not put those rows back, so a kernel refusal after a successful grid
        // resize would leave the two permanently disagreeing about one size. The kernel's own size
        // is two numbers it stores, so a refusal from the grid can be answered by putting them
        // back, and the only cost is that the application is told the window changed twice.
        //
        // The grid still refuses before it allocates: a size whose two screen buffers do not fit
        // this session's budget is refused with the grid unchanged.
        let previous = self.pty.dimensions();
        self.pty.resize(dimensions)?;
        if let Err(error) = self.engine.resize(dimensions, kr_ipc::now_ms().get()) {
            // Back to the size the grid still has. A second window-change notification is visible
            // to the application; a kernel and a grid that disagree for the rest of the session
            // are not, until something draws in the wrong place.
            if let Err(rollback) = self.pty.resize(previous) {
                // Both directions have now failed, which means the terminal is taking nothing at
                // all. Reporting the first refusal alone would say the size did not move when the
                // kernel's did, so this says what actually happened and names both.
                return Err(WorkerError::ResourceUnavailable {
                    detail: format!(
                        "the canonical grid refused {}x{} ({error}) and the terminal would not go \
                         back to {}x{} ({rollback}), so the two no longer agree",
                        dimensions.columns.get(),
                        dimensions.rows.get(),
                        previous.columns.get(),
                        previous.rows.get()
                    ),
                });
            }
            return Err(error);
        }
        Ok(())
    }

    /// Tells every subscriber that its view of this session is no longer continuous.
    fn require_resync_of_every_subscriber(&mut self) {
        let next = self.history.next_cursor();
        let oldest = self.history.oldest_retained_cursor();
        for attachment_id in self.hub.subscribers() {
            self.hub
                .require_resync(attachment_id, ResyncReason::ProjectionReset, next, oldest);
        }
    }

    /// Installs a fresh screen for every subscriber, naming why the last one does not continue.
    ///
    /// A projected subscriber is installed again *in band*, with the reason: the projection
    /// protocol has a reset of its own, and a client that has been sent one followed by a fresh
    /// snapshot needs no round trip to ask for what it has already been given. A direct subscriber
    /// has no such event, so it is told to resynchronise and asks for a screen itself.
    fn reinstall_every_subscriber(&mut self, reason: ProjectionResetReason) {
        let next = self.history.next_cursor();
        let oldest = self.history.oldest_retained_cursor();
        for attachment_id in self.hub.subscribers() {
            if self.presentation_of(attachment_id) == crate::output::Presentation::Projected {
                let Ok(dimensions) = self.attachment_dimensions(attachment_id) else {
                    continue;
                };
                // Forgetting its base is what makes this an install rather than a continuation.
                self.projections.forget(attachment_id);
                let _ = self.publish_projection(attachment_id, dimensions, Some(reason), oldest);
                continue;
            }
            self.hub
                .require_resync(attachment_id, ResyncReason::ProjectionReset, next, oldest);
        }
    }

    /// Tells the canonical grid where a side effect currently goes.
    ///
    /// A bell, a clipboard write or a notification leaves the terminal, so it goes to exactly one
    /// place: the attachment holding the input lease. Every path that moves the lease passes
    /// through here, so the destination can never be an attachment that stopped holding it.
    fn note_lease_holder(&mut self) {
        let epoch = kr_protocol::ids::InputLeaseEpoch::new(self.lease.epoch());
        self.engine.set_lease_holder(self.lease.holder(), epoch);
        // The fence goes out here, with the change itself. Everything that reads what the lease
        // that just ended left behind reads it afterwards, so the writer can no longer be adding to
        // that count or writing from it while it is being counted.
        self.input_fence
            .store(self.lease.epoch(), std::sync::atomic::Ordering::Release);
        // The writer is told the lease moved, so a paste the old lease left open at the
        // application is closed even when nothing follows it. One outstanding notice answers every
        // change that happens before the writer takes it, because what the writer then reads is
        // the fence as it stands rather than the change that queued the notice.
        if !self
            .lease_change_queued
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.pending_input.push(InputBatch::LeaseChanged);
        }
    }

    /// Returns the flag the writer clears when it has answered a lease change.
    #[must_use]
    pub fn lease_change_queued(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.lease_change_queued)
    }

    /// Returns the writer's record of whether the application is inside a bracketed paste.
    #[must_use]
    pub fn delivered_paste_open(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.delivered_paste_open)
    }

    /// Returns the canonical grid this session's screen lives on.
    #[must_use]
    pub const fn engine(&self) -> &crate::projection::TerminalEngine {
        &self.engine
    }

    /// Returns the bytes that put one attachment's terminal into the session's current screen.
    ///
    /// This is what an attachment is given in place of replayed history. It carries no sequence
    /// that can ring, copy, notify, download, launch or ask anything, because the operations it is
    /// built from have no member that can: a terminal that was not there when the history happened
    /// does not have the history happen to it.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownAttachment`] when the identifier names no attachment of this
    /// session.
    pub fn restoration(&mut self, attachment_id: AttachmentId) -> Result<(u64, Vec<u8>)> {
        let scope = self.content_scope(attachment_id);
        let dimensions = self.attachment_dimensions(attachment_id)?;
        let gate = self.lane_gate();
        let keyboard = self.attachments.keyboard_control(attachment_id);
        let (cursor, restoration, settled) =
            self.engine
                .restoration(dimensions, gate, kr_ipc::now_ms().get(), keyboard, scope);
        // Taking a snapshot settles the screen, and whatever that released belongs to the
        // attachments that were already watching. Delivering it here is what stops one client's
        // snapshot swallowing a character that was owed to another.
        self.deliver(settled);
        self.note_restoration(attachment_id, &restoration);
        Ok((cursor, restoration.bytes))
    }

    /// Narrows what one attachment may be shown of the session's screen.
    ///
    /// It is recorded with the attachment because every later repaint has to answer the same
    /// question and the caller is not there to be asked again. An attachment nobody narrows is
    /// drawn the whole screen, which is the local case: a caller the operating system
    /// authenticated as this user holds no grant to be narrowed by.
    pub fn narrow_content(&mut self, attachment_id: AttachmentId, scope: crate::render::Scope) {
        self.content_scopes.insert(attachment_id, scope);
    }

    /// Returns how much of the screen one attachment's caller may be shown.
    ///
    /// An attachment with no recorded scope is drawn the whole screen. That is the local case: a
    /// caller the operating system authenticated as this user is not narrowed by a grant, because
    /// it holds none.
    fn content_scope(&self, attachment_id: AttachmentId) -> crate::render::Scope {
        self.content_scopes
            .get(&attachment_id)
            .copied()
            .unwrap_or_default()
    }

    /// Returns the screen one attachment joins on, in the form that attachment is served in.
    ///
    /// The two forms are not interchangeable. An attachment whose own terminal is the session's
    /// size and can take the stream is handed bytes, because its screen *is* a terminal and the
    /// restoration has to put that terminal into the session's state before live output resumes. A
    /// projected attachment is handed the canonical grid as state and draws it itself, which is
    /// what lets a terminal of another size show the session without being sent bytes that assume
    /// it is the session's size.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::UnknownAttachment`] when the identifier names no attachment of this
    /// session.
    pub fn join(&mut self, attachment_id: AttachmentId) -> Result<Joined> {
        // Whether this attachment may be handed the stream at all is settled first. A screen and a
        // byte cursor have to name the same boundary, so an attachment joining while the parser is
        // mid-sequence is served a projection and moves to forwarding when a boundary arrives.
        // This attachment is named as the one installing, because a join is a fresh start whatever
        // it was being served a moment ago: an attachment that is already forwarding and asks for
        // a screen is asking to begin again, and beginning again has to meet a boundary.
        self.settle_forwarding(kr_ipc::now_ms().get(), Some(attachment_id));
        if self.presentation_of(attachment_id) == crate::output::Presentation::Projected {
            // The screen is settled here, before this attachment has a queue, and whatever that
            // released is delivered to the attachments that were already watching. Settling inside
            // the snapshot instead would let this client's snapshot swallow a character that was
            // owed to another.
            self.deliver(crate::projection::Filtered::default());
            // Its own screen is state, and it goes through the queue like every other delivery, so
            // that it is charged to this subscriber's bound rather than written around it. That
            // happens in `install_projection`, once the queue exists.
            return Ok(Joined {
                cursor: self.history.next_cursor(),
                bytes: Vec::new(),
            });
        }
        let (cursor, bytes) = self.restoration(attachment_id)?;
        Ok(Joined { cursor, bytes })
    }

    /// Queues the screen a projected attachment joins on, through its own subscription.
    ///
    /// Called after the subscription exists, because the events are charged to that subscriber's
    /// queue: a screen written around the queue is a screen a client with an eight-kilobyte bound
    /// could be sent several megabytes of. They are the first thing in the queue, so they are still
    /// the first thing the client receives.
    ///
    /// A direct attachment is a no-op here: its screen is the bytes [`Session::join`] returned.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is unknown or the engine's state cannot be spelled on
    /// the wire.
    pub fn install_projection(&mut self, attachment_id: AttachmentId) -> Result<()> {
        if self.presentation_of(attachment_id) != crate::output::Presentation::Projected {
            return Ok(());
        }
        let dimensions = self.attachment_dimensions(attachment_id)?;
        let oldest = self.history.oldest_retained_cursor();
        // Forgetting first is what makes this an install rather than a continuation: whatever an
        // earlier subscription of this attachment was left holding is not what it is about to be
        // sent.
        self.projections.forget(attachment_id);
        let _ = self.publish_projection(attachment_id, dimensions, None, oldest);
        Ok(())
    }

    /// What the smallest screen this session can install on one attachment costs its send queue.
    ///
    /// Every message of the installation, not the largest one: a client holding some of them holds
    /// no screen. It is what [`Self::subscribe_within`] refuses a smaller queue against, and it
    /// changes nothing about the session.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is unknown, or when the engine's state cannot be
    /// spelled on the wire.
    pub fn minimum_projection_install(&self, attachment_id: AttachmentId) -> Result<usize> {
        let dimensions = self.attachment_dimensions(attachment_id)?;
        self.engine.minimum_projection_install(
            self.window_of(attachment_id, dimensions),
            self.content_scope(attachment_id),
        )
    }

    /// The retained row one attachment's window starts at, or `None` for the live screen.
    #[must_use]
    pub fn history_window(&self, attachment_id: AttachmentId) -> Option<i64> {
        self.attachments.history_top_row(attachment_id)
    }

    /// What one attachment is looking through: its own size, and where its window sits.
    fn window_of(
        &self,
        attachment_id: AttachmentId,
        dimensions: Dimensions,
    ) -> crate::projection::Window {
        crate::projection::Window {
            dimensions,
            anchor: crate::projection::ViewportAnchor::of(
                self.attachments.history_top_row(attachment_id),
            ),
        }
    }

    /// Returns one attachment's own dimensions, falling back to the session's canonical geometry.
    fn attachment_dimensions(&self, attachment_id: AttachmentId) -> Result<Dimensions> {
        Ok(self
            .attachments
            .own_dimensions(attachment_id)
            .ok_or_else(|| WorkerError::UnknownAttachment {
                attachment: attachment_id.to_string(),
            })?
            .unwrap_or_else(|| self.attachments.geometry().dimensions))
    }

    /// Records where this session's initial palette came from.
    ///
    /// Section 8 fixes the palette at creation and forbids succession from changing it, so this is
    /// called once, before the session has produced anything. Every snapshot then carries the
    /// provenance, so a client can say where the colours it is drawing came from.
    ///
    /// # Errors
    ///
    /// Returns an error once the session has produced output.
    pub fn set_initial_palette(&mut self, choice: crate::snapshot::PaletteChoice) -> Result<()> {
        self.engine.set_initial_palette(choice)
    }

    /// Where the session's palette came from.
    #[must_use]
    pub fn palette_source(&self) -> kr_term::palette::PaletteSource {
        self.engine.palette_source()
    }

    /// Records what a rendered restoration could not carry.
    ///
    /// Nothing is silently lost: the renderer counts every omission, and this is where the session
    /// keeps the count so a person asking the host doctor can be told.
    fn note_restoration(
        &mut self,
        attachment_id: AttachmentId,
        restoration: &crate::render::Restoration,
    ) {
        let carried = restoration.carried;
        // What this screen could not carry decides how the attachment that was given it is served
        // from here: a terminal that continues the raw stream from a screen missing the state the
        // application is about to address shows something the session does not have.
        self.attachments
            .note_restoration(attachment_id, carried.continues_the_stream());
        self.restoration_losses.inactive_rows += carried.inactive_rows;
        self.restoration_losses.other_saved_cursors += carried.other_saved_cursors;
        self.restoration_losses.title_stack += carried.title_stack;
        self.restoration_losses.clipped_rows += carried.clipped_rows;
        self.restoration_losses.soft_wraps += carried.soft_wraps;
        self.restoration_losses.other_keyboard |= carried.other_keyboard;
        self.restoration_losses.keyboard_stack += carried.keyboard_stack;
        self.restoration_losses.pending_wrap |= carried.pending_wrap;
    }

    /// Returns what the renderings this session has produced could not carry.
    #[must_use]
    pub const fn restoration_losses(&self) -> crate::render::Carried {
        self.restoration_losses
    }

    /// Returns the terminal engine's rate-limited diagnostic totals.
    #[must_use]
    pub fn terminal_diagnostics(&self) -> Vec<(kr_term::diag::DiagnosticKind, u64)> {
        self.engine.diagnostics()
    }

    /// Adds an attachment.
    ///
    /// # Errors
    ///
    /// Returns an error when the session is closed or the request is not valid.
    pub fn attach(
        &mut self,
        params: &SessionAttachParams,
        granted: CanonicalSet<AttachmentCapability>,
        attachment_id: AttachmentId,
    ) -> Result<SessionAttachResult> {
        self.require_running()?;
        let previous = self.attachments.geometry();
        let (mut attachment, change) =
            self.attachments
                .attach(params, granted, attachment_id, kr_ipc::now_ms())?;

        if change.resize_required
            && let Err(error) = self.resize_canonical(change.state.dimensions)
        {
            // The kernel refused the size, so the attachment never happened. The table and the
            // geometry both go back to exactly what they were, epoch included: a refused change
            // that left the epoch moved would invalidate every client's next request over
            // something that did not happen.
            let _ = self.attachments.detach(attachment_id);
            self.attachments.restore_geometry(&previous);
            return Err(error);
        }
        if change.resize_required {
            // The size moved, so every client's screen is at the old one. The table already holds
            // this attachment and its window, so each screen is drawn for the window it belongs to.
            self.reinstall_every_subscriber(ProjectionResetReason::Geometry);
        }
        // Whether this attachment may forward depends on where the parser stands, which is a fact
        // about this moment rather than about the attachment. It is settled here so the answer the
        // attach reports is the answer the session will act on, rather than one that changes
        // between the attach and the subscription. This attachment has nothing to continue from,
        // so it is the one installing.
        self.settle_forwarding(kr_ipc::now_ms().get(), Some(attachment_id));
        if let Some(settled) = self
            .attachments
            .summaries()
            .into_iter()
            .find(|summary| summary.attachment_id == attachment_id)
        {
            attachment = settled;
        }
        Ok(SessionAttachResult {
            attachment,
            geometry: change.state,
            output_cursor: U64::new(self.history.next_cursor()),
        })
    }

    /// Removes an attachment, releasing whatever it held.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is unknown.
    pub fn detach(&mut self, attachment_id: AttachmentId) -> Result<SessionDetachResult> {
        self.content_scopes.remove(&attachment_id);
        // Undelivered input from the removed attachment goes with it; nothing is replayed. A paste
        // it had open is closed first, so the application is not left inside a bracketed paste
        // whose source has gone.
        let held = self.lease.holder() == Some(attachment_id);
        let ending_epoch = self.lease.epoch();
        let discarded_queue = self.lease.release_attachment(attachment_id);
        if held {
            let framing = self.close_framing_for_takeover();
            let ended = self.end_lease();
            // The source of this input has gone, which is the loss section 8 asks to be reported.
            // The attachment that is leaving has no answer left to read it in, so it is carried to
            // whoever takes the keys next.
            self.interrupted.bytes = self
                .interrupted
                .bytes
                .saturating_add(discarded_queue)
                .saturating_add(ended.left)
                .saturating_add(framing.discarded_prefix.len() as u64);
            self.interrupted.closed_open_paste |= framing.terminator.is_some()
                || Self::delivered_paste_was_ours(&ended, ending_epoch);
        } else {
            self.note_lease_holder();
        }
        self.pump_replies();
        self.hub.detached(attachment_id);
        self.projections.forget(attachment_id);
        // The handoff this attachment was waiting on goes with it. An attachment that left while a
        // sequence was still arriving would otherwise leave an entry nothing ever visits again.
        self.forwarding_held.remove(&attachment_id);
        let previous = self.attachments.geometry();
        let change = self.attachments.detach(attachment_id)?;
        if change.resize_required
            && self.state.is_running()
            && let Err(error) = self.resize_canonical(change.state.dimensions)
        {
            // The attachment is gone either way — it asked to leave — but the geometry it would
            // have handed on is not moved when the kernel refuses the size.
            self.attachments.restore_geometry(&previous);
            return Err(error);
        }
        if change.resize_required && self.state.is_running() {
            // Succession moved the size, so every remaining client's screen is at the old one.
            // After the table, because the screen each is given is drawn for the window it has.
            self.reinstall_every_subscriber(ProjectionResetReason::Geometry);
        }
        Ok(SessionDetachResult {
            attachment_id,
            geometry: change.state,
            remaining: U64::new(self.attachments.len() as u64),
        })
    }

    /// Records an attachment's own dimensions.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is unknown or the dimensions are not valid.
    pub fn viewport(
        &mut self,
        attachment_id: AttachmentId,
        dimensions: Dimensions,
        position: Option<kr_protocol::attachment::ViewportPosition>,
    ) -> Result<(TerminalPresentationMode, Option<i64>)> {
        let before = self.presentation_of_attachment(attachment_id);
        let before_dimensions = self.attachments.own_dimensions(attachment_id).flatten();
        let before_top_row = self.attachments.history_top_row(attachment_id);
        // The same two answers the dispatch asked for before it marked the effect. Asked again
        // because this is callable on its own, and because asking twice costs a measurement while
        // not asking costs a refusal nobody can read.
        self.window_refusal(attachment_id, dimensions, position)?;
        // Resolved against the session as it stands now: an offset above the live screen is a
        // place, and the row it names is what the attachment holds from here.
        let top_row = self.engine.resolve_position(position);
        let presentation = self
            .attachments
            .viewport(attachment_id, dimensions, top_row)?;
        // A window that changed size is looking at a different part of the grid, and one that
        // changed presentation is being served a different thing altogether. Either way what it
        // holds is no longer continuous with what it is about to be sent, so it is told now rather
        // than on the next byte the application happens to write - which for an idle session may
        // be never, and the person would sit looking at a screen drawn for another size.
        // A presentation that changed needs a fresh screen, and so does a viewport whose window
        // moved: what it is drawn is clipped to that window. A report that repeated the size the
        // attachment already had changed nothing, and stopping its output to redraw the same screen
        // would make an idle client that reports its size on a timer never see anything else.
        let no_longer_continuous = before != Some(presentation)
            || (presentation == TerminalPresentationMode::Viewport
                && before_dimensions != Some(dimensions));
        if no_longer_continuous {
            let next = self.history.next_cursor();
            let oldest = self.history.oldest_retained_cursor();
            self.hub
                .require_resync(attachment_id, ResyncReason::ProjectionReset, next, oldest);
        } else if before_top_row != top_row {
            // The window moved without the terminal changing. Nothing about the session changed
            // either, so there is nothing for the client to ask again for: the pages that cover
            // where it is now looking are queued through its own subscription, charged to its own
            // bound, exactly as the first screen was.
            self.install_projection(attachment_id)?;
        }
        Ok((presentation, top_row))
    }

    /// Returns how one attachment is currently being shown the session, without changing anything.
    fn presentation_of_attachment(
        &mut self,
        attachment_id: AttachmentId,
    ) -> Option<TerminalPresentationMode> {
        self.attachments
            .set_carryable(self.engine.direct_is_carryable());
        self.attachments
            .summaries()
            .into_iter()
            .find(|summary| summary.attachment_id == attachment_id)
            .and_then(|summary| summary.presentation.0)
    }

    /// Adds or withdraws a geometry claim.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is unknown or may not claim geometry.
    pub fn configure(
        &mut self,
        attachment_id: AttachmentId,
        claim_geometry: bool,
    ) -> Result<GeometryState> {
        let previous = self.attachments.geometry();
        let change = self.attachments.configure(attachment_id, claim_geometry)?;
        if change.resize_required
            && self.state.is_running()
            && let Err(error) = self.resize_canonical(change.state.dimensions)
        {
            // A withdrawn claim stays withdrawn, because the attachment asked for that, but the
            // geometry it would have handed on is not moved when the kernel refuses the size, and
            // the size does not go back to an attachment that no longer claims it.
            self.attachments.restore_geometry(&previous);
            return Err(error);
        }
        if change.resize_required && self.state.is_running() {
            // The claim moved the size, so every client's screen is at the old one.
            self.reinstall_every_subscriber(ProjectionResetReason::Geometry);
        }
        Ok(change.state)
    }

    /// Changes the canonical geometry at the owner's request.
    ///
    /// # Errors
    ///
    /// Returns an error when the caller does not own the size, names a stale epoch, or asks for a
    /// geometry that violates a constraint.
    pub fn resize(
        &mut self,
        attachment_id: AttachmentId,
        dimensions: Dimensions,
        expected_epoch: u64,
    ) -> Result<GeometryState> {
        self.require_running()?;
        // Ask the kernel first. A table that recorded a size the terminal never took would leave
        // every attachment drawing at a geometry the application does not have.
        self.attachments
            .check_resize(attachment_id, dimensions, expected_epoch)?;
        self.resize_canonical(dimensions)?;
        let change = self
            .attachments
            .resize(attachment_id, dimensions, expected_epoch)?;
        // After the table, because the screen each client is given is drawn for the window that
        // client has and the owner's own window is one of the things that just changed.
        self.reinstall_every_subscriber(ProjectionResetReason::Geometry);
        Ok(change.state)
    }

    /// Hands size ownership to another eligible attachment.
    ///
    /// # Errors
    ///
    /// Returns an error when the target is unknown or not eligible, or the epoch is stale.
    pub fn transfer_geometry(
        &mut self,
        attachment_id: AttachmentId,
        expected_epoch: u64,
    ) -> Result<GeometryState> {
        self.require_running()?;
        let previous = self.attachments.geometry();
        let change = self.attachments.transfer(attachment_id, expected_epoch)?;
        if change.resize_required {
            if let Err(error) = self.resize_canonical(change.state.dimensions) {
                // The transfer is undone, owner and epoch together: a half-completed handover would
                // leave the session with an owner whose size it never took.
                self.attachments.restore_geometry(&previous);
                return Err(error);
            }
            // The new owner's size is the session's now, so every client's screen is at the old
            // one. After the transfer, because each screen is drawn for the window its client has.
            self.reinstall_every_subscriber(ProjectionResetReason::Geometry);
        } else {
            // The size did not move, so nothing above resynchronised anybody - and every
            // attachment's picture of who owns the size and at which epoch has still changed.
            // Section 8 requires them to be told atomically, so they are told here, inside the same
            // locked step that moved the ownership, and the snapshot each one then asks for carries
            // the committed owner and epoch.
            self.require_resync_of_every_subscriber();
        }
        Ok(change.state)
    }

    /// Takes the input lease for an attachment.
    ///
    /// # Errors
    ///
    /// Returns an error when the session is closed or the attachment is unknown.
    pub fn acquire_input(
        &mut self,
        attachment_id: AttachmentId,
        connection_id: ConnectionId,
        expected_epoch: Option<u64>,
    ) -> Result<InputAcquireResult> {
        self.require_running()?;
        if self.attachments.get(attachment_id).is_none() {
            return Err(WorkerError::UnknownAttachment {
                attachment: attachment_id.to_string(),
            });
        }
        if let Some(expected) = expected_epoch
            && expected != self.lease.epoch()
        {
            return Err(WorkerError::LeaseLost);
        }
        self.input_compatible(attachment_id)?;

        // An interrupted paste is closed before the new lease writes, so the application never
        // sees a paste finished under a different actor.
        let framing = self.close_framing_for_takeover();
        // Read before the lease moves: it is the ending lease's answer, not the new one's.
        let ending_epoch = self.lease.epoch();
        let discarded_queue = self.lease.acquire(attachment_id, connection_id);
        // The lease ends and what it left behind is counted in one step, on the boundary the writer
        // takes for every write: no byte of this lease's can be written after it, and none was
        // being written while it was counted. Taking the counter rather than reading it is what
        // makes the answer that lease's own: the next takeover starts from zero and cannot report
        // these bytes again.
        let ended = self.end_lease();
        let mut discarded = ended.left;
        discarded += discarded_queue;
        discarded += framing.discarded_prefix.len() as u64;
        // A paste is reported as closed when one was open in the stream this lease accepted, or
        // when one is open at the application: the writer keeps the second, because a terminator
        // the framer accepted may have been queued behind a writer that never wrote it.
        let mut closed_open_paste =
            framing.terminator.is_some() || Self::delivered_paste_was_ours(&ended, ending_epoch);
        // Plus whatever a lease the host ended by itself left behind. It had no answer of its own
        // to be reported in, so it is reported here, once, and then it is nobody's any more.
        let carried = std::mem::take(&mut self.interrupted);
        discarded = discarded.saturating_add(carried.bytes);
        closed_open_paste |= carried.closed_open_paste;
        // Nothing is queued for the terminator here. The writer closes a paste the application is
        // actually inside, before anything from the new lease reaches it; queueing a correction
        // under the old lease is what let one be discarded with it.
        self.pump_replies();
        Ok(InputAcquireResult {
            lease: self.lease.to_wire(),
            discarded_bytes: U64::new(discarded),
            closed_open_paste,
        })
    }

    /// Releases the lease held by this attachment.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::LeaseLost`] when the caller does not hold it at that epoch.
    pub fn release_input(
        &mut self,
        attachment_id: AttachmentId,
        epoch: u64,
    ) -> Result<InputLeaseState> {
        let ending_epoch = self.lease.epoch();
        let discarded_queue = self
            .lease
            .release(attachment_id, epoch)
            .ok_or(WorkerError::LeaseLost)?;
        // A paste this lease opened is closed as it goes. Leaving it open would put the
        // application into a bracketed paste that nothing was ever going to end, so the next
        // keystroke would arrive inside somebody else's paste. The writer supplies the terminator,
        // because it is the only thing that knows whether the application ever saw the start.
        let framing = self.close_framing_for_takeover();
        // What this lease handed over and the writer has not written goes with it, counted on the
        // same boundary that stopped the writer from touching it. The answer to a release is the
        // lease state, which has nowhere to say it, so it is carried to whoever takes the keys next
        // rather than dropped: an actor that let go of the keys still interrupted whatever it had
        // not delivered.
        let ended = self.end_lease();
        self.interrupted.bytes = self
            .interrupted
            .bytes
            .saturating_add(discarded_queue)
            .saturating_add(ended.left)
            .saturating_add(framing.discarded_prefix.len() as u64);
        self.interrupted.closed_open_paste |=
            framing.terminator.is_some() || Self::delivered_paste_was_ours(&ended, ending_epoch);
        self.pump_replies();
        Ok(self.lease.to_wire())
    }

    /// Accepts ordered input for the pseudo-terminal.
    ///
    /// The bytes are forwarded unchanged. Nothing here decodes, re-encodes or normalises them; the
    /// only thing the worker tracks is where a bracketed paste begins and ends.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::LeaseLost`] for a stale epoch or a caller that does not hold the
    /// lease, and an invalid-argument failure when the sequence does not follow.
    pub fn write_input(
        &mut self,
        attachment_id: AttachmentId,
        epoch: u64,
        sequence: u64,
        bytes: &[u8],
        authority_deadline_boot_ms: Option<u64>,
        now: Instant,
    ) -> Result<InputAccepted> {
        if !self.state.accepts_input() {
            return Err(WorkerError::SessionClosed);
        }
        // A terminal that has gone takes nothing, and an acknowledgement here would say the
        // opposite. The session itself is still open - what happened to the shell is the child
        // monitor's question, not this one's - so this is the resource it is rather than a closure.
        if self
            .terminal_gone
            .load(std::sync::atomic::Ordering::Acquire)
        {
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
        let claimed = bytes.len().saturating_add(crate::input::PASTE_END.len());
        let queued = self
            .queued_input_bytes
            .load(std::sync::atomic::Ordering::Acquire);
        if queued.saturating_add(claimed) > MAX_QUEUED_INPUT_BYTES {
            return Err(WorkerError::ResourceUnavailable {
                detail: format!(
                    "the application is not reading its input and {MAX_QUEUED_INPUT_BYTES} bytes                      are already waiting for it, so these bytes were not accepted"
                ),
            });
        }
        let outcome = self.framer.push(bytes, now);
        // The recogniser can hold bytes back, so what this push forwards may carry bytes an
        // earlier write handed over. Whichever authority ends first is the one that decides: an
        // earlier write's deadline never gets extended by a later write, and a later write's
        // never gets extended by an earlier one.
        let admitted = tightest(self.held_input_deadline, authority_deadline_boot_ms);
        if !outcome.forward.is_empty() {
            // The framer's own state after the push is what these bytes leave the application in,
            // because `forward` carries every delimiter the push completed and no part of one it
            // did not. Whether a start is among them is the separate question the writer asks when
            // it has delivered only part of the batch.
            let paste = PasteTransition {
                delimiters: outcome.delimiters.clone(),
            };
            self.queue_input(InputBatch::Lease {
                epoch,
                bytes: outcome.forward.clone(),
                paste,
                authority_deadline_boot_ms: admitted,
            });
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
        // A paste that has just closed, or a frame that has just completed, opens the gate the
        // response lane was waiting on. An application that asked a question during one of those
        // and then sat still would otherwise wait for its answer until the next byte of output.
        self.pump_replies();
        Ok(InputAccepted {
            forwarded_bytes: outcome.forward.len() as u64,
            held_prefix_bytes: outcome.held as u64,
            deadline: outcome.deadline,
        })
    }

    /// Forwards a held delimiter prefix whose deadline has passed.
    ///
    /// The timer runs whether or not more input arrives, so a lone Escape is never waiting for
    /// another keystroke.
    pub fn expire_paste_prefix(&mut self, now: Instant) -> usize {
        let epoch = self.lease.epoch();
        let expired = match self.framer.expire(now) {
            Some(bytes) if !bytes.is_empty() => {
                let len = bytes.len();
                // The prefix was accepted when it arrived and counted against the budget then, so
                // it goes through whatever the budget says now: forwarding it unchanged is what
                // the recogniser promised, and it is at most one delimiter long.
                self.queue_input(InputBatch::Lease {
                    epoch,
                    bytes,
                    paste: PasteTransition::default(),
                    authority_deadline_boot_ms: self.held_input_deadline,
                });
                self.held_input_deadline = None;
                len
            }
            _ => 0,
        };
        // The held prefix has gone, so a frame that was open is closed and the response lane's
        // gate is open again.
        self.pump_replies();
        expired
    }

    /// Returns the deadline of a held delimiter prefix, if there is one.
    #[must_use]
    pub fn paste_deadline(&self) -> Option<Instant> {
        self.framer.deadline()
    }

    /// Records that the application has enabled or disabled bracketed-paste mode.
    ///
    /// Turning it off with a mere delimiter prefix held releases those bytes at once: the framing
    /// they were being held for no longer exists, so waiting out a deadline that now guards nothing
    /// would delay a keystroke for no reason. A prefix held inside an open paste keeps waiting,
    /// because that paste still has to be closed before another actor writes.
    pub fn set_bracketed_paste(&mut self, enabled: bool) {
        let released = self.framer.set_bracketed_paste(enabled);
        self.release_prefix(released);
    }

    /// Queues bytes the recogniser has stopped holding, under the lease that sent them.
    fn release_prefix(&mut self, released: Vec<u8>) {
        if released.is_empty() {
            return;
        }
        if self.lease.holder().is_none() {
            // Nothing holds the keys, so these bytes belong to a lease that has ended and went
            // with it. Writing them now would put an ended actor's input in front of the next one.
            self.held_input_deadline = None;
            return;
        }
        self.queue_input(InputBatch::Lease {
            epoch: self.lease.epoch(),
            bytes: released,
            paste: PasteTransition::default(),
            authority_deadline_boot_ms: self.held_input_deadline,
        });
        self.held_input_deadline = None;
        // The held prefix has gone, so a frame that was open is closed and the response lane's
        // gate is open again.
        self.pump_replies();
    }

    /// Returns whether a bracketed paste has been started and not yet ended.
    #[must_use]
    pub const fn paste_open(&self) -> bool {
        self.framer.paste_open()
    }

    /// Sends the terminal's configured interrupt to the foreground process group.
    ///
    /// It takes the current lease and epoch, accepts no other action, and is not held behind a
    /// reader transition.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::LeaseLost`] when the caller does not hold the lease.
    pub fn interrupt(&mut self, attachment_id: AttachmentId, epoch: u64) -> Result<()> {
        if self.lease.holder() != Some(attachment_id) || self.lease.epoch() != epoch {
            return Err(WorkerError::LeaseLost);
        }
        // The terminal's own foreground group first, because that is what the interrupt key
        // reaches. The root shell's group is the fallback for a terminal that will not say.
        if self.pty.interrupt_foreground().is_ok() {
            return Ok(());
        }
        let shell = self.shell.as_mut().ok_or(WorkerError::SessionClosed)?;
        shell.interrupt()
    }

    /// Takes the batches waiting to be written to the pseudo-terminal.
    pub fn take_pending_input(&mut self) -> Vec<InputBatch> {
        std::mem::take(&mut self.pending_input)
    }

    /// Returns the epoch a batch must carry to still be written.
    ///
    /// Everything queued under an earlier epoch is stale. A takeover, a release, a detach or a
    /// close moves this, and the writer drops whatever it is still holding from before.
    #[must_use]
    pub fn input_fence(&self) -> u64 {
        self.lease.epoch()
    }

    /// Returns the published fence the writer compares every queued batch against.
    #[must_use]
    pub fn input_fence_handle(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.input_fence)
    }

    /// Subscribes an attachment to output.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is unknown.
    pub fn subscribe(&mut self, attachment_id: AttachmentId) -> Result<OutputStream> {
        self.subscribe_within(attachment_id, self.config.send_queue_bytes)
    }

    /// Subscribes an attachment to output with its own queue bound.
    ///
    /// The bound is per peer, as section 9 describes it. A client that asks for less gets less,
    /// and nothing lets one client raise the bound for another.
    ///
    /// # Errors
    ///
    /// Returns an error when the attachment is unknown, and
    /// [`WorkerError::InvalidArgument`] when a projected attachment asks for a queue too small to
    /// hold the smallest screen this session can be installed with. That refusal is definite: a
    /// client cannot be sent part of a screen, so the alternative would be a resynchronisation it
    /// would answer by asking for the same screen again.
    pub fn subscribe_within(
        &mut self,
        attachment_id: AttachmentId,
        send_queue_bytes: usize,
    ) -> Result<OutputStream> {
        if self.attachments.get(attachment_id).is_none() {
            return Err(WorkerError::UnknownAttachment {
                attachment: attachment_id.to_string(),
            });
        }
        let limit = send_queue_bytes.clamp(1, self.config.send_queue_bytes);
        let presentation = self.presentation_of(attachment_id);
        if presentation == crate::output::Presentation::Projected {
            let minimum = self.minimum_projection_install(attachment_id)?;
            if limit < minimum {
                return Err(WorkerError::InvalidArgument(format!(
                    "a send queue of {limit} bytes cannot carry this session's screen: the \
                     smallest one it can be installed with is {minimum} bytes, and a client holding \
                     part of a screen holds none of it"
                )));
            }
        }
        Ok(self.hub.subscribe(attachment_id, limit, presentation))
    }

    /// Returns how one attachment is served: the raw stream, or the canonical grid as state.
    fn presentation_of(&mut self, attachment_id: AttachmentId) -> crate::output::Presentation {
        self.attachments
            .set_carryable(self.engine.direct_is_carryable());
        let projected = self
            .attachments
            .projected()
            .into_iter()
            .any(|(id, _)| id == attachment_id);
        if projected {
            crate::output::Presentation::Projected
        } else {
            crate::output::Presentation::Direct
        }
    }

    /// Decides which attachments may begin live byte forwarding right now.
    ///
    /// An attachment that is already forwarding is left alone: it is mid-stream and the rule is
    /// about *starting*. One the host would serve directly and that is not forwarding yet may only
    /// start where the parser stands on ground, because starting anywhere else would hand a
    /// physical terminal the middle of an escape sequence. Until a boundary arrives it is held, and
    /// section 8's 250 ms is the point at which the answer becomes "stay projected" rather than
    /// "wait": waiting longer would not make the stream safer, it would only delay the screen.
    fn settle_forwarding(&mut self, now_ms: u64, installing: Option<AttachmentId>) {
        self.attachments
            .set_carryable(self.engine.direct_is_carryable());
        let projected: std::collections::BTreeSet<AttachmentId> = self
            .attachments
            .projected()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        let boundary = self.engine.ground_boundary();
        for summary in self.attachments.summaries() {
            let id = summary.attachment_id;
            if projected.contains(&id) && !self.forwarding_held.contains_key(&id) {
                // The host is not serving this one directly at all, for a reason of its own: its
                // size, its profile, its stream or the screen it was given. There is no handoff.
                continue;
            }
            if self.hub.presentation_of(id) == Some(crate::output::Presentation::Direct)
                && !self.hub.is_resynchronising(id)
                && installing != Some(id)
                && !self.forwarding_held.contains_key(&id)
            {
                // Already forwarding, and continuing: the boundary rule is about the moment
                // forwarding *begins*, and this stream has not stopped. Two cases are not that.
                // Three cases are not that. A subscriber that has been told to resynchronise is
                // waiting for a fresh screen; one that is asking for a screen right now is
                // beginning again from whatever it is given; and one already waiting for a
                // boundary is still waiting for it, whatever it was being served when it asked.
                // For all three the screen and the bytes after it have to meet at a boundary like
                // any other transition, so the exemption does not apply.
                self.forwarding_held.remove(&id);
                self.attachments.hold_forwarding(id, false);
                continue;
            }
            if boundary.is_some() {
                self.forwarding_held.remove(&id);
                self.attachments.hold_forwarding(id, false);
                continue;
            }
            let handoff = self
                .forwarding_held
                .entry(id)
                .or_insert_with(|| kr_term::snapshot::LiveForwardingHandoff::start(now_ms));
            if handoff.poll(now_ms, None) == kr_term::snapshot::HandoffOutcome::StayProjected {
                // The window passed with the parser still mid-sequence. The attachment stays
                // projected, and the next boundary is what moves it, so the wait begins again
                // rather than being abandoned.
                *handoff = kr_term::snapshot::LiveForwardingHandoff::start(now_ms);
            }
            self.attachments.hold_forwarding(id, true);
        }
    }

    /// Returns whether one subscriber has been told to resynchronise and has not come back.
    ///
    /// The queue for a client that stopped reading fills, and the answer is this: the session keeps
    /// reading the terminal and the client is told to ask for a fresh screen. A test watches it to
    /// know when that moment has actually arrived, rather than waiting a while and assuming.
    #[must_use]
    pub fn is_resynchronising(&self, attachment_id: AttachmentId) -> bool {
        self.hub.is_resynchronising(attachment_id)
    }

    /// Returns whether one attachment is being held out of live byte forwarding.
    #[must_use]
    pub fn forwarding_held(&self, attachment_id: AttachmentId) -> bool {
        self.forwarding_held.contains_key(&attachment_id)
    }

    /// Records output from the terminal, interprets it and delivers what each attachment may see.
    ///
    /// This is the read loop's only entry point. It never waits for a client: a subscriber that
    /// cannot keep up is told to resynchronise and the loop continues.
    ///
    /// Three things happen to every batch, in this order:
    ///
    /// 1. **The raw stream is retained.** The history is the durable record of what the
    ///    application wrote, and the cursor every other part of the host quotes is a position in
    ///    it. Nothing the engine decides changes what is kept.
    /// 2. **The canonical grid consumes it.** A query is answered here and travels no further; a
    ///    bell, a clipboard write or a notification is routed to the one attachment holding the
    ///    input lease; a sequence the profile does not name is consumed rather than forwarded in
    ///    the hope that it is harmless.
    /// 3. **Each attachment is given what it can take.** A terminal of the session's own size is
    ///    handed the spans the engine says a terminal may take unchanged; a terminal of any other
    ///    size is drawn the canonical screen clipped to the size it has.
    pub fn ingest_output(&mut self, bytes: &[u8]) -> Vec<AttachmentId> {
        if bytes.is_empty() {
            return Vec::new();
        }
        let cursor = self.history.append(bytes);
        let gate = self.lane_gate();
        let filtered = self
            .engine
            .feed(cursor, bytes, gate, kr_ipc::now_ms().get());
        // The application is the only thing that decides whether bracketed paste is on, and the
        // canonical parser is the only thing that knows what it decided: a sequence split across
        // two reads, and one that appears inside a string and sets nothing, are both answered
        // correctly here and by nothing else. The recogniser is told after the batch is parsed,
        // which is the first moment the answer exists.
        let released = self
            .framer
            .set_bracketed_paste(self.engine.bracketed_paste());
        self.release_prefix(released);
        // The same batch may have changed the keyboard negotiation, and whoever holds the keys has
        // to be able to produce whatever it changed to.
        self.reevaluate_lease();
        self.deliver(filtered)
    }

    /// Takes the keys from a holder that can no longer supply what the application reads.
    ///
    /// Section 8 requires a mid-session mode change to re-evaluate each controller, and an
    /// incompatible lease to be released explicitly rather than left sending an encoding it only
    /// advertises. It runs in both directions and needs no separate arming for either: an
    /// application that turns an enhanced protocol on takes the keys from a terminal that cannot
    /// produce it, and one that turns it off leaves the ordinary encoding, which every declared
    /// terminal produces, so that terminal can acquire again.
    ///
    /// The release is the ordinary one. The epoch advances, the fence goes out, a paste this lease
    /// had open is closed before anything else reaches the application, and the bytes it handed over
    /// and the writer has not written go with it. The holder learns on its next write, which is
    /// `LEASE_LOST`: nothing is queued under a lease that has stopped existing.
    ///
    /// Returns whether the keys were taken.
    fn reevaluate_lease(&mut self) -> bool {
        let Some(holder) = self.lease.holder() else {
            return false;
        };
        let required = self.engine.keyboard_negotiated();
        if self.attachments.supplies_encoding(holder, required) {
            return false;
        }
        let ending_epoch = self.lease.epoch();
        let discarded_queue = self.lease.release_attachment(holder);
        let framing = self.close_framing_for_takeover();
        let ended = self.end_lease();
        // What this lease lost is carried rather than dropped. Nobody asked for the release, so
        // there is no answer to put it in; the next acquire reports it with its own.
        self.interrupted.bytes = self
            .interrupted
            .bytes
            .saturating_add(discarded_queue)
            .saturating_add(ended.left)
            .saturating_add(framing.discarded_prefix.len() as u64);
        self.interrupted.closed_open_paste |=
            framing.terminator.is_some() || Self::delivered_paste_was_ours(&ended, ending_epoch);
        self.pump_replies();
        true
    }

    /// Returns whether a paste the writer was holding open belongs to the lease just ending.
    ///
    /// The writer keeps that latch because a terminator the framer accepted may have been queued
    /// behind a writer that never wrote it, and it clears the latch when it writes the correction.
    /// Two things follow. The value has to say *whose* paste it is, or a second lease change in the
    /// writer's window would report the same closure again; so it names the lease that wrote into
    /// the paste, as one more than that lease's epoch, and zero for no paste at all. And it has to
    /// be read before the fence goes out, or the writer's own answer to this change would be read
    /// as an answer about the lease before it; so the reading happens inside
    /// [`Session::end_lease`], on the boundary, and travels here.
    const fn delivered_paste_was_ours(ended: &LeaseEnded, ending_epoch: u64) -> bool {
        ended.paste_open_for != 0 && ended.paste_open_for == ending_epoch.saturating_add(1)
    }

    /// Returns what a lease the host ended by itself left behind and nobody has been told about.
    ///
    /// It is cleared by the next acquire, which reports it. A test reads it here because the wire
    /// answer belongs to that acquire rather than to the release.
    #[must_use]
    pub const fn interrupted_input(&self) -> Interrupted {
        self.interrupted
    }

    /// Settles the screen when the terminal's output goes quiet.
    ///
    /// The engine holds the last scalar of a run back in case a combining mark follows it, so a
    /// screen that has stopped changing is only final once this has run. The read loop calls it
    /// when a read finds nothing waiting.
    pub fn quiesce_output(&mut self) -> Vec<AttachmentId> {
        let filtered = self
            .engine
            .quiesce(self.lane_gate(), kr_ipc::now_ms().get());
        self.deliver(filtered)
    }

    /// Writes anything the host owes the application that the gate now allows.
    ///
    /// The lane is drained when output arrives, which is the common case: an application that asked
    /// a question is usually about to write something. It is not the only case. A reply held back
    /// because a bracketed paste was open has nothing to wait for once the paste closes, and an
    /// application that asked and then sat still would wait for ever. Every place that opens the
    /// gate calls this.
    pub fn pump_replies(&mut self) {
        let gate = self.lane_gate();
        let replies = self.engine.drain_replies(gate, kr_ipc::now_ms().get());
        self.queue_replies(replies);
    }

    /// Queues the host's own answers for the application, up to what one may wait for.
    ///
    /// The response lane bounds what it holds; this bounds what has left the lane and is waiting
    /// for an application that has stopped reading its input. One that asks questions and never
    /// reads the answers stops being answered here rather than growing this queue without limit.
    fn queue_replies(&mut self, replies: Vec<Vec<u8>>) {
        for reply in replies {
            let queued = self
                .queued_input_bytes
                .load(std::sync::atomic::Ordering::Acquire);
            let held = queued.saturating_sub(self.queued_lease_bytes.load());
            // Two bounds, both of them this reply's: its own share, so an application that asks
            // questions without reading the answers cannot fill the terminal by itself, and the
            // whole budget, so its share cannot be spent on top of a full queue.
            if held.saturating_add(reply.len()) > MAX_PENDING_REPLY_BYTES
                || queued.saturating_add(reply.len()) > MAX_QUEUED_INPUT_BYTES
            {
                return;
            }
            self.queue_input(InputBatch::Reply { bytes: reply });
        }
    }

    /// Queues one batch for the pseudo-terminal, counted against the session's input budget.
    ///
    /// Every producer goes through here, because the writer releases every piece it writes against
    /// the same counter: charging only some of them would make the count drift down until it
    /// stopped bounding anything.
    fn queue_input(&mut self, batch: InputBatch) {
        self.queued_input_bytes
            .fetch_add(batch.len(), std::sync::atomic::Ordering::AcqRel);
        if let InputBatch::Lease { epoch, .. } = batch {
            self.queued_lease_bytes.add(epoch, batch.len());
        }
        self.pending_input.push(batch);
    }

    /// Returns the counter the writer releases as the application takes its input.
    #[must_use]
    pub fn queued_input_bytes(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.queued_input_bytes)
    }

    /// Returns the counter holding the current lease's share of the queue.
    #[must_use]
    pub fn queued_lease_bytes(&self) -> Arc<crate::runtime::LeaseBytes> {
        Arc::clone(&self.queued_lease_bytes)
    }

    /// Returns what the response lane is allowed to write right now.
    ///
    /// A reply must not land in the middle of a bracketed paste or a recognised human input frame,
    /// because the application would read it as part of what the person was typing.
    fn lane_gate(&self) -> kr_term::lane::LaneGate {
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

    /// Sends one projected attachment what it is owed: a bounded update, or a fresh screen.
    ///
    /// The update is bounded because that is what section 8 requires of ordinary output: a
    /// projected attachment is not redrawn after every batch. A client that holds a screen this
    /// engine can still continue from is sent the rows that changed; one that holds nothing, or
    /// whose base has fallen outside the replay window, or whose change is larger than one bounded
    /// update, is installed again from a snapshot.
    ///
    /// Returns whether the subscriber was told to resynchronise.
    fn publish_projection(
        &mut self,
        attachment_id: AttachmentId,
        dimensions: Dimensions,
        reset: Option<ProjectionResetReason>,
        oldest: u64,
    ) -> bool {
        let held = self.projections.held(attachment_id);
        let owed = match held {
            Some(held) if reset.is_none() => self
                .engine
                .projection_advance(
                    held,
                    self.window_of(attachment_id, dimensions),
                    self.content_scope(attachment_id),
                )
                .unwrap_or(crate::snapshot::Owed::Snapshot(
                    ProjectionResetReason::ReplayGap,
                )),
            // The engine said what replaced the screen, so the client is told that rather than
            // being left to infer it. An attachment holding nothing is being installed for the
            // first time.
            _ => crate::snapshot::Owed::Snapshot(reset.unwrap_or(ProjectionResetReason::Attached)),
        };
        let update = match owed {
            crate::snapshot::Owed::Nothing => return false,
            crate::snapshot::Owed::Update(update) => update,
            crate::snapshot::Owed::Snapshot(reason) => {
                let gate = self.lane_gate();
                let now = kr_ipc::now_ms().get();
                // The subscriber's own send queue is what a screen has to fit: this is the one
                // message a client cannot use part of, so a screen too large for that queue is cut
                // to it and marked degraded rather than refused for ever.
                let budget = self.hub.limit_of(attachment_id);
                // And how much of the screen this client's authority reaches: a caller drawn the
                // live screen alone is paged the buffer that is showing and never the other one.
                let scope = self.content_scope(attachment_id);
                let window = self.window_of(attachment_id, dimensions);
                match self
                    .engine
                    .projection_install(window, reason, gate, now, budget, scope)
                {
                    Ok((update, settled)) => {
                        // Taking a snapshot settles the screen. It changes no display state here,
                        // because the screen was settled before this loop began, but it can still
                        // release replies the response lane held in the moment between, and those
                        // are the application's.
                        self.queue_replies(settled.replies);
                        update
                    }
                    Err(_) => {
                        // The engine's state cannot be spelled on the wire, which this engine
                        // cannot produce. The client is told to install a fresh screen rather than
                        // being left holding one that no longer matches.
                        self.projections.forget(attachment_id);
                        self.hub.require_resync(
                            attachment_id,
                            ResyncReason::ProjectionReset,
                            self.history.next_cursor(),
                            oldest,
                        );
                        return true;
                    }
                }
            }
        };
        let held = crate::snapshot::Held {
            base: update.base,
            viewport: self
                .engine
                .anchored_viewport(self.window_of(attachment_id, dimensions)),
            screen_top_row: self.engine.live_top_row(),
        };
        for outgoing in update.events {
            let cursor = outgoing.event.cursor();
            if self.hub.publish_projection(
                attachment_id,
                cursor,
                outgoing.event,
                outgoing.bytes,
                oldest,
            ) {
                // Its queue filled part way through. What it has is not a screen, so the base goes
                // with it and the fresh snapshot it asks for starts again.
                self.projections.forget(attachment_id);
                return true;
            }
        }
        self.projections.record(attachment_id, held);
        false
    }

    /// Delivers one interpreted batch to the attachments and the application.
    ///
    /// The order this runs in is the contract:
    ///
    /// 1. **What the host owes the application** goes into its terminal input. It asked and it is
    ///    waiting, and nothing a person is typing comes before an answer that only the host has.
    /// 2. **The presentation of every subscriber is settled**, and one that has just moved between
    ///    the two is told to install a fresh screen. A terminal that is about to be drawn a
    ///    rendering must not first receive the bytes that assume it is the session's size.
    /// 3. **The stream is published in source order.** A bell that happened between two spans is
    ///    delivered between them, so the attachment holding the input lease never sees a cursor go
    ///    backwards and never hears a bell in the wrong place.
    /// 4. **Every terminal of another size is drawn the screen it can see**, once per attachment,
    ///    because each is looking at its own window.
    fn deliver(&mut self, mut filtered: crate::projection::Filtered) -> Vec<AttachmentId> {
        // The engine's answer is recorded first, so a summary and a delivery cannot disagree about
        // how an attachment is being served. Which of them may *begin* forwarding is settled with
        // it, because that answer depends on where the parser stands and not only on a size.
        if filtered.projection_reset {
            // The screen was replaced rather than changed, and what replaced it has no history
            // above it: the alternate buffer keeps none, and a full reset starts the rows again.
            // Every window therefore comes back to the live screen with it, before anything reads
            // where a window is: whether an attachment may take the stream depends on that answer,
            // and a window nobody is above is not a reason to keep drawing a projection.
            self.attachments.clear_history_windows();
        }
        self.attachments
            .set_carryable(self.engine.direct_is_carryable());
        self.settle_forwarding(kr_ipc::now_ms().get(), None);
        let projected = self.attachments.projected();
        if !projected.is_empty() {
            // Taking a snapshot settles the screen, which releases whatever the engine was holding
            // back. Settling once here, before any snapshot, is what stops those bytes disappearing
            // inside the first projected subscriber's repaint when a direct attachment was owed
            // them.
            let gate = self.lane_gate();
            let settled = self.engine.quiesce(gate, kr_ipc::now_ms().get());
            filtered.absorb(settled);
        }
        self.queue_replies(filtered.replies);
        for effect in filtered.host_events {
            // Nothing holds the input lease, so there is no terminal this belongs to. Section 8
            // makes it a durable host event rather than something shown to whoever is watching.
            if let Some(journal) = self.journal.as_mut() {
                let _ = journal.record_host_event(&effect, kr_ipc::now_ms());
            }
        }
        let oldest = self.history.oldest_retained_cursor();
        let next = self.history.next_cursor();
        let mut resynchronised = Vec::new();

        let projecting: std::collections::BTreeSet<AttachmentId> =
            projected.iter().map(|(id, _)| *id).collect();
        for attachment_id in self.hub.subscribers() {
            let presentation = if projecting.contains(&attachment_id) {
                crate::output::Presentation::Projected
            } else {
                crate::output::Presentation::Direct
            };
            if self.hub.set_presentation(attachment_id, presentation) {
                // What it holds is not what it is about to be served, so the base goes with the
                // change: an attachment that has become direct is handed bytes, and one that has
                // become projected is installed from a snapshot rather than continued from a
                // screen it was drawn in another form.
                self.projections.forget(attachment_id);
                self.hub
                    .require_resync(attachment_id, ResyncReason::ProjectionReset, next, oldest);
                resynchronised.push(attachment_id);
            }
        }
        // A projection reset, or a span the engine cleared that this host could no longer produce,
        // means no client's screen continues from the one it holds. Both are answered the same
        // way: install a fresh screen rather than drawing on top of one with a hole in it.
        //
        // A projected attachment is installed again *in band*, in this same call: the projection
        // protocol has a reset of its own, and a client that has been sent one followed by a fresh
        // snapshot needs no round trip to ask for what it has already been given. Forgetting its
        // base is what makes the loop below install rather than continue. A direct attachment has
        // no such event, so it is told to resynchronise and asks for a new screen itself.
        let reset_reason = if filtered.projection_reset {
            Some(ProjectionResetReason::BufferSwitch)
        } else if filtered.lost {
            Some(ProjectionResetReason::ReplayGap)
        } else {
            None
        };
        if reset_reason.is_some() {
            for attachment_id in self.hub.subscribers() {
                if projecting.contains(&attachment_id) {
                    self.projections.forget(attachment_id);
                    continue;
                }
                self.hub
                    .require_resync(attachment_id, ResyncReason::ProjectionReset, next, oldest);
                resynchronised.push(attachment_id);
            }
        }

        // One ordered stream. The spans a terminal may take and the side effects that belong to
        // the lease holder are two views of the same output, and the holder receives both, so they
        // are published in the order the application produced them.
        let mut pieces: Vec<(u64, bool, Vec<u8>)> =
            Vec::with_capacity(filtered.direct.len() + filtered.effects.len());
        pieces.extend(
            filtered
                .direct
                .into_iter()
                .map(|(cursor, bytes)| (cursor, false, bytes)),
        );
        pieces.extend(
            filtered
                .effects
                .into_iter()
                .map(|(cursor, bytes)| (cursor, true, bytes)),
        );
        pieces.sort_by_key(|(cursor, effect, _)| (*cursor, *effect));
        let holder = self.lease.holder();
        for (cursor, is_effect, bytes) in pieces {
            let shared = Arc::new(bytes);
            if is_effect {
                if let Some(holder) = holder
                    && self.hub.publish_to(holder, cursor, &shared, oldest)
                {
                    resynchronised.push(holder);
                }
            } else {
                resynchronised.extend(self.hub.publish_direct(cursor, &shared, oldest));
            }
        }

        for (attachment_id, dimensions) in projected {
            if self.hub.is_resynchronising(attachment_id) {
                // It has been told to install a fresh screen and is not being sent updates in the
                // meantime. Building one for it would spend the work and then throw it away.
                continue;
            }
            if self.publish_projection(attachment_id, dimensions, reset_reason, oldest) {
                resynchronised.push(attachment_id);
            }
        }
        resynchronised.sort_unstable();
        resynchronised.dedup();
        resynchronised
    }

    /// Builds a snapshot of present state at the current cursor.
    #[must_use]
    pub fn snapshot(&self) -> EventsSnapshotResult {
        EventsSnapshotResult {
            cursor: U64::new(self.history.next_cursor()),
            session: self.summary(),
            geometry: self.attachments.geometry(),
            lease: self.lease.to_wire(),
            attachments: self.attachments.summaries(),
            oldest_retained_cursor: U64::new(self.history.oldest_retained_cursor()),
            taken_at_ms: kr_ipc::now_ms(),
        }
    }

    /// Reads one page of retained output.
    ///
    /// # Errors
    ///
    /// Returns an error when the spool cannot be read.
    pub fn history_page(&self, from_cursor: u64, max_bytes: u64) -> Result<HistoryPageResult> {
        self.history.page(from_cursor, max_bytes)
    }

    /// Tells one attachment to install a fresh snapshot.
    pub fn require_resync(&mut self, attachment_id: AttachmentId, reason: ResyncReason) {
        self.hub.require_resync(
            attachment_id,
            reason,
            self.history.next_cursor(),
            self.history.oldest_retained_cursor(),
        );
    }

    /// Returns the capabilities one attachment was granted.
    #[must_use]
    pub fn attachment_capabilities(
        &self,
        attachment_id: AttachmentId,
    ) -> Option<CanonicalSet<AttachmentCapability>> {
        self.attachments
            .get(attachment_id)
            .map(|attachment| attachment.granted.clone())
    }

    /// Returns every attachment, for diagnostics and snapshots.
    #[must_use]
    pub fn attachments(&self) -> Vec<AttachmentSummary> {
        self.attachments.summaries()
    }

    /// Refuses an operation that needs a session which is still running.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::SessionClosed`] once the session has begun closing.
    pub const fn require_live(&self) -> Result<()> {
        self.require_running()
    }

    /// Decides whether this session can admit the attachment these parameters ask for.
    ///
    /// The admission path calls this before anything durable is written, and [`Self::attach`]
    /// applies the same rules where the attachment is made. Section 9 requires a refusal the host
    /// can decide to be a rejection, and a rule applied only inside the effect cannot be one.
    ///
    /// # Errors
    ///
    /// Returns the first reason the attachment cannot be admitted, including a session that is no
    /// longer running.
    pub fn attachable(&self, params: &SessionAttachParams) -> Result<()> {
        self.attachments.admissible(params).map(|_| ())
    }

    /// Decides whether one attachment may be given the geometry.
    ///
    /// # Errors
    ///
    /// Returns the first reason the transfer cannot be admitted.
    pub fn transferable(&self, attachment_id: AttachmentId) -> Result<()> {
        self.attachments.transferable(attachment_id)
    }

    /// Decides whether one attachment may resize the session now.
    ///
    /// The dimensions, the ownership and the epoch, which is every reason a resize can be refused
    /// from what this host already holds. [`Self::resize`] applies the same three where the size
    /// changes.
    ///
    /// # Errors
    ///
    /// Returns the first reason the resize cannot be admitted.
    pub fn resizable(
        &self,
        attachment_id: AttachmentId,
        dimensions: Dimensions,
        expected_epoch: u64,
    ) -> Result<()> {
        self.attachments
            .check_resize(attachment_id, dimensions, expected_epoch)
    }

    /// Decides whether one attachment may take or drop a geometry claim.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] when a semantic attachment claims geometry or the
    /// attachment does not hold the geometry right, and [`WorkerError::UnknownAttachment`] when
    /// the identifier names no attachment of this session.
    pub fn configurable(&self, attachment_id: AttachmentId, claim_geometry: bool) -> Result<()> {
        self.attachments
            .check_configure(attachment_id, claim_geometry)
    }

    /// Decides whether one attachment may report a viewport of these dimensions.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] when the dimensions are not ones this host serves
    /// or the attachment has no terminal presentation, and [`WorkerError::UnknownAttachment`] when
    /// the identifier names no attachment of this session.
    pub fn viewportable(
        &self,
        attachment_id: AttachmentId,
        dimensions: Dimensions,
        position: Option<kr_protocol::attachment::ViewportPosition>,
    ) -> Result<()> {
        self.attachments.check_viewport(attachment_id, dimensions)?;
        self.window_refusal(attachment_id, dimensions, position)
    }

    /// Why this attachment may not put its window where the report asks, when it may not.
    ///
    /// Both answers are about the request rather than about anything the report would change, so
    /// they belong where a refusal is still a refusal: before the marker that says the effect may
    /// have happened. A refusal raised after it would be an outcome nobody can read, and the
    /// requests behind it would wait on a receipt that never resolves.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::PresentationUnsupported`] when a caller shown the live screen and no
    /// retained content beyond it asks for a window above it, and [`WorkerError::InvalidArgument`]
    /// when the smallest screen of that window will not cross the queue this attachment holds.
    fn window_refusal(
        &self,
        attachment_id: AttachmentId,
        dimensions: Dimensions,
        position: Option<kr_protocol::attachment::ViewportPosition>,
    ) -> Result<()> {
        // What this attachment's caller may be shown decides whether it may look above the live
        // page at all. A caller narrowed to the live screen is served the screen that is showing
        // and no retained content beyond it, and a window in the session's history is exactly that
        // content: it is refused rather than quietly answered with the live screen, because a
        // client told its window moved would draw as though it had.
        if position.is_some()
            && self.content_scope(attachment_id) == crate::render::Scope::LiveScreen
        {
            return Err(WorkerError::PresentationUnsupported {
                detail: "this attachment is shown the live screen and no retained rows above it, \
                         so its window cannot be placed in the session's history"
                    .to_owned(),
            });
        }
        // The dimensions this report carries are checked before anything is built for them: a
        // report that violates a constraint is refused for that, and naming a limit is the answer
        // section 8 asks for rather than a figure about a queue.
        if let Some(violation) = dimensions.violations().into_iter().next() {
            return Err(WorkerError::Dimensions(violation));
        }
        // And the screen that window needs has to cross the queue this attachment already has. A
        // window above the live page carries the rows it shows and the live screen behind them, so
        // it can be a larger screen than the one this subscriber was admitted for; being told the
        // window moved and then that the queue is full is two answers where there should be one.
        // The size is part of the question: the same row in a taller window is a larger screen.
        let top_row = self.engine.resolve_position(position);
        let before_top_row = self.attachments.history_top_row(attachment_id);
        let before_dimensions = self.attachments.own_dimensions(attachment_id).flatten();
        if top_row.is_some() && (top_row != before_top_row || before_dimensions != Some(dimensions))
        {
            let limit = self.hub.limit_of(attachment_id);
            let minimum = self.engine.minimum_projection_install(
                crate::projection::Window {
                    dimensions,
                    anchor: crate::projection::ViewportAnchor::of(top_row),
                },
                self.content_scope(attachment_id),
            )?;
            if limit > 0 && limit < minimum {
                return Err(WorkerError::InvalidArgument(format!(
                    "a send queue of {limit} bytes cannot carry this window: it is admitted \
                     against {minimum} bytes, which is what the smallest screen of it costs with \
                     the longest reason a reset can carry, and a client holding part of a screen \
                     holds none of it"
                )));
            }
        }
        Ok(())
    }

    /// Decides whether one attachment can supply the input encoding this application reads.
    ///
    /// Section 8: the lease goes to a controller that can supply the encoding the application
    /// reads. Refusing leaves the attachment everything else it has - it goes on watching, and its
    /// typed actions are unaffected - rather than letting it send an encoding that means other
    /// keys. It is refused whichever way the mismatch runs: a terminal nobody was allowed to ask
    /// about is as likely to be in an enhanced protocol somebody else left it in as it is to be in
    /// the ordinary one, and neither this host nor that terminal can say which.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InputIncompatible`] when the attachment cannot supply the encoding,
    /// and [`WorkerError::UnknownAttachment`] when it names no attachment of this session.
    pub fn input_compatible(&self, attachment_id: AttachmentId) -> Result<()> {
        let required = self.engine.keyboard_negotiated();
        match self.attachments.encoders(attachment_id) {
            Some(Some(encoders)) if encoders.supplies(required) => Ok(()),
            Some(offered) => Err(WorkerError::InputIncompatible {
                required: self.engine.keyboard_in_force(),
                offered: offered.map_or_else(
                    || UNDECLARED_TERMINAL.to_owned(),
                    crate::input::Encoders::describe,
                ),
            }),
            None => Err(WorkerError::UnknownAttachment {
                attachment: attachment_id.to_string(),
            }),
        }
    }

    /// Returns the host time contract this session's expiries are decided by.
    #[must_use]
    pub fn time(&self) -> &Arc<crate::action::time::TimeContract> {
        &self.time
    }

    /// Looks at the host's clocks and says what moved.
    ///
    /// Section 9 puts this before anything whose answer depends on an expiry. What the caller does
    /// with a discontinuity is revalidate the freshness resources it owns, which this session does
    /// not hold: the windows belong to the host that issued them. Anything the observation changed
    /// that a restarted host could not work out again is written down here, because the next thing
    /// to happen may be the crash that makes it matter.
    pub fn observe_time(&mut self) -> crate::action::time::Discontinuity {
        let time = Arc::clone(&self.time);
        let found = time.observe();
        self.persist_time(&time);
        found
    }

    /// Records that the freshness resources a discontinuity affected have been rechecked.
    pub fn note_leases_revalidated(&mut self) {
        let time = Arc::clone(&self.time);
        time.leases_revalidated();
    }

    /// Collects de-duplication records past the retention period, and says how many went.
    ///
    /// The host time contract decides whether it runs at all. Retention is expiry-based
    /// collection, and section 9 stops that while the wall clock cannot be proved: collecting
    /// against an unproved clock is how a rollback deletes something that had not expired.
    ///
    /// A failure is recorded against this session rather than returned. Collection is maintenance:
    /// nothing a caller asked for depends on it, the next run tries again, and recording the
    /// failure here rather than handing it back is what keeps the caller to one look at this
    /// session - a caller that took the lock again to record it would be waiting for the lock it
    /// was already holding.
    pub fn collect_expired(&mut self) -> usize {
        let permitted = self.time.may_collect_expired();
        let collected = match self.journal.as_mut() {
            Some(journal) => journal.prune_if_due(kr_ipc::now_ms(), permitted),
            None => Ok(0),
        };
        match collected {
            Ok(collected) => collected,
            Err(error) => {
                self.note_journal_failure(error);
                0
            }
        }
    }

    /// Writes down what the time contract has to survive a restart, when it has changed.
    fn persist_time(&mut self, time: &crate::action::time::TimeContract) {
        if !time.unsaved() {
            return;
        }
        let (state, generation) = time.durable_state();
        let recorded = self
            .journal
            .as_mut()
            .map(|journal| journal.record_host_time(&state));
        match recorded {
            Some(Ok(())) => time.note_saved(generation),
            // A host that cannot write down an unresolved clock or an expired object still holds
            // both in memory. What it loses is the restart, and that is what the recorded failure
            // says: this session's durability is no longer what it claimed.
            Some(Err(error)) => self.note_journal_failure(error),
            None => {}
        }
    }

    /// Returns the private journal for reading, when one is available.
    ///
    /// The pre-dispatch revalidation reads it and writes nothing, so it takes this rather than the
    /// mutable one: what it decides is whether a mutation may be admitted at all, which is a
    /// question about the journal's current contents.
    #[must_use]
    pub const fn journal(&self) -> Option<&Journal> {
        self.journal.as_ref()
    }

    /// Returns the private journal for writing, when one is available.
    pub fn journal_mut(&mut self) -> Option<&mut Journal> {
        self.journal.as_mut()
    }

    /// Returns why the journal is unavailable, when it is.
    #[must_use]
    pub fn journal_failure(&self) -> Option<&str> {
        self.journal_failure.as_deref()
    }

    /// Returns the final closure record once the session has closed.
    #[must_use]
    pub fn closure(&self) -> Option<&ClosureRecord> {
        self.closure.as_ref()
    }

    /// Begins closure, or reports the closure already under way.
    ///
    /// The reply is built before any process is signalled, because the caller may be inside the
    /// group about to be stopped.
    pub fn begin_close(&mut self, reason: ClosureReason) -> CloseAcceptance {
        match self.state {
            SessionState::Closed => CloseAcceptance {
                state: SessionState::Closed,
                durability: self.durability(),
                closure: self.closure.clone(),
                initiated: false,
            },
            SessionState::Closing => CloseAcceptance {
                state: SessionState::Closing,
                durability: self.durability(),
                closure: None,
                initiated: false,
            },
            SessionState::Creating | SessionState::Live => {
                // Atomic admission: the state changes before anything else, so input is rejected
                // from here on and a second request joins this closure instead of starting a
                // second one. Nothing is signalled yet. The caller may itself be inside the
                // process group about to be stopped, and section 7 gives it its acceptance first.
                self.state = SessionState::Closing;
                self.closing_reason = Some(reason);
                // Input is rejected from here, and that has to reach bytes already handed to the
                // writer as well as the ones not yet accepted. Releasing the lease moves the fence,
                // so a keystroke queued a moment before the close is dropped rather than typed into
                // a shell that is being stopped.
                if let Some(holder) = self.lease.holder() {
                    self.lease.release_attachment(holder);
                }
                self.close_framing_for_takeover();
                let _ = self.end_lease().left;
                CloseAcceptance {
                    state: SessionState::Closing,
                    durability: self.durability(),
                    closure: None,
                    initiated: true,
                }
            }
        }
    }

    /// Asks the owned process group to stop.
    ///
    /// This is deliberately separate from [`Session::begin_close`]: the acceptance reaches the
    /// caller before anything is signalled, because the caller is often a command running inside
    /// the group.
    ///
    /// # Errors
    ///
    /// Returns an error when the signal cannot be sent.
    pub fn request_stop(&mut self) -> Result<()> {
        // Everything the boundary holds is asked to stop, not only the root. A shell that has
        // already exited leaves descendants behind, and they are what this reaches.
        if let Some(owned) = self.owned.as_mut() {
            owned.observe();
        }
        let outcome = match self.shell.as_mut() {
            Some(shell) => shell.request_stop(),
            None => Ok(()),
        };
        if let Some(owned) = self.owned.as_ref() {
            crate::ownership::request_stop(owned);
        }
        outcome
    }

    /// Forces whatever is left of the owned group to stop.
    ///
    /// # Errors
    ///
    /// Returns an error when the signal cannot be sent.
    pub fn force_close(&mut self) -> Result<bool> {
        if let Some(owned) = self.owned.as_mut() {
            owned.observe();
        }
        let remaining = self
            .owned
            .as_ref()
            .is_some_and(|owned| !owned.surviving().is_empty());
        // Recorded before any signal, while the kernel still names the processes force is being
        // used on. Afterwards there would be nothing left to mark.
        if let Some(owned) = self.owned.as_mut() {
            owned.note_forced_now();
        }
        if let Some(shell) = self.shell.as_mut()
            && shell.try_wait()?.is_none()
        {
            shell.force_stop()?;
        }
        if let Some(owned) = self.owned.as_ref() {
            crate::ownership::force_stop(owned);
        }
        Ok(remaining)
    }

    /// Writes the final record and moves the session to `closed`.
    ///
    /// Which processes were forced is recorded where force was applied, not here: by the time this
    /// runs, the ones force actually ended are gone and there is nothing left to mark.
    pub fn finish_close(&mut self) -> ClosureRecord {
        let exit = self.root_exit.clone().or_else(|| {
            self.shell
                .as_mut()
                .and_then(|shell| shell.try_wait().ok().flatten())
        });
        let reason = self.closing_reason.unwrap_or(ClosureReason::CloseRequested);
        self.record_closure_with(reason, exit)
    }

    /// Checks whether the root shell has ended, and records the closure if it has.
    ///
    /// This watches the child itself rather than the terminal. A descendant can keep the terminal
    /// open after the shell exits, and a read error on the terminal is not proof of death, so the
    /// two are observed separately.
    pub fn poll_root_exit(&mut self) -> bool {
        if self.state == SessionState::Closed {
            return false;
        }
        let exit = match self.shell.as_mut().map(RootShell::try_wait) {
            Some(Ok(Some(exit))) => exit,
            _ => return false,
        };
        self.root_exit.get_or_insert(exit.clone());
        if self.state == SessionState::Closing {
            // A closure already under way finishes through its own sequence, which stops the rest
            // of what the session owns and drains output before it writes the record.
            return false;
        }
        // A root shell that ends on its own is a closure like any other: it goes through the same
        // admission, so the lease is released, a paste the old lease left open is closed and the
        // input fence moves, and then through the same sequence, so descendants are still stopped
        // and output is still drained. Committing the record here would skip all of it.
        let reason = if exit.signalled() {
            ClosureReason::RootSignal
        } else {
            ClosureReason::RootExit
        };
        self.begin_close(reason).initiated
    }

    /// Records that the pseudo-terminal closed, which means the root shell has ended.
    ///
    /// The shell's real status is read from the child rather than assumed, so a shell that was
    /// signalled is recorded as signalled.
    pub fn note_terminal_ended(&mut self) -> ClosureRecord {
        let exit = self
            .shell
            .as_mut()
            .and_then(|shell| shell.wait().ok())
            .unwrap_or(ShellExit {
                code: 0,
                signal: None,
            });
        self.note_shell_exit(exit)
    }

    /// Records that the root shell ended on its own.
    ///
    /// An explicit `exit`, an end of file at the root prompt or a crash all close the session.
    /// KalaReach never restarts the shell.
    pub fn note_shell_exit(&mut self, exit: ShellExit) -> ClosureRecord {
        let reason = if exit.signalled() {
            ClosureReason::RootSignal
        } else {
            ClosureReason::RootExit
        };
        if self.state == SessionState::Live || self.state == SessionState::Creating {
            self.state = SessionState::Closing;
            self.closing_reason = Some(reason);
        }
        self.record_closure_with(self.closing_reason.unwrap_or(reason), Some(exit))
    }

    fn record_closure(&mut self, reason: ClosureReason, exit: Option<ShellExit>) -> ClosureRecord {
        self.record_closure_with(reason, exit)
    }

    fn record_closure_with(
        &mut self,
        reason: ClosureReason,
        exit: Option<ShellExit>,
    ) -> ClosureRecord {
        if let Some(existing) = self.closure.clone() {
            return existing;
        }
        // One last look before the record is written, so a process that started late is still
        // accounted for.
        if let Some(owned) = self.owned.as_mut() {
            owned.observe();
        }
        // Only confirmed terminations are listed, and coverage follows the boundary this host
        // actually has rather than the outcome it would prefer. A terminal process group cannot
        // see a descendant that left it, so a host with only that never reports complete.
        let (terminated, surviving, coverage) = self.owned.as_ref().map_or_else(
            || (Vec::new(), Vec::new(), OwnershipCoverage::Incomplete),
            |owned| {
                (
                    owned.terminated(),
                    owned.surviving_resources(),
                    owned.coverage(),
                )
            },
        );
        let mut record = ClosureRecord {
            session_id: self.config.session_id,
            session_epoch: self.config.session_epoch,
            reason,
            root_exit_code: Nullable(
                exit.as_ref()
                    .filter(|exit| !exit.signalled())
                    .map(|exit| U64::new(u64::from(exit.code))),
            ),
            root_signal: Nullable(exit.as_ref().and_then(|exit| exit.signal.as_ref()).cloned()),
            terminated,
            surviving,
            ownership_coverage: coverage,
            durability: self.durability(),
            closed_at_ms: kr_ipc::now_ms(),
        };
        record.durability = self.commit_closure(&record);
        self.state = SessionState::Closed;
        self.application_state = None;
        self.closure = Some(record.clone());
        record
    }

    /// Writes the closure record to the journal and reports whether it was recorded durably.
    ///
    /// Storage failure never blocks an authorised stop. What it changes is the answer the host
    /// gives: a closure that could not be written says `volatile` rather than claiming durability
    /// it does not have.
    fn commit_closure(&mut self, record: &ClosureRecord) -> Durability {
        let Some(journal) = self.journal.as_mut() else {
            return Durability::Volatile;
        };
        match journal.record_closure(record) {
            Ok(()) => Durability::Durable,
            Err(error) => {
                self.journal_failure = Some(error.to_string());
                Durability::Volatile
            }
        }
    }

    /// Records that a durable write failed.
    ///
    /// The journal stays open, because a later write may well succeed and the de-duplication
    /// records in it are still the session's. What changes is the answer the host gives about
    /// durability, which stops being a claim the session cannot support.
    pub fn note_journal_failure(&mut self, detail: impl std::fmt::Display) {
        self.journal_failure = Some(detail.to_string());
    }

    const fn durability(&self) -> Durability {
        if self.journal.is_some() && self.journal_failure.is_none() {
            Durability::Durable
        } else {
            Durability::Volatile
        }
    }

    const fn require_running(&self) -> Result<()> {
        if self.state.is_running() {
            Ok(())
        } else {
            Err(WorkerError::SessionClosed)
        }
    }
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

/// One ordered batch of input on its way to the pseudo-terminal.
///
/// The variants are fenced differently, which is the whole reason the distinction exists. A
/// person's keystrokes belong to a lease, and a takeover discards the ones the previous holder had
/// already handed over. The host's own answer to a query the application asked belongs to the
/// application: it was asked for, nothing else can supply it, and dropping it because the lease
/// happened to move would leave the application waiting for a reply that will never come.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputBatch {
    /// An attachment's input, accepted under one lease epoch.
    Lease {
        /// The epoch the lease held when these bytes were accepted.
        epoch: u64,
        /// The bytes, exactly as they arrived.
        bytes: Vec<u8>,
        /// What they do to the bracketed paste the application is inside.
        paste: PasteTransition,
        /// When the authority that accepted these bytes runs out, on the machine's own
        /// continuous clock. Null when that authority does not expire.
        ///
        /// It travels with the bytes because the writer is the last boundary before the
        /// application, and a batch can wait there: the grant behind it can end between the
        /// moment the host accepted it and the moment the terminal takes it.
        authority_deadline_boot_ms: Option<u64>,
    },
    /// The host answering the application, on the response lane.
    Reply {
        /// The bytes of the answer.
        bytes: Vec<u8>,
    },
    /// A lease has changed, with nothing queued behind it.
    ///
    /// It carries no bytes. What it carries is the moment: the writer looks at the fence when it
    /// takes a batch, and a lease that changed while nothing was queued would otherwise leave the
    /// application inside a paste until somebody typed something.
    LeaseChanged,
}

impl InputBatch {
    /// Returns how many bytes this batch is holding against the session's input budget.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Lease { bytes, .. } | Self::Reply { bytes } => bytes.len(),
            Self::LeaseChanged => 0,
        }
    }

    /// Returns whether this batch carries no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a batch of input does to the bracketed paste the application is inside.
///
/// The framer decides it from the delimiters the bytes complete; the *writer* keeps it, because the
/// writer is the only thing that knows what actually reached the application. A batch the writer
/// drops or abandons never happened as far as the application is concerned, however the framer read
/// it.
///
/// Where every paste delimiter these bytes carry sits inside them.
///
/// This is what the writer needs to answer two questions about a batch it delivered only part of:
/// what the application's framing is at the point where delivery stopped, and whether it stopped
/// inside a delimiter. Both need positions; neither can be answered by a summary of the batch.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PasteTransition {
    /// The delimiters, in the order they appear.
    pub delimiters: Vec<crate::input::Delimiter>,
}

impl PasteTransition {
    /// Returns the application's framing once `delivered` bytes of the batch have reached it.
    ///
    /// `None` means these bytes decided nothing and whatever was true before still is. A delimiter
    /// that is only partly delivered decides nothing either; the writer finishes it first, which is
    /// what makes this exact rather than a guess.
    #[must_use]
    pub fn after(&self, delivered: usize) -> Option<bool> {
        let delivered = u32::try_from(delivered).unwrap_or(u32::MAX);
        self.delimiters
            .iter()
            .rev()
            .find(|delimiter| delimiter.end <= delivered)
            .map(|delimiter| delimiter.opens)
    }

    /// Returns where a delimiter that `delivered` stopped inside of ends.
    ///
    /// A delimiter half of which reached the application is the one thing a takeover cannot leave
    /// behind: the next actor's first bytes could complete it, and its paste would begin inside the
    /// previous actor's. The writer finishes those few bytes before it abandons the rest.
    #[must_use]
    pub fn unfinished(&self, delivered: usize) -> Option<usize> {
        let delivered = u32::try_from(delivered).unwrap_or(u32::MAX);
        self.delimiters
            .iter()
            .find(|delimiter| delimiter.start() < delivered && delivered < delimiter.end)
            .map(|delimiter| delimiter.end as usize)
    }
}

/// What an attachment that never declared its terminal can offer.
///
/// Nothing that can be checked. Section 8 re-evaluates every controller when the application
/// changes its keyboard protocol; this host has nothing for that pass to change, because what it
/// checks does not depend on which protocol is in force: an attachment that cannot be put into one
/// and cannot be asked about one is refused control under every one of them, the ordinary encoding
/// included.
const UNDECLARED_TERMINAL: &str = "this attachment never declared what terminal it is, so what its keys mean cannot be \
     established";

/// What accepting input produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputAccepted {
    /// Bytes forwarded to the pseudo-terminal now.
    pub forwarded_bytes: u64,
    /// Bytes held as an incomplete delimiter prefix.
    pub held_prefix_bytes: u64,
    /// When that prefix must be forwarded even if nothing else arrives.
    pub deadline: Option<Instant>,
}

/// How much of the host's own answers may wait for an application that is not reading.
///
/// The response lane bounds what it queues; this bounds what has left the lane and is waiting for a
/// terminal whose application has stopped reading its input. An application that asks questions
/// without ever reading the answers stops being answered at this point rather than growing the
/// queue without limit. It is the response lane's share of [`MAX_QUEUED_INPUT_BYTES`], so a burst
/// of answers cannot take the whole budget and leave a person unable to type.
pub const MAX_PENDING_REPLY_BYTES: usize = 64 * 1024;

/// How much input may be waiting for the pseudo-terminal, across every producer at once.
///
/// One budget, because there is one pseudo-terminal and one application behind it. A lease holder's
/// keystrokes, the host's answers to the application's own questions and everything else that is
/// written into the terminal are counted against this together, and the writer releases each piece
/// as the application takes it. Beyond it a lease write is refused with a named result rather than
/// acknowledged, because an application that has stopped reading has not received those bytes and
/// telling the person otherwise is the one answer that is certainly wrong.
///
/// A megabyte is far more than a person can type and far more than a terminal's own buffer, so it
/// is only ever reached by an application that has genuinely stopped reading its input.
pub const MAX_QUEUED_INPUT_BYTES: usize = 1024 * 1024;

/// A cursor on the output stream.
#[must_use]
pub const fn cursor(value: u64) -> StreamCursor {
    StreamCursor::new(value)
}
