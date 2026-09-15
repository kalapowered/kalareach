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

/// One live session.
pub struct Session {
    config: SessionConfig,
    state: SessionState,
    pty: Pty,
    shell: Option<RootShell>,
    attachments: AttachmentTable,
    lease: InputLease,
    framer: PasteFramer,
    history: OutputHistory,
    hub: OutputHub,
    journal: Option<Journal>,
    journal_failure: Option<String>,
    closure: Option<ClosureRecord>,
    application_state: Option<ApplicationState>,
    closing_reason: Option<ClosureReason>,
    created_at_ms: TimestampMs,
    pending_input: Vec<InputBatch>,
    owned: Option<OwnedProcesses>,
    root_exit: Option<ShellExit>,
    /// The canonical grid. Every byte the terminal produces passes through it.
    engine: crate::projection::TerminalEngine,
    /// What the renderings this session has produced could not carry.
    restoration_losses: crate::render::Carried,
    /// The host's own answers that have been queued for the application and not yet written.
    ///
    /// The response lane bounds what it holds; this bounds what has left the lane. Counting only
    /// what is in `pending_input` would count nothing, because every flush hands that vector to
    /// the writer, so the counter is shared with the writer and comes down as each batch is
    /// written.
    host_reply_bytes: Arc<std::sync::atomic::AtomicUsize>,
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
        let pty = Pty::open(config.dimensions)?;
        let engine = crate::projection::TerminalEngine::new(config.dimensions)?;
        let history = match config.spool_directory.as_ref() {
            Some(directory) => {
                OutputHistory::with_spool(config.resident_bytes, directory, SpoolLayout::DEFAULT)?
            }
            None => OutputHistory::in_memory(config.resident_bytes),
        };
        let (journal, journal_failure) = match config.journal_path.as_ref() {
            Some(path) => match Journal::open(path) {
                Ok(mut journal) => {
                    // A dispatch marker with no authoritative answer is unresolvable from here, so
                    // it becomes unknown and is never dispatched again.
                    let _ = journal.resolve_unfinished_dispatches(kr_ipc::now_ms());
                    let _ = journal.prune(kr_ipc::now_ms());
                    (Some(journal), None)
                }
                Err(error) => (None, Some(error.to_string())),
            },
            None => (Journal::in_memory().ok(), None),
        };
        Ok(Self {
            attachments: AttachmentTable::new(config.dimensions),
            state: SessionState::Creating,
            pty,
            shell: None,
            lease: InputLease::new(),
            framer: PasteFramer::new(),
            history,
            hub: OutputHub::new(),
            journal,
            journal_failure,
            closure: None,
            application_state: None,
            closing_reason: None,
            created_at_ms: kr_ipc::now_ms(),
            pending_input: Vec::new(),
            owned: None,
            root_exit: None,
            engine,
            restoration_losses: crate::render::Carried::default(),
            host_reply_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
    /// profile is for. A desktop-bound one is bound to a login generation, and a generation that is
    /// gone means the desktop this session belongs to is gone with it.
    #[must_use]
    pub fn desktop_lost(&self) -> bool {
        if self.config.worker_profile != WorkerProfile::DesktopBound {
            return false;
        }
        let Some(bound) = self.config.desktop.login_generation.as_ref() else {
            return false;
        };
        let current = crate::environment::desktop_binding();
        // A binding this host can no longer read, or one that now names a different login, is a
        // desktop that has ended. A reading that agrees is a desktop that has not.
        current
            .login_generation
            .as_ref()
            .is_none_or(|generation| generation.get() != bound.get())
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
    fn resize_canonical(&mut self, dimensions: Dimensions) -> Result<()> {
        self.pty.resize(dimensions)?;
        self.engine.resize(dimensions)?;
        // A resize advances the engine's projection: every client's screen is at the old size and
        // nothing continues from it. They are told, here, rather than on the next byte the
        // application happens to write, which for an idle session may be never.
        let next = self.history.next_cursor();
        let oldest = self.history.oldest_retained_cursor();
        for attachment_id in self.hub.subscribers() {
            self.hub
                .require_resync(attachment_id, ResyncReason::ProjectionReset, next, oldest);
        }
        Ok(())
    }

    /// Tells the canonical grid where a side effect currently goes.
    ///
    /// A bell, a clipboard write or a notification leaves the terminal, so it goes to exactly one
    /// place: the attachment holding the input lease. Every path that moves the lease passes
    /// through here, so the destination can never be an attachment that stopped holding it.
    fn note_lease_holder(&mut self) {
        let epoch = kr_protocol::ids::InputLeaseEpoch::new(self.lease.epoch());
        self.engine.set_lease_holder(self.lease.holder(), epoch);
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
        let dimensions = self
            .attachments
            .own_dimensions(attachment_id)
            .ok_or_else(|| WorkerError::UnknownAttachment {
                attachment: attachment_id.to_string(),
            })?
            .unwrap_or_else(|| self.attachments.geometry().dimensions);
        let gate = self.lane_gate();
        let (cursor, restoration, settled) =
            self.engine
                .restoration(dimensions, gate, kr_ipc::now_ms().get());
        // Taking a snapshot settles the screen, and whatever that released belongs to the
        // attachments that were already watching. Delivering it here is what stops one client's
        // snapshot swallowing a character that was owed to another.
        self.deliver(settled);
        self.note_restoration(&restoration);
        Ok((cursor, restoration.bytes))
    }

    /// Records what a rendered restoration could not carry.
    ///
    /// Nothing is silently lost: the renderer counts every omission, and this is where the session
    /// keeps the count so a person asking the host doctor can be told.
    fn note_restoration(&mut self, restoration: &crate::render::Restoration) {
        let carried = restoration.carried;
        self.restoration_losses.inactive_rows += carried.inactive_rows;
        self.restoration_losses.other_saved_cursors += carried.other_saved_cursors;
        self.restoration_losses.title_stack += carried.title_stack;
        self.restoration_losses.clipped_rows += carried.clipped_rows;
        self.restoration_losses.soft_wraps += carried.soft_wraps;
        self.restoration_losses.other_keyboard |= carried.other_keyboard;
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
        let (attachment, change) =
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
        // Undelivered input from the removed attachment goes with it; nothing is replayed. A paste
        // it had open is closed first, so the application is not left inside a bracketed paste
        // whose source has gone.
        let held = self.lease.holder() == Some(attachment_id);
        self.lease.release_attachment(attachment_id);
        if held {
            let framing = self.framer.close_for_takeover();
            if let Some(terminator) = framing.terminator {
                self.pending_input.push(InputBatch {
                    origin: InputOrigin::Host,
                    bytes: terminator.to_vec(),
                });
            }
        }
        self.note_lease_holder();
        self.pump_replies();
        self.hub.detached(attachment_id);
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
    ) -> Result<TerminalPresentationMode> {
        self.attachments.viewport(attachment_id, dimensions)
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
            self.attachments.restore_geometry(&previous);
            return Err(error);
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
        if change.resize_required
            && let Err(error) = self.resize_canonical(change.state.dimensions)
        {
            // The transfer is undone, owner and epoch together: a half-completed handover would
            // leave the session with an owner whose size it never took.
            self.attachments.restore_geometry(&previous);
            return Err(error);
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
        // An interrupted paste is closed before the new lease writes, so the application never
        // sees a paste finished under a different actor.
        let previous_epoch = self.lease.epoch();
        let framing = self.framer.close_for_takeover();
        let mut discarded = self.lease.acquire(attachment_id, connection_id);
        discarded += framing.discarded_prefix.len() as u64;
        let closed_open_paste = framing.terminator.is_some();
        if let Some(terminator) = framing.terminator {
            // The terminator closes the paste the previous lease opened. It is the host's own
            // correction rather than that lease's keystrokes: fencing it would leave the
            // application inside a bracketed paste that nothing was ever going to end, which is
            // exactly the failure closing it exists to prevent.
            let _ = previous_epoch;
            self.pending_input.push(InputBatch {
                origin: InputOrigin::Host,
                bytes: terminator.to_vec(),
            });
        }
        self.note_lease_holder();
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
        self.lease
            .release(attachment_id, epoch)
            .ok_or(WorkerError::LeaseLost)?;
        // A paste this lease opened is closed as it goes. Leaving it open would put the
        // application into a bracketed paste that nothing was ever going to end, so the next
        // keystroke would arrive inside somebody else's paste.
        let framing = self.framer.close_for_takeover();
        if let Some(terminator) = framing.terminator {
            self.pending_input.push(InputBatch {
                origin: InputOrigin::Host,
                bytes: terminator.to_vec(),
            });
        }
        self.note_lease_holder();
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
        now: Instant,
    ) -> Result<InputAccepted> {
        if !self.state.accepts_input() {
            return Err(WorkerError::SessionClosed);
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
        let outcome = self.framer.push(bytes, now);
        if !outcome.forward.is_empty() {
            self.pending_input.push(InputBatch {
                origin: InputOrigin::Lease(epoch),
                bytes: outcome.forward.clone(),
            });
        }
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
                self.pending_input.push(InputBatch {
                    origin: InputOrigin::Lease(epoch),
                    bytes,
                });
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
    pub const fn set_bracketed_paste(&mut self, enabled: bool) {
        self.framer.set_bracketed_paste(enabled);
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
    /// Returns an error when the attachment is unknown.
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
        Ok(self.hub.subscribe(attachment_id, limit, presentation))
    }

    /// Returns how one attachment is served: the raw stream, or a rendering of the screen.
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
        self.framer
            .set_bracketed_paste(self.engine.bracketed_paste());
        self.deliver(filtered)
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
            if self
                .host_reply_bytes
                .load(std::sync::atomic::Ordering::Acquire)
                >= MAX_PENDING_REPLY_BYTES
            {
                return;
            }
            self.host_reply_bytes
                .fetch_add(reply.len(), std::sync::atomic::Ordering::AcqRel);
            self.pending_input.push(InputBatch {
                origin: InputOrigin::Host,
                bytes: reply,
            });
        }
    }

    /// Returns the counter the writer releases as it writes the host's own answers.
    #[must_use]
    pub fn host_reply_bytes(&self) -> Arc<std::sync::atomic::AtomicUsize> {
        Arc::clone(&self.host_reply_bytes)
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
        // how an attachment is being served.
        self.attachments
            .set_carryable(self.engine.direct_is_carryable());
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
                self.hub
                    .require_resync(attachment_id, ResyncReason::ProjectionReset, next, oldest);
                resynchronised.push(attachment_id);
            }
        }
        // A projection reset, or a span the engine cleared that this host could no longer produce,
        // means no client's screen continues from the one it holds. Both are answered the same
        // way: install a fresh screen rather than drawing on top of one with a hole in it.
        if filtered.projection_reset || filtered.lost {
            for attachment_id in self.hub.subscribers() {
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
            let gate = self.lane_gate();
            let (cursor, restoration, settled) =
                self.engine
                    .restoration(dimensions, gate, kr_ipc::now_ms().get());
            self.note_restoration(&restoration);
            let shared = Arc::new(restoration.bytes);
            if self
                .hub
                .publish_screen(attachment_id, cursor, &shared, oldest)
            {
                resynchronised.push(attachment_id);
            }
            // The screen was settled before this loop began, so this snapshot changes no display
            // state. It can still return replies the response lane released in the moment between,
            // and those are the application's, not this subscriber's repaint.
            debug_assert!(
                settled.direct.is_empty() && settled.effects.is_empty(),
                "the screen is settled once, before any snapshot is taken"
            );
            self.queue_replies(settled.replies);
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

    /// Returns the private journal, when one is available.
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
                let framing = self.framer.close_for_takeover();
                if let Some(terminator) = framing.terminator {
                    self.pending_input.push(InputBatch {
                        origin: InputOrigin::Host,
                        bytes: terminator.to_vec(),
                    });
                }
                self.note_lease_holder();
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
        // sequence, so descendants are still stopped and output is still drained. Committing the
        // record here would skip both.
        let reason = if exit.signalled() {
            ClosureReason::RootSignal
        } else {
            ClosureReason::RootExit
        };
        self.state = SessionState::Closing;
        self.closing_reason = Some(reason);
        true
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

/// Where one batch of terminal input came from.
///
/// The two are fenced differently, which is the whole reason the distinction exists. A person's
/// keystrokes belong to a lease, and a takeover discards the ones the previous holder had already
/// handed over. The host's own answer to a query the application asked belongs to the application:
/// it was asked for, nothing else can supply it, and dropping it because the lease happened to
/// move would leave the application waiting for a reply that will never come.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputOrigin {
    /// An attachment's input, accepted under one lease epoch.
    Lease(u64),
    /// The host answering the application, on the response lane.
    Host,
}

/// One ordered batch of input, and what it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputBatch {
    /// Where the batch came from, which decides whether a moved lease discards it.
    pub origin: InputOrigin,
    /// The bytes, exactly as they arrived.
    pub bytes: Vec<u8>,
}

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
/// queue without limit.
pub const MAX_PENDING_REPLY_BYTES: usize = 64 * 1024;

/// A cursor on the output stream.
#[must_use]
pub const fn cursor(value: u64) -> StreamCursor {
    StreamCursor::new(value)
}
