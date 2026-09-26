//! Attaching a terminal and driving it until the attachment ends.
//!
//! An attach is three things happening at once: bytes from the terminal going to the session, bytes
//! from the session going to the terminal, and a connection that can end at any moment. They run in
//! one loop rather than in tasks that each decide separately when to stop, because every way this
//! ends has to end the *other two* as well. A terminal left in raw mode because one half was still
//! waiting for a keystroke is the failure section 8 names.

use std::sync::Arc;

use kr_client::error::refusal;
use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::client::LocalClient;
use kr_protocol::attachment::ViewportPosition;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{InputLeaseEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{ClosureReason, ClosureRecord, Dimensions, SESSION_CLOSED_EVENT};
use kr_protocol::worker::WorkerDescriptor;

use crate::attach::{Attachment, RestorationGuard};
use crate::error::{CliError, Result};
use crate::terminal::ControllingTerminal;

/// Why an attachment ended.
#[derive(Clone, PartialEq, Eq)]
pub enum AttachOutcome {
    /// The terminal's own input ended, or the user detached.
    Detached,
    /// The session closed while this terminal was attached, and its worker said how.
    Closed {
        /// The session's closure record, as its worker sent it.
        record: Box<ClosureRecord>,
        /// Whether something typed here was not delivered because the session was closing.
        undelivered: bool,
    },
    /// The session closed while this terminal was attached, and the closure it was sent could not
    /// be read.
    ///
    /// The session has ended, so this is no lost connection; how it ended is not known here, so it
    /// is no success either.
    ClosureUnreadable {
        /// Why the closure could not be read: the rule it broke and where, never what it held.
        detail: Shown,
        /// Whether something typed here was not delivered because the session was closing.
        undelivered: bool,
    },
    /// The input lease moved to somebody else.
    LeaseLost,
    /// The connection to the worker ended.
    Disconnected,
    /// Input could not be delivered, and whether it arrived is not known.
    DeliveryUncertain(Shown),
}

impl std::fmt::Debug for AttachOutcome {
    /// How the attachment ended, and whether typing was left undelivered. Never the closure record,
    /// which names what the session ran.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Detached => formatter.write_str("Detached"),
            Self::Closed { undelivered, .. } => formatter
                .debug_struct("Closed")
                .field("undelivered", undelivered)
                .finish_non_exhaustive(),
            Self::ClosureUnreadable {
                detail,
                undelivered,
            } => formatter
                .debug_struct("ClosureUnreadable")
                .field("detail", detail)
                .field("undelivered", undelivered)
                .finish(),
            Self::LeaseLost => formatter.write_str("LeaseLost"),
            Self::Disconnected => formatter.write_str("Disconnected"),
            Self::DeliveryUncertain(detail) => formatter
                .debug_tuple("DeliveryUncertain")
                .field(detail)
                .finish(),
        }
    }
}

/// What the line about a closure adds when the session refused something typed here.
const UNDELIVERED: &str = "; what was typed while it was closing was not delivered";

impl AttachOutcome {
    /// Returns the sentence a person is shown.
    #[must_use]
    pub fn detail(&self) -> Shown {
        match self {
            Self::Detached => Shown::said("detached"),
            Self::Closed {
                record,
                undelivered,
            } => shown!(
                "the session closed: {}{}",
                how_it_closed(record),
                if *undelivered { UNDELIVERED } else { "" }
            ),
            Self::ClosureUnreadable {
                detail,
                undelivered,
            } => shown!(
                "the session closed, and how it closed could not be read ({}){}",
                *detail,
                if *undelivered { UNDELIVERED } else { "" }
            ),
            Self::LeaseLost => Shown::said("another attachment took the input lease"),
            Self::Disconnected => Shown::said("the connection to the session ended"),
            Self::DeliveryUncertain(detail) => {
                shown!("some input may not have reached the session: {}", *detail)
            }
        }
    }

    /// Returns the closure record this attachment was sent, when it was sent one.
    #[must_use]
    pub fn closure(&self) -> Option<&ClosureRecord> {
        match self {
            Self::Closed { record, .. } => Some(record.as_ref()),
            _ => None,
        }
    }

    /// Returns whether this outcome is a failure the exit code must carry.
    ///
    /// A closure is one when it was not clean, see [`closed_cleanly`], or when it could not be
    /// read.
    #[must_use]
    pub fn is_failure(&self) -> bool {
        match self {
            Self::Detached => false,
            Self::Closed { record, .. } => !closed_cleanly(record),
            Self::ClosureUnreadable { .. }
            | Self::LeaseLost
            | Self::Disconnected
            | Self::DeliveryUncertain(_) => true,
        }
    }

    /// Returns the failure this outcome is reported as.
    #[must_use]
    pub fn into_error(self) -> Option<CliError> {
        match self {
            Self::Detached => None,
            Self::Closed { ref record, .. } => {
                (!closed_cleanly(record)).then(|| CliError::SessionClosed(self.detail()))
            }
            Self::ClosureUnreadable { .. } => Some(CliError::SessionClosed(self.detail())),
            Self::LeaseLost => Some(CliError::Refused(refusal(
                ErrorCode::LeaseLost,
                self.detail(),
            ))),
            Self::Disconnected => Some(CliError::HostUnavailable(self.detail())),
            Self::DeliveryUncertain(_) => Some(CliError::Refused(refusal(
                ErrorCode::OutcomeUnknown,
                self.detail(),
            ))),
        }
    }
}

/// How an attachment ends when its session's closure arrives.
///
/// A closure this build cannot read is still the end of the session, and it is not a lost
/// connection. What it would have said is not known, so it is not reported as a success, and why it
/// could not be read is the rule it broke and where, never what it held.
fn closed(payload: &kr_protocol::envelope::ParamsValue, undelivered: bool) -> AttachOutcome {
    match payload.to_typed::<ClosureRecord>() {
        Ok(record) => AttachOutcome::Closed {
            record: Box::new(record),
            undelivered,
        },
        Err(error) => AttachOutcome::ClosureUnreadable {
            detail: Shown::cbor(&error),
            undelivered,
        },
    }
}

/// Whether a session closed the way the person meant it to.
///
/// Two closures are clean: a shell that exited with status 0, which is what `exit` and the end of
/// its input are when the last command succeeded, and a close somebody asked for. An attachment
/// ends successfully for those. Every other closure is a shell that failed or was ended by
/// something outside it, and an attachment reports it as the failure it is.
#[must_use]
pub fn closed_cleanly(record: &ClosureRecord) -> bool {
    match record.reason {
        ClosureReason::CloseRequested => true,
        ClosureReason::RootExit => record
            .root_exit_code
            .as_ref()
            .is_some_and(|code| code.get() == 0),
        ClosureReason::RootSignal
        | ClosureReason::RootLaunchFailed
        | ClosureReason::WorkerCrash
        | ClosureReason::DesktopLost
        | ClosureReason::HostShutdown => false,
    }
}

/// Says how a session closed, in the words a person is shown: what an attachment says when the
/// session closes under it, and what an attach to a session that has already closed says.
#[must_use]
pub fn how_it_closed(record: &ClosureRecord) -> Shown {
    match record.reason {
        ClosureReason::RootExit => record.root_exit_code.as_ref().map_or_else(
            || Shown::said("its shell exited"),
            |code| shown!("its shell exited with status {}", code.get()),
        ),
        ClosureReason::RootSignal => Shown::signal(record).map_or_else(
            || Shown::said("a signal ended its shell"),
            |signal| shown!("a signal ended its shell ({})", signal),
        ),
        ClosureReason::CloseRequested => Shown::said("it was closed on request"),
        ClosureReason::RootLaunchFailed => Shown::said("its shell never became ready"),
        ClosureReason::WorkerCrash => Shown::said("its worker ended before it finished closing"),
        ClosureReason::DesktopLost => Shown::said("the desktop login it ran in ended"),
        ClosureReason::HostShutdown => Shown::said("its host shut down"),
    }
}

/// How an attach presents the session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttachOptions {
    /// Take size ownership for this terminal.
    pub take_geometry: bool,
    /// Skip the outer terminal's capability probe and use the conservative profile.
    pub no_probe: bool,
    /// Come back to the live screen as soon as the session writes something.
    ///
    /// Off by default, because a person reading their scrollback has asked to look at what is
    /// above the live page and a chatty session would pull them off it on the next line. It is the
    /// client's own choice: nothing on the wire follows or does not follow, and the host goes on
    /// delivering live output either way.
    pub follow_live: bool,
    /// What the person typed before this attachment began, which nothing has delivered yet.
    ///
    /// Creating a session with `--palette probe` asks this terminal a question of its own, and
    /// what the person typed while it was being asked is theirs. It is carried here so the
    /// attachment that follows delivers it in front of its own handshake's typing, in the order
    /// it was typed.
    pub typed_before: Vec<u8>,
}

/// How far one scroll-back step moves this terminal's window.
///
/// A whole window less one line. The line that stays is the join: a person reading upwards keeps
/// one line of what they have just read at the other edge, and knows the two pages are continuous.
///
/// `rows` is the window this terminal is *shown*, which is not always the window it has: a
/// terminal taller than the session is shown the session's rows and blank space below them, and a
/// step measured from its own height would skip the rows in between.
fn scroll_step(rows: u64) -> u64 {
    rows.saturating_sub(1).max(1)
}

/// Shift and Page Up, which is what a terminal sends for the usual scroll-back key.
const SCROLL_BACK_KEY: &[u8] = b"\x1b[5;2~";

/// Shift and Page Down.
const SCROLL_FORWARD_KEY: &[u8] = b"\x1b[6;2~";

/// This terminal's own scroll-back, when a read is one of those keys and nothing else.
///
/// It reads nothing of the session's: section 8 puts passive scrollback with focus events and
/// terminal replies among the things that do not seize the input lease, so these keys are answered
/// by reporting where this window is looking and never by writing input.
///
/// A read is one of them or it is the session's, whole and unchanged. That is the rule because of
/// what the alternative costs: a reader that looked *inside* a batch would have to hold the
/// beginning of a sequence the read boundary cut in half and decide what a key means among bytes
/// it did not recognise, and each of those is a way for the command to alter what somebody typed.
/// A read is a batch of bytes and not a key, so what this recognises is a batch that is one key
/// and nothing else: a key pressed on its own usually arrives that way, and one that arrives among
/// other bytes is forwarded like every other byte and scrolls nothing. A read of several of the
/// same key is that many pages; a read mixing the two is nobody's gesture and belongs to the
/// session.
///
/// Returns how far the window moves: positive back through the history, negative towards the live
/// screen, and `None` for a read that is not this.
fn scroll_keys(bytes: &[u8]) -> Option<i64> {
    for (key, direction) in [(SCROLL_BACK_KEY, 1_i64), (SCROLL_FORWARD_KEY, -1_i64)] {
        if !bytes.is_empty()
            && bytes.len().is_multiple_of(key.len())
            && bytes.chunks_exact(key.len()).all(|chunk| chunk == key)
        {
            let count = i64::try_from(bytes.len() / key.len()).unwrap_or(i64::MAX);
            return Some(direction.saturating_mul(count));
        }
    }
    None
}

/// The bytes a terminal sends when a bracketed paste begins.
const PASTE_START: &[u8] = b"\x1b[200~";

/// The bytes a terminal sends when a bracketed paste ends.
const PASTE_END: &[u8] = b"\x1b[201~";

/// Whether a bracketed paste is open, watched across the reads that go past.
///
/// It holds nothing back, rewrites nothing and reorders nothing: every byte is forwarded as it
/// arrives, and this only remembers what it saw so that a later read can be told apart from one of
/// this terminal's own keys. A delimiter a read boundary cut in half is still that delimiter,
/// because what carries across the boundary is how much of one the last read ended inside.
#[derive(Debug, Default)]
struct PasteWatch {
    /// Whether a paste is open.
    open: bool,
    /// How many bytes of a delimiter the last read ended inside, for each delimiter.
    partial: [usize; 2],
}

/// What one read did to a bracketed paste.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Pasting {
    /// Whether a paste is open after it.
    open: bool,
    /// Whether a delimiter completed inside it.
    ///
    /// A read that carries one has a paste boundary inside it, and nothing may be taken out of
    /// such a read: where the paste begins or ends within it is not something a rule about whole
    /// reads can say.
    touched: bool,
}

impl PasteWatch {
    /// Whether a paste was open before the next read.
    const fn is_open(&self) -> bool {
        self.open
    }

    /// Reads one batch and answers what it did.
    fn observe(&mut self, bytes: &[u8]) -> Pasting {
        let mut touched = false;
        for byte in bytes {
            for (which, delimiter) in [PASTE_START, PASTE_END].into_iter().enumerate() {
                let matched = self.partial[which];
                if delimiter[matched] == *byte {
                    self.partial[which] = matched + 1;
                    if self.partial[which] == delimiter.len() {
                        self.open = which == 0;
                        touched = true;
                        self.partial = [0, 0];
                    }
                } else {
                    // Start again from this byte, which may itself be a delimiter's first.
                    self.partial[which] = usize::from(delimiter[0] == *byte);
                }
            }
        }
        Pasting {
            open: self.open,
            touched,
        }
    }
}

/// The longest a pointer report can be before it is not one.
///
/// `CSI <` and three numbers and a terminator. The numbers are a button, a column and a row, and a
/// terminal that has not finished one within this many bytes is not sending one.
const LONGEST_POINTER_REPORT: usize = 24;

/// What a pointer report says, as far as this terminal needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PointerReport {
    /// How far the wheel turned: positive back through the history, negative towards the live
    /// screen, and zero for a report that is not a wheel.
    wheel: i64,
}

/// The pointer reports a terminal sent, taken out of what it sent.
///
/// This runs only while the window is above the live page, where a report is a thing the session
/// must not be given: it names a cell of the live screen, and the rows the person is looking at
/// are not on it. Section 8 answers that case directly, that input outside the visible grid has no
/// application effect, so the reports are consumed here and the wheel among them moves the window.
///
/// A report the read boundary cut in half is held until the rest of it arrives or until what is
/// held cannot be a report, which is a few bytes and a moment rather than input held back:
/// forwarding half a report, or coordinates that describe somebody's history, is a click in a cell
/// nobody pointed at.
#[derive(Debug, Default)]
struct PointerReports {
    /// The beginning of a report, waiting for the rest of it.
    held: Vec<u8>,
}

/// What the classifier took out of one batch.
#[derive(Debug, Default, PartialEq, Eq)]
struct Pointers {
    /// The reports, in the order they arrived.
    reports: Vec<PointerReport>,
    /// The bytes that are not part of any report.
    input: Vec<u8>,
    /// Whether the beginning of a report is being held.
    holding: bool,
}

/// How much of a pointer report a run of bytes is.
enum Match {
    /// A whole report, this many bytes long.
    Whole(usize, PointerReport),
    /// The beginning of one, and nothing yet that says it is not.
    Partial,
    /// Not one.
    None,
}

/// Reads the beginning of `bytes` as a pointer report.
///
/// The two encodings this host advertises: xterm's SGR reports, which are three numbers between
/// `CSI <` and a press or a release, and the legacy form, which is three bytes after `CSI M`.
fn pointer_report(bytes: &[u8]) -> Match {
    for prefix in [b"\x1b[<".as_slice(), b"\x1b[M".as_slice()] {
        if bytes.len() < prefix.len() {
            if prefix.starts_with(bytes) {
                return Match::Partial;
            }
            continue;
        }
        if !bytes.starts_with(prefix) {
            continue;
        }
        if prefix == b"\x1b[M" {
            return if bytes.len() >= 6 {
                Match::Whole(6, PointerReport { wheel: 0 })
            } else {
                Match::Partial
            };
        }
        let body = &bytes[prefix.len()..];
        let Some(end) = body.iter().position(|byte| *byte == b'M' || *byte == b'm') else {
            return if body.len() < LONGEST_POINTER_REPORT
                && body
                    .iter()
                    .all(|byte| byte.is_ascii_digit() || *byte == b';')
            {
                Match::Partial
            } else {
                Match::None
            };
        };
        let fields: Vec<&[u8]> = body[..end].split(|byte| *byte == b';').collect();
        if fields.len() != 3
            || !fields
                .iter()
                .all(|field| !field.is_empty() && field.iter().all(u8::is_ascii_digit))
        {
            return Match::None;
        }
        // The button, whose wheel bits are the only part this terminal reads: 64 turns the wheel
        // back through the history and 65 turns it towards the live screen.
        let button: u64 = std::str::from_utf8(fields[0])
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or_default();
        let wheel = match button & 0xc3 {
            64 => 1,
            65 => -1,
            _ => 0,
        };
        return Match::Whole(prefix.len() + end + 1, PointerReport { wheel });
    }
    Match::None
}

impl PointerReports {
    /// Splits one batch into the reports it carries and the bytes that are not part of one.
    fn take(&mut self, bytes: &[u8]) -> Pointers {
        let mut buffer = std::mem::take(&mut self.held);
        buffer.extend_from_slice(bytes);
        let mut taken = Pointers::default();
        let mut at = 0_usize;
        while at < buffer.len() {
            match pointer_report(&buffer[at..]) {
                Match::Whole(length, report) => {
                    taken.reports.push(report);
                    at += length;
                }
                Match::Partial => break,
                Match::None => {
                    taken.input.push(buffer[at]);
                    at += 1;
                }
            }
        }
        self.held = buffer[at..].to_vec();
        taken.holding = !self.held.is_empty();
        taken
    }

    /// Gives back what is being held, because nothing came to finish it.
    fn release(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }
}

/// How long the beginning of a pointer report waits for the rest of itself.
///
/// The same window section 8 gives a held input prefix. A terminal writes one report in one go, so
/// nothing normally waits at all; what this covers is a read boundary landing inside one, and a
/// wait longer than this would be a keystroke held for a report the person never made.
const POINTER_DEADLINE: std::time::Duration = std::time::Duration::from_millis(25);

/// Waits until a held report's own deadline, or for ever when nothing is being held.
async fn pointer_expiry(until: Option<tokio::time::Instant>) {
    match until {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// The row an answer says this window landed on, or `None` for the live screen.
const fn landed(position: Option<ViewportPosition>) -> Option<u64> {
    match position {
        None => None,
        Some(ViewportPosition::Row(row) | ViewportPosition::Above(row)) => Some(row.get()),
        // A line is a place on the live screen, which this record holds as none. This terminal
        // never names one: its window on the live screen stays where its cells are the canonical
        // cells, because the pointer reports it forwards there are not mapped.
        Some(ViewportPosition::Line(_)) => None,
    }
}

/// Where a movement of `steps` puts this terminal's window.
///
/// `parked` is the row this window starts at, as the screen its last report caused says, and
/// `None` means it is on the live screen. Going back from the live screen is the one case that
/// cannot name a row: this client has not been given one above the page it is looking at, so it
/// asks by distance and the host answers with the row it landed on. Going forward from the live
/// screen asks nothing, because the live screen is as far forward as a window goes.
fn scrolled(parked: Option<u64>, steps: i64, step: u64) -> Option<Option<ViewportPosition>> {
    let distance = step.saturating_mul(steps.unsigned_abs());
    match (parked, steps) {
        (_, 0) => None,
        (None, ..=-1) => None,
        (None, 1..) => Some(Some(ViewportPosition::Above(U64::new(distance)))),
        (Some(row), 1..) => Some(Some(ViewportPosition::Row(U64::new(
            row.saturating_sub(distance),
        )))),
        (Some(row), ..=-1) => Some(Some(ViewportPosition::Row(U64::new(
            row.saturating_add(distance),
        )))),
    }
}

/// One viewport report to send: this terminal's size and where its window is to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Sending {
    dimensions: Dimensions,
    position: Option<ViewportPosition>,
}

/// Who owns the session's size, as an accepted viewport answer says, and the resize this terminal
/// owes when it is the owner and the session is not the size it is looking at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ownership {
    epoch: kr_protocol::ids::GeometryEpoch,
    owns: bool,
    resize: Option<Dimensions>,
}

/// Reads who owns the session's size from an accepted viewport answer.
///
/// Every accepted answer carries the geometry, whatever its report was for, and it is read from
/// every one of them: a move or a return carries this terminal's newest size too, and its answer
/// can name this terminal as the owner of a session that is still at another size. `looking_at` is
/// the size this terminal is looking at, when it has one; an owner looking at another size than the
/// session's owes the resize that puts the session at its own, unless one of the owner's resizes
/// still in flight, whose sizes `resizing` holds, already asks for it: an answer written before that
/// resize was applied still carries the old size, and a second resize to the same size would quote
/// the epoch the first one moves on from, and be refused.
fn ownership(
    geometry: &kr_protocol::attachment::GeometryState,
    attachment_id: kr_protocol::ids::AttachmentId,
    looking_at: Option<Dimensions>,
    resizing: &[Dimensions],
) -> Ownership {
    let owns = geometry.owner.as_ref() == Some(&attachment_id);
    Ownership {
        epoch: geometry.epoch,
        owns,
        resize: looking_at
            .filter(|size| owns && *size != geometry.dimensions && !resizing.contains(size)),
    }
}

/// How the host answered one viewport report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// Refused: nothing changed.
    Refused,
    /// Accepted, with the revision the report left the window at, whether this terminal is now
    /// handed the stream, and where the window landed.
    Accepted {
        window_revision: u64,
        direct: bool,
        landed: Option<u64>,
    },
}

/// Where this terminal's window is, and the viewport reports it owes the session.
///
/// Every viewport report this terminal sends goes through here, one at a time, and the session
/// answers each with the revision it left the window at; every screen it installs names the
/// revision of the window it is drawn for. That is what lets a report be settled by the screen
/// it caused and by nothing else: the answer and the screens reach this terminal from two writers,
/// either can arrive first, and a screen of an earlier revision, such as a repaint queued before
/// the report, is not the report's.
///
/// What goes next is one choice, and the command's loop asks for it at the top of every turn, so
/// nothing owed waits on an event that does not come: a return to the live screen, then the
/// question a refused resize leaves owed, then the newest size if it is not the one last sent,
/// then the next run of moves. Nothing goes while a report is in flight, while no screen is held
/// to measure a move from, while a new subscription is being asked for, or once the session has
/// said it is closing. Holding every report while a subscription is asked for is what lets that
/// subscription's first delivery settle the report in flight: it can only have been sent before.
#[derive(Debug)]
struct WindowReports {
    /// Where the window is: `Some(Some(row))` above the live page, `Some(None)` on the live screen
    /// from its origin, and `None` while this terminal holds no screen to say.
    record: Option<Option<u64>>,
    /// The newest revision any answer has named. A screen of an earlier one is drawn for a window
    /// this terminal has since moved, and never moves the record.
    answered: u64,
    /// The revision the newest complete screen named.
    installed: Option<u64>,
    /// The report in flight, if any.
    in_flight: Option<InFlight>,
    /// Whether a new subscription has been asked for and its first screen or restoration has not
    /// arrived.
    recovering: bool,
    /// A return to the live screen, asked for and not yet sent.
    return_owed: bool,
    /// The question a refused resize leaves owed: who owns the size, and at which epoch.
    question_owed: bool,
    /// The newest size this terminal measured.
    size: Dimensions,
    /// The size the last report carried.
    size_sent: Dimensions,
    /// Moves not yet sent, in runs: neighbouring moves in one direction merge, and a reversal
    /// starts a new run, so a movement the window cannot make at a limit takes nothing else with it.
    runs: std::collections::VecDeque<i64>,
    /// How far one step moves the window.
    step: u64,
    /// Whether the session has said it is closing.
    closing: bool,
}

/// The one report in flight.
#[derive(Clone, Copy, Debug)]
struct InFlight {
    /// Its request, once the loop has sent it.
    request: Option<kr_protocol::ids::RequestId>,
    /// The revision its answer named, once it has one and until a screen naming it arrives.
    awaiting: Option<u64>,
}

impl WindowReports {
    /// A terminal that has just attached at this size, and holds no screen yet.
    fn new(size: Dimensions) -> Self {
        Self {
            record: None,
            answered: 0,
            installed: None,
            in_flight: None,
            recovering: false,
            return_owed: false,
            question_owed: false,
            size,
            size_sent: size,
            runs: std::collections::VecDeque::new(),
            step: 1,
            closing: false,
        }
    }

    /// Where the window is, when this terminal holds a screen that says.
    const fn record(&self) -> Option<Option<u64>> {
        self.record
    }

    /// A scroll-back key or a turn of the wheel: `steps` pages of `step` rows, back through the
    /// history when positive.
    fn pressed(&mut self, steps: i64, step: u64, size: Dimensions) {
        self.step = step;
        self.size = size;
        match self.runs.back_mut() {
            Some(run) if run.signum() == steps.signum() => *run = run.saturating_add(steps),
            _ if steps != 0 => self.runs.push_back(steps),
            _ => {}
        }
    }

    /// This terminal's size changed.
    const fn measured(&mut self, size: Dimensions) {
        self.size = size;
    }

    /// This terminal gave the session its size as the owner, which tells the session without a
    /// viewport report. Later reports carry that size, and none is owed for it.
    const fn took_size(&mut self, size: Dimensions) {
        self.size = size;
        self.size_sent = size;
    }

    /// A resize was refused because somebody else owns the size, or owns it at another epoch.
    const fn owe_question(&mut self, size: Dimensions) {
        self.size = size;
        self.question_owed = true;
    }

    /// The person typed while following the live screen, which takes the window back to it. That
    /// is a newer instruction than any move still waiting.
    fn return_to_live(&mut self) {
        self.return_owed = true;
        self.runs.clear();
    }

    /// A screen arrived whole: the revision of the window it is drawn for, and where it puts the
    /// window.
    fn installed(&mut self, window_revision: u64, above: Option<u64>) {
        self.installed = Some(window_revision);
        // While a subscription replaces another, the one being replaced delivers no screen here, so
        // a screen that arrives is the new subscription's, and the recovery is over.
        self.recovering = false;
        if window_revision >= self.answered {
            self.record = Some(above);
        }
        if let Some(InFlight {
            awaiting: Some(awaited),
            ..
        }) = self.in_flight
            && window_revision >= awaited
        {
            self.in_flight = None;
        }
    }

    /// A subscription began with the stream's restoration rather than a screen.
    ///
    /// The session hands the stream only to a window at the live screen's origin, so that is where
    /// the window is, and every report sent before the subscription was asked for is settled by it.
    /// The moves still waiting were meant for a projection this terminal is no longer drawing: its
    /// keys are the session's while the stream is its screen.
    fn streamed(&mut self) {
        self.record = Some(None);
        self.in_flight = None;
        self.recovering = false;
        self.runs.clear();
    }

    /// This terminal discarded its screen and asked for a new subscription. Until that one's first
    /// screen or restoration arrives, nothing says where the window is, and nothing is sent: an
    /// answer that arrives meanwhile, a direct one included, settles its own report and no more.
    const fn recovering(&mut self) {
        self.record = None;
        self.recovering = true;
    }

    /// The session has said it is closing, and is sent nothing more.
    const fn close(&mut self) {
        self.closing = true;
    }

    /// The report to send now, if any. It is in flight from here until it settles.
    fn next(&mut self) -> Option<Sending> {
        if self.closing || self.recovering || self.in_flight.is_some() {
            return None;
        }
        let record = self.record?;
        let place = record.map(|row| ViewportPosition::Row(U64::new(row)));
        let sending = if self.return_owed {
            self.return_owed = false;
            Sending {
                dimensions: self.size,
                position: None,
            }
        } else if self.question_owed {
            // What it asks for is the answer's owner and epoch, so it goes whatever its size.
            self.question_owed = false;
            Sending {
                dimensions: self.size,
                position: place,
            }
        } else if self.size != self.size_sent {
            Sending {
                dimensions: self.size,
                position: place,
            }
        } else {
            loop {
                let run = self.runs.pop_front()?;
                // A movement the window cannot make is spent here, inside the same choice, so the
                // run behind it goes now rather than waiting for something else to happen.
                if let Some(position) = scrolled(record, run, self.step) {
                    break Sending {
                        dimensions: self.size,
                        position,
                    };
                }
            }
        };
        self.size_sent = sending.dimensions;
        self.in_flight = Some(InFlight {
            request: None,
            awaiting: None,
        });
        Some(sending)
    }

    /// The loop sent the report `next` handed it, under this request.
    const fn sent(&mut self, request: kr_protocol::ids::RequestId) {
        if let Some(in_flight) = self.in_flight.as_mut() {
            in_flight.request = Some(request);
        }
    }

    /// The session answered one of this terminal's viewport reports.
    ///
    /// A refusal settles it and changes nothing. An answer that hands this terminal the stream
    /// settles it where that answer says the window landed, which for a terminal handed the stream
    /// is the live screen's origin. Any other answer settles it only once a screen naming its
    /// revision, or a later one, has arrived, whether that screen came before the answer or comes
    /// after it.
    fn answered(&mut self, request: kr_protocol::ids::RequestId, answer: Answer) {
        let ours = self
            .in_flight
            .is_some_and(|in_flight| in_flight.request == Some(request));
        match answer {
            Answer::Refused => {
                if ours {
                    self.in_flight = None;
                }
            }
            Answer::Accepted {
                window_revision,
                direct,
                landed: at,
            } => {
                self.answered = self.answered.max(window_revision);
                if !ours {
                    return;
                }
                if direct {
                    self.record = Some(at);
                    self.runs.clear();
                    self.in_flight = None;
                } else if self
                    .installed
                    .is_some_and(|installed| installed >= window_revision)
                {
                    self.in_flight = None;
                } else if let Some(in_flight) = self.in_flight.as_mut() {
                    in_flight.awaiting = Some(window_revision);
                }
            }
        }
    }
}

/// Which subscription a notification belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Heard {
    /// A notification of the stream a new subscription is replacing.
    Replaced,
    /// The first delivery of a subscription, other than a gap: its screen or the stream's
    /// restoration.
    First,
    /// Anything else.
    Later,
}

/// The subscriptions this terminal asks for, and where a new one's stream begins.
///
/// Every subscription's notifications on one connection share a stream identifier and restart
/// their sequence at zero, and the one being replaced stops before the new one writes anything.
/// This terminal asks for a new one only after reading a notification of the old one, so the next
/// notification of sequence zero is the new stream's first, and it asks for one at a time, so there
/// is never a second new stream to mistake for it. The sequence is read before anything else about
/// a notification, which is what lets a first notification that cannot be decoded still open the
/// new stream.
#[derive(Debug, Default)]
struct Subscriptions {
    /// A new subscription has been asked for, and its stream has not begun.
    replacing: bool,
    /// The stream's first delivery other than a gap has not arrived.
    opening: bool,
}

impl Subscriptions {
    /// The first subscription, whose first delivery has not arrived.
    const fn new() -> Self {
        Self {
            replacing: false,
            opening: true,
        }
    }

    /// Asks for a new subscription, unless one is already being asked for; says which.
    const fn replace(&mut self) -> bool {
        if self.replacing {
            return false;
        }
        self.replacing = true;
        true
    }

    /// Says which subscription a notification belongs to, from its sequence and its type.
    fn heard(&mut self, sequence: u64, event_type: &str) -> Heard {
        if self.replacing {
            if sequence != 0 {
                return Heard::Replaced;
            }
            self.replacing = false;
            self.opening = true;
        }
        if self.opening && event_type != "session.gap" {
            self.opening = false;
            return Heard::First;
        }
        Heard::Later
    }
}

/// What the person typed before a session existed, until something delivers it.
///
/// Creating a session with `--palette probe` asks this terminal a question of its own, and what
/// the person typed while it was being asked is theirs. Between the question and the attachment
/// that forwards it there is nowhere for those bytes to go, and every way out of that stretch
/// passes through this: the count is reported unless something says it arrived.
#[derive(Debug)]
pub struct UndeliveredTyping {
    bytes: usize,
}

impl UndeliveredTyping {
    /// Takes responsibility for `bytes` the session has not been given.
    #[must_use]
    pub const fn new(bytes: usize) -> Self {
        Self { bytes }
    }

    /// Something took them, so nothing is owed.
    pub const fn delivered(&mut self) {
        self.bytes = 0;
    }
}

impl Drop for UndeliveredTyping {
    fn drop(&mut self) {
        if self.bytes > 0 {
            crate::report::say(&shown!(
                "kr: {} bytes typed while this terminal was asked for its colours could not be \
                 delivered to the session",
                self.bytes
            ));
        }
    }
}

/// Attaches this terminal to a session and drives it until the attachment ends.
///
/// # Errors
///
/// Returns the host's refusal, a terminal failure, or the failure the attachment ended with.
pub async fn run(
    descriptor: &WorkerDescriptor,
    mut owed: UndeliveredTyping,
    options: AttachOptions,
) -> Result<(AttachOutcome, SessionId)> {
    let terminal = ControllingTerminal::open()?;
    let size = terminal.size()?;
    let dimensions = Dimensions::new(u64::from(size.columns), u64::from(size.rows));

    // Everything that touches this terminal happens after the guard is holding its state. The
    // capability handshake changes the terminal's modes to read the answers, so it is inside that
    // protection too: a process killed during the handshake must still leave a terminal somebody
    // can put back.
    let saved = terminal.modes()?;
    let mut guard = RestorationGuard::arm(
        &crate::attach::guard_program(),
        &terminal,
        &crate::terminal::SavedModes::from_state(&saved),
    )?;
    // Section 8's bounded synchronous handshake, before any application input. It asks the terminal
    // what it is and what keyboard protocols it has negotiated, so that what is put back afterwards
    // is this terminal's own state rather than nothing at all, and it ends with the
    // device-attributes terminator. A terminal that does not finish it fails this attach rather
    // than forwarding live input on a stream that may still receive a late reply.
    //
    // This process has written nothing to the terminal yet, so the stream is clean. `--no-probe` is
    // chosen here, before any probe: choosing it afterwards would not unsend the questions.
    // What this terminal declares itself to be decides which questions may be asked of it, because
    // section 8 requires every question asked to be answered. A terminal the profile cannot require
    // anything of beyond the terminator is asked only that.
    let declared = std::env::var("TERM").ok();
    // Whether a probe has already gone out on this terminal, which is a fact about the terminal
    // rather than about this process: a second `kr attach` in a window where one failed is looking
    // at the same input stream, and a late reply from the first is still coming to it.
    let context = crate::terminal::input_context(&terminal);
    let probe = if options.no_probe {
        crate::terminal::Probe::unasked(context)
    } else {
        terminal.probe(context, declared.as_deref())
    };
    let probe = match probe {
        Ok(probe) => probe,
        Err(error) => {
            // Nothing has begun forwarding, so the outer terminal's own keyboard negotiation is
            // not this attachment's to clear. Its modes are put back and the failure is reported.
            // The record that makes the next attempt require a fresh terminal was written before
            // the first question went out, and an exchange that did not finish leaves it there.
            // Nothing was read, so nothing but the documented defaults can be put back.
            let _ = terminal.restore(&saved, None, &crate::terminal::ScreenModes::UNASKED);
            guard.release();
            return Err(error);
        }
    };
    let keyboard = probe.keyboard;
    // The mouse modes, the cursor visibility and the bracketed-paste state this terminal had before
    // anything of this attachment's changed them. Held here because the rest of the probe is handed
    // to the loop, and the restoration at the end of this function needs them.
    let modes = probe.modes;
    // The guard is told them *here*, before anything else can fail. Whatever happens from now on -
    // a worker that cannot be reached, an attachment the host refuses, this process killed outright
    // - the guard puts the terminal back, and what it writes is the reset block. That block is the
    // documented default for every one of these modes, so a guard that had not been told them would
    // clear a person's mouse reporting on the way out of a failure that never touched it.
    guard.learn_modes(&modes);

    let mut client = crate::resolve::open_worker(descriptor, crate::build_id()).await?;
    // A terminal attachment claims the session's size. Section 8 makes that the default: a
    // terminal that did not claim it would be shown a projection of somebody else's size, which is
    // exactly what a lone attachment does not need. `--take-geometry` goes further and takes the
    // claim from whoever holds it.
    let attachment: Attachment =
        crate::attach::attach(&mut client, descriptor, dimensions, true, !options.no_probe).await?;
    // The transfer's own answer is what the loop starts from. Starting from the attach result
    // instead would leave it quoting an epoch the transfer has already moved, and believing
    // somebody else still owns the size it has just taken.
    let geometry = if options.take_geometry {
        crate::attach::take_geometry(
            &mut client,
            descriptor,
            attachment.attachment_id,
            attachment.result.geometry.epoch,
        )
        .await?
        .geometry
    } else {
        attachment.result.geometry.clone()
    };
    // `None` where the host would not let this terminal type: section 8 requires it to check that
    // a controller can supply the encoding the application reads, and a terminal nobody was allowed
    // to ask about cannot be shown to. The attachment stands and watches, and the person is told
    // which of the two they have before the screen arrives over it.
    let epoch = attachment.lease.as_ref().map(|lease| lease.lease.epoch);
    if epoch.is_none() {
        crate::report::say(&Shown::said(
            "kr: this terminal was not asked what it is, so the host will not let it type. \
             Attach without --no-probe to control the session.",
        ));
    }

    // From the cursor the attachment was allocated at, not from the beginning of what is retained.
    // Replaying historical bytes into this terminal would replay whatever they contained: a
    // clipboard write, a bell, a query whose answer would arrive at the wrong moment.
    crate::attach::subscribe(
        &mut client,
        descriptor.session_id,
        attachment.attachment_id,
        Some(attachment.result.output_cursor.get()),
    )
    .await?;

    // Forwarding begins here, and the terminal's keyboard protocols are dealt with at this exact
    // boundary and not before.
    //
    // An attachment that asked its terminal nothing changes nothing about its keyboard: the host
    // serves it a screen that installs no protocol, because nothing could put back what installing
    // one would take away. There is then nothing for the guard to give back.
    //
    // One that did ask hands the guard the answers it got and tells it that forwarding is about to
    // begin. The guard then owes those protocols back however this attachment ends, and it writes
    // them as the state they are: no stack of the terminal's is operated, because an entry pushed
    // here could be taken off by an application inside the session and the pop would then land on
    // somebody else's. The guard confirms before this returns, so nothing is forwarded until
    // something that outlives this process is holding what the terminal had. An attach that failed
    // on its way here told it nothing.
    if !options.no_probe {
        guard.learn_keyboard(&keyboard);
        guard.begin_keyboard()?;
    }
    let raw_replaced = terminal.enter_raw_mode()?;

    let handle = Arc::new(
        terminal
            .handle()
            .try_clone()
            .map_err(|error| CliError::Terminal(Shown::io(&error)))?,
    );
    let input_handle = terminal
        .handle()
        .try_clone()
        .map_err(|error| CliError::Terminal(Shown::io(&error)))?;
    let mut input = crate::attach::spawn_input_reader(input_handle);

    // The terminal's size can change while the attachment runs. The session is told, so the
    // application sees the resize the way it would in any other terminal.
    let mut resized = window_changes();
    // What this terminal shows while it is projected, with each keyboard protocol decided on its
    // own terms. The `modifyOtherKeys` level goes in when the person here can type, because that is
    // the encoding the host advertises for them and `CSI > 4 m` puts any terminal back to the level
    // it started with. The Kitty flags go in only when this terminal reported its own, because
    // nothing else could put those back and a person left in an encoding their shell does not
    // expect is the failure they cannot work around.
    let mut display =
        crate::render::ProjectedDisplay::with_keyboard(epoch.is_some(), keyboard.kitty.is_some());
    let outcome = drive(
        &mut client,
        descriptor,
        &mut owed,
        [options.typed_before, probe.typed].concat(),
        Attached {
            attachment_id: attachment.attachment_id,
            dimensions,
            lease_epoch: epoch,
            geometry_epoch: geometry.epoch,
            owns_geometry: geometry.owner.as_ref() == Some(&attachment.attachment_id),
        },
        &mut input,
        &handle,
        &terminal,
        resized.as_mut(),
        &mut display,
        options.follow_live,
    )
    .await;

    // The terminal comes back here on every path out of the loop, and the guard is released only
    // once it has.
    // The modes are this process's to put back; the keyboard protocols are the guard's, and it
    // writes them back as it is released, which is what keeps the two halves in order.
    terminal.restore(&raw_replaced, None, &modes)?;
    guard.release();
    // Said after the terminal is its own again, never during the attachment: a sentence written
    // into a terminal that is showing a projection would wrap, overwrite cells and scroll the
    // bottom row, which is damage to the very screen it is describing.
    if let Some(detail) = display.degradation() {
        crate::report::say(&shown!(
            "kr: this terminal was showing a projection of the session, and it did not carry all \
             of it: {}",
            detail
        ));
    }
    // And what this attachment could not establish about the terminal itself: the modes it had to
    // put back to their documented default because nothing could be read for them, and a
    // destination whose declared identity is not qualified for the character widths this session
    // measures with. Both are the attachment making a smaller promise than a qualified terminal
    // gets, and both are said out loud rather than assumed either way.
    let qualification = crate::render::Qualification {
        defaulted_modes: modes.unanswered(),
        width_unqualified: (display.frames().0 > 0)
            .then(|| {
                declared
                    .clone()
                    .unwrap_or_else(|| "a terminal with no name of its own".to_owned())
            })
            .filter(|identity| !kr_term::profile::width_qualified(identity)),
    };
    if let Some(detail) = qualification.report() {
        crate::report::say(&shown!(
            "kr: not everything about this terminal could be established: {}",
            detail
        ));
    }
    Ok((outcome, descriptor.session_id))
}

/// What the attach established, which the loop then keeps up to date.
#[derive(Clone, Copy, Debug)]
struct Attached {
    attachment_id: kr_protocol::ids::AttachmentId,
    /// The size this attachment reported when it joined.
    dimensions: Dimensions,
    /// The input lease, where this attachment was given one. `None` is an attachment that watches:
    /// the host would not let this terminal type, because what its keys mean was never established.
    lease_epoch: Option<InputLeaseEpoch>,
    /// The geometry epoch this terminal last saw. A resize quotes it, so a claim that moved while
    /// the window was being dragged is refused rather than silently applied to a stale view.
    geometry_epoch: kr_protocol::ids::GeometryEpoch,
    /// Whether this attachment owns the session's size.
    owns_geometry: bool,
}

/// What one outstanding request was for, so its answer is read as an answer to that.
#[derive(Clone, Copy, Debug)]
enum Outstanding {
    /// Input at this sequence number.
    Input(u64),
    /// A size change this terminal made as the size owner, to this size.
    Resize(Dimensions),
    /// A viewport report, which `WindowReports` holds.
    Window,
    /// A fresh screen this terminal asked for after a resynchronisation marker.
    Resubscribe,
}

/// The sizes this terminal's resizes as the owner asked for, of those still waiting for an answer.
fn resizes_in_flight(
    outstanding: &std::collections::BTreeMap<kr_protocol::ids::RequestId, Outstanding>,
) -> Vec<Dimensions> {
    outstanding
        .values()
        .filter_map(|what| match what {
            Outstanding::Resize(dimensions) => Some(*dimensions),
            _ => None,
        })
        .collect()
}

/// Runs the attachment's input, output and connection in one loop.
#[expect(
    clippy::too_many_arguments,
    reason = "one attachment is its client, its session, its terminal and everything it started with"
)]
async fn drive(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    owed: &mut UndeliveredTyping,
    typed_during_the_probe: Vec<u8>,
    attached: Attached,
    input: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    output: &Arc<std::fs::File>,
    terminal: &ControllingTerminal,
    resized: Option<&mut WindowChanges>,
    display: &mut crate::render::ProjectedDisplay,
    follow_live: bool,
) -> AttachOutcome {
    use std::io::Write as _;

    let session_id = descriptor.session_id;
    let attachment_id = attached.attachment_id;
    // `None` where this terminal may not type. What it types is then dropped rather than sent:
    // the host has already refused it the lease, so every keystroke would be one refused request,
    // and the attachment would end on the first of them. Watching is what is left, and watching is
    // what this attachment asked for when it chose not to be asked about.
    let epoch = attached.lease_epoch;
    let mut geometry_epoch = attached.geometry_epoch;
    let mut owns_geometry = attached.owns_geometry;
    let mut resized = resized;

    // Whether a bracketed paste is open, so that nothing inside one is read as a key.
    let mut paste = PasteWatch::default();
    // The pointer reports this terminal sends while its window is above the live page, and the
    // moment a report it is part way through stops waiting for the rest of itself.
    let mut pointers = PointerReports::default();
    let mut pointer_deadline: Option<tokio::time::Instant> = None;
    // Whether the last screen this terminal was given is above the live page. It is what this
    // terminal is *displaying*, which a reset does not change: between a reset and the last page
    // of the screen that follows it, the rows on the person's terminal are still the old ones.
    let mut showing_history = false;
    let mut sequence = 0_u64;
    let mut outstanding: std::collections::BTreeMap<kr_protocol::ids::RequestId, Outstanding> =
        std::collections::BTreeMap::new();
    let mut next_request = 1_u64;
    // Where this terminal's window is, and every viewport report it owes the session about it,
    // which go one at a time and are settled by the screen each one caused.
    let mut window = WindowReports::new(attached.dimensions);
    // Which subscription each notification belongs to, while a new one replaces the old.
    let mut subscriptions = Subscriptions::new();

    // The output cursor of the last whole screen this terminal was given, which is how it tells a
    // screen the session had something new to say from one it asked for itself.
    let mut drawn_at: Option<u64> = None;

    // Whether the session has said it is closing, by refusing something this terminal sent. From
    // then on nothing more is sent: the session refuses input from the moment its closing began,
    // and a size or a fresh screen is of no use to a session that is ending. The terminal stays,
    // showing what the session drains, until the closure arrives as the last thing on its stream,
    // so it ends with that closure's own status rather than a guess made halfway through it. The
    // worker bounds how long that is, as it does for every attachment that is only watching; a
    // connection that ends first ends this as a connection lost, like any other.
    let mut closing = false;
    // Whether something typed here was not delivered because the session was closing.
    let mut undelivered = false;

    // What the person typed while the host was asking the terminal what it was. It was buffered
    // rather than discarded, and it is the first thing the application receives, in the order it
    // was typed in.
    // What the person typed while the terminal was being asked goes to the application like
    // everything else, and past the paste watch like everything else: a delimiter among it is a
    // delimiter, and what follows it is pasted text rather than one of this terminal's own keys.
    paste.observe(&typed_during_the_probe);
    if !typed_during_the_probe.is_empty()
        && let Some(epoch) = epoch
    {
        // It is on its way to the application, so nothing is owed for it any more.
        owed.delivered();
        let request_id = kr_protocol::ids::RequestId::new(next_request);
        next_request += 1;
        if !send_input(
            client,
            request_id,
            session_id,
            attachment_id,
            epoch,
            sequence,
            typed_during_the_probe,
        )
        .await
        {
            return AttachOutcome::DeliveryUncertain(Shown::said(
                "the connection ended while input was being sent",
            ));
        }
        outstanding.insert(request_id, Outstanding::Input(sequence));
        sequence += 1;
    }
    loop {
        // What this terminal owes the session about its window goes first, one report at a time.
        // It is asked here, at the top of every turn, so an event that lets a report go is never
        // one that forgot to ask for it.
        if let Some(report) = window.next() {
            let request_id = kr_protocol::ids::RequestId::new(next_request);
            next_request += 1;
            let params = kr_protocol::attachment::AttachmentViewportParams {
                attachment_id,
                dimensions: report.dimensions,
                position: Nullable(report.position),
                column: U64::ZERO,
            };
            if !send_geometry(
                client,
                descriptor,
                request_id,
                Method::AttachmentViewport,
                &params,
            )
            .await
            {
                return AttachOutcome::Disconnected;
            }
            window.sent(request_id);
            outstanding.insert(request_id, Outstanding::Window);
        }
        tokio::select! {
            // Biased towards the worker, so output and refusals are seen before more input is
            // sent. What comes before even that is a held prefix whose moment has passed: it is
            // the person's own bytes, and a session that keeps printing must not keep them.
            biased;
            () = pointer_expiry(pointer_deadline) => {
                // Nothing came to finish it, so it was not a report. What was held is the
                // person's, and it goes to the application now.
                pointer_deadline = None;
                let held = pointers.release();
                if closing {
                    undelivered |= !held.is_empty();
                    continue;
                }
                // Typing brings a following window back to the live screen, wherever in this loop
                // the typing turns out to have been.
                if !held.is_empty() && follow_live && showing_history {
                    window.return_to_live();
                }
                if !held.is_empty()
                    && let Some(epoch) = epoch
                {
                    let request_id = kr_protocol::ids::RequestId::new(next_request);
                    next_request += 1;
                    if !send_input(
                        client,
                        request_id,
                        session_id,
                        attachment_id,
                        epoch,
                        sequence,
                        held,
                    )
                    .await
                    {
                        return AttachOutcome::DeliveryUncertain(Shown::said(
                            "the connection ended while input was being sent",
                        ));
                    }
                    outstanding.insert(request_id, Outstanding::Input(sequence));
                    sequence += 1;
                }
            }
            message = client.recv() => {
                match message {
                    Ok(ControlFrame::Notification(notification)) => {
                        // The session has closed, and this is how. It is the last thing the stream
                        // carries, after every byte this terminal was owed, and it ends the
                        // attachment with the status the closure implies.
                        if notification.event_type.as_str() == SESSION_CLOSED_EVENT {
                            return closed(&notification.payload, undelivered);
                        }
                        // Which subscription this belongs to, read before anything else about it:
                        // a first notification that cannot even be decoded still opens the new
                        // stream. While a new subscription replaces the old one, the old stream's
                        // screens and markers describe what is being replaced and are passed over.
                        let heard = subscriptions.heard(
                            notification.sequence.get(),
                            notification.event_type.as_str(),
                        );
                        if heard == Heard::Replaced
                            && (crate::render::is_projection_event(
                                notification.event_type.as_str(),
                            ) || notification.event_type.as_str() == "session.resync")
                        {
                            continue;
                        }
                        // A subscription that begins with the stream rather than a screen is
                        // served at the live screen's origin, which is the only place the session
                        // hands its stream to.
                        if heard == Heard::First
                            && notification.event_type.as_str() == "session.output"
                        {
                            window.streamed();
                        }
                        if notification.event_type.as_str() == "session.output"
                            && let Ok(event) = notification
                                .payload
                                .to_typed::<kr_protocol::recovery::OutputEvent>()
                        {
                            // Bytes drawn while this terminal holds no projection are its own
                            // stream or its restoration, and both are the live screen: what it is
                            // showing from here is not somebody's history. A bell routed to the
                            // lease holder arrives the same way, so the screen decides whether
                            // this is a redraw: a terminal holding a projection is still drawing
                            // that projection.
                            if !display.holds_screen() {
                                showing_history = false;
                            }
                            let mut handle = output.as_ref();
                            if handle.write_all(event.bytes.as_slice()).is_err() {
                                return AttachOutcome::Disconnected;
                            }
                            let _ = handle.flush();
                        }
                        // A projected attachment is sent the canonical grid as state and draws it
                        // itself. The renderer is shared with the client library, so this terminal
                        // and the companion application put a canonical cell in the same place.
                        if crate::render::is_projection_event(notification.event_type.as_str()) {
                            let Some(event) =
                                crate::render::decode(
                                    notification.event_type.as_str(),
                                    &notification.payload,
                                )
                            else {
                                // A payload this build cannot decode is not drawn and not guessed
                                // at. What is held goes with it, because the next thing drawn has
                                // to be a screen this terminal was actually sent.
                                display.discard();
                                if closing || !subscriptions.replace() {
                                    continue;
                                }
                                window.recovering();
                                let request_id = kr_protocol::ids::RequestId::new(next_request);
                                next_request += 1;
                                if !resubscribe(client, descriptor, request_id, attachment_id).await
                                {
                                    return AttachOutcome::Disconnected;
                                }
                                outstanding.insert(request_id, Outstanding::Resubscribe);
                                continue;
                            };
                            let drawn = display.apply(event);
                            // What counts as the session writing is the session's output cursor
                            // moving, which is the one thing a screen this terminal asked for
                            // itself does not do. A reason cannot answer it: the same reason
                            // covers a screen sent after an overflow and a screen this terminal
                            // moved its own window to.
                            let changed = match display.output_cursor() {
                                Some(now) => {
                                    let moved = drawn_at.is_some_and(|before| now > before);
                                    drawn_at = Some(now);
                                    moved
                                }
                                None => false,
                            };
                            // What this terminal is showing, which every screen and update it draws
                            // decides: the rows on the person's terminal are the ones drawn last.
                            if let Some(above) = display.window_above_the_live_page() {
                                showing_history = above.is_some();
                            }
                            // Where the window is, which only a whole screen says: the session
                            // gives up its oldest rows, and a window over them is moved to the
                            // oldest that survive; a full-screen application takes the screen,
                            // and the window comes back to the live screen with it. The screen
                            // names the window's revision, so one drawn for a window this terminal
                            // has since moved is told apart from the one its report caused.
                            if drawn.installed
                                && let (Some(revision), Some(above)) =
                                    (display.window_revision(), display.window_above_the_live_page())
                            {
                                window.installed(revision, above);
                            }
                            // The client's own choice, not the session's: a person who asked to
                            // follow the live screen is taken back to it the moment the session
                            // writes, and one who did not stays where they scrolled to while the
                            // output goes on arriving underneath.
                            if follow_live && changed && window.record().flatten().is_some() {
                                window.return_to_live();
                            }
                            if !drawn.bytes.is_empty() {
                                let mut handle = output.as_ref();
                                if handle.write_all(&drawn.bytes).is_err() {
                                    return AttachOutcome::Disconnected;
                                }
                                let _ = handle.flush();
                            }
                            if drawn.resubscribe && !closing && subscriptions.replace() {
                                window.recovering();
                                let request_id = kr_protocol::ids::RequestId::new(next_request);
                                next_request += 1;
                                if !resubscribe(client, descriptor, request_id, attachment_id).await
                                {
                                    return AttachOutcome::Disconnected;
                                }
                                outstanding.insert(request_id, Outstanding::Resubscribe);
                            }

                        }
                        // A resynchronisation marker means this terminal's view of the session is
                        // no longer continuous: its size changed, its presentation changed, or it
                        // fell behind. It is not a reason to end the attachment — a person resizing
                        // a window would lose their session — so the marker is answered by asking
                        // for the screen again, which is what the marker is for.
                        if notification.event_type.as_str() == "session.resync" {
                            // Whatever this terminal was holding is no longer the session's screen.
                            // It is discarded before the fresh one is asked for, so nothing is
                            // drawn from it in between.
                            display.discard();
                            if closing || !subscriptions.replace() {
                                continue;
                            }
                            window.recovering();
                            let request_id = kr_protocol::ids::RequestId::new(next_request);
                            next_request += 1;
                            if !resubscribe(client, descriptor, request_id, attachment_id).await {
                                return AttachOutcome::Disconnected;
                            }
                            outstanding.insert(request_id, Outstanding::Resubscribe);
                        }
                        // This attachment was ended somewhere else, which is what `kr detach` from
                        // another window does. The terminal comes back and the command finishes.
                        if notification.event_type.as_str() == "session.detached" {
                            return AttachOutcome::Detached;
                        }
                    }
                    Ok(ControlFrame::Response(response)) => {
                        let answered = response.request_id;
                        let Some(what) = outstanding.remove(&answered) else {
                            continue;
                        };
                        // A session that is closing has nothing more to say to this terminal in an
                        // answer, and nothing an answer would have it send is of use any more.
                        if closing {
                            continue;
                        }
                        match (what, response.outcome) {
                            // A size report is a report, not an insistence. Another attachment may
                            // own the size, and the answer then says so; the terminal is shown that
                            // size rather than taking it, and the attachment carries on.
                            (Outstanding::Resize(_), outcome) => match outcome {
                                kr_protocol::envelope::Outcome::Ok(value) => {
                                    if let Ok(result) = value
                                        .to_typed::<kr_protocol::attachment::GeometryResult>()
                                    {
                                        geometry_epoch = result.geometry.epoch;
                                        owns_geometry =
                                            result.geometry.owner.as_ref() == Some(&attachment_id);
                                    }
                                }
                                // Somebody else owns the size now, or owns it at another epoch.
                                // The refusal carries neither, so this asks the only question whose
                                // answer does: a viewport report, which says who owns the size and
                                // at which epoch and changes nothing. Without it this terminal would
                                // go on sending owner-only resizes for the rest of the attachment
                                // and go on being refused them.
                                kr_protocol::envelope::Outcome::Error(error)
                                    if error.code == ErrorCode::GeometryNotOwner =>
                                {
                                    owns_geometry = false;
                                    let Ok(size) = terminal.size() else {
                                        continue;
                                    };
                                    if size.columns == 0 || size.rows == 0 {
                                        // A terminal with no size is one the host would refuse
                                        // anyway. Asking would swap one refusal for another.
                                        continue;
                                    }
                                    // It goes behind whatever viewport report is in flight, with
                                    // where the window is, whatever its size.
                                    window.owe_question(Dimensions::new(
                                        u64::from(size.columns),
                                        u64::from(size.rows),
                                    ));
                                }
                                kr_protocol::envelope::Outcome::Error(_) => {}
                            },
                            // A viewport report answers with the presentation it produced as well
                            // as the geometry, so it has its own result type and its own decoder.
                            // Where the window is comes from the screen the answer names, not from
                            // the answer: an answer can arrive before that screen, and after one
                            // drawn for an earlier window.
                            (Outstanding::Window, outcome) => {
                                let result = match outcome {
                                    kr_protocol::envelope::Outcome::Ok(value) => value
                                        .to_typed::<kr_protocol::attachment::AttachmentViewportResult>(
                                        )
                                        .ok(),
                                    kr_protocol::envelope::Outcome::Error(_) => None,
                                };
                                let Some(result) = result else {
                                    window.answered(answered, Answer::Refused);
                                    continue;
                                };
                                window.answered(
                                    answered,
                                    Answer::Accepted {
                                        window_revision: result.window_revision.get(),
                                        direct: result.presentation
                                            == kr_protocol::attachment::TerminalPresentationMode::Direct,
                                        landed: landed(result.position.0),
                                    },
                                );
                                // Who owns the size is read from every accepted answer, before the
                                // next report is chosen, so a terminal an answer names as the owner
                                // resizes as the owner. A report this terminal made because a resize
                                // was refused for a stale epoch answers with the epoch it should have
                                // quoted, and the size it asked for is still the size the person is
                                // looking at, so it asks again, once, with what the answer said.
                                let looking_at = terminal
                                    .size()
                                    .ok()
                                    .filter(|size| size.columns > 0 && size.rows > 0)
                                    .map(|size| {
                                        Dimensions::new(
                                            u64::from(size.columns),
                                            u64::from(size.rows),
                                        )
                                    });
                                let owner = ownership(
                                    &result.geometry,
                                    attachment_id,
                                    looking_at,
                                    &resizes_in_flight(&outstanding),
                                );
                                geometry_epoch = owner.epoch;
                                owns_geometry = owner.owns;
                                if let Some(dimensions) = owner.resize {
                                    window.took_size(dimensions);
                                    let request_id = kr_protocol::ids::RequestId::new(next_request);
                                    next_request += 1;
                                    let params = kr_protocol::attachment::TerminalResizeParams {
                                        attachment_id,
                                        dimensions,
                                        expected_geometry_epoch: geometry_epoch,
                                    };
                                    if !send_geometry(
                                        client,
                                        descriptor,
                                        request_id,
                                        Method::TerminalResize,
                                        &params,
                                    )
                                    .await
                                    {
                                        return AttachOutcome::Disconnected;
                                    }
                                    outstanding.insert(request_id, Outstanding::Resize(dimensions));
                                }
                            }
                            (
                                Outstanding::Input(sent),
                                kr_protocol::envelope::Outcome::Error(error),
                            ) => match error.code {
                                ErrorCode::LeaseLost => return AttachOutcome::LeaseLost,
                                // The session is closing, and refuses input from the moment it
                                // began. This terminal stops sending and waits for the closure.
                                ErrorCode::SessionClosed => {
                                    closing = true;
                                    window.close();
                                    undelivered = true;
                                }
                                code => {
                                    return AttachOutcome::DeliveryUncertain(shown!(
                                        "{} at input {}: {}",
                                        code,
                                        sent,
                                        Shown::protocol(&error)
                                    ));
                                }
                            },
                            (Outstanding::Input(_), kr_protocol::envelope::Outcome::Ok(_)) => {}
                            // The screen follows as ordinary output. A refusal because the session
                            // is closing is answered by the closure, which is still to come; any
                            // other means the session no longer has this attachment, which is the
                            // end of it.
                            (Outstanding::Resubscribe, outcome) => {
                                if let kr_protocol::envelope::Outcome::Error(error) = outcome {
                                    if error.code != ErrorCode::SessionClosed {
                                        return AttachOutcome::Disconnected;
                                    }
                                    closing = true;
                                    window.close();
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    // A connection that ends without the closure is a connection lost, even after
                    // the session said it was closing: a refusal says the session had begun to
                    // close, not how it ended, and a worker that went before saying so may have
                    // gone for any reason.
                    Err(_) => return AttachOutcome::Disconnected,
                }
            }
            () = wait_for_resize(&mut resized) => {
                if closing {
                    continue;
                }
                // The outer terminal changed size. The session is told, so the application is
                // redrawn at the size the person is actually looking at. The request goes out on
                // this loop's own connection and its answer comes back through the arm above:
                // calling out to a separate request-and-wait here would read this attachment's
                // output, resynchronisation and detach events as though they were the answer.
                let Ok(size) = terminal.size() else {
                    continue;
                };
                let dimensions = Dimensions::new(
                    u64::from(size.columns),
                    u64::from(size.rows),
                );
                // The owner moves the session's size at once, which is not a viewport report and
                // waits behind none. Anybody else reports the size it is looking at, which changes
                // which presentation it is served and nothing else: only the newest size waits,
                // behind whatever viewport report is in flight, and goes with where the window is.
                if !owns_geometry {
                    window.measured(dimensions);
                    continue;
                }
                window.took_size(dimensions);
                let request_id = kr_protocol::ids::RequestId::new(next_request);
                next_request += 1;
                let params = kr_protocol::attachment::TerminalResizeParams {
                    attachment_id,
                    dimensions,
                    expected_geometry_epoch: geometry_epoch,
                };
                if !send_geometry(
                    client,
                    descriptor,
                    request_id,
                    Method::TerminalResize,
                    &params,
                )
                .await
                {
                    return AttachOutcome::Disconnected;
                }
                outstanding.insert(request_id, Outstanding::Resize(dimensions));
            }
            bytes = input.recv() => {
                let Some(bytes) = bytes else {
                    // The terminal's own input ended. Whatever the classifier was part way
                    // through is the person's, and it goes before the attachment does, unless the
                    // session is closing and would refuse it.
                    let held = pointers.release();
                    if !held.is_empty() && !closing {
                        let Some(epoch) = epoch else {
                            return AttachOutcome::Detached;
                        };
                        let request_id = kr_protocol::ids::RequestId::new(next_request);
                        if !send_input(
                            client,
                            request_id,
                            session_id,
                            attachment_id,
                            epoch,
                            sequence,
                            held,
                        )
                        .await
                        {
                            return AttachOutcome::DeliveryUncertain(Shown::said(
                                "the connection ended while input was being sent",
                            ));
                        }
                    }
                    return AttachOutcome::Detached;
                };
                // The session is closing and refuses input. What is typed now goes nowhere, and
                // the line this attachment ends with says so.
                if closing {
                    undelivered = true;
                    continue;
                }
                // The scroll-back keys first, where they are this terminal's at all. They move
                // the window it is looking through and never reach the session, so an attachment
                // that may not type can still read what is above the live page.
                //
                // Two things decide whether they are this terminal's. A terminal being handed the
                // session's own bytes has those bytes, so its own scrollback holds the history and
                // the command takes none of its keys; a terminal drawing a projection was never
                // sent them, so there is nothing above its screen but the session's window. And a
                // full-screen application has its own use for these keys on a buffer that keeps no
                // history, so they are this terminal's only while the shell's buffer is showing.
                // Nothing inside a bracketed paste is a key or a report: pasted text reaches the
                // session byte for byte, whatever it happens to contain. The delimiters are read
                // whole, like everything else here, so a paste is open from the read that begins
                // with one to the read that ends with the other.
                let was_pasting = paste.is_open();
                let pasting = paste.observe(&bytes);
                // A read with a paste boundary inside it is forwarded whole: where the paste
                // begins and ends within such a read is not something a rule about whole reads can
                // say, and taking anything out of it could take it out of the paste.
                let outside_a_paste = !was_pasting && !pasting.open && !pasting.touched;
                // Every pointer report is this terminal's while it is showing history: a report
                // names a cell of the live screen, and the rows the person is looking at are not
                // on it. Section 8 answers that directly, that input outside the visible grid has
                // no application effect, so they are taken here and the wheel among them moves the
                // window. A report the read boundary cut in half waits for the rest of it rather
                // than reaching the application as half of one.
                //
                // What it is showing is the last screen it was given, not the one it is being
                // given: between a reset and the last page of the screen that follows it, this
                // terminal is still displaying what it drew before.
                let (bytes, wheel) = if showing_history && outside_a_paste {
                    let taken = pointers.take(&bytes);
                    pointer_deadline = taken
                        .holding
                        .then(|| {
                            pointer_deadline
                                .unwrap_or_else(|| tokio::time::Instant::now() + POINTER_DEADLINE)
                        });
                    let wheel = taken
                        .reports
                        .iter()
                        .fold(0_i64, |total, report| total.saturating_add(report.wheel));
                    (taken.input, wheel)
                } else {
                    // The window is on the live screen, so a report addresses the cell it names.
                    // Anything the classifier was holding goes first, in the order it was typed.
                    pointer_deadline = None;
                    let mut input = pointers.release();
                    input.extend_from_slice(&bytes);
                    (input, 0)
                };
                let mine =
                    outside_a_paste && display.holds_screen() && display.showing_history_buffer();
                // A key is the whole read and nothing of it goes on; a wheel report was taken out
                // of the read, and whatever else was in that read is still the session's.
                let key = mine.then(|| scroll_keys(&bytes)).flatten();
                if mine
                    && let Some(steps) = key.or((wheel != 0).then_some(wheel))
                    && let Ok(size) = terminal.size()
                    && size.columns > 0
                    && size.rows > 0
                {
                    // The rows the session is drawing here, which a terminal taller than the
                    // session has fewer of than it has lines.
                    let shown = display
                        .window_rows()
                        .unwrap_or_else(|| u64::from(size.rows));
                    // Where the window is is the session's to say and never a request's guess, so
                    // one report is in flight at a time and what the person presses meanwhile
                    // waits for it to settle, then goes from where it put the window.
                    window.pressed(
                        steps,
                        scroll_step(shown),
                        Dimensions::new(u64::from(size.columns), u64::from(size.rows)),
                    );
                    if key.is_some() {
                        // The key was this terminal's, so nothing of that read reaches the
                        // session, whether or not the window had anywhere to go.
                        continue;
                    }
                }
                if bytes.is_empty() {
                    continue;
                }
                // Typing goes to the application wherever the window is. A person who asked to
                // follow the live screen is taken back to it by the first key they press, because
                // what they type is answered there and not in what they were reading.
                if follow_live && showing_history {
                    window.return_to_live();
                }
                let Some(epoch) = epoch else {
                    // This terminal may not type. The bytes go nowhere, and the attachment goes on
                    // watching rather than ending on a refusal it already knows about.
                    continue;
                };
                let request_id = kr_protocol::ids::RequestId::new(next_request);
                next_request += 1;
                if !send_input(
                    client,
                    request_id,
                    session_id,
                    attachment_id,
                    epoch,
                    sequence,
                    bytes,
                )
                .await
                {
                    // The bytes were handed to a connection that has gone. Whether they arrived
                    // cannot be established from here, and the exit code says so.
                    return AttachOutcome::DeliveryUncertain(Shown::said(
                        "the connection ended while input was being sent",
                    ));
                }
                outstanding.insert(request_id, Outstanding::Input(sequence));
                sequence += 1;
            }
        }
    }
}

/// Asks for the session's screen again, on this loop's own connection.
///
/// A resynchronisation marker says the view is no longer continuous; this is how the view is made
/// continuous again. The screen arrives as ordinary output on the same stream.
async fn resubscribe(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    request_id: kr_protocol::ids::RequestId,
    attachment_id: kr_protocol::ids::AttachmentId,
) -> bool {
    let mut streams = kr_protocol::scalars::CanonicalSet::new();
    streams.insert(kr_protocol::recovery::EventStream::Output);
    let params = kr_protocol::recovery::EventsSubscribeParams {
        session_id: descriptor.session_id,
        attachment_id,
        streams,
        from_cursor: kr_protocol::scalars::Nullable::null(),
    };
    let Ok(params) = kr_protocol::envelope::ParamsValue::from_typed(&params) else {
        return false;
    };
    let request = kr_protocol::envelope::Request {
        request_id,
        method: Method::EventsSubscribe.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        params,
    };
    client
        .writer()
        .write_message(&ControlFrame::Request(request))
        .await
        .is_ok()
}

/// Writes one batch of terminal input on this loop's own connection.
///
/// Returns whether it reached the socket. Its answer comes back through the loop, like every other
/// answer on this connection.
async fn send_input(
    client: &mut LocalClient,
    request_id: kr_protocol::ids::RequestId,
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    bytes: Vec<u8>,
) -> bool {
    let params = kr_protocol::input::InputWriteParams {
        session_id,
        attachment_id,
        epoch,
        sequence: kr_protocol::ids::InputSequence::new(sequence),
        bytes: kr_protocol::scalars::Bytes::new(bytes),
    };
    let Ok(params) = kr_protocol::envelope::ParamsValue::from_typed(&params) else {
        return false;
    };
    client
        .writer()
        .write_message(&ControlFrame::Request(kr_protocol::envelope::Request {
            request_id,
            method: Method::InputWrite.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            params,
        }))
        .await
        .is_ok()
}

/// Writes one size report on this loop's own connection.
///
/// Returns whether it reached the socket. The answer comes back through the loop, like every other
/// answer on this connection.
async fn send_geometry<T: serde::Serialize + ?Sized>(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    request_id: kr_protocol::ids::RequestId,
    method: Method,
    params: &T,
) -> bool {
    let Ok(params) = kr_protocol::envelope::ParamsValue::from_typed(params) else {
        return false;
    };
    let mutation = kr_protocol::envelope::MutationRequest {
        request_id,
        method: method.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
        grant_id: kr_protocol::scalars::Nullable::null(),
        target: crate::attach::target(descriptor),
        expected: kr_protocol::envelope::ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(
            kr_protocol::limits::DEFAULT_MUTATION_TTL.get(),
        ),
        params,
    };
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .is_ok()
}

/// How this platform reports that the terminal changed size.
///
/// Unix delivers a signal. Windows delivers a console input record instead, which arrives on the
/// input stream this loop is already reading, so there is nothing separate to wait on there.
#[cfg(unix)]
pub type WindowChanges = tokio::signal::unix::Signal;

/// How this platform reports that the terminal changed size.
#[cfg(not(unix))]
pub type WindowChanges = std::convert::Infallible;

/// Returns the stream of window-size changes, where the platform has one.
#[cfg(unix)]
fn window_changes() -> Option<WindowChanges> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
}

/// Returns the stream of window-size changes, where the platform has one.
#[cfg(not(unix))]
const fn window_changes() -> Option<WindowChanges> {
    None
}

/// Waits for the next window-size change, or for ever when the platform reports none.
#[cfg(unix)]
async fn wait_for_resize(resized: &mut Option<&mut WindowChanges>) {
    match resized {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending().await,
    }
}

/// Waits for the next window-size change, or for ever when the platform reports none.
#[cfg(not(unix))]
async fn wait_for_resize(_resized: &mut Option<&mut WindowChanges>) {
    std::future::pending().await
}

#[cfg(test)]
mod tests {
    use super::{
        Answer, AttachOutcome, Heard, Outstanding, Ownership, SCROLL_BACK_KEY, SCROLL_FORWARD_KEY,
        Sending, Subscriptions, WindowReports, landed, ownership, resizes_in_flight, scroll_keys,
        scroll_step, scrolled,
    };
    use kr_client::shown::Shown;
    use kr_protocol::attachment::ViewportPosition;
    use kr_protocol::scalars::{Nullable, U64};
    use kr_protocol::session::{ClosureReason, ClosureRecord};

    fn closure(reason: ClosureReason, code: Option<u64>, signal: Option<&str>) -> ClosureRecord {
        ClosureRecord {
            session_id: kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes(
                [7; 16],
            )),
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            reason,
            root_exit_code: Nullable(code.map(U64::new)),
            root_signal: Nullable(signal.map(ToOwned::to_owned)),
            terminated: Vec::new(),
            surviving: Vec::new(),
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        }
    }

    /// The exit status an outcome ends the command with.
    fn status(outcome: &AttachOutcome) -> u8 {
        outcome
            .clone()
            .into_error()
            .map_or(0, |error| error.exit_code())
    }

    /// KR-REQ-07.52: an attachment ends with the status its session's closure implies, and says
    /// how the session closed in one line.
    #[test]
    fn a_closure_ends_the_attachment_with_the_status_it_implies() {
        for (record, expected, said) in [
            (
                closure(ClosureReason::RootExit, Some(0), None),
                0,
                "the session closed: its shell exited with status 0",
            ),
            (
                closure(ClosureReason::RootExit, Some(7), None),
                1,
                "the session closed: its shell exited with status 7",
            ),
            // The shell's own status is not passed through: 3 is what a lost connection ends
            // with, and a script has to be able to tell the two apart.
            (
                closure(ClosureReason::RootExit, Some(3), None),
                1,
                "the session closed: its shell exited with status 3",
            ),
            (
                closure(ClosureReason::RootSignal, None, Some("Killed: 9")),
                1,
                "the session closed: a signal ended its shell (Killed: 9)",
            ),
            // A close somebody asked for is how the person meant the session to end, whatever
            // the stopped shell's own status was.
            (
                closure(ClosureReason::CloseRequested, None, Some("Terminated")),
                0,
                "the session closed: it was closed on request",
            ),
            (
                closure(ClosureReason::DesktopLost, None, Some("Hangup")),
                1,
                "the session closed: the desktop login it ran in ended",
            ),
            (
                closure(ClosureReason::RootLaunchFailed, None, None),
                1,
                "the session closed: its shell never became ready",
            ),
        ] {
            let outcome = AttachOutcome::Closed {
                record: Box::new(record.clone()),
                undelivered: false,
            };
            assert_eq!(status(&outcome), expected, "{record:?}");
            assert_eq!(outcome.is_failure(), expected != 0, "{record:?}");
            assert_eq!(outcome.detail().as_str(), said);
            assert_eq!(outcome.closure(), Some(&record));
        }
    }

    /// An attachment that typed while its session was closing is told the typing went nowhere.
    #[test]
    fn what_was_typed_while_the_session_closed_is_said_to_be_undelivered() {
        let outcome = AttachOutcome::Closed {
            record: Box::new(closure(ClosureReason::CloseRequested, None, None)),
            undelivered: true,
        };
        assert_eq!(status(&outcome), 0);
        assert_eq!(
            outcome.detail().as_str(),
            "the session closed: it was closed on request; what was typed while it was closing \
             was not delivered"
        );
    }

    /// A closure this build cannot read ends the attachment as a failure: the session ended, and
    /// how it ended is not known.
    #[test]
    fn a_closure_that_cannot_be_read_is_not_reported_as_a_success() {
        let outcome = AttachOutcome::ClosureUnreadable {
            detail: Shown::said("an unknown field"),
            undelivered: false,
        };
        assert_eq!(status(&outcome), 1);
        assert!(outcome.is_failure());
        assert_eq!(
            outcome.detail().as_str(),
            "the session closed, and how it closed could not be read (an unknown field)"
        );
        assert_eq!(outcome.closure(), None);
    }

    /// A closure that cannot be read is reported by the rule it broke, never by what it held.
    #[test]
    fn a_closure_that_cannot_be_read_does_not_repeat_what_it_held() {
        use crate::shown::marker::{MARKER, assert_unmarked, failure_renderings};

        let planted = |key: &str| {
            kr_protocol::envelope::ParamsValue::from_typed(&std::collections::BTreeMap::from([(
                key, 1_u64,
            )]))
            .expect("a map")
        };
        let payload = planted(MARKER);
        // The negative control: the decoder's failure keeps the key it refused in a field of its
        // own, which a rendering that copied the failure's fields would quote.
        let unread = payload
            .to_typed::<ClosureRecord>()
            .expect_err("not a closure");
        assert!(
            matches!(&unread, kr_cbor::CborError::UnknownField { field, .. } if field == MARKER),
            "{unread}"
        );

        let outcome = super::closed(&payload, false);
        assert!(matches!(outcome, AttachOutcome::ClosureUnreadable { .. }));
        assert_eq!(status(&outcome), 1);
        // The neutral control: another key is reported in the same words, which name the rule the
        // record broke.
        let neutral = super::closed(&planted("neutral-value"), false);
        assert_eq!(outcome.detail(), neutral.detail());
        assert!(
            neutral.detail().as_str().contains(unread.rule()),
            "{}",
            neutral.detail()
        );
        assert_unmarked(
            "an unreadable closure",
            &[outcome.detail().into_string(), format!("{outcome:?}")],
        );
        assert_unmarked(
            "an unreadable closure, as the command reports it",
            &failure_renderings(outcome.into_error().expect("a failure")),
        );

        let record = closure(ClosureReason::RootExit, Some(0), None);
        let read = super::closed(
            &kr_protocol::envelope::ParamsValue::from_typed(&record).expect("a closure"),
            false,
        );
        assert_eq!(read.closure(), Some(&record));
    }

    /// A signal name is said as the host recorded it, unless it holds what no platform's signal
    /// name holds.
    #[test]
    fn a_signal_name_with_control_characters_is_not_repeated() {
        let spoken = closure(ClosureReason::RootSignal, None, Some("Killed: 9"));
        assert_eq!(
            super::how_it_closed(&spoken).as_str(),
            "a signal ended its shell (Killed: 9)"
        );
        let hostile = closure(
            ClosureReason::RootSignal,
            None,
            Some("\u{1b}]0;title\u{7}Killed"),
        );
        assert_eq!(
            super::how_it_closed(&hostile).as_str(),
            "a signal ended its shell ([a signal name this build does not list])"
        );
    }

    /// A connection that ends without a closure still ends the command as a lost connection.
    #[test]
    fn a_connection_lost_without_a_closure_still_ends_with_status_3() {
        let outcome = AttachOutcome::Disconnected;
        assert_eq!(status(&outcome), 3);
        assert_eq!(
            outcome.detail().as_str(),
            "the connection to the session ended"
        );
        assert_eq!(outcome.closure(), None);
    }

    /// Section 8 line 459: a scroll-back key is this terminal's own, and never the session's.
    #[test]
    fn a_read_that_is_one_scroll_key_moves_the_window() {
        assert_eq!(scroll_keys(SCROLL_BACK_KEY), Some(1));
        assert_eq!(scroll_keys(SCROLL_FORWARD_KEY), Some(-1));
    }

    /// Holding the key repeats it, and a read of several is that many pages.
    #[test]
    fn a_held_key_moves_the_window_once_per_repeat() {
        let mut held = SCROLL_BACK_KEY.to_vec();
        held.extend_from_slice(SCROLL_BACK_KEY);
        held.extend_from_slice(SCROLL_BACK_KEY);
        assert_eq!(scroll_keys(&held), Some(3));
        let mut down = SCROLL_FORWARD_KEY.to_vec();
        down.extend_from_slice(SCROLL_FORWARD_KEY);
        assert_eq!(scroll_keys(&down), Some(-2));
    }

    /// Everything else is the session's, whole and unchanged.
    #[test]
    fn everything_else_the_person_typed_is_theirs() {
        assert_eq!(scroll_keys(b""), None);
        assert_eq!(scroll_keys(b"ls -l\r"), None, "ordinary typing");
        assert_eq!(scroll_keys(b"\x1b"), None, "a lone escape is never held");
        assert_eq!(scroll_keys(b"\x1b[5~"), None, "an unshifted Page Up");
        assert_eq!(scroll_keys(b"\x1b[5;"), None, "half of a key is not a key");
        let mut mixed = SCROLL_BACK_KEY.to_vec();
        mixed.extend_from_slice(b"x");
        assert_eq!(
            scroll_keys(&mixed),
            None,
            "a key among other bytes is forwarded like every other byte"
        );
        let mut both = SCROLL_BACK_KEY.to_vec();
        both.extend_from_slice(SCROLL_FORWARD_KEY);
        assert_eq!(
            scroll_keys(&both),
            None,
            "and a read that goes both ways is nobody's gesture"
        );
    }

    /// Which is what keeps a paste a paste: nothing inside one is ever read as a key.
    #[test]
    fn a_pasted_key_sequence_is_pasted_text() {
        let mut pasted = b"\x1b[200~before".to_vec();
        pasted.extend_from_slice(SCROLL_BACK_KEY);
        pasted.extend_from_slice(b"after\x1b[201~");
        assert_eq!(
            scroll_keys(&pasted),
            None,
            "the paste reaches the session exactly as it arrived"
        );
    }

    #[test]
    fn a_step_is_a_window_less_the_line_that_joins_the_two_pages() {
        assert_eq!(scroll_step(24), 23);
        assert_eq!(scroll_step(2), 1);
        assert_eq!(scroll_step(1), 1, "a window of one row still moves");
        assert_eq!(scroll_step(0), 1);
    }

    #[test]
    fn a_window_on_the_live_screen_asks_by_distance_and_then_by_row() {
        let first = scrolled(None, 1, 23)
            .expect("a window can go back from live")
            .expect("and it asks for somewhere");
        assert!(
            matches!(first, ViewportPosition::Above(rows) if rows.get() == 23),
            "a client with no row identifier above its page asks by distance: {first:?}"
        );
        let next = scrolled(Some(500), 1, 23)
            .expect("and keeps going back")
            .expect("somewhere");
        assert!(matches!(next, ViewportPosition::Row(row) if row.get() == 477));
        let forward = scrolled(Some(477), -1, 23)
            .expect("and comes back down")
            .expect("somewhere");
        assert!(matches!(forward, ViewportPosition::Row(row) if row.get() == 500));
        assert!(
            scrolled(None, -1, 23).is_none(),
            "the live screen is as far forward as a window goes"
        );
        let held = scrolled(Some(500), 3, 23)
            .expect("three pages back is three pages")
            .expect("somewhere");
        assert!(
            matches!(held, ViewportPosition::Row(row) if row.get() == 500 - 69),
            "three pages back from row 500, not one: {held:?}"
        );
        let floor = scrolled(Some(10), 1, 23)
            .expect("a window near the beginning")
            .expect("somewhere");
        assert!(
            matches!(floor, ViewportPosition::Row(row) if row.get() == 0),
            "which asks for the first row rather than for one below it: {floor:?}"
        );
    }

    /// A read with a paste boundary inside it is forwarded whole, reports and all.
    #[test]
    fn a_read_that_carries_a_paste_boundary_is_the_sessions() {
        use super::PasteWatch;

        let mut paste = PasteWatch::default();
        let opened = paste.observe(b"\x1b[200~ab\x1b[<0;10;4Mcd");
        assert!(opened.open, "the paste is open after it");
        assert!(
            opened.touched,
            "and the read carried the boundary, so nothing may be taken out of it"
        );
        let closed = paste.observe(b"\x1b[201~");
        assert!(!closed.open);
        assert!(closed.touched);
        let after = paste.observe(b"\x1b[<0;10;4M");
        assert!(!after.open);
        assert!(
            !after.touched,
            "and a read after the paste carries no boundary, so its report is this terminal's"
        );
    }

    /// Section 8: input outside the visible grid has no application effect.
    #[test]
    fn every_pointer_report_is_taken_while_the_window_shows_history() {
        use super::PointerReports;

        let mut pointers = PointerReports::default();
        let taken = pointers.take(b"\x1b[<0;10;4M");
        assert_eq!(taken.reports.len(), 1, "a press");
        assert!(taken.input.is_empty(), "and nothing of it reaches anybody");
        let taken = pointers.take(b"\x1b[<0;10;4m");
        assert_eq!(taken.reports.len(), 1, "a release");
        let taken = pointers.take(b"\x1b[M !!");
        assert_eq!(taken.reports.len(), 1, "and the legacy form");
        let taken = pointers.take(b"\x1b[<0;10;4M\x1b[<0;10;4m");
        assert_eq!(taken.reports.len(), 2, "a press and its release together");
    }

    /// A report among other bytes is the report and the rest, each to where it belongs.
    #[test]
    fn a_report_among_other_bytes_is_split_from_them() {
        use super::PointerReports;

        let mut pointers = PointerReports::default();
        let taken = pointers.take(b"ab\x1b[<0;10;4Mcd");
        assert_eq!(taken.reports.len(), 1, "the report is taken");
        assert_eq!(taken.input, b"abcd", "and the typing around it is not");
        assert!(!taken.holding);
    }

    /// And one the read boundary cut in half waits for the rest of itself.
    #[test]
    fn a_report_split_across_reads_is_still_one_report() {
        use super::PointerReports;

        let mut pointers = PointerReports::default();
        let first = pointers.take(b"ls\x1b[<0;10");
        assert_eq!(first.input, b"ls", "what was whole goes on");
        assert!(first.reports.is_empty());
        assert!(first.holding, "and the beginning of the report waits");
        let second = pointers.take(b";4M");
        assert_eq!(second.reports.len(), 1, "the two halves are one report");
        assert!(second.input.is_empty());
        assert!(!second.holding);
    }

    /// Something that starts like a report and is not one goes to the application.
    #[test]
    fn what_is_not_a_report_is_the_applications() {
        use super::PointerReports;

        let mut pointers = PointerReports::default();
        let taken = pointers.take(b"ls -l\r");
        assert!(taken.reports.is_empty());
        assert_eq!(taken.input, b"ls -l\r");
        let taken = pointers.take(b"\x1b[<not a report");
        assert!(taken.reports.is_empty());
        assert_eq!(
            taken.input, b"\x1b[<not a report",
            "a sequence that cannot finish as a report is forwarded whole"
        );
        let held = pointers.take(b"\x1b[<0;1");
        assert!(held.holding, "and one that still could waits");
        assert_eq!(
            pointers.release(),
            b"\x1b[<0;1",
            "until nothing comes, and then it is the person's"
        );
    }

    /// The wheel moves the window while the person is reading their history.
    #[test]
    fn the_wheel_moves_the_window() {
        use super::PointerReports;

        let mut pointers = PointerReports::default();
        let back = pointers.take(b"\x1b[<64;10;4M");
        assert_eq!(back.reports.len(), 1);
        assert_eq!(back.reports[0].wheel, 1, "the wheel turns back");
        let forward = pointers.take(b"\x1b[<65;10;4M");
        assert_eq!(forward.reports[0].wheel, -1, "and towards the live screen");
        let click = pointers.take(b"\x1b[<0;10;4M");
        assert_eq!(click.reports[0].wheel, 0, "a click turns nothing");
    }

    /// The step is the window this terminal is shown, not the lines it happens to have.
    #[test]
    fn a_step_measures_the_window_the_session_draws() {
        assert_eq!(
            scroll_step(40),
            39,
            "a terminal taller than the session moves by the session's rows"
        );
    }

    /// A paste is open from the delimiter that opens it to the one that closes it.
    #[test]
    fn a_delimiter_anywhere_in_a_read_decides_the_paste() {
        use super::PasteWatch;

        let mut paste = PasteWatch::default();
        assert!(
            !paste.observe(b"ls -l").open,
            "an ordinary read opens nothing"
        );
        assert!(paste.observe(b"x\x1b[200~").open, "a paste opening");
        assert!(paste.observe(b"text").open, "and it stays open");
        assert!(!paste.observe(b"\x1b[201~x").open, "until one closes it");
        assert!(
            !paste.observe(b"\x1b[200~text\x1b[201~").open,
            "a whole paste in one read is closed at the end of it"
        );
        assert!(
            paste.observe(b"\x1b[201~\x1b[200~more").open,
            "and one paste ending while another begins is open"
        );
    }

    /// A delimiter a read boundary cut in half is still that delimiter.
    #[test]
    fn a_delimiter_split_across_reads_is_still_a_delimiter() {
        use super::PasteWatch;

        let mut paste = PasteWatch::default();
        assert!(!paste.observe(b"\x1b[20").open, "half of a start delimiter");
        assert!(
            paste.observe(b"0~").open,
            "and the rest of it opens the paste"
        );
        assert!(
            paste.observe(super::SCROLL_BACK_KEY).open,
            "a key inside it is pasted text and the paste stays open"
        );
        assert!(
            paste.observe(b"\x1b[201").open,
            "half of an end delimiter closes nothing yet"
        );
        assert!(
            !paste.observe(b"~").open,
            "and the rest of it closes the paste"
        );
        assert!(
            !paste.observe(super::SCROLL_BACK_KEY).open,
            "so the key after it is a key again"
        );
    }

    /// Something that starts like a delimiter and is not one leaves the paste alone.
    #[test]
    fn a_sequence_that_is_not_a_delimiter_opens_nothing() {
        use super::PasteWatch;

        let mut paste = PasteWatch::default();
        assert!(
            !paste.observe(b"\x1b[2").open,
            "the beginning of many things"
        );
        assert!(!paste.observe(b"J").open, "which turned out to be an erase");
        assert!(
            !paste.observe(b"\x1b[200").open,
            "and a start delimiter that never finishes"
        );
        assert!(!paste.observe(b"x").open, "opens no paste either");
    }

    #[test]
    fn where_the_window_landed_is_read_from_the_answer() {
        assert_eq!(landed(None), None, "no position at all is the live screen");
        assert_eq!(
            landed(Some(ViewportPosition::Row(kr_protocol::scalars::U64::new(
                42
            )))),
            Some(42)
        );
    }

    fn size(columns: u64, rows: u64) -> kr_protocol::session::Dimensions {
        kr_protocol::session::Dimensions::new(columns, rows)
    }

    fn request(id: u64) -> kr_protocol::ids::RequestId {
        kr_protocol::ids::RequestId::new(id)
    }

    fn accepted(window_revision: u64, landed: Option<u64>) -> Answer {
        Answer::Accepted {
            window_revision,
            direct: false,
            landed,
        }
    }

    fn row(row: u64) -> Option<ViewportPosition> {
        Some(ViewportPosition::Row(U64::new(row)))
    }

    fn above(rows: u64) -> Option<ViewportPosition> {
        Some(ViewportPosition::Above(U64::new(rows)))
    }

    /// Sends what the window owes next, as the command's loop does, and says what it was.
    fn send(window: &mut WindowReports, id: u64) -> Option<Sending> {
        let sending = window.next()?;
        window.sent(request(id));
        Some(sending)
    }

    /// A terminal that attached on the live screen and moved one page back, to row 477, whose
    /// report was answered with revision 1 and whose screen arrived.
    fn parked_at_477() -> WindowReports {
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.pressed(1, 23, size(80, 24));
        let first = send(&mut window, 1).expect("the first page back goes at once");
        assert_eq!(first.position, above(23));
        window.answered(request(1), accepted(1, Some(477)));
        window.installed(1, Some(477));
        assert_eq!(window.record(), Some(Some(477)));
        window
    }

    /// An earlier report's screen never moves the record of where the window is.
    ///
    /// The host queues a repaint of the window where it was, then the screen for the next move,
    /// and the move's answer can overtake the repaint. The repaint names the revision before the
    /// move's, so it is not the move's screen, and the press made meanwhile goes from where the
    /// move's answer and its own screen put the window.
    #[test]
    fn an_earlier_reports_screen_never_moves_the_record() {
        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        let second = send(&mut window, 2).expect("the next page back");
        assert_eq!(second.position, row(454));
        window.answered(request(2), accepted(2, Some(454)));
        // The repaint of row 477, queued before the report and read after its answer.
        window.installed(1, Some(477));
        window.pressed(1, 23, size(80, 24));
        assert_eq!(
            window.next(),
            None,
            "the press waits for the screen the answer names, not the repaint before it"
        );
        window.installed(2, Some(454));
        let third = send(&mut window, 3).expect("the press goes once the report has settled");
        assert_eq!(
            third.position,
            row(431),
            "measured from where the answer and its screen put the window"
        );
    }

    /// Presses queued behind a report go from where its answer and named screen put the window,
    /// and when the next subscription's first screen names a change of the host's own, from there.
    #[test]
    fn queued_presses_go_from_where_the_answer_and_its_screen_put_the_window() {
        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        let second = send(&mut window, 2).expect("the next page back");
        assert_eq!(second.position, row(454));
        window.pressed(1, 23, size(80, 24));
        window.answered(request(2), accepted(2, Some(454)));
        assert_eq!(
            window.next(),
            None,
            "an answer alone does not settle a move: its screen has not arrived"
        );
        // This terminal is told to resynchronise before the move's screen reaches it, and the
        // host brings its window back to the live screen meanwhile.
        window.recovering();
        assert_eq!(window.next(), None, "nothing goes while no screen is held");
        window.installed(3, None);
        let third = send(&mut window, 3).expect("the queued press goes");
        assert_eq!(
            third.position,
            above(23),
            "from the live screen, where the host's own change put the window"
        );
    }

    /// A screen that arrives before its report's answer is the one the answer then names.
    #[test]
    fn a_screen_before_its_answer_is_found_by_the_answer() {
        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        send(&mut window, 2).expect("the next page back");
        window.installed(2, Some(454));
        window.pressed(1, 23, size(80, 24));
        assert_eq!(window.next(), None, "the report is not answered yet");
        window.answered(request(2), accepted(2, Some(454)));
        let third = send(&mut window, 3).expect("settled by the screen already held");
        assert_eq!(third.position, row(431));
    }

    /// At the oldest row a page back is spent where the host holds the window, and the reversal
    /// queued behind it still goes, from the oldest row.
    #[test]
    fn a_reversal_at_the_oldest_row_goes_from_the_oldest_row() {
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.pressed(1, 23, size(80, 24));
        send(&mut window, 1).expect("back from the live screen");
        window.answered(request(1), accepted(1, Some(100)));
        window.installed(1, Some(100));
        // Row 100 is the oldest there is. Back once more, back again and forward, quickly.
        window.pressed(1, 23, size(80, 24));
        assert_eq!(send(&mut window, 2).map(|s| s.position), Some(row(77)));
        window.pressed(1, 23, size(80, 24));
        window.pressed(-1, 23, size(80, 24));
        // The host holds the window at row 100 and sends nothing for it.
        window.answered(request(2), accepted(1, Some(100)));
        assert_eq!(
            send(&mut window, 3).map(|s| s.position),
            Some(row(77)),
            "the page back queued behind it is asked for from row 100"
        );
        window.answered(request(3), accepted(1, Some(100)));
        assert_eq!(
            send(&mut window, 4).map(|s| s.position),
            Some(row(123)),
            "and the reversal is not lost to it"
        );
    }

    /// On the live screen a page forward is spent inside the same choice, and the reversal
    /// behind it goes without waiting for anything else to happen.
    #[test]
    fn a_reversal_at_the_live_screen_goes_at_once() {
        let mut window = parked_at_477();
        window.pressed(-1, 23, size(80, 24));
        assert_eq!(send(&mut window, 2).map(|s| s.position), Some(row(500)));
        window.pressed(-1, 23, size(80, 24));
        window.pressed(1, 23, size(80, 24));
        // Row 500 is the live screen's first row: the host answers with the live screen.
        window.answered(request(2), accepted(2, None));
        window.installed(2, None);
        assert_eq!(
            send(&mut window, 3).map(|s| s.position),
            Some(above(23)),
            "the page forward had nowhere to go, and the page back goes from the live screen"
        );
    }

    /// A refused move does not take a newer size with it: the size waits for the move and goes
    /// next, with the place the window is really at.
    #[test]
    fn a_refused_move_while_a_newer_size_waits_keeps_the_size() {
        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        send(&mut window, 2).expect("the next page back");
        window.measured(size(100, 30));
        assert_eq!(window.next(), None, "the size waits for the move");
        window.answered(request(2), Answer::Refused);
        let next = send(&mut window, 3).expect("the size goes after the refusal");
        assert_eq!(
            (next.dimensions, next.position),
            (size(100, 30), row(477)),
            "with the newest size and where the window is, not where the refused move asked"
        );
        window.pressed(1, 23, size(100, 30));
        window.answered(request(3), accepted(2, Some(477)));
        window.recovering();
        window.installed(2, Some(477));
        assert_eq!(
            send(&mut window, 4).map(|s| s.position),
            Some(row(454)),
            "and a press made meanwhile goes from the next complete screen"
        );
    }

    /// An answer that hands this terminal the stream settles its report at the live screen's
    /// origin, and so does a subscription that begins with the stream; the presses waiting are
    /// the session's keys now, and go nowhere.
    #[test]
    fn the_stream_settles_a_report_at_the_live_origin_and_drops_the_presses() {
        let mut window = parked_at_477();
        window.pressed(-1, 23, size(80, 24));
        send(&mut window, 2).expect("forward, onto the live screen");
        window.pressed(1, 23, size(80, 24));
        window.answered(
            request(2),
            Answer::Accepted {
                window_revision: 2,
                direct: true,
                landed: None,
            },
        );
        assert_eq!(window.record(), Some(None), "the live screen's origin");
        // A screen of the window before the report, queued ahead of the marker that a change of
        // presentation brings, can still arrive after the answer. It names an earlier revision
        // than the answer, and does not move the record back into the history.
        window.installed(1, Some(477));
        assert_eq!(
            window.record(),
            Some(None),
            "still the live screen's origin"
        );
        assert_eq!(window.next(), None, "the press waiting is dropped");

        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        send(&mut window, 2).expect("the next page back");
        window.pressed(1, 23, size(80, 24));
        window.recovering();
        window.streamed();
        assert_eq!(
            window.record(),
            Some(None),
            "the stream is served at the origin"
        );
        assert_eq!(window.next(), None, "the press waiting is dropped");
        window.pressed(1, 23, size(80, 24));
        assert_eq!(
            send(&mut window, 3).map(|s| s.position),
            Some(above(23)),
            "and the report that was in flight no longer holds anything back"
        );
    }

    /// A size measured while no screen is held goes once the next subscription gives one, or
    /// once it begins with the stream, even with nothing else to answer.
    #[test]
    fn a_size_measured_during_a_recovery_goes_once_the_record_returns() {
        for streamed in [false, true] {
            let mut window = WindowReports::new(size(80, 24));
            window.installed(0, None);
            window.recovering();
            window.measured(size(100, 30));
            assert_eq!(window.next(), None, "no screen, so no place to report");
            if streamed {
                window.streamed();
            } else {
                window.installed(1, None);
            }
            let next = send(&mut window, 1).expect("the size goes");
            assert_eq!((next.dimensions, next.position), (size(100, 30), None));
        }
    }

    /// A report refused while a recovery is under way sends nothing until the recovery gives a
    /// record.
    #[test]
    fn a_refusal_during_a_recovery_waits_for_the_record() {
        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        send(&mut window, 2).expect("the next page back");
        window.recovering();
        window.measured(size(100, 30));
        window.answered(request(2), Answer::Refused);
        assert_eq!(window.next(), None, "no record yet");
        window.installed(1, Some(477));
        let next = send(&mut window, 3).expect("the size goes");
        assert_eq!((next.dimensions, next.position), (size(100, 30), row(477)));
    }

    /// The report a refused resize leaves this terminal owing goes whatever its size, even the
    /// size last sent: what it asks for is who owns the size and at which epoch.
    #[test]
    fn the_question_a_refused_resize_owes_goes_at_the_size_last_sent() {
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.owe_question(size(80, 24));
        let next = send(&mut window, 1).expect("the question goes");
        assert_eq!((next.dimensions, next.position), (size(80, 24), None));
        window.answered(request(1), accepted(0, None));
        assert_eq!(window.next(), None, "and only once");

        // A return asked for while a question is owed goes first, and the question after it keeps
        // the window where the return put it; a newer size measured meanwhile is not lost.
        let mut window = parked_at_477();
        window.owe_question(size(80, 24));
        window.return_to_live();
        window.measured(size(90, 30));
        let first = send(&mut window, 2).expect("the return");
        assert_eq!(
            (first.dimensions, first.position),
            (size(90, 30), None),
            "the return goes first, with the newest size"
        );
        window.answered(request(2), accepted(2, None));
        window.installed(2, None);
        let second = send(&mut window, 3).expect("then the question");
        assert_eq!(
            (second.dimensions, second.position),
            (size(90, 30), None),
            "from the live screen, where the return put the window, at the size already sent"
        );
        window.answered(request(3), accepted(2, None));
        assert_eq!(
            window.next(),
            None,
            "the newest size needs no report of its own"
        );
    }

    /// Every accepted answer says who owns the session's size, whatever its report was for, and an
    /// owner looking at another size than the session's owes the resize.
    #[test]
    fn every_accepted_answer_says_who_owns_the_size() {
        let this =
            kr_protocol::ids::AttachmentId::new(kr_protocol::scalars::Uuid::from_bytes([4; 16]));
        let other =
            kr_protocol::ids::AttachmentId::new(kr_protocol::scalars::Uuid::from_bytes([9; 16]));
        let geometry = |owner, columns, rows| kr_protocol::attachment::GeometryState {
            owner: Nullable::some(owner),
            epoch: kr_protocol::ids::GeometryEpoch::new(7),
            dimensions: size(columns, rows),
        };
        // A return that carried this terminal's newer size, answered after the owner left and this
        // terminal inherited the size at the one it reported before.
        assert_eq!(
            ownership(&geometry(this, 80, 24), this, Some(size(100, 30)), &[]),
            Ownership {
                epoch: kr_protocol::ids::GeometryEpoch::new(7),
                owns: true,
                resize: Some(size(100, 30)),
            },
            "the owner resizes the session to what it is looking at"
        );
        assert_eq!(
            ownership(&geometry(this, 100, 30), this, Some(size(100, 30)), &[]).resize,
            None,
            "an owner already at its size owes nothing"
        );
        assert_eq!(
            ownership(&geometry(other, 80, 24), this, Some(size(100, 30)), &[]),
            Ownership {
                epoch: kr_protocol::ids::GeometryEpoch::new(7),
                owns: false,
                resize: None,
            },
            "a terminal that does not own the size resizes nothing"
        );
        assert_eq!(
            ownership(&geometry(this, 80, 24), this, None, &[]).resize,
            None,
            "a terminal with no size of its own asks for none"
        );
    }

    /// An answer written before the owner's resize was applied still carries the session's old
    /// size. The resize in flight already asks for the size this terminal is looking at, so the
    /// answer owes no second one: it would quote the epoch the one in flight moves on from, and be
    /// refused.
    #[test]
    fn an_answer_owes_no_resize_the_owner_has_in_flight() {
        let this =
            kr_protocol::ids::AttachmentId::new(kr_protocol::scalars::Uuid::from_bytes([4; 16]));
        let before_the_resize = kr_protocol::attachment::GeometryState {
            owner: Nullable::some(this),
            epoch: kr_protocol::ids::GeometryEpoch::new(7),
            dimensions: size(80, 24),
        };
        let mut outstanding = std::collections::BTreeMap::new();
        outstanding.insert(
            kr_protocol::ids::RequestId::new(12),
            Outstanding::Resize(size(100, 30)),
        );
        outstanding.insert(kr_protocol::ids::RequestId::new(11), Outstanding::Window);
        assert_eq!(resizes_in_flight(&outstanding), vec![size(100, 30)]);
        assert_eq!(
            ownership(
                &before_the_resize,
                this,
                Some(size(100, 30)),
                &resizes_in_flight(&outstanding)
            ),
            Ownership {
                epoch: kr_protocol::ids::GeometryEpoch::new(7),
                owns: true,
                resize: None,
            },
            "the resize in flight is the one this terminal owes"
        );
    }

    /// A size no resize in flight asks for still goes at once, as the owner's.
    #[test]
    fn a_size_no_resize_in_flight_asks_for_still_goes() {
        let this =
            kr_protocol::ids::AttachmentId::new(kr_protocol::scalars::Uuid::from_bytes([4; 16]));
        let before_the_resize = kr_protocol::attachment::GeometryState {
            owner: Nullable::some(this),
            epoch: kr_protocol::ids::GeometryEpoch::new(7),
            dimensions: size(80, 24),
        };
        assert_eq!(
            ownership(
                &before_the_resize,
                this,
                Some(size(120, 40)),
                &[size(100, 30)]
            )
            .resize,
            Some(size(120, 40)),
            "a newer size than the one in flight"
        );
    }

    /// Nothing is sent while a new subscription is being asked for, not even after a direct answer
    /// arrives meanwhile, so that subscription's first delivery settles only a report sent before
    /// it was asked for.
    #[test]
    fn nothing_goes_until_the_next_subscription_begins() {
        let mut window = parked_at_477();
        // A new size, which the session answers by telling this terminal to resynchronise.
        window.measured(size(80, 30));
        send(&mut window, 2).expect("the size goes");
        window.recovering();
        window.answered(
            request(2),
            Answer::Accepted {
                window_revision: 2,
                direct: true,
                landed: None,
            },
        );
        window.measured(size(80, 32));
        assert_eq!(
            window.next(),
            None,
            "the direct answer settles its own report and opens nothing while the subscription is asked for"
        );
        window.streamed();
        let next = send(&mut window, 3).expect("the newest size goes once the stream begins");
        assert_eq!((next.dimensions, next.position), (size(80, 32), None));
        window.pressed(1, 23, size(80, 32));
        assert_eq!(
            window.next(),
            None,
            "and it stays in flight until its own answer settles it"
        );
    }

    /// Once the session has said it is closing, nothing more is sent.
    #[test]
    fn a_closing_session_is_sent_nothing_more() {
        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        window.close();
        window.measured(size(100, 30));
        assert_eq!(window.next(), None);
    }

    /// While a new subscription replaces the old one, the old stream's notifications are told
    /// apart from the new stream's, whose first delivery other than a gap is its screen.
    #[test]
    fn a_new_subscription_begins_at_its_first_notification_of_sequence_zero() {
        let mut subscriptions = Subscriptions::new();
        assert_eq!(
            subscriptions.heard(0, "session.projection.reset"),
            Heard::First,
            "the first subscription's first delivery"
        );
        assert_eq!(
            subscriptions.heard(1, "session.projection.snapshot"),
            Heard::Later
        );
        assert!(
            subscriptions.replace(),
            "a marker asks for a new subscription"
        );
        assert!(
            !subscriptions.replace(),
            "and a second reason before the new stream begins asks nothing more"
        );
        for (sequence, event) in [
            (7, "session.projection.delta"),
            (8, "session.output"),
            (9, "session.resync"),
        ] {
            assert_eq!(
                subscriptions.heard(sequence, event),
                Heard::Replaced,
                "{event} at {sequence} belongs to the stream being replaced"
            );
        }
        assert_eq!(subscriptions.heard(0, "session.gap"), Heard::Later);
        assert_eq!(
            subscriptions.heard(1, "session.output"),
            Heard::First,
            "the new stream's first delivery after its gap is its restoration"
        );
        assert_eq!(subscriptions.heard(2, "session.output"), Heard::Later);
        // A new stream whose first notification cannot even be decoded still opens it: the
        // sequence is read first, and the next reason asks again.
        assert!(subscriptions.replace());
        assert_eq!(
            subscriptions.heard(0, "session.projection.reset"),
            Heard::First
        );
        assert!(
            subscriptions.replace(),
            "a new stream is under way, so another can be asked for"
        );
    }
}
