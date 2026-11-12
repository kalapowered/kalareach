//! Attaching a terminal and driving it until the attachment ends.
//!
//! An attach is three things happening at once: bytes from the terminal going to the session, bytes
//! from the session going to the terminal, and a connection that can end at any moment. They run in
//! one loop rather than in tasks that each decide separately when to stop, because every way this
//! ends has to end the *other two* as well. A terminal left in raw mode because one half was still
//! waiting for a keystroke is the failure section 8 names.

use std::sync::Arc;

use crate::attach::{Attaching, TerminalInput};
use crate::bridge::link::Link;
use kr_client::error::{HostWord, refusal};
use kr_client::retry::{Attempts, Failure, Recovery, RequestClass};
use kr_client::shown;
use kr_client::shown::Shown;
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
    /// The session refused what was typed here, from one write on, because the application in it
    /// asked for a keyboard encoding that console keys cannot be sent in.
    InputRefused(Shown),
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
            Self::InputRefused(detail) => {
                formatter.debug_tuple("InputRefused").field(detail).finish()
            }
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
            Self::InputRefused(detail) => shown!(
                "the session took no more of what was typed here, because the application in it \
                 asked for a keyboard encoding that this terminal's keys cannot be sent in; \
                 `kr attach --no-probe` watches it without typing: {}",
                *detail
            ),
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
            | Self::DeliveryUncertain(_)
            | Self::InputRefused(_) => true,
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
            Self::InputRefused(_) => Some(CliError::Refused(refusal(
                ErrorCode::InputIncompatible,
                self.detail(),
            ))),
        }
    }

    /// Returns whether a command run to hold its window on failure waits for a key after this
    /// ending: a failure, other than the session's shell exiting, which is how the person ended it.
    #[must_use]
    pub fn holds_the_window(&self) -> bool {
        self.is_failure()
            && !self
                .closure()
                .is_some_and(|record| matches!(record.reason, ClosureReason::RootExit))
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
#[derive(Clone, Default, PartialEq, Eq)]
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

impl std::fmt::Debug for AttachOptions {
    /// The switches, and how many bytes were typed before. Never those bytes.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachOptions")
            .field("take_geometry", &self.take_geometry)
            .field("no_probe", &self.no_probe)
            .field("follow_live", &self.follow_live)
            .field("typed_before", &self.typed_before.len())
            .finish()
    }
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

/// Virtual-key codes of the keys a console reports for the scroll-back chord and the modifiers
/// that go down with it.
const VK_PRIOR: u16 = 0x21;
const VK_NEXT: u16 = 0x22;
const VK_SHIFT: u16 = 0x10;
const VK_CONTROL: u16 = 0x11;
const VK_MENU: u16 = 0x12;
/// The keys that toggle a lock. Pressing one types nothing: it changes a state the next key carries.
const VK_CAPITAL: u16 = 0x14;
/// The virtual-key code a console gives a character that is no key of the keyboard's, such as one an
/// input method committed. Every such character has it, so the code says nothing of which key came
/// up.
const VK_PACKET: u16 = 0xe7;
const VK_LWIN: u16 = 0x5b;
const VK_RWIN: u16 = 0x5c;
const VK_NUMLOCK: u16 = 0x90;
const VK_SCROLL: u16 = 0x91;

/// Takes this terminal's own scroll-back out of the records a console reported, and returns the
/// rest with how far the window is to move.
///
/// Shift and Page Up or Page Down are the chord. A console reports pressing one as its records
/// one by one: the modifier going down, the key going down and coming up, the modifier coming up,
/// and nothing says they arrive in one read, so the chord is taken key by key. The key going down
/// is taken, by its repeat count, and the same key coming up is taken after it, wherever it
/// arrives. The modifier's own records are the session's, going down and coming up, so that what
/// the application is told of it is balanced. Every other record is returned in its place, a
/// release among them.
///
/// Where a scroll key's first record went is where the rest of the hold goes: `held` is the
/// scroll keys down now, each by [`which_key`] with whether it is the window's. A key the session
/// was sent going down has its repeats and its release sent too, whatever the modifiers do
/// meanwhile, and a key taken is taken until it comes up. A chord that is not this terminal's
/// (`mine` is false) is the session's, and a repeat of a key the window has, when the window is no
/// longer this terminal's, is dropped.
fn take_scroll_keys(
    keys: Vec<kr_term::win32::KeyRecord>,
    held: &mut Vec<(WhichKey, bool)>,
    mine: bool,
) -> (Vec<kr_term::win32::KeyRecord>, i64) {
    use kr_term::win32::control_keys::{
        LEFT_ALT_PRESSED, LEFT_CTRL_PRESSED, RIGHT_ALT_PRESSED, RIGHT_CTRL_PRESSED, SHIFT_PRESSED,
    };

    const OTHERS: u32 =
        LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED | LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED;
    let mut rest = Vec::with_capacity(keys.len());
    let mut steps = 0_i64;
    for key in keys {
        let direction = match key.virtual_key {
            VK_PRIOR => 1_i64,
            VK_NEXT => -1_i64,
            _ => {
                rest.push(key);
                continue;
            }
        };
        let which = which_key(&key);
        let place = held.iter().position(|(code, _)| *code == which);
        if !key.key_down {
            // The key comes up where it went down. One not seen going down is the session's.
            match place.map(|at| held.remove(at)) {
                Some((_, true)) => {}
                _ => rest.push(key),
            }
            continue;
        }
        let window = match place {
            Some(at) => held[at].1,
            None => {
                let window =
                    mine && key.control_keys & SHIFT_PRESSED != 0 && key.control_keys & OTHERS == 0;
                held.push((which, window));
                window
            }
        };
        if !window {
            rest.push(key);
        } else if mine {
            steps = steps.saturating_add(direction.saturating_mul(i64::from(key.repeat.max(1))));
        }
    }
    (rest, steps)
}

/// A key, told by its virtual key, its scan code and whether it is an enhanced key: two keys can
/// report one virtual key (the left and right Shift, Ctrl and Alt, and the Page Up of the cursor
/// block and the one of the numeric keypad), and only the scan code and the enhanced flag tell them
/// apart.
type WhichKey = (u16, u16, bool);

/// The key a record is of.
const fn which_key(key: &kr_term::win32::KeyRecord) -> WhichKey {
    (
        key.virtual_key,
        key.scan_code,
        key.control_keys & kr_term::win32::control_keys::ENHANCED_KEY != 0,
    )
}

/// Takes the releases of keys this attachment did not see go down out of a run of key records.
///
/// A console reports a key coming up that went down before the attachment began to read, most often
/// the Return that started the command. Sending that release tells the application a key came up
/// that was never pressed, and a session that cannot spell records refuses the write for it. `down`
/// is the keys whose press this attachment has sent, each by [`which_key`]. The order of what is
/// kept is the order it arrived in. A record with no key of its own (a character an input method
/// committed, or none) cannot be matched to a press, and is kept. So is an Alt coming up with the
/// character composed on the numeric keypad, whether or not its press was seen: the character is on
/// that record alone, and dropping it would lose text the person typed.
fn drop_unseen_releases(
    keys: Vec<kr_term::win32::KeyRecord>,
    down: &mut Vec<WhichKey>,
) -> Vec<kr_term::win32::KeyRecord> {
    keys.into_iter()
        .filter(|key| {
            if matches!(key.virtual_key, 0 | VK_PACKET) {
                return true;
            }
            let which = which_key(key);
            let place = down.iter().position(|pressed| *pressed == which);
            if key.key_down {
                if place.is_none() {
                    down.push(which);
                }
                return true;
            }
            let seen = place.map(|at| down.remove(at)).is_some();
            seen || composed_with_alt(key)
        })
        .collect()
}

/// Whether a record is an Alt coming up with the character composed on the numeric keypad, which
/// the console reports on the Alt's release and on no other record.
const fn composed_with_alt(key: &kr_term::win32::KeyRecord) -> bool {
    !key.key_down && key.virtual_key == VK_MENU && key.unicode != 0
}

/// Whether a run of key records holds a key the person pressed: one going down that is not a
/// modifier or a lock, or an Alt coming up with the character composed on the numeric keypad. Any
/// other release, a modifier on its own and a lock key are not typing.
fn presses(keys: &[kr_term::win32::KeyRecord]) -> bool {
    keys.iter().any(|key| {
        if !key.key_down {
            return composed_with_alt(key);
        }
        !matches!(
            key.virtual_key,
            VK_SHIFT
                | VK_CONTROL
                | VK_MENU
                | VK_LWIN
                | VK_RWIN
                | VK_CAPITAL
                | VK_NUMLOCK
                | VK_SCROLL
        )
    })
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
#[derive(Default)]
struct PointerReports {
    /// The beginning of a report, waiting for the rest of it.
    held: Vec<u8>,
}

impl std::fmt::Debug for PointerReports {
    /// How many bytes it holds back. Never the bytes, which a person typed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PointerReports")
            .field("held", &self.held.len())
            .finish()
    }
}

/// What the classifier took out of one batch.
#[derive(Default, PartialEq, Eq)]
struct Pointers {
    /// The reports, in the order they arrived.
    reports: Vec<PointerReport>,
    /// The bytes that are not part of any report.
    input: Vec<u8>,
    /// Whether the beginning of a report is being held.
    holding: bool,
}

impl std::fmt::Debug for Pointers {
    /// How many reports and bytes it holds. Never a report or a byte, which a person typed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Pointers")
            .field("reports", &self.reports.len())
            .field("input", &self.input.len())
            .field("holding", &self.holding)
            .finish()
    }
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

/// Waits until `until`, or for ever when there is nothing to wait for.
async fn wait_until(until: Option<tokio::time::Instant>) {
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
/// still in flight, or one whose outcome the session could not say, whose sizes `resizing` holds,
/// already asks for it: an answer written before that resize was applied still carries the old
/// size, and a second resize to the same size would quote the epoch the first one moves on from,
/// and be refused; and a resize of unknown outcome is not made again by itself.
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

/// The size this terminal is looking at, when it has one the host would take.
fn measured_size(terminal: &ControllingTerminal) -> Option<Dimensions> {
    let size = terminal.size().ok()?;
    (size.columns > 0 && size.rows > 0)
        .then(|| Dimensions::new(u64::from(size.columns), u64::from(size.rows)))
}

/// How many times in a row a size the session did not take for now goes again with the session's
/// next word. After that it waits for this terminal to be measured or pressed, so a session that
/// keeps refusing is not asked once for every word it says.
const RETRIES: u8 = 3;

/// How the host answered one viewport report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// Refused in the session's definite word: nothing changed, and the report is settled.
    Refused,
    /// Refused for now: the session's word that nothing took effect, so the report may be made
    /// again. A size is owed again, since a report states the size and the place, and sending it
    /// again changes nothing a first one did not. A move, and a return to the live screen, are the
    /// person's own keys: they are settled as not taken.
    NotTaken,
    /// The session could not establish what became of the report. That proves nothing of whether
    /// it was dispatched, and an unknown outcome is not retryable, so the report is settled as
    /// unknown and nothing is owed for it: the next report this terminal makes carries the size
    /// it has.
    Unknown,
    /// Accepted, with the revision the report left the window at, whether this terminal is now
    /// handed the stream, and where the window landed.
    Accepted {
        window_revision: u64,
        direct: bool,
        landed: Option<u64>,
    },
}

/// What the session's answer to a viewport report is: the result it gave, or how the report is
/// settled when it gave none. The session's definite word settles a refusal and changes nothing; a
/// refusal for now owes the size the report carried again, if it carried one; one that cannot say
/// what became of the report leaves its outcome unknown, and so does a success that cannot be read,
/// since what it did to the window is not known.
fn viewport_result(
    outcome: kr_protocol::envelope::Outcome,
) -> std::result::Result<kr_protocol::attachment::AttachmentViewportResult, Answer> {
    match outcome {
        kr_protocol::envelope::Outcome::Ok(value) => value
            .to_typed::<kr_protocol::attachment::AttachmentViewportResult>()
            .map_err(|_| Answer::Unknown),
        kr_protocol::envelope::Outcome::Error(error) => Err(match HostWord::of(error.code) {
            HostWord::Definite => Answer::Refused,
            HostWord::Transient => Answer::NotTaken,
            HostWord::Unknown => Answer::Unknown,
        }),
    }
}

/// How the host answered a resize this terminal made as the size's owner, when it gave no result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResizeRefusal {
    /// Somebody else owns the size now, or owns it at another epoch.
    NotOwner,
    /// Refused for now: the session's word that nothing took effect, so the session may be at the
    /// old size and the question that says what size it has is owed.
    NotTaken,
    /// The session could not establish what became of the resize, or took it and gave an answer
    /// that cannot be read. That proves nothing of whether it was dispatched, and an unknown
    /// outcome is not retryable, so the resize is settled as unknown and is not made again by
    /// itself.
    Unknown,
    /// The session's definite word: the resize did not happen and will not.
    Refused,
}

/// What the session's answer to a resize is: the geometry it gave, or how the resize is settled
/// when it gave none. The retry category of the code tells a refusal for now from one that cannot
/// say what became of the resize and from the definite word, whichever the code is; a success that
/// cannot be read leaves the outcome unknown, since what it did to the size is not known.
fn resize_result(
    outcome: kr_protocol::envelope::Outcome,
) -> std::result::Result<kr_protocol::attachment::GeometryResult, ResizeRefusal> {
    match outcome {
        kr_protocol::envelope::Outcome::Ok(value) => value
            .to_typed::<kr_protocol::attachment::GeometryResult>()
            .map_err(|_| ResizeRefusal::Unknown),
        kr_protocol::envelope::Outcome::Error(error)
            if error.code == ErrorCode::GeometryNotOwner =>
        {
            Err(ResizeRefusal::NotOwner)
        }
        kr_protocol::envelope::Outcome::Error(error) => Err(match HostWord::of(error.code) {
            HostWord::Definite => ResizeRefusal::Refused,
            HostWord::Transient => ResizeRefusal::NotTaken,
            HostWord::Unknown => ResizeRefusal::Unknown,
        }),
    }
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
/// question a refused resize leaves owed, then the newest size if it is not the one last sent or
/// if a report of it was not settled, then the next run of moves. Nothing goes while a report is
/// in flight, while no screen is held to measure a move from, while a new subscription is being
/// asked for, while a size the session did not take for now rests, or once the session has said it
/// is closing. Holding every report while a subscription is asked for is what lets that
/// subscription's first delivery settle where the window is for the report in flight: it can only
/// have been sent before. What became of the size it carried is the session's answer to say, and a
/// size the session did not take is owed again even when that answer comes after the first delivery.
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
    /// The reports a stream's start settled before the session answered them. The stream settles
    /// where the window is, not what became of a size: an answer that comes after the stream's
    /// first bytes is still the answer to one of these, and says whether the session took the size.
    answerless: Vec<InFlight>,
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
    /// The newest report the session refused for now that carried the newest size, a return to the
    /// live screen that carried it included, when that size is owed to the session whatever the size
    /// last sent was. The session did not take that report, so even the size last sent has to be
    /// said again. A report sent after the one refused carried the newest size too: one the session
    /// took has given it the size, and one it could not answer is not retried, so either ends the
    /// debt.
    size_owed: Option<kr_protocol::ids::RequestId>,
    /// The newest report that carried the newest size to the session: one the session took, or one
    /// it could not say what became of. A refusal for now of an older report, answered after this
    /// one, owes nothing.
    carried_at: Option<kr_protocol::ids::RequestId>,
    /// Whether a size the session did not take for now waits for something to arrive before it
    /// goes again, so that a session that keeps saying so is not asked in a loop.
    resting: bool,
    /// How many size reports in a row the session did not take for now.
    not_taken_in_a_row: u8,
    /// How many resizes this terminal made as the owner, one after another, the session did not
    /// take for now. They end when a resize is taken, or when the person resizes the terminal.
    owner_not_taken: u8,
    /// The request and the size of the newest resize this terminal asked for as the owner, the
    /// person's or one an answer showed it owed. It ends when the person resizes the terminal to
    /// another size while it does not own the size, since that resize is newer than any the owner
    /// asked for; a signal for the size it asked for is no newer resize.
    owner_request: Option<(kr_protocol::ids::RequestId, Dimensions)>,
    /// The size of the newest resize this terminal asked for as the owner that the session could
    /// not say what became of. It is not made again by itself, whatever size the session is found
    /// at: nothing is asked in its place, and the next resize the person makes is. It ends when
    /// the person resizes the terminal to another size.
    resize_unknown: Option<Dimensions>,
    /// Whether the window may be at the live screen though the record puts it above it: a return
    /// to the live screen was refused for now, which the person's key asked for, or the session
    /// could not say what became of it and may have taken it. What goes before a screen says where
    /// the window is goes there, which is where the key that asked for the return wanted it.
    live_unsettled: bool,
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
    /// Whether it carries moves, or the return to the live screen: the person's own keys. A report
    /// that carries neither carries the size, or asks the question a refused resize leaves owed.
    moves: bool,
    /// Whether it is the return to the live screen.
    returning: bool,
    /// Whether it carries a size the session was owed: the return goes before the size and takes
    /// the newest one with it, so a size measured before it, or one an earlier report left owed,
    /// rides inside it.
    sized: bool,
    /// Whether this terminal was measured or pressed after the report went: a word the window does
    /// not rest from, whatever the session answers.
    spoke: bool,
}

impl WindowReports {
    /// A terminal that has just attached at this size, and holds no screen yet.
    fn new(size: Dimensions) -> Self {
        Self {
            record: None,
            answered: 0,
            installed: None,
            in_flight: None,
            answerless: Vec::new(),
            recovering: false,
            return_owed: false,
            question_owed: false,
            size,
            size_sent: size,
            size_owed: None,
            carried_at: None,
            owner_request: None,
            resize_unknown: None,
            resting: false,
            not_taken_in_a_row: 0,
            owner_not_taken: 0,
            live_unsettled: false,
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
        self.spoke();
    }

    /// This terminal's size changed. Whatever the session did not take for now goes again with the
    /// next report chosen. A size other than the one the newest owner's resize asked for, and the
    /// one a resize ended unknown for, is a new resize by the person, which ends what was left of
    /// those; a signal for either size is no newer resize.
    fn measured(&mut self, size: Dimensions) {
        self.size = size;
        self.owner_request.take_if(|(_, asked)| *asked != size);
        if self.resize_unknown != Some(size) {
            self.resize_unknown = None;
        }
        self.spoke();
    }

    /// The session said something. A size it did not take for now goes again, as long as it has not
    /// failed to take it more than [`RETRIES`] times in a row since this terminal last spoke.
    const fn heard(&mut self) {
        if self.not_taken_in_a_row <= RETRIES {
            self.resting = false;
        }
    }

    /// This terminal spoke: a new start for whatever waits. A report in flight is told, so that its
    /// answer does not make this terminal's word wait.
    fn spoke(&mut self) {
        self.resting = false;
        self.not_taken_in_a_row = 0;
        for flight in self.in_flight.iter_mut().chain(&mut self.answerless) {
            flight.spoke = true;
        }
    }

    /// This terminal gave the session its size as the owner, which tells the session without a
    /// viewport report. Later reports carry that size, and none is owed for it.
    fn took_size(&mut self, size: Dimensions) {
        self.size = size;
        self.size_sent = size;
        self.size_owed = None;
        self.resize_unknown = None;
        self.spoke();
    }

    /// The person resized this terminal while it owns the size, which gives the session the new
    /// size as `took_size` does, and is a new start for the resizes the session did not take.
    /// Says whether the resize is to be made. A signal for the size a resize ended unknown for is
    /// no new resize, since an answer may have read the new size before the signal was read: it
    /// is not made again.
    #[must_use]
    fn resized_as_owner(&mut self, size: Dimensions) -> bool {
        if self.resize_unknown == Some(size) {
            self.size = size;
            return false;
        }
        self.owner_not_taken = 0;
        self.took_size(size);
        true
    }

    /// The resize this terminal asked for as the owner, to `size`, went under `request`.
    const fn resize_sent(&mut self, request: kr_protocol::ids::RequestId, size: Dimensions) {
        self.owner_request = Some((request, size));
    }

    /// A resize this terminal made as the owner was taken.
    const fn resize_taken(&mut self) {
        self.owner_not_taken = 0;
    }

    /// A resize this terminal made as the owner was not taken for now, and `size` is the size the
    /// person is looking at. The session may be at the old size, so the question a refused resize
    /// leaves owed is owed: its answer says who owns the size and what it is, and the owner then
    /// resizes if the session is not at its own. It goes with the session's next word, and for at
    /// most [`RETRIES`] resizes in a row; after that the session is left as it is until the person
    /// resizes this terminal again.
    const fn resize_not_taken(&mut self, size: Dimensions) {
        self.size = size;
        if self.owner_not_taken >= RETRIES {
            return;
        }
        self.owner_not_taken += 1;
        self.question_owed = true;
        self.resting = true;
    }

    /// The session could not say what became of the resize that went under `request`. It may have
    /// been dispatched, and an unknown outcome is not retried, so it is not made again, and nothing
    /// is asked in its place: no answer owes it. It is no resize taken, and no resize refused for
    /// now, so the count of those stands. Only the newest resize this terminal asked for counts: an
    /// older one answered late, after a newer resize or after the person resized the terminal,
    /// leaves no mark, since the size has moved on from it.
    fn resize_ended_unknown(&mut self, request: kr_protocol::ids::RequestId) {
        if let Some((newest, asked)) = self.owner_request
            && newest == request
        {
            self.resize_unknown = Some(asked);
        }
    }

    /// The size of the resize that ended unknown and has not been made again, when there is one.
    const fn resize_unknown(&self) -> Option<Dimensions> {
        self.resize_unknown
    }

    /// A resize was refused because somebody else owns the size, or owns it at another epoch.
    fn owe_question(&mut self, size: Dimensions) {
        self.size = size;
        self.question_owed = true;
        self.spoke();
    }

    /// The person typed while following the live screen, which takes the window back to it. That
    /// is a newer instruction than any move still waiting.
    fn return_to_live(&mut self) {
        self.return_owed = true;
        self.runs.clear();
        self.spoke();
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
            self.live_unsettled = false;
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
    ///
    /// That settles where the window is, and not what became of the size a report carried: the
    /// answers and the stream come from two writers, so the answer to a report that has none yet
    /// can still come after the stream's first bytes, and if it says the session did not take the
    /// size, the size is owed again. The report is kept until its answer comes for that.
    fn streamed(&mut self) {
        self.record = Some(None);
        self.live_unsettled = false;
        if let Some(flight) = self.in_flight.take()
            && flight.awaiting.is_none()
            && flight.request.is_some()
        {
            self.answerless.push(flight);
        }
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
        if self.closing || self.recovering || self.in_flight.is_some() || self.resting {
            return None;
        }
        let record = self.record?;
        // Where the window is, as far as a report that is not a move can say: not the row the
        // record keeps while a return the person's key asked for is unsettled.
        let place = if self.live_unsettled {
            None
        } else {
            record.map(|row| ViewportPosition::Row(U64::new(row)))
        };
        let mut moves = false;
        let mut returning = false;
        let mut sized = false;
        let sending = if self.return_owed {
            self.return_owed = false;
            moves = true;
            returning = true;
            sized = self.size != self.size_sent || self.size_owed.is_some();
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
        } else if self.size != self.size_sent || self.size_owed.is_some() {
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
                    moves = true;
                    break Sending {
                        dimensions: self.size,
                        position,
                    };
                }
            }
        };
        self.size_sent = sending.dimensions;
        self.size_owed = None;
        self.in_flight = Some(InFlight {
            request: None,
            awaiting: None,
            moves,
            returning,
            sized,
            spoke: false,
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
    /// A definite refusal settles it and changes nothing. A refusal for now settles a move the same
    /// way, but not a size: the newest size is owed again, with the next word from the session or
    /// from this terminal, or at once when this terminal spoke while the report was in flight, unless
    /// a newer report has since carried the size to the session. An answer that cannot say what
    /// became of the report settles it as unknown and owes nothing. An
    /// answer that hands this terminal the stream settles it
    /// where that answer says the window landed, which for a terminal handed the stream is the live
    /// screen's origin. Any other answer settles it only once a screen naming its revision, or a
    /// later one, has arrived, whether that screen came before the answer or comes after it.
    fn answered(&mut self, request: kr_protocol::ids::RequestId, answer: Answer) {
        let ours = self
            .in_flight
            .is_some_and(|in_flight| in_flight.request == Some(request));
        // A report the stream's start settled: its answer settles nothing more, but the size it
        // carried is owed again if the session refused it for now.
        let late = self
            .answerless
            .iter()
            .position(|flight| flight.request == Some(request))
            .map(|at| self.answerless.swap_remove(at));
        match answer {
            Answer::Refused => {
                if ours {
                    self.not_taken_in_a_row = 0;
                    self.in_flight = None;
                }
            }
            Answer::NotTaken => {
                if ours {
                    self.not_taken(request);
                } else if let Some(flight) = late {
                    self.size_not_taken_behind_the_stream(request, flight);
                }
            }
            Answer::Unknown => {
                if ours {
                    self.unknown(request);
                } else if late.is_some() {
                    self.size_carried_by(request);
                }
            }
            Answer::Accepted {
                window_revision,
                direct,
                landed: at,
            } => {
                self.answered = self.answered.max(window_revision);
                if ours || late.is_some() {
                    self.size_carried_by(request);
                }
                if ours {
                    self.not_taken_in_a_row = 0;
                }
                if !ours {
                    return;
                }
                if direct {
                    self.record = Some(at);
                    self.live_unsettled = false;
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

    /// The session could not say what became of the report `request`, in flight. Whether it was
    /// dispatched is not known, so it is not made again and no size is owed for it. A move of
    /// unknown outcome may have been taken, so it leaves the record as it was, and what is owed
    /// goes at the row it keeps. A return to the live screen may have been taken, so what goes next
    /// goes at the live screen until a screen says where the window is, which is where the key that
    /// asked for it wanted the window.
    fn unknown(&mut self, request: kr_protocol::ids::RequestId) {
        let Some(flight) = self.in_flight.take() else {
            return;
        };
        self.not_taken_in_a_row = 0;
        if flight.returning {
            self.live_unsettled = true;
        }
        self.size_carried_by(request);
    }

    /// The report `request`, which carried the newest size there was when it went, was taken by the
    /// session, or the session could not say what became of it. A size an older report was refused
    /// for now, whether that refusal came before this answer or comes after it, is not owed any
    /// more: the session has the size, or sending it again would send this report again.
    fn size_carried_by(&mut self, request: kr_protocol::ids::RequestId) {
        self.carried_at = self.carried_at.max(Some(request));
        if self.size_owed < Some(request) {
            self.size_owed = None;
        }
    }

    /// Owes the newest size again, for the report `request` that the session refused for now.
    fn owe_size(&mut self, request: kr_protocol::ids::RequestId) {
        self.size_owed = self.size_owed.max(Some(request));
    }

    /// The session refused the report `request`, in flight, for now.
    fn not_taken(&mut self, request: kr_protocol::ids::RequestId) {
        let Some(flight) = self.in_flight.take() else {
            return;
        };
        if flight.moves {
            // A move, or a return to the live screen, is the person's own key and is not asked for
            // again by this loop: it is settled as not taken, and the next key asks for it again.
            // A move not taken did nothing, so it leaves the record as it was, and what is owed
            // goes at the row it keeps.
            //
            // A return differs in what goes after it, and only in that. The person typed, which
            // wants the window at the live screen, so a size or a question owed meanwhile or since
            // goes with no position, and a report with no position puts the window at the live
            // screen. That is the return made later, but only inside a report the session is owed
            // anyway, never as a request of its own.
            self.not_taken_in_a_row = 0;
            if flight.returning {
                self.live_unsettled = true;
                // The return took the newest size with it, and the session may not have taken
                // that either. It is owed again, the way a size report not taken is: when the
                // session next says something, or at once if this terminal spoke meanwhile. The
                // return was the first asking of that size, so it counts as one that failed, and
                // the size goes again three times at most before the terminal speaks.
                if flight.sized {
                    self.owe_size(request);
                    self.resting = !flight.spoke;
                    self.not_taken_in_a_row = 1;
                }
            }
            return;
        }
        // A size the session did not take is not settled: the newest size is owed again, whatever
        // the size last sent was, since the session did not take the one this report carried. It
        // waits for something to arrive, unless this terminal spoke while the report was in flight.
        self.owe_size(request);
        self.not_taken_in_a_row = self.not_taken_in_a_row.saturating_add(1);
        self.resting = !flight.spoke;
    }

    /// The session refused for now the report `request`, which the stream's start had settled. A
    /// move carried no size; a return carried the newest one only when `sized` says so; any other
    /// report carried a size. What it carried is owed again as if the report had been in flight:
    /// the session's next word brings it, or at once if this terminal spoke meanwhile. Where the
    /// window is stays as the stream put it, since the stream's start is later than the report. It
    /// is not owed when a newer report has been answered that the session took, or could not say
    /// what became of: that one carried the newest size, and it is not sent again.
    fn size_not_taken_behind_the_stream(
        &mut self,
        request: kr_protocol::ids::RequestId,
        flight: InFlight,
    ) {
        if flight.moves && !(flight.returning && flight.sized) {
            return;
        }
        if self.carried_at > Some(request) {
            return;
        }
        self.owe_size(request);
        self.not_taken_in_a_row = self.not_taken_in_a_row.saturating_add(1);
        self.resting = !flight.spoke;
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
///
/// A session that refuses a new subscription for now has changed nothing, and the subscription is
/// a read, so it is asked for again by the shared retry policy: after the pause the policy gives,
/// and for as many times as it gives. The pause is a timer and not the session's next word,
/// because a session that has sent a resynchronisation marker says nothing more until it is asked
/// for the screen again.
#[derive(Debug, Default)]
struct Subscriptions {
    /// A new subscription has been asked for, and its stream has not begun.
    replacing: bool,
    /// The stream's first delivery other than a gap has not arrived.
    opening: bool,
    /// What the retry policy has left for the subscription being asked for.
    attempts: Attempts,
    /// When the subscription the session refused for now is asked for again.
    retry_at: Option<tokio::time::Instant>,
}

impl Subscriptions {
    /// The first subscription, whose first delivery has not arrived.
    fn new() -> Self {
        Self {
            replacing: false,
            opening: true,
            attempts: Attempts::new(),
            retry_at: None,
        }
    }

    /// The session refused the new subscription under `code`, for now. Says whether it is asked for
    /// again, which the policy decides; when it is not, the attachment ends as it does when the
    /// session refuses in its definite word.
    fn refused_for_now(&mut self, code: ErrorCode) -> bool {
        let decision = self
            .attempts
            .decide(Failure::new(code), RequestClass::IdempotentRead);
        let Recovery::Retry { delay } = decision.recovery else {
            return false;
        };
        self.retry_at = Some(tokio::time::Instant::now() + delay);
        true
    }

    /// The session took the new subscription.
    fn taken(&mut self) {
        self.attempts = Attempts::new();
        self.retry_at = None;
    }

    /// When the subscription the session refused for now is asked for again, if it is owed.
    const fn retry_at(&self) -> Option<tokio::time::Instant> {
        self.retry_at
    }

    /// The subscription the session refused for now is being asked for, or is no longer wanted.
    const fn asked_again(&mut self) {
        self.retry_at = None;
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
/// `opened` is a connection the caller already made to the session's worker, and answered the hello
/// and proof on; the attachment goes over it. Without one the worker is opened after this terminal
/// has been asked what it is.
///
/// # Errors
///
/// Returns the host's refusal, a terminal failure, or the failure the attachment ended with.
pub async fn run(
    descriptor: &WorkerDescriptor,
    opened: Option<kr_ipc::client::LocalClient>,
    owed: UndeliveredTyping,
    options: AttachOptions,
) -> Result<(AttachOutcome, SessionId)> {
    run_over(
        Attaching::from(descriptor),
        || async move {
            match opened {
                Some(client) => Ok(client),
                None => crate::resolve::open_worker(descriptor, crate::build_id()).await,
            }
        },
        owed,
        options,
    )
    .await
}

/// Attaches this terminal to a session reached through `open`, and drives it until the
/// attachment ends.
///
/// `open` is called once, after this terminal has been asked what it is and before the session is
/// asked for anything. It makes the connection to the session's worker: a local socket for a
/// session on this host, a bridge for a session in another environment. The connection is ended
/// after the terminal is its own again, which is when anything it has to say can be said.
///
/// # Errors
///
/// Returns the host's refusal, a terminal failure, or the failure the attachment ended with.
pub async fn run_over<L, Open, Opening>(
    attaching: Attaching,
    open: Open,
    mut owed: UndeliveredTyping,
    options: AttachOptions,
) -> Result<(AttachOutcome, SessionId)>
where
    L: Link,
    Open: FnOnce() -> Opening,
    Opening: std::future::Future<Output = Result<L>>,
{
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
    let declared = terminal.profile();
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

    let mut client = match open().await {
        Ok(client) => client,
        Err(error) => {
            // Nothing has begun forwarding, so the terminal's modes are put back, as they are when
            // the probe fails, and the refusal is said once the terminal is the person's again.
            let _ = terminal.restore(&saved, None, &modes);
            guard.release();
            return Err(error);
        }
    };
    // A worker outlives an upgrade, so it can be of a build whose screens this one cannot read.
    // Its answer to the hello says which, and that is settled before the session is asked for
    // anything: nothing is attached, no size is claimed and no lease is taken. Nothing has begun
    // forwarding either, so the terminal's modes are put back, as they are when the probe fails,
    // and the refusal is said once the terminal is the person's again.
    if let Err(refusal) = crate::attach::check_build(client.build(), attaching.display_number) {
        let _ = terminal.restore(&saved, None, &modes);
        guard.release();
        return Err(refusal);
    }
    // A terminal attachment claims the session's size. Section 8 makes that the default: a
    // terminal that did not claim it would be shown a projection of somebody else's size, which is
    // exactly what a lone attachment does not need. `--take-geometry` goes further and takes the
    // claim from whoever holds it.
    let attachment: Attachment = crate::attach::attach(
        &mut client,
        &attaching,
        dimensions,
        true,
        declared.as_deref().filter(|_| !options.no_probe),
    )
    .await?;
    // The transfer's own answer is what the loop starts from. Starting from the attach result
    // instead would leave it quoting an epoch the transfer has already moved, and believing
    // somebody else still owns the size it has just taken.
    let geometry = if options.take_geometry {
        crate::attach::take_geometry(
            &mut client,
            &attaching,
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
        attaching.session_id,
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
    // A Windows console reports keys as records, which the session spells as its terminal asked
    // for; a terminal emulator hands over bytes.
    #[cfg(unix)]
    let raw_replaced = terminal.enter_raw_mode()?;
    #[cfg(not(unix))]
    let raw_replaced = terminal.enter_record_mode()?;

    // What the session draws goes to the terminal's output handle. On Windows that is the console's
    // output buffer, `CONOUT$`, and not its input handle, which is the one the input reader below
    // reads from and takes no drawn bytes.
    let output = Arc::new(
        terminal
            .output()
            .try_clone()
            .map_err(|error| CliError::Terminal(Shown::io(&error)))?,
    );
    let input_handle = terminal
        .handle()
        .try_clone()
        .map_err(|error| CliError::Terminal(Shown::io(&error)))?;
    let switch = terminal.input_switch()?;
    let (mut input, input_stop) = crate::attach::spawn_input_reader(input_handle, &switch)?;

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
    // What the attachment has to say about its keys, which waits for the terminal to be the
    // person's again like everything else it says.
    let mut said_after: Vec<Shown> = Vec::new();
    let mut fallback = Fallback::default();
    let outcome = drive(
        &mut client,
        &attaching,
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
        &output,
        &terminal,
        resized.as_mut(),
        &mut display,
        options.follow_live,
        &switch,
        &mut fallback,
    )
    .await;
    // The reader stops before anything else reads this terminal: a command that goes on after the
    // attachment must be the only reader of it.
    // What it had read and the loop had not taken is dropped, and a typed key in it was lost.
    let stopped = input_stop.stop();
    said_after.extend(after_the_reader_stops(stopped, &mut fallback, &mut input));

    // The terminal comes back here on every path out of the loop, and the guard is released only
    // once it has.
    // The modes are this process's to put back; the keyboard protocols are the guard's, and it
    // writes them back as it is released, which is what keeps the two halves in order.
    terminal.restore(&raw_replaced, None, &modes)?;
    guard.release();
    // Said after the terminal is its own again, never during the attachment: a sentence written
    // into a terminal that is showing a projection would wrap, overwrite cells and scroll the
    // bottom row, which is damage to the very screen it is describing.
    for line in &said_after {
        crate::report::say(line);
    }
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
    // The connection ends here, with the terminal back and nothing on the screen to damage.
    client.finish().await;
    Ok((outcome, attaching.session_id))
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

/// What an attachment says once its console spells its own keys: the session refused the records.
const KEYS_SPELLED_BY_THE_CONSOLE: &str = "kr: the application in the session uses a keyboard \
     encoding that console keys cannot be sent in, so the session refused them, and from then on \
     the keys go as this console spells them, with its modifier detail and without key releases.";

/// What an attachment says when the session refused its records and its console would not spell its
/// keys: it stopped sending keys, and watched.
const WATCHING_AFTER_A_REFUSAL: &str = "kr: the application in the session uses a keyboard \
     encoding that console keys cannot be sent in, and this console would not spell its keys \
     itself, so this attachment stopped sending keys and watched.";

/// What an attachment says when the thread that reads its console had not ended by the time the
/// attachment did.
const READER_STILL_RUNNING: &str = "kr: the part of this command that reads the console's keys had \
     not ended when the terminal came back, so the next key you type may be lost, the console's \
     input mode may change, and the keys it had already taken were not counted.";

/// What an attachment says when that thread ended only after the command asked the system to cancel
/// its read of the console, which hands the next key typed to a read that was cancelled.
const READER_CANCEL_ASKED: &str = "kr: the part of this command that reads the console's keys had \
     not ended when the attachment did, so the command asked the system to cancel its read of the \
     console, and the next key you type may be lost.";

/// What is added to either when something the person typed was lost with the refusal.
const TYPED_KEYS_LOST: &str = "Keys typed just before the session refused them were lost: the batch \
     it refused, the writes sent behind that batch and the records this command had already read.";

/// The same, when the console would not spell its keys: nothing is sent after the refusal, so the
/// keys read since are part of what the attachment did not send.
const TYPED_KEYS_LOST_WATCHING: &str = "Keys typed from the moment the session refused them were \
     lost: the batch it refused, the writes sent behind that batch and the keys read since.";

/// What `kr attach --no-probe` does, said to an attachment that can no longer type.
const WATCHING_WITHOUT_TYPING: &str = "`kr attach --no-probe` watches without typing.";

/// What the attachment did when the session refused its console keys, and what that cost.
#[derive(Debug, Default)]
struct Fallback {
    /// How it went on, once it did.
    how: Option<Spelling>,
    /// Whether anything the person typed was lost in the change. A key coming up (an Alt with a
    /// composed character apart), a modifier on its own and a lock key are not typing, so a refusal
    /// of only those loses nothing.
    typed_keys_lost: bool,
}

/// What the attachment says once the thread that reads its console has been stopped: how it went on
/// if the session refused its console keys, counting what the reader left, that the thread had not
/// ended if it had not, and otherwise that a cancel of a read of the console was asked if one was.
fn after_the_reader_stops(
    stopped: crate::attach::Stopped,
    fallback: &mut Fallback,
    input: &mut tokio::sync::mpsc::UnboundedReceiver<TerminalInput>,
) -> Vec<Shown> {
    let mut said: Vec<Shown> = fallback.finish(input, &stopped.left).into_iter().collect();
    if stopped.still_running {
        said.push(Shown::said(READER_STILL_RUNNING));
    } else if stopped.cancel_asked {
        said.push(Shown::said(READER_CANCEL_ASKED));
    }
    said
}

/// How an attachment goes on once the session refused its console keys.
#[derive(Clone, Copy, Debug)]
enum Spelling {
    /// The console spells its keys, and what it spells is sent as bytes.
    Console,
    /// The console would not, so the attachment stopped sending keys and watches.
    Watching,
}

impl Fallback {
    /// Counts the records left in `input` and the ones the reader left when it ended, which are
    /// dropped, and returns what the attachment says after the terminal is the person's again, if it
    /// changed how it sends keys.
    ///
    /// The reader must have stopped, so that nothing it read is still on its way. When the stop said
    /// it had not, a send the reader was already past the look for the stop in can still arrive
    /// after this, which the line about the reader says.
    fn finish(
        &mut self,
        input: &mut tokio::sync::mpsc::UnboundedReceiver<TerminalInput>,
        left: &[TerminalInput],
    ) -> Option<Shown> {
        self.how?;
        let mut count = |read: &TerminalInput| {
            if let TerminalInput::Keys(keys) = read {
                self.typed_keys_lost |= presses(keys);
            }
        };
        left.iter().for_each(&mut count);
        while let Ok(read) = input.try_recv() {
            count(&read);
        }
        self.line()
    }

    /// What the attachment says after the terminal is the person's again, if it changed how it
    /// sends keys.
    fn line(&self) -> Option<Shown> {
        let (head, lost, tail) = match self.how? {
            Spelling::Console => (KEYS_SPELLED_BY_THE_CONSOLE, TYPED_KEYS_LOST, None),
            Spelling::Watching => (
                WATCHING_AFTER_A_REFUSAL,
                TYPED_KEYS_LOST_WATCHING,
                Some(WATCHING_WITHOUT_TYPING),
            ),
        };
        let parts = std::iter::once(head)
            .chain(self.typed_keys_lost.then_some(lost))
            .chain(tail)
            .map(Shown::said);
        Some(Shown::joined(parts, " "))
    }
}

/// One `input.write` this terminal sent, and what it held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Write {
    /// The sequence number it was sent under.
    sequence: u64,
    /// Whether it held something the person typed. A key coming up (an Alt with a composed character
    /// apart), a modifier on its own and a lock key are not typing, so a write of only those is
    /// refused without anything being lost.
    typed: bool,
    /// Whether it was console key records and not bytes.
    keys: bool,
}

impl Write {
    /// A write of bytes, which are what the person typed.
    const fn bytes(sequence: u64) -> Self {
        Self {
            sequence,
            typed: true,
            keys: false,
        }
    }

    /// A write of the reports of a console's mouse, which are not what the person typed.
    const fn pointer(sequence: u64) -> Self {
        Self {
            sequence,
            typed: false,
            keys: false,
        }
    }

    /// A write of console key records.
    fn keys(sequence: u64, records: &[kr_term::win32::KeyRecord]) -> Self {
        Self {
            sequence,
            typed: presses(records),
            keys: true,
        }
    }
}

/// What the host's refusal of one input write means for the attachment.
#[derive(Debug, PartialEq, Eq)]
enum Refused {
    /// Another attachment holds the keys.
    LeaseLost,
    /// The session is closing and refuses input. `undelivered` is whether what it refused was typed.
    Closing { undelivered: bool },
    /// The host took none of a write of console keys, and says it cannot spell them in the encoding
    /// the session is in.
    KeysIncompatible,
    /// The host took none of a write of bytes, and says it cannot take it in the encoding the
    /// session is in.
    Incompatible(Shown),
    /// Any other refusal, after which it is not known what the session has.
    Uncertain(Shown),
}

/// Reads the refusal of one input write.
fn refused_write(write: Write, error: &kr_protocol::error::ProtocolError) -> Refused {
    match error.code {
        ErrorCode::LeaseLost => Refused::LeaseLost,
        ErrorCode::SessionClosed => Refused::Closing {
            undelivered: write.typed,
        },
        ErrorCode::InputIncompatible if write.keys => Refused::KeysIncompatible,
        ErrorCode::InputIncompatible => Refused::Incompatible(Shown::protocol(error)),
        code => Refused::Uncertain(shown!(
            "{} at input {}: {}",
            code,
            write.sequence,
            Shown::protocol(error)
        )),
    }
}

/// What one outstanding request was for, so its answer is read as an answer to that.
#[derive(Clone, Copy, Debug)]
enum Outstanding {
    /// One input write, with what it held.
    Input(Write),
    /// A size change this terminal made as the size owner, to this size.
    Resize(Dimensions),
    /// A viewport report, which `WindowReports` holds.
    Window,
    /// A fresh screen this terminal asked for after a resynchronisation marker.
    Resubscribe,
    /// A request whose answer changes nothing: the lease handed back, or a write of console keys
    /// sent before the console began to spell its keys, which the host refuses or cannot place.
    Ignored,
}

/// The sizes this terminal's resizes as the owner asked for that no answer owes again: those still
/// waiting for an answer, and `unknown`, the one the session could not say what became of.
fn resizes_not_owed(
    outstanding: &std::collections::BTreeMap<kr_protocol::ids::RequestId, Outstanding>,
    unknown: Option<Dimensions>,
) -> Vec<Dimensions> {
    outstanding
        .values()
        .filter_map(|what| match what {
            Outstanding::Resize(dimensions) => Some(*dimensions),
            _ => None,
        })
        .chain(unknown)
        .collect()
}

/// What an attachment does about its console's mouse.
///
/// A Windows console reports the mouse as records. A console window reports them only once it has
/// been asked to, and keeps the mouse for selecting text until then; a pseudo console turns the
/// mouse reports it is sent into records whatever its input mode is. The application in the session
/// asks to be told of the mouse by what it writes, so this learns of that from the output, has the
/// console report the mouse while the application asks and gives it back to the console when it
/// stops, and spells the records the console reports as the reports the application asked for. On
/// other platforms the terminal sends the reports itself, and this does nothing of the kind.
#[derive(Debug, Default)]
struct ConsoleMouse {
    reporting: crate::mouse::MouseReporting,
    speller: crate::mouse::MouseSpeller,
    /// Which of the output events are a restoration.
    restoration: crate::mouse::Restoration,
    /// Whether the first delivery of the subscription is output that has yet to be read: it is the
    /// screen the session drew for this terminal, and only an output event that is decoded and read
    /// uses it up.
    awaiting_first: bool,
    /// Whether the stream has a hole in it that no screen has closed: the bridge shed a frame and
    /// queued a marker in its place, or a frame could not be decoded. What the reader holds of the
    /// mouse may then differ from what the session holds, so the output that follows is read as
    /// drawn, with nothing written after it to put a terminal in an encoding the session may have
    /// left, until the first frame of the screen that follows.
    hole: bool,
    /// Whether the console has been asked to report the mouse.
    given: bool,
}

impl ConsoleMouse {
    /// Reads output that is about to be shown on the console, and gives the mouse to the
    /// application or back to the console as what it asked for changes. `may_type` says whether
    /// this terminal may send input to the session, which is what the mouse would be.
    ///
    /// Says what the terminal is to be written after the output, so that it ends in the state the
    /// session holds.
    fn shown(
        &mut self,
        output: &[u8],
        terminal: &ControllingTerminal,
        may_type: bool,
        reading: crate::mouse::Reading,
    ) -> Vec<crate::mouse::Follow> {
        let follows = self.reporting.read(output, reading);
        self.update(terminal, may_type);
        follows
    }

    /// Reads a screen this command drew from the session's own, which is read as a terminal reads
    /// it: what a worker of an earlier build writes into a restoration is not what this command's
    /// own painter writes.
    fn painted(&mut self, output: &[u8], terminal: &ControllingTerminal, may_type: bool) {
        let _ = self.shown(output, terminal, may_type, crate::mouse::Reading::Painted);
    }

    /// A subscription has delivered its first notification, which is output or something else: a
    /// stream that begins with something else, a projected one, has no screen of output to read.
    fn first_delivery_is(&mut self, output: bool) {
        self.awaiting_first = output;
    }

    /// The stream has a hole in it: output of the subscription that is being replaced, or output
    /// that cannot be decoded, says nothing of what was lost.
    fn hole_in_the_stream(&mut self) {
        self.hole = true;
    }

    /// How an output event of the session is read: as part of a restoration, or as what the
    /// application wrote, which is read as drawn while there is a hole in the stream.
    fn reading_of(&mut self, cursor: u64, length: usize) -> crate::mouse::Reading {
        let first = std::mem::take(&mut self.awaiting_first);
        let reading = self.restoration.reading(first, cursor, length);
        // The first frame of a new subscription is its screen, which says the state again.
        if first {
            self.hole = false;
        }
        if self.hole && reading == crate::mouse::Reading::Live {
            crate::mouse::Reading::Painted
        } else {
            reading
        }
    }

    /// Gives the mouse to the application or back to the console to match what the application has
    /// asked for and whether this terminal may send it input, and says whether it is asked for. A
    /// console that will not change its mode keeps the mouse as it is, and is asked again whenever
    /// the output, a mouse record or the lease gives a reason to look.
    fn update(&mut self, terminal: &ControllingTerminal, may_type: bool) -> bool {
        let asked = may_type && self.reporting.tracking() != crate::mouse::Tracking::Off;
        if asked != self.given && report_mouse(terminal, asked) {
            self.given = asked;
        }
        if !asked {
            // A console that reports no mouse says nothing of a button let go of meanwhile.
            self.speller.forget_the_buttons();
        }
        asked
    }

    /// The bytes that tell the application of `record`, or none.
    fn spelled(
        &mut self,
        record: crate::mouse::MouseRecord,
        terminal: &ControllingTerminal,
        may_type: bool,
    ) -> Vec<u8> {
        // A record that comes while the console should no longer be reporting is the reason to ask
        // again for the mouse to be given back, and it says nothing to the application: a record
        // the console had queued before it stopped reporting must not leave a button held.
        if !self.update(terminal, may_type) {
            return Vec::new();
        }
        self.speller
            .spell(record, &self.reporting, window(terminal))
    }
}

/// Has the console report its mouse, or gives the mouse back to it, and says whether the console
/// took the change.
#[cfg(not(unix))]
fn report_mouse(terminal: &ControllingTerminal, asked: bool) -> bool {
    terminal.report_mouse(asked).is_ok()
}

/// A terminal emulator sends the mouse reports itself.
#[cfg(unix)]
const fn report_mouse(_terminal: &ControllingTerminal, _asked: bool) -> bool {
    true
}

/// The part of the console's screen buffer its window shows, which a mouse record's position is
/// counted in and a report's is not; all of the buffer from its origin when the console does not
/// say.
#[cfg(not(unix))]
fn window(terminal: &ControllingTerminal) -> crate::mouse::Window {
    terminal.window().unwrap_or(crate::mouse::Window::UNBOUNDED)
}

#[cfg(unix)]
const fn window(_terminal: &ControllingTerminal) -> crate::mouse::Window {
    crate::mouse::Window::UNBOUNDED
}

/// Runs the attachment's input, output and connection in one loop.
///
/// `fallback` is what the loop learns of a refusal of its console keys; the caller says it once the
/// terminal is the person's again, after the reader has stopped.
#[expect(
    clippy::too_many_arguments,
    reason = "one attachment is its client, its session, its terminal and everything it started with"
)]
async fn drive(
    client: &mut impl Link,
    attaching: &Attaching,
    owed: &mut UndeliveredTyping,
    typed_during_the_probe: Vec<u8>,
    attached: Attached,
    input: &mut tokio::sync::mpsc::UnboundedReceiver<TerminalInput>,
    output: &Arc<std::fs::File>,
    terminal: &ControllingTerminal,
    resized: Option<&mut WindowChanges>,
    display: &mut crate::render::ProjectedDisplay,
    follow_live: bool,
    switch: &crate::attach::InputSwitch,
    fallback: &mut Fallback,
) -> AttachOutcome {
    use std::io::Write as _;

    let session_id = attaching.session_id;
    let attachment_id = attached.attachment_id;
    // `None` where this terminal may not type. What it types is then dropped rather than sent:
    // the host has already refused it the lease, so every keystroke would be one refused request,
    // and the attachment would end on the first of them. Watching is what is left, and watching is
    // what this attachment asked for when it chose not to be asked about.
    let mut epoch = attached.lease_epoch;
    let mut geometry_epoch = attached.geometry_epoch;
    let mut owns_geometry = attached.owns_geometry;
    let mut resized = resized;

    // Whether a bracketed paste is open, so that nothing inside one is read as a key.
    let mut paste = PasteWatch::default();
    // The scroll keys that are down now, each with whether this terminal took it.
    let mut scroll_keys_held: Vec<(WhichKey, bool)> = Vec::new();
    // The keys whose press has been sent to the session and whose release is still to come.
    let mut keys_down: Vec<WhichKey> = Vec::new();
    // Whether the console spells its keys itself now, because the session refused its records. The
    // records the reader read before that are dropped, and none are sent after it.
    let mut console_spells = false;
    // The pointer reports this terminal sends while its window is above the live page, and the
    // moment a report it is part way through stops waiting for the rest of itself.
    let mut pointers = PointerReports::default();
    let mut pointer_deadline: Option<tokio::time::Instant> = None;
    // What the application has asked of the mouse, and whether the console has been given it: a
    // console window reports the mouse as records only while it has.
    let mut console_mouse = ConsoleMouse::default();
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
        outstanding.insert(request_id, Outstanding::Input(Write::bytes(sequence)));
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
            if !send_mutation(
                client,
                attaching,
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
            // A subscription the session refused for now is asked for again when the retry
            // policy's pause is over, whether or not the session has said anything: a session
            // that asked for a new subscription has nothing to say until it gets one.
            () = wait_until(subscriptions.retry_at()) => {
                subscriptions.asked_again();
                if closing {
                    continue;
                }
                let request_id = kr_protocol::ids::RequestId::new(next_request);
                next_request += 1;
                if !resubscribe(client, attaching, request_id, attachment_id).await {
                    return AttachOutcome::Disconnected;
                }
                outstanding.insert(request_id, Outstanding::Resubscribe);
            }
            () = wait_until(pointer_deadline) => {
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
                    outstanding.insert(request_id, Outstanding::Input(Write::bytes(sequence)));
                    sequence += 1;
                }
            }
            message = client.recv() => {
                // Whatever the session says lets a size it did not take for now go again.
                if message.is_ok() {
                    window.heard();
                }
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
                        // The same delivery is the screen the session drew for this terminal. A
                        // payload that cannot be decoded below is not drawn and does not use that
                        // up: the next output that decodes is the screen.
                        if heard == Heard::First {
                            console_mouse
                                .first_delivery_is(notification.event_type.as_str() == "session.output");
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
                            // The console is given the mouse before it is shown that the
                            // application asked for it, so that nothing it is shown can be
                            // answered by a mouse the console still kept.
                            let reading = console_mouse
                                .reading_of(event.cursor.get(), event.bytes.as_slice().len());
                            let follows = console_mouse.shown(
                                event.bytes.as_slice(),
                                terminal,
                                epoch.is_some(),
                                reading,
                            );
                            // What the terminal is written after a sequence that would leave it
                            // in another state than the session goes in the middle of the event.
                            let mut handle = output.as_ref();
                            let mut written = 0;
                            let mut failed = false;
                            for follow in &follows {
                                failed = failed
                                    || handle
                                        .write_all(&event.bytes.as_slice()[written..follow.at])
                                        .is_err()
                                    || handle.write_all(&follow.bytes()).is_err();
                                written = follow.at;
                            }
                            if failed
                                || handle
                                    .write_all(&event.bytes.as_slice()[written..])
                                    .is_err()
                            {
                                return AttachOutcome::Disconnected;
                            }
                            let _ = handle.flush();
                        } else if notification.event_type.as_str() == "session.output" {
                            // Output that cannot be decoded is not drawn, and what it carried is
                            // lost to the reader.
                            console_mouse.hole_in_the_stream();
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
                                if !resubscribe(client, attaching, request_id, attachment_id).await
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
                                console_mouse.painted(&drawn.bytes, terminal, epoch.is_some());
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
                                if !resubscribe(client, attaching, request_id, attachment_id).await
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
                            // The frames the bridge shed to queue this marker are not the reader's
                            // to know, and the output of this subscription that follows is read
                            // without them.
                            console_mouse.hole_in_the_stream();
                            if closing || !subscriptions.replace() {
                                continue;
                            }
                            window.recovering();
                            let request_id = kr_protocol::ids::RequestId::new(next_request);
                            next_request += 1;
                            if !resubscribe(client, attaching, request_id, attachment_id).await {
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
                        // answer, and nothing an answer would have it send is of use any more. What
                        // it refuses of the person's typing it still refused, and that is counted.
                        if closing {
                            if let (
                                Outstanding::Input(write),
                                kr_protocol::envelope::Outcome::Error(error),
                            ) = (&what, &response.outcome)
                            {
                                undelivered |= matches!(
                                    refused_write(*write, error),
                                    Refused::Closing { undelivered: true }
                                );
                            }
                            continue;
                        }
                        match (what, response.outcome) {
                            // A size report is a report, not an insistence. Another attachment may
                            // own the size, and the answer then says so; the terminal is shown that
                            // size rather than taking it, and the attachment carries on.
                            (Outstanding::Resize(_), outcome) => match resize_result(outcome) {
                                Ok(result) => {
                                    window.resize_taken();
                                    geometry_epoch = result.geometry.epoch;
                                    owns_geometry =
                                        result.geometry.owner.as_ref() == Some(&attachment_id);
                                }
                                // Somebody else owns the size now, or owns it at another epoch.
                                // The refusal carries neither, so this asks the only question whose
                                // answer does: a viewport report, which says who owns the size and
                                // at which epoch and changes nothing. Without it this terminal would
                                // go on sending owner-only resizes for the rest of the attachment
                                // and go on being refused them.
                                Err(ResizeRefusal::NotOwner) => {
                                    owns_geometry = false;
                                    // A terminal with no size is one the host would refuse
                                    // anyway. Asking would swap one refusal for another.
                                    let Some(size) = measured_size(terminal) else {
                                        continue;
                                    };
                                    // It goes behind whatever viewport report is in flight, with
                                    // where the window is, whatever its size.
                                    window.owe_question(size);
                                }
                                // The session did not take the resize for now, so it may be at the
                                // old size while this terminal has told it the new one. The same
                                // question settles it: its answer names the size the session has,
                                // and this terminal resizes again if it owns the size and the
                                // session is at another.
                                Err(ResizeRefusal::NotTaken) => {
                                    let Some(size) = measured_size(terminal) else {
                                        continue;
                                    };
                                    window.resize_not_taken(size);
                                }
                                // The session could not say what became of the resize, or took it
                                // and said so in a way that cannot be read. It may have been
                                // dispatched, and an unknown outcome is not retried, so it is not
                                // made again by any answer. Nothing is asked in its place: a viewport
                                // report changes the window the session keeps for this terminal, so
                                // it is no read. If the resize was taken, the next resize is
                                // refused for its epoch and the question follows that definite word.
                                Err(ResizeRefusal::Unknown) => {
                                    window.resize_ended_unknown(answered);
                                }
                                // The session's definite word: the resize did not happen and will
                                // not, and asking again changes nothing.
                                Err(ResizeRefusal::Refused) => {}
                            },
                            // A viewport report answers with the presentation it produced as well
                            // as the geometry, so it has its own result type and its own decoder.
                            // Where the window is comes from the screen the answer names, not from
                            // the answer: an answer can arrive before that screen, and after one
                            // drawn for an earlier window.
                            (Outstanding::Window, outcome) => {
                                let result = match viewport_result(outcome) {
                                    Ok(result) => result,
                                    Err(answer) => {
                                        window.answered(answered, answer);
                                        continue;
                                    }
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
                                let resizing = resizes_not_owed(&outstanding, window.resize_unknown());
                                let owner = ownership(
                                    &result.geometry,
                                    attachment_id,
                                    measured_size(terminal),
                                    &resizing,
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
                                    if !send_mutation(
                                        client,
                                        attaching,
                                        request_id,
                                        Method::TerminalResize,
                                        &params,
                                    )
                                    .await
                                    {
                                        return AttachOutcome::Disconnected;
                                    }
                                    outstanding.insert(request_id, Outstanding::Resize(dimensions));
                                    window.resize_sent(request_id, dimensions);
                                }
                            }
                            (
                                Outstanding::Input(write),
                                kr_protocol::envelope::Outcome::Error(error),
                            ) => match refused_write(write, &error) {
                                Refused::LeaseLost => return AttachOutcome::LeaseLost,
                                // The session is closing, and refuses input from the moment it
                                // began. This terminal stops sending and waits for the closure.
                                Refused::Closing { undelivered: typed } => {
                                    closing = true;
                                    window.close();
                                    undelivered |= typed;
                                }
                                // The session cannot spell this console's records in the
                                // encoding its application is in, and took none of them. The
                                // console is asked to spell its keys itself, as a terminal does,
                                // and what it spells goes as bytes from then on. The host took no
                                // sequence number for the refused write, so the next is sent under
                                // it, and the writes sent behind it, as records or as the reports
                                // of the mouse, are of no further use: whatever the host answers
                                // them, they are not read. What the person typed in them is lost,
                                // and so is what is dropped below, which the line afterwards says.
                                Refused::KeysIncompatible => {
                                    sequence = write.sequence;
                                    fallback.typed_keys_lost |= write.typed;
                                    for what in outstanding.values_mut() {
                                        if let Outstanding::Input(sent) = what
                                            && (sent.keys || sent.sequence > write.sequence)
                                        {
                                            fallback.typed_keys_lost |= sent.typed;
                                            *what = Outstanding::Ignored;
                                        }
                                    }
                                    if switch.engage().is_ok() {
                                        console_spells = true;
                                        fallback.how = Some(Spelling::Console);
                                    } else {
                                        // A console that will not spell its keys cannot be typed
                                        // at: the lease is handed back and the attachment watches.
                                        fallback.how = Some(Spelling::Watching);
                                        if let Some(held) = epoch.take() {
                                            // A terminal that may not type has no use for the
                                            // mouse: the console has it back at once, and does not
                                            // wait for the application's next output.
                                            console_mouse.update(terminal, false);
                                            let request_id =
                                                kr_protocol::ids::RequestId::new(next_request);
                                            next_request += 1;
                                            let params = kr_protocol::input::InputReleaseParams {
                                                session_id,
                                                attachment_id,
                                                epoch: held,
                                            };
                                            if !send_mutation(
                                                client,
                                                attaching,
                                                request_id,
                                                Method::InputRelease,
                                                &params,
                                            )
                                            .await
                                            {
                                                return AttachOutcome::Disconnected;
                                            }
                                            outstanding.insert(request_id, Outstanding::Ignored);
                                        }
                                    }
                                }
                                // A refusal the session made whole: it took none of what was
                                // sent, and says why. The terminal is told so and the attachment
                                // ends, rather than being left typing into a session that refuses
                                // every key.
                                Refused::Incompatible(detail) => {
                                    return AttachOutcome::InputRefused(detail);
                                }
                                Refused::Uncertain(detail) => {
                                    return AttachOutcome::DeliveryUncertain(detail);
                                }
                            },
                            (Outstanding::Input(_), kr_protocol::envelope::Outcome::Ok(_))
                            | (Outstanding::Ignored, _) => {}
                            // The screen follows as ordinary output. A refusal because the session
                            // is closing is answered by the closure, which is still to come. A
                            // refusal for now changed nothing: the subscription is asked for again
                            // after the retry policy's pause, a few times at most, and the stream
                            // being replaced goes on meanwhile. Any other refusal means the session
                            // no longer has this attachment, which is the end of it.
                            (Outstanding::Resubscribe, outcome) => match outcome {
                                kr_protocol::envelope::Outcome::Ok(_) => subscriptions.taken(),
                                kr_protocol::envelope::Outcome::Error(error)
                                    if error.code == ErrorCode::SessionClosed =>
                                {
                                    closing = true;
                                    window.close();
                                }
                                kr_protocol::envelope::Outcome::Error(error) => {
                                    let for_now = HostWord::of(error.code) == HostWord::Transient;
                                    if !for_now || !subscriptions.refused_for_now(error.code) {
                                        return AttachOutcome::Disconnected;
                                    }
                                }
                            },
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
                if !window.resized_as_owner(dimensions) {
                    continue;
                }
                let request_id = kr_protocol::ids::RequestId::new(next_request);
                next_request += 1;
                let params = kr_protocol::attachment::TerminalResizeParams {
                    attachment_id,
                    dimensions,
                    expected_geometry_epoch: geometry_epoch,
                };
                if !send_mutation(
                    client,
                    attaching,
                    request_id,
                    Method::TerminalResize,
                    &params,
                )
                .await
                {
                    return AttachOutcome::Disconnected;
                }
                outstanding.insert(request_id, Outstanding::Resize(dimensions));
                window.resize_sent(request_id, dimensions);
            }
            read = input.recv() => {
                let Some(read) = read else {
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
                    // A release (an Alt with a composed character apart) or a modifier going down is
                    // not something typed.
                    undelivered |= match &read {
                        TerminalInput::Bytes(_) => true,
                        TerminalInput::Keys(keys) => presses(keys),
                        // A pointer moving over the window is not something typed.
                        TerminalInput::Mouse(_) => false,
                    };
                    continue;
                }
                let mut mouse_report: Option<Vec<u8>> = None;
                let bytes = match read {
                    TerminalInput::Bytes(bytes) => bytes,
                    // A console reports the mouse as records, and the mouse is a virtual-terminal
                    // operation in this protocol: the application that asked to be told of it is
                    // sent the report it asked for, as bytes, and goes on from here like any other.
                    TerminalInput::Mouse(record) => {
                        let report = console_mouse.spelled(record, terminal, epoch.is_some());
                        if report.is_empty() {
                            continue;
                        }
                        mouse_report = Some(report.clone());
                        report
                    }
                    // A console reports keys as records. There is no paste delimiter or pointer
                    // report in them to watch for, because those are bytes, and the records go to
                    // the session as they are.
                    // Records the reader read before the console began to spell its keys. The
                    // session refused the first of them, and the rest would be refused too: they
                    // are dropped and never turned into bytes, and counted.
                    TerminalInput::Keys(keys) if console_spells => {
                        fallback.typed_keys_lost |= presses(&keys);
                        continue;
                    }
                    TerminalInput::Keys(keys) => {
                        // The scroll-back keys first, on the same terms as for bytes: they move
                        // the window this terminal is looking through and never reach the
                        // session. A console reports a key going down and coming up as two
                        // records, often in two reads, so it is the key that is taken and not the
                        // read: the release of a key taken goes with it, and every other record
                        // is the session's.
                        let size = terminal
                            .size()
                            .ok()
                            .filter(|size| size.columns > 0 && size.rows > 0);
                        let mine = size.is_some()
                            && display.holds_screen()
                            && display.showing_history_buffer();
                        let (keys, steps) = take_scroll_keys(keys, &mut scroll_keys_held, mine);
                        // A key that came up here after going down before this command read the
                        // console, the Return that started it among them, is not the session's:
                        // it never went down there.
                        let keys = drop_unseen_releases(keys, &mut keys_down);
                        if let (Some(size), true) = (size, steps != 0) {
                            let shown = display
                                .window_rows()
                                .unwrap_or_else(|| u64::from(size.rows));
                            window.pressed(
                                steps,
                                scroll_step(shown),
                                Dimensions::new(u64::from(size.columns), u64::from(size.rows)),
                            );
                        }
                        if keys.is_empty() {
                            continue;
                        }
                        // As for bytes: a person who asked to follow the live screen is taken back
                        // to it by the first key they press. A key coming up (an Alt with a
                        // composed character apart), or a modifier going down, is not one.
                        if follow_live && showing_history && presses(&keys) {
                            window.return_to_live();
                        }
                        let Some(epoch) = epoch else {
                            // This terminal may not type, and watches. After a refusal of its
                            // console keys that is the loss the line afterwards names.
                            if fallback.how.is_some() {
                                fallback.typed_keys_lost |= presses(&keys);
                            }
                            continue;
                        };
                        let request_id = kr_protocol::ids::RequestId::new(next_request);
                        next_request += 1;
                        let write = Write::keys(sequence, &keys);
                        if !send_keys(
                            client,
                            request_id,
                            session_id,
                            attachment_id,
                            epoch,
                            sequence,
                            keys,
                        )
                        .await
                        {
                            return AttachOutcome::DeliveryUncertain(Shown::said(
                                "the connection ended while input was being sent",
                            ));
                        }
                        outstanding.insert(request_id, Outstanding::Input(write));
                        sequence += 1;
                        continue;
                    }
                };
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
                // What the person typed and the pointer classifier held back goes out with a
                // report of the mouse as typing; a write that is only the report is not.
                let write = if mouse_report.as_deref() == Some(bytes.as_slice()) {
                    Write::pointer(sequence)
                } else {
                    Write::bytes(sequence)
                };
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
                outstanding.insert(request_id, Outstanding::Input(write));
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
    client: &mut impl Link,
    attaching: &Attaching,
    request_id: kr_protocol::ids::RequestId,
    attachment_id: kr_protocol::ids::AttachmentId,
) -> bool {
    let mut streams = kr_protocol::scalars::CanonicalSet::new();
    streams.insert(kr_protocol::recovery::EventStream::Output);
    let params = kr_protocol::recovery::EventsSubscribeParams {
        session_id: attaching.session_id,
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
    client.send(ControlFrame::Request(request)).await.is_ok()
}

/// Writes one batch of terminal input on this loop's own connection.
///
/// Returns whether it reached the socket. Its answer comes back through the loop, like every other
/// answer on this connection.
async fn send_input(
    client: &mut impl Link,
    request_id: kr_protocol::ids::RequestId,
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    bytes: Vec<u8>,
) -> bool {
    send_write(
        client,
        request_id,
        session_id,
        attachment_id,
        epoch,
        sequence,
        kr_protocol::input::InputContent::Bytes {
            bytes: kr_protocol::scalars::Bytes::new(bytes),
        },
    )
    .await
}

/// Writes one run of key records on this loop's own connection, as the console reported them.
///
/// The records are not spelled here. What they are written to the application as is the session's
/// to decide, where it knows what its terminal asked for; a record is never turned into a character
/// and back with a scan code this command chose. Its answer comes back through the loop.
async fn send_keys(
    client: &mut impl Link,
    request_id: kr_protocol::ids::RequestId,
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    keys: Vec<kr_term::win32::KeyRecord>,
) -> bool {
    send_write(
        client,
        request_id,
        session_id,
        attachment_id,
        epoch,
        sequence,
        kr_protocol::input::InputContent::ConsoleKeys {
            keys: keys.into_iter().map(Into::into).collect(),
        },
    )
    .await
}

/// Writes one `input.write` on this loop's own connection.
async fn send_write(
    client: &mut impl Link,
    request_id: kr_protocol::ids::RequestId,
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
    input: kr_protocol::input::InputContent,
) -> bool {
    let params = kr_protocol::input::InputWriteParams {
        session_id,
        attachment_id,
        epoch,
        sequence: kr_protocol::ids::InputSequence::new(sequence),
        input,
    };
    let Ok(params) = kr_protocol::envelope::ParamsValue::from_typed(&params) else {
        return false;
    };
    client
        .send(ControlFrame::Request(kr_protocol::envelope::Request {
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
async fn send_mutation<T: serde::Serialize + ?Sized>(
    client: &mut impl Link,
    attaching: &Attaching,
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
        target: attaching.target(),
        expected: kr_protocol::envelope::ParamsValue::empty(),
        action_window_id: client.action_window_id(),
        requested_ttl_ms: kr_protocol::scalars::DurationMs::new(
            kr_protocol::limits::DEFAULT_MUTATION_TTL.get(),
        ),
        params,
    };
    client
        .send(ControlFrame::Mutation(Box::new(mutation)))
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
        Answer, AttachOutcome, Fallback, Heard, Outstanding, Ownership, ResizeRefusal,
        SCROLL_BACK_KEY, SCROLL_FORWARD_KEY, Sending, Spelling, Subscriptions, WindowReports,
        after_the_reader_stops, drop_unseen_releases, landed, ownership, presses, resize_result,
        resizes_not_owed, scroll_keys, scroll_step, scrolled, take_scroll_keys, viewport_result,
    };
    #[cfg(unix)]
    use crate::error::CliError;
    use kr_client::error::HostWord;
    #[cfg(unix)]
    use kr_client::error::refusal;
    use kr_client::shown::Shown;
    use kr_protocol::attachment::ViewportPosition;
    use kr_protocol::error::ErrorCode;
    #[cfg(unix)]
    use kr_protocol::method::Method;
    use kr_protocol::scalars::{Nullable, U64};
    use kr_protocol::session::{ClosureReason, ClosureRecord};

    /// The attach loop run against a connection the case holds both ends of.
    ///
    /// Everything the loop sends reaches the case as a frame, and everything the case answers it
    /// reads as the worker's. The loop's terminal is a device that is no terminal, which it takes
    /// to be one with no size.
    #[cfg(unix)]
    mod wire {
        use std::sync::Arc;

        use kr_protocol::envelope::{ControlFrame, Notification, Outcome, ParamsValue, Response};
        use kr_protocol::error::{ErrorCode, ProtocolError};
        use kr_protocol::ids::{
            ActionWindowId, AttachmentId, EnvironmentId, EventSequence, EventType, InputLeaseEpoch,
            RequestId, SessionId, StreamId,
        };
        use kr_protocol::input::{InputContent, InputReleaseParams, InputWriteParams};
        use kr_protocol::method::Method;
        use kr_protocol::scalars::Uuid;
        use kr_protocol::session::{
            ClosureReason, Dimensions, DisplayNumber, SESSION_CLOSED_EVENT,
        };
        use tokio::sync::mpsc;

        use super::super::{AttachOutcome, Attached, Attaching, TerminalInput, UndeliveredTyping};
        use crate::bridge::link::{Answer, Link};
        use crate::error::{CliError, Result};
        use crate::terminal::ControllingTerminal;

        /// The `input.write` requests among the frames the loop sent, as (sequence, content).
        pub fn writes_in(sent: &[ControlFrame]) -> Vec<(u64, InputContent)> {
            sent.iter()
                .filter_map(|frame| match frame {
                    ControlFrame::Request(request)
                        if request.method == Method::InputWrite.into() =>
                    {
                        let params: InputWriteParams =
                            request.params.to_typed().expect("write parameters");
                        Some((params.sequence.get(), params.input))
                    }
                    _ => None,
                })
                .collect()
        }

        /// The `input.release` mutations among the frames the loop sent.
        pub fn released_in(sent: &[ControlFrame]) -> Vec<InputReleaseParams> {
            sent.iter()
                .filter_map(|frame| match frame {
                    ControlFrame::Mutation(mutation)
                        if mutation.method == Method::InputRelease.into() =>
                    {
                        Some(mutation.params.to_typed().expect("release parameters"))
                    }
                    _ => None,
                })
                .collect()
        }

        /// The loop's end of the connection.
        struct Wire {
            sent: mpsc::UnboundedSender<ControlFrame>,
            /// Everything the loop has sent, in order, for a case that asks at the end.
            log: Arc<std::sync::Mutex<Vec<ControlFrame>>>,
            heard: mpsc::UnboundedReceiver<ControlFrame>,
        }

        impl Link for Wire {
            fn build(&self) -> Option<&kr_protocol::local::LocalBuild> {
                None
            }

            fn action_window_id(&self) -> ActionWindowId {
                ActionWindowId::new("wire").expect("a window")
            }

            async fn request<T: serde::Serialize + ?Sized>(
                &mut self,
                _method: Method,
                _params: &T,
            ) -> Result<Answer> {
                Err(CliError::Other(kr_client::shown::Shown::said(
                    "the loop asks for nothing by request",
                )))
            }

            async fn mutate<T: serde::Serialize + ?Sized>(
                &mut self,
                _method: Method,
                _action_id: kr_protocol::ids::ActionId,
                _target: kr_protocol::envelope::ActionTarget,
                _params: &T,
            ) -> Result<Answer> {
                Err(CliError::Other(kr_client::shown::Shown::said(
                    "the loop mutates by frame",
                )))
            }

            async fn recv(&mut self) -> Result<ControlFrame> {
                self.heard.recv().await.ok_or_else(|| {
                    CliError::Other(kr_client::shown::Shown::said("the case ended the wire"))
                })
            }

            async fn send(&mut self, frame: ControlFrame) -> Result<()> {
                self.log
                    .lock()
                    .expect("the log is not poisoned")
                    .push(frame.clone());
                let _ = self.sent.send(frame);
                Ok(())
            }

            async fn finish(self) {}
        }

        /// The case's end: the console it types at, and the frames the loop sends.
        pub struct Case {
            console: Option<mpsc::UnboundedSender<TerminalInput>>,
            written: mpsc::UnboundedReceiver<ControlFrame>,
            answers: mpsc::UnboundedSender<ControlFrame>,
            /// How many times the loop has asked the console to spell its keys.
            asked: Arc<std::sync::atomic::AtomicUsize>,
            /// The terminal the loop reads its size from, for a case that changes it. The run keeps
            /// it until the loop ends, so a case that has finished does not take the size from
            /// under an answer the loop has yet to read.
            sized: Option<std::rc::Rc<SizedTerminal>>,
        }

        /// A pseudo-terminal the loop reads its size from, and the signal that tells it the size
        /// changed.
        pub struct SizedTerminal {
            master: Box<dyn portable_pty::MasterPty + Send>,
        }

        impl SizedTerminal {
            /// The person resizes the terminal: its size is set and the loop is told, as the system
            /// does with a signal.
            pub fn changes_to(&self, columns: u16, rows: u16) {
                self.master
                    .resize(portable_pty::PtySize {
                        rows,
                        cols: columns,
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .expect("the terminal is resized");
                rustix::process::kill_process(
                    rustix::process::getpid(),
                    rustix::process::Signal::WINCH,
                )
                .expect("the loop is told");
            }
        }

        /// One `input.write` the loop sent.
        pub struct Written {
            pub request_id: RequestId,
            pub sequence: u64,
            pub content: InputContent,
        }

        impl Case {
            /// Types `input` at the console and returns the write the loop makes of it.
            pub async fn types(&mut self, input: TerminalInput) -> Written {
                self.console
                    .as_ref()
                    .expect("the console is open")
                    .send(input)
                    .expect("the loop reads the console");
                self.next_write().await
            }

            /// Types `input` at the console without waiting for the loop to do anything with it.
            pub fn types_without_waiting(&self, input: TerminalInput) {
                self.console
                    .as_ref()
                    .expect("the console is open")
                    .send(input)
                    .expect("the loop reads the console");
            }

            /// The next frame the loop sends. A loop that has ended and sent nothing more is a
            /// failure of the case and not a wait without end.
            async fn next_frame(&mut self) -> ControlFrame {
                tokio::time::timeout(std::time::Duration::from_secs(10), self.written.recv())
                    .await
                    .expect("the loop sent nothing more in ten seconds")
                    .expect("the loop is running")
            }

            /// The next `input.write` the loop sends, whatever else it sends first.
            pub async fn next_write(&mut self) -> Written {
                loop {
                    let frame = self.next_frame().await;
                    let ControlFrame::Request(request) = frame else {
                        continue;
                    };
                    if request.method != Method::InputWrite.into() {
                        continue;
                    }
                    let params: InputWriteParams =
                        request.params.to_typed().expect("write parameters");
                    return Written {
                        request_id: request.request_id,
                        sequence: params.sequence.get(),
                        content: params.input,
                    };
                }
            }

            /// The next mutation the loop sends with this method, whatever else it sends first.
            pub async fn next_mutation(&mut self, method: Method) -> ParamsValue {
                self.next_mutation_asked(method).await.1
            }

            /// The next mutation the loop sends with this method, whatever else it sends first, and
            /// the request it is.
            pub async fn next_mutation_asked(
                &mut self,
                method: Method,
            ) -> (RequestId, ParamsValue) {
                loop {
                    let frame = self.next_frame().await;
                    if let ControlFrame::Mutation(mutation) = frame
                        && mutation.method == method.into()
                    {
                        return (mutation.request_id, mutation.params);
                    }
                }
            }

            /// The host answers the request with `outcome`.
            pub fn answers_with(&self, request_id: RequestId, outcome: Outcome) {
                self.answers
                    .send(ControlFrame::Response(Response {
                        request_id,
                        outcome,
                    }))
                    .expect("the loop reads the wire");
            }

            /// The session says something: a batch of output on its stream, the `sequence`th.
            pub fn says_output(&self, sequence: u64) {
                self.says_output_bytes(sequence, b"x");
            }

            /// The session writes `bytes`, as the `sequence`th batch of output on its stream.
            pub fn says_output_bytes(&self, sequence: u64, bytes: &[u8]) {
                self.answers
                    .send(ControlFrame::Notification(Notification {
                        stream_id: StreamId::new("session").expect("a stream"),
                        sequence: EventSequence::new(sequence),
                        event_type: EventType::new("session.output").expect("an event type"),
                        payload: ParamsValue::from_typed(&kr_protocol::recovery::OutputEvent {
                            cursor: kr_protocol::scalars::U64::new(sequence),
                            bytes: kr_protocol::scalars::Bytes::new(bytes.to_vec()),
                        })
                        .expect("an output event"),
                    }))
                    .expect("the loop reads the wire");
            }

            /// The session says that the stream does not begin where the terminal asked it to, as the
            /// `sequence`th thing it says.
            pub fn says_gap(&self, sequence: u64) {
                self.answers
                    .send(ControlFrame::Notification(Notification {
                        stream_id: StreamId::new("session").expect("a stream"),
                        sequence: EventSequence::new(sequence),
                        event_type: EventType::new("session.gap").expect("an event type"),
                        payload: ParamsValue::empty(),
                    }))
                    .expect("the loop reads the wire");
            }

            /// The session says a batch of output on its stream, the `sequence`th, that this build
            /// cannot decode.
            pub fn says_output_it_cannot_decode(&self, sequence: u64) {
                self.answers
                    .send(ControlFrame::Notification(Notification {
                        stream_id: StreamId::new("session").expect("a stream"),
                        sequence: EventSequence::new(sequence),
                        event_type: EventType::new("session.output").expect("an event type"),
                        payload: ParamsValue::empty(),
                    }))
                    .expect("the loop reads the wire");
            }

            /// The session says its view of it is no longer continuous, as the `sequence`th thing
            /// it says: the marker a terminal answers by asking for a new subscription.
            pub fn says_resync(&self, sequence: u64) {
                self.answers
                    .send(ControlFrame::Notification(Notification {
                        stream_id: StreamId::new("session").expect("a stream"),
                        sequence: EventSequence::new(sequence),
                        event_type: EventType::new("session.resync").expect("an event type"),
                        payload: ParamsValue::empty(),
                    }))
                    .expect("the loop reads the wire");
            }

            /// The next request the loop sends with this method, whatever else it sends first.
            pub async fn next_request_asked(&mut self, method: Method) -> RequestId {
                loop {
                    let frame = self.next_frame().await;
                    if let ControlFrame::Request(request) = frame
                        && request.method == method.into()
                    {
                        return request.request_id;
                    }
                }
            }

            /// The terminal the case changes the size of.
            pub fn terminal(&self) -> &SizedTerminal {
                self.sized
                    .as_deref()
                    .expect("the case has a sized terminal")
            }

            /// The host took the write.
            pub fn takes(&self, written: &Written) {
                self.answer(written, Outcome::Ok(ParamsValue::empty()));
            }

            /// The host refused the write with `code`.
            pub fn refuses(&self, written: &Written, code: ErrorCode) {
                self.answer(
                    written,
                    Outcome::Error(ProtocolError::new(code, "refused by the case")),
                );
            }

            fn answer(&self, written: &Written, outcome: Outcome) {
                self.answers
                    .send(ControlFrame::Response(Response {
                        request_id: written.request_id,
                        outcome,
                    }))
                    .expect("the loop reads the wire");
            }

            /// The session closes, as the last thing its stream carries.
            pub fn closes(&self) {
                let record = super::closure(ClosureReason::CloseRequested, None, None);
                self.answers
                    .send(ControlFrame::Notification(Notification {
                        stream_id: StreamId::new("session").expect("a stream"),
                        sequence: EventSequence::new(1),
                        event_type: EventType::new(SESSION_CLOSED_EVENT).expect("an event type"),
                        payload: ParamsValue::from_typed(&record).expect("a closure"),
                    }))
                    .expect("the loop reads the wire");
            }

            /// Waits until the loop has asked the console to spell its keys, which it does once it
            /// has read the host's refusal, and says how many times it has.
            pub async fn waits_for_the_console_to_be_asked(&self) -> usize {
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    loop {
                        let asked = self.asked.load(std::sync::atomic::Ordering::SeqCst);
                        if asked > 0 {
                            return asked;
                        }
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("the loop asked the console")
            }

            /// The console's input ends, which ends the attachment.
            pub fn hangs_up(&mut self) {
                self.console = None;
            }
        }

        /// How the attachment ended, what it said after the terminal was the person's again, every
        /// frame it sent, and every byte it wrote to the terminal.
        pub struct Ran {
            pub outcome: AttachOutcome,
            pub said: Vec<kr_client::shown::Shown>,
            pub sent: Vec<ControlFrame>,
            pub written: Vec<u8>,
        }

        /// Runs the loop with a lease held and a console that will spell its keys, and `case` for
        /// what happens, and returns how the attachment ended.
        pub async fn run<F, Fut>(holds_lease: bool, case: F) -> AttachOutcome
        where
            F: FnOnce(Case) -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            run_switched(holds_lease, true, case).await.outcome
        }

        /// Runs the loop with the lease held or not, and a console that will spell its keys
        /// itself or will not.
        pub async fn run_switched<F, Fut>(
            holds_lease: bool,
            console_will_spell: bool,
            case: F,
        ) -> Ran
        where
            F: FnOnce(Case) -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            run_with(
                Setup {
                    holds_lease,
                    console_will_spell,
                    owns_geometry: false,
                    sized: false,
                },
                case,
            )
            .await
        }

        /// Runs the loop on a pseudo-terminal whose size the case changes, with the session's
        /// size the terminal's own or not.
        pub async fn run_sized<F, Fut>(owns_geometry: bool, case: F) -> Ran
        where
            F: FnOnce(Case) -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            run_with(
                Setup {
                    holds_lease: true,
                    console_will_spell: true,
                    owns_geometry,
                    sized: true,
                },
                case,
            )
            .await
        }

        /// How a run is set up.
        struct Setup {
            holds_lease: bool,
            console_will_spell: bool,
            owns_geometry: bool,
            sized: bool,
        }

        async fn run_with<F, Fut>(setup: Setup, case: F) -> Ran
        where
            F: FnOnce(Case) -> Fut,
            Fut: std::future::Future<Output = ()>,
        {
            let Setup {
                holds_lease,
                console_will_spell,
                owns_geometry,
                sized,
            } = setup;
            let (sent, written) = mpsc::unbounded_channel();
            let (answers, heard) = mpsc::unbounded_channel();
            let (console, mut input) = mpsc::unbounded_channel();
            let log = Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut wire = Wire {
                sent,
                log: Arc::clone(&log),
                heard,
            };
            let device = std::fs::File::options()
                .read(true)
                .write(true)
                .open("/dev/null")
                .expect("a device to hold the place of a terminal");
            // A terminal that has a size is a pseudo-terminal the case holds the other end of.
            let (terminal, sized, _slave, mut changes) = if sized {
                let pty = portable_pty::native_pty_system()
                    .openpty(portable_pty::PtySize {
                        rows: 24,
                        cols: 80,
                        pixel_width: 0,
                        pixel_height: 0,
                    })
                    .expect("opens a terminal");
                let name = pty.master.tty_name().expect("the terminal has a name");
                let handle = std::fs::File::options()
                    .read(true)
                    .write(true)
                    .open(name)
                    .expect("opens the terminal");
                let changes =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                        .expect("a stream of size changes");
                (
                    ControllingTerminal::over(handle),
                    Some(SizedTerminal { master: pty.master }),
                    Some(pty.slave),
                    Some(changes),
                )
            } else {
                (
                    ControllingTerminal::over(device.try_clone().expect("a duplicate")),
                    None,
                    None,
                    None,
                )
            };
            // What the loop writes to the terminal is kept for the case to read.
            let written_to = tempfile::tempfile().expect("a file for what the loop writes");
            let output = Arc::new(written_to.try_clone().expect("a duplicate"));
            let attaching = Attaching {
                session_id: SessionId::new(Uuid::from_bytes([1; 16])),
                environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
                display_number: DisplayNumber::new(1),
            };
            let attached = Attached {
                attachment_id: AttachmentId::new(Uuid::from_bytes([3; 16])),
                dimensions: Dimensions::new(80, 24),
                lease_epoch: holds_lease.then(|| InputLeaseEpoch::new(5)),
                geometry_epoch: kr_protocol::ids::GeometryEpoch::new(1),
                owns_geometry,
            };
            let mut owed = UndeliveredTyping::new(0);
            let mut display = crate::render::ProjectedDisplay::new();
            let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let counted = Arc::clone(&asked);
            let switch = crate::attach::InputSwitch::new(move || {
                counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if console_will_spell {
                    Ok(())
                } else {
                    Err(CliError::Terminal(kr_client::shown::Shown::said(
                        "the console refused",
                    )))
                }
            });
            let mut fallback = super::super::Fallback::default();
            // Held until the loop has ended: a wire the case let go of reads as a connection lost,
            // and the loop looks at the worker's side first.
            let keep_open = answers.clone();
            let sized = sized.map(std::rc::Rc::new);
            let keep_sized = sized.clone();
            let case = case(Case {
                console: Some(console),
                written,
                answers,
                asked,
                sized,
            });
            let (outcome, ()) = tokio::join!(
                super::super::drive(
                    &mut wire,
                    &attaching,
                    &mut owed,
                    Vec::new(),
                    attached,
                    &mut input,
                    &output,
                    &terminal,
                    changes.as_mut(),
                    &mut display,
                    false,
                    &switch,
                    &mut fallback,
                ),
                case
            );
            drop(keep_open);
            drop(keep_sized);
            let sent = log.lock().expect("the log is not poisoned").clone();
            let written = {
                use std::io::{Read, Seek};
                let mut file = written_to;
                let mut written = Vec::new();
                file.rewind().expect("the start of what was written");
                file.read_to_end(&mut written).expect("what was written");
                written
            };
            Ran {
                outcome,
                said: super::super::after_the_reader_stops(
                    crate::attach::Stopped::default(),
                    &mut fallback,
                    &mut input,
                ),
                sent,
                written,
            }
        }
    }

    /// An application that typed a key (not a modifier, a lock or a release) before the session
    /// began to close is refused, and the line that ends the attachment says so. A key coming up is
    /// not typing: the session refusing it lost nothing the person typed.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn only_typing_the_closing_session_refused_is_said_to_be_undelivered() {
        use kr_term::win32::KeyRecord;

        let key = |key_down: bool| KeyRecord {
            virtual_key: u16::from(b'A'),
            scan_code: 0x1e,
            unicode: u16::from(b'a'),
            key_down,
            control_keys: 0,
            repeat: 1,
        };
        let keys = |down: bool| crate::attach::TerminalInput::Keys(vec![key(down)]);

        // The release is the write the session refuses: the press before it was taken.
        let outcome = wire::run(true, |mut case| async move {
            let pressed = case.types(keys(true)).await;
            case.takes(&pressed);
            let released = case.types(keys(false)).await;
            case.refuses(&released, ErrorCode::SessionClosed);
            case.closes();
        })
        .await;
        assert!(
            matches!(
                outcome,
                AttachOutcome::Closed {
                    undelivered: false,
                    ..
                }
            ),
            "a release refused by a closing session lost nothing: {outcome:?}"
        );

        // The control: the press is the write the session refuses.
        let outcome = wire::run(true, |mut case| async move {
            let pressed = case.types(keys(true)).await;
            case.refuses(&pressed, ErrorCode::SessionClosed);
            case.closes();
        })
        .await;
        assert!(
            matches!(
                outcome,
                AttachOutcome::Closed {
                    undelivered: true,
                    ..
                }
            ),
            "a key pressed and refused by a closing session was typing lost: {outcome:?}"
        );
    }

    /// A new subscription the session refuses for now has changed nothing: the stream being replaced
    /// goes on, and the subscription is asked for again after the pause the retry policy gives,
    /// whether or not the session says anything meanwhile, three times at most, after which the
    /// attachment ends. A refusal in the session's definite word, or an answer that cannot say what
    /// became of the request, ends it at the first. The clock is stopped, so the pauses cost
    /// nothing and the case reads the time that passed.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn a_subscription_the_session_refuses_for_now_is_asked_for_again_after_the_policys_pause()
    {
        use kr_client::retry::RETRY_BACKOFF_MIN;
        use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue};
        use kr_protocol::error::ProtocolError;

        let refusing = |code| Outcome::Error(ProtocolError::new(code, "refused by the case"));
        let asked_of = |sent: &[ControlFrame]| {
            sent.iter()
                .filter(|frame| {
                    matches!(frame, ControlFrame::Request(request)
                        if request.method == Method::EventsSubscribe.into())
                })
                .count()
        };

        // Refused for now, then taken: the session says nothing in between, since a session that
        // sent a resynchronisation marker says nothing more until it is asked for the screen.
        let ran = wire::run_switched(true, true, |mut case| async move {
            case.says_output(0);
            case.says_resync(1);
            let first = case.next_request_asked(Method::EventsSubscribe).await;
            let refused_at = tokio::time::Instant::now();
            case.answers_with(first, refusing(ErrorCode::ResourceUnavailable));
            let second = case.next_request_asked(Method::EventsSubscribe).await;
            assert_ne!(second, first, "it is another request");
            assert!(
                refused_at.elapsed() >= RETRY_BACKOFF_MIN,
                "it is not asked again at once"
            );
            case.answers_with(second, Outcome::Ok(ParamsValue::empty()));
            case.closes();
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Closed { .. }),
            "{:?}",
            ran.outcome
        );
        assert_eq!(asked_of(&ran.sent), 2);

        // Refused for now at every asking: three askings after the first, and the attachment ends
        // at the refusal of the fourth. A subscription the session took gave the policy's budget
        // back: the same count holds for the next one, after a refusal and a taking before it.
        let ran = wire::run_switched(true, true, |mut case| async move {
            case.says_output(0);
            case.says_resync(1);
            for _ in 0..4 {
                let asked = case.next_request_asked(Method::EventsSubscribe).await;
                case.answers_with(asked, refusing(ErrorCode::ResourceUnavailable));
            }
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Disconnected),
            "{:?}",
            ran.outcome
        );
        assert_eq!(asked_of(&ran.sent), 4);

        let ran = wire::run_switched(true, true, |mut case| async move {
            case.says_output(0);
            case.says_resync(1);
            let refused = case.next_request_asked(Method::EventsSubscribe).await;
            case.answers_with(refused, refusing(ErrorCode::ResourceUnavailable));
            let taken = case.next_request_asked(Method::EventsSubscribe).await;
            case.answers_with(taken, Outcome::Ok(ParamsValue::empty()));
            // The new stream begins, and later the session asks for a screen again.
            case.says_output(0);
            case.says_resync(1);
            for _ in 0..4 {
                let asked = case.next_request_asked(Method::EventsSubscribe).await;
                case.answers_with(asked, refusing(ErrorCode::ResourceUnavailable));
            }
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Disconnected),
            "{:?}",
            ran.outcome
        );
        assert_eq!(
            asked_of(&ran.sent),
            6,
            "two for the first, four for the second"
        );

        // The controls: the session's definite word, and an answer that cannot say what became of
        // the request, end the attachment at the first.
        for code in [ErrorCode::PermissionDenied, ErrorCode::OutcomeUnknown] {
            let ran = wire::run_switched(true, true, |mut case| async move {
                case.says_output(0);
                case.says_resync(1);
                let asked = case.next_request_asked(Method::EventsSubscribe).await;
                case.answers_with(asked, refusing(code));
            })
            .await;
            assert!(
                matches!(ran.outcome, AttachOutcome::Disconnected),
                "{code:?}: {:?}",
                ran.outcome
            );
            assert_eq!(asked_of(&ran.sent), 1, "{code:?}");
        }
    }

    /// The attach loop, on a terminal whose size changes, asks the session again about a size it did
    /// not take for now: a viewport report of a terminal that does not own the size goes again with
    /// the session's next word, and a resize of the owner goes again as the question that says what
    /// size the session has, answered by a resize if the session is at another. A resize of the
    /// owner that ends in a word that cannot say what became of it is not made again, and no
    /// question is asked in its place: an unknown outcome is not retryable, whatever the terminal
    /// is signalled for or told of the size's owner meanwhile. The cases are one test, since a size
    /// change is a signal to the whole process.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_size_the_session_did_not_take_for_now_is_asked_about_when_it_says_something() {
        use kr_protocol::attachment::{
            AttachmentViewportParams, AttachmentViewportResult, GeometryState,
            TerminalPresentationMode, TerminalResizeParams,
        };
        use kr_protocol::envelope::{ControlFrame, Outcome};
        use kr_protocol::error::ProtocolError;
        use kr_protocol::ids::{AttachmentId, GeometryEpoch};
        use kr_protocol::scalars::Uuid;

        let not_now = || {
            Outcome::Error(ProtocolError::new(
                ErrorCode::ResourceUnavailable,
                "the session cannot take it now",
            ))
        };

        // A terminal that does not own the size reports it. The session refuses the report for
        // now and rests it; the next thing the session says lets it go again.
        let ran = wire::run_sized(false, |mut case| async move {
            case.says_output(0);
            case.terminal().changes_to(100, 30);
            let (first, params) = case.next_mutation_asked(Method::AttachmentViewport).await;
            let params: AttachmentViewportParams = params.to_typed().expect("a report");
            assert_eq!(params.dimensions, size(100, 30));
            case.answers_with(first, not_now());
            case.says_output(1);
            let (second, params) = case.next_mutation_asked(Method::AttachmentViewport).await;
            let params: AttachmentViewportParams = params.to_typed().expect("a report");
            assert_ne!(second, first, "it is another request");
            assert_eq!(params.dimensions, size(100, 30), "of the size it is owed");
            case.closes();
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Closed { .. }),
            "{:?}",
            ran.outcome
        );

        // What the session says of its size when asked: it is the owner's, and still at the old size.
        let attachment_id = AttachmentId::new(Uuid::from_bytes([3; 16]));
        let at_the_old_size = move || {
            Outcome::Ok(
                kr_protocol::envelope::ParamsValue::from_typed(&AttachmentViewportResult {
                    geometry: GeometryState {
                        owner: Nullable::some(attachment_id),
                        epoch: GeometryEpoch::new(1),
                        dimensions: size(80, 24),
                    },
                    presentation: TerminalPresentationMode::Direct,
                    presentation_reason: Nullable::null(),
                    position: Nullable::null(),
                    column: U64::ZERO,
                    window_revision: U64::new(1),
                })
                .expect("an answer"),
            )
        };

        // The owner of the size resizes the session. The session refuses the resize for now, and
        // the terminal asks what size it has; it is at the old one, so the owner resizes again.
        let ran = wire::run_sized(true, |mut case| async move {
            case.says_output(0);
            case.terminal().changes_to(100, 30);
            let (resize, params) = case.next_mutation_asked(Method::TerminalResize).await;
            let params: TerminalResizeParams = params.to_typed().expect("a resize");
            assert_eq!(params.dimensions, size(100, 30));
            case.answers_with(resize, not_now());
            case.says_output(1);
            let (question, params) = case.next_mutation_asked(Method::AttachmentViewport).await;
            let params: AttachmentViewportParams = params.to_typed().expect("a report");
            assert_eq!(params.dimensions, size(100, 30));
            case.answers_with(question, at_the_old_size());
            let (again, params) = case.next_mutation_asked(Method::TerminalResize).await;
            let params: TerminalResizeParams = params.to_typed().expect("a resize");
            assert_ne!(again, resize, "it is another request");
            assert_eq!(params.dimensions, size(100, 30));
            assert_eq!(params.expected_geometry_epoch, GeometryEpoch::new(1));
            case.closes();
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Closed { .. }),
            "{:?}",
            ran.outcome
        );

        // The owner's resize ends in a word that cannot say what became of it. It may have been
        // dispatched, so it is not made again, and nothing is asked in its place: a viewport
        // report is a write of the window the session keeps for this terminal, not a read.
        let sent_with = |sent: &[ControlFrame], method: Method| {
            sent.iter()
                .filter(|frame| {
                    matches!(frame, ControlFrame::Mutation(mutation)
                        if mutation.method == method.into())
                })
                .count()
        };
        let ran = wire::run_sized(true, |mut case| async move {
            case.says_output(0);
            case.terminal().changes_to(100, 30);
            let (resize, _) = case.next_mutation_asked(Method::TerminalResize).await;
            case.answers_with(
                resize,
                Outcome::Error(ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    "the host cannot say",
                )),
            );
            case.says_output(1);
            case.closes();
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Closed { .. }),
            "{:?}",
            ran.outcome
        );
        assert_eq!(
            sent_with(&ran.sent, Method::TerminalResize),
            1,
            "the resize is not made again"
        );
        assert_eq!(
            sent_with(&ran.sent, Method::AttachmentViewport),
            0,
            "and no report is made in its place"
        );

        // The owner resizes twice, and the session answers the older resize late, saying somebody
        // else owns the size. The terminal is then signalled for the size the newer resize asked
        // for, which is no newer resize, and the session cannot say what became of that one. The
        // next answer shows the terminal as the owner of a session at the old size, and the resize
        // that may have been taken is not made a third time.
        let ran = wire::run_sized(true, |mut case| async move {
            case.says_output(0);
            case.terminal().changes_to(100, 30);
            let (older, _) = case.next_mutation_asked(Method::TerminalResize).await;
            case.terminal().changes_to(90, 20);
            let (newer, params) = case.next_mutation_asked(Method::TerminalResize).await;
            let params: TerminalResizeParams = params.to_typed().expect("a resize");
            assert_eq!(params.dimensions, size(90, 20));
            case.answers_with(
                older,
                Outcome::Error(ProtocolError::new(
                    ErrorCode::GeometryNotOwner,
                    "somebody else owns the size",
                )),
            );
            // The terminal asks who owns the size, and the session cannot take that for now, so
            // the terminal rests: what makes it report again is the signal, which shows the loop
            // has read the signal before the newer resize is answered.
            let (question, _) = case.next_mutation_asked(Method::AttachmentViewport).await;
            case.answers_with(question, not_now());
            case.terminal().changes_to(90, 20);
            let (report, params) = case.next_mutation_asked(Method::AttachmentViewport).await;
            let params: AttachmentViewportParams = params.to_typed().expect("a report");
            assert_eq!(params.dimensions, size(90, 20));
            case.answers_with(
                newer,
                Outcome::Error(ProtocolError::new(
                    ErrorCode::OutcomeUnknown,
                    "the host cannot say",
                )),
            );
            case.answers_with(report, at_the_old_size());
            case.closes();
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Closed { .. }),
            "{:?}",
            ran.outcome
        );
        assert_eq!(
            sent_with(&ran.sent, Method::TerminalResize),
            2,
            "the resize that ended unknown is not made again"
        );
    }

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

    /// A command run to hold its window on failure waits for a key after an attachment that ended
    /// in a failure, and not after a detach, a clean close or its shell exiting, which is how the
    /// person ended it, whatever the status.
    #[test]
    fn only_a_failure_that_is_not_the_shell_exiting_holds_the_window() {
        let closed = |record| AttachOutcome::Closed {
            record: Box::new(record),
            undelivered: false,
        };
        assert!(!AttachOutcome::Detached.holds_the_window());
        assert!(!closed(closure(ClosureReason::CloseRequested, None, None)).holds_the_window());
        assert!(!closed(closure(ClosureReason::RootExit, Some(0), None)).holds_the_window());
        assert!(
            !closed(closure(ClosureReason::RootExit, Some(7), None)).holds_the_window(),
            "a shell that exited with a status is how the person ended the session"
        );
        assert!(closed(closure(ClosureReason::WorkerCrash, None, None)).holds_the_window());
        assert!(AttachOutcome::Disconnected.holds_the_window());
        assert!(AttachOutcome::LeaseLost.holds_the_window());
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

    /// An attachment whose session refused the bytes it sent as unable to take them in the
    /// encoding the session is in ends as a refusal with the status of one, and says how to go on
    /// watching.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn bytes_the_session_refused_as_incompatible_end_the_attachment_as_a_refusal() {
        let outcome = wire::run(true, |mut case| async move {
            let typed = case
                .types(crate::attach::TerminalInput::Bytes(b"x".to_vec()))
                .await;
            case.refuses(&typed, ErrorCode::InputIncompatible);
        })
        .await;
        assert!(
            matches!(outcome, AttachOutcome::InputRefused(_)),
            "{outcome:?}"
        );
        assert!(outcome.is_failure());
        assert_eq!(
            status(&outcome),
            CliError::Refused(refusal(ErrorCode::InputIncompatible, Shown::said(""))).exit_code()
        );
        assert!(outcome.detail().as_str().contains("--no-probe"));
    }

    /// Bytes as a case reads them in a failure.
    #[cfg(unix)]
    fn shown(bytes: &[u8]) -> String {
        bytes.escape_ascii().to_string()
    }

    /// What a terminal is written after output depends on whether the output is the screen the
    /// session drew for it or what the application wrote: the first delivery of a subscription is
    /// that screen, which a terminal is drawn as it is, and the output after it is the application's
    /// own, after which a terminal that returns the default at a reset of either encoding is put in
    /// the encoding the session holds. A gap notice is not a delivery of the screen, and a new
    /// subscription begins a new one.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn the_first_delivery_of_a_subscription_is_read_as_a_restoration_and_later_output_as_live()
     {
        const SCREEN: &[u8] = b"\x1b[?1000h\x1b[?1006h\x1b[?1005l";
        let follow = crate::mouse::Follow {
            at: 0,
            encoding: 1006,
        }
        .bytes();

        // The same bytes as the first delivery and as the second.
        let ran = wire::run_switched(true, true, |case| async move {
            case.says_output_bytes(0, SCREEN);
            case.says_output_bytes(1, SCREEN);
            case.closes();
        })
        .await;
        assert_eq!(
            shown(&ran.written),
            shown(&[SCREEN, SCREEN, &follow].concat())
        );

        // A gap notice before the screen is not the screen.
        let ran = wire::run_switched(true, true, |case| async move {
            case.says_gap(0);
            case.says_output_bytes(1, SCREEN);
            case.says_output_bytes(2, SCREEN);
            case.closes();
        })
        .await;
        assert_eq!(
            shown(&ran.written),
            shown(&[SCREEN, SCREEN, &follow].concat())
        );

        // A new subscription begins with a screen of its own.
        let ran = wire::run_switched(true, true, |case| async move {
            case.says_output_bytes(0, SCREEN);
            case.says_output_bytes(1, SCREEN);
            case.says_resync(2);
            case.says_output_bytes(0, SCREEN);
            case.says_output_bytes(1, SCREEN);
            case.closes();
        })
        .await;
        assert_eq!(
            shown(&ran.written),
            shown(&[SCREEN, SCREEN, &follow, SCREEN, SCREEN, &follow].concat())
        );
    }

    /// After a hole in the stream, the state the reader holds is not trusted: a frame the bridge shed
    /// may have carried a reset or a set, so the output of the old subscription that follows the
    /// marker is read as drawn, with nothing written after it, until the first frame of the new
    /// subscription's screen. A terminal that returns the default at a reset of either encoding is
    /// not put in an encoding the session may no longer hold. The screen's own modes arrive, and what
    /// the application writes after it is read as live again.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn output_of_the_old_subscription_after_a_hole_is_written_no_follow_up() {
        let follow_1006 = crate::mouse::Follow {
            at: 0,
            encoding: 1006,
        }
        .bytes();

        // A reset of 1006 is shed, and the output that follows it resets 1005.
        let ran = wire::run_switched(true, true, |case| async move {
            case.says_output_bytes(0, b"\x1b[?1000h\x1b[?1006h");
            case.says_resync(2);
            case.says_output_bytes(3, b"\x1b[?1005l");
            case.says_output_bytes(0, b"\x1b[?1000h\x1b[?1005;1006l");
            case.says_output_bytes(1, b"\x1b[?1006h\x1b[?1005l");
            case.closes();
        })
        .await;
        assert_eq!(
            shown(&ran.written),
            shown(
                &[
                    &b"\x1b[?1000h\x1b[?1006h"[..],
                    b"\x1b[?1005l",
                    b"\x1b[?1000h\x1b[?1005;1006l",
                    // The new subscription's output is read as live again.
                    b"\x1b[?1006h\x1b[?1005l",
                    &follow_1006,
                ]
                .concat()
            )
        );

        // A set of 1006 is shed while 1005 is held, and the output that follows it resets 1006.
        let follow_1005 = crate::mouse::Follow {
            at: 0,
            encoding: 1005,
        }
        .bytes();
        let ran = wire::run_switched(true, true, |case| async move {
            case.says_output_bytes(0, b"\x1b[?1000h\x1b[?1005h");
            case.says_resync(2);
            case.says_output_bytes(3, b"\x1b[?1006l");
            case.says_output_bytes(0, b"\x1b[?1000h\x1b[?1005;1006l\x1b[?1006h");
            case.says_output_bytes(1, b"\x1b[?1005h\x1b[?1006l");
            case.closes();
        })
        .await;
        assert_eq!(
            shown(&ran.written),
            shown(
                &[
                    &b"\x1b[?1000h\x1b[?1005h"[..],
                    b"\x1b[?1006l",
                    b"\x1b[?1000h\x1b[?1005;1006l\x1b[?1006h",
                    b"\x1b[?1005h\x1b[?1006l",
                    &follow_1005,
                ]
                .concat()
            )
        );

        // A frame that cannot be decoded is a hole too, and nothing closes it but a screen.
        let ran = wire::run_switched(true, true, |case| async move {
            case.says_output_bytes(0, b"\x1b[?1000h\x1b[?1006h");
            case.says_output_it_cannot_decode(1);
            case.says_output_bytes(2, b"\x1b[?1005l");
            case.closes();
        })
        .await;
        assert_eq!(
            shown(&ran.written),
            shown(b"\x1b[?1000h\x1b[?1006h\x1b[?1005l")
        );
    }

    /// A first delivery that cannot be decoded is not drawn and does not use up the first delivery:
    /// the next one that decodes is still the screen the session drew for the terminal.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_delivery_that_cannot_be_decoded_does_not_use_up_the_first() {
        const SCREEN: &[u8] = b"\x1b[?1000h\x1b[?1006h\x1b[?1005l";
        let follow = crate::mouse::Follow {
            at: 0,
            encoding: 1006,
        }
        .bytes();
        let ran = wire::run_switched(true, true, |case| async move {
            case.says_output_it_cannot_decode(0);
            case.says_output_bytes(1, SCREEN);
            case.says_output_bytes(2, SCREEN);
            case.closes();
        })
        .await;
        assert_eq!(
            shown(&ran.written),
            shown(&[SCREEN, SCREEN, &follow].concat())
        );
    }

    /// The report of a click that is sent behind console keys the session refuses is no more read
    /// than the keys behind them are: the host cannot place it under the number it was sent with and
    /// says so, which is no reason to end the attachment once the console spells its keys. Shift
    /// going down is not typing and neither is a click, so nothing is said to have been lost.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_click_sent_behind_console_keys_the_session_refuses_does_not_end_the_attachment() {
        use kr_protocol::input::InputContent;

        let ran = wire::run_switched(true, true, |mut case| async move {
            // The application has asked for clicks, and Shift going down and a click are on their
            // way when the host refuses the key.
            case.says_output_bytes(0, b"\x1b[?1000h\x1b[?1006h");
            let key = case.types(key_down(0x10)).await;
            let click = case
                .types(crate::attach::TerminalInput::Mouse(
                    crate::mouse::MouseRecord {
                        column: 1,
                        row: 1,
                        buttons: 1,
                        control_keys: 0,
                        flags: 0,
                    },
                ))
                .await;
            assert_eq!((key.sequence, click.sequence), (0, 1));
            assert!(matches!(click.content, InputContent::Bytes { .. }));
            case.refuses(&key, ErrorCode::InputIncompatible);
            case.refuses(&click, ErrorCode::InvalidArgument);
            assert_eq!(case.waits_for_the_console_to_be_asked().await, 1);

            let typed = case
                .types(crate::attach::TerminalInput::Bytes(b"c".to_vec()))
                .await;
            assert_eq!(
                typed.sequence, key.sequence,
                "the refused write took no number"
            );
            case.takes(&typed);
            case.hangs_up();
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Detached),
            "{:?}",
            ran.outcome
        );
        assert_eq!(ran.said.len(), 1, "{:?}", ran.said);
        assert!(
            ran.said[0].as_str().contains("this console spells"),
            "{:?}",
            ran.said[0]
        );
        assert!(
            !ran.said[0].as_str().contains("were lost"),
            "Shift going down and a click are not typing: {:?}",
            ran.said[0]
        );
    }

    /// What the command's own painter draws never takes the reading that is for a restoration of an
    /// earlier worker: a reset of a tracking mode that is not on, in a screen it drew, turns tracking
    /// off.
    #[cfg(unix)]
    #[test]
    fn what_the_painter_draws_turns_tracking_off_at_a_reset_of_a_mode_that_is_not_on() {
        let device = std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("a device to hold the place of a terminal");
        let terminal = crate::terminal::ControllingTerminal::over(device);
        let mut mouse = super::ConsoleMouse::default();
        mouse.shown(
            b"\x1b[?1003h",
            &terminal,
            true,
            crate::mouse::Reading::Restoration,
        );
        assert_eq!(mouse.reporting.tracking(), crate::mouse::Tracking::Motion);
        mouse.painted(b"\x1b[?1002l", &terminal, true);
        assert_eq!(mouse.reporting.tracking(), crate::mouse::Tracking::Off);
    }

    /// A mouse record that arrives after the application stopped asking for the mouse, because the
    /// console had queued it before it stopped reporting, tells the application nothing and leaves no
    /// button held: when the application asks again, the next press is a press.
    #[cfg(unix)]
    #[test]
    fn a_record_queued_before_the_mouse_was_given_back_leaves_no_button_held() {
        let device = std::fs::File::options()
            .read(true)
            .write(true)
            .open("/dev/null")
            .expect("a device to hold the place of a terminal");
        let terminal = crate::terminal::ControllingTerminal::over(device);
        let press = crate::mouse::MouseRecord {
            column: 1,
            row: 1,
            buttons: 1,
            control_keys: 0,
            flags: 0,
        };
        let mut mouse = super::ConsoleMouse::default();

        mouse.shown(
            b"\x1b[?1000h\x1b[?1006h",
            &terminal,
            true,
            crate::mouse::Reading::Live,
        );
        assert_eq!(
            mouse.spelled(press, &terminal, true),
            b"\x1b[<0;2;2M".to_vec()
        );
        mouse.shown(b"\x1b[?1000l", &terminal, true, crate::mouse::Reading::Live);
        assert!(
            mouse.spelled(press, &terminal, true).is_empty(),
            "a record after the application stopped asking is told to nobody"
        );
        mouse.shown(b"\x1b[?1000h", &terminal, true, crate::mouse::Reading::Live);
        assert_eq!(
            mouse.spelled(press, &terminal, true),
            b"\x1b[<0;2;2M".to_vec(),
            "the button the console reported down before the mouse was given back is not held"
        );
    }

    /// The session cannot spell the records of a console whose application has negotiated an
    /// encoding they cannot express, and refuses them. The attachment keeps its lease and goes on
    /// typing, as the console spells the keys and as bytes: the keys that were refused are not sent
    /// again, the writes sent behind them are not read, and the next write takes the number the
    /// refused one was sent under, which the host never took.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_refusal_of_console_keys_turns_the_attachment_to_the_bytes_the_console_spells() {
        use kr_protocol::input::InputContent;

        let ran = wire::run_switched(true, true, |mut case| async move {
            // Two batches of records are on their way when the host refuses the first. The host
            // cannot place the second under the number it was sent with, and says so.
            let first = case.types(key_down(b'A')).await;
            let second = case.types(key_down(b'B')).await;
            assert_eq!((first.sequence, second.sequence), (0, 1));
            case.refuses(&first, ErrorCode::InputIncompatible);
            case.refuses(&second, ErrorCode::InvalidArgument);
            assert_eq!(case.waits_for_the_console_to_be_asked().await, 1);

            let typed = case
                .types(crate::attach::TerminalInput::Bytes(b"c".to_vec()))
                .await;
            assert_eq!(
                typed.sequence, first.sequence,
                "the refused write took no number"
            );
            assert!(matches!(typed.content, InputContent::Bytes { .. }));
            case.takes(&typed);
            // A batch of records the reader had read before the console began to spell its keys
            // reaches the loop now, and is not sent.
            case.types_without_waiting(key_down(b'D'));
            let next = case
                .types(crate::attach::TerminalInput::Bytes(b"e".to_vec()))
                .await;
            assert_eq!(next.sequence, typed.sequence + 1);
            case.takes(&next);
            case.hangs_up();
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Detached),
            "{:?}",
            ran.outcome
        );
        assert_eq!(
            ran.said.len(),
            1,
            "the person is told once, after the terminal is theirs again: {:?}",
            ran.said
        );
        assert!(ran.said[0].as_str().contains("this console spells"));
        assert!(
            ran.said[0].as_str().contains("were lost"),
            "a letter was typed when the session refused the records: {:?}",
            ran.said[0]
        );
        assert!(
            wire::released_in(&ran.sent).is_empty(),
            "the lease is kept while the console spells the keys"
        );
        assert_eq!(
            wire::writes_in(&ran.sent).len(),
            4,
            "the two records, then two byte writes"
        );
    }

    /// A console that will not spell its keys cannot be typed at once the session has refused its
    /// records: the attachment hands the lease back, goes on watching, and says so afterwards.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_console_that_will_not_spell_its_keys_hands_the_lease_back_and_watches() {
        let ran = wire::run_switched(true, false, |mut case| async move {
            let first = case.types(key_down(b'A')).await;
            case.refuses(&first, ErrorCode::InputIncompatible);
            case.next_mutation(Method::InputRelease).await;
            // What is typed now is dropped and not sent, and the attachment goes on.
            case.types_without_waiting(crate::attach::TerminalInput::Bytes(b"x".to_vec()));
            case.types_without_waiting(key_down(b'B'));
            case.hangs_up();
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Detached),
            "{:?}",
            ran.outcome
        );
        let released = wire::released_in(&ran.sent);
        assert_eq!(released.len(), 1, "the lease goes back once");
        assert_eq!(
            released[0].epoch.get(),
            5,
            "and it is the one the attachment held"
        );
        assert_eq!(
            wire::writes_in(&ran.sent).len(),
            1,
            "nothing is sent after the refusal"
        );
        assert_eq!(ran.said.len(), 1);
        assert!(ran.said[0].as_str().contains("would not spell its keys"));
        assert!(ran.said[0].as_str().contains("--no-probe"));
    }

    /// What the line after a refusal of console keys says, for a case that ends once the console has
    /// been asked, with how the attachment ended and every frame it sent.
    #[cfg(unix)]
    async fn after_a_refusal<F, Fut>(console_will_spell: bool, case: F) -> wire::Ran
    where
        F: FnOnce(wire::Case) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let ran = wire::run_switched(true, console_will_spell, case).await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Detached),
            "{:?}",
            ran.outcome
        );
        assert_eq!(ran.said.len(), 1, "one line: {:?}", ran.said);
        ran
    }

    /// A modifier going down at the console, which is no typing.
    #[cfg(unix)]
    fn shift_down() -> crate::attach::TerminalInput {
        crate::attach::TerminalInput::Keys(vec![kr_term::win32::KeyRecord {
            virtual_key: super::VK_SHIFT,
            scan_code: 0x2a,
            unicode: 0,
            key_down: true,
            control_keys: 0x10,
            repeat: 1,
        }])
    }

    /// The line after a refusal of console keys says keys were lost only when a typed key was, and
    /// names where it was lost: the batch the session refused, a write sent behind it, or a record
    /// already read. A modifier on its own is none of these, and the session refusing it lost
    /// nothing.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn the_line_after_a_refusal_says_keys_were_lost_only_when_a_typed_key_was() {
        // What the line names, for a console that spells its keys and for one that will not.
        for (console_will_spell, batch, behind, read) in [
            (
                true,
                "the batch it refused",
                "writes sent behind that batch",
                "records this command had already read",
            ),
            (
                false,
                "the batch it refused",
                "writes sent behind that batch",
                "the keys read since",
            ),
        ] {
            // Only a modifier was refused, and nothing else was typed.
            let ran = after_a_refusal(console_will_spell, |mut case| async move {
                let shift = case.types(shift_down()).await;
                case.refuses(&shift, ErrorCode::InputIncompatible);
                case.waits_for_the_console_to_be_asked().await;
                case.hangs_up();
            })
            .await;
            assert!(
                !ran.said[0].as_str().contains("lost"),
                "nothing typed was lost ({console_will_spell}): {:?}",
                ran.said[0]
            );

            // The batch the session refused was a letter.
            let ran = after_a_refusal(console_will_spell, |mut case| async move {
                let letter = case.types(key_down(b'A')).await;
                case.refuses(&letter, ErrorCode::InputIncompatible);
                case.waits_for_the_console_to_be_asked().await;
                case.hangs_up();
            })
            .await;
            assert!(
                ran.said[0].as_str().contains("were lost") && ran.said[0].as_str().contains(batch),
                "the refused batch was typed ({console_will_spell}): {:?}",
                ran.said[0]
            );

            // A letter was written behind the modifier the session refused. The writes sent as
            // records behind a refused one are not read.
            let ran = after_a_refusal(console_will_spell, |mut case| async move {
                let shift = case.types(shift_down()).await;
                let behind_it = case.types(key_down(b'B')).await;
                case.refuses(&shift, ErrorCode::InputIncompatible);
                case.refuses(&behind_it, ErrorCode::InvalidArgument);
                case.waits_for_the_console_to_be_asked().await;
                case.hangs_up();
            })
            .await;
            assert!(
                ran.said[0].as_str().contains("were lost") && ran.said[0].as_str().contains(behind),
                "the write behind the refused one was typed ({console_will_spell}): {:?}",
                ran.said[0]
            );

            // A letter the reader had already read, and the loop had not yet taken, when the session
            // refused a modifier. It is dropped and counted, and no write is made of it.
            let ran = after_a_refusal(console_will_spell, |mut case| async move {
                let shift = case.types(shift_down()).await;
                case.types_without_waiting(key_down(b'D'));
                case.refuses(&shift, ErrorCode::InputIncompatible);
                case.waits_for_the_console_to_be_asked().await;
                case.hangs_up();
            })
            .await;
            assert!(
                ran.said[0].as_str().contains("were lost") && ran.said[0].as_str().contains(read),
                "the record already read was typed ({console_will_spell}): {:?}",
                ran.said[0]
            );
            assert_eq!(
                wire::writes_in(&ran.sent).len(),
                1,
                "only the modifier was written: the record already read is not sent"
            );

            // A modifier read since is no more typing than the one that was refused, whether the
            // loop took it or it was left in the channel when the session closed.
            let ran = after_a_refusal(console_will_spell, |mut case| async move {
                let shift = case.types(shift_down()).await;
                case.types_without_waiting(shift_down());
                case.refuses(&shift, ErrorCode::InputIncompatible);
                case.waits_for_the_console_to_be_asked().await;
                case.hangs_up();
            })
            .await;
            assert!(
                !ran.said[0].as_str().contains("lost"),
                "a modifier was read since ({console_will_spell}): {:?}",
                ran.said[0]
            );
            let ran = wire::run_switched(true, console_will_spell, |mut case| async move {
                let shift = case.types(shift_down()).await;
                case.types_without_waiting(shift_down());
                case.refuses(&shift, ErrorCode::InputIncompatible);
                case.closes();
            })
            .await;
            assert!(
                ran.said.len() == 1 && !ran.said[0].as_str().contains("lost"),
                "a modifier was left in the channel ({console_will_spell}): {:?}",
                ran.said
            );

            // A modifier was refused, and text composed with Alt on the numeric keypad was read
            // since: it is the person's text, dropped, and the line counts it.
            let ran = after_a_refusal(console_will_spell, |mut case| async move {
                let shift = case.types(shift_down()).await;
                case.types_without_waiting(alt_down());
                case.types_without_waiting(alt_composed());
                case.refuses(&shift, ErrorCode::InputIncompatible);
                case.waits_for_the_console_to_be_asked().await;
                case.hangs_up();
            })
            .await;
            assert!(
                ran.said[0].as_str().contains("were lost"),
                "text composed with Alt was read since ({console_will_spell}): {:?}",
                ran.said[0]
            );

            // The same letter, with the session's closure ready beside the refusal: the attachment
            // ends before the loop takes the letter, and the line still counts it.
            let ran = wire::run_switched(true, console_will_spell, |mut case| async move {
                let shift = case.types(shift_down()).await;
                case.types_without_waiting(key_down(b'D'));
                case.refuses(&shift, ErrorCode::InputIncompatible);
                case.closes();
            })
            .await;
            assert!(
                matches!(ran.outcome, AttachOutcome::Closed { .. }),
                "{:?}",
                ran.outcome
            );
            assert!(
                ran.said.len() == 1 && ran.said[0].as_str().contains("were lost"),
                "the letter left in the channel was typed ({console_will_spell}): {:?}",
                ran.said
            );
        }
    }

    /// The Alt going down that the composed character's Alt comes up from.
    #[cfg(unix)]
    fn alt_down() -> crate::attach::TerminalInput {
        crate::attach::TerminalInput::Keys(vec![kr_term::win32::KeyRecord {
            virtual_key: super::VK_MENU,
            scan_code: 0x38,
            unicode: 0,
            key_down: true,
            control_keys: 0x02,
            repeat: 1,
        }])
    }

    /// An Alt coming up with the character composed on the numeric keypad, as the console reports
    /// the text typed that way.
    #[cfg(unix)]
    fn alt_composed() -> crate::attach::TerminalInput {
        crate::attach::TerminalInput::Keys(vec![kr_term::win32::KeyRecord {
            virtual_key: super::VK_MENU,
            scan_code: 0x38,
            unicode: 0x00e9,
            key_down: false,
            control_keys: 0,
            repeat: 1,
        }])
    }

    /// A key going down at the console, as the case types it.
    #[cfg(unix)]
    fn key_down(code: u8) -> crate::attach::TerminalInput {
        key_going(code, true)
    }

    /// A key coming up at the console, as the case types it.
    #[cfg(unix)]
    fn key_up(code: u8) -> crate::attach::TerminalInput {
        key_going(code, false)
    }

    #[cfg(unix)]
    fn key_going(code: u8, key_down: bool) -> crate::attach::TerminalInput {
        crate::attach::TerminalInput::Keys(vec![kr_term::win32::KeyRecord {
            virtual_key: u16::from(code),
            scan_code: 0,
            unicode: u16::from(code.to_ascii_lowercase()),
            key_down,
            control_keys: 0,
            repeat: 1,
        }])
    }

    /// The virtual key and direction of each record of a write of console keys.
    #[cfg(unix)]
    fn records_of(content: &kr_protocol::input::InputContent) -> Vec<(u16, bool)> {
        match content {
            kr_protocol::input::InputContent::ConsoleKeys { keys } => keys
                .iter()
                .map(|key| (key.virtual_key, key.key_down))
                .collect(),
            other => panic!("not a write of console keys: {other:?}"),
        }
    }

    /// A key that came up at the console after going down before this command read it, the Return
    /// that started the command among them, is not sent: it never went down in the session. The
    /// release of a key this attachment did see go down is.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn the_loop_sends_no_release_for_a_key_whose_press_it_did_not_see() {
        const RETURN: u8 = 0x0d;
        let ran = wire::run_switched(true, true, |mut case| async move {
            case.types_without_waiting(key_up(RETURN));
            let pressed = case.types(key_down(b'A')).await;
            assert_eq!(
                (pressed.sequence, records_of(&pressed.content)),
                (0, vec![(u16::from(b'A'), true)]),
                "the first write is the press: the release of the Return was dropped"
            );
            case.takes(&pressed);
            let released = case.types(key_up(b'A')).await;
            assert_eq!(
                (released.sequence, records_of(&released.content)),
                (1, vec![(u16::from(b'A'), false)]),
                "a key seen going down is sent coming up"
            );
            case.takes(&released);
            case.hangs_up();
        })
        .await;
        assert!(
            matches!(ran.outcome, AttachOutcome::Detached),
            "{:?}",
            ran.outcome
        );
    }

    /// A session that refuses a release first, and refuses a key pressed after it, is a session
    /// that lost typing: the refusal of the release began the closing, and the press was refused
    /// while the attachment was already closing.
    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn a_press_refused_after_a_release_by_a_closing_session_is_said_to_be_undelivered() {
        let outcome = wire::run(true, |mut case| async move {
            let pressed = case.types(key_down(b'A')).await;
            let released = case.types(key_up(b'A')).await;
            let behind = case.types(key_down(b'B')).await;
            case.takes(&pressed);
            case.refuses(&released, ErrorCode::SessionClosed);
            case.refuses(&behind, ErrorCode::SessionClosed);
            case.closes();
        })
        .await;
        assert!(
            matches!(
                outcome,
                AttachOutcome::Closed {
                    undelivered: true,
                    ..
                }
            ),
            "the press refused behind the release was typing lost: {outcome:?}"
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

    /// The same gesture from a console, which reports it as the records of the keys and not as a
    /// sequence, and not in one read: Shift going down, Page Up going down, Page Up coming up and
    /// Shift coming up each arrive on their own. The key is taken with its release, and what is
    /// not the chord is the session's wherever it arrives.
    #[test]
    fn the_scroll_keys_of_a_console_are_taken_key_by_key_and_the_rest_is_the_sessions() {
        use kr_term::win32::{KeyRecord, control_keys::SHIFT_PRESSED};

        let key = |virtual_key: u16, key_down: bool, control_keys: u32, repeat: u16| KeyRecord {
            virtual_key,
            scan_code: 0,
            unicode: 0,
            key_down,
            control_keys,
            repeat,
        };
        let mut held = Vec::new();

        // The modifier is the session's, going down and coming up.
        let shift_down = key(0x10, true, SHIFT_PRESSED, 1);
        let (rest, steps) = take_scroll_keys(vec![shift_down], &mut held, true);
        assert_eq!((rest, steps), (vec![shift_down], 0));
        // Page Up going down moves the window by its repeat count and is not the session's.
        let (rest, steps) =
            take_scroll_keys(vec![key(0x21, true, SHIFT_PRESSED, 3)], &mut held, true);
        assert_eq!((rest.len(), steps), (0, 3));
        // Its release arrives in a read of its own, and goes the same way.
        let (rest, steps) =
            take_scroll_keys(vec![key(0x21, false, SHIFT_PRESSED, 1)], &mut held, true);
        assert_eq!(
            (rest.len(), steps),
            (0, 0),
            "the release of a key taken is taken"
        );
        assert!(held.is_empty());
        let shift_up = key(0x10, false, 0, 1);
        let (rest, steps) = take_scroll_keys(vec![shift_up], &mut held, true);
        assert_eq!((rest, steps), (vec![shift_up], 0));

        // Page Down goes the other way.
        let (_, steps) = take_scroll_keys(vec![key(0x22, true, SHIFT_PRESSED, 1)], &mut held, true);
        assert_eq!(steps, -1);
        let _ = take_scroll_keys(vec![key(0x22, false, SHIFT_PRESSED, 1)], &mut held, true);

        // A key the chord shares a read with is not taken with it: a letter's release is the
        // session's, whatever is beside it.
        let a_up = key(u16::from(b'A'), false, SHIFT_PRESSED, 1);
        let (rest, steps) = take_scroll_keys(
            vec![a_up, key(0x21, true, SHIFT_PRESSED, 1)],
            &mut held,
            true,
        );
        assert_eq!((rest, steps), (vec![a_up], 1));
        let _ = take_scroll_keys(vec![key(0x21, false, SHIFT_PRESSED, 1)], &mut held, true);

        // Unshifted, it is the application's.
        let plain = key(0x21, true, 0, 1);
        let (rest, steps) = take_scroll_keys(vec![plain], &mut held, true);
        assert_eq!((rest, steps), (vec![plain], 0));
        let _ = take_scroll_keys(vec![key(0x21, false, 0, 1)], &mut held, true);
        // Where the chord is not this terminal's it is the session's too.
        let chord = key(0x21, true, SHIFT_PRESSED, 1);
        let (rest, steps) = take_scroll_keys(vec![chord], &mut held, false);
        assert_eq!((rest, steps), (vec![chord], 0));
        let _ = take_scroll_keys(vec![key(0x21, false, SHIFT_PRESSED, 1)], &mut held, false);
        assert!(held.is_empty());
    }

    /// The modifier can change while a scroll key is held, and the key goes where it went down:
    /// the session that was sent a key going down is sent its repeats and its release, and a key
    /// the window took is the window's until it comes up.
    #[test]
    fn a_scroll_key_held_goes_where_it_went_down_whatever_the_modifier_does_meanwhile() {
        use kr_term::win32::{KeyRecord, control_keys::SHIFT_PRESSED};

        let key = |key_down: bool, control_keys: u32| KeyRecord {
            virtual_key: 0x21,
            scan_code: 0,
            unicode: 0,
            key_down,
            control_keys,
            repeat: 1,
        };

        // Down without Shift, then Shift joins and the key repeats, then it comes up: all the
        // session's, so the application sees a key go down and come up.
        let mut held = Vec::new();
        let sent = [
            key(true, 0),
            key(true, SHIFT_PRESSED),
            key(false, SHIFT_PRESSED),
        ];
        let (rest, steps) = take_scroll_keys(sent.to_vec(), &mut held, true);
        assert_eq!(
            (rest, steps),
            (sent.to_vec(), 0),
            "the session is sent every record, in the order the console reported them"
        );
        assert!(held.is_empty());

        // Down with Shift, then Shift is let go and the key repeats, then it comes up: all the
        // window's, which moves for the repeat as well.
        let taken = [key(true, SHIFT_PRESSED), key(true, 0), key(false, 0)];
        let (rest, steps) = take_scroll_keys(taken.to_vec(), &mut held, true);
        assert_eq!((rest.len(), steps), (0, 2));
        assert!(held.is_empty());

        // Records of other keys among a held one's keep their order, and the held key's own go where
        // it went down.
        let other = |virtual_key: u16, key_down: bool| KeyRecord {
            virtual_key,
            ..key(key_down, 0)
        };
        let mixed = [
            other(0x41, true),
            key(true, 0),
            other(0x42, true),
            key(true, SHIFT_PRESSED),
            other(0x41, false),
            key(false, 0),
            other(0x42, false),
        ];
        let (rest, steps) = take_scroll_keys(mixed.to_vec(), &mut held, true);
        assert_eq!((rest, steps), (mixed.to_vec(), 0));
        assert!(held.is_empty());

        // The window stops being this terminal's part way through a hold: its repeats are dropped
        // and its release is taken.
        let (_, steps) = take_scroll_keys(vec![key(true, SHIFT_PRESSED)], &mut held, true);
        assert_eq!(steps, 1);
        let (rest, steps) = take_scroll_keys(
            vec![key(true, SHIFT_PRESSED), key(false, 0)],
            &mut held,
            false,
        );
        assert_eq!((rest.len(), steps), (0, 0));
        assert!(held.is_empty());
    }

    /// The Page Up of the cursor block and the one of the numeric keypad report one virtual key, and
    /// only the enhanced flag tells them apart. Each goes where it went down and comes up where it
    /// went down: the one held with Shift is the window's, the other, held without, is the session's,
    /// and neither one's release moves the other.
    #[test]
    fn two_scroll_keys_that_share_a_virtual_key_are_told_apart() {
        use kr_term::win32::{
            KeyRecord,
            control_keys::{ENHANCED_KEY, SHIFT_PRESSED},
        };

        let page_up = |key_down: bool, control_keys: u32| KeyRecord {
            virtual_key: super::VK_PRIOR,
            scan_code: 0x49,
            unicode: 0,
            key_down,
            control_keys,
            repeat: 1,
        };
        let block_down = page_up(true, ENHANCED_KEY | SHIFT_PRESSED);
        let block_up = page_up(false, ENHANCED_KEY);
        let keypad_down = page_up(true, 0);
        let keypad_up = page_up(false, 0);
        let mut held = Vec::new();

        // The block's key, with Shift, moves the window.
        let (rest, steps) = take_scroll_keys(vec![block_down], &mut held, true);
        assert_eq!((rest.len(), steps), (0, 1));
        // The keypad's, without Shift, is the application's, though the block's is still down.
        let (rest, steps) = take_scroll_keys(vec![keypad_down], &mut held, true);
        assert_eq!((rest, steps), (vec![keypad_down], 0));
        // The block's comes up first and is the window's; the keypad's release is the session's.
        let (rest, steps) = take_scroll_keys(vec![block_up], &mut held, true);
        assert_eq!((rest.len(), steps), (0, 0));
        let (rest, steps) = take_scroll_keys(vec![keypad_up], &mut held, true);
        assert_eq!((rest, steps), (vec![keypad_up], 0));
        assert!(held.is_empty());
    }

    /// A console reached over a remote desktop or a virtual keyboard reports its own scan code for a
    /// key, so two records with one virtual key and one enhanced flag can still be two keys. The one
    /// held with Shift is the window's, the one with another scan code and no Shift is the session's,
    /// and neither one's release moves the other.
    #[test]
    fn two_scroll_keys_that_differ_only_in_their_scan_code_are_told_apart() {
        use kr_term::win32::{
            KeyRecord,
            control_keys::{ENHANCED_KEY, SHIFT_PRESSED},
        };

        let page_up = |scan_code: u16, key_down: bool, control_keys: u32| KeyRecord {
            virtual_key: super::VK_PRIOR,
            scan_code,
            unicode: 0,
            key_down,
            control_keys: control_keys | ENHANCED_KEY,
            repeat: 1,
        };
        let held_down = page_up(0x49, true, SHIFT_PRESSED);
        let held_up = page_up(0x49, false, 0);
        let other_down = page_up(0, true, 0);
        let other_up = page_up(0, false, 0);
        let mut held = Vec::new();

        let (rest, steps) = take_scroll_keys(vec![held_down], &mut held, true);
        assert_eq!((rest.len(), steps), (0, 1));
        let (rest, steps) = take_scroll_keys(vec![other_down], &mut held, true);
        assert_eq!((rest, steps), (vec![other_down], 0));
        let (rest, steps) = take_scroll_keys(vec![held_up], &mut held, true);
        assert_eq!((rest.len(), steps), (0, 0));
        let (rest, steps) = take_scroll_keys(vec![other_up], &mut held, true);
        assert_eq!((rest, steps), (vec![other_up], 0));
        assert!(held.is_empty());
    }

    /// A release, a modifier on its own and a lock key are not something the person typed: they
    /// neither take a terminal back to the live screen nor count as input a closing session
    /// refused.
    #[test]
    fn only_a_key_going_down_that_is_not_a_modifier_or_a_lock_is_a_press() {
        use kr_term::win32::KeyRecord;

        let key = |virtual_key: u16, key_down: bool| KeyRecord {
            virtual_key,
            scan_code: 0,
            unicode: 0,
            key_down,
            control_keys: 0,
            repeat: 1,
        };
        assert!(presses(&[key(u16::from(b'A'), true)]));
        assert!(!presses(&[key(u16::from(b'A'), false)]), "a release");
        assert!(
            !presses(&[
                key(0x10, true),
                key(0x11, true),
                key(0x12, true),
                key(0x5b, true),
                key(0x5c, true)
            ]),
            "modifiers and the Windows keys"
        );
        assert!(presses(&[key(0x10, true), key(0x0d, true)]));
        assert!(!presses(&[]));
        for (lock, name) in [
            (0x14, "Caps Lock"),
            (0x90, "Num Lock"),
            (0x91, "Scroll Lock"),
        ] {
            assert!(!presses(&[key(lock, true)]), "{name} types nothing");
            assert!(presses(&[key(lock, true), key(u16::from(b'A'), true)]));
        }
    }

    /// An Alt coming up with the character composed on the numeric keypad is the text the person
    /// typed: the console reports the character on the Alt's release. An Alt coming up with none is
    /// a modifier like any other.
    #[test]
    fn an_alt_coming_up_with_a_composed_character_is_a_press() {
        use kr_term::win32::KeyRecord;

        let alt_up = |unicode: u16| KeyRecord {
            virtual_key: 0x12,
            scan_code: 0x38,
            unicode,
            key_down: false,
            control_keys: 0,
            repeat: 1,
        };
        assert!(presses(&[alt_up(0x00e9)]), "an é composed from 0233");
        assert!(!presses(&[alt_up(0)]), "an Alt coming up on its own");
        let a_up = KeyRecord {
            virtual_key: u16::from(b'A'),
            unicode: u16::from(b'a'),
            ..alt_up(0)
        };
        assert!(!presses(&[a_up]), "another key coming up carries no text");
    }

    /// What the attachment says once the reader of its console has been stopped: that the reader had
    /// not ended when it had not, and a typed key the reader left when it ended among the keys lost
    /// with the refusal. A reader that ended with nothing, or with a modifier on its own, says
    /// nothing of either.
    #[test]
    fn what_the_reader_leaves_when_it_is_stopped_is_counted_and_a_reader_still_running_is_said() {
        use crate::attach::{Stopped, TerminalInput};
        use kr_term::win32::KeyRecord;

        let key = |virtual_key: u16, unicode: u16| {
            TerminalInput::Keys(vec![KeyRecord {
                virtual_key,
                scan_code: 0,
                unicode,
                key_down: true,
                control_keys: 0,
                repeat: 1,
            }])
        };
        let (_keep, mut input) = tokio::sync::mpsc::unbounded_channel();
        let spelling = || Fallback {
            how: Some(Spelling::Console),
            typed_keys_lost: false,
        };

        // Nothing left, nothing running, and no refusal: nothing to say.
        let said = after_the_reader_stops(Stopped::default(), &mut Fallback::default(), &mut input);
        assert!(said.is_empty(), "{said:?}");

        // A reader that had not ended says so, whether or not the session refused anything.
        let running = Stopped {
            still_running: true,
            ..Stopped::default()
        };
        let said = after_the_reader_stops(running, &mut Fallback::default(), &mut input);
        assert!(
            said.len() == 1 && said[0].as_str().contains("had not ended"),
            "{said:?}"
        );

        // A reader that had not ended and had a cancel asked says the first, once.
        let both = Stopped {
            still_running: true,
            cancel_asked: true,
            ..Stopped::default()
        };
        let said = after_the_reader_stops(both, &mut Fallback::default(), &mut input);
        assert!(
            said.len() == 1
                && said[0].as_str().contains("input mode may change")
                && !said[0].as_str().contains("asked the system to cancel"),
            "the line for a reader that had not ended, and not the one for a cancel: {said:?}"
        );

        // A reader that ended only after a cancel of its read of the console was asked says so too.
        let cancel_asked = Stopped {
            cancel_asked: true,
            ..Stopped::default()
        };
        let said = after_the_reader_stops(cancel_asked, &mut Fallback::default(), &mut input);
        assert!(
            said.len() == 1
                && said[0].as_str().contains("asked the system to cancel")
                && said[0].as_str().contains("next key you type may be lost"),
            "{said:?}"
        );

        // The half of a character the reader held is a key typed; a modifier on its own is not.
        let left = |read| Stopped {
            left: vec![read],
            ..Stopped::default()
        };
        let said = after_the_reader_stops(left(key(0, 0xd83d)), &mut spelling(), &mut input);
        assert!(
            said.len() == 1 && said[0].as_str().contains("were lost"),
            "a half held at the stop was typed: {said:?}"
        );
        let said = after_the_reader_stops(left(key(0x10, 0)), &mut spelling(), &mut input);
        assert!(
            said.len() == 1 && !said[0].as_str().contains("lost"),
            "a modifier left at the stop is no typing: {said:?}"
        );
    }

    /// A key that came up without this attachment seeing it go down is not the session's, however
    /// the console's records are cut into reads: the Return that started the command is the usual
    /// one.
    #[test]
    fn the_release_of_a_key_this_attachment_did_not_see_go_down_is_not_sent() {
        use kr_term::win32::KeyRecord;

        let key = |virtual_key: u16, key_down: bool| KeyRecord {
            virtual_key,
            scan_code: 0,
            unicode: 0,
            key_down,
            control_keys: 0,
            repeat: 1,
        };
        const RETURN: u16 = 0x0d;
        const SHIFT: u16 = 0x10;
        let a = u16::from(b'A');
        let mut down = Vec::new();

        // The Return that started the command comes up first, and goes nowhere.
        let kept = drop_unseen_releases(vec![key(RETURN, false)], &mut down);
        assert!(kept.is_empty(), "{kept:?}");
        // Shift going down, the letter going down in a read of its own, and both coming up in
        // another, keep their order, and the release of a key sent going down is sent.
        let shift_down = key(SHIFT, true);
        let a_down = key(a, true);
        assert_eq!(
            drop_unseen_releases(vec![shift_down], &mut down),
            vec![shift_down]
        );
        assert_eq!(
            drop_unseen_releases(vec![a_down, a_down], &mut down),
            vec![a_down, a_down],
            "a key held down repeats"
        );
        let a_up = key(a, false);
        let shift_up = key(SHIFT, false);
        assert_eq!(
            drop_unseen_releases(vec![a_up, shift_up], &mut down),
            vec![a_up, shift_up]
        );
        assert!(down.is_empty());
        // And the same release again, with nothing down, is not sent a second time.
        assert!(drop_unseen_releases(vec![a_up], &mut down).is_empty());
        // A character no key of the keyboard made has no press to match, and is kept whole.
        let packet = |key_down| key(0xe7, key_down);
        let run = vec![packet(true), packet(true), packet(false), packet(false)];
        assert_eq!(drop_unseen_releases(run.clone(), &mut down), run);
        // One read that holds a release before its own press drops the release and keeps the press.
        assert_eq!(
            drop_unseen_releases(vec![a_up, a_down], &mut down),
            vec![a_down]
        );
    }

    /// The character composed on the numeric keypad is on the record of the Alt coming up, and is
    /// the person's text however the Alt's going down was missed: the attachment began to read the
    /// console after it, or the Alt went down in a read it did not take. The record is kept, so that
    /// the character reaches the session and a refusal counts it, where the release of any other
    /// key this attachment did not see go down is not sent.
    #[test]
    fn an_alt_coming_up_with_a_composed_character_is_sent_though_its_press_was_not_seen() {
        use kr_term::win32::KeyRecord;

        let alt = |key_down: bool, unicode: u16| KeyRecord {
            virtual_key: super::VK_MENU,
            scan_code: 0x38,
            unicode,
            key_down,
            control_keys: 0,
            repeat: 1,
        };
        let mut down = Vec::new();

        // The press was never seen: the character is kept.
        let composed = alt(false, 0x00e9);
        assert_eq!(
            drop_unseen_releases(vec![composed], &mut down),
            vec![composed]
        );
        assert!(down.is_empty(), "a release leaves nothing down");
        assert!(presses(&[composed]), "and a refusal counts it");
        // An Alt coming up with no character is still not sent.
        assert!(drop_unseen_releases(vec![alt(false, 0)], &mut down).is_empty());
        // The press was seen: the character is kept and the Alt is no longer down.
        let pressed = alt(true, 0);
        assert_eq!(
            drop_unseen_releases(vec![pressed, composed], &mut down),
            vec![pressed, composed]
        );
        assert!(down.is_empty(), "the Alt came up");
    }

    /// Two keys can report one virtual key: the left and right Shift, and the left and right Ctrl
    /// and Alt, which the scan code and the enhanced flag tell apart. Each is seen going down and
    /// coming up on its own, so the release of the second to come up is sent too, and the session
    /// hears that it came up.
    #[test]
    fn two_keys_that_share_a_virtual_key_are_each_seen_coming_up() {
        use kr_term::win32::KeyRecord;

        const SHIFT: u16 = 0x10;
        const CONTROL: u16 = 0x11;
        const ENHANCED: u32 = 0x0100;
        let key = |virtual_key: u16, scan_code: u16, control_keys: u32, key_down: bool| KeyRecord {
            virtual_key,
            scan_code,
            unicode: 0,
            key_down,
            control_keys,
            repeat: 1,
        };

        // The left and right Shift have scan codes of their own.
        let shifts = |left_first: bool| {
            let (first, second) = if left_first {
                (0x2a, 0x36)
            } else {
                (0x36, 0x2a)
            };
            vec![
                key(SHIFT, first, 0x10, true),
                key(SHIFT, second, 0x10, true),
                key(SHIFT, first, 0, false),
                key(SHIFT, second, 0, false),
            ]
        };
        for left_first in [true, false] {
            let mut down = Vec::new();
            let run = shifts(left_first);
            assert_eq!(drop_unseen_releases(run.clone(), &mut down), run);
            assert!(down.is_empty(), "both came up");
        }

        // The left and right Ctrl share a scan code, and the right one is the enhanced key.
        let mut down = Vec::new();
        let run = vec![
            key(CONTROL, 0x1d, 0x08, true),
            key(CONTROL, 0x1d, 0x04 | ENHANCED, true),
            key(CONTROL, 0x1d, ENHANCED, false),
            key(CONTROL, 0x1d, 0, false),
        ];
        assert_eq!(drop_unseen_releases(run.clone(), &mut down), run);
        assert!(down.is_empty(), "both Ctrl came up");

        // A key of the pair that came up without being seen going down is still not sent.
        let right_up = key(SHIFT, 0x36, 0, false);
        let left_down = key(SHIFT, 0x2a, 0x10, true);
        assert_eq!(
            drop_unseen_releases(vec![left_down, right_up], &mut down),
            vec![left_down],
            "the right Shift was never seen going down"
        );
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

    /// A size the session does not take for now is not settled: it is said again with the
    /// session's next word, whatever size was last sent, and not said again once it is taken. The
    /// control is the session's definite refusal, which settles the report and changes nothing.
    #[test]
    fn a_size_the_session_did_not_take_for_now_goes_again_with_its_next_word() {
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.measured(size(100, 30));
        let first = send(&mut window, 1).expect("the size goes");
        assert_eq!((first.dimensions, first.position), (size(100, 30), None));
        window.answered(request(1), Answer::NotTaken);
        assert_eq!(
            window.next(),
            None,
            "it rests until the session says something"
        );
        window.heard();
        let again = send(&mut window, 2).expect("the size goes again, though it is the size sent");
        assert_eq!((again.dimensions, again.position), (size(100, 30), None));
        window.answered(request(2), accepted(0, None));
        window.heard();
        assert_eq!(
            window.next(),
            None,
            "a size the session took is not said again"
        );
        window.measured(size(90, 20));
        assert!(
            send(&mut window, 3).is_some(),
            "and nothing stays in flight behind it"
        );

        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.measured(size(100, 30));
        send(&mut window, 1).expect("the size goes");
        window.answered(request(1), Answer::Refused);
        window.heard();
        assert_eq!(window.next(), None, "a definite refusal settles the report");
        window.measured(size(90, 20));
        assert!(
            send(&mut window, 2).is_some(),
            "and nothing stays in flight behind it"
        );
    }

    /// A session that keeps refusing a size for now is asked again with its next word up to three
    /// times in a row, and then not until this terminal is measured or pressed.
    #[test]
    fn a_session_that_keeps_refusing_a_size_for_now_waits_for_the_terminal_after_three_tries() {
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.measured(size(100, 30));
        send(&mut window, 1).expect("the size goes");
        for id in 2..=4 {
            window.answered(request(id - 1), Answer::NotTaken);
            window.heard();
            send(&mut window, id).expect("and again with the session's next word");
        }
        window.answered(request(4), Answer::NotTaken);
        window.heard();
        assert_eq!(
            window.next(),
            None,
            "three tries in a row, and the session's words no longer bring it"
        );
        window.measured(size(100, 31));
        let measured = send(&mut window, 5).expect("a measure of the terminal does");
        assert_eq!(measured.dimensions, size(100, 31));
        window.answered(request(5), Answer::NotTaken);
        window.heard();
        assert!(send(&mut window, 6).is_some(), "and starts the tries again");
    }

    /// What this terminal does while a size report is in flight is not made to wait behind the rest
    /// the refusal leaves, and a size measured back to the one sent is still owed.
    #[test]
    fn what_the_terminal_does_during_a_size_report_the_session_did_not_take_goes_at_once() {
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.measured(size(100, 30));
        send(&mut window, 1).expect("the size goes");
        window.measured(size(90, 20));
        window.measured(size(100, 30));
        window.answered(request(1), Answer::NotTaken);
        let at_once = send(&mut window, 2).expect("the terminal spoke meanwhile, so no rest");
        assert_eq!(
            at_once.dimensions,
            size(100, 30),
            "the size is owed though the terminal measured back to the one the report carried"
        );

        let mut window = parked_at_477();
        window.measured(size(100, 30));
        send(&mut window, 2).expect("the size goes");
        window.pressed(1, 23, size(100, 30));
        window.answered(request(2), Answer::NotTaken);
        let size_again = send(&mut window, 3).expect("a press meanwhile ends the rest");
        assert_eq!(
            (size_again.dimensions, size_again.position),
            (size(100, 30), row(477)),
            "the size goes first, with the window where it is"
        );
    }

    /// A move is the person's own key: a move the session did not take for now is settled as not
    /// taken and is not made again, and the size it carried was already the session's.
    #[test]
    fn a_move_the_session_did_not_take_for_now_is_settled_and_not_made_later() {
        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        let moved = send(&mut window, 2).expect("the next page back");
        assert_eq!(moved.position, row(454));
        window.answered(request(2), Answer::NotTaken);
        window.heard();
        assert_eq!(window.next(), None, "it is not made again");
        window.pressed(1, 23, size(80, 24));
        assert_eq!(
            send(&mut window, 3).map(|sending| sending.position),
            Some(row(454)),
            "the person presses again, from where the window is"
        );
    }

    /// A refused resize and a resize the terminal made as the owner are the terminal speaking: each
    /// ends the rest a session that keeps refusing a size leaves, so the question the first owes and
    /// the moves waiting behind the second go.
    #[test]
    fn a_resize_the_terminal_makes_or_has_refused_ends_the_rest() {
        let resting = |after: fn(&mut WindowReports)| {
            let mut window = parked_at_477();
            window.pressed(1, 23, size(80, 24));
            window.measured(size(100, 30));
            send(&mut window, 2).expect("the size goes");
            for id in 3..=6 {
                window.answered(request(id - 1), Answer::NotTaken);
                window.heard();
                if id < 6 {
                    send(&mut window, id).expect("and again with the session's next word");
                }
            }
            window.heard();
            assert_eq!(window.next(), None, "four tries in a row, and it rests");
            after(&mut window);
            window
        };

        let mut window = resting(|window| window.owe_question(size(100, 30)));
        let question = send(&mut window, 7).expect("the question goes at once");
        assert_eq!(
            (question.dimensions, question.position),
            (size(100, 30), row(477))
        );

        let mut window = resting(|window| window.took_size(size(100, 30)));
        assert_eq!(
            send(&mut window, 7).map(|sending| sending.position),
            Some(row(454)),
            "the owner's own resize ended the rest, and the move that waited goes"
        );
    }

    /// A return to the live screen is the person's own key, like a move: one the session did not
    /// take for now is settled as not taken, and no size is sent at the row the window was at,
    /// which would take the window back from where the key put it. The next key asks again.
    #[test]
    fn a_return_the_session_did_not_take_for_now_is_settled_and_not_made_later() {
        let mut window = parked_at_477();
        window.return_to_live();
        let back = send(&mut window, 2).expect("the return");
        assert_eq!(back.position, None);
        window.answered(request(2), Answer::NotTaken);
        window.heard();
        assert_eq!(
            window.next(),
            None,
            "nothing goes, though no screen has said where the window is"
        );
        window.return_to_live();
        assert_eq!(
            send(&mut window, 3).map(|sending| sending.position),
            Some(None),
            "the next key asks for the return again"
        );
    }

    /// A size measured while a return to the live screen was in flight, and a question owed then,
    /// go where the person's typing wanted the window once the return was not taken: a report at
    /// the row the record keeps would take the window back from where the key put it. A screen that
    /// says where the window is ends the doubt, and a move the session did not take leaves the
    /// record as it was.
    #[test]
    fn a_size_owed_after_a_return_the_session_did_not_take_goes_at_the_live_screen() {
        let mut window = parked_at_477();
        window.return_to_live();
        let back = send(&mut window, 2).expect("the return");
        assert_eq!(back.position, None);
        window.measured(size(100, 30));
        window.answered(request(2), Answer::NotTaken);
        let sized = send(&mut window, 3).expect("the size goes at once");
        assert_eq!(
            (sized.dimensions, sized.position),
            (size(100, 30), None),
            "at the live screen, not at the row the window may have left"
        );

        let mut window = parked_at_477();
        window.return_to_live();
        send(&mut window, 2).expect("the return");
        window.owe_question(size(80, 24));
        window.answered(request(2), Answer::NotTaken);
        let question = send(&mut window, 3).expect("the question goes at once");
        assert_eq!(
            (question.dimensions, question.position),
            (size(80, 24), None),
            "at the live screen as well"
        );

        // The doubt ends with a screen that says where the window is.
        let mut window = parked_at_477();
        window.return_to_live();
        send(&mut window, 2).expect("the return");
        window.answered(request(2), Answer::NotTaken);
        window.installed(2, Some(477));
        window.measured(size(100, 30));
        assert_eq!(
            send(&mut window, 3).map(|sending| sending.position),
            Some(row(477)),
            "the screen put the window at the row, and that is where it is"
        );

        // A return the session took is told by the screen it caused, as it was.
        let mut window = parked_at_477();
        window.return_to_live();
        send(&mut window, 2).expect("the return");
        window.measured(size(100, 30));
        window.answered(request(2), accepted(2, None));
        window.installed(2, None);
        assert_eq!(
            send(&mut window, 3).map(|sending| sending.position),
            Some(None),
            "the window is at the live screen"
        );

        // The control: a move the session did not take is not a return, and what is owed after it
        // goes at the row the record keeps.
        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        send(&mut window, 2).expect("the next page back");
        window.measured(size(100, 30));
        window.answered(request(2), Answer::NotTaken);
        assert_eq!(
            send(&mut window, 3).map(|sending| sending.position),
            Some(row(477)),
            "a move leaves the record where it was"
        );
    }

    /// The return to the live screen goes before the size and takes the newest one with it: the one
    /// measured before it went, the one an earlier report left owed, and the one measured while
    /// another report was in flight. When the session does not take the return, it may not have
    /// taken that size either, so the size is owed again at the live screen, once the session next
    /// says something, as the size of a report not taken is. A return the session took carried it,
    /// and one it refused in its definite word is settled like any report refused so.
    #[test]
    fn a_size_a_return_the_session_did_not_take_carried_goes_again_at_the_live_screen() {
        // Measured before the return went.
        let mut window = parked_at_477();
        window.measured(size(100, 30));
        window.return_to_live();
        let back = send(&mut window, 2).expect("the return");
        assert_eq!((back.dimensions, back.position), (size(100, 30), None));
        window.answered(request(2), Answer::NotTaken);
        assert_eq!(
            window.next(),
            None,
            "it waits for the session to say something, as a size not taken does"
        );
        window.heard();
        let sized = send(&mut window, 3).expect("the size goes again");
        assert_eq!(
            (sized.dimensions, sized.position),
            (size(100, 30), None),
            "at the live screen, not at the row the window may have left"
        );

        // Left owed by an earlier report the session did not take, which the return then carried.
        let mut window = parked_at_477();
        window.measured(size(100, 30));
        send(&mut window, 2).expect("the size goes");
        window.answered(request(2), Answer::NotTaken);
        window.return_to_live();
        let back = send(&mut window, 3).expect("the return carries the size");
        assert_eq!(back.dimensions, size(100, 30));
        window.answered(request(3), Answer::NotTaken);
        window.heard();
        let sized = send(&mut window, 4).expect("the size goes again");
        assert_eq!(
            (sized.dimensions, sized.position),
            (size(100, 30), None),
            "even though the size is the one last sent"
        );

        // The return was the first asking of the size: three more follow it with the session's
        // words, and then it rests until the terminal speaks.
        let mut id = 5;
        for _ in 0..2 {
            window.answered(request(id - 1), Answer::NotTaken);
            window.heard();
            send(&mut window, id).expect("and again with the session's next word");
            id += 1;
        }
        window.answered(request(id - 1), Answer::NotTaken);
        window.heard();
        assert_eq!(
            window.next(),
            None,
            "four askings of the size in all, the return's included"
        );

        // Measured while a move was in flight, before the return went.
        let mut window = parked_at_477();
        window.pressed(1, 23, size(80, 24));
        send(&mut window, 2).expect("the next page back");
        window.measured(size(100, 30));
        window.return_to_live();
        window.answered(request(2), accepted(2, Some(454)));
        window.installed(2, Some(454));
        let back = send(&mut window, 3).expect("the return");
        assert_eq!((back.dimensions, back.position), (size(100, 30), None));
        window.answered(request(3), Answer::NotTaken);
        window.heard();
        let sized = send(&mut window, 4).expect("the size goes again");
        assert_eq!((sized.dimensions, sized.position), (size(100, 30), None));

        // The person pressed a key while the return was in flight: no rest, the size goes at once.
        let mut window = parked_at_477();
        window.measured(size(100, 30));
        window.return_to_live();
        send(&mut window, 2).expect("the return");
        window.pressed(1, 23, size(100, 30));
        window.answered(request(2), Answer::NotTaken);
        let sized = send(&mut window, 3).expect("no rest: the terminal spoke meanwhile");
        assert_eq!((sized.dimensions, sized.position), (size(100, 30), None));

        // The controls: a return the session took carried the size, and a definite refusal settles
        // the return as it settles every report.
        let mut window = parked_at_477();
        window.measured(size(100, 30));
        window.return_to_live();
        send(&mut window, 2).expect("the return");
        window.answered(request(2), accepted(2, None));
        window.installed(2, None);
        window.heard();
        assert_eq!(window.next(), None, "the session has the size");
        let mut window = parked_at_477();
        window.measured(size(100, 30));
        window.return_to_live();
        send(&mut window, 2).expect("the return");
        window.answered(request(2), Answer::Refused);
        window.heard();
        assert_eq!(
            window.next(),
            None,
            "the session's definite word is its last"
        );
    }

    /// A subscription that begins with the stream settles where the window is, and not what became
    /// of the size a report in flight carried: the session's answer can come after the stream's
    /// first bytes, and when it says the session did not take the size, whether the report was a
    /// size report or a return to the live screen that carried the newest size, the size is owed
    /// again as it is when the answer comes first. It goes at the place the stream has put the
    /// window, with the session's next word, or at once if the terminal spoke meanwhile, and it
    /// counts toward the same four askings. The controls are the answers that owe nothing: the
    /// session took the report, refused it in its definite word, or it carried no size.
    #[test]
    fn a_size_the_session_did_not_take_is_owed_again_though_its_answer_comes_after_the_stream() {
        // A size report.
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.measured(size(100, 30));
        send(&mut window, 1).expect("the size goes");
        window.recovering();
        window.streamed();
        window.answered(request(1), Answer::NotTaken);
        assert_eq!(
            window.next(),
            None,
            "it waits for the session to say something, as a size not taken does"
        );
        window.heard();
        let again = send(&mut window, 2).expect("the size goes again");
        assert_eq!((again.dimensions, again.position), (size(100, 30), None));

        // Four askings in all, the report the stream settled included.
        for id in 3..=4 {
            window.answered(request(id - 1), Answer::NotTaken);
            window.heard();
            send(&mut window, id).expect("and again with the session's next word");
        }
        window.answered(request(4), Answer::NotTaken);
        window.heard();
        assert_eq!(window.next(), None, "four askings, and then the terminal");

        // A return to the live screen that carried the newest size.
        let mut window = parked_at_477();
        window.measured(size(100, 30));
        window.return_to_live();
        let back = send(&mut window, 2).expect("the return");
        assert_eq!((back.dimensions, back.position), (size(100, 30), None));
        window.recovering();
        window.streamed();
        window.answered(request(2), Answer::NotTaken);
        window.heard();
        let again = send(&mut window, 3).expect("the size goes again");
        assert_eq!((again.dimensions, again.position), (size(100, 30), None));

        // The terminal spoke while the answer was awaited: no rest.
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.measured(size(100, 30));
        send(&mut window, 1).expect("the size goes");
        window.recovering();
        window.streamed();
        window.measured(size(90, 20));
        window.answered(request(1), Answer::NotTaken);
        let at_once = send(&mut window, 2).expect("the terminal spoke, so no rest");
        assert_eq!(at_once.dimensions, size(90, 20), "the newest size");

        // The person scrolled back after the stream began, and the session took that move before
        // it refused the return for now. The move carried the size, so none is owed for the
        // return; and a late answer never says the window is at the live screen, so a size
        // measured afterwards goes at the row the window is at.
        let mut window = parked_at_477();
        window.measured(size(100, 30));
        window.return_to_live();
        send(&mut window, 2).expect("the return");
        window.recovering();
        window.streamed();
        window.pressed(1, 23, size(100, 30));
        let moved = send(&mut window, 3).expect("the page back");
        assert_eq!(moved.position, above(23));
        window.answered(request(3), accepted(2, Some(477)));
        window.installed(2, Some(477));
        window.answered(request(2), Answer::NotTaken);
        window.heard();
        assert_eq!(window.next(), None, "the move carried the size");
        window.measured(size(90, 20));
        assert_eq!(
            send(&mut window, 4).map(|sending| sending.position),
            Some(row(477)),
            "at the row the window is at"
        );

        // The controls: a report the session took, one it refused in its definite word, a move,
        // and a return that carried no size owe nothing.
        for (answer, mover) in [
            (accepted(1, None), false),
            (Answer::Refused, false),
            (Answer::NotTaken, true),
        ] {
            let mut window = parked_at_477();
            if mover {
                window.pressed(1, 23, size(80, 24));
            } else {
                window.measured(size(100, 30));
            }
            send(&mut window, 2).expect("the report");
            window.recovering();
            window.streamed();
            window.answered(request(2), answer);
            window.heard();
            assert_eq!(window.next(), None, "{answer:?} owes nothing");
        }
        let mut window = parked_at_477();
        window.return_to_live();
        let back = send(&mut window, 2).expect("the return");
        assert_eq!(back.dimensions, size(80, 24), "it carries no new size");
        window.recovering();
        window.streamed();
        window.answered(request(2), Answer::NotTaken);
        window.heard();
        assert_eq!(
            window.next(),
            None,
            "a return that carried no size owes none"
        );
    }

    /// Only an idempotent read, a transfer chunk or a request whose receipt proves no dispatch may
    /// retry on its own, and an unknown outcome is not retryable: a viewport report is none of
    /// those, so an answer that cannot say what became of it settles it as unknown, and the size it
    /// carried is not sent again for it. Only the session's refusal for now, which proves nothing
    /// took effect, owes the size again. That holds for a size report and for a return to the live
    /// screen that carried the size, and whether the answer comes before the first bytes of a new
    /// subscription or after them. The next report this terminal makes carries the size it has.
    #[test]
    fn a_report_whose_outcome_is_unknown_is_not_sent_again_and_one_refused_for_now_is() {
        use kr_protocol::envelope::{Outcome, ParamsValue};
        use kr_protocol::error::ProtocolError;
        let says = |code| {
            viewport_result(Outcome::Error(ProtocolError::new(code, "said")))
                .expect_err("a refusal gives no result")
        };
        let for_now = says(ErrorCode::ResourceUnavailable);
        let unknown = says(ErrorCode::OutcomeUnknown);
        for behind_the_stream in [false, true] {
            for (answer, owed) in [(for_now, true), (unknown, false)] {
                let at = |what: &str| {
                    format!("{what}, {answer:?}, behind the stream: {behind_the_stream}")
                };

                // A size report.
                let mut window = WindowReports::new(size(80, 24));
                window.installed(0, None);
                window.measured(size(100, 30));
                send(&mut window, 1).expect("the size goes");
                if behind_the_stream {
                    window.recovering();
                    window.streamed();
                }
                window.answered(request(1), answer);
                window.heard();
                if owed {
                    assert!(window.next().is_some(), "{}", at("the size is owed again"));
                } else {
                    assert_eq!(window.next(), None, "{}", at("a size report owes nothing"));
                    window.pressed(1, 23, size(110, 40));
                    let next = send(&mut window, 2).expect("the next report goes");
                    assert_eq!(
                        next.dimensions,
                        size(110, 40),
                        "{}",
                        at("and carries the size the terminal has")
                    );
                }

                // A return to the live screen that carried the newest size.
                let mut window = parked_at_477();
                window.measured(size(100, 30));
                window.return_to_live();
                send(&mut window, 2).expect("the return");
                if behind_the_stream {
                    window.recovering();
                    window.streamed();
                }
                window.answered(request(2), answer);
                window.heard();
                if owed {
                    assert!(
                        window.next().is_some(),
                        "{}",
                        at("the carried size is owed")
                    );
                } else {
                    assert_eq!(window.next(), None, "{}", at("a return owes no size"));
                    if !behind_the_stream {
                        // The session may have taken the return, so what goes next goes at the live
                        // screen, where the key that asked for it wanted the window.
                        window.measured(size(90, 20));
                        assert_eq!(
                            send(&mut window, 3).map(|sending| sending.position),
                            Some(None),
                            "{}",
                            at("the window may be at the live screen")
                        );
                    }
                }
            }
        }

        // A success that cannot be read says nothing of what it did to the window: a return it may
        // have completed leaves what goes next at the live screen, where the key wanted the window.
        let unreadable = viewport_result(Outcome::Ok(ParamsValue::empty()))
            .expect_err("an empty result is not a viewport answer");
        let mut window = parked_at_477();
        window.return_to_live();
        send(&mut window, 2).expect("the return");
        window.measured(size(100, 30));
        window.answered(request(2), unreadable);
        assert_eq!(
            send(&mut window, 3).map(|sending| sending.position),
            Some(None),
            "the return may have been completed"
        );
    }

    /// Two reports can be unanswered at once once a stream has begun, and the size an older one was
    /// refused for now is the size a newer one carried. When the newer one is of unknown outcome it
    /// is not sent again, and neither is the older one's size, whichever answer comes first: the
    /// newer report carried the newest size, and sending it again would send that report again.
    /// The newer report may be a size report or a move. The control is a newer move the session
    /// refused for now, which owes no size of its own, so the older one's size is still owed.
    #[test]
    fn a_size_an_older_report_was_refused_for_is_not_sent_again_after_a_newer_report_of_unknown_outcome()
     {
        for older_first in [true, false] {
            for newer_is_a_move in [false, true] {
                let mut window = WindowReports::new(size(80, 24));
                window.installed(0, None);
                window.measured(size(100, 30));
                send(&mut window, 1).expect("the size goes");
                window.recovering();
                window.streamed();
                if newer_is_a_move {
                    window.pressed(1, 23, size(100, 30));
                } else {
                    window.measured(size(90, 20));
                }
                send(&mut window, 2).expect("the newer report");
                if older_first {
                    window.answered(request(1), Answer::NotTaken);
                    window.answered(request(2), Answer::Unknown);
                } else {
                    window.answered(request(2), Answer::Unknown);
                    window.answered(request(1), Answer::NotTaken);
                }
                window.heard();
                assert_eq!(
                    window.next(),
                    None,
                    "older answered first: {older_first}, newer is a move: {newer_is_a_move}"
                );
            }
        }

        // A newer move refused for now owes no size, so the older report's is still owed.
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        window.measured(size(100, 30));
        send(&mut window, 1).expect("the size goes");
        window.recovering();
        window.streamed();
        window.pressed(1, 23, size(100, 30));
        send(&mut window, 2).expect("the move");
        window.answered(request(1), Answer::NotTaken);
        window.answered(request(2), Answer::NotTaken);
        window.heard();
        assert!(window.next().is_some(), "the older report's size is owed");
    }

    /// Two reports can be unanswered at once once a stream has begun, and the size an older one was
    /// refused for now is the size a newer one carried. When the session took the newer report it
    /// holds the size, so the older one's is not owed, whichever answer comes first and whether the
    /// newer answer comes before or after another stream's first bytes: sending it again would
    /// send a size the session already has. The newer report may be a size report or a move. The
    /// controls are a newer report the session refused for now, which owes the size itself whether
    /// an older report was refused or taken, and an older report taken after a newer one was
    /// refused, which ends nothing the newer owes.
    #[test]
    fn a_size_an_older_report_was_refused_for_is_not_sent_again_after_a_newer_report_the_session_took()
     {
        for older_first in [true, false] {
            for newer_is_a_move in [false, true] {
                for newer_behind_the_stream in [false, true] {
                    let mut window = WindowReports::new(size(80, 24));
                    window.installed(0, None);
                    window.measured(size(100, 30));
                    send(&mut window, 1).expect("the size goes");
                    window.recovering();
                    window.streamed();
                    if newer_is_a_move {
                        window.pressed(1, 23, size(100, 30));
                    } else {
                        window.measured(size(90, 20));
                    }
                    send(&mut window, 2).expect("the newer report");
                    if newer_behind_the_stream {
                        window.recovering();
                        window.streamed();
                    }
                    let took = if newer_is_a_move {
                        accepted(1, Some(477))
                    } else {
                        accepted(1, None)
                    };
                    if older_first {
                        window.answered(request(1), Answer::NotTaken);
                        window.answered(request(2), took);
                    } else {
                        window.answered(request(2), took);
                        window.answered(request(1), Answer::NotTaken);
                    }
                    if !newer_behind_the_stream {
                        window.installed(1, newer_is_a_move.then_some(477));
                    }
                    window.heard();
                    assert_eq!(
                        window.next(),
                        None,
                        "older answered first: {older_first}, newer is a move: {newer_is_a_move}, \
                         newer behind the stream: {newer_behind_the_stream}"
                    );
                }
            }
        }

        // A newer report refused for now owes the size itself, whether the older one was refused
        // or taken, and in either order.
        for (older, older_first) in [
            (Answer::NotTaken, true),
            (accepted(1, None), true),
            (Answer::NotTaken, false),
            (accepted(1, None), false),
        ] {
            let mut window = WindowReports::new(size(80, 24));
            window.installed(0, None);
            window.measured(size(100, 30));
            send(&mut window, 1).expect("the size goes");
            window.recovering();
            window.streamed();
            window.measured(size(90, 20));
            send(&mut window, 2).expect("the newer report");
            if older_first {
                window.answered(request(1), older);
                window.answered(request(2), Answer::NotTaken);
            } else {
                window.answered(request(2), Answer::NotTaken);
                window.answered(request(1), older);
            }
            window.heard();
            assert!(
                window.next().is_some(),
                "the newer report's size is owed: older {older:?}, older first: {older_first}"
            );
        }
    }

    /// A resize this terminal made as the owner that the session did not take for now, or could not
    /// say what became of, leaves the question owed that says what size the session has: it goes
    /// with the session's next word, and for three resizes in a row at most. A resize taken ends
    /// the count, and so does the person resizing the terminal.
    #[test]
    fn an_owners_resize_the_session_did_not_take_for_now_is_asked_about_with_its_next_word() {
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        assert!(window.resized_as_owner(size(100, 30)));
        assert_eq!(window.next(), None, "the resize is not a viewport report");
        window.resize_not_taken(size(100, 30));
        assert_eq!(
            window.next(),
            None,
            "it rests until the session says something"
        );
        window.heard();
        let question = send(&mut window, 1).expect("the question goes");
        assert_eq!(
            (question.dimensions, question.position),
            (size(100, 30), None)
        );
        window.answered(request(1), accepted(0, None));
        assert_eq!(window.next(), None, "and only once");

        // Three resizes in a row, the first above included, and then the session is left as it is.
        let mut id = 2;
        for _ in 0..2 {
            window.took_size(size(100, 30));
            window.resize_not_taken(size(100, 30));
            window.heard();
            send(&mut window, id).expect("the question goes");
            window.answered(request(id), accepted(0, None));
            id += 1;
        }
        window.took_size(size(100, 30));
        window.resize_not_taken(size(100, 30));
        window.heard();
        assert_eq!(
            window.next(),
            None,
            "four in a row, and the session's words no longer bring it"
        );

        // The person resizing the terminal starts the count again, and so does a resize taken.
        assert!(window.resized_as_owner(size(90, 20)));
        window.resize_not_taken(size(90, 20));
        window.heard();
        assert!(
            send(&mut window, id).is_some(),
            "a new resize starts the tries again"
        );
        window.answered(request(id), accepted(0, None));
        id += 1;
        for _ in 0..2 {
            window.took_size(size(90, 20));
            window.resize_not_taken(size(90, 20));
            window.heard();
            send(&mut window, id).expect("the question goes");
            window.answered(request(id), accepted(0, None));
            id += 1;
        }
        window.resize_taken();
        window.took_size(size(90, 20));
        window.resize_not_taken(size(90, 20));
        window.heard();
        assert!(
            send(&mut window, id).is_some(),
            "a resize taken ends the count"
        );
    }

    /// A refusal of a viewport report settles it in the session's definite word, owes the size it
    /// carried again in a refusal for now, and leaves its outcome unknown in a word that cannot say
    /// what became of it: the retry category of the code tells, whichever the code is. A success
    /// that cannot be read is no answer the session's word can be read from: what it did to the
    /// window is not known.
    #[test]
    fn a_viewport_reports_answer_is_told_by_the_retry_category_of_its_code() {
        use kr_protocol::envelope::{Outcome, ParamsValue};
        use kr_protocol::error::ProtocolError;
        for code in ErrorCode::ALL {
            let answer = viewport_result(Outcome::Error(ProtocolError::new(*code, "said")))
                .expect_err("a refusal gives no result");
            let expected = match HostWord::of(*code) {
                HostWord::Definite => Answer::Refused,
                HostWord::Transient => Answer::NotTaken,
                HostWord::Unknown => Answer::Unknown,
            };
            assert_eq!(answer, expected, "{code:?}");
        }
        let unreadable = viewport_result(Outcome::Ok(ParamsValue::empty()))
            .expect_err("an empty result is not a viewport answer");
        assert_eq!(unreadable, Answer::Unknown);
    }

    /// An owner's resize is answered by the retry category of the code, whichever the code is,
    /// except that the refusal for somebody else owning the size is its own: the session's word
    /// that it took none of it, one that cannot say what became of it, and a success that cannot be
    /// read, which leaves the outcome unknown, are told apart, and only the word that nothing took
    /// effect owes the resize again.
    #[test]
    fn an_owners_resize_answer_is_told_by_the_retry_category_of_its_code() {
        use kr_protocol::envelope::{Outcome, ParamsValue};
        use kr_protocol::error::ProtocolError;
        for code in ErrorCode::ALL {
            let answer = resize_result(Outcome::Error(ProtocolError::new(*code, "said")))
                .expect_err("a refusal gives no geometry");
            let expected = if *code == ErrorCode::GeometryNotOwner {
                ResizeRefusal::NotOwner
            } else {
                match HostWord::of(*code) {
                    HostWord::Definite => ResizeRefusal::Refused,
                    HostWord::Transient => ResizeRefusal::NotTaken,
                    HostWord::Unknown => ResizeRefusal::Unknown,
                }
            };
            assert_eq!(answer, expected, "{code:?}");
        }
        let unreadable = resize_result(Outcome::Ok(ParamsValue::empty()))
            .expect_err("an empty result is not a geometry");
        assert_eq!(unreadable, ResizeRefusal::Unknown);
    }

    /// A resize this terminal made as the owner that the session could not say what became of is
    /// not made again, and nothing is owed in its place. A signal for the size it was made for is
    /// no new resize, and a resize to another size is: from the person, whether the terminal owns
    /// the size or not. Only the newest resize this terminal asked for leaves a mark: an older one
    /// answered late, whether a newer resize went to another size, back to the same size or the
    /// person resized the terminal while it did not own the size, leaves none. It is no resize
    /// taken and none refused for now: the count of those, which ends a session that keeps
    /// refusing after three, stands as it was.
    #[test]
    fn an_owners_resize_of_unknown_outcome_is_not_made_again_and_owes_nothing() {
        let (a, b) = (size(100, 30), size(90, 20));
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        assert!(window.resized_as_owner(a), "the person's resize");
        window.resize_sent(request(101), a);
        window.resize_ended_unknown(request(101));
        assert_eq!(
            window.resize_unknown(),
            Some(a),
            "no answer owes this resize"
        );
        window.heard();
        assert_eq!(window.next(), None, "and nothing is asked in its place");
        window.pressed(0, 1, b);
        assert!(
            !window.resized_as_owner(a),
            "a signal for the size the resize was made for is no new resize"
        );
        assert_eq!(window.resize_unknown(), Some(a));
        assert_eq!(
            window.next(),
            None,
            "and the size the terminal has is the one the resize was made for"
        );
        assert!(window.resized_as_owner(b), "another size is a new resize");
        window.resize_sent(request(102), b);
        assert_eq!(window.resize_unknown(), None);

        // The person drags through a size, away and back: the answer to the first resize comes
        // after the third was asked, though all three are for sizes the terminal went through.
        assert!(window.resized_as_owner(a));
        window.resize_sent(request(103), a);
        assert!(window.resized_as_owner(b));
        window.resize_sent(request(104), b);
        assert!(window.resized_as_owner(a));
        window.resize_sent(request(105), a);
        window.resize_ended_unknown(request(103));
        assert_eq!(
            window.resize_unknown(),
            None,
            "the older one leaves no mark"
        );
        window.resize_ended_unknown(request(105));
        assert_eq!(window.resize_unknown(), Some(a), "the newest does");

        // The terminal lost the size and the person resized it: an answer to the resize it made
        // as the owner leaves no mark, and a measured size other than the marked one ends one.
        assert!(window.resized_as_owner(b));
        window.resize_sent(request(106), b);
        window.measured(a);
        window.resize_ended_unknown(request(106));
        assert_eq!(window.resize_unknown(), None);
        assert!(
            window.resized_as_owner(b),
            "so the resize back to it is made"
        );
        window.resize_sent(request(107), b);
        window.resize_ended_unknown(request(107));
        window.measured(b);
        assert_eq!(
            window.resize_unknown(),
            Some(b),
            "the same size keeps the mark"
        );
        window.measured(a);
        assert_eq!(window.resize_unknown(), None, "another size ends it");

        // Resizes refused for now go three times in a row at most, and one of unknown outcome
        // between them neither ends the count nor adds to it.
        let mut id = 1;
        let mut refused_for_now = |window: &mut WindowReports| {
            window.took_size(a);
            window.resize_not_taken(a);
            window.heard();
            let asked = send(window, id).is_some();
            if asked {
                window.answered(request(id), accepted(0, None));
            }
            id += 1;
            asked
        };
        assert!(refused_for_now(&mut window), "the first");
        assert!(refused_for_now(&mut window), "the second");
        window.took_size(a);
        window.resize_sent(request(108), a);
        window.resize_ended_unknown(request(108));
        assert_eq!(window.resize_unknown(), Some(a));
        window.heard();
        assert_eq!(window.next(), None);
        assert!(refused_for_now(&mut window), "the third");
        assert!(
            !refused_for_now(&mut window),
            "the fourth in all, and the session's words no longer bring it"
        );
    }

    /// A resize the owner asked for that ends unknown leaves its mark when the terminal was
    /// signalled for the size it asked for in between, whether or not the terminal still owns the
    /// size: the signal is no newer resize. The viewport answer that shows the session at the old
    /// size then owes nothing, since the resize may have been taken and is not made again. A signal
    /// for another size is a newer resize of the person's, and ends the mark.
    #[test]
    fn a_signal_for_the_size_an_owners_resize_asked_for_leaves_its_mark() {
        let this =
            kr_protocol::ids::AttachmentId::new(kr_protocol::scalars::Uuid::from_bytes([4; 16]));
        let at_the_old_size = kr_protocol::attachment::GeometryState {
            owner: Nullable::some(this),
            epoch: kr_protocol::ids::GeometryEpoch::new(7),
            dimensions: size(80, 24),
        };
        let (b, c) = (size(90, 20), size(100, 30));
        let owed = |window: &WindowReports, looking_at| {
            ownership(
                &at_the_old_size,
                this,
                Some(looking_at),
                &resizes_not_owed(&std::collections::BTreeMap::new(), window.resize_unknown()),
            )
            .resize
        };

        // The owner resizes to `b`. An answer to an older request, late, says the terminal does not
        // own the size, and a second signal for `b` is read while the resize is in flight.
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        assert!(window.resized_as_owner(b));
        window.resize_sent(request(201), b);
        window.owe_question(b);
        window.measured(b);
        window.resize_ended_unknown(request(201));
        assert_eq!(window.resize_unknown(), Some(b));
        assert_eq!(owed(&window, b), None, "the resize is not made again");

        // The control: a signal for another size is the person's newer resize, and the resize
        // that ended unknown leaves no mark.
        let mut window = WindowReports::new(size(80, 24));
        window.installed(0, None);
        assert!(window.resized_as_owner(b));
        window.resize_sent(request(202), b);
        window.owe_question(c);
        window.measured(c);
        window.resize_ended_unknown(request(202));
        assert_eq!(window.resize_unknown(), None);
        assert_eq!(
            owed(&window, c),
            Some(c),
            "so the answer owes the size the terminal has"
        );
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
    /// refused. Nor does an answer owe the resize the session could not say what became of, which
    /// is not retried, though it shows the session at the old size.
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
        assert_eq!(resizes_not_owed(&outstanding, None), vec![size(100, 30)]);
        assert_eq!(
            ownership(
                &before_the_resize,
                this,
                Some(size(100, 30)),
                &resizes_not_owed(&outstanding, None)
            ),
            Ownership {
                epoch: kr_protocol::ids::GeometryEpoch::new(7),
                owns: true,
                resize: None,
            },
            "the resize in flight is the one this terminal owes"
        );

        let unknown = Some(size(90, 20));
        assert_eq!(
            resizes_not_owed(&outstanding, unknown),
            vec![size(100, 30), size(90, 20)]
        );
        let owed = |unknown| {
            ownership(
                &before_the_resize,
                this,
                Some(size(90, 20)),
                &resizes_not_owed(&std::collections::BTreeMap::new(), unknown),
            )
            .resize
        };
        assert_eq!(
            owed(None),
            Some(size(90, 20)),
            "the session is at another size"
        );
        assert_eq!(
            owed(unknown),
            None,
            "but that resize ended unknown, and is not made again"
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

    /// A bridge that has to shed the view a second time, while a new subscription is being asked
    /// for, leaves the old stream's marker ahead of the new stream's opening and keeps the opening:
    /// the marker is the old stream's and asks for nothing more, and the opening begins the new
    /// stream, which is then told apart from the one before it. An opening that was dropped leaves
    /// the terminal waiting for one that never comes, and everything after it is the old stream's.
    #[test]
    fn a_marker_ahead_of_the_new_streams_opening_does_not_hide_it() {
        let mut subscriptions = Subscriptions::new();
        assert_eq!(
            subscriptions.heard(0, "session.projection.reset"),
            Heard::First
        );
        assert!(
            subscriptions.replace(),
            "a marker asked for a new subscription"
        );
        // What the bridge delivers after a second overflow.
        assert_eq!(
            subscriptions.heard(8, "session.resync"),
            Heard::Replaced,
            "the marker is the old stream's, and asks for nothing more"
        );
        assert_eq!(
            subscriptions.heard(0, "session.projection.reset"),
            Heard::First,
            "the opening begins the new stream"
        );
        assert_eq!(
            subscriptions.heard(1, "session.projection.snapshot"),
            Heard::Later
        );
        assert!(subscriptions.replace(), "and its marker asks again");

        // The control: without the opening, nothing is ever the new stream's.
        let mut lost = Subscriptions::new();
        assert_eq!(lost.heard(0, "session.projection.reset"), Heard::First);
        assert!(lost.replace());
        for sequence in 1..=5 {
            assert_eq!(
                lost.heard(sequence, "session.projection.delta"),
                Heard::Replaced,
                "{sequence}"
            );
        }
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

    /// How an attachment ended is said without the closure record, which names what the session
    /// ran.
    #[test]
    fn how_an_attachment_ended_renders_without_the_closure_record() {
        const MARKER: &str = "kr-marker-7c1e";
        let record = kr_protocol::session::ClosureRecord {
            session_id: kr_protocol::ids::SessionId::new(kr_protocol::scalars::Uuid::from_bytes(
                [2; 16],
            )),
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            reason: kr_protocol::session::ClosureReason::CloseRequested,
            root_exit_code: kr_protocol::scalars::Nullable::null(),
            root_signal: kr_protocol::scalars::Nullable::some(MARKER.to_owned()),
            terminated: Vec::new(),
            surviving: vec![kr_protocol::session::SurvivingResource {
                kind: MARKER.to_owned(),
                detail: MARKER.to_owned(),
            }],
            ownership_coverage: kr_protocol::session::OwnershipCoverage::Complete,
            durability: kr_protocol::session::Durability::Durable,
            closed_at_ms: kr_protocol::scalars::TimestampMs::new(1),
        };
        assert_eq!(
            format!(
                "{:?}",
                AttachOutcome::Closed {
                    record: Box::new(record),
                    undelivered: true,
                }
            ),
            "Closed { undelivered: true, .. }"
        );
        assert_eq!(
            format!(
                "{:?}",
                AttachOutcome::DeliveryUncertain(Shown::said("not known"))
            ),
            "DeliveryUncertain(\"not known\")"
        );
        assert_eq!(format!("{:?}", AttachOutcome::Detached), "Detached");
    }
}
