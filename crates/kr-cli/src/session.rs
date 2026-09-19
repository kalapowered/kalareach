//! Attaching a terminal and driving it until the attachment ends.
//!
//! An attach is three things happening at once: bytes from the terminal going to the session, bytes
//! from the session going to the terminal, and a connection that can end at any moment. They run in
//! one loop rather than in tasks that each decide separately when to stop, because every way this
//! ends has to end the *other two* as well. A terminal left in raw mode because one half was still
//! waiting for a keystroke is the failure section 8 names.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_protocol::attachment::ViewportPosition;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{InputLeaseEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::Dimensions;
use kr_protocol::worker::WorkerDescriptor;

use crate::attach::{Attachment, RestorationGuard};
use crate::error::{CliError, Result};
use crate::terminal::ControllingTerminal;

/// Why an attachment ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachOutcome {
    /// The terminal's own input ended, or the user detached.
    Detached,
    /// The session closed while this terminal was attached.
    SessionClosed,
    /// The input lease moved to somebody else.
    LeaseLost,
    /// The connection to the worker ended.
    Disconnected,
    /// Input could not be delivered, and whether it arrived is not known.
    DeliveryUncertain(String),
}

impl AttachOutcome {
    /// Returns the sentence a person is shown.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Detached => "detached".to_owned(),
            Self::SessionClosed => "the session closed".to_owned(),
            Self::LeaseLost => "another attachment took the input lease".to_owned(),
            Self::Disconnected => "the connection to the session ended".to_owned(),
            Self::DeliveryUncertain(detail) => {
                format!("some input may not have reached the session: {detail}")
            }
        }
    }

    /// Returns whether this outcome is a failure the exit code must carry.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        match self {
            Self::Detached | Self::SessionClosed => false,
            Self::LeaseLost | Self::Disconnected | Self::DeliveryUncertain(_) => true,
        }
    }

    /// Returns the failure this outcome is reported as.
    #[must_use]
    pub fn into_error(self) -> Option<CliError> {
        match self {
            Self::Detached | Self::SessionClosed => None,
            Self::LeaseLost => Some(CliError::Refused(kr_protocol::error::ProtocolError::new(
                ErrorCode::LeaseLost,
                self.detail(),
            ))),
            Self::Disconnected => Some(CliError::HostUnavailable(self.detail())),
            Self::DeliveryUncertain(_) => Some(CliError::Refused(
                kr_protocol::error::ProtocolError::new(ErrorCode::OutcomeUnknown, self.detail()),
            )),
        }
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
    }
}

/// Where a movement of `steps` puts this terminal's window.
///
/// `parked` is the row the host last said this window starts at, and `None` means it is on the
/// live screen. Going back from the live screen is the one case that cannot name a row: this
/// client has not been given one above the page it is looking at, so it asks by distance and the
/// host answers with the row it landed on. Going forward from the live screen asks nothing,
/// because the live screen is as far forward as a window goes.
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
            eprintln!(
                "kr: {} bytes typed while this terminal was asked for its colours could not be \
                 delivered to the session",
                self.bytes
            );
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
        eprintln!(
            "kr: this terminal was not asked what it is, so the host will not let it type. \
             Attach without --no-probe to control the session."
        );
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
            .map_err(|error| CliError::Terminal(error.to_string()))?,
    );
    let input_handle = terminal
        .handle()
        .try_clone()
        .map_err(|error| CliError::Terminal(error.to_string()))?;
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
        eprintln!(
            "kr: this terminal was showing a projection of the session, and it did not carry all \
             of it: {detail}"
        );
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
        eprintln!("kr: not everything about this terminal could be established: {detail}");
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
    /// A size change this terminal made as the size owner.
    Resize,
    /// A size this terminal reported while somebody else owns the size.
    Viewport,
    /// A fresh screen this terminal asked for after a resynchronisation marker.
    Resubscribe,
    /// Where this terminal's window is now looking, after a scroll-back key.
    Scrollback,
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
    // The row this terminal's window starts at while it is looking above the live page. `None` is
    // the live screen. It is reported with every size report as well, so a window the person has
    // scrolled back to stays where they put it when they resize their terminal.
    let mut parked: Option<u64> = None;
    // What each report still in flight asked for, exactly as it asked: a distance above the live
    // screen is not the row it resolves to, and a size report that turned one into the other would
    // name somewhere else. A size report sent meanwhile carries what the newest of them asked for
    // rather than the position the window has left, because the session answers them in the order
    // they arrive and the last one is the one it keeps. They are kept per request, so an older
    // answer cannot forget what a newer request is still waiting to be told.
    let mut requested: std::collections::BTreeMap<
        kr_protocol::ids::RequestId,
        Option<ViewportPosition>,
    > = std::collections::BTreeMap::new();
    // Movement the person has asked for and the session has not answered yet, the step it was
    // measured with, and the size that report carried.
    let mut queued = 0_i64;
    let mut step = 1_u64;
    let mut dimensions_now = attached.dimensions;

    // The output cursor of the last whole screen this terminal was given, which is how it tells a
    // screen the session had something new to say from one it asked for itself.
    let mut drawn_at: Option<u64> = None;

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
            return AttachOutcome::DeliveryUncertain(
                "the connection ended while input was being sent".to_owned(),
            );
        }
        outstanding.insert(request_id, Outstanding::Input(sequence));
        sequence += 1;
    }
    loop {
        tokio::select! {
            // Biased towards the worker, so output and refusals are seen before more input is sent.
            biased;
            message = client.recv() => {
                match message {
                    Ok(ControlFrame::Notification(notification)) => {
                        if notification.event_type.as_str() == "session.output"
                            && let Ok(event) = notification
                                .payload
                                .to_typed::<kr_protocol::recovery::OutputEvent>()
                        {
                            // The session's own bytes: this terminal is being handed the live
                            // stream, so what it shows is the live screen whatever a projection
                            // last said about it.
                            showing_history = false;
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
                            // Where the window actually is, which is not always where this
                            // terminal last asked for: the session gives up its oldest rows, and a
                            // window that was over them is moved to the oldest ones that survive.
                            //
                            // A full-screen application takes the screen, and the window comes
                            // back to the live screen with it: that buffer keeps no history, and
                            // its rows are numbered from its own beginning, so a row identifier
                            // taken from it would name a row of another screen.
                            //
                            // Only a screen that has arrived whole says anything. Between a reset
                            // and the last of its pages this terminal holds no screen at all, and
                            // reading a position out of that would forget where the window is
                            // half way through being told.
                            if let Some(above) = display.window_above_the_live_page() {
                                parked = above;
                                showing_history = above.is_some();
                            }
                            // The client's own choice, not the session's: a person who asked to
                            // follow the live screen is taken back to it the moment the session
                            // writes, and one who did not stays where they scrolled to while the
                            // output goes on arriving underneath.
                            if follow_live
                                && changed
                                && parked.is_some()
                                && let Ok(size) = terminal.size()
                                && size.columns > 0
                                && size.rows > 0
                            {
                                let request_id =
                                    kr_protocol::ids::RequestId::new(next_request);
                                next_request += 1;
                                let params =
                                    kr_protocol::attachment::AttachmentViewportParams {
                                        attachment_id,
                                        dimensions: Dimensions::new(
                                            u64::from(size.columns),
                                            u64::from(size.rows),
                                        ),
                                        position: Nullable(None),
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
                                outstanding.insert(request_id, Outstanding::Scrollback);
                                // Like every other report that names a position: a size report
                                // sent before this is answered carries what this asked for.
                                requested.insert(request_id, None);
                                // Going back to the live screen is a newer instruction than
                                // anything the person had queued above it.
                                queued = 0;
                            }
                            if !drawn.bytes.is_empty() {
                                let mut handle = output.as_ref();
                                if handle.write_all(&drawn.bytes).is_err() {
                                    return AttachOutcome::Disconnected;
                                }
                                let _ = handle.flush();
                            }
                            if drawn.resubscribe {
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
                        // Only this request's own record: an older answer must not forget what a
                        // newer request is still waiting to be told.
                        requested.remove(&answered);
                        match (what, response.outcome) {
                            // A size report is a report, not an insistence. Another attachment may
                            // own the size, and the answer then says so; the terminal is shown that
                            // size rather than taking it, and the attachment carries on.
                            (Outstanding::Resize, outcome) => match outcome {
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
                                    let request_id =
                                        kr_protocol::ids::RequestId::new(next_request);
                                    next_request += 1;
                                    let params =
                                        kr_protocol::attachment::AttachmentViewportParams {
                                            attachment_id,
                                            dimensions: Dimensions::new(
                                                u64::from(size.columns),
                                                u64::from(size.rows),
                                            ),
                                            position: Nullable(
                                                requested
                                                    .values()
                                                    .next_back()
                                                    .copied()
                                                    .unwrap_or_else(|| {
                                                        display
                                                            .window_above_the_live_page()
                                                            .unwrap_or(parked)
                                                            .map(|row| {
                                                                ViewportPosition::Row(U64::new(
                                                                    row,
                                                                ))
                                                            })
                                                    }),
                                            ),
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
                                    outstanding.insert(request_id, Outstanding::Viewport);
                                    requested.insert(request_id, params.position.0);
                                }
                                kr_protocol::envelope::Outcome::Error(_) => {}
                            },
                            // A viewport report answers with the presentation it produced as well
                            // as the geometry, so it has its own result type and its own decoder.
                            (Outstanding::Viewport, outcome) => {
                                if let kr_protocol::envelope::Outcome::Ok(value) = outcome
                                    && let Ok(result) = value.to_typed::<
                                        kr_protocol::attachment::AttachmentViewportResult,
                                    >()
                                {
                                    parked = landed(result.position.0);
                                    geometry_epoch = result.geometry.epoch;
                                    owns_geometry =
                                        result.geometry.owner.as_ref() == Some(&attachment_id);
                                    // A report this terminal made because a resize was refused for
                                    // a stale epoch answers with the epoch it should have quoted.
                                    // The size it asked for is still the size the person is looking
                                    // at, so it asks again, once, with what the answer said.
                                    if owns_geometry
                                        && let Ok(size) = terminal.size()
                                        && size.columns > 0
                                        && size.rows > 0
                                    {
                                        let dimensions = Dimensions::new(
                                            u64::from(size.columns),
                                            u64::from(size.rows),
                                        );
                                        if dimensions != result.geometry.dimensions {
                                            let request_id =
                                                kr_protocol::ids::RequestId::new(next_request);
                                            next_request += 1;
                                            let params =
                                                kr_protocol::attachment::TerminalResizeParams {
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
                                            outstanding.insert(request_id, Outstanding::Resize);
                                        }
                                    }
                                }
                            }
                            (
                                Outstanding::Input(sent),
                                kr_protocol::envelope::Outcome::Error(error),
                            ) => {
                                return match error.code {
                                    ErrorCode::LeaseLost => AttachOutcome::LeaseLost,
                                    ErrorCode::SessionClosed => AttachOutcome::SessionClosed,
                                    code => AttachOutcome::DeliveryUncertain(format!(
                                        "{code} at input {sent}: {}",
                                        error.message
                                    )),
                                };
                            }
                            (Outstanding::Input(_), kr_protocol::envelope::Outcome::Ok(_)) => {}
                            // A scroll-back report answers with the row the window actually
                            // landed on, which is not always the one it asked for: a row the
                            // session has given up becomes the oldest one it still holds, and a
                            // row inside the live page becomes the live screen. The pages that
                            // cover it arrive as ordinary output.
                            (Outstanding::Scrollback, outcome) => {
                                if let kr_protocol::envelope::Outcome::Ok(value) = outcome
                                    && let Ok(result) = value.to_typed::<
                                        kr_protocol::attachment::AttachmentViewportResult,
                                    >()
                                {
                                    parked = landed(result.position.0);
                                }
                                // What the person asked for while this was in flight, resolved
                                // against where the window actually ended up. A refusal leaves the
                                // window where it was, and the movement is measured from there.
                                let asked = (queued != 0)
                                    .then(|| scrolled(parked, queued, step))
                                    .flatten();
                                queued = 0;
                                if let Some(position) = asked {
                                    let request_id =
                                        kr_protocol::ids::RequestId::new(next_request);
                                    next_request += 1;
                                    let params =
                                        kr_protocol::attachment::AttachmentViewportParams {
                                            attachment_id,
                                            dimensions: dimensions_now,
                                            position: Nullable(position),
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
                                    outstanding.insert(request_id, Outstanding::Scrollback);
                                    requested.insert(request_id, position);
                                }
                            }
                            // The screen follows as ordinary output. A refusal means the session no
                            // longer has this attachment, which is the end of it.
                            (Outstanding::Resubscribe, outcome) => {
                                if let kr_protocol::envelope::Outcome::Error(error) = outcome {
                                    return match error.code {
                                        ErrorCode::SessionClosed => AttachOutcome::SessionClosed,
                                        _ => AttachOutcome::Disconnected,
                                    };
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => return AttachOutcome::Disconnected,
                }
            }
            () = wait_for_resize(&mut resized) => {
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
                // What every later report about this window carries, so one queued behind a scroll
                // does not put the terminal's old size back.
                dimensions_now = dimensions;
                let request_id = kr_protocol::ids::RequestId::new(next_request);
                next_request += 1;
                // The owner moves the session's size; anybody else reports the size it is
                // looking at, which changes which presentation it is served and nothing else.
                let (sent, what) = if owns_geometry {
                    let params = kr_protocol::attachment::TerminalResizeParams {
                        attachment_id,
                        dimensions,
                        expected_geometry_epoch: geometry_epoch,
                    };
                    (
                        send_geometry(
                            client,
                            descriptor,
                            request_id,
                            Method::TerminalResize,
                            &params,
                        )
                        .await,
                        Outstanding::Resize,
                    )
                } else {
                    let params = kr_protocol::attachment::AttachmentViewportParams {
                        attachment_id,
                        dimensions,
                        position: Nullable(requested.values().next_back().copied().unwrap_or_else(
                            || {
                                // The window this terminal is drawing, not the last thing an
                                // answer said about it: a screen is newer than an answer that
                                // crossed it.
                                display
                                    .window_above_the_live_page()
                                    .unwrap_or(parked)
                                    .map(|row| ViewportPosition::Row(U64::new(row)))
                            },
                        )),
                    };
                    // Like every other report that names a position: one sent after this, before
                    // this is answered, carries what this asked for.
                    requested.insert(request_id, params.position.0);
                    (
                        send_geometry(
                            client,
                            descriptor,
                            request_id,
                            Method::AttachmentViewport,
                            &params,
                        )
                        .await,
                        Outstanding::Viewport,
                    )
                };
                if !sent {
                    return AttachOutcome::Disconnected;
                }
                outstanding.insert(request_id, what);
            }
            () = pointer_expiry(pointer_deadline) => {
                // Nothing came to finish it, so it was not a report. What was held is the
                // person's, and it goes to the application now.
                pointer_deadline = None;
                let held = pointers.release();
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
                        return AttachOutcome::DeliveryUncertain(
                            "the connection ended while input was being sent".to_owned(),
                        );
                    }
                    outstanding.insert(request_id, Outstanding::Input(sequence));
                    sequence += 1;
                }
            }
            bytes = input.recv() => {
                let Some(bytes) = bytes else {
                    // The terminal's own input ended. Whatever the classifier was part way
                    // through is the person's, and it goes before the attachment does.
                    let held = pointers.release();
                    if !held.is_empty() {
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
                            return AttachOutcome::DeliveryUncertain(
                                "the connection ended while input was being sent".to_owned(),
                            );
                        }
                    }
                    return AttachOutcome::Detached;
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
                    step = scroll_step(shown);
                    dimensions_now =
                        Dimensions::new(u64::from(size.columns), u64::from(size.rows));
                    // Where the window is is the answer's to say and never a request's guess, so
                    // one request is in flight at a time and what the person presses meanwhile
                    // waits for it. A key answered from a position the host had already moved past
                    // would ask for somewhere nobody is, and two keys resolved against the same
                    // position would land where one of them did.
                    queued = queued.saturating_add(steps);
                    if !outstanding
                        .values()
                        .any(|what| matches!(what, Outstanding::Scrollback))
                    {
                        // A movement the window cannot make is spent rather than kept: a window on
                        // the live screen asked to go forward has nowhere to go, and holding that
                        // against the next key would swallow it.
                        let asked = scrolled(parked, queued, step);
                        queued = 0;
                        if let Some(position) = asked {
                        let request_id = kr_protocol::ids::RequestId::new(next_request);
                        next_request += 1;
                        let params = kr_protocol::attachment::AttachmentViewportParams {
                            attachment_id,
                            dimensions: dimensions_now,
                            position: Nullable(position),
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
                        outstanding.insert(request_id, Outstanding::Scrollback);
                        requested.insert(request_id, position);
                        }
                    }
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
                if follow_live
                    && showing_history
                    && let Ok(size) = terminal.size()
                    && size.columns > 0
                    && size.rows > 0
                {
                    let request_id = kr_protocol::ids::RequestId::new(next_request);
                    next_request += 1;
                    let params = kr_protocol::attachment::AttachmentViewportParams {
                        attachment_id,
                        dimensions: Dimensions::new(
                            u64::from(size.columns),
                            u64::from(size.rows),
                        ),
                        position: Nullable(None),
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
                    outstanding.insert(request_id, Outstanding::Scrollback);
                    requested.insert(request_id, None);
                    // Going back to the live screen is a newer instruction than anything the
                    // person had queued above it.
                    queued = 0;
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
                    return AttachOutcome::DeliveryUncertain(
                        "the connection ended while input was being sent".to_owned(),
                    );
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
    use super::{SCROLL_BACK_KEY, SCROLL_FORWARD_KEY, landed, scroll_keys, scroll_step, scrolled};
    use kr_protocol::attachment::ViewportPosition;

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
}
