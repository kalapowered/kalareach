//! A session's screen restored at every point of its output.
//!
//! A person attaches in the middle of whatever the application is doing: half way through an
//! escape sequence, inside a character that takes four bytes, a moment before the application
//! leaves its full-screen view or a moment after it copied something to the clipboard. What the
//! person's terminal holds afterwards has to be the session's screen, and nothing that happened
//! before the person arrived may happen again to their terminal.
//!
//! [`run`] checks that for one corpus. It opens a worker's session in this process (a real
//! pseudo-terminal whose own program writes nothing) and feeds it the corpus one byte at a time
//! through the read loop's own entry, so every point of the output is a point a client can arrive
//! at, and nothing depends on how fast anything runs. At every point two clients attach, each the
//! way a person's client attaches and subscribed the way the worker's service subscribes it:
//!
//! * a terminal of the session's size, which is handed the restoration's bytes and then the live
//!   stream, or a projection that the command's own painter draws into it while the session holds
//!   it back. Its terminal is a terminal engine, which also says every side effect it performed;
//! * a terminal of another size, which holds a projection.
//!
//! At every end of a write, which is where the application paused and the session settles its
//! screen, each client is compared with the session's own screen, read by a client installed at
//! that moment. A client stays attached until the check after the next buffer switch that follows
//! it, so the switch is part of what it is checked through.
//!
//! What is checked, by what each client holds:
//!
//! * **Continuity.** A terminal being handed the stream holds the session's whole screen: both
//!   buffers, the cursor with its pending wrap, the saved cursors, the modes, the keyboard
//!   protocol, the character sets, the margins, the titles, the links and the palette. A terminal
//!   the painter is drawing holds the rows it shows and the cursor, and the painter's own account
//!   of what it could not carry is read apart. A projection holds the session's screen.
//! * **The restored screen.** Directly after a restoration, before anything later is drawn, the
//!   terminal holds the whole screen, the buffer that is not showing included.
//! * **Through a buffer switch.** A client attached before a switch, told to begin again or reset
//!   in its projection by it, holds the session's screen after it.
//! * **No replay.** Taking a restoration, or a painted screen, performs no side effect at all: no
//!   clipboard write or read, no bell, no notification and no reply to a query, and the bytes carry
//!   no sequence that asks for one. Every side effect the application causes after a client
//!   attached reaches the client holding the input lease once, and no other client.
//!
//! [`Strategy`] plants a defect in the direct client instead of taking what the session sends it,
//! so a check that could not fail is not counted as one that passed.

use kr_cli::render::ProjectedDisplay;
use kr_client::projection::{Applied, Projection};
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::ids::{AttachmentId, ConnectionId, SessionId};
use kr_protocol::projection::ProjectionEvent;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::Dimensions;
use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig};
use kr_term::sideeffect::SideEffectKind;
use kr_worker::action::time::TimeSources;
use kr_worker::output::{OutputDelivery, OutputStream};
use kr_worker::session::{InputBatch, Session};

use crate::corpus::Corpus;
use crate::screen::{Parts, View};
use crate::terminal::{Performed, Terminal};

/// The terminal a client of the session's size says it is: one the session hands its stream to.
const QUALIFIED: &str = "xterm-256color";

/// How far narrower than the session the projected client is. A terminal of another size is shown
/// a projection whatever it is, and a whole number of rows keeps its window on every row.
const NARROWER_BY: u16 = 4;

/// How many pairs of clients one session holds at once. A session takes 32 attachments; two per
/// pair and the probe the session's own screen is read with leave one spare.
const PAIRS_AT_ONCE: usize = 15;

/// What the direct client does with what the session sends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// What a person's client does: it takes the restoration and then the stream, and draws a
    /// projection with the command's painter while it is shown one.
    Product,
    /// A restoration that replays the session's retained output instead of drawing its screen.
    Replay,
    /// A restoration with the buffer that is not showing left out.
    WithoutInactive,
    /// A terminal drawn the screen where the client arrived and handed the raw output from that
    /// point, as though the stream could begin anywhere.
    RawFromOffset,
    /// A restoration whose switches into and out of the buffer that is not showing go the other
    /// way, so that buffer's rows land in the one that shows and the other way round.
    ReversedSwitch,
}

/// Which property a failure is of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Property {
    /// A client holds the session's screen at a check.
    Continuity,
    /// A terminal holds the whole screen directly after its restoration.
    Restored,
    /// A client holds the session's screen after a buffer switch that followed its attach.
    ThroughSwitch,
    /// Taking a restoration or a painted screen performed no side effect, and the live stream asked
    /// no terminal a question.
    NoReplay,
    /// A side effect the application caused after a client arrived reached the client holding the
    /// input lease once, and no other client.
    LiveEffect,
}

/// One thing that did not hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// The property.
    pub property: Property,
    /// Where the client attached, as an offset into the corpus.
    pub attached_at: usize,
    /// Where it was checked.
    pub checked_at: usize,
    /// Which client.
    pub client: &'static str,
    /// What was found.
    pub what: String,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{:?}: the {} client attached at byte {} and checked at byte {}: {}",
            self.property, self.client, self.attached_at, self.checked_at, self.what
        )
    }
}

/// What one run found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    /// How many points clients attached at.
    pub points: usize,
    /// How many comparisons were made.
    pub comparisons: usize,
    /// How many restorations were checked directly after they were taken.
    pub restorations: usize,
    /// How many side effects the application caused after some client attached, each of which was
    /// followed to the client it reached.
    pub live_effects: usize,
    /// Everything that did not hold.
    pub failures: Vec<Failure>,
}

impl Outcome {
    /// The failures of one property.
    #[must_use]
    pub fn of(&self, property: Property) -> Vec<&Failure> {
        self.failures
            .iter()
            .filter(|failure| failure.property == property)
            .collect()
    }
}

/// What a direct client's terminal is being given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Served {
    /// Nothing yet.
    Nothing,
    /// The restoration and then the stream.
    Stream,
    /// A projection the painter draws.
    Painted,
}

/// Which of the two clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    /// A terminal of the session's size.
    Direct,
    /// A terminal of another size.
    Projected,
}

impl Form {
    const fn name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Projected => "projected",
        }
    }
}

/// One application side effect, known from the corpus alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caused {
    /// What it was.
    pub kind: SideEffectKind,
    /// The offset its sequence began at, which is the cursor the session delivers it at.
    pub at: u64,
    /// The offset at which the byte that completed it had been read.
    pub completed_at: u64,
}

/// One side effect a client's terminal performed from the live stream, with the cursor of the
/// delivery that carried it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    /// The cursor of the delivery.
    pub cursor: u64,
    /// What the terminal performed.
    pub kind: SideEffectKind,
}

/// What following one client's owed side effects found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    /// Owed effects the terminal never performed, and effects it performed that nobody owed it.
    pub failures: Vec<String>,
}

/// Follows each owed side effect to the delivery that performed it.
///
/// An occurrence is matched by the cursor it is delivered at, which is where its sequence began, and
/// by what it is, so two equal effects are never taken for each other; and the deliveries are
/// matched in the order the effects were caused, because a terminal that performed two clipboard
/// writes the other way round ends up holding the wrong one. An owed effect with no match is a
/// failure, wherever the session told the client to begin again; so is a delivery that matches no
/// owed effect.
#[must_use]
pub fn account(owed: &[Caused], delivered: &[Delivered]) -> Account {
    let mut used = vec![false; delivered.len()];
    let mut found = Account::default();
    // The first delivery a later effect may be matched to.
    let mut after = 0;
    for effect in owed {
        let matched = delivered
            .iter()
            .enumerate()
            .skip(after)
            .find(|(_, got)| got.cursor == effect.at && same_effect(&got.kind, &effect.kind))
            .map(|(index, _)| index);
        match matched {
            Some(index) => {
                used[index] = true;
                after = index + 1;
            }
            None => {
                let what = format!(
                    "its terminal never performed {:?}, which the application began at byte {} and \
                     completed at byte {} while it held the lease",
                    effect.kind, effect.at, effect.completed_at
                );
                found.failures.push(what);
            }
        }
    }
    for (got, used) in delivered.iter().zip(used) {
        if used {
            continue;
        }
        let caused = owed
            .iter()
            .any(|effect| got.cursor == effect.at && same_effect(&got.kind, &effect.kind));
        found.failures.push(if caused {
            format!(
                "its terminal performed {:?} from a delivery at byte {} out of the order the \
                 application caused it in",
                got.kind, got.cursor
            )
        } else {
            format!(
                "its terminal performed {:?} from a delivery at byte {}, which the application did \
                 not cause while it held the lease",
                got.kind, got.cursor
            )
        });
    }
    found
}

struct Client {
    form: Form,
    attachment: AttachmentId,
    attached_at: usize,
    /// The last check this client stays for.
    until: usize,
    stream: Option<OutputStream>,
    /// The terminal a direct client draws into.
    terminal: Option<Terminal>,
    /// The command's painter, for a direct client shown a projection.
    display: Option<ProjectedDisplay>,
    /// The projection this client holds, whatever form it is.
    projection: Projection,
    served: Served,
    /// Side effects the terminal performed while being restored or painted.
    restoring: Vec<String>,
    /// Side effects the terminal performed from the live stream.
    live: Vec<Delivered>,
    ended: bool,
    /// Where the client left, once it has.
    left_at: Option<usize>,
    /// The lease epoch it holds, once it has taken the lease.
    epoch: Option<u64>,
    /// The sequence number of its next input.
    sequence: u64,
}

impl Client {
    /// Feeds the terminal bytes that draw a screen rather than continue one: a restoration, or a
    /// screen the painter drew.
    fn draw(&mut self, bytes: &[u8], what: &str) {
        for sequence in forbidden_in_a_restoration(bytes) {
            self.restoring.push(format!(
                "{what} carries {sequence}, which a restoration never sends"
            ));
        }
        let Some(terminal) = self.terminal.as_mut() else {
            return;
        };
        let performed = terminal.feed(bytes);
        for performed in named(&performed) {
            self.restoring
                .push(format!("taking {what} performed {performed}"));
        }
    }

    /// What this client's terminal shows.
    fn terminal_view(&mut self) -> Result<Option<View>, String> {
        self.terminal.as_mut().map(Terminal::view).transpose()
    }

    /// Feeds the terminal a delivery of the live stream at `cursor`.
    fn live(&mut self, bytes: &[u8], cursor: u64) {
        let Some(terminal) = self.terminal.as_mut() else {
            return;
        };
        let performed = terminal.feed(bytes);
        if performed.replies > 0 {
            self.restoring.push(format!(
                "the live stream asked this terminal {} question(s), which the session answers \
                 itself",
                performed.replies
            ));
        }
        self.live.extend(
            performed
                .effects
                .into_iter()
                .map(|kind| Delivered { cursor, kind }),
        );
    }
}

/// Where a client differs from the session's screen, by what it holds: a projection holds the
/// whole screen; a terminal being handed the stream holds all of it but the wrap marks; a painted
/// terminal holds the rows it shows and the cursor, and then its projection is read as well.
fn compare(client: &mut Client, expected: &View) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    match client.form {
        Form::Projected => match client.projection.screen() {
            Some(screen) => found.extend(
                View::of(screen)
                    .differences(expected, Parts::Whole)
                    .into_iter()
                    .map(|line| format!("its projection: {line}")),
            ),
            None => found.push("it holds no whole screen".to_owned()),
        },
        Form::Direct => {
            let parts = match client.served {
                Served::Stream => Parts::Terminal,
                Served::Painted | Served::Nothing => Parts::Painted,
            };
            if let Some(got) = client.terminal_view()? {
                let mut differences = got.differences(expected, parts);
                // A painter cannot place a cursor that waits to wrap: no sequence moves one there.
                // It says so, and the cursor is then not read from where it was left. The screen
                // the client holds now decides that, never an earlier one, so a cursor misplaced
                // later is still found.
                let waiting_to_wrap = client
                    .projection
                    .screen()
                    .is_some_and(|screen| screen.cursor.pending_wrap);
                if parts == Parts::Painted && waiting_to_wrap {
                    differences.retain(|line| !line.starts_with("cursor at"));
                }
                found.extend(
                    differences
                        .into_iter()
                        .map(|line| format!("its terminal: {line}")),
                );
            }
            if client.served == Served::Painted {
                match client.projection.screen() {
                    Some(screen) => found.extend(
                        View::of(screen)
                            .differences(expected, Parts::Whole)
                            .into_iter()
                            .map(|line| format!("its projection: {line}")),
                    ),
                    None => found.push("it holds no whole screen".to_owned()),
                }
            }
        }
    }
    Ok(found)
}

/// What a terminal performed, as a person would name it.
fn named(performed: &Performed) -> Vec<String> {
    let mut found: Vec<String> = performed
        .effects
        .iter()
        .map(|effect| format!("{effect:?}"))
        .collect();
    found.extend(performed.refused.iter().cloned());
    if performed.replies > 0 {
        found.push(format!("{} reply(ies) to a query", performed.replies));
    }
    found
}

/// The sequences that ask a terminal to do something, found anywhere in `bytes`.
///
/// A restoration is drawn with the string terminator `ESC \`, so a BEL in one is a bell, and an
/// operating-system command that copies, notifies or reports has no business in one at all. The
/// scan is on the bytes, whatever the terminal model makes of them, so it holds for a terminal
/// that reads these differently from the profile.
#[must_use]
pub fn forbidden_in_a_restoration(bytes: &[u8]) -> Vec<&'static str> {
    const SEQUENCES: &[(&[u8], &str)] = &[
        (b"\x07", "a bell"),
        (b"\x1b]52;", "a clipboard write (OSC 52)"),
        (b"\x1b]9;", "a notification (OSC 9)"),
        (b"\x1b]99;", "a notification (OSC 99)"),
        (b"\x1b]777;", "a notification (OSC 777)"),
        (b"\x1b[c", "a device attributes query"),
        (b"\x1b[6n", "a cursor position query"),
        (
            b"\xc2\x9d",
            "an operating-system command introduced by a C1 control",
        ),
    ];
    SEQUENCES
        .iter()
        .filter(|(sequence, _)| {
            bytes
                .windows(sequence.len())
                .any(|window| window == *sequence)
        })
        .map(|(_, name)| *name)
        .collect()
}

/// The side effects a corpus causes, and the offset at which each is complete.
///
/// A terminal engine of the session's size reads the corpus one byte at a time; the byte after
/// which it reports an effect is where the effect happened.
fn caused(corpus: &Corpus) -> Result<Vec<Caused>, String> {
    let mut engine = session_engine(corpus)?;
    let mut found = Vec::new();
    for (offset, byte) in corpus.bytes().iter().enumerate() {
        let outcome = engine.feed(std::slice::from_ref(byte), 0);
        found.extend(outcome.side_effects.into_iter().map(|effect| Caused {
            kind: effect.kind,
            at: effect.at,
            completed_at: offset as u64 + 1,
        }));
    }
    Ok(found)
}

/// Where the corpus switches buffers or resets its screen, as offsets after the byte that did.
fn switches(corpus: &Corpus) -> Result<Vec<usize>, String> {
    let mut engine = session_engine(corpus)?;
    let mut found = Vec::new();
    for (offset, byte) in corpus.bytes().iter().enumerate() {
        if engine.feed(std::slice::from_ref(byte), 0).projection_reset {
            found.push(offset + 1);
        }
    }
    Ok(found)
}

fn session_engine(corpus: &Corpus) -> Result<Engine, String> {
    Engine::new(EngineConfig {
        size: GridSize {
            cols: u32::from(corpus.columns),
            rows: u32::from(corpus.rows),
        },
        ..EngineConfig::DEFAULT
    })
    .map_err(|error| format!("a terminal engine of {}: {error}", corpus.name))
}

/// The session a corpus or a trace is fed to, and everything a run keeps about it.
pub(crate) struct Stage {
    columns: u16,
    rows: u16,
    strategy: Strategy,
    session: Session,
    session_id: SessionId,
    bytes: Vec<u8>,
    fed: usize,
    clients: Vec<Client>,
    /// Which direct client holds the input lease, from which offset: each direct client takes it
    /// when it attaches.
    holders: Vec<(usize, AttachmentId)>,
    outcome: Outcome,
}

/// Runs one corpus with the direct client following `strategy`.
///
/// A pair of clients arrives at every point of the corpus. A session holds a bounded number of
/// attachments, so the points are shared among passes: each pass is a session of its own that is
/// fed the whole corpus and takes every `stride`-th point, the stride being the smallest that keeps
/// each pass's clients within [`PAIRS_AT_ONCE`] at any moment.
///
/// # Errors
///
/// Returns what stopped the run itself: a session that could not be opened, a client that could
/// not attach or subscribe. What the run found is in the outcome's failures.
pub fn run(corpus: &Corpus, strategy: Strategy) -> Result<Outcome, String> {
    let caused = caused(corpus)?;
    let switches = switches(corpus)?;
    let write_ends = corpus.write_ends();
    let total = corpus.bytes().len();
    // A client stays for the check after the first switch that follows its arrival; with no
    // switch after it, for the first check after it.
    let until: Vec<usize> = (0..=total)
        .map(|point| {
            let after = switches
                .iter()
                .copied()
                .find(|switch| *switch > point)
                .unwrap_or(point);
            write_ends
                .iter()
                .copied()
                .find(|end| *end >= after)
                .unwrap_or(total)
        })
        .collect();
    let stride = stride(&until, PAIRS_AT_ONCE);
    let mut outcome = Outcome::default();
    for first in 0..stride {
        let mut stage = Stage::open(
            corpus.columns,
            corpus.rows,
            corpus.bytes(),
            strategy,
            TimeSources::system(),
            None,
        )?;
        for (point, leaves) in until.iter().copied().enumerate() {
            if point % stride == first {
                stage.attach(Form::Direct, leaves, true)?;
                stage.attach(Form::Projected, leaves, false)?;
                stage.outcome.points += 1;
            }
            if point == total {
                break;
            }
            stage.feed(point)?;
            if write_ends.contains(&(point + 1)) {
                stage.check(point + 1, &switches)?;
            }
        }
        // The clients that arrived after the last byte are checked on the screen it left.
        stage.check(total, &switches)?;
        stage.settle_effects(&caused);
        outcome.points += stage.outcome.points;
        outcome.comparisons += stage.outcome.comparisons;
        outcome.restorations += stage.outcome.restorations;
        outcome.live_effects += stage.outcome.live_effects;
        outcome.failures.append(&mut stage.outcome.failures);
    }
    Ok(outcome)
}

/// The smallest stride that keeps every pass within `at_once` clients of each form, given where
/// each point's client leaves.
fn stride(until: &[usize], at_once: usize) -> usize {
    (1..=until.len().max(1))
        .find(|stride| {
            (0..*stride).all(|first| {
                (0..until.len()).all(|position| {
                    until
                        .iter()
                        .enumerate()
                        .filter(|(point, leaves)| {
                            point % stride == first && *point <= position && position <= **leaves
                        })
                        .count()
                        <= at_once
                })
            })
        })
        .unwrap_or(1)
}

impl Stage {
    /// Opens a session of `columns` by `rows` on the clocks `time`, keeping its journal at
    /// `journal` when one is named; `bytes` is what [`Stage::feed`] reads from.
    pub(crate) fn open(
        columns: u16,
        rows: u16,
        bytes: Vec<u8>,
        strategy: Strategy,
        time: TimeSources,
        journal: Option<std::path::PathBuf>,
    ) -> Result<Self, String> {
        let config = crate::session::config(columns, rows, time, journal);
        let session_id = config.session_id;
        let mut session =
            Session::open(config).map_err(|error| format!("the session did not open: {error}"))?;
        session
            .launch()
            .map_err(|error| format!("the session's program did not start: {error}"))?;
        Ok(Self {
            columns,
            rows,
            strategy,
            session,
            session_id,
            bytes,
            fed: 0,
            clients: Vec::new(),
            holders: Vec::new(),
            outcome: Outcome::default(),
        })
    }

    fn fail(&mut self, property: Property, client: &Client, checked_at: usize, what: String) {
        self.outcome.failures.push(Failure {
            property,
            attached_at: client.attached_at,
            checked_at,
            client: client.form.name(),
            what,
        });
    }

    /// Attaches one client where the output has reached, taking the input lease for it when
    /// `lease` says so, subscribes it and draws what it was given. It stays for the checks up to
    /// `until`. Returns which client it is.
    pub(crate) fn attach(
        &mut self,
        form: Form,
        until: usize,
        lease: bool,
    ) -> Result<usize, String> {
        let point = self.fed;
        let (columns, rows) = match form {
            Form::Direct => (self.columns, self.rows),
            Form::Projected => (self.columns.saturating_sub(NARROWER_BY).max(1), self.rows),
        };
        let attachment = AttachmentId::new(kr_ipc::new_uuid());
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        if form == Form::Direct {
            requested.insert(AttachmentCapability::Input);
        }
        let params = SessionAttachParams {
            session_id: self.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(u64::from(columns), u64::from(rows))),
            terminal_profile_id: Nullable::some(QUALIFIED.to_owned()),
            requested: requested.clone(),
        };
        self.session
            .attach(&params, requested, attachment)
            .map_err(|error| format!("a {} client did not attach: {error}", form.name()))?;
        let mut epoch = None;
        if form == Form::Direct && lease {
            let acquired = self
                .session
                .acquire_input(attachment, ConnectionId::new(kr_ipc::new_uuid()), None)
                .map_err(|error| format!("the direct client did not take the lease: {error}"))?;
            epoch = Some(acquired.lease.epoch.get());
            self.holders.push((point, attachment));
        }
        let mut client = Client {
            form,
            attachment,
            attached_at: point,
            until,
            stream: None,
            terminal: match form {
                Form::Direct => Some(Terminal::new(columns, rows)?),
                Form::Projected => None,
            },
            display: (form == Form::Direct).then(ProjectedDisplay::new),
            projection: Projection::new(),
            served: Served::Nothing,
            restoring: Vec::new(),
            live: Vec::new(),
            ended: false,
            left_at: None,
            epoch,
            sequence: 0,
        };
        self.subscribe(&mut client)?;
        self.pump(&mut client)?;
        self.clients.push(client);
        Ok(self.clients.len() - 1)
    }

    /// Subscribes a client as the worker's service subscribes one: its screen first, under the same
    /// hold that starts its queue, then the projection a projected attachment is installed with.
    fn subscribe(&mut self, client: &mut Client) -> Result<(), String> {
        let joined = self
            .session
            .join(client.attachment)
            .map_err(|error| format!("the {} client did not join: {error}", client.form.name()))?;
        let stream = self.session.subscribe(client.attachment).map_err(|error| {
            format!(
                "the {} client did not subscribe: {error}",
                client.form.name()
            )
        })?;
        self.session
            .install_projection(client.attachment)
            .map_err(|error| {
                format!(
                    "the {} client's screen was not queued: {error}",
                    client.form.name()
                )
            })?;
        client.stream = Some(stream);
        client.projection.discard();
        if client.form == Form::Projected {
            return Ok(());
        }
        if self.strategy == Strategy::RawFromOffset {
            // The screen where the client arrived, whatever the parser is in the middle of, and the
            // raw output from that point on.
            if client.served == Served::Nothing {
                let (_, bytes) = self
                    .session
                    .restoration(client.attachment)
                    .map_err(|error| format!("no screen at the point of arrival: {error}"))?;
                client.draw(&bytes, "the screen at the point of arrival");
                client.served = Served::Stream;
            }
            return Ok(());
        }
        if joined.bytes.is_empty() {
            return Ok(());
        }
        let bytes = match self.strategy {
            Strategy::Replay => {
                let oldest = self.session.oldest_retained_cursor();
                self.session
                    .history_page(oldest, u64::MAX)
                    .map_err(|error| format!("the retained output could not be read: {error}"))?
                    .bytes
                    .as_slice()
                    .to_vec()
            }
            Strategy::WithoutInactive => without_the_buffer_not_showing(&joined.bytes),
            Strategy::ReversedSwitch => with_the_switches_reversed(&joined.bytes),
            Strategy::Product | Strategy::RawFromOffset => joined.bytes,
        };
        client.draw(&bytes, "the restoration");
        client.served = Served::Stream;
        // The restored screen, checked before anything later is drawn on it. When the session
        // hands this terminal the stream afterwards, the restoration had to carry the whole
        // screen; when it keeps the terminal on a projection, because the restoration could not
        // carry some of it, what every restoration carries is both buffers' rows.
        let handed_the_stream = self
            .session
            .attachments()
            .into_iter()
            .find(|summary| summary.attachment_id == client.attachment)
            .is_some_and(|summary| {
                summary.presentation.as_ref()
                    == Some(&kr_protocol::attachment::TerminalPresentationMode::Direct)
            });
        let parts = if handed_the_stream {
            Parts::Terminal
        } else {
            Parts::Buffers
        };
        let expected = self.canonical()?;
        if let Some(got) = client.terminal_view()? {
            self.outcome.restorations += 1;
            let found = got.differences(&expected, parts);
            if !found.is_empty() {
                let at = self.fed;
                self.fail(Property::Restored, client, at, found.join("; "));
            }
        }
        Ok(())
    }

    /// Takes everything queued for one client and draws it.
    fn pump(&mut self, client: &mut Client) -> Result<(), String> {
        loop {
            let Some(stream) = client.stream.as_mut() else {
                return Ok(());
            };
            let Some(delivery) = stream.try_recv() else {
                return Ok(());
            };
            stream.written(delivery.len());
            match delivery {
                OutputDelivery::Bytes { cursor, bytes }
                | OutputDelivery::Effect { cursor, bytes } => {
                    if client.form == Form::Projected {
                        let at = self.fed;
                        self.fail(
                            Property::NoReplay,
                            client,
                            at,
                            "a terminal of another size was handed raw output".to_owned(),
                        );
                    } else if self.strategy != Strategy::RawFromOffset {
                        client.live(&bytes, cursor);
                    }
                }
                OutputDelivery::Screen { bytes, .. } => {
                    if self.strategy != Strategy::RawFromOffset {
                        client.draw(&bytes, "a drawn screen");
                    }
                }
                OutputDelivery::Projection { event, .. } => self.projected(client, *event)?,
                OutputDelivery::Resync(_) => {
                    // As the command does: the screen it held is no longer the session, so it asks
                    // for the session's screen again, on the same attachment, from no cursor.
                    self.subscribe(client)?;
                }
                OutputDelivery::Detached | OutputDelivery::Closed(_) => {
                    client.ended = true;
                    client.stream = None;
                }
                OutputDelivery::EditorBusy(_)
                | OutputDelivery::AgentResource { .. }
                | OutputDelivery::AgentInstance { .. } => {}
            }
        }
    }

    fn projected(&mut self, client: &mut Client, event: ProjectionEvent) -> Result<(), String> {
        let refused = matches!(client.projection.apply(event.clone()), Applied::Refused(_));
        let mut again = refused;
        if client.form == Form::Direct
            && self.strategy != Strategy::RawFromOffset
            && let Some(display) = client.display.as_mut()
        {
            let drawn = display.apply(event);
            again |= drawn.resubscribe;
            if !drawn.bytes.is_empty() {
                client.draw(&drawn.bytes, "a painted screen");
            }
            if drawn.installed {
                client.served = Served::Painted;
            }
        }
        if again {
            self.subscribe(client)?;
        }
        Ok(())
    }

    /// Reads byte `point` of the corpus into the session, as the read loop would.
    fn feed(&mut self, point: usize) -> Result<(), String> {
        debug_assert_eq!(point, self.fed, "a corpus is read in order");
        let byte = [self.bytes[point]];
        self.ingest(&byte)
    }

    /// The session's own screen, as a client installed at this moment holds it.
    fn canonical(&mut self) -> Result<View, String> {
        let probe = AttachmentId::new(kr_ipc::new_uuid());
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        let params = SessionAttachParams {
            session_id: self.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(
                u64::from(self.columns),
                u64::from(self.rows),
            )),
            // No terminal named, so the probe is shown a projection whatever the parser is doing.
            terminal_profile_id: Nullable::null(),
            requested: requested.clone(),
        };
        self.session
            .attach(&params, requested, probe)
            .map_err(|error| format!("the probe did not attach: {error}"))?;
        let _ = self
            .session
            .join(probe)
            .map_err(|error| format!("the probe did not join: {error}"))?;
        let mut stream = self
            .session
            .subscribe(probe)
            .map_err(|error| format!("the probe did not subscribe: {error}"))?;
        self.session
            .install_projection(probe)
            .map_err(|error| format!("the probe's screen was not queued: {error}"))?;
        let mut projection = Projection::new();
        while let Some(delivery) = stream.try_recv() {
            stream.written(delivery.len());
            if let OutputDelivery::Projection { event, .. } = delivery {
                let _ = projection.apply(*event);
            }
        }
        let _ = self.session.detach(probe);
        projection
            .screen()
            .map(View::of)
            .ok_or_else(|| "the probe was not installed a whole screen".to_owned())
    }

    /// Compares every client with the session's screen at `at`, and lets go of those whose stay is
    /// over.
    fn check(&mut self, at: usize, switches: &[usize]) -> Result<(), String> {
        let _ = self.session.quiesce_output();
        let mut clients = std::mem::take(&mut self.clients);
        for client in &mut clients {
            self.pump(client)?;
        }
        if clients.iter().all(|client| client.ended) {
            self.clients = clients;
            return Ok(());
        }
        let expected = self.canonical()?;
        for client in &mut clients {
            if client.ended {
                continue;
            }
            let switched = switches
                .iter()
                .any(|switch| *switch > client.attached_at && *switch <= at);
            let property = if switched {
                Property::ThroughSwitch
            } else {
                Property::Continuity
            };
            self.outcome.comparisons += 1;
            let found = compare(client, &expected)?;
            if !found.is_empty() {
                self.fail(property, client, at, found.join("; "));
            }
            let restoring = std::mem::take(&mut client.restoring);
            for what in restoring {
                self.fail(Property::NoReplay, client, at, what);
            }
        }
        // Those whose stay is over leave; what they were given stays with them for the account of
        // live side effects.
        for client in &mut clients {
            if client.until <= at && !client.ended {
                let _ = self.session.detach(client.attachment);
                client.stream = None;
                client.ended = true;
                client.left_at = Some(at);
            }
        }
        self.clients = clients;
        Ok(())
    }

    /// Follows every side effect the application caused to the clients it reached.
    ///
    /// Each one that happened while some direct client held the lease is owed to that client once
    /// and to no other; those that happened while no client was attached are owed to nobody. What
    /// [`account`] finds lost is kept apart: see [`Outcome::lost`].
    fn settle_effects(&mut self, caused: &[Caused]) {
        let clients = std::mem::take(&mut self.clients);
        for client in &clients {
            if client.form != Form::Direct || self.strategy != Strategy::Product {
                continue;
            }
            let left = client.left_at.unwrap_or(client.until);
            let owed: Vec<Caused> = caused
                .iter()
                .filter(|effect| {
                    effect.completed_at > client.attached_at as u64
                        && effect.completed_at <= left as u64
                        && self.holder_at(effect.completed_at) == Some(client.attachment)
                        && kr_worker::render::side_effect(&effect.kind).is_some()
                })
                .cloned()
                .collect();
            self.outcome.live_effects += owed.len();
            let found = account(&owed, &client.live);
            let failure = |what: String| Failure {
                property: Property::LiveEffect,
                attached_at: client.attached_at,
                checked_at: left,
                client: client.form.name(),
                what,
            };
            self.outcome
                .failures
                .extend(found.failures.into_iter().map(failure));
        }
        self.clients = clients;
    }

    /// The direct client holding the lease once the byte at `offset` had been read.
    fn holder_at(&self, offset: u64) -> Option<AttachmentId> {
        self.holders
            .iter()
            .rev()
            .find(|(from, _)| (*from as u64) < offset)
            .map(|(_, attachment)| *attachment)
    }

    /// Reads `bytes` into the session as one read of the program's output, and hands every client
    /// what it was given. A direct client planted to take the raw output from where it arrived is
    /// handed these bytes as they are.
    pub(crate) fn ingest(&mut self, bytes: &[u8]) -> Result<(), String> {
        let _ = self.session.ingest_output(bytes);
        let at = self.fed as u64;
        self.fed += bytes.len();
        let mut clients = std::mem::take(&mut self.clients);
        for client in &mut clients {
            if client.form == Form::Direct
                && self.strategy == Strategy::RawFromOffset
                && client.served == Served::Stream
            {
                client.live(bytes, at);
            }
        }
        self.clients = clients;
        self.pump_all()
    }

    fn pump_all(&mut self) -> Result<(), String> {
        let mut clients = std::mem::take(&mut self.clients);
        let mut pumped = Ok(());
        for client in &mut clients {
            pumped = pumped.and_then(|()| self.pump(client));
        }
        self.clients = clients;
        pumped
    }

    /// Settles the session's screen, as the read loop does when the program pauses, and hands
    /// every client what that released.
    pub(crate) fn settle(&mut self) -> Result<(), String> {
        let _ = self.session.quiesce_output();
        self.pump_all()
    }

    /// Takes the input lease for client `index`, and returns what the session said.
    pub(crate) fn acquire(
        &mut self,
        index: usize,
    ) -> Result<kr_protocol::input::InputAcquireResult, String> {
        let attachment = self.clients[index].attachment;
        let acquired = self
            .session
            .acquire_input(attachment, ConnectionId::new(kr_ipc::new_uuid()), None)
            .map_err(|error| format!("client {index} did not take the lease: {error}"))?;
        // A lease numbers its writes from zero.
        self.clients[index].epoch = Some(acquired.lease.epoch.get());
        self.clients[index].sequence = 0;
        self.holders.push((self.fed, attachment));
        self.pump_all()?;
        Ok(acquired)
    }

    /// Writes `bytes` as client `index`'s input at `now`, under the lease it took last, and returns
    /// what the session answered. A client that never took the lease has nothing to write under.
    pub(crate) fn input(
        &mut self,
        index: usize,
        bytes: &[u8],
        now: std::time::Instant,
    ) -> Result<kr_worker::Result<kr_worker::session::InputAccepted>, String> {
        let client = &mut self.clients[index];
        let epoch = client
            .epoch
            .ok_or_else(|| format!("client {index} never took the lease"))?;
        let sequence = client.sequence;
        client.sequence += 1;
        let attachment = client.attachment;
        let answer = self
            .session
            .write_input(attachment, epoch, sequence, bytes, None, now);
        self.pump_all()?;
        Ok(answer)
    }

    /// Fires the paste recogniser's timer when its deadline is at or before `now`, as the
    /// worker's timer does, and says whether it fired.
    pub(crate) fn fire_paste_timer(&mut self, now: std::time::Instant) -> Result<bool, String> {
        let due = self
            .session
            .paste_deadline()
            .is_some_and(|deadline| deadline <= now);
        if due {
            let _ = self.session.expire_paste_prefix(now);
            self.pump_all()?;
        }
        Ok(due)
    }

    /// Detaches client `index`; what it was given stays with it.
    pub(crate) fn detach(&mut self, index: usize) -> Result<(), String> {
        let client = &mut self.clients[index];
        self.session
            .detach(client.attachment)
            .map_err(|error| format!("client {index} did not detach: {error}"))?;
        client.stream = None;
        client.ended = true;
        client.left_at = Some(self.fed);
        self.pump_all()
    }

    /// Everything queued for the program's input since the last call.
    pub(crate) fn pending_input(&mut self) -> Vec<InputBatch> {
        self.session.take_pending_input()
    }

    /// Where client `index` differs from the session's screen now; empty when it holds it.
    pub(crate) fn differences(&mut self, index: usize) -> Result<Vec<String>, String> {
        self.settle()?;
        let expected = self.canonical()?;
        compare(&mut self.clients[index], &expected)
    }

    /// The side effects client `index`'s terminal performed from the live stream.
    pub(crate) fn live(&self, index: usize) -> &[Delivered] {
        &self.clients[index].live
    }

    /// What client `index`'s terminal did while it was being drawn a screen since the last call,
    /// which is nothing when all is well.
    pub(crate) fn take_restoring(&mut self, index: usize) -> Vec<String> {
        std::mem::take(&mut self.clients[index].restoring)
    }

    /// What the checks the stage makes on its own found since the last call: a restored screen
    /// that was not the session's, and raw output handed to a terminal of another size.
    pub(crate) fn take_failures(&mut self) -> Vec<Failure> {
        std::mem::take(&mut self.outcome.failures)
    }

    /// The session's own screen once the application pauses.
    pub(crate) fn screen(&mut self) -> Result<View, String> {
        self.settle()?;
        self.canonical()
    }

    /// The session itself.
    pub(crate) const fn session(&mut self) -> &mut Session {
        &mut self.session
    }
}

/// Two side effects are the same kind, a clipboard write's selection and content included.
fn same_effect(got: &SideEffectKind, owed: &SideEffectKind) -> bool {
    match (got, owed) {
        (
            SideEffectKind::ClipboardWrite {
                selection: got_selection,
                content: got_content,
            },
            SideEffectKind::ClipboardWrite {
                selection: owed_selection,
                content: owed_content,
            },
        ) => got_selection == owed_selection && got_content == owed_content,
        _ => std::mem::discriminant(got) == std::mem::discriminant(owed),
    }
}

/// A restoration with every mode-47 switch turned the other way.
#[must_use]
pub fn with_the_switches_reversed(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let rest = &bytes[at..];
        if rest.starts_with(b"\x1b[?47h") {
            out.extend_from_slice(b"\x1b[?47l");
            at += 6;
        } else if rest.starts_with(b"\x1b[?47l") {
            out.extend_from_slice(b"\x1b[?47h");
            at += 6;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    out
}

/// A restoration with the part that paints the buffer that is not showing cut out.
///
/// The session paints that buffer between a switch to it with mode 47 and the switch back; this
/// removes both switches and everything between them, and returns the bytes unchanged when there
/// is no such part.
#[must_use]
pub fn without_the_buffer_not_showing(bytes: &[u8]) -> Vec<u8> {
    for (enter, leave) in [
        (&b"\x1b[?47h"[..], &b"\x1b[?47l"[..]),
        (&b"\x1b[?47l"[..], &b"\x1b[?47h"[..]),
    ] {
        let Some(start) = find(bytes, enter) else {
            continue;
        };
        let Some(end) = find(&bytes[start + enter.len()..], leave) else {
            continue;
        };
        let end = start + enter.len() + end + leave.len();
        let mut cut = bytes[..start].to_vec();
        cut.extend_from_slice(&bytes[end..]);
        return cut;
    }
    bytes.to_vec()
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scan_names_each_sequence_a_restoration_must_not_carry() {
        assert!(forbidden_in_a_restoration(b"\x1b[?25h\x1b]2;title\x1b\\text").is_empty());
        assert_eq!(
            forbidden_in_a_restoration(b"a\x07b\x1b]52;c;eA==\x1b\\"),
            vec!["a bell", "a clipboard write (OSC 52)"]
        );
    }

    #[test]
    fn reversing_the_switches_turns_each_mode_47_switch_the_other_way() {
        assert_eq!(
            with_the_switches_reversed(b"a\x1b[?47hb\x1b[?47lc\x1b[?1047h"),
            b"a\x1b[?47lb\x1b[?47hc\x1b[?1047h".to_vec()
        );
    }

    fn bell(at: u64, completed_at: u64) -> Caused {
        Caused {
            kind: SideEffectKind::Bell,
            at,
            completed_at,
        }
    }

    #[test]
    fn an_owed_effect_the_terminal_never_performed_fails_wherever_it_was_completed() {
        // Two bells owed and neither performed: each is a failure, whatever else was happening at
        // the byte that completed it.
        let found = account(&[bell(9, 10), bell(19, 20)], &[]);
        assert_eq!(found.failures.len(), 2, "{found:?}");
        assert!(
            found.failures[0].contains("completed at byte 10"),
            "{found:?}"
        );
        assert!(
            found.failures[1].contains("completed at byte 20"),
            "{found:?}"
        );
    }

    #[test]
    fn an_effect_nobody_owed_fails_beside_one_that_was_not_performed() {
        let delivered = [Delivered {
            cursor: 30,
            kind: SideEffectKind::Bell,
        }];
        let found = account(&[bell(9, 10)], &delivered);
        assert_eq!(found.failures.len(), 2, "{found:?}");
        assert!(
            found
                .failures
                .iter()
                .any(|failure| failure.contains("delivery at byte 30")),
            "{found:?}"
        );
    }

    #[test]
    fn two_equal_effects_are_told_apart_by_where_they_were_delivered() {
        // The second bell arrived; the first did not.
        let delivered = [Delivered {
            cursor: 19,
            kind: SideEffectKind::Bell,
        }];
        let found = account(&[bell(9, 10), bell(19, 20)], &delivered);
        assert_eq!(found.failures.len(), 1, "{found:?}");
        assert!(found.failures[0].contains("began at byte 9"), "{found:?}");
    }

    fn clipboard(content: &str, at: u64) -> Caused {
        Caused {
            kind: SideEffectKind::ClipboardWrite {
                selection: kr_term::sideeffect::ClipboardSelection::Clipboard,
                content: content.as_bytes().to_vec(),
            },
            at,
            completed_at: at + 5,
        }
    }

    fn performed(effect: &Caused) -> Delivered {
        Delivered {
            cursor: effect.at,
            kind: effect.kind.clone(),
        }
    }

    #[test]
    fn two_effects_performed_the_other_way_round_fail() {
        let (first, second) = (clipboard("first", 10), clipboard("second", 20));
        let found = account(
            &[first.clone(), second.clone()],
            &[performed(&second), performed(&first)],
        );
        assert!(
            found
                .failures
                .iter()
                .any(|failure| failure.contains("out of the order")),
            "{found:?}"
        );
        let in_order = account(
            &[first.clone(), second.clone()],
            &[performed(&first), performed(&second)],
        );
        assert_eq!(in_order, Account::default());
    }

    #[test]
    fn a_reversed_pair_fails_beside_an_effect_that_was_not_performed() {
        let (first, second) = (clipboard("first", 10), clipboard("second", 20));
        let found = account(
            &[bell(4, 5), first.clone(), second.clone()],
            &[performed(&second), performed(&first)],
        );
        assert!(
            found
                .failures
                .iter()
                .any(|failure| failure.contains("completed at byte 5")),
            "the bell fails: {found:?}"
        );
        assert!(
            found
                .failures
                .iter()
                .any(|failure| failure.contains("out of the order")),
            "the reversal fails too: {found:?}"
        );
    }

    #[test]
    fn cutting_the_other_buffer_removes_the_switch_and_everything_it_painted() {
        let restoration = b"\x1b[!p\x1b[?47h\x1b[H\x1b[2Jother\x1b[?47l\x1b[Hshowing";
        assert_eq!(
            without_the_buffer_not_showing(restoration),
            b"\x1b[!p\x1b[Hshowing".to_vec()
        );
        assert_eq!(without_the_buffer_not_showing(b"plain"), b"plain".to_vec());
    }
}
