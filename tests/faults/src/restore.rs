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
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{AttachmentId, ConnectionId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::projection::ProjectionEvent;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig, FeedOutcome};
use kr_term::sideeffect::SideEffectKind;
use kr_worker::output::{OutputDelivery, OutputStream};
use kr_worker::session::{Session, SessionConfig};

use crate::corpus::Corpus;
use crate::screen::{Parts, View};

/// The terminal a client of the session's size says it is: one the session hands its stream to.
const QUALIFIED: &str = "xterm-256color";

/// How far narrower than the session the projected client is. A terminal of another size is shown
/// a projection whatever it is, and a whole number of rows keeps its window on every row.
const NARROWER_BY: u16 = 4;

/// Every subscriber's queue, large enough that a client that is read after every byte is never
/// told to begin again for want of room: that is a different property, with tests of its own.
const SEND_QUEUE_BYTES: usize = 8 * 1024 * 1024;

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
    /// Side effects owed to a lease holder that the session told to begin again on the byte that
    /// completed them, and that never reached it. They are kept apart from the failures, because
    /// they are one known behaviour of the session with a test of its own.
    pub lost: Vec<Failure>,
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
enum Form {
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

/// One application side effect, known from the corpus alone: what it was and the offset at which
/// the byte that completed it had been read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Caused {
    kind: SideEffectKind,
    completed_at: usize,
}

struct Client {
    form: Form,
    attachment: AttachmentId,
    attached_at: usize,
    /// The last check this client stays for.
    until: usize,
    stream: Option<OutputStream>,
    /// The terminal a direct client draws into.
    terminal: Option<Engine>,
    /// The command's painter, for a direct client shown a projection.
    display: Option<ProjectedDisplay>,
    /// The projection this client holds, whatever form it is.
    projection: Projection,
    served: Served,
    /// Side effects the terminal performed while being restored or painted.
    restoring: Vec<String>,
    /// Side effects the terminal performed from the live stream.
    live: Vec<SideEffectKind>,
    /// The offsets at which the session told this client to begin again.
    resyncs_at: Vec<usize>,
    ended: bool,
    /// Where the client left, once it has.
    left_at: Option<usize>,
    /// The other buffer as the last restoration painted it, for a direct client.
    ///
    /// A restoration paints the buffer that is not showing by switching to it with mode 47 and
    /// back. A terminal of the xterm family, which is what a direct client's terminal is, switches
    /// on mode 47; the profile's own engine records the mode and stays on the buffer it is on, so
    /// the model hands those rows to a buffer of their own, as such a terminal would.
    other: Option<Vec<crate::screen::Line>>,
    started: std::time::Instant,
}

impl Client {
    fn now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Feeds the terminal a restoration: the bytes that put a terminal into the session's state.
    ///
    /// The part that paints the buffer that is not showing is painted into a buffer of its own,
    /// which is what a terminal that switches on mode 47 does with it.
    fn restore(&mut self, bytes: &[u8], what: &str) -> Result<(), String> {
        let (showing, other) = split_the_buffer_not_showing(bytes);
        if let Some(terminal) = self.terminal.as_ref() {
            let size = terminal.grid().size();
            let mut buffer = Engine::new(EngineConfig {
                size,
                ..EngineConfig::DEFAULT
            })
            .map_err(|error| format!("a buffer for the other rows: {error}"))?;
            if let Some(rows) = other.as_ref() {
                let outcome = buffer.feed(rows, 0);
                for performed in performed(&outcome) {
                    self.restoring
                        .push(format!("painting the other buffer performed {performed}"));
                }
            }
            self.other = Some(crate::screen::View::of_engine(&mut buffer, 0)?.lines);
        }
        self.paint(&showing, what);
        Ok(())
    }

    /// Feeds the terminal bytes that draw a screen rather than continue one.
    fn paint(&mut self, bytes: &[u8], what: &str) {
        for sequence in forbidden_in_a_restoration(bytes) {
            self.restoring.push(format!(
                "{what} carries {sequence}, which a restoration never sends"
            ));
        }
        let now = self.now();
        let Some(terminal) = self.terminal.as_mut() else {
            return;
        };
        let outcome = terminal.feed(bytes, now);
        let settled = terminal.quiesce(now);
        for outcome in [outcome, settled] {
            for performed in performed(&outcome) {
                self.restoring
                    .push(format!("taking {what} performed {performed}"));
            }
        }
    }

    /// What this client's terminal shows, with the other buffer as its restoration painted it.
    fn terminal_view(&mut self) -> Result<Option<View>, String> {
        let now = self.now();
        let other = self.other.clone();
        let Some(terminal) = self.terminal.as_mut() else {
            return Ok(None);
        };
        let view = View::of_engine(terminal, now)?;
        Ok(Some(match other {
            Some(other) => view.with_other(other),
            None => view,
        }))
    }

    /// Feeds the terminal bytes of the live stream.
    fn live(&mut self, bytes: &[u8]) {
        let now = self.now();
        let Some(terminal) = self.terminal.as_mut() else {
            return;
        };
        let outcome = terminal.feed(bytes, now);
        if outcome.responses > 0 {
            self.restoring.push(format!(
                "the live stream asked this terminal {} question(s), which the session answers \
                 itself",
                outcome.responses
            ));
        }
        self.live
            .extend(outcome.side_effects.into_iter().map(|effect| effect.kind));
    }
}

/// What a terminal performed, as a person would name it.
fn performed(outcome: &FeedOutcome) -> Vec<String> {
    let mut found: Vec<String> = outcome
        .side_effects
        .iter()
        .map(|effect| format!("{:?}", effect.kind))
        .collect();
    found.extend(
        outcome
            .refusals
            .iter()
            .map(|refusal| format!("a refused side effect ({refusal:?})")),
    );
    if outcome.responses > 0 {
        found.push(format!("{} reply(ies) to a query", outcome.responses));
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
            completed_at: offset + 1,
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

/// A terminal engine standing in for a person's physical terminal.
fn terminal(columns: u16, rows: u16) -> Result<Engine, String> {
    Engine::new(EngineConfig {
        size: GridSize {
            cols: u32::from(columns),
            rows: u32::from(rows),
        },
        ..EngineConfig::DEFAULT
    })
    .map_err(|error| format!("a terminal of {columns}x{rows}: {error}"))
}

/// The session a corpus is fed to, and everything a run keeps about it.
struct Stage<'a> {
    corpus: &'a Corpus,
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
        let mut stage = Stage::open(corpus, strategy)?;
        for (point, leaves) in until.iter().copied().enumerate() {
            if point % stride == first {
                stage.attach(Form::Direct, point, leaves)?;
                stage.attach(Form::Projected, point, leaves)?;
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
        outcome.lost.append(&mut stage.outcome.lost);
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

impl<'a> Stage<'a> {
    fn open(corpus: &'a Corpus, strategy: Strategy) -> Result<Self, String> {
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            display_number: DisplayNumber::new(1),
            // A program that writes nothing and waits: every byte of output is the corpus.
            shell: kr_worker::testing::posix_script("IFS= read -r _"),
            shell_mode: ShellMode::NativeCompat,
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(u64::from(corpus.columns), u64::from(corpus.rows)),
            journal_path: None,
            spool_directory: None,
            worker_endpoint: None,
            send_queue_bytes: SEND_QUEUE_BYTES,
            resident_bytes: 4 * 1024 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
        };
        let mut session =
            Session::open(config).map_err(|error| format!("the session did not open: {error}"))?;
        session
            .launch()
            .map_err(|error| format!("the session's program did not start: {error}"))?;
        Ok(Self {
            corpus,
            strategy,
            session,
            session_id,
            bytes: corpus.bytes(),
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

    /// Attaches one client at `point`, subscribes it and draws what it was given.
    fn attach(&mut self, form: Form, point: usize, until: usize) -> Result<(), String> {
        let (columns, rows) = match form {
            Form::Direct => (self.corpus.columns, self.corpus.rows),
            Form::Projected => (
                self.corpus.columns.saturating_sub(NARROWER_BY).max(1),
                self.corpus.rows,
            ),
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
        if form == Form::Direct {
            self.session
                .acquire_input(attachment, ConnectionId::new(kr_ipc::new_uuid()), None)
                .map_err(|error| format!("the direct client did not take the lease: {error}"))?;
            self.holders.push((point, attachment));
        }
        let mut client = Client {
            form,
            attachment,
            attached_at: point,
            until,
            stream: None,
            terminal: match form {
                Form::Direct => Some(terminal(columns, rows)?),
                Form::Projected => None,
            },
            display: (form == Form::Direct).then(ProjectedDisplay::new),
            projection: Projection::new(),
            served: Served::Nothing,
            restoring: Vec::new(),
            live: Vec::new(),
            resyncs_at: Vec::new(),
            ended: false,
            left_at: None,
            other: None,
            started: std::time::Instant::now(),
        };
        self.subscribe(&mut client)?;
        self.pump(&mut client)?;
        self.clients.push(client);
        Ok(())
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
                client.restore(&bytes, "the screen at the point of arrival")?;
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
            Strategy::Product | Strategy::RawFromOffset => joined.bytes,
        };
        client.restore(&bytes, "the restoration")?;
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
                OutputDelivery::Bytes { bytes, .. } => {
                    if client.form == Form::Projected {
                        let at = self.fed;
                        self.fail(
                            Property::NoReplay,
                            client,
                            at,
                            "a terminal of another size was handed raw output".to_owned(),
                        );
                    } else if self.strategy != Strategy::RawFromOffset {
                        client.live(&bytes);
                    }
                }
                OutputDelivery::Screen { bytes, .. } => {
                    if self.strategy != Strategy::RawFromOffset {
                        client.paint(&bytes, "a drawn screen");
                    }
                }
                OutputDelivery::Projection { event, .. } => self.projected(client, *event)?,
                OutputDelivery::Resync(_) => {
                    // As the command does: the screen it held is no longer the session, so it asks
                    // for the session's screen again, on the same attachment, from no cursor.
                    client.resyncs_at.push(self.fed);
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
                client.paint(&drawn.bytes, "a painted screen");
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
        let byte = [self.bytes[point]];
        let _ = self.session.ingest_output(&byte);
        self.fed = point + 1;
        let mut clients = std::mem::take(&mut self.clients);
        for client in &mut clients {
            if client.form == Form::Direct
                && self.strategy == Strategy::RawFromOffset
                && client.served == Served::Stream
            {
                client.live(&byte);
            }
            self.pump(client)?;
        }
        self.clients = clients;
        Ok(())
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
                u64::from(self.corpus.columns),
                u64::from(self.corpus.rows),
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
            let mut found = Vec::new();
            match client.form {
                Form::Projected => {
                    self.outcome.comparisons += 1;
                    match client.projection.screen() {
                        Some(screen) => found.extend(
                            View::of(screen)
                                .differences(&expected, Parts::Whole)
                                .into_iter()
                                .map(|line| format!("its projection: {line}")),
                        ),
                        None => found.push("it holds no whole screen".to_owned()),
                    }
                }
                Form::Direct => {
                    self.outcome.comparisons += 1;
                    let parts = match client.served {
                        Served::Stream => Parts::Terminal,
                        Served::Painted | Served::Nothing => Parts::Painted,
                    };
                    if let Some(got) = client.terminal_view()? {
                        let mut differences = got.differences(&expected, parts);
                        if parts == Parts::Painted {
                            // A cursor the painter said it could not place is read from its own
                            // account, not from where it was left.
                            let losses = client
                                .display
                                .as_ref()
                                .map(ProjectedDisplay::losses)
                                .unwrap_or_default();
                            if losses.pending_wrap || losses.cursor_outside {
                                differences.retain(|line| !line.starts_with("cursor at"));
                            }
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
                                    .differences(&expected, Parts::Whole)
                                    .into_iter()
                                    .map(|line| format!("its projection: {line}")),
                            ),
                            None => found.push("it holds no whole screen".to_owned()),
                        }
                    }
                }
            }
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
    /// and to no other. Those that happened while no client was attached are owed to nobody. An
    /// owed effect the client never performed, completed by the very byte at which the session
    /// told that client to begin again, is counted as lost rather than failed: see
    /// [`Outcome::lost`].
    fn settle_effects(&mut self, caused: &[Caused]) {
        let clients = std::mem::take(&mut self.clients);
        for client in &clients {
            if client.form != Form::Direct || self.strategy != Strategy::Product {
                continue;
            }
            let left = client.left_at.unwrap_or(client.until);
            let owed: Vec<&Caused> = caused
                .iter()
                .filter(|effect| {
                    effect.completed_at > client.attached_at
                        && effect.completed_at <= left
                        && self.holder_at(effect.completed_at) == Some(client.attachment)
                        && kr_worker::render::side_effect(&effect.kind).is_some()
                })
                .collect();
            self.outcome.live_effects += owed.len();
            // Each owed effect is matched with the next thing the terminal performed; an owed
            // effect with no match was not delivered.
            let mut performed = client.live.iter().peekable();
            let mut missing = Vec::new();
            for effect in &owed {
                if performed
                    .peek()
                    .is_some_and(|got| same_effect(got, &effect.kind))
                {
                    performed.next();
                } else {
                    missing.push(*effect);
                }
            }
            let extra: Vec<&SideEffectKind> = performed.collect();
            for effect in missing {
                let failure = Failure {
                    property: Property::LiveEffect,
                    attached_at: client.attached_at,
                    checked_at: left,
                    client: client.form.name(),
                    what: format!(
                        "its terminal never performed {:?}, which the application caused at byte {} \
                         while it held the lease",
                        effect.kind, effect.completed_at
                    ),
                };
                if client.resyncs_at.contains(&effect.completed_at) {
                    self.outcome.lost.push(failure);
                } else {
                    self.outcome.failures.push(failure);
                }
            }
            if !extra.is_empty() {
                self.outcome.failures.push(Failure {
                    property: Property::LiveEffect,
                    attached_at: client.attached_at,
                    checked_at: left,
                    client: client.form.name(),
                    what: format!(
                        "its terminal performed {extra:?} from the live stream, which the \
                         application did not cause while it held the lease"
                    ),
                });
            }
        }
        self.clients = clients;
    }

    /// The direct client holding the lease once the byte at `offset` had been read.
    fn holder_at(&self, offset: usize) -> Option<AttachmentId> {
        self.holders
            .iter()
            .rev()
            .find(|(from, _)| *from < offset)
            .map(|(_, attachment)| *attachment)
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

/// A restoration split into what paints the showing buffer and what paints the other one.
///
/// The second is the rows between the switch to the other buffer and the switch back, as a
/// terminal that switches on mode 47 draws them into that buffer; the first is everything else.
/// With no such part, the other buffer is painted nothing.
#[must_use]
pub fn split_the_buffer_not_showing(bytes: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    for (enter, leave) in [
        (&b"\x1b[?47h"[..], &b"\x1b[?47l"[..]),
        (&b"\x1b[?47l"[..], &b"\x1b[?47h"[..]),
    ] {
        let Some(start) = find(bytes, enter) else {
            continue;
        };
        let Some(length) = find(&bytes[start + enter.len()..], leave) else {
            continue;
        };
        let inner = bytes[start + enter.len()..start + enter.len() + length].to_vec();
        let mut showing = bytes[..start].to_vec();
        showing.extend_from_slice(&bytes[start + enter.len() + length + leave.len()..]);
        return (showing, Some(inner));
    }
    (bytes.to_vec(), None)
}

/// A restoration with the part that paints the buffer that is not showing cut out.
///
/// The session paints that buffer by switching to it with mode 47, clearing it, drawing its rows
/// and switching back; this removes exactly that, and returns the bytes unchanged when there is no
/// such part.
#[must_use]
pub fn without_the_buffer_not_showing(bytes: &[u8]) -> Vec<u8> {
    for (enter, leave) in [
        (&b"\x1b[?47h\x1b[H\x1b[2J"[..], &b"\x1b[?47l"[..]),
        (&b"\x1b[?47l\x1b[H\x1b[2J"[..], &b"\x1b[?47h"[..]),
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
    fn splitting_the_other_buffer_gives_its_rows_to_it_and_the_rest_to_the_showing_one() {
        let restoration = b"\x1b[!p\x1b[?47h\x1b[H\x1b[2Jother\x1b[?47l\x1b[Hshowing";
        let (showing, other) = split_the_buffer_not_showing(restoration);
        assert_eq!(showing, b"\x1b[!p\x1b[Hshowing".to_vec());
        assert_eq!(other, Some(b"\x1b[H\x1b[2Jother".to_vec()));
        assert_eq!(
            split_the_buffer_not_showing(b"plain"),
            (b"plain".to_vec(), None)
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
