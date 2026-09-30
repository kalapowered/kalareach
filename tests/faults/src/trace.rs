//! Retained traces: an ordering race written down as the steps that reproduce it, and replayed on
//! simulated time.
//!
//! A trace opens a worker's session in this process on a [`SimulatedTime`] timeline and plays the
//! session's peers from a script: the application, whose output is read through the read loop's own
//! entry, and the clients, which attach and subscribe the way the worker's service subscribes one,
//! take the input lease and type. Nothing waits on a clock. A step that moves time says by how
//! much, and a timer that comes due fires in that step, so a race happens in the same order on
//! every run and on every machine.
//!
//! Each step does something or states an expectation, and [`replay`] names the trace and the step
//! whose expectation did not hold. Beside what a trace states, every attach checks the screen the
//! client is restored to, and no terminal of another size may be handed raw output.
//!
//! Every window the session decides is on the continuous clock the replay moves, so a trace says
//! exactly what it expects of each: a reply to a question the application asks while the person's
//! input is inside a paste or a held delimiter waits until that closes and is dropped after two
//! seconds, the replies one drain of the response lane writes past a byte budget wait for a later
//! drain and are dropped after the same two seconds, and replies past 256 a second are dropped until
//! the clock has moved on. A step of the wall clock moves none of them.
//!
//! [`minimise`] takes a failing trace down to steps from which no single one can be taken and the
//! trace still fail at the same step, which is the trace worth keeping once the race it shows is
//! fixed.
//!
//! ```json
//! {
//!   "format": "kalareach.trace/1",
//!   "name": "takeover-during-a-paste",
//!   "about": "a client takes the lease while another is part way through a paste",
//!   "columns": 20,
//!   "rows": 3,
//!   "wall_ms": 1790000000000,
//!   "steps": [
//!     { "do": "output", "text": "\u001b[?2004h$ " },
//!     { "do": "attach", "client": "a", "form": "direct" },
//!     { "do": "acquire", "client": "a" },
//!     { "do": "input", "client": "a", "text": "\u001b[200~first half " }
//!   ]
//! }
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kr_protocol::projection::ProjectedBuffer;
use kr_term::sideeffect::{ClipboardSelection, SideEffectKind};
use kr_worker::action::time::{Discontinuity, ExpiringObject, Validity};
use kr_worker::journal::Journal;
use kr_worker::persistence::WorkClass;
use kr_worker::session::InputBatch;
use serde::{Deserialize, Serialize};

use crate::journal::{JournalFixture, Made};
use crate::restore::{Form, Stage, Strategy};
use crate::screen::Line;
use crate::time::SimulatedTime;

/// The format every trace names, so a file of another shape is refused rather than misread.
pub const FORMAT: &str = "kalareach.trace/1";

/// Where the traces are kept, from this crate's own directory.
#[must_use]
pub fn directory() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/faults/traces")
}

/// One ordering race, as the steps that reproduce it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trace {
    /// Always [`FORMAT`].
    pub format: String,
    /// Its name, which is its file's name.
    pub name: String,
    /// The race it reproduces, for a person reading a failure.
    pub about: String,
    /// The session's columns.
    pub columns: u16,
    /// The session's rows.
    pub rows: u16,
    /// The wall clock when the trace begins, in UTC milliseconds.
    pub wall_ms: u64,
    /// The kept journal fixture the session opens its journal on, made with its fault; an
    /// in-memory journal when none is named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub journal: Option<String>,
    /// The steps, in order.
    pub steps: Vec<Step>,
}

/// One step: something a peer does, time moving, or an expectation.
///
/// Bytes are `text` where they are text and `hex` where they are not, never both.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "do", rename_all = "snake_case", deny_unknown_fields)]
pub enum Step {
    /// The application writes: one read of its output, as the read loop takes it.
    Output {
        /// The bytes, as text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        /// The bytes, in hexadecimal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hex: Option<String>,
    },
    /// The application pauses, and the session settles its screen as the read loop does.
    Settle,
    /// A client attaches and subscribes the way the worker's service subscribes one.
    Attach {
        /// The name the trace gives it.
        client: String,
        /// A terminal of the session's size or of another size.
        form: ClientForm,
    },
    /// A client detaches.
    Detach {
        /// Which.
        client: String,
    },
    /// A client takes the input lease.
    Acquire {
        /// Which.
        client: String,
        /// What the session answers, when the trace says.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expect: Option<Acquired>,
    },
    /// A client types, under the lease it took last.
    Input {
        /// Which.
        client: String,
        /// The bytes, as text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        /// The bytes, in hexadecimal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hex: Option<String>,
        /// The protocol code the session refuses them with; none when it accepts them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refused: Option<String>,
    },
    /// The terminal's writer takes everything queued for the application.
    TakeInput {
        /// What it takes, in order.
        expect: Vec<Batch>,
    },
    /// Every clock moves on, and a timer that comes due fires.
    Advance {
        /// By how many milliseconds.
        ms: u64,
    },
    /// The machine sleeps: the continuous and wall clocks move and the active clock does not.
    Suspend {
        /// For how many milliseconds.
        ms: u64,
    },
    /// The wall clock alone is stepped.
    StepWall {
        /// By how many milliseconds, back when negative.
        ms: i64,
    },
    /// The platform's time service starts or stops disciplining the wall clock.
    TimeService {
        /// Whether it does.
        synchronised: bool,
    },
    /// The session looks at its clocks.
    ObserveTime {
        /// What it finds moved; empty when nothing did.
        expect: Vec<Moved>,
    },
    /// The freshness a discontinuity affected has been rechecked.
    Revalidated,
    /// The session's time contract decides one object.
    Validity {
        /// The object.
        object: Object,
        /// `valid`, `expired: continuous_deadline`, `expired: trusted_utc_deadline`,
        /// `unproven` or `revalidation owed`.
        expect: String,
    },
    /// The application pauses, and the client holds the session's screen and performed nothing
    /// while it was being drawn one.
    Holds {
        /// Which.
        client: String,
    },
    /// The application pauses, and the session's own screen reads as given. A row is its text
    /// with trailing blanks dropped; rows past those given are blank.
    Screen {
        /// The buffer showing.
        active: ProjectedBuffer,
        /// Its rows, from the top.
        lines: Vec<String>,
        /// The other buffer's rows, when the trace says.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        other: Option<Vec<String>>,
    },
    /// The session's journal stops growing and takes actions until the store refuses one.
    FillJournal {
        /// The protocol code the store's refusal is reported under.
        expect: String,
    },
    /// What the session's journal is able to do.
    Journal {
        /// `healthy`, or the fault it is under: `full`, `write_failed`, `corrupt` or `absent`.
        expect: String,
        /// Whether a rich mutation is admitted in the posture that condition gives.
        rich_work: bool,
    },
    /// The session's journal may grow again, and the session tries to leave its fault.
    ReleaseJournal {
        /// The fault the interval it records was under; none when nothing is recorded.
        expect: Option<String>,
    },
    /// Every side effect the client's terminal has performed from the live stream so far.
    Effects {
        /// Which.
        client: String,
        /// The effects, in order: `bell`, `clipboard write: <content>`, `primary selection
        /// write: <content>`, `clipboard read`, `notification: <body>` and `progress`.
        expect: Vec<String>,
    },
}

/// A client's terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientForm {
    /// A terminal of the session's size, handed the stream.
    Direct,
    /// A terminal of another size, which holds a projection.
    Projected,
}

/// What the session answers a client that takes the lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acquired {
    /// Whether it closed a paste the lease it ended had open.
    pub closed_open_paste: bool,
    /// How many bytes that lease had handed over that were never written.
    pub discarded_bytes: u64,
}

/// One batch the terminal's writer takes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "batch", rename_all = "snake_case", deny_unknown_fields)]
pub enum Batch {
    /// A client's input, under the lease it took.
    Input {
        /// The client whose lease it was accepted under.
        client: String,
        /// The bytes, as text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        /// The bytes, in hexadecimal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hex: Option<String>,
        /// The paste delimiters in it, in order.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        paste: Vec<PasteEdge>,
    },
    /// The host answering the application.
    Reply {
        /// The bytes, as text.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        /// The bytes, in hexadecimal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hex: Option<String>,
    },
    /// The lease changed, which is the writer's moment to close a paste the application is inside.
    LeaseChanged,
}

/// A paste delimiter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PasteEdge {
    /// A paste start.
    Opens,
    /// A paste end.
    Closes,
}

/// What an observation of the clocks can find.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Moved {
    /// The machine slept.
    Suspended,
    /// The boot changed.
    Rebooted,
    /// The wall clock went back further than the tolerance.
    RolledBack,
}

/// An object whose validity the time contract decides.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    /// How its store names it.
    pub name: String,
    /// Its deadline on this boot's continuous clock, in milliseconds after the trace began.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub within_boot_ms: Option<u64>,
    /// Its trusted UTC deadline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub utc_ms: Option<u64>,
    /// A personal owner grant that does not expire.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub owner_grant: bool,
}

impl Trace {
    /// Reads one trace, which is named by its file.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the file: unreadable, not a trace, or a name that is not its
    /// file's.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
        let trace = Self::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
        let stem = path.file_stem().and_then(|stem| stem.to_str());
        if stem != Some(trace.name.as_str()) {
            return Err(format!(
                "{} names itself {:?}; a trace is named by its file",
                path.display(),
                trace.name
            ));
        }
        Ok(trace)
    }

    /// Reads one trace from its text.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with it: not a trace, another format, or a screen with no cells.
    pub fn parse(text: &str) -> Result<Self, String> {
        let trace: Self =
            serde_json::from_str(text).map_err(|error| format!("not a trace: {error}"))?;
        if trace.format != FORMAT {
            return Err(format!(
                "the format is {:?}, and a trace is {FORMAT:?}",
                trace.format
            ));
        }
        if trace.columns == 0 || trace.rows == 0 {
            return Err("the session has a screen with no cells".to_owned());
        }
        Ok(trace)
    }

    /// Every trace kept with this crate, in name order.
    ///
    /// # Errors
    ///
    /// Returns what is wrong with the first file that cannot be read as a trace, or with the
    /// directory.
    pub fn all() -> Result<Vec<Self>, String> {
        let directory = directory();
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&directory)
            .map_err(|error| format!("{} could not be listed: {error}", directory.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect();
        paths.sort();
        paths.iter().map(|path| Self::load(path)).collect()
    }

    /// The trace as a file keeps it.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self).unwrap_or_default();
        text.push('\n');
        text
    }

    /// This trace with only the steps at `kept`, in their order, and then the step at `last`.
    fn keeping(&self, kept: &[usize], last: usize) -> Self {
        let mut steps: Vec<Step> = kept
            .iter()
            .map(|index| self.steps[*index].clone())
            .collect();
        steps.push(self.steps[last].clone());
        Self {
            format: self.format.clone(),
            name: self.name.clone(),
            about: self.about.clone(),
            columns: self.columns,
            rows: self.rows,
            wall_ms: self.wall_ms,
            journal: self.journal.clone(),
            steps,
        }
    }
}

/// Why a replay stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// An expectation did not hold: what the product did is not what the trace says.
    Expectation,
    /// The trace cannot be run as written: a client that never attached, bytes that are not
    /// hexadecimal, a session that could not be opened.
    Malformed,
}

/// Where and why a replay stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stopped {
    /// The trace's name.
    pub trace: String,
    /// The step it stopped at, counted from zero; none when the session could not be opened.
    pub step: Option<usize>,
    /// The step itself, as the file spells it.
    pub spelled: String,
    /// Why.
    pub cause: Cause,
    /// What was found.
    pub what: String,
}

impl std::fmt::Display for Stopped {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cause = match self.cause {
            Cause::Expectation => "an expectation did not hold",
            Cause::Malformed => "the trace cannot be run as written",
        };
        match self.step {
            Some(step) => write!(
                formatter,
                "trace {}, step {step} {}: {cause}: {}",
                self.trace, self.spelled, self.what
            ),
            None => write!(formatter, "trace {}: {cause}: {}", self.trace, self.what),
        }
    }
}

/// Replays a trace against a session in this process.
///
/// # Errors
///
/// Returns the step that stopped it: an expectation that did not hold, or a step that cannot be
/// run as written.
pub fn replay(trace: &Trace) -> Result<(), Stopped> {
    replay_with(trace, Strategy::Product)
}

/// Replays a trace with every direct client following `strategy`, so a planted defect can show
/// that a trace's checks fail when the product is wrong.
///
/// # Errors
///
/// As [`replay`].
pub fn replay_with(trace: &Trace, strategy: Strategy) -> Result<(), Stopped> {
    replay_between(trace, strategy, &mut |_, _| Ok(()))
}

/// What a control does after a step: it is given the step's index and the path of the kept journal
/// the trace opened, when it opened one.
type Between<'a> = dyn FnMut(usize, Option<&Path>) -> Result<(), String> + 'a;

/// As [`replay_with`], and `between` is called after each step with that step's index and the path
/// of the kept journal the trace opened, when it opened one: what a control does to the store behind
/// the session's back, as another connection would.
fn replay_between(
    trace: &Trace,
    strategy: Strategy,
    between: &mut Between<'_>,
) -> Result<(), Stopped> {
    let stopped = |step: Option<usize>, cause: Cause, what: String| Stopped {
        trace: trace.name.clone(),
        step,
        spelled: step
            .and_then(|step| serde_json::to_string(&trace.steps[step]).ok())
            .unwrap_or_default(),
        cause,
        what,
    };
    let time = SimulatedTime::new(trace.wall_ms);
    let journal = match trace.journal.as_deref() {
        Some(name) => {
            Some(JournalHome::made(name).map_err(|what| stopped(None, Cause::Malformed, what))?)
        }
        None => None,
    };
    let stage = Stage::open(
        trace.columns,
        trace.rows,
        Vec::new(),
        strategy,
        time.worker_sources(),
        journal.as_ref().map(JournalHome::path),
    )
    .map_err(|what| stopped(None, Cause::Malformed, what))?;
    let mut replay = Replay {
        time,
        stage,
        clients: BTreeMap::new(),
        epochs: BTreeMap::new(),
        journal_home: journal,
        gaps: (0, 0),
    };
    if trace.journal.is_some() {
        replay.gaps.0 = replay
            .stored_gaps()
            .map_err(|what| stopped(None, Cause::Malformed, what))?
            .len();
    }
    for (index, step) in trace.steps.iter().enumerate() {
        replay
            .run(step)
            .map_err(|(cause, what)| stopped(Some(index), cause, what))?;
        let journal = replay.journal_home.as_ref().map(JournalHome::path);
        between(index, journal.as_deref())
            .map_err(|what| stopped(Some(index), Cause::Malformed, what))?;
    }
    Ok(())
}

/// A replay in progress.
struct Replay {
    time: SimulatedTime,
    stage: Stage,
    /// Each client's name, and which of the stage's clients it is.
    clients: BTreeMap<String, usize>,
    /// Which client took each lease epoch.
    epochs: BTreeMap<u64, String>,
    /// Where the session's journal was made, kept until the replay ends.
    journal_home: Option<JournalHome>,
    /// How many intervals the journal held written down when the session opened it, and how many
    /// this replay has had it record since.
    gaps: (usize, usize),
}

/// A kept journal fixture made with its fault in a directory of its own, which goes with this.
struct JournalHome {
    directory: tempfile::TempDir,
}

impl JournalHome {
    fn made(name: &str) -> Result<Self, String> {
        let fixture =
            JournalFixture::load(&crate::journal::directory().join(format!("{name}.json")))?;
        let directory = tempfile::Builder::new()
            .prefix("kr-faults-trace-journal-")
            .tempdir()
            .map_err(|error| format!("a directory for journal {name}: {error}"))?;
        let home = Self { directory };
        fixture.make(&home.path(), Made::WithFault)?;
        Ok(home)
    }

    fn path(&self) -> std::path::PathBuf {
        self.directory.path().join("journal.sqlite3")
    }
}

/// Whether the intervals a journal reads as written down, oldest first, are the ones it should
/// hold: exactly `owed` of them, which counts the intervals the journal held when the session
/// opened it and the ones this replay has had it record since, and, when this step recorded one
/// (`recorded` is its kind), the newest of them is of that kind.
fn gaps_written_down(owed: usize, recorded: Option<&str>, stored: &[&str]) -> Result<(), String> {
    if stored.len() == owed && (recorded.is_none() || stored.last().copied() == recorded) {
        Ok(())
    } else {
        Err(format!(
            "reads {} interval(s) written down, the newest {:?}; {owed} are owed (the intervals \
             the journal held when the session opened it and those this replay has had it \
             record), and the newest must be of kind {recorded:?} when this step recorded one",
            stored.len(),
            stored.last()
        ))
    }
}

type StepResult = Result<(), (Cause, String)>;

fn malformed(what: String) -> (Cause, String) {
    (Cause::Malformed, what)
}

fn unmet(what: String) -> (Cause, String) {
    (Cause::Expectation, what)
}

impl Replay {
    fn run(&mut self, step: &Step) -> StepResult {
        match step {
            Step::Output { text, hex } => {
                let bytes = bytes_of(text.as_deref(), hex.as_deref()).map_err(malformed)?;
                self.stage.ingest(&bytes).map_err(malformed)?;
            }
            Step::Settle => self.stage.settle().map_err(malformed)?,
            Step::Attach { client, form } => self.attach(client, *form)?,
            Step::Detach { client } => {
                let index = self.client(client)?;
                self.stage.detach(index).map_err(malformed)?;
            }
            Step::Acquire { client, expect } => self.acquire(client, expect.as_ref())?,
            Step::Input {
                client,
                text,
                hex,
                refused,
            } => self.input(client, text.as_deref(), hex.as_deref(), refused.as_deref())?,
            Step::TakeInput { expect } => self.take_input(expect)?,
            Step::Advance { ms } => {
                self.time.advance(Duration::from_millis(*ms));
                self.fire_timers()?;
            }
            Step::Suspend { ms } => {
                self.time.suspend(Duration::from_millis(*ms));
                self.fire_timers()?;
            }
            Step::StepWall { ms } => self.time.step_wall(*ms),
            Step::TimeService { synchronised } => self.time.set_synchronised(*synchronised),
            Step::ObserveTime { expect } => {
                let got = moved(self.stage.session().observe_time());
                let mut expected = expect.clone();
                expected.sort_unstable();
                expected.dedup();
                if got != expected {
                    return Err(unmet(format!(
                        "the session found {got:?} moved, and the trace expects {expected:?}"
                    )));
                }
            }
            Step::Revalidated => self.stage.session().note_leases_revalidated(),
            Step::Validity { object, expect } => {
                let object = self.object(object)?;
                let decided = decided(&self.stage.session().time().validity(&object));
                if decided != *expect {
                    return Err(unmet(format!(
                        "the time contract decided {decided:?}, and the trace expects {expect:?}"
                    )));
                }
            }
            Step::Holds { client } => {
                let index = self.client(client)?;
                let mut found = self.stage.differences(index).map_err(malformed)?;
                found.extend(self.stage.take_restoring(index));
                if !found.is_empty() {
                    return Err(unmet(found.join("; ")));
                }
            }
            Step::Screen {
                active,
                lines,
                other,
            } => self.screen(*active, lines, other.as_deref())?,
            Step::FillJournal { expect } => self.fill_journal(expect)?,
            Step::Journal { expect, rich_work } => {
                let posture = self.stage.session().durability_posture();
                let condition = posture
                    .fault()
                    .map_or("healthy", |fault| fault.kind.as_str());
                let admits = posture.admits(WorkClass::RichMutation);
                if condition != expect || admits != *rich_work {
                    return Err(unmet(format!(
                        "the journal is {condition} and {} rich work, and the trace expects it \
                         {expect} and {} it",
                        if admits { "admits" } else { "fences" },
                        if *rich_work { "admitting" } else { "fencing" }
                    )));
                }
            }
            Step::ReleaseJournal { expect } => self.release_journal(expect.as_deref())?,
            Step::Effects { client, expect } => {
                let index = self.client(client)?;
                let got: Vec<String> = self
                    .stage
                    .live(index)
                    .iter()
                    .map(|delivered| effect_name(&delivered.kind))
                    .collect();
                if got != *expect {
                    return Err(unmet(format!(
                        "its terminal performed {got:?}, and the trace expects {expect:?}"
                    )));
                }
            }
        }
        // What the stage checks on its own, at every step: the screen each attach restored, and
        // no raw output handed to a terminal of another size.
        let failures = self.stage.take_failures();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(unmet(
                failures
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    }

    /// Lets the session's journal grow again and has the session try to leave its fault, then
    /// reads what the store holds: through the session's own connection, and through one opened
    /// afterwards as a reader of the closed session's journal opens it.
    fn release_journal(&mut self, expect: Option<&str>) -> StepResult {
        let session = self.stage.session();
        let released = session
            .journal_mut()
            .ok_or_else(|| malformed("the session has no journal".to_owned()))?
            .release_size_cap();
        released.map_err(|error| malformed(format!("the cap stays: {error}")))?;
        let gap = session
            .recover_journal()
            .map(|gap| gap.kind.as_str().to_owned());
        if gap.as_deref() != expect {
            return Err(unmet(format!(
                "the session recorded a gap of {gap:?}, and the trace expects {expect:?}"
            )));
        }
        if gap.is_some() {
            self.gaps.1 += 1;
        }
        let owed = self.gaps.0 + self.gaps.1;
        let through_the_session = self.stored_gaps().map_err(malformed)?;
        let path = self
            .journal_home
            .as_ref()
            .map(JournalHome::path)
            .ok_or_else(|| malformed("the trace opened no kept journal".to_owned()))?;
        let reopened = Journal::open_read_only(&path)
            .and_then(|journal| journal.recovery_gaps())
            .map_err(|error| malformed(format!("the journal could not be reopened: {error}")))?;
        for (whose, gaps) in [
            ("the session's own connection", &through_the_session),
            ("a reader that opens the file afresh", &reopened),
        ] {
            let kinds: Vec<&str> = gaps.iter().map(|gap| gap.kind.as_str()).collect();
            gaps_written_down(owed, expect, &kinds)
                .map_err(|what| unmet(format!("{whose} {what}")))?;
        }
        Ok(())
    }

    /// The intervals the session's own connection reads as written down in its journal.
    fn stored_gaps(&mut self) -> Result<Vec<kr_worker::persistence::fault::RecoveryGap>, String> {
        self.stage
            .session()
            .journal_mut()
            .ok_or_else(|| "the session has no journal".to_owned())?
            .recovery_gaps()
            .map_err(|error| format!("the journal's intervals could not be read: {error}"))
    }

    /// Stops the session's journal growing and has it take the fixtures' actions until the store
    /// refuses one, as the worker's own admission would.
    fn fill_journal(&mut self, expect: &str) -> StepResult {
        let journal = self
            .stage
            .session()
            .journal_mut()
            .ok_or_else(|| malformed("the session has no journal".to_owned()))?;
        journal
            .cap_at_current_size()
            .map_err(|error| malformed(format!("the journal could not be capped: {error}")))?;
        for action in 100..=u8::MAX {
            let submission = crate::journal::submission(action).map_err(malformed)?;
            if let Err(error) = journal.accept(&submission) {
                let code = error.code().as_str();
                return if code == expect {
                    Ok(())
                } else {
                    Err(unmet(format!(
                        "the store refused an action with {code} ({error}), and the trace expects \
                         {expect}"
                    )))
                };
            }
        }
        Err(unmet(
            "the store took every action it was given and never filled".to_owned(),
        ))
    }

    fn client(&self, name: &str) -> Result<usize, (Cause, String)> {
        self.clients
            .get(name)
            .copied()
            .ok_or_else(|| malformed(format!("no client {name} has attached")))
    }

    fn attach(&mut self, client: &str, form: ClientForm) -> StepResult {
        if self.clients.contains_key(client) {
            return Err(malformed(format!("client {client} has attached already")));
        }
        let form = match form {
            ClientForm::Direct => Form::Direct,
            ClientForm::Projected => Form::Projected,
        };
        let index = self
            .stage
            .attach(form, usize::MAX, false)
            .map_err(malformed)?;
        self.clients.insert(client.to_owned(), index);
        Ok(())
    }

    fn acquire(&mut self, client: &str, expect: Option<&Acquired>) -> StepResult {
        let index = self.client(client)?;
        let acquired = self.stage.acquire(index).map_err(malformed)?;
        self.epochs
            .insert(acquired.lease.epoch.get(), client.to_owned());
        let got = Acquired {
            closed_open_paste: acquired.closed_open_paste,
            discarded_bytes: acquired.discarded_bytes.get(),
        };
        match expect {
            Some(expected) if got != *expected => Err(unmet(format!(
                "the session answered {got:?}, and the trace expects {expected:?}"
            ))),
            _ => Ok(()),
        }
    }

    fn input(
        &mut self,
        client: &str,
        text: Option<&str>,
        hex: Option<&str>,
        refused: Option<&str>,
    ) -> StepResult {
        let index = self.client(client)?;
        let bytes = bytes_of(text, hex).map_err(malformed)?;
        let answer = self
            .stage
            .input(index, &bytes, self.time.instant())
            .map_err(malformed)?;
        match (answer, refused) {
            (Ok(_), None) => Ok(()),
            (Ok(accepted), Some(code)) => Err(unmet(format!(
                "the session accepted it ({accepted:?}), and the trace expects it refused with \
                 {code}"
            ))),
            (Err(error), expected) => {
                let code = error.code().as_str();
                if expected == Some(code) {
                    Ok(())
                } else {
                    Err(unmet(format!(
                        "the session refused it with {code} ({error}), and the trace expects {}",
                        expected.map_or_else(|| "it accepted".to_owned(), |code| code.to_owned())
                    )))
                }
            }
        }
    }

    fn take_input(&mut self, expect: &[Batch]) -> StepResult {
        let got: Vec<Batch> = self
            .stage
            .pending_input()
            .into_iter()
            .map(|batch| self.spelled(batch))
            .collect();
        let expected = expect
            .iter()
            .map(respelled)
            .collect::<Result<Vec<_>, _>>()
            .map_err(malformed)?;
        if got == expected {
            Ok(())
        } else {
            Err(unmet(format!(
                "the writer took {}, and the trace expects {}",
                serde_json::to_string(&got).unwrap_or_default(),
                serde_json::to_string(&expected).unwrap_or_default()
            )))
        }
    }

    /// A batch as a trace spells it, naming the client whose lease it was accepted under.
    fn spelled(&self, batch: InputBatch) -> Batch {
        match batch {
            InputBatch::Lease {
                epoch,
                bytes,
                paste,
                ..
            } => {
                let (text, hex) = spell(&bytes);
                Batch::Input {
                    client: self
                        .epochs
                        .get(&epoch)
                        .cloned()
                        .unwrap_or_else(|| format!("the lease of epoch {epoch}")),
                    text,
                    hex,
                    paste: paste
                        .delimiters
                        .iter()
                        .map(|delimiter| {
                            if delimiter.opens {
                                PasteEdge::Opens
                            } else {
                                PasteEdge::Closes
                            }
                        })
                        .collect(),
                }
            }
            InputBatch::Reply { bytes, .. } => {
                let (text, hex) = spell(&bytes);
                Batch::Reply { text, hex }
            }
            InputBatch::LeaseChanged => Batch::LeaseChanged,
        }
    }

    /// Fires what came due when time moved: the paste recogniser's timer, as the worker's own
    /// timer would.
    fn fire_timers(&mut self) -> StepResult {
        self.stage
            .fire_paste_timer(self.time.instant())
            .map(|_| ())
            .map_err(malformed)
    }

    fn object(&mut self, object: &Object) -> Result<ExpiringObject, (Cause, String)> {
        let boot = self.stage.session().time().boot_identity().clone();
        match (object.within_boot_ms, object.utc_ms, object.owner_grant) {
            (None, None, true) => Ok(ExpiringObject::non_expiring_owner_grant(&object.name)),
            (within_boot, utc, false) if within_boot.is_some() || utc.is_some() => {
                Ok(ExpiringObject {
                    name: object.name.clone(),
                    boot_identity: within_boot.map(|_| boot),
                    continuous_deadline_ms: within_boot,
                    trusted_utc_deadline_ms: utc,
                    non_expiring_owner_grant: false,
                })
            }
            _ => Err(malformed(format!(
                "object {} has neither a deadline nor is it an owner grant, or is both",
                object.name
            ))),
        }
    }

    fn screen(
        &mut self,
        active: ProjectedBuffer,
        lines: &[String],
        other: Option<&[String]>,
    ) -> StepResult {
        let view = self.stage.screen().map_err(malformed)?;
        let mut found = Vec::new();
        if view.active != active {
            found.push(format!(
                "the {:?} buffer shows, and the trace expects the {active:?} one",
                view.active
            ));
        }
        found.extend(rows_differing("row", &view.lines, lines));
        if let Some(other) = other {
            found.extend(rows_differing("the other buffer's row", &view.other, other));
        }
        if found.is_empty() {
            Ok(())
        } else {
            Err(unmet(found.join("; ")))
        }
    }
}

/// The rows of `got` whose text is not what `expected` gives, rows past it being blank.
fn rows_differing(what: &str, got: &[Line], expected: &[String]) -> Vec<String> {
    let mut found: Vec<String> = got
        .iter()
        .map(Line::text)
        .enumerate()
        .filter_map(|(row, text)| {
            let wanted = expected.get(row).map_or("", String::as_str);
            (text != wanted)
                .then(|| format!("{what} {row} reads {text:?}, and the trace expects {wanted:?}"))
        })
        .collect();
    if expected.len() > got.len() {
        found.push(format!(
            "the trace gives {} rows for a screen of {}",
            expected.len(),
            got.len()
        ));
    }
    found
}

/// The bytes a step spells, as text or in hexadecimal.
fn bytes_of(text: Option<&str>, hex: Option<&str>) -> Result<Vec<u8>, String> {
    match (text, hex) {
        (Some(text), None) => Ok(text.as_bytes().to_vec()),
        (None, Some(digits)) => {
            hex::decode(digits).map_err(|error| format!("{digits:?} is not hexadecimal: {error}"))
        }
        _ => Err("bytes are given as text or in hexadecimal, and not both".to_owned()),
    }
}

/// Bytes as a trace spells them: text when they are text.
fn spell(bytes: &[u8]) -> (Option<String>, Option<String>) {
    match std::str::from_utf8(bytes) {
        Ok(text) => (Some(text.to_owned()), None),
        Err(_) => (None, Some(hex::encode(bytes))),
    }
}

/// An expected batch spelled the way a taken one is, so text and hexadecimal compare by the bytes
/// they give.
fn respelled(batch: &Batch) -> Result<Batch, String> {
    Ok(match batch {
        Batch::Input {
            client,
            text,
            hex,
            paste,
        } => {
            let (text, hex) = spell(&bytes_of(text.as_deref(), hex.as_deref())?);
            Batch::Input {
                client: client.clone(),
                text,
                hex,
                paste: paste.clone(),
            }
        }
        Batch::Reply { text, hex } => {
            let (text, hex) = spell(&bytes_of(text.as_deref(), hex.as_deref())?);
            Batch::Reply { text, hex }
        }
        Batch::LeaseChanged => Batch::LeaseChanged,
    })
}

fn moved(found: Discontinuity) -> Vec<Moved> {
    let mut moved = Vec::new();
    if found.suspended {
        moved.push(Moved::Suspended);
    }
    if found.rebooted {
        moved.push(Moved::Rebooted);
    }
    if found.rolled_back {
        moved.push(Moved::RolledBack);
    }
    moved.sort_unstable();
    moved
}

/// A decision as a trace spells it.
fn decided(validity: &Validity) -> String {
    match validity {
        Validity::Valid => "valid".to_owned(),
        Validity::Expired(reason) => format!("expired: {}", reason.as_str()),
        Validity::Unproven => "unproven".to_owned(),
        Validity::RevalidationOwed => "revalidation owed".to_owned(),
    }
}

/// A side effect as a trace spells it.
#[must_use]
pub fn effect_name(kind: &SideEffectKind) -> String {
    let selection = |selection: &ClipboardSelection| match selection {
        ClipboardSelection::Clipboard => "clipboard",
        ClipboardSelection::Primary => "primary selection",
    };
    match kind {
        SideEffectKind::Bell => "bell".to_owned(),
        SideEffectKind::ClipboardWrite {
            selection: which,
            content,
        } => format!(
            "{} write: {}",
            selection(which),
            String::from_utf8_lossy(content)
        ),
        SideEffectKind::ClipboardRead { selection: which } => {
            format!("{} read", selection(which))
        }
        SideEffectKind::Notification { body, .. } => format!("notification: {body}"),
        SideEffectKind::Progress { .. } => "progress".to_owned(),
    }
}

/// Takes a failing trace down to steps from which no single one can be taken and the trace still
/// fail at the same step.
///
/// The step the trace fails at is kept, and every step after it goes, since a replay stops there.
/// The steps before it are reduced by delta debugging: a set of them goes whenever the trace
/// without them still fails at that step because an expectation did not hold, rather than because
/// it can no longer be run. Taking any one more step out of the result makes it pass, fail at
/// another step, or stop being runnable; a smaller trace that fails the same way may still exist,
/// because delta debugging does not search every subset.
///
/// # Errors
///
/// Returns why there is nothing to minimise: the trace replays, or it cannot be run as written.
pub fn minimise(trace: &Trace) -> Result<Trace, String> {
    let failing = match replay(trace) {
        Ok(()) => {
            return Err(format!(
                "trace {} replays, so there is nothing to minimise",
                trace.name
            ));
        }
        Err(Stopped {
            cause: Cause::Expectation,
            step: Some(step),
            ..
        }) => step,
        Err(stopped) => {
            return Err(format!("{stopped}, so it shows no race to minimise"));
        }
    };
    let reproduces = |kept: &[usize]| {
        matches!(
            replay(&trace.keeping(kept, failing)),
            Err(Stopped {
                cause: Cause::Expectation,
                step: Some(step),
                ..
            }) if step == kept.len()
        )
    };
    let kept = reduce((0..failing).collect(), &reproduces);
    Ok(trace.keeping(&kept, failing))
}

/// Delta debugging: a subset of `items`, in their order, that still `reproduces`, from which no one
/// item can be taken and still reproduce.
fn reduce(mut items: Vec<usize>, reproduces: &dyn Fn(&[usize]) -> bool) -> Vec<usize> {
    if reproduces(&[]) {
        return Vec::new();
    }
    let mut parts = 2;
    while items.len() >= 2 {
        let chunks = chunked(&items, parts);
        if let Some(chunk) = chunks.iter().find(|chunk| reproduces(chunk)) {
            items = chunk.clone();
            parts = 2;
            continue;
        }
        let complement = (0..chunks.len())
            .map(|skipped| {
                chunks
                    .iter()
                    .enumerate()
                    .filter(|(index, _)| *index != skipped)
                    .flat_map(|(_, chunk)| chunk.iter().copied())
                    .collect::<Vec<usize>>()
            })
            .find(|complement| reproduces(complement));
        if let Some(complement) = complement {
            items = complement;
            parts = (parts - 1).max(2);
            continue;
        }
        if parts >= items.len() {
            break;
        }
        parts = (parts * 2).min(items.len());
    }
    items
}

/// `items` in `parts` runs of nearly equal length.
fn chunked(items: &[usize], parts: usize) -> Vec<Vec<usize>> {
    let parts = parts.clamp(1, items.len().max(1));
    let (size, longer) = (items.len() / parts, items.len() % parts);
    let mut chunks = Vec::with_capacity(parts);
    let mut start = 0;
    for part in 0..parts {
        let length = size + usize::from(part < longer);
        chunks.push(items[start..start + length].to_vec());
        start += length;
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recovery_is_read_back_once_of_the_kind_it_recorded_and_no_other_way_passes() {
        assert_eq!(gaps_written_down(1, Some("full"), &["full"]), Ok(()));
        assert_eq!(gaps_written_down(2, None, &["corrupt", "full"]), Ok(()));
        // Never written down, written down twice, and of another kind: each fails.
        assert!(gaps_written_down(1, Some("full"), &[]).is_err());
        assert!(gaps_written_down(1, Some("full"), &["full", "full"]).is_err());
        assert!(gaps_written_down(1, Some("full"), &["corrupt"]).is_err());
        // A second recovery that found nothing to record leaves the count as it was.
        assert!(gaps_written_down(1, None, &["full", "full"]).is_err());
        assert!(gaps_written_down(1, None, &[]).is_err());
    }

    /// A control for the read-back of the intervals: a row another connection writes into the
    /// journal between the two recoveries of a kept trace is one the second recovery never made,
    /// and the second read-back finds more written down than the session owes.
    #[test]
    fn an_interval_another_connection_writes_between_two_recoveries_fails_the_second_read_back() {
        let kept = Trace::load(&directory().join("full-journal-keeps-native-input.json"))
            .unwrap_or_else(|error| panic!("{error}"));
        let releases: Vec<usize> = kept
            .steps
            .iter()
            .enumerate()
            .filter(|(_, step)| matches!(step, Step::ReleaseJournal { .. }))
            .map(|(index, _)| index)
            .collect();
        let [first, second] = releases[..] else {
            panic!("the kept trace recovers twice: {releases:?}");
        };
        let mut written = false;
        let stopped = replay_between(&kept, Strategy::Product, &mut |step, journal| {
            if step != first {
                return Ok(());
            }
            let path = journal.ok_or_else(|| "the trace opened no kept journal".to_owned())?;
            rusqlite::Connection::open(path)
                .and_then(|connection| {
                    connection.execute(
                        "INSERT INTO journal_gaps (
                             kind, detail, faulted_at_ms, recovered_at_ms, durable_through,
                             resumed_at
                         ) VALUES ('full', 'written by another connection', 1, 2, 3, 4)",
                        [],
                    )
                })
                .map_err(|error| format!("the other connection could not write: {error}"))?;
            written = true;
            Ok(())
        })
        .expect_err("the second read-back finds a row nobody recorded");
        assert!(written, "the control wrote its row");
        assert_eq!(
            (stopped.step, stopped.cause),
            (Some(second), Cause::Expectation),
            "{stopped}"
        );
        assert!(
            stopped.what.contains("interval(s) written down"),
            "{stopped}"
        );
        let unchanged = replay(&kept);
        assert!(
            unchanged.is_ok(),
            "the same trace replays without it: {unchanged:?}"
        );
    }

    #[test]
    fn delta_debugging_keeps_exactly_the_items_the_failure_needs() {
        let needs = |kept: &[usize]| kept.contains(&3) && kept.contains(&7) && kept.contains(&8);
        assert_eq!(reduce((0..12).collect(), &needs), vec![3, 7, 8]);
        assert_eq!(
            reduce((0..5).collect(), &|_: &[usize]| true),
            Vec::<usize>::new()
        );
        let order = |kept: &[usize]| kept.windows(2).any(|pair| pair == [2, 5]);
        assert_eq!(reduce((0..9).collect(), &order), vec![2, 5]);
    }

    #[test]
    fn a_step_is_read_with_its_expectation_and_written_back_the_same() {
        let text = r#"{"format":"kalareach.trace/1","name":"sample","about":"a sample","columns":4,
            "rows":2,"wall_ms":5,"steps":[{"do":"output","hex":"1b5b"},{"do":"settle"},
            {"do":"validity","object":{"name":"grant","within_boot_ms":10},"expect":"valid"},
            {"do":"take_input","expect":[{"batch":"lease_changed"},
            {"batch":"input","client":"a","text":"x","paste":["opens"]}]}]}"#;
        let trace = Trace::parse(text).expect("a trace");
        assert_eq!(trace.steps.len(), 4);
        assert_eq!(Trace::parse(&trace.to_json()), Ok(trace));
        let unknown = text.replace("\"within_boot_ms\"", "\"within_boot_seconds\"");
        assert!(Trace::parse(&unknown).is_err_and(|error| error.contains("within_boot_seconds")));
        let other = text.replace("kalareach.trace/1", "x/1");
        assert!(Trace::parse(&other).is_err_and(|error| error.contains("x/1")));
    }

    #[test]
    fn text_and_hexadecimal_spell_the_same_bytes_and_one_of_them_is_required() {
        assert_eq!(bytes_of(Some("ab"), None), Ok(b"ab".to_vec()));
        assert_eq!(bytes_of(None, Some("6162")), Ok(b"ab".to_vec()));
        assert!(bytes_of(None, None).is_err());
        assert!(bytes_of(Some("ab"), Some("6162")).is_err());
        let hex = Batch::Reply {
            text: None,
            hex: Some("6162".to_owned()),
        };
        assert_eq!(
            respelled(&hex),
            Ok(Batch::Reply {
                text: Some("ab".to_owned()),
                hex: None
            })
        );
    }
}
