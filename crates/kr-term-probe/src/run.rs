//! Running the corpus against a terminal and against the canonical grid.

use std::io;

use kr_term::budget::GridSize;
use kr_term::lane::LaneGate;
use kr_term::snapshot::Viewport;
use kr_term::{Engine, EngineConfig};

use crate::corpus::Step;
use crate::replies::{self, Position};
use crate::{BARRIER, CURSOR_POSITION, RESET};

/// The terminal a run talks to: bytes go out, and everything it answers comes back up to the reply
/// to primary device attributes.
pub trait Terminal {
    /// Writes bytes to the terminal.
    ///
    /// # Errors
    ///
    /// Fails when the terminal cannot be written to.
    fn send(&mut self, bytes: &[u8]) -> io::Result<()>;

    /// Reads what the terminal answers, up to and including its reply to primary device
    /// attributes. Returns `None` when that reply does not arrive within the terminal's deadline or
    /// the bytes that did arrive pass the size bound first.
    ///
    /// # Errors
    ///
    /// Fails when the terminal cannot be read from.
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>>;
}

/// What a terminal says about itself when asked.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Identity {
    /// The reply to the terminal version query, which not every terminal gives.
    pub version: Option<String>,
    /// The parameters of the primary device attributes reply.
    pub primary_attributes: Option<Vec<u32>>,
    /// The parameters of the secondary device attributes reply.
    pub secondary_attributes: Option<Vec<u32>>,
    /// The window size the terminal reports, as `[rows, columns]`.
    pub window: Option<(u32, u32)>,
    /// The status the terminal reports for mode 2027, grapheme clustering.
    pub grapheme_clustering: Option<u32>,
}

/// Asks the terminal who it is.
///
/// # Errors
///
/// Fails when the terminal cannot be written to or read from.
pub fn identify(terminal: &mut dyn Terminal) -> io::Result<Identity> {
    terminal.send(b"\x1b[>q\x1b[18t\x1b[?2027$p\x1b[>c")?;
    terminal.send(BARRIER)?;
    let Some(bytes) = terminal.receive()? else {
        return Ok(Identity::default());
    };
    Ok(Identity {
        version: replies::version_text(&bytes),
        primary_attributes: replies::primary_attributes(&bytes),
        secondary_attributes: replies::secondary_attributes(&bytes),
        window: replies::window_size(&bytes),
        grapheme_clustering: replies::mode_status(&bytes, 2027),
    })
}

/// What one step found.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Outcome {
    /// The step's name.
    pub id: String,
    /// The rule it exercises.
    pub group: String,
    /// The bytes it wrote, in hexadecimal.
    pub bytes: String,
    /// Where the terminal says its cursor was, or none when it did not say.
    pub terminal: Option<Position>,
    /// Where the canonical grid says its cursor is after the same bytes.
    pub canonical: Position,
    /// Whether the canonical grid holds a wrap it has not yet made at the cursor.
    pub canonical_pending_wrap: bool,
    /// Whether the terminal's reply to primary device attributes, which ends the read, arrived.
    pub barrier: bool,
    /// Whether the two agree.
    pub agrees: bool,
}

/// The canonical grid's answer after `bytes`, in a window of `cols` by `rows`.
///
/// The answer is what the engine writes back to an application that asks for the cursor position,
/// which is the answer a session gives and so the one a physical terminal has to match.
///
/// # Panics
///
/// Panics when the engine cannot be built for a window that a terminal reported, or does not answer
/// the cursor position report, which would be a defect in the engine rather than a finding.
#[must_use]
pub fn canonical(cols: u32, rows: u32, bytes: &[u8]) -> (Position, bool) {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(cols, rows),
        ..EngineConfig::DEFAULT
    })
    .expect("an engine for a window a terminal reported");
    engine.feed(bytes, 0);
    engine.quiesce(0);
    engine.feed(CURSOR_POSITION, 0);
    let replies = engine.lane_mut().drain(LaneGate::default(), 4096, 0);
    let answer: Vec<u8> = replies
        .iter()
        .flat_map(|reply| reply.bytes().to_vec())
        .collect();
    let position =
        replies::cursor_position(&answer).expect("the engine answers a cursor position report");
    let state = engine.screen_state(Viewport {
        top_row: 0,
        rows,
        left_col: 0,
        cols,
    });
    (position, state.cursor.pending_wrap)
}

/// Measures one step.
///
/// # Errors
///
/// Fails when the terminal cannot be written to or read from.
pub fn measure(
    terminal: &mut dyn Terminal,
    step: &Step,
    cols: u32,
    rows: u32,
) -> io::Result<Outcome> {
    let mut sent = RESET.to_vec();
    sent.extend_from_slice(&step.bytes);
    sent.extend_from_slice(CURSOR_POSITION);
    sent.extend_from_slice(BARRIER);
    terminal.send(&sent)?;
    let received = terminal.receive()?;
    let barrier = received.is_some();
    let answered = received.and_then(|bytes| replies::cursor_position(&bytes));
    let (canonical, pending) = canonical(cols, rows, &step.bytes);
    Ok(Outcome {
        id: step.id.clone(),
        group: step.group.to_owned(),
        bytes: kr_term::conformance::hex(&step.bytes),
        terminal: answered,
        canonical,
        canonical_pending_wrap: pending,
        barrier,
        agrees: answered == Some(canonical),
    })
}

/// What a run of the corpus produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measured {
    /// The steps measured, in order. A run that stopped early holds the steps before the stop and
    /// the one it stopped at.
    pub outcomes: Vec<Outcome>,
    /// Why the run stopped before the end of the corpus, when it did.
    pub stopped: Option<String>,
}

/// Measures every step, in order, and stops at the first step whose reply to primary device
/// attributes never arrives.
///
/// The reply to primary device attributes is what ends each step's read. When it does not come the
/// terminal may still be about to answer, and an answer that arrives during the next step would be
/// taken for that step's, so the run ends there rather than go on with a stream it can no longer
/// trust. The step it stopped at is recorded as unanswered.
///
/// # Errors
///
/// Fails when the terminal cannot be written to or read from.
pub fn measure_all(
    terminal: &mut dyn Terminal,
    steps: &[Step],
    cols: u32,
    rows: u32,
) -> io::Result<Measured> {
    let mut outcomes = Vec::with_capacity(steps.len());
    let mut stopped = None;
    for step in steps {
        let outcome = measure(terminal, step, cols, rows)?;
        let answered = outcome.barrier;
        outcomes.push(outcome);
        if !answered {
            stopped = Some(format!(
                "no reply to primary device attributes after {}, so a late reply could be taken \
                 for the next step's",
                step.id
            ));
            break;
        }
    }
    // Leave the terminal as a person would want it.
    terminal.send(&[RESET, b"\x1b[?25h"].concat())?;
    Ok(Measured { outcomes, stopped })
}
