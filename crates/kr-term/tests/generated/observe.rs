//! What an engine does with a stream read in pieces.

use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig, FeedOutcome};
use kr_term::event::Event;
use kr_term::lane::{LaneGate, LaneLimits};
use kr_term::lexer::{LexLimits, Lexer};
use kr_term::sideeffect::{LeaseHolder, SideEffectKind};
use kr_term::snapshot::{Snapshot, Viewport};

/// The two grids every stream is run on: an ordinary one and one so small that everything wraps,
/// scrolls and clips.
pub const SIZES: [(u32, u32); 2] = [(80, 24), (7, 4)];

/// Everything one run of a stream through an engine shows.
#[derive(Clone)]
pub struct Seen {
    /// The bytes the engine says a direct attachment may be handed, and where they came from.
    pub forward: Vec<u8>,
    pub forwarded: Vec<(u64, u64)>,
    pub side_effects: Vec<(SideEffectKind, u64)>,
    pub refusals: usize,
    /// The replies the lane holds, by the offset of the query each answers.
    pub replies: Vec<(u64, Vec<u8>)>,
    pub projection_at: Option<u64>,
    pub snapshot: Snapshot,
    pub degraded: bool,
    pub ground: bool,
    pub grid_writes: usize,
    pub unrecognised: u64,
    /// The most bytes the lane held at the end of any read.
    pub queue_peak: usize,
}

impl Seen {
    /// The same run with a forwarded set the engine did not produce. A check that is handed this
    /// must name what is wrong with it.
    pub fn forging(&self, bytes: &[u8], spans: &[(u64, u64)]) -> Self {
        let mut forged = self.clone();
        forged.forwarded = spans.to_vec();
        forged.forward = spans
            .iter()
            .flat_map(|&(start, end)| bytes[index(start)..index(end)].iter().copied())
            .collect();
        forged
    }
}

pub fn index(offset: u64) -> usize {
    usize::try_from(offset).unwrap_or(usize::MAX)
}

pub fn viewport(size: GridSize) -> Viewport {
    Viewport {
        top_row: 0,
        rows: size.rows,
        left_col: 0,
        cols: size.cols,
    }
}

fn take(outcome: &FeedOutcome, bytes: &[u8], seen: &mut Seen) {
    for span in &outcome.forward {
        let (start, end) = (span.start(), span.end());
        seen.forwarded.push((start, end));
        seen.forward
            .extend_from_slice(&bytes[index(start)..index(end)]);
    }
    for effect in &outcome.side_effects {
        seen.side_effects.push((effect.kind.clone(), effect.at));
    }
    seen.refusals += outcome.refusals.len();
    if seen.projection_at.is_none() {
        seen.projection_at = outcome.projection_required_at;
    }
}

/// Feeds `bytes` to a new engine in reads that end at `cuts`, closes it and takes what it shows.
pub fn feed_in(bytes: &[u8], cuts: &[usize], size: GridSize) -> Seen {
    let mut engine = Engine::new(EngineConfig {
        size,
        ..EngineConfig::DEFAULT
    })
    .expect("an engine");
    engine.set_lease_holder(LeaseHolder::none());
    let empty = engine.screen_with_rows(viewport(size));
    let mut seen = Seen {
        forward: Vec::new(),
        forwarded: Vec::new(),
        side_effects: Vec::new(),
        refusals: 0,
        replies: Vec::new(),
        projection_at: None,
        snapshot: empty,
        degraded: false,
        ground: false,
        grid_writes: 0,
        unrecognised: 0,
        queue_peak: 0,
    };
    let mut from = 0;
    for &to in cuts {
        let outcome = engine.feed(&bytes[from..to], 0);
        take(&outcome, bytes, &mut seen);
        seen.queue_peak = seen.queue_peak.max(engine.lane().queued_bytes());
        from = to;
    }
    let closing = engine.close(0);
    take(&closing, bytes, &mut seen);
    seen.queue_peak = seen.queue_peak.max(engine.lane().queued_bytes());
    for reply in engine
        .lane_mut()
        .drain(LaneGate::default(), usize::MAX / 2, 0)
    {
        seen.replies
            .push((reply.query_at(), reply.bytes().to_vec()));
    }
    seen.degraded = engine.lane().degradation().is_degraded();
    seen.ground = engine.at_ground();
    seen.grid_writes = engine.grid().writer_log().bytes;
    seen.unrecognised = engine.grid().unrecognised();
    seen.snapshot = engine.snapshot(viewport(size), 0).0;
    seen
}

/// Feeds `bytes` in one read.
pub fn feed_whole(bytes: &[u8], size: GridSize) -> Seen {
    feed_in(bytes, &[bytes.len()], size)
}

/// The events the lexer makes of `bytes` read at once, at every depth.
pub fn lex(bytes: &[u8]) -> Vec<Event> {
    let mut lexer = Lexer::with_limits(LexLimits::DEFAULT);
    let mut events = Vec::new();
    lexer.feed(bytes, &mut events);
    lexer.close(&mut events);
    events
}

/// The bound on the lane's queue.
pub const QUEUE_BOUND: usize = LaneLimits::DEFAULT.max_queue_bytes;
