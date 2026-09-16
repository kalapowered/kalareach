//! The canonical grid, the filtered stream and the presentation each terminal is served.
//!
//! A worker owns the raw byte stream: what the application wrote, in order, with a cursor. Section
//! 8 is explicit that it must own the *interpretation* as well, because the moment two terminals
//! can see one session the ordinary assumption that the terminal in front of you is the terminal
//! stops being true. Column counts decide where lines wrap and where the cursor is; a query has
//! exactly one correct answer and exactly one place to come from; a bell, a clipboard write and a
//! notification happen once, to one destination.
//!
//! This module is where a session holds [`kr_term::Engine`] and where every consequence of holding
//! it is decided.
//!
//! # What passing the stream through the engine changes
//!
//! | | Before | Through the engine |
//! | --- | --- | --- |
//! | A query the application sends | reaches every attached terminal, and each answers | consumed; the broker answers once, into the application's own input |
//! | A bell, clipboard write or notification | reaches every attached terminal | routed to the one attachment holding the input lease |
//! | A sequence the profile does not name | forwarded and hoped to be harmless | consumed, with a rate-limited diagnostic |
//! | A terminal of another size | sent bytes that assume the session's width | shown the canonical grid, clipped to the size it has |
//! | A terminal that reconnects | replayed the raw history it missed | given a side-effect-free restoration of the screen as it is now |
//!
//! # The two presentations
//!
//! | Presentation | What it receives | When it applies |
//! | --- | --- | --- |
//! | `direct` | the spans of the raw stream the engine says a terminal may take unchanged | the terminal is exactly the canonical size and the stream is still carryable |
//! | `viewport` | a rendering of the canonical grid, clipped to the terminal's own size | every other case |
//!
//! Direct mode is *qualified*, not assumed: the engine reports the point at which the stream stops
//! being something a physical terminal can be handed, and an attachment moves to a projection there
//! rather than being sent bytes that would leave its screen wrong. A direct attachment is only ever
//! handed complete spans the engine has cleared, each one beginning where a sequence begins, so
//! there is no moment at which it could be handed the middle of an escape sequence.

use kr_protocol::ids::{AttachmentId, InputLeaseEpoch};
use kr_protocol::session::Dimensions;
use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig, FeedOutcome};
use kr_term::lane::LaneGate;
use kr_term::sideeffect::{LeaseHolder, SideEffect, SideEffectKind};
use kr_term::snapshot::{Viewport, restoration_operations};

use crate::error::{Result, WorkerError};
use crate::render::{Restoration, render};

/// The most raw output the host keeps so a span the engine clears later can still be produced.
///
/// Trimming to the engine's committed offset is exactly what a valid forward span needs, and it is
/// not a memory bound on its own: a control string that never terminates leaves the committed
/// offset where it is while the lexer keeps discarding its payload in constant space. This bounds
/// what the host keeps, and a span that then cannot be produced is reported as lost rather than
/// skipped, which resynchronises every subscriber.
pub const MAX_RETAINED_TAIL: usize = 1024 * 1024;

/// The largest batch of query answers written into the application in one go.
///
/// The lane is already bounded by its own limits; this bounds what one read of the terminal can
/// turn into in one write, so a burst of queries cannot become one enormous write.
pub const MAX_REPLY_BYTES: usize = 4 * 1024;

/// What one batch of raw output became.
#[derive(Clone, Debug, Default)]
pub struct Filtered {
    /// Spans of the raw stream a direct attachment may be shown, each with its own cursor.
    ///
    /// The cursors are positions in the raw stream, so they stay comparable with the session's
    /// history and with a snapshot's own cursor. They are not contiguous: what the engine withheld
    /// leaves a gap, which is the point.
    pub direct: Vec<(u64, Vec<u8>)>,
    /// Bytes that belong to the one attachment holding the input lease.
    pub effects: Vec<(u64, Vec<u8>)>,
    /// What the host owes the application, to be written into its terminal input.
    pub replies: Vec<Vec<u8>>,
    /// Where the stream stopped being something a direct attachment can take unchanged.
    pub projection_required_at: Option<u64>,
    /// Whether the projection generation advanced, which invalidates every client's screen.
    pub projection_reset: bool,
    /// Whether a span the engine cleared named bytes this host could no longer produce.
    ///
    /// It should never happen: the retained window begins at the engine's own committed offset, and
    /// nothing before that can be forwarded afterwards. If it ever does, the direct stream has a
    /// hole in it, and a hole a client is not told about is the one failure section 9 forbids.
    pub lost: bool,
    /// Side effects that had no attachment to go to and became host events.
    pub host_events: Vec<SideEffect>,
}

impl Filtered {
    /// Returns whether this batch carries nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.direct.is_empty()
            && self.effects.is_empty()
            && self.replies.is_empty()
            && self.host_events.is_empty()
            && self.projection_required_at.is_none()
            && !self.projection_reset
            && !self.lost
    }

    /// Takes everything another batch carries into this one.
    ///
    /// The two are consecutive parts of one stream, so the cursors each piece carries keep them in
    /// order; nothing here has to know which came first.
    pub fn absorb(&mut self, other: Self) {
        self.direct.extend(other.direct);
        self.effects.extend(other.effects);
        self.replies.extend(other.replies);
        self.host_events.extend(other.host_events);
        self.projection_required_at = self.projection_required_at.or(other.projection_required_at);
        self.projection_reset |= other.projection_reset;
        self.lost |= other.lost;
    }
}

/// The canonical grid of one session.
pub struct TerminalEngine {
    engine: Engine,
    canonical: Dimensions,
    /// Set when the engine says a direct attachment can no longer take the stream unchanged.
    ///
    /// It is cleared by a projection reset, because a reset is the engine starting the projection
    /// again from a screen it fully describes.
    projection_required: bool,
    /// The raw bytes the engine has not committed yet, so a span it clears later can be resolved.
    ///
    /// It begins at the engine's own committed offset and is trimmed to it after every call, which
    /// is exactly what is needed and no more: a span the engine emits names committed bytes, and
    /// nothing before the committed offset can be emitted afterwards. The engine's own lexer
    /// bounds how much it can be collecting, so this is bounded with it.
    tail: Vec<u8>,
    /// The raw cursor `tail` starts at.
    tail_cursor: u64,
}

impl std::fmt::Debug for TerminalEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TerminalEngine")
            .field("canonical", &self.canonical)
            .field("projection_required", &self.projection_required)
            .finish_non_exhaustive()
    }
}

impl TerminalEngine {
    /// Builds the canonical grid of a session of these dimensions.
    ///
    /// # Errors
    ///
    /// Returns an error when the dimensions are outside what a canonical grid may be.
    pub fn new(canonical: Dimensions) -> Result<Self> {
        let size = grid_size(canonical)?;
        let engine = Engine::new(EngineConfig {
            size,
            ..EngineConfig::DEFAULT
        })
        .map_err(term_failure)?;
        Ok(Self {
            engine,
            canonical,
            projection_required: false,
            tail: Vec::new(),
            tail_cursor: 0,
        })
    }

    /// Returns the session's canonical dimensions.
    #[must_use]
    pub const fn canonical(&self) -> Dimensions {
        self.canonical
    }

    /// Returns the raw cursor the engine has *committed* to.
    ///
    /// It lags what has been read by whatever the parser is still collecting, which is what stops a
    /// client holding a cursor for output it has not been given.
    #[must_use]
    pub fn output_cursor(&self) -> u64 {
        self.engine.output_cursor()
    }

    /// Returns whether a direct attachment can still be handed the raw stream.
    #[must_use]
    pub const fn direct_is_carryable(&self) -> bool {
        !self.projection_required
    }

    /// Follows the session's canonical geometry.
    ///
    /// # Errors
    ///
    /// Returns an error when the grid cannot be that size, including
    /// [`WorkerError::ResourceUnavailable`] when what both screen buffers would hold at that size
    /// does not fit the session's budget. Nothing is allocated and nothing moves in that case.
    pub fn resize(&mut self, canonical: Dimensions, now_ms: u64) -> Result<()> {
        let size = grid_size(canonical)?;
        self.engine.resize(size, now_ms).map_err(term_failure)?;
        self.canonical = canonical;
        // A resize advances the engine's projection, so every client's screen is described again
        // from a snapshot rather than continued from one taken at another size. The retained bytes
        // are kept: the lexer's position does not move, so a sequence that was arriving across the
        // resize still has to be resolvable when it completes.
        self.projection_required = false;
        Ok(())
    }

    /// Records who holds the input lease, which is where a side effect goes.
    pub const fn set_lease_holder(&mut self, holder: Option<AttachmentId>, epoch: InputLeaseEpoch) {
        let lease = match holder {
            Some(attachment) => LeaseHolder::new(attachment, epoch),
            None => LeaseHolder::none(),
        };
        self.engine.set_lease_holder(lease);
    }

    /// Feeds one batch of raw output through the canonical grid.
    ///
    /// `cursor` is where the batch starts in the raw stream, which must be where the engine has
    /// consumed to: the grid and the history are two views of one stream, and a disagreement about
    /// where a byte is would put a snapshot's cursor somewhere the history does not have.
    pub fn feed(&mut self, cursor: u64, bytes: &[u8], gate: LaneGate, now_ms: u64) -> Filtered {
        debug_assert_eq!(
            self.engine.read_offset(),
            cursor,
            "the canonical grid and the retained history are two views of one stream"
        );
        let outcome = self.engine.feed(bytes, now_ms);
        self.tail.extend_from_slice(bytes);
        self.collect(&outcome, gate, now_ms)
    }

    /// Returns what the application has negotiated for its keys, when that is not the plain one.
    ///
    /// `None` means an ordinary terminal's own encoding, which every attachment can send. Anything
    /// else is a protocol the terminal has to have been put into: a controller whose terminal was
    /// never put into it sends the plain encoding, and the application reads it as different keys.
    #[must_use]
    pub fn negotiated_keyboard(&self) -> Option<String> {
        let modes = self.engine.modes();
        let level = modes.modify_other_keys();
        match (modes.kitty_flags(), level) {
            (Some(flags), _) if flags != 0 => {
                Some(format!("the Kitty keyboard protocol with flags {flags}"))
            }
            (_, level) if level != 0 => Some(format!("modifyOtherKeys level {level}")),
            _ => None,
        }
    }

    /// Returns whether the application has bracketed paste on, as the canonical parser has it.
    #[must_use]
    pub fn bracketed_paste(&self) -> bool {
        self.engine.bracketed_paste()
    }

    /// Takes whatever the response lane is allowed to write right now.
    ///
    /// The lane holds a reply back while a bracketed paste or a human input frame is open, so the
    /// moment one of those closes is a moment to look again. Nothing else in the engine changes.
    pub fn drain_replies(&mut self, gate: LaneGate, now_ms: u64) -> Vec<Vec<u8>> {
        self.engine
            .lane_mut()
            .drain(gate, MAX_REPLY_BYTES, now_ms)
            .into_iter()
            .map(|reply| reply.bytes().to_vec())
            .collect()
    }

    /// Reads the engine's own rate-limited diagnostic totals.
    ///
    /// The engine consumes a sequence the profile does not name and counts it rather than
    /// forwarding it. Nothing is lost: the totals are here.
    #[must_use]
    pub fn diagnostics(&self) -> Vec<(kr_term::diag::DiagnosticKind, u64)> {
        self.engine.diagnostic_totals()
    }

    /// Settles the screen when the stream goes quiet.
    ///
    /// The last scalar of a run waits to see whether a combining mark follows it, so a screen that
    /// has stopped changing is only final once this has run.
    pub fn quiesce(&mut self, gate: LaneGate, now_ms: u64) -> Filtered {
        let outcome = self.engine.quiesce(now_ms);
        self.collect(&outcome, gate, now_ms)
    }

    /// Returns the window a terminal of these dimensions looks at.
    ///
    /// The window is anchored at the left of the grid and at the top of the visible page: nothing
    /// is reflowed, so a terminal narrower than the session sees the left of each line rather than
    /// a rewrapped approximation of all of it. The top row is filled in when the snapshot is taken,
    /// because it is the snapshot that says which canonical rows the page currently holds.
    #[must_use]
    pub fn viewport_for(&self, dimensions: Dimensions) -> Viewport {
        let rows = u32::try_from(dimensions.rows.get()).unwrap_or(u32::MAX);
        let cols = u32::try_from(dimensions.columns.get()).unwrap_or(u32::MAX);
        let canonical = grid_size(self.canonical).unwrap_or(GridSize::new(1, 1));
        Viewport {
            top_row: 0,
            rows: rows.min(canonical.rows),
            left_col: 0,
            cols: cols.min(canonical.cols),
        }
    }

    /// Returns the bytes that put a terminal into the session's current screen.
    ///
    /// This is what an attachment is given instead of replayed history. Nothing in it can ring,
    /// copy, notify, download, launch or ask anything, because the operations it is built from
    /// have no member that can.
    /// Returns the bytes that put a terminal into the session's current screen.
    ///
    /// Taking a snapshot settles the screen, which releases whatever the engine was holding back.
    /// Those bytes belong to every direct attachment, so they come back with the restoration rather
    /// than disappearing inside one subscriber's snapshot.
    pub fn restoration(
        &mut self,
        dimensions: Dimensions,
        gate: LaneGate,
        now_ms: u64,
        keyboard: crate::render::Keyboard,
    ) -> (u64, Restoration, Filtered) {
        let mut viewport = self.viewport_for(dimensions);
        let (mut snapshot, settled) = self.engine.snapshot(viewport, now_ms);
        let settled = self.collect(&settled, gate, now_ms);
        // The page's own first row is what the window is anchored to. It is read from the snapshot
        // rather than guessed at, because eviction and scrolling both move it.
        if let Some(first) = snapshot.rows.first() {
            viewport.top_row = first.stable_id;
        }
        snapshot.viewport = viewport;
        let operations = restoration_operations(&snapshot);
        (
            snapshot.output_cursor,
            render(&operations, viewport, keyboard),
            settled,
        )
    }

    fn collect(&mut self, outcome: &FeedOutcome, gate: LaneGate, now_ms: u64) -> Filtered {
        let mut filtered = Filtered {
            projection_required_at: outcome.projection_required_at,
            projection_reset: outcome.projection_reset,
            ..Filtered::default()
        };
        if outcome.projection_required_at.is_some() {
            self.projection_required = true;
        }
        if outcome.projection_reset {
            // A reset describes the screen again from a snapshot, so whatever made the stream
            // uncarryable is behind every client rather than in front of it.
            self.projection_required = false;
        }
        for span in &outcome.forward {
            let start = span.start();
            let Some(offset) = start.checked_sub(self.tail_cursor) else {
                filtered.lost = true;
                continue;
            };
            let (Ok(offset), Ok(len)) = (usize::try_from(offset), usize::try_from(span.len()))
            else {
                filtered.lost = true;
                continue;
            };
            let end = offset.saturating_add(len).min(self.tail.len());
            if offset >= end {
                filtered.lost = true;
                continue;
            }
            filtered
                .direct
                .push((start, self.tail[offset..end].to_vec()));
        }
        // Everything up to the engine's committed offset has been decided. Nothing before it can
        // be forwarded afterwards, so nothing before it needs keeping.
        let committed = self.engine.output_cursor();
        if let Some(spent) = committed.checked_sub(self.tail_cursor)
            && let Ok(spent) = usize::try_from(spent)
        {
            let spent = spent.min(self.tail.len());
            self.tail.drain(..spent);
            self.tail_cursor = self.tail_cursor.saturating_add(spent as u64);
        }
        // And a bound of its own, because the committed offset can stand still while an
        // unterminated control string arrives without limit.
        if self.tail.len() > MAX_RETAINED_TAIL {
            let surplus = self.tail.len() - MAX_RETAINED_TAIL;
            self.tail.drain(..surplus);
            self.tail_cursor = self.tail_cursor.saturating_add(surplus as u64);
            filtered.lost = true;
        }
        for effect in &outcome.side_effects {
            match effect.destination {
                kr_term::sideeffect::SideEffectDestination::Attachment { .. } => {
                    if let Some(rendered) = crate::render::side_effect(&effect.kind) {
                        filtered.effects.push((effect.at, rendered));
                    }
                }
                // Nothing holds the lease, so there is no terminal this belongs to. It is reported
                // rather than sent to whoever happens to be watching.
                kr_term::sideeffect::SideEffectDestination::HostEvent => {
                    filtered.host_events.push(effect.clone());
                }
            }
        }
        for reply in self.engine.lane_mut().drain(gate, MAX_REPLY_BYTES, now_ms) {
            filtered.replies.push(reply.bytes().to_vec());
        }
        filtered
    }
}

/// Returns the canonical grid size of a session's dimensions.
fn grid_size(dimensions: Dimensions) -> Result<GridSize> {
    let cols = u32::try_from(dimensions.columns.get()).map_err(|_| {
        WorkerError::InvalidArgument("the session is too wide for a grid".to_owned())
    })?;
    let rows = u32::try_from(dimensions.rows.get()).map_err(|_| {
        WorkerError::InvalidArgument("the session is too tall for a grid".to_owned())
    })?;
    GridSize::new(cols, rows).validate().map_err(term_failure)
}

/// Renders a terminal-engine failure as a worker failure.
fn term_failure(error: kr_term::TermError) -> WorkerError {
    // The engine says what each of its failures is on the wire, and a geometry it refuses before
    // allocating anything is not the caller's mistake but this session's capacity: a client answers
    // it by asking for a size that fits, which is what `RESOURCE_UNAVAILABLE` tells it to do.
    match error.code() {
        kr_protocol::error::ErrorCode::ResourceUnavailable => WorkerError::ResourceUnavailable {
            detail: error.to_string(),
        },
        _ => WorkerError::InvalidArgument(error.to_string()),
    }
}

/// Returns whether a side effect is one a terminal is shown at all.
#[must_use]
pub const fn is_displayable(kind: &SideEffectKind) -> bool {
    !matches!(kind, SideEffectKind::ClipboardRead { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::U64;

    fn dimensions(columns: u64, rows: u64) -> Dimensions {
        Dimensions {
            columns: U64::new(columns),
            rows: U64::new(rows),
        }
    }

    fn engine() -> TerminalEngine {
        TerminalEngine::new(dimensions(80, 24)).expect("a canonical grid")
    }

    #[test]
    fn ordinary_output_reaches_a_direct_attachment_unchanged() {
        let mut engine = engine();
        let filtered = engine.feed(0, b"hello", LaneGate::default(), 0);
        let forwarded: Vec<u8> = filtered
            .direct
            .iter()
            .flat_map(|(_, bytes)| bytes.clone())
            .collect();
        // The last scalar waits for a combining mark, so a settled screen needs the quiesce the
        // session loop performs when the read goes quiet.
        let settled = engine.quiesce(LaneGate::default(), 0);
        let tail: Vec<u8> = settled
            .direct
            .iter()
            .flat_map(|(_, bytes)| bytes.clone())
            .collect();
        assert_eq!([forwarded, tail].concat(), b"hello".to_vec());
    }

    #[test]
    fn a_query_is_answered_into_the_application_and_reaches_no_terminal() {
        let mut engine = engine();
        let filtered = engine.feed(0, b"\x1b[c", LaneGate::default(), 0);
        assert!(
            filtered.direct.is_empty(),
            "no attached terminal is asked the question"
        );
        assert_eq!(
            filtered.replies,
            vec![b"\x1b[?62;22c".to_vec()],
            "the host answers it once, into the application's own input"
        );
    }

    #[test]
    fn a_bell_goes_to_the_lease_holder_alone() {
        let mut engine = engine();
        let attachment = AttachmentId::new(kr_ipc::new_uuid());
        engine.set_lease_holder(Some(attachment), InputLeaseEpoch::new(1));
        let filtered = engine.feed(0, b"\x07", LaneGate::default(), 0);
        assert!(filtered.direct.is_empty(), "nothing is broadcast");
        assert_eq!(filtered.effects.len(), 1);
        assert_eq!(filtered.effects[0].1, vec![0x07]);
        assert!(filtered.host_events.is_empty());
    }

    #[test]
    fn a_bell_with_no_lease_holder_becomes_a_host_event() {
        let mut engine = engine();
        let filtered = engine.feed(0, b"\x07", LaneGate::default(), 0);
        assert!(filtered.effects.is_empty());
        assert_eq!(filtered.host_events.len(), 1);
    }

    #[test]
    fn a_restoration_describes_the_screen_rather_than_the_bytes_that_made_it() {
        let mut engine = engine();
        engine.feed(0, b"\x07before\x1b[c after", LaneGate::default(), 0);
        let (cursor, restoration, _) = engine.restoration(
            dimensions(80, 24),
            LaneGate::default(),
            0,
            crate::render::Keyboard::Install,
        );
        assert!(cursor > 0);
        let text = String::from_utf8_lossy(&restoration.bytes).into_owned();
        assert!(text.contains("before"), "the screen's text is drawn");
        assert!(
            !restoration.bytes.contains(&0x07),
            "the bell is not rung again"
        );
        assert!(!text.contains("\x1b[c"), "the query is not asked again");
    }

    #[test]
    fn a_smaller_terminal_is_shown_the_part_of_the_grid_it_has_room_for() {
        let engine = engine();
        let viewport = engine.viewport_for(dimensions(40, 10));
        assert_eq!(viewport.cols, 40);
        assert_eq!(viewport.rows, 10);
    }

    #[test]
    fn a_larger_terminal_is_never_shown_more_grid_than_there_is() {
        let engine = engine();
        let viewport = engine.viewport_for(dimensions(200, 60));
        assert_eq!(viewport.cols, 80);
        assert_eq!(viewport.rows, 24);
    }
}
