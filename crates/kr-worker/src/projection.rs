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
use kr_protocol::projection::ProjectionResetReason;
use kr_protocol::session::Dimensions;
use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig, FeedOutcome};
use kr_term::lane::LaneGate;
use kr_term::modes::KeyboardEncoding;
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
    /// Whether the session's initial palette has been chosen.
    ///
    /// Once, at creation. A second choice is a change to the session's palette, which is a terminal
    /// mutation with an authority of its own and not something a creation-time seam may make.
    palette_chosen: bool,
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
            palette_chosen: false,
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

    /// Returns the output cursor of a parser-ground boundary, when the parser is on one.
    ///
    /// This is where live byte forwarding may begin, and it is the only place it may: anywhere else
    /// is inside an incomplete UTF-8 scalar or an incomplete control sequence, and a physical
    /// terminal handed the middle of one draws something nobody wrote. The same cursor is what a
    /// snapshot taken here names, so the screen and the byte stream meet exactly.
    #[must_use]
    pub fn ground_boundary(&self) -> Option<u64> {
        self.engine.ground_boundary()
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

    /// Returns the encoding an input path must produce to control this application.
    ///
    /// The canonical parser is the only thing that knows it. Every answer is a demand on the
    /// controller, the ordinary one included: a terminal left in an enhanced protocol by whatever
    /// ran before this attachment sends key events an application expecting the ordinary encoding
    /// reads as something else entirely, which is the same failure as the other direction.
    #[must_use]
    pub fn keyboard_negotiated(&self) -> KeyboardEncoding {
        self.engine.modes().keyboard_encoding()
    }

    /// Describes that encoding for a refusal a caller reads.
    #[must_use]
    pub fn keyboard_in_force(&self) -> String {
        match self.keyboard_negotiated() {
            KeyboardEncoding::Legacy => "the ordinary terminal encoding".to_owned(),
            KeyboardEncoding::Kitty(flags) => {
                format!("the Kitty keyboard protocol with flags {flags}")
            }
            KeyboardEncoding::ModifyOtherKeys(level) => format!("modifyOtherKeys level {level}"),
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
        scope: crate::render::Scope,
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
            render(&operations, viewport, keyboard, scope),
            settled,
        )
    }

    /// Records where this session's initial palette came from.
    ///
    /// Section 8 fixes the palette at creation and forbids succession from changing it, so this is
    /// called once, before the session has produced anything. After that the palette is the
    /// session's own: a second attachment whose terminal has different colours is shown these.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] once the session has produced output, because a
    /// palette chosen then would be a change to a screen somebody is already looking at rather
    /// than the provenance of the one it started with.
    pub fn set_initial_palette(&mut self, choice: crate::snapshot::PaletteChoice) -> Result<()> {
        // What the engine has *read*, not what it has committed. A session whose first read was an
        // incomplete escape sequence, or whose first character is still held for a combining mark,
        // has produced output whose committed cursor is still zero; a palette chosen then would be
        // a change to a screen rather than the provenance of the one it started with.
        if self.engine.read_offset() > 0 || self.palette_chosen {
            return Err(WorkerError::InvalidArgument(
                "the session's palette is fixed at creation and this session has already produced \
                 output"
                    .to_owned(),
            ));
        }
        self.engine.adopt_palette(choice.palette());
        self.palette_chosen = true;
        Ok(())
    }

    /// Where the session's palette came from.
    #[must_use]
    pub fn palette_source(&self) -> kr_term::palette::PaletteSource {
        self.engine.palette().source()
    }

    /// Which buffer the canonical grid is showing.
    #[must_use]
    pub fn active_buffer(&self) -> kr_term::snapshot::ActiveBuffer {
        if self.engine.grid().alternate_active() {
            kr_term::snapshot::ActiveBuffer::Alternate
        } else {
            kr_term::snapshot::ActiveBuffer::Primary
        }
    }

    /// The window a client of these dimensions is looking at, anchored at the visible page.
    ///
    /// The top row is read from the grid rather than guessed at, because eviction and scrolling
    /// both move it and a client holding rows by their identifiers has to be told which of them
    /// the page now holds.
    #[must_use]
    pub fn anchored_viewport(&self, dimensions: Dimensions) -> Viewport {
        let mut viewport = self.viewport_for(dimensions);
        viewport.top_row = self.engine.grid().visible_top_row();
        viewport
    }

    /// Builds the events that install the canonical screen on a projected client.
    ///
    /// Taking a snapshot settles the screen, which releases whatever the engine was holding back.
    /// Those bytes belong to every direct attachment, so they come back with the update rather
    /// than disappearing inside one subscriber's snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the engine's state cannot be spelled on the wire.
    pub fn projection_install(
        &mut self,
        dimensions: Dimensions,
        reason: ProjectionResetReason,
        gate: LaneGate,
        now_ms: u64,
        budget: usize,
    ) -> Result<(crate::snapshot::Update, Filtered)> {
        let viewport = self.viewport_for(dimensions);
        // The state without its rows, and then the rows a bounded run at a time as the pages are
        // built. Taking the whole screen first and paging it afterwards would hold the session
        // twice over: once as the engine's copy of it and once as the wire's.
        let (mut snapshot, settled) = self.engine.snapshot_without_rows(viewport, now_ms);
        let settled = self.collect(&settled, gate, now_ms);
        let mut viewport = viewport;
        viewport.top_row = self.engine.grid().visible_top_row();
        snapshot.viewport = viewport;
        let degraded = self.resident_state_truncated();
        let update =
            crate::snapshot::install(&snapshot, viewport, reason, degraded, budget, &self.engine)?;
        Ok((update, settled))
    }

    /// What the smallest installation of this screen costs a subscriber's queue.
    ///
    /// The whole of one - the reset, the header and the pages - with every row emptied, which is as
    /// small as this session's screen can be made. A queue below it is one no screen can cross, and
    /// a client with one is told so when it asks rather than being resynchronised for ever.
    ///
    /// It changes nothing: measuring a screen is not a reason to settle one, so this reads the state
    /// where it stands rather than taking a snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when the engine's state cannot be spelled on the wire.
    pub fn minimum_projection_install(&self, dimensions: Dimensions) -> Result<usize> {
        let viewport = self.anchored_viewport(dimensions);
        let mut state = self.engine.screen_state(viewport);
        state.viewport = viewport;
        crate::snapshot::minimum_install(&state, viewport, &self.engine)
    }

    /// Builds what one client is owed, given the screen it already holds.
    ///
    /// The answer is a bounded update, nothing at all, or a fresh screen with the reason it is one:
    /// a base this engine can no longer continue from, or a change larger than one bounded update.
    ///
    /// # Errors
    ///
    /// Returns an error when the engine's state cannot be spelled on the wire.
    pub fn projection_advance(
        &self,
        held: crate::snapshot::Held,
        dimensions: Dimensions,
    ) -> Result<crate::snapshot::Owed> {
        let Ok(delta) = self.engine.delta(held.base.cursor, held.base.generation) else {
            // The base is outside the engine's replay window, or the projection was reset since
            // then. Either way there is nothing to continue from.
            return Ok(crate::snapshot::Owed::Snapshot(
                ProjectionResetReason::ReplayGap,
            ));
        };
        let (oldest, _) = self.engine.grid().stable_range();
        crate::snapshot::advance(
            &delta,
            self.active_buffer(),
            self.anchored_viewport(dimensions),
            oldest,
            oldest > 0,
            self.resident_state_truncated(),
            Some(held.viewport),
        )
    }

    /// Whether this session has had to shorten content to stay inside a resident-state bound.
    ///
    /// Section 8 requires truncation to have an explicit projection degradation. A client drawing
    /// the canonical grid cannot tell a cell whose combining marks were dropped at the per-cell
    /// bound from a cell the application wrote that way, so the fact travels with the projection.
    #[must_use]
    pub fn resident_state_truncated(&self) -> bool {
        self.engine
            .diagnostic_totals()
            .into_iter()
            .any(|(kind, total)| {
                kind == kr_term::diag::DiagnosticKind::ResidentStateTruncated && total > 0
            })
    }

    /// The generation every projection update currently names.
    #[must_use]
    pub const fn projection_generation(&self) -> u64 {
        self.engine.projection_generation()
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
            crate::render::Scope::WholeScreen,
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

#[cfg(test)]
mod projection_tests {
    use super::*;
    use crate::snapshot::{Base, Held, Owed, PaletteChoice};
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

    /// KR-REQ-08.83: each buffer's pages carry that buffer's own retention.
    ///
    /// The primary buffer keeps a scrollback and gives its oldest rows up; the alternate buffer
    /// keeps none and numbers its rows from its own beginning. A client told the showing buffer's
    /// cutoff for the other one would give up rows that are the whole of that screen.
    #[test]
    fn each_buffers_pages_carry_that_buffers_own_retention() {
        let mut engine = engine();
        // Past the scrollback bound, so the primary buffer has given rows up.
        let mut stream = Vec::new();
        for line in 0..3_600 {
            stream.extend_from_slice(format!("line {line}\r\n").as_bytes());
        }
        // Then into the alternate buffer, which starts its own numbering and keeps no history.
        stream.extend_from_slice(b"\x1b[?1049h");
        stream.extend_from_slice(b"an application's screen\r\n");
        engine.feed(0, &stream, LaneGate::default(), 0);
        let (update, _) = engine
            .projection_install(
                dimensions(80, 24),
                ProjectionResetReason::Attached,
                LaneGate::default(),
                0,
                crate::output::DEFAULT_SEND_QUEUE_BYTES,
            )
            .expect("a snapshot");
        let pages: Vec<&kr_protocol::projection::ProjectionRowPage> = update
            .events
            .iter()
            .filter_map(|outgoing| match &outgoing.event {
                kr_protocol::projection::ProjectionEvent::Rows(page) => Some(page),
                _ => None,
            })
            .collect();
        let primary = pages
            .iter()
            .find(|page| page.buffer == kr_protocol::projection::ProjectedBuffer::Primary)
            .expect("the primary buffer's rows");
        let alternate = pages
            .iter()
            .find(|page| page.buffer == kr_protocol::projection::ProjectedBuffer::Alternate)
            .expect("the alternate buffer's rows");
        assert!(
            primary.oldest_retained_row.get() > 0 && primary.evicted,
            "the primary buffer gave rows up and says so: {:?}",
            primary.oldest_retained_row
        );
        assert!(
            !alternate.evicted,
            "the alternate buffer keeps no history, so nothing of it was evicted"
        );
        assert_eq!(
            alternate.oldest_retained_row.get(),
            0,
            "and its own numbering starts where it started"
        );
    }

    /// KR-REQ-08.79: a screen that fits arrives whole, however unevenly its content is spread.
    ///
    /// The bound is on the whole installation, not on each row's share of it. One long row among
    /// many short ones is a screen a person can read, and a rule that gave every row the same
    /// allowance would cut that row for the sake of a budget the screen never came near.
    #[test]
    fn one_long_row_among_short_ones_keeps_what_it_has() {
        let mut engine = engine();
        let mut stream = Vec::new();
        // One row carrying a long hyperlink on every cell, and twenty-three rows carrying a word.
        for column in 0..80_u32 {
            let target = format!("https://example.invalid/{column}/{}", "u".repeat(1_900));
            stream.extend_from_slice(format!("\x1b]8;;{target}\x1b\\x\x1b]8;;\x1b\\").as_bytes());
        }
        stream.extend_from_slice(b"\r\n");
        for line in 0..23 {
            stream.extend_from_slice(format!("line {line}\r\n").as_bytes());
        }
        engine.feed(0, &stream, LaneGate::default(), 0);
        // A queue several times what this screen costs, and far less than forty-eight times what
        // its longest row costs: a rule that gave every row the same allowance would cut that row
        // here, and the screen it belongs to never came near the queue.
        let (update, _) = engine
            .projection_install(
                dimensions(80, 24),
                ProjectionResetReason::Attached,
                LaneGate::default(),
                0,
                512 * 1024,
            )
            .expect("a snapshot");
        let total: usize = update.events.iter().map(|outgoing| outgoing.bytes).sum();
        assert!(
            total < 512 * 1024,
            "the screen is well inside the queue: {total} bytes"
        );
        let header = update
            .events
            .iter()
            .find_map(|outgoing| match &outgoing.event {
                kr_protocol::projection::ProjectionEvent::Snapshot(header) => Some(header),
                _ => None,
            })
            .expect("a header");
        assert!(!header.degraded, "so nothing of it was given up");
        let truncated = update
            .events
            .iter()
            .filter_map(|outgoing| match &outgoing.event {
                kr_protocol::projection::ProjectionEvent::Rows(page) => Some(page),
                _ => None,
            })
            .flat_map(|page| page.rows.iter())
            .filter(|row| row.truncated)
            .count();
        assert_eq!(
            truncated, 0,
            "and no row was cut, although one of them is far longer than an even share"
        );
    }

    /// KR-REQ-08.79 and KR-REQ-08.80: a screen larger than a subscriber's queue is cut to it,
    /// explicitly, rather than refused for ever.
    ///
    /// A client holding some of a snapshot's pages holds no screen and draws nothing, so a screen
    /// that cannot fit the queue it must pass through has to be cut and say so. Refusing it instead
    /// would resynchronise the client, produce the same screen again and refuse it again.
    #[test]
    fn a_screen_too_large_for_a_subscribers_queue_is_cut_and_says_so() {
        let mut engine = engine();
        // A distinct long hyperlink target on every cell of every row, which is what the wire has
        // to repeat per run. Legal, and far larger than the queue below.
        let mut stream = Vec::new();
        for row in 0..24_u32 {
            for column in 0..80_u32 {
                let target = format!(
                    "https://example.invalid/{row}/{column}/{}",
                    "u".repeat(1_900)
                );
                stream
                    .extend_from_slice(format!("\x1b]8;;{target}\x1b\\x\x1b]8;;\x1b\\").as_bytes());
            }
            stream.extend_from_slice(b"\r\n");
        }
        engine.feed(0, &stream, LaneGate::default(), 0);
        let budget = 256 * 1024;
        let (update, _) = engine
            .projection_install(
                dimensions(80, 24),
                ProjectionResetReason::Attached,
                LaneGate::default(),
                0,
                budget,
            )
            .expect("a snapshot");
        let total: usize = update.events.iter().map(|outgoing| outgoing.bytes).sum();
        assert!(
            total <= budget,
            "the whole screen fits the queue it has to pass through: {total} bytes against {budget}"
        );
        // And exactly at the boundary, which is where an installation measured by its rows alone
        // would overflow: the pages themselves cost something, and a budget that fits the rows but
        // not the pages would be refused, resynchronised and refused again.
        let (tight, _) = engine
            .projection_install(
                dimensions(80, 24),
                ProjectionResetReason::Attached,
                LaneGate::default(),
                0,
                total,
            )
            .expect("a snapshot");
        let carried: usize = tight.events.iter().map(|outgoing| outgoing.bytes).sum();
        assert!(
            carried <= total,
            "a budget of exactly what the last screen cost still carries a whole screen: \
             {carried} against {total}"
        );
        let header = update
            .events
            .iter()
            .find_map(|outgoing| match &outgoing.event {
                kr_protocol::projection::ProjectionEvent::Snapshot(header) => Some(header),
                _ => None,
            })
            .expect("a header");
        assert!(
            header.degraded,
            "and the client is told that what it is holding is not all of the session"
        );
        // And at every budget, not only at the one this test picked. The interesting failures are
        // at the boundaries: a budget that fits the rows and not the pages they divide into, and
        // one that fits neither. The smallest installation there is - every row emptied - is what
        // a budget below it gets, and the publish then tells the client its queue is full.
        let smallest: usize = engine
            .projection_install(
                dimensions(80, 24),
                ProjectionResetReason::Attached,
                LaneGate::default(),
                0,
                0,
            )
            .expect("a snapshot")
            .0
            .events
            .iter()
            .map(|outgoing| outgoing.bytes)
            .sum();
        for divisor in [1_usize, 2, 3, 5, 8, 13, 21, 34, 55] {
            let budget = (total / divisor).max(1);
            let (tried, _) = engine
                .projection_install(
                    dimensions(80, 24),
                    ProjectionResetReason::Attached,
                    LaneGate::default(),
                    0,
                    budget,
                )
                .expect("a snapshot");
            let carried: usize = tried.events.iter().map(|outgoing| outgoing.bytes).sum();
            assert!(
                carried <= budget || budget < smallest,
                "a budget of {budget} carries {carried} bytes, and the smallest screen this \
                 session can be sent is {smallest}"
            );
            let complete = tried
                .events
                .iter()
                .filter(|outgoing| {
                    matches!(
                        &outgoing.event,
                        kr_protocol::projection::ProjectionEvent::Rows(page) if !page.more
                    )
                })
                .count();
            assert_eq!(
                complete, 1,
                "and whatever it carries is a whole screen: one page clears `more`"
            );
        }

        let pages: Vec<&kr_protocol::projection::ProjectionRowPage> = update
            .events
            .iter()
            .filter_map(|outgoing| match &outgoing.event {
                kr_protocol::projection::ProjectionEvent::Rows(page) => Some(page),
                _ => None,
            })
            .collect();
        assert!(!pages.is_empty(), "the rows still arrive");
        assert!(
            pages.iter().filter(|page| !page.more).count() == 1,
            "and the last page clears `more`, so the screen completes"
        );
        assert!(
            pages
                .iter()
                .flat_map(|page| page.rows.iter())
                .any(|row| row.truncated),
            "the rows that were cut say they were cut"
        );
    }

    /// KR-REQ-08.80 and KR-REQ-08.83: a base outside the replay window asks for a fresh screen.
    #[test]
    fn a_base_outside_the_bounded_replay_window_asks_for_a_fresh_snapshot() {
        let mut engine = engine();
        let (update, _) = engine
            .projection_install(
                dimensions(40, 10),
                ProjectionResetReason::Attached,
                LaneGate::default(),
                0,
                crate::output::DEFAULT_SEND_QUEUE_BYTES,
            )
            .expect("a snapshot");
        let held = Held {
            base: update.base,
            viewport: engine.anchored_viewport(dimensions(40, 10)),
        };
        // One batch later the client can still be continued from.
        let mut cursor = engine.output_cursor();
        let batch = b"a\r\n";
        engine.feed(cursor, batch, LaneGate::default(), 0);
        cursor += batch.len() as u64;
        assert!(
            matches!(
                engine
                    .projection_advance(held, dimensions(40, 10))
                    .expect("an answer"),
                Owed::Update(_)
            ),
            "a base inside the window is continued from"
        );
        // Far enough past it that the checkpoint the client named has left the window. The window
        // is bounded, which is the whole point: a client that has fallen further behind than this
        // is told to start again rather than being reasoned about.
        for _ in 0..200 {
            engine.feed(cursor, batch, LaneGate::default(), 0);
            cursor += batch.len() as u64;
        }
        assert_eq!(
            engine
                .projection_advance(held, dimensions(40, 10))
                .expect("an answer"),
            Owed::Snapshot(ProjectionResetReason::ReplayGap),
            "and a base past the window is a gap, which discards what the client holds"
        );
    }

    /// KR-REQ-08.44: the palette's provenance is fixed at creation and reported afterwards.
    #[test]
    fn the_palette_source_is_chosen_at_creation_and_refused_afterwards() {
        let mut engine = engine();
        assert_eq!(
            engine.palette_source(),
            kr_term::palette::PaletteSource::ProfileDefault
        );
        engine
            .set_initial_palette(PaletteChoice::LightPreset)
            .expect("a session that has produced nothing");
        assert_eq!(
            engine.palette_source(),
            kr_term::palette::PaletteSource::LightPreset
        );
        engine.feed(0, b"output", LaneGate::default(), 0);
        let refused = engine
            .set_initial_palette(PaletteChoice::DarkPreset)
            .expect_err("a session that has produced output");
        assert!(
            matches!(refused, WorkerError::InvalidArgument(_)),
            "changing it later would be a change to a screen somebody is looking at: {refused:?}"
        );
        assert_eq!(
            engine.palette_source(),
            kr_term::palette::PaletteSource::LightPreset,
            "and the refusal changed nothing"
        );
    }

    /// KR-REQ-08.79: a geometry whose state would not fit the session budget is refused first.
    #[test]
    fn a_geometry_that_does_not_fit_the_session_budget_is_refused_before_it_is_allocated() {
        let mut engine = engine();
        // Inside every one of section 8's three independent limits — 61 columns, 1,002 rows and
        // 61,122 cells — and outside what both screen buffers and their scrollback may hold. The
        // two are different refusals and this is the second one.
        let refused = engine
            .resize(dimensions(61, 1_002), 0)
            .expect_err("a grid whose state does not fit the session budget");
        assert!(
            matches!(refused, WorkerError::ResourceUnavailable { .. }),
            "the refusal is this session's capacity rather than the caller's mistake: {refused:?}"
        );
        assert!(
            matches!(
                engine.resize(dimensions(2_048, 1_024), 0),
                Err(WorkerError::InvalidArgument(_))
            ),
            "and a geometry outside the cell count is the caller's mistake, which is a different              refusal"
        );
        assert_eq!(
            engine.canonical(),
            dimensions(80, 24),
            "and nothing moved: the grid is the size it was"
        );
    }

    /// KR-REQ-08.83: nothing is sent for a screen that has not changed.
    #[test]
    fn a_screen_that_has_not_changed_produces_no_update() {
        let mut engine = engine();
        let (update, _) = engine
            .projection_install(
                dimensions(40, 10),
                ProjectionResetReason::Attached,
                LaneGate::default(),
                0,
                crate::output::DEFAULT_SEND_QUEUE_BYTES,
            )
            .expect("a snapshot");
        let held = Held {
            base: update.base,
            viewport: engine.anchored_viewport(dimensions(40, 10)),
        };
        assert_eq!(
            engine
                .projection_advance(held, dimensions(40, 10))
                .expect("an answer"),
            Owed::Nothing,
            "a quiet stream is not an update"
        );
    }

    /// KR-REQ-08.83: a base from another generation is not a base this engine can continue from.
    #[test]
    fn a_base_from_another_generation_asks_for_a_fresh_snapshot() {
        let mut engine = engine();
        let (update, _) = engine
            .projection_install(
                dimensions(40, 10),
                ProjectionResetReason::Attached,
                LaneGate::default(),
                0,
                crate::output::DEFAULT_SEND_QUEUE_BYTES,
            )
            .expect("a snapshot");
        let stale = Held {
            base: Base {
                cursor: update.base.cursor,
                generation: update.base.generation.saturating_sub(1),
            },
            viewport: engine.anchored_viewport(dimensions(40, 10)),
        };
        assert_eq!(
            engine
                .projection_advance(stale, dimensions(40, 10))
                .expect("an answer"),
            Owed::Snapshot(ProjectionResetReason::ReplayGap),
            "the same cursor in another generation is another screen"
        );
    }
}
