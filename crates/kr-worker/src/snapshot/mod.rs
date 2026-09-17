//! The projection producer: snapshots, bounded row pages, deltas and explicit resets.
//!
//! A projected attachment used to be sent a rendering of the whole screen after every batch of
//! output. Section 8 forbids exactly that — ordinary output is not redrawn after every batch — and
//! the answer is this module. A client is installed once, from a snapshot, and then receives one
//! bounded update per batch: the rows that changed and the state that changed with them.
//!
//! # What a client holds, and why it is two numbers
//!
//! [`Base`] is an output cursor *and* a projection generation. The cursor alone is not a position
//! in a screen's history: a projection reset can happen without a byte arriving, so the same
//! cursor can name two different screens. An update that does not match both is not applied; the
//! client is reset and installed again, which is cheaper than reasoning about what it might have
//! missed.
//!
//! # Every bound
//!
//! | What | Bound | Where it comes from |
//! | --- | --- | --- |
//! | Rows in one page | [`MAX_PROJECTION_PAGE_ROWS`] | Section 8's history-page limit |
//! | Encoded bytes in one page | [`PAGE_BYTES`] | Section 8's page limit and the control-frame limit, whichever binds |
//! | Values in one page | [`PAGE_ITEMS`] | The codec's own item limit |
//! | Rows in one delta | One page's worth of all three | Past any of them the update is a repaint, and a snapshot is sent |
//! | Replay window | The engine's checkpoint window | A base outside it is a gap |
//!
//! Every one of those is **measured** rather than estimated: a page is built from the encoded cost
//! of each row, and the event that carries it is charged to its subscriber's queue at the length it
//! actually encodes to. An estimate of a structure this shape is wrong by an order of magnitude,
//! and a page built from a wrong estimate is a frame the transport refuses to carry — which is a
//! client left with no screen and no marker telling it so.
//!
//! A row that alone exceeds a page bound is not dropped and not silently shortened: its runs are
//! cut and the row is marked truncated, which is the explicit projection degradation section 8
//! asks for.

pub mod wire;

use std::collections::BTreeMap;

use kr_protocol::ids::AttachmentId;
use kr_protocol::projection::{
    MAX_PROJECTION_PAGE_BYTES, MAX_PROJECTION_PAGE_ROWS, ProjectedBuffer, ProjectedRow,
    ProjectionDelta, ProjectionEvent, ProjectionReset, ProjectionResetReason, ProjectionRowPage,
    ProjectionSnapshot,
};
use kr_protocol::scalars::{Nullable, U64};
use kr_term::palette::{Palette, PaletteSource, Rgb};
use kr_term::snapshot::{ActiveBuffer, Delta, Snapshot, Viewport};
use wire::Cost;

use crate::error::Result;

/// Where a session's initial palette comes from.
///
/// Section 8 fixes the palette at creation and forbids succession from changing it. The choice is
/// therefore made once, before the session has produced anything, and the provenance travels with
/// every snapshot so a client can say where the colours it is drawing came from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PaletteChoice {
    /// The profile's own palette, for a session no client stated a preference for.
    #[default]
    ProfileDefault,
    /// The light preset, for a no-probe or invisible creation.
    LightPreset,
    /// The dark preset, for a no-probe or invisible creation.
    DarkPreset,
    /// The foreground and background a client shared during its bounded probe.
    Shared {
        /// The default foreground.
        foreground: Rgb,
        /// The default background.
        background: Rgb,
    },
}

impl PaletteChoice {
    /// The palette this choice starts a session with.
    #[must_use]
    pub fn palette(self) -> Palette {
        match self {
            Self::ProfileDefault => Palette::new(PaletteSource::ProfileDefault),
            Self::LightPreset => Palette::new(PaletteSource::LightPreset),
            Self::DarkPreset => Palette::new(PaletteSource::DarkPreset),
            Self::Shared {
                foreground,
                background,
            } => Palette::from_client_preference(foreground, background),
        }
    }
}

/// What one client's screen is: a cursor in the output stream and the generation it belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Base {
    /// The output cursor the client's screen describes.
    pub cursor: u64,
    /// The projection generation it belongs to.
    pub generation: u64,
}

/// What one client was last sent: the base, and the window it was drawn for.
///
/// The window is part of it because a scroll moves which rows the window holds without changing
/// one of them. A client that was last sent one window and is now looking at another has to be
/// told, and a client whose window has not moved and whose rows have not changed needs no message
/// at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {
    /// The base the next update continues from.
    pub base: Base,
    /// The window that base was built for.
    pub viewport: Viewport,
}

/// What every projected attachment holds.
///
/// It is recorded only once the events that establish it have been queued for that client, so the
/// next update continues from a screen the client has actually been sent.
#[derive(Debug, Default)]
pub struct Bases {
    held: BTreeMap<AttachmentId, Held>,
}

impl Bases {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// What this attachment holds, when it holds anything.
    #[must_use]
    pub fn held(&self, attachment_id: AttachmentId) -> Option<Held> {
        self.held.get(&attachment_id).copied()
    }

    /// Records what an attachment now holds.
    pub fn record(&mut self, attachment_id: AttachmentId, held: Held) {
        self.held.insert(attachment_id, held);
    }

    /// Forgets an attachment, which has detached or moved out of projected mode.
    pub fn forget(&mut self, attachment_id: AttachmentId) {
        self.held.remove(&attachment_id);
    }

    /// Forgets every attachment, which a projection reset does to all of them at once.
    pub fn forget_all(&mut self) {
        self.held.clear();
    }

    /// How many attachments hold a base.
    #[must_use]
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether no attachment holds a base.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }
}

/// What a frame may cost, in bytes.
///
/// The smaller of section 8's page limit and what a control frame can carry once the notification
/// around it and the stream header in front of it are accounted for. A page that met the first and
/// missed the second would be built and then refused by the transport.
pub const PAGE_BYTES: usize = {
    let framed = kr_protocol::limits::MAX_CONTROL_FRAME_LEN
        - kr_protocol::limits::MAX_STREAM_HEADER_LEN
        - ENVELOPE_RESERVE;
    let section_eight = MAX_PROJECTION_PAGE_BYTES as usize;
    if framed < section_eight {
        framed
    } else {
        section_eight
    }
};

/// What a frame may cost, in values.
///
/// The codec counts every scalar, array, map and key against one limit for the whole message, and
/// a page of one run per cell reaches it long before the byte limit. The reserve is the page's own
/// fields and the notification around it.
pub const PAGE_ITEMS: usize = 65_536 - ENVELOPE_RESERVE_ITEMS;

/// What the notification around a payload costs, with room to spare.
const ENVELOPE_RESERVE: usize = 8 * 1024;

/// What the notification around a payload costs in values, with room to spare.
const ENVELOPE_RESERVE_ITEMS: usize = 1_024;

/// How many times an installation is measured, cut and paged again to fit a subscriber's queue.
///
/// Two would do: the first pass learns what the pages cost and the second cuts the rows to what is
/// left. A third answers a cut that changed how the rows divide into pages, and a fourth is there
/// so that the loop's end is a bound rather than a hope.
const PAGE_FITTING_ATTEMPTS: usize = 4;

/// One event, with what it costs the subscriber's queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outgoing {
    /// The event.
    pub event: ProjectionEvent,
    /// The bytes it encodes to, which is what its subscriber's queue is charged.
    pub bytes: usize,
}

/// The events one attachment is owed, and the base it holds once they have been sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    /// The events, in the order they must be delivered.
    pub events: Vec<Outgoing>,
    /// The base the client holds after applying them.
    pub base: Base,
}

impl Update {
    /// Whether this update carries nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// What every event in it costs a subscriber's queue.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.events
            .iter()
            .fold(0_usize, |total, event| total.saturating_add(event.bytes))
    }
}

/// Wraps one event with the cost of the payload it carries.
fn outgoing(event: ProjectionEvent) -> Outgoing {
    let bytes = match &event {
        ProjectionEvent::Reset(reset) => wire::measure(reset),
        ProjectionEvent::Snapshot(header) => wire::measure(header),
        ProjectionEvent::Rows(page) => wire::measure(page),
        ProjectionEvent::Delta(delta) => wire::measure(delta),
    }
    // A payload the codec cannot represent is charged the whole frame, so the subscriber whose
    // queue it would fill is resynchronised rather than sent something nothing can decode.
    .map_or(PAGE_BYTES, |cost| cost.bytes);
    Outgoing { event, bytes }
}

/// Builds the events that install `snapshot` on a client showing `viewport`.
///
/// The order is the contract: the reset discards whatever the client was showing, the header
/// carries everything a screen is apart from its rows, and the pages carry the rows. The last page
/// clears `more`, and a client that has not seen that page does not yet hold a whole screen.
///
/// # Errors
///
/// Returns an error when a row's stable identifier is not a forward count, which this engine
/// cannot produce.
pub fn install(
    snapshot: &Snapshot,
    viewport: Viewport,
    reason: ProjectionResetReason,
    degraded: bool,
    budget: usize,
) -> Result<Update> {
    let generation = snapshot.projection_generation;
    let cursor = snapshot.output_cursor;
    let oldest = wire::row_id(snapshot.oldest_retained_row)?;
    let inactive_oldest = wire::row_id(snapshot.inactive_oldest_retained_row)?;
    let mut events = vec![
        outgoing(ProjectionEvent::Reset(ProjectionReset {
            projection_generation: U64::new(generation),
            cursor: U64::new(cursor),
            reason,
        })),
        outgoing(ProjectionEvent::Snapshot(Box::new(ProjectionSnapshot {
            projection_generation: U64::new(generation),
            output_cursor: U64::new(cursor),
            active_buffer: wire::buffer(snapshot.active_buffer),
            dimensions: kr_protocol::session::Dimensions::new(
                u64::from(snapshot.dimensions.cols),
                u64::from(snapshot.dimensions.rows),
            ),
            viewport: wire::viewport(viewport)?,
            cursor: wire::cursor(snapshot.cursor),
            saved_cursors: wire::saved_cursors(&snapshot.saved_cursors),
            margins: wire::margins(snapshot.margins),
            rendition: wire::rendition(snapshot.rendition),
            tab_stops: snapshot
                .tab_stops
                .iter()
                .map(|at| wire::cells(*at))
                .collect(),
            charsets: wire::charsets(&snapshot.charsets),
            modes: snapshot
                .modes
                .iter()
                .map(|entry| wire::mode(*entry))
                .collect(),
            keypad_application: snapshot.keypad_application,
            keyboard: wire::keyboard(&snapshot.keyboard),
            title: wire::title(&snapshot.title),
            title_stack: snapshot.title_stack.iter().map(wire::saved_title).collect(),
            hyperlink: Nullable(snapshot.hyperlink.clone()),
            palette: wire::palette(&snapshot.palette),
            oldest_retained_row: oldest,
            evicted: snapshot.evicted,
            degraded,
        }))),
    ];

    // The buffer that is not showing is paged first, so a client that switches to it later already
    // has what the shell left behind. Its identity is named rather than implied: "the other one" is
    // not a fact a client can act on after a buffer switch.
    let inactive_buffer = match snapshot.active_buffer {
        ActiveBuffer::Primary => ProjectedBuffer::Alternate,
        ActiveBuffer::Alternate => ProjectedBuffer::Primary,
    };
    // What the reset and the header cost. They come before any row and a client cannot use a row
    // without them, so they are the part of the budget the rows do not get.
    let fixed: usize = events.iter().map(|outgoing| outgoing.bytes).sum();
    let mut carried: Vec<(ProjectedBuffer, &Vec<kr_term::grid::GridRow>)> = vec![
        (inactive_buffer, &snapshot.inactive_rows),
        (wire::buffer(snapshot.active_buffer), &snapshot.rows),
    ];
    let mut converted: Vec<(ProjectedBuffer, Vec<ProjectedRow>)> = Vec::new();
    for (buffer, rows) in core::mem::take(&mut carried) {
        let mut rows = wire::rows(rows)?;
        for row in &mut rows {
            truncate_row(row);
        }
        converted.push((buffer, rows));
    }
    // A screen has to arrive whole or not at all: a client that holds some of the pages holds no
    // screen and draws nothing. So the whole installation is measured against this subscriber's own
    // send queue - the reset, the header and every page as it will be sent - and a screen larger
    // than the queue it has to cross is cut to fit and said to be cut, rather than being refused,
    // resynchronised and refused again. The pages are built, measured and built again, because how
    // much the pages themselves cost depends on how the rows divide between them.
    let row_count: usize = converted.iter().map(|(_, rows)| rows.len()).sum();
    let mut pages = paged(
        snapshot,
        &converted,
        generation,
        cursor,
        oldest,
        inactive_oldest,
    );
    let mut cut = false;
    for _ in 0..PAGE_FITTING_ATTEMPTS {
        let carried: usize = pages
            .iter()
            .map(|page| wire::measure(page).map_or(PAGE_BYTES, |cost| cost.bytes))
            .sum();
        if fixed.saturating_add(carried) <= budget {
            break;
        }
        if row_count == 0 {
            // Nothing left to give up: this queue cannot hold a header and a single empty page.
            // The screen is still built, and the publish refuses it and tells the client that its
            // queue is full, which is exactly what has happened.
            break;
        }
        // What the pages cost with no rows in them is the part of the budget the rows cannot have.
        let envelopes: usize = pages
            .iter()
            .map(|page| {
                let empty = ProjectionRowPage {
                    rows: Vec::new(),
                    ..page.clone()
                };
                wire::measure(&empty).map_or(0, |cost| cost.bytes)
            })
            .sum();
        let room = budget.saturating_sub(fixed.saturating_add(envelopes));
        let share = room / row_count;
        for (_, rows) in &mut converted {
            for row in rows {
                truncate_row_to(row, share, PAGE_ITEMS);
            }
        }
        cut = true;
        pages = paged(
            snapshot,
            &converted,
            generation,
            cursor,
            oldest,
            inactive_oldest,
        );
        if share == 0 {
            // The rows are already empty. Another pass would cut nothing further.
            break;
        }
    }
    if cut
        && let Some(Outgoing {
            event: ProjectionEvent::Snapshot(header),
            ..
        }) = events.get_mut(1)
    {
        header.degraded = true;
    }
    if let Some(last) = pages.last_mut() {
        last.more = false;
    }
    events.extend(
        pages
            .into_iter()
            .map(|page| outgoing(ProjectionEvent::Rows(page))),
    );
    Ok(Update {
        events,
        base: Base { cursor, generation },
    })
}

/// Builds the pages of both buffers, each inside every page bound.
///
/// Separate from [`install`] because the pages are built more than once: how much a page costs
/// depends on how the rows divide between them, so a screen that has to be cut to fit a queue is
/// measured, cut and paged again.
fn paged(
    snapshot: &Snapshot,
    converted: &[(ProjectedBuffer, Vec<ProjectedRow>)],
    generation: u64,
    cursor: u64,
    oldest: U64,
    inactive_oldest: U64,
) -> Vec<ProjectionRowPage> {
    let mut pages = Vec::new();
    for (buffer, rows) in converted {
        // Retention belongs to a buffer, so each buffer's pages carry its own. The engine reports
        // both: the cutoff of the buffer that is showing and the cutoff of the one that is not.
        // Labelling one buffer's pages with the other's would tell a client to give up rows that
        // are the whole of that screen, or to keep rows that are gone, and which of those it is
        // changes with every buffer switch.
        let (page_oldest, page_evicted) = if *buffer == wire::buffer(snapshot.active_buffer) {
            (oldest, snapshot.evicted)
        } else {
            (inactive_oldest, snapshot.inactive_evicted)
        };
        for page in paginate(rows.clone()) {
            pages.push(ProjectionRowPage {
                projection_generation: U64::new(generation),
                output_cursor: U64::new(cursor),
                buffer: *buffer,
                rows: page,
                oldest_retained_row: page_oldest,
                evicted: page_evicted,
                more: true,
            });
        }
    }
    // A snapshot of an empty session still has to complete, or a client would wait for a page that
    // is never coming. The active buffer's page is therefore always present, even with no rows.
    if pages.is_empty() {
        pages.push(ProjectionRowPage {
            projection_generation: U64::new(generation),
            output_cursor: U64::new(cursor),
            buffer: wire::buffer(snapshot.active_buffer),
            rows: Vec::new(),
            oldest_retained_row: oldest,
            evicted: snapshot.evicted,
            more: true,
        });
    }
    pages
}

/// What one client is owed right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owed {
    /// Nothing has changed since the base, so nothing is sent.
    ///
    /// The read loop settles the screen whenever the stream goes quiet, and a screen that has not
    /// changed is not an update. Sending one anyway would put a message on every subscriber's queue
    /// for every quiet moment of the session.
    Nothing,
    /// A bounded update.
    Update(Update),
    /// A fresh screen, for the named reason.
    Snapshot(ProjectionResetReason),
}

/// Builds the bounded update that continues from `delta`.
///
/// # Errors
///
/// Returns an error when a row's stable identifier is not a forward count.
pub fn advance(
    delta: &Delta,
    buffer: ActiveBuffer,
    viewport: Viewport,
    oldest_retained_row: i64,
    evicted: bool,
    degraded: bool,
    held_viewport: Option<Viewport>,
) -> Result<Owed> {
    let mut rows = wire::rows(&delta.rows)?;
    if !fits_one_page(&rows) {
        // More rows changed than one page carries. That is a repaint rather than an update, and a
        // repaint is a snapshot: it pages, and a client that applied a delta this size would have
        // to hold the whole thing in one message first.
        return Ok(Owed::Snapshot(ProjectionResetReason::Repaint));
    }
    if carries_nothing(delta, viewport, held_viewport) {
        return Ok(Owed::Nothing);
    }
    for row in &mut rows {
        truncate_row(row);
    }
    let generation = delta.projection_generation;
    let update = ProjectionDelta {
        base_cursor: U64::new(delta.base_cursor),
        next_cursor: U64::new(delta.next_cursor),
        projection_generation: U64::new(generation),
        buffer: wire::buffer(buffer),
        viewport: wire::viewport(viewport)?,
        rows,
        cursor: wire::cursor(delta.cursor),
        modes: delta.modes.iter().map(|entry| wire::mode(*entry)).collect(),
        margins: Nullable(delta.margins.map(wire::margins)),
        rendition: Nullable(delta.rendition.map(wire::rendition)),
        tab_stops: Nullable(
            delta
                .tab_stops
                .as_ref()
                .map(|stops| stops.iter().map(|at| wire::cells(*at)).collect()),
        ),
        charsets: Nullable(delta.charsets.as_ref().map(wire::charsets)),
        hyperlinks: wire::hyperlinks(&delta.hyperlinks)?,
        hyperlink: Nullable(delta.hyperlink.as_ref().map(|uri| {
            kr_protocol::projection::HyperlinkChange {
                uri: Nullable(uri.clone()),
            }
        })),
        title: Nullable(delta.title.as_ref().map(wire::title)),
        title_stack: Nullable(
            delta
                .title_stack
                .as_ref()
                .map(|stack| stack.iter().map(wire::saved_title).collect()),
        ),
        keyboard: Nullable(delta.keyboard.as_ref().map(wire::keyboard)),
        palette: Nullable(delta.palette.as_ref().map(wire::palette)),
        dimensions: Nullable(delta.dimensions.map(|size| {
            kr_protocol::session::Dimensions::new(u64::from(size.cols), u64::from(size.rows))
        })),
        saved_cursors: Nullable(delta.saved_cursors.as_ref().map(wire::saved_cursors)),
        oldest_retained_row: wire::row_id(oldest_retained_row)?,
        evicted,
        degraded,
    };
    // The whole message, measured, and not only its rows. A delta carries the state that changed
    // with them: a hyperlink change repeats its target, a title stack can hold twenty of them, and
    // a palette carries every override. Rows that fit a page say nothing about what the rest of the
    // message adds, and a message the transport refuses is a client that is told nothing at all.
    let Some(cost) = wire::measure(&update) else {
        return Ok(Owed::Snapshot(ProjectionResetReason::Repaint));
    };
    if !cost.fits(PAGE_BYTES, PAGE_ITEMS) {
        // Too large to be one bounded update. A snapshot pages, so it can carry what this cannot.
        return Ok(Owed::Snapshot(ProjectionResetReason::Repaint));
    }
    Ok(Owed::Update(Update {
        events: vec![Outgoing {
            event: ProjectionEvent::Delta(Box::new(update)),
            bytes: cost.bytes,
        }],
        base: Base {
            cursor: delta.next_cursor,
            generation,
        },
    }))
}

/// Whether a delta would change nothing a client is holding.
///
/// The cursor is not part of the question when the delta stands where the client already does:
/// nothing can have moved the cursor without a byte, a mode or a row, and every one of those is
/// checked here.
fn carries_nothing(delta: &Delta, viewport: Viewport, held: Option<Viewport>) -> bool {
    delta.next_cursor == delta.base_cursor
        && delta.rows.is_empty()
        && delta.modes.is_empty()
        && delta.hyperlinks.is_empty()
        && delta.margins.is_none()
        && delta.rendition.is_none()
        && delta.tab_stops.is_none()
        && delta.charsets.is_none()
        && delta.title.is_none()
        && delta.title_stack.is_none()
        && delta.keyboard.is_none()
        && delta.palette.is_none()
        && delta.dimensions.is_none()
        && delta.saved_cursors.is_none()
        && delta.hyperlink.is_none()
        && held == Some(viewport)
}

/// Builds the reset one attachment receives when its screen is no longer continuous.
#[must_use]
pub fn reset(generation: u64, cursor: u64, reason: ProjectionResetReason) -> ProjectionEvent {
    ProjectionEvent::Reset(ProjectionReset {
        projection_generation: U64::new(generation),
        cursor: U64::new(cursor),
        reason,
    })
}

/// Whether these rows fit one page under every bound.
fn fits_one_page(rows: &[ProjectedRow]) -> bool {
    if rows.len() as u64 > MAX_PROJECTION_PAGE_ROWS {
        return false;
    }
    let mut total = Cost::default();
    for row in rows {
        total.absorb(wire::row_cost(row));
    }
    total.fits(PAGE_BYTES, PAGE_ITEMS)
}

/// Splits rows into pages, each inside every bound.
///
/// A row larger than a whole page is still representable: it is cut to the bound and marked
/// truncated, because a reader that could never get past it would never see the rows after it.
fn paginate(rows: Vec<ProjectedRow>) -> Vec<Vec<ProjectedRow>> {
    let mut pages: Vec<Vec<ProjectedRow>> = Vec::new();
    let mut page: Vec<ProjectedRow> = Vec::new();
    let mut held = Cost::default();
    for mut row in rows {
        truncate_row(&mut row);
        let cost = wire::row_cost(&row);
        let mut with_it = held;
        with_it.absorb(cost);
        let full =
            page.len() as u64 >= MAX_PROJECTION_PAGE_ROWS || !with_it.fits(PAGE_BYTES, PAGE_ITEMS);
        if full && !page.is_empty() {
            pages.push(core::mem::take(&mut page));
            held = Cost::default();
        }
        held.absorb(cost);
        page.push(row);
    }
    if !page.is_empty() {
        pages.push(page);
    }
    pages
}

/// Cuts one row's runs to the page bounds, marking it truncated when anything was left out.
///
/// Both bounds, because a row of one run per cell reaches the codec's item limit while its bytes
/// are still well inside the frame.
fn truncate_row(row: &mut ProjectedRow) {
    truncate_row_to(row, PAGE_BYTES, PAGE_ITEMS);
}

/// Cuts one row to a bound of the caller's, marking it truncated when anything was given up.
///
/// The page bound is the usual one. A smaller one is what a subscriber's own send queue leaves for
/// each row of a screen it could not otherwise be sent at all: a client holding part of a screen
/// holds no screen, so a snapshot that does not fit is cut and said to be cut, rather than being
/// refused over and over.
fn truncate_row_to(row: &mut ProjectedRow, bytes: usize, items: usize) {
    if wire::row_cost(row).fits(bytes, items) {
        return;
    }
    let empty = ProjectedRow {
        row: row.row,
        soft_wrapped: row.soft_wrapped,
        truncated: true,
        runs: Vec::new(),
    };
    let envelope = wire::row_cost(&empty);
    let mut kept: Vec<kr_protocol::projection::CellRun> = Vec::new();
    let mut held = envelope;
    for run in core::mem::take(&mut row.runs) {
        let mut one = empty.clone();
        one.runs = vec![run.clone()];
        // What this run adds is what a row holding only it costs, less the row's own envelope,
        // which the running total already carries.
        let alone = wire::row_cost(&one);
        let mut with_it = held;
        with_it.absorb(Cost {
            bytes: alone.bytes.saturating_sub(envelope.bytes),
            items: alone.items.saturating_sub(envelope.items),
        });
        if !with_it.fits(bytes, items) {
            row.truncated = true;
            break;
        }
        held = with_it;
        kept.push(run);
    }
    row.runs = kept;
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::projection::{CellRendition, CellRun};

    fn row(id: u64, text: &str) -> ProjectedRow {
        ProjectedRow {
            row: U64::new(id),
            soft_wrapped: false,
            truncated: false,
            runs: vec![CellRun {
                column: U64::ZERO,
                cells: U64::new(text.chars().count() as u64),
                text: text.to_owned(),
                rendition: CellRendition::PLAIN,
                hyperlink: Nullable::null(),
            }],
        }
    }

    #[test]
    fn a_page_holds_at_most_the_row_bound() {
        let rows: Vec<ProjectedRow> = (0..2_500).map(|id| row(id, "x")).collect();
        let pages = paginate(rows);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[0].len(), MAX_PROJECTION_PAGE_ROWS as usize);
        assert_eq!(pages[1].len(), MAX_PROJECTION_PAGE_ROWS as usize);
        assert_eq!(pages[2].len(), 500);
    }

    /// Measures one page as the transport would carry it.
    fn framed(page: &[ProjectedRow]) -> Cost {
        wire::measure(&ProjectionRowPage {
            projection_generation: U64::new(1),
            output_cursor: U64::ZERO,
            buffer: ProjectedBuffer::Primary,
            rows: page.to_vec(),
            oldest_retained_row: U64::ZERO,
            evicted: false,
            more: true,
        })
        .expect("a page the codec can represent")
    }

    #[test]
    fn a_page_holds_at_most_the_byte_bound() {
        let wide = "y".repeat(200 * 1024);
        let rows: Vec<ProjectedRow> = (0..12).map(|id| row(id, &wide)).collect();
        let pages = paginate(rows);
        assert!(
            pages.len() > 1,
            "twelve rows of 200 KiB do not fit one page"
        );
        for page in &pages {
            // The page as one message, which is what the transport carries and what it refuses.
            let cost = framed(page);
            assert!(
                cost.bytes <= kr_protocol::limits::MAX_CONTROL_FRAME_LEN,
                "a page fits one control frame: {cost:?}"
            );
            assert!(cost.items <= 65_536, "and the codec's item limit: {cost:?}");
        }
    }

    /// KR-REQ-08.83: a page of one run per cell reaches the value bound long before the byte one.
    #[test]
    fn a_page_holds_at_most_the_value_bound() {
        // Twenty rows of 120 columns, every cell its own run, which is what alternating attributes
        // produce. Their bytes are well inside one frame; their values are not, and a bound counted
        // in bytes alone would put them all in one page.
        let cell = |column: u64| CellRun {
            column: U64::new(column),
            cells: U64::new(1),
            text: "x".to_owned(),
            rendition: CellRendition::PLAIN,
            hyperlink: Nullable::null(),
        };
        let rows: Vec<ProjectedRow> = (0..20)
            .map(|id| ProjectedRow {
                row: U64::new(id),
                soft_wrapped: false,
                truncated: false,
                runs: (0..120).map(cell).collect(),
            })
            .collect();
        let bytes: usize = rows.iter().map(|row| wire::row_cost(row).bytes).sum();
        let items: usize = rows.iter().map(|row| wire::row_cost(row).items).sum();
        assert!(
            bytes < PAGE_BYTES,
            "all twenty rows are inside the byte bound: {bytes} bytes"
        );
        assert!(
            items > PAGE_ITEMS,
            "and outside the value bound: {items} values"
        );
        let pages = paginate(rows);
        assert!(
            pages.len() > 1,
            "and are still more than one page, because the values are what bind"
        );
        for page in &pages {
            let cost = framed(page);
            assert!(cost.items <= 65_536, "each page is decodable: {cost:?}");
            assert!(
                cost.bytes <= kr_protocol::limits::MAX_CONTROL_FRAME_LEN,
                "and carryable: {cost:?}"
            );
        }
    }

    #[test]
    fn one_row_larger_than_a_page_is_degraded_explicitly_rather_than_dropped() {
        let enormous = "z".repeat(2 * MAX_PROJECTION_PAGE_BYTES as usize);
        let pages = paginate(vec![row(7, &enormous)]);
        assert_eq!(pages.len(), 1);
        let row = &pages[0][0];
        assert!(row.truncated, "the row says it is not all of the row");
        assert!(
            row.runs.is_empty(),
            "the run that could not fit was left out"
        );
        assert_eq!(row.row.get(), 7, "and it is still the row it was");
    }

    #[test]
    fn a_base_is_a_cursor_and_a_generation_together() {
        let mut bases = Bases::new();
        let id = AttachmentId::new(kr_protocol::scalars::Uuid::from_bytes([3; 16]));
        assert!(bases.held(id).is_none());
        let window = Viewport {
            top_row: 0,
            rows: 4,
            left_col: 0,
            cols: 8,
        };
        bases.record(
            id,
            Held {
                base: Base {
                    cursor: 12,
                    generation: 4,
                },
                viewport: window,
            },
        );
        assert_eq!(
            bases.held(id).map(|held| held.base),
            Some(Base {
                cursor: 12,
                generation: 4
            })
        );
        assert_eq!(bases.held(id).map(|held| held.viewport), Some(window));
        bases.forget_all();
        assert!(bases.is_empty());
    }

    /// KR-REQ-08.83: a delta is measured whole, not by its rows.
    ///
    /// A delta carries the state that changed with the rows, and a hyperlink change repeats its
    /// target for every range. Six rows fit any page; six rows plus six hundred long targets fit no
    /// frame at all, and a message the transport refuses leaves a client holding nothing.
    #[test]
    fn a_delta_whose_state_does_not_fit_a_frame_asks_for_a_snapshot() {
        let rows: Vec<kr_term::grid::GridRow> = (0..6)
            .map(|id| kr_term::grid::GridRow {
                stable_id: id,
                soft_wrapped: false,
                truncated: false,
                runs: Vec::new(),
            })
            .collect();
        let target: String = std::iter::repeat_n('u', 1_900).collect();
        let hyperlinks: Vec<kr_term::snapshot::HyperlinkRange> = (0..600)
            .map(|index| kr_term::snapshot::HyperlinkRange {
                row: index % 6,
                start_col: 0,
                end_col: 1,
                uri: format!("https://example.invalid/{index}/{target}"),
            })
            .collect();
        let window = Viewport {
            top_row: 0,
            rows: 6,
            left_col: 0,
            cols: 80,
        };
        let delta = Delta {
            base_cursor: 0,
            next_cursor: 1,
            projection_generation: 1,
            rows,
            cursor: kr_term::snapshot::CursorState {
                col: 0,
                row: 0,
                visible: true,
                style: 1,
                pending_wrap: false,
            },
            modes: Vec::new(),
            margins: None,
            rendition: None,
            tab_stops: None,
            charsets: None,
            hyperlinks,
            title: None,
            keyboard: None,
            palette: None,
            dimensions: None,
            title_stack: None,
            saved_cursors: None,
            hyperlink: None,
        };
        assert_eq!(
            advance(
                &delta,
                ActiveBuffer::Primary,
                window,
                0,
                false,
                false,
                Some(window)
            )
            .expect("an answer"),
            Owed::Snapshot(ProjectionResetReason::Repaint),
            "the rows fit a page and the message does not, so the client is sent a fresh screen"
        );
    }

    /// KR-REQ-08.83: a change larger than one bounded update is a repaint, and pages.
    #[test]
    fn a_change_larger_than_one_bounded_update_asks_for_a_snapshot() {
        let rows: Vec<kr_term::grid::GridRow> = (0..=MAX_PROJECTION_PAGE_ROWS)
            .map(|id| kr_term::grid::GridRow {
                stable_id: i64::try_from(id).expect("a row"),
                soft_wrapped: false,
                truncated: false,
                runs: Vec::new(),
            })
            .collect();
        let window = Viewport {
            top_row: 0,
            rows: 4,
            left_col: 0,
            cols: 8,
        };
        let delta = Delta {
            base_cursor: 0,
            next_cursor: 1,
            projection_generation: 1,
            rows,
            cursor: kr_term::snapshot::CursorState {
                col: 0,
                row: 0,
                visible: true,
                style: 1,
                pending_wrap: false,
            },
            modes: Vec::new(),
            margins: None,
            rendition: None,
            tab_stops: None,
            charsets: None,
            hyperlinks: Vec::new(),
            title: None,
            keyboard: None,
            palette: None,
            dimensions: None,
            title_stack: None,
            saved_cursors: None,
            hyperlink: None,
        };
        assert_eq!(
            advance(
                &delta,
                ActiveBuffer::Primary,
                window,
                0,
                false,
                false,
                Some(window)
            )
            .expect("an answer"),
            Owed::Snapshot(ProjectionResetReason::Repaint),
            "one message larger than a page bound is not an update"
        );
    }

    #[test]
    fn a_palette_choice_records_where_the_colours_came_from() {
        assert_eq!(
            PaletteChoice::ProfileDefault.palette().source(),
            PaletteSource::ProfileDefault
        );
        assert_eq!(
            PaletteChoice::DarkPreset.palette().source(),
            PaletteSource::DarkPreset
        );
        let shared = PaletteChoice::Shared {
            foreground: Rgb::new(1, 2, 3),
            background: Rgb::new(4, 5, 6),
        }
        .palette();
        assert_eq!(shared.source(), PaletteSource::ClientPreference);
        assert_eq!(
            shared.dynamic(kr_term::palette::DynamicColour::Foreground),
            Rgb::new(1, 2, 3)
        );
    }
}
