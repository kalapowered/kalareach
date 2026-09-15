//! Geometry validation, admission, and the resident-state budgets.
//!
//! Three rules from section 8 meet here. Geometry is validated against three constraints that
//! apply at the same time, with checked multiplication, *before* anything is allocated. A geometry
//! that passes them is then admitted against the session budget: what both screen buffers can hold
//! at that size is reserved before the grid is built, so a session that has been admitted can fill
//! its screens without ever being refused. And the historical row cache is bounded separately, as
//! a cache of rows the spool still has.
//!
//! Every bound is checked before the allocation, not after it. A refusal names the bound it hit.

use crate::error::{Result, TermError};
use crate::grid::{
    ALERT_LIST_BYTES, CELL_ATTRIBUTE_BYTES, CELL_TEXT_HEAP_BYTES, LINK_TABLE_ENTRY_BYTES,
    LINK_TABLE_NODE_BYTES, ROW_SLOT_BYTES, STRING_HANDLE_BYTES,
};

/// The maximum number of columns.
pub const MAX_COLS: u32 = 2_048;
/// The maximum number of rows.
pub const MAX_ROWS: u32 = 1_024;
/// The maximum number of cells, which the independent maxima can exceed together.
pub const MAX_CELLS: u32 = 262_144;

/// The size an invisible session starts at.
pub const DEFAULT_SIZE: GridSize = GridSize {
    cols: 120,
    rows: 40,
};

/// Canonical grid dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridSize {
    /// Columns.
    pub cols: u32,
    /// Rows.
    pub rows: u32,
}

impl GridSize {
    /// Builds a size without validating it.
    #[must_use]
    pub const fn new(cols: u32, rows: u32) -> Self {
        Self { cols, rows }
    }

    /// Checks all three constraints at once.
    ///
    /// The independent maxima are not valid together, which is the whole point of the third
    /// constraint: 2,048 columns and 1,024 rows are each allowed, and 2,048 by 1,024 is not.
    ///
    /// # Errors
    ///
    /// Returns [`TermError::Geometry`] naming the first constraint that fails.
    pub const fn validate(self) -> Result<Self> {
        if self.cols == 0 || self.cols > MAX_COLS {
            return Err(self.violation("columns"));
        }
        if self.rows == 0 || self.rows > MAX_ROWS {
            return Err(self.violation("rows"));
        }
        let Some(cells) = self.cols.checked_mul(self.rows) else {
            return Err(self.violation("cells"));
        };
        if cells > MAX_CELLS {
            return Err(self.violation("cells"));
        }
        Ok(self)
    }

    const fn violation(self, violated: &'static str) -> TermError {
        TermError::Geometry {
            cols: self.cols,
            rows: self.rows,
            violated,
            max_cols: MAX_COLS,
            max_rows: MAX_ROWS,
            max_cells: MAX_CELLS,
        }
    }

    /// The number of cells, when the size is valid.
    #[must_use]
    pub const fn cells(self) -> Option<u32> {
        self.cols.checked_mul(self.rows)
    }
}

/// The resident-state bounds one session works inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetLimits {
    /// Bytes of in-memory historical rows. Older rows come from the spool, and this cache is
    /// bounded on its own rather than out of the session budget.
    pub row_cache_bytes: u64,
    /// Bytes for the canonical screens, attributes, hyperlink and title tables, and per-cell
    /// storage, together.
    pub session_bytes: u64,
    /// Distinct hyperlink targets one session keeps resident.
    pub unique_links: usize,
    /// Bytes one hyperlink may hold, parameters and target together.
    pub link_bytes: usize,
    /// Rows in one history page.
    pub history_page_rows: usize,
    /// Bytes in one history page.
    pub history_page_bytes: usize,
}

impl BudgetLimits {
    /// The section 8 bounds: an 8 MiB row cache beside a 64 MiB session budget, and history pages
    /// of at most 1,000 rows and 1 MiB.
    pub const DEFAULT: Self = Self {
        row_cache_bytes: 8 * 1024 * 1024,
        session_bytes: 64 * 1024 * 1024,
        unique_links: 4_096,
        link_bytes: 2_048,
        history_page_rows: 1_000,
        history_page_bytes: 1024 * 1024,
    };

    /// What the hyperlink state may hold: the table of distinct targets at its full size, and the
    /// link objects the rows of both screens share.
    ///
    /// One envelope for both, because they hold the same thing from two directions: the table
    /// keeps one string per distinct target, and a row keeps one object per link an application
    /// opened. A session that has been admitted can use all of it, and a hyperlink that would pass
    /// it is refused rather than allowed to eat the screens' room.
    #[must_use]
    pub const fn link_envelope(&self) -> u64 {
        // A target is held in a string that was built by appending, so it can be holding twice the
        // bytes it shows, and the entry carries the slot and the room beside it in the table node.
        let entry = 2 * self.link_bytes as u64 + STRING_HANDLE_BYTES + LINK_TABLE_ENTRY_BYTES;
        (self.unique_links as u64).saturating_mul(entry) + LINK_TABLE_NODE_BYTES
    }
}

impl Default for BudgetLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Bytes one cell of one screen buffer costs in the row it sits in.
///
/// The row holds either a vector of cells or a string with a run of attributes beside it, and both
/// are built by appending, so the figure covers twice the larger of the two.
pub const CELL_OVERHEAD_BYTES: u64 = 64;

/// What one cell of one buffer can hold beyond its slot in the row.
///
/// Its text at twice the bytes a cell may carry, because a row grows its string by appending; the
/// allocation the grid makes for the attributes the packed form on the cell cannot hold; and the
/// header a cell's text keeps once it is too long to live inside the cell.
#[must_use]
pub const fn cell_content_bytes(cell_bytes: u64) -> u64 {
    2 * cell_bytes + CELL_ATTRIBUTE_BYTES + CELL_TEXT_HEAP_BYTES
}

/// The worst-case resident footprint of one geometry.
///
/// Section 8 asks for rejection before a state allocation that cannot fit. The allocation that
/// matters is the screen: text arriving for a screen cannot be refused without stopping a session
/// from drawing, so what the screens can come to is reserved when the geometry is admitted, and
/// everything printed afterwards is already paid for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Footprint {
    /// The cells of both buffers, at the slot each one takes in its row.
    pub cell_slots: u64,
    /// What the cells of both buffers can hold: text, attribute allocations and text headers.
    pub cell_content: u64,
    /// The arrays the rows of both buffers sit in, the scrollback slots included.
    pub row_arrays: u64,
    /// The hyperlink envelope: the table of distinct targets and the objects the rows hold.
    pub links: u64,
    /// The titles and the virtual stack, at their bounds.
    pub titles: u64,
    /// The alert channel, at its bound.
    pub alerts: u64,
}

impl Footprint {
    /// Bytes of the session budget this footprint needs.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.cell_slots
            .saturating_add(self.cell_content)
            .saturating_add(self.row_arrays)
            .saturating_add(self.links)
            .saturating_add(self.titles)
            .saturating_add(self.alerts)
    }
}

/// What the session is measured to be holding inside its reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BudgetUsage {
    /// Bytes each buffer's rows hold beyond their cell slots, primary first.
    ///
    /// Both, because the buffer that is not showing still holds its own.
    pub screen_content: [u64; 2],
    /// Bytes the hyperlink state holds: the objects the rows of both buffers keep, the link the
    /// pen is inside, the links the saved cursors carry, and the table of distinct targets.
    pub links: u64,
    /// Bytes the titles and the virtual stack hold.
    pub titles: u64,
    /// Bytes the historical row cache holds, against its own bound.
    pub rows: u64,
}

impl BudgetUsage {
    /// What the two buffers' rows hold, together.
    #[must_use]
    pub const fn screens(self) -> u64 {
        self.screen_content[0].saturating_add(self.screen_content[1])
    }
}

/// The session's resource budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBudget {
    limits: BudgetLimits,
    reserved: Footprint,
    usage: BudgetUsage,
    truncations: u64,
}

impl SessionBudget {
    /// Builds a budget with the section 8 bounds and nothing admitted yet.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limits(BudgetLimits::DEFAULT)
    }

    /// Builds a budget with explicit bounds.
    #[must_use]
    pub const fn with_limits(limits: BudgetLimits) -> Self {
        Self {
            limits,
            reserved: Footprint {
                cell_slots: 0,
                cell_content: 0,
                row_arrays: 0,
                links: 0,
                titles: 0,
                alerts: 0,
            },
            usage: BudgetUsage {
                screen_content: [0, 0],
                links: 0,
                titles: 0,
                rows: 0,
            },
            truncations: 0,
        }
    }

    /// The bounds in force.
    #[must_use]
    pub const fn limits(&self) -> BudgetLimits {
        self.limits
    }

    /// What the admitted geometry reserved.
    #[must_use]
    pub const fn reserved(&self) -> Footprint {
        self.reserved
    }

    /// What the last measurement found inside that reservation.
    #[must_use]
    pub const fn usage(&self) -> BudgetUsage {
        self.usage
    }

    /// How many times content has been truncated to stay inside a bound.
    #[must_use]
    pub const fn truncations(&self) -> u64 {
        self.truncations
    }

    /// Records one truncation.
    pub const fn record_truncation(&mut self) {
        self.truncations = self.truncations.saturating_add(1);
    }

    /// The worst-case footprint of `size`, with `scrollback_rows` of history and `cell_bytes` of
    /// content in a cell.
    ///
    /// Both buffers, because a session can fill the primary one, switch, and fill the alternate as
    /// well. The scrollback slots are in it because the rows of the history sit in the same array
    /// as the rows of the screen; what those rows *hold* is the row cache's own bound.
    #[must_use]
    pub const fn footprint(
        &self,
        size: GridSize,
        scrollback_rows: usize,
        cell_bytes: u64,
    ) -> Footprint {
        let cells = (size.cols as u64).saturating_mul(size.rows as u64);
        let rows = size.rows as u64;
        Footprint {
            cell_slots: 2u64
                .saturating_mul(cells)
                .saturating_mul(CELL_OVERHEAD_BYTES),
            cell_content: 2u64
                .saturating_mul(cells)
                .saturating_mul(cell_content_bytes(cell_bytes)),
            // The primary buffer's array holds the screen and the history; the alternate buffer
            // keeps no history.
            row_arrays: rows
                .saturating_add(scrollback_rows as u64)
                .saturating_add(rows)
                .saturating_mul(ROW_SLOT_BYTES),
            links: self.limits.link_envelope(),
            titles: crate::title::MAX_RESIDENT_BYTES,
            alerts: ALERT_LIST_BYTES,
        }
    }

    /// Admits a geometry, or refuses it because its footprint does not fit the session budget.
    ///
    /// Nothing is committed here: the caller applies the geometry and then commits the footprint
    /// it was given, so a refusal leaves the current grid and the current reservation alone.
    ///
    /// # Errors
    ///
    /// Returns [`TermError::Admission`] naming the cells that were asked for, what they would
    /// cost and the budget.
    pub const fn check_geometry(
        &self,
        size: GridSize,
        scrollback_rows: usize,
        cell_bytes: u64,
    ) -> Result<Footprint> {
        let footprint = self.footprint(size, scrollback_rows, cell_bytes);
        let needed = footprint.total();
        if needed > self.limits.session_bytes {
            return Err(TermError::Admission {
                cols: size.cols,
                rows: size.rows,
                cells: (size.cols as u64).saturating_mul(size.rows as u64),
                footprint: needed,
                budget: self.limits.session_bytes,
            });
        }
        Ok(footprint)
    }

    /// Commits a footprint that has been admitted.
    ///
    /// The new reservation replaces the old one: the geometry it was made for is gone.
    pub const fn commit_geometry(&mut self, footprint: Footprint) {
        self.reserved = footprint;
    }

    /// Bytes of the session budget the session is holding.
    ///
    /// The reservation, plus anything a measurement found beyond what was reserved for it. The
    /// second term is zero while the model reserves at or above the truth, and reporting it is how
    /// a session that found otherwise says so.
    #[must_use]
    pub const fn committed(&self) -> u64 {
        self.reserved.total().saturating_add(self.excess())
    }

    /// What the measurements found beyond their reservations.
    #[must_use]
    pub const fn excess(&self) -> u64 {
        over(self.usage.screens(), self.reserved.cell_content)
            .saturating_add(over(self.usage.links, self.reserved.links))
            .saturating_add(over(self.usage.titles, self.reserved.titles))
    }

    /// Whether committed usage is over the session budget.
    #[must_use]
    pub const fn session_over_budget(&self) -> bool {
        self.committed() > self.limits.session_bytes
    }

    /// Records the measured size of the historical row cache.
    ///
    /// The figure recorded is what the rows actually cost, not the bound. Recording the bound
    /// instead would make a session that is over its cache look exactly like one that is at it,
    /// and the reading that matters most is the one taken while the cache is too big.
    ///
    /// Returns whether the measurement is over the cache bound.
    pub const fn set_row_cache(&mut self, bytes: u64) -> bool {
        self.usage.rows = bytes;
        bytes > self.limits.row_cache_bytes
    }

    /// Charges rows that have just joined the historical cache.
    ///
    /// The cache is a byte bound, and two rows can carry more than the whole of it, so what they
    /// cost is charged where they join rather than at the next measurement.
    pub const fn add_row_cache(&mut self, bytes: u64) {
        self.usage.rows = self.usage.rows.saturating_add(bytes);
    }

    /// Whether the historical row cache is over its bound.
    #[must_use]
    pub const fn row_cache_over_budget(&self) -> bool {
        self.usage.rows > self.limits.row_cache_bytes
    }

    /// Records what one buffer's rows hold beyond their cell slots.
    pub const fn set_screen_content(&mut self, alternate: bool, bytes: u64) {
        self.usage.screen_content[alternate as usize] = bytes;
    }

    /// Records what the titles and the virtual stack hold.
    pub const fn set_titles(&mut self, bytes: u64) {
        self.usage.titles = bytes;
    }

    /// Records what the hyperlink state holds.
    pub const fn set_links(&mut self, bytes: u64) {
        self.usage.links = bytes;
    }

    /// Adds the cost of a hyperlink that has just been admitted.
    ///
    /// Admission cannot wait for the next measurement: one read can carry a session's worth of
    /// links, and a bound that is only checked afterwards is not a bound.
    pub const fn add_links(&mut self, bytes: u64) {
        self.usage.links = self.usage.links.saturating_add(bytes);
    }

    /// Gives back what was reserved for a hyperlink that was refused after all.
    pub const fn release_links(&mut self, bytes: u64) {
        self.usage.links = self.usage.links.saturating_sub(bytes);
    }

    /// Whether another `bytes` of hyperlink state would fit the envelope.
    #[must_use]
    pub const fn links_fit(&self, bytes: u64) -> bool {
        self.usage.links.saturating_add(bytes) <= self.reserved.links
    }

    /// Clears the measurements a reset made stale, after it emptied both buffers.
    pub const fn clear_measurements(&mut self) {
        self.usage.screen_content = [0, 0];
        self.usage.links = 0;
        self.usage.titles = 0;
    }
}

/// How far `measured` is past `reserved`.
const fn over(measured: u64, reserved: u64) -> u64 {
    measured.saturating_sub(reserved)
}

impl Default for SessionBudget {
    fn default() -> Self {
        Self::new()
    }
}
