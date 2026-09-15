//! Geometry validation and the resident-state budgets.
//!
//! Two rules from section 8 meet here. Geometry is validated against three constraints that apply
//! at the same time, with checked multiplication, *before* anything is allocated. And resident
//! terminal state is bounded independently of what is on disk, so a session cannot grow without
//! bound because an application kept emitting combining characters or hyperlinks.
//!
//! Every bound is checked before the allocation, not after it. A refusal names the bound it hit.

use crate::error::{Result, TermError};

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
    /// Bytes of in-memory historical rows. Older rows come from the spool.
    pub row_cache_bytes: u64,
    /// Bytes for the canonical screens, attributes, hyperlink and title tables, and per-cell
    /// storage, together.
    pub session_bytes: u64,
    /// Bytes of encoded content one cell may hold.
    pub cell_bytes: u64,
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
    /// The section 8 bounds: an 8 MiB row cache inside a 64 MiB session budget, and history pages
    /// of at most 1,000 rows and 1 MiB.
    pub const DEFAULT: Self = Self {
        row_cache_bytes: 8 * 1024 * 1024,
        session_bytes: 64 * 1024 * 1024,
        cell_bytes: 64,
        unique_links: 4_096,
        link_bytes: 2_048,
        history_page_rows: 1_000,
        history_page_bytes: 1024 * 1024,
    };
}

impl Default for BudgetLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How many bytes of the session budget each part is using.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BudgetUsage {
    /// Bytes held by the two screen buffers.
    pub screens: u64,
    /// Bytes held by the historical row cache.
    pub rows: u64,
    /// Bytes held by the hyperlink and title tables.
    pub metadata: u64,
    /// Bytes of encoded content each buffer's rows hold beyond the fixed per-cell cost, primary
    /// first.
    pub screen_content: [u64; 2],
    /// Bytes held by the hyperlinks of each buffer's rows, primary first.
    ///
    /// Both, because the buffer that is not showing still holds its links: charging only the active
    /// one would let a session fill the primary buffer, switch, and fill the alternate as well.
    pub screen_links: [u64; 2],
}

impl BudgetUsage {
    /// Total committed bytes.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.screens
            + self.rows
            + self.metadata
            + self.screen_content[0]
            + self.screen_content[1]
            + self.screen_links[0]
            + self.screen_links[1]
    }
}

/// The session's resource budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionBudget {
    limits: BudgetLimits,
    usage: BudgetUsage,
    truncations: u64,
}

/// Bytes one cell costs in the canonical grid, before its own encoded content.
///
/// Used to decide whether a geometry change fits, before it is applied. The figure counts the
/// scalar, the attribute set and the per-cell bookkeeping the pinned grid library keeps.
pub const CELL_OVERHEAD_BYTES: u64 = 64;

impl SessionBudget {
    /// Builds a budget with the section 8 bounds.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_limits(BudgetLimits::DEFAULT)
    }

    /// Builds a budget with explicit bounds.
    #[must_use]
    pub const fn with_limits(limits: BudgetLimits) -> Self {
        Self {
            limits,
            usage: BudgetUsage {
                screens: 0,
                rows: 0,
                metadata: 0,
                screen_content: [0, 0],
                screen_links: [0, 0],
            },
            truncations: 0,
        }
    }

    /// The bounds in force.
    #[must_use]
    pub const fn limits(&self) -> BudgetLimits {
        self.limits
    }

    /// What is committed now.
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

    /// What two screen buffers of `size` cost.
    #[must_use]
    pub const fn screens_cost(size: GridSize) -> u64 {
        // Two buffers: primary and alternate.
        (size.cols as u64) * (size.rows as u64) * CELL_OVERHEAD_BYTES * 2
    }

    /// Checks that a geometry change fits before applying it.
    ///
    /// # Errors
    ///
    /// Returns [`TermError::Budget`] when the new screens would not fit alongside what is already
    /// committed.
    pub const fn check_geometry(&self, size: GridSize) -> Result<u64> {
        let cost = Self::screens_cost(size);
        let other = self.usage.rows
            + self.usage.metadata
            + self.usage.screen_content[0]
            + self.usage.screen_content[1]
            + self.usage.screen_links[0]
            + self.usage.screen_links[1];
        if cost + other > self.limits.session_bytes {
            return Err(TermError::Budget {
                what: "canonical screens",
                requested: cost,
                used: other,
                budget: self.limits.session_bytes,
            });
        }
        Ok(cost)
    }

    /// Commits the cost of a geometry change that has been checked.
    pub const fn commit_geometry(&mut self, cost: u64) {
        self.usage.screens = cost;
    }

    /// Records the measured size of the historical row cache.
    ///
    /// The figure recorded is what the rows actually cost, not the bound. Recording the bound
    /// instead would make a session that is over its cache look exactly like one that is at it,
    /// and the reading that matters most is the one taken while the cache is too big.
    ///
    /// Returns whether the measurement is over the cache bound. Eviction is not instant: the grid
    /// lowers its scrollback row count and the rows leave as later rows arrive, so the measurement
    /// falls back under the bound over the following rows rather than in one step.
    pub const fn set_row_cache(&mut self, bytes: u64) -> bool {
        self.usage.rows = bytes;
        bytes > self.limits.row_cache_bytes
    }

    /// Whether the historical row cache is over its bound.
    #[must_use]
    pub const fn row_cache_over_budget(&self) -> bool {
        self.usage.rows > self.limits.row_cache_bytes
    }

    /// Whether committed usage is over the session budget.
    #[must_use]
    pub const fn session_over_budget(&self) -> bool {
        self.usage.total() > self.limits.session_bytes
    }

    /// Records the current size of the hyperlink and title tables.
    pub const fn set_metadata(&mut self, bytes: u64) {
        self.usage.metadata = bytes;
    }

    /// Records what one buffer's content costs.
    pub const fn set_screen_content(&mut self, alternate: bool, bytes: u64) {
        self.usage.screen_content[alternate as usize] = bytes;
    }

    /// Clears the recorded content cost of both buffers, after a reset emptied them.
    pub const fn clear_screen_content(&mut self) {
        self.usage.screen_content = [0, 0];
    }

    /// Clears the recorded cost of both buffers' hyperlinks, after a reset emptied them.
    pub const fn clear_screen_links(&mut self) {
        self.usage.screen_links = [0, 0];
    }

    /// Gives back what was reserved for a link that was refused after all.
    pub const fn release_screen_links(&mut self, alternate: bool, bytes: u64) {
        let slot = alternate as usize;
        self.usage.screen_links[slot] = self.usage.screen_links[slot].saturating_sub(bytes);
    }

    /// Records what one buffer's hyperlinks cost.
    pub const fn set_screen_links(&mut self, alternate: bool, bytes: u64) {
        self.usage.screen_links[alternate as usize] = bytes;
    }

    /// Adds the cost of a link that has just been admitted.
    ///
    /// Admission cannot wait for the next measurement: one read can carry a session's worth of
    /// links, and a bound that is only checked afterwards is not a bound.
    pub const fn add_screen_links(&mut self, alternate: bool, bytes: u64) {
        let slot = alternate as usize;
        self.usage.screen_links[slot] = self.usage.screen_links[slot].saturating_add(bytes);
    }

    /// Whether another `bytes` of metadata would fit.
    #[must_use]
    pub const fn metadata_fits(&self, bytes: u64) -> bool {
        self.usage.total() + bytes <= self.limits.session_bytes
    }
}

impl Default for SessionBudget {
    fn default() -> Self {
        Self::new()
    }
}
