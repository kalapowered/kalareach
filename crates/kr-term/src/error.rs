//! Typed failures.
//!
//! Every variant names a rule from section 8 rather than a place in the code, so a caller can map
//! it to a protocol error and a person can read what went wrong.

/// A terminal engine failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TermError {
    /// Dimensions violated at least one of the three simultaneous geometry constraints.
    #[error(
        "geometry {cols}x{rows} violates {violated}: columns 1..={max_cols}, rows 1..={max_rows}, \
         cells 1..={max_cells}"
    )]
    Geometry {
        /// Requested columns.
        cols: u32,
        /// Requested rows.
        rows: u32,
        /// Which constraint failed first.
        violated: &'static str,
        /// The column bound.
        max_cols: u32,
        /// The row bound.
        max_rows: u32,
        /// The cell bound.
        max_cells: u32,
    },

    /// An allocation was refused before it happened because it did not fit the session budget.
    #[error(
        "{what} needs {requested} bytes; {used} of the {budget}-byte session budget is already \
         committed"
    )]
    Budget {
        /// What was being allocated.
        what: &'static str,
        /// Bytes the allocation needed.
        requested: u64,
        /// Bytes already committed.
        used: u64,
        /// The budget.
        budget: u64,
    },

    /// A colour specification was not one the profile accepts.
    #[error("colour specification {spec:?} is not a form kr-vt/1 accepts")]
    ColourSpec {
        /// The specification as it arrived.
        spec: String,
    },

    /// A probe handshake did not finish within its bound, or an answer never came.
    #[error("TERMINAL_PROBE_FAILED: {reason}")]
    ProbeFailed {
        /// What went wrong.
        reason: ProbeFailure,
    },

    /// A delta named a base cursor the engine is no longer holding.
    #[error("delta bases on cursor {requested} but the engine holds {available}")]
    CursorGap {
        /// The base cursor the client asked for.
        requested: u64,
        /// The oldest cursor the engine can still serve.
        available: u64,
    },

    /// A history page request was outside the retained range.
    #[error("history rows {from}..{to} are outside the retained range {oldest}..{newest}")]
    HistoryEvicted {
        /// First requested row.
        from: i64,
        /// One past the last requested row.
        to: i64,
        /// Oldest retained row.
        oldest: i64,
        /// One past the newest row.
        newest: i64,
    },

    /// An attachment cannot supply the keyboard encoding the application has negotiated.
    #[error(
        "INPUT_INCOMPATIBLE: the application negotiated {required}, the attachment offers {offered}"
    )]
    InputIncompatible {
        /// The encoding the application expects.
        required: String,
        /// The encoding the attachment can produce.
        offered: String,
    },
}

/// Why a probe handshake failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProbeFailure {
    /// The one-second bound passed before every requested answer arrived.
    #[error("the one-second bound passed with answers outstanding")]
    DeadlinePassed,
    /// The DA1 terminator never arrived, so late answers cannot be ruled out.
    #[error("the DA1 terminator never arrived")]
    NoTerminator,
    /// A question the probe asked went unanswered.
    #[error("a question the probe asked went unanswered")]
    MissingAnswer,
    /// An answer arrived that the probe did not ask for.
    #[error("an answer arrived that the probe did not ask for")]
    UnexpectedAnswer,
    /// An answer was malformed.
    #[error("an answer was malformed")]
    MalformedAnswer,
    /// A probe was attempted on an input stream that is not known to be clean.
    #[error("the outer terminal's input stream is not known to be clean")]
    ContaminatedInput,
}

/// A convenient result type.
pub type Result<T> = core::result::Result<T, TermError>;
