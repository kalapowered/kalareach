//! The broker's journal of each invocation. Its records are framed by [`framing`]; [`rows`] says what
//! a record means, [`replay`] reads a file back and refuses rows that come in the wrong order, and
//! the file that holds them, written through, is in `win::journal`.

pub mod framing;
pub mod limits;
pub mod replay;
pub mod rows;
