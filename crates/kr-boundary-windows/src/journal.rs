//! The broker's journal of each invocation. Its records are framed by [`framing`]; the rows they
//! carry and the file they are written to are other parts of this module.

pub mod framing;
