//! The qualification matrix as a reference run reads it.
//!
//! Every case section 22 names is printed with what stands behind it, the targets it has been
//! exercised on and what that evidence leaves out, and the case and target pairs nothing has
//! exercised follow. The tool fails while a case has nothing run behind it, or has no row at all,
//! so the matrix cannot be read as complete while a run is still owed.

use std::fmt::Write as _;

use kr_describe::qualification::{Evidence, Matrix, REQUIRED_TARGETS};

/// The printed matrix and whether every case has something run behind it.
pub struct Reading {
    /// The text a reference run prints.
    pub text: String,
    /// Whether no case is waiting for a run and none is missing a row.
    pub complete: bool,
}

/// Reads the matrix.
pub fn read(matrix: &Matrix) -> Reading {
    let mut text = String::new();
    let mut complete = true;
    let _ = writeln!(text, "# KR-PERF-009: the qualification matrix");
    let _ = writeln!(text, "required targets: {}", REQUIRED_TARGETS.join(", "));
    for row in matrix.rows() {
        let evidence = match row.evidence {
            Evidence::Test { name } => format!("test {name}"),
            Evidence::Benchmark { script } => format!("benchmark {script}"),
            Evidence::ReportedNotReproduced {
                reported_on,
                missing,
            } => format!("reported on {reported_on}, not reproduced, missing: {missing}"),
            Evidence::NotRun { owner } => {
                complete = false;
                format!("not run, owner {owner}")
            }
        };
        let _ = writeln!(
            text,
            "{}\t{evidence}\ttargets: {}\tnot covered: {}",
            row.case.as_str(),
            row.targets.join(", "),
            row.not_covered
        );
    }
    for (case, target) in matrix.gaps() {
        let _ = writeln!(text, "gap\t{}\t{target}", case.as_str());
    }
    for case in matrix.uncovered() {
        complete = false;
        let _ = writeln!(text, "no row\t{}", case.as_str());
    }
    Reading { text, complete }
}
