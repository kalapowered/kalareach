//! The benchmark tool prints the qualification matrix and fails while a required case has nothing
//! run behind it, so a reference run reads which targets must still qualify instead of finding the
//! record only in the library.

use std::process::Command;

use kr_describe::qualification::{Case, Evidence, Matrix, REQUIRED_TARGETS};

fn matrix_run() -> (std::process::ExitStatus, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_kr-describe-bench"))
        .arg("--matrix")
        .output()
        .expect("the benchmark tool starts");
    (
        output.status,
        String::from_utf8(output.stdout).expect("the matrix is text"),
    )
}

/// KR-PERF-009: every case of the matrix is printed with what stands behind it and the targets it
/// still lacks, and the tool's exit status is a failure while any case is not run.
#[test]
fn the_matrix_is_printed_and_the_tool_fails_while_a_required_case_is_not_run() {
    let matrix = Matrix::builtin();
    let (status, printed) = matrix_run();

    for case in Case::ALL {
        assert!(
            printed.lines().any(|line| line.starts_with(case.as_str())),
            "the matrix lists {}:\n{printed}",
            case.as_str()
        );
    }
    for row in matrix.rows() {
        if let Evidence::NotRun { owner } = row.evidence {
            let line = printed
                .lines()
                .find(|line| line.starts_with(row.case.as_str()))
                .expect("the row is listed");
            assert!(
                line.contains("not run") && line.contains(owner),
                "a case nothing has run says who runs it: {line}"
            );
        }
    }
    for (case, target) in matrix.gaps() {
        assert!(
            printed
                .lines()
                .any(|line| line.contains(case.as_str()) && line.contains(target)),
            "the gap of {} on {target} is printed:\n{printed}",
            case.as_str()
        );
    }
    assert!(
        REQUIRED_TARGETS
            .iter()
            .all(|target| printed.contains(target)),
        "every required target is named:\n{printed}"
    );

    let waiting = matrix
        .rows()
        .iter()
        .any(|row| matches!(row.evidence, Evidence::NotRun { .. }));
    assert_eq!(
        status.code(),
        Some(i32::from(waiting)),
        "the exit status is 1 exactly while a case is not run:\n{printed}"
    );
}
