//! The version that the installation records for Git is what a successful `git --version` run
//! wrote: one line, `git version` and a number. A run that failed reports none, whatever it wrote.

use kr_boundary_windows::manifest::git_version;

#[test]
fn a_successful_run_that_wrote_the_one_line_reports_its_version() {
    assert_eq!(
        git_version(true, b"git version 2.47.1.windows.2\n").as_deref(),
        Some("git version 2.47.1.windows.2")
    );
    assert_eq!(
        git_version(true, b"git version 2.47.1.windows.2\r\n").as_deref(),
        Some("git version 2.47.1.windows.2")
    );
}

#[test]
fn a_run_that_failed_reports_no_version_even_when_it_wrote_the_line() {
    assert_eq!(git_version(false, b"git version 2.47.1.windows.2\n"), None);
}

#[test]
fn a_run_that_wrote_anything_else_reports_no_version() {
    for text in [
        &b""[..],
        b"fatal: not a git repository\n",
        b"git version \n",
        b"git version unknown\n",
        b"git version 2.47.1\nwarning: something else\n",
        b"not git version 2.47.1\n",
        b"2.47.1\n",
    ] {
        assert_eq!(git_version(true, text), None, "{text:?}");
    }
}
