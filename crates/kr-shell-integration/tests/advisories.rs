//! The check that reads what the shells' upstreams publish, put through what it must refuse.
//!
//! `scripts/check-shell-advisories.py` fails a change an upstream published that the triage
//! register has no row for. It reads public sources, so it cannot be run against them in a test;
//! its `self-test` command runs it against recorded answers of the real sources and against the
//! ranges and spellings it must read correctly. This file runs that command on every Unix host that
//! runs the workspace's tests, so the requirement it serves is held there and not only in the one
//! job that names it.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

/// KR-REQ-07.88: the check that holds the register against the upstream advisories reads a range
/// the way the advisory's source writes it: a bare pre-release with a number is a version and not a
/// span, and the words of a pre-release are ordered both by their codes and without regard to
/// case. The command exits non-zero at the first range it reads wrongly, naming it.
#[test]
fn the_advisories_check_reads_the_ranges_the_sources_publish() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let output = Command::new("python3")
        .arg(root.join("scripts/check-shell-advisories.py"))
        .arg("self-test")
        .output()
        .expect("python3 runs the advisories check");
    assert!(
        output.status.success(),
        "the advisories check failed its self-test: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
