//! The standing function takes the locks the roster lists and no other.
//!
//! `standing_takes.txt` lists, against the source of this crate, every take of a lock inside the
//! functions of the standing function and the pure readers it uses, by file, function and callee,
//! with how many there are. A take with no row, a row with no take, a different number of takes, a
//! scope row with no function and a row outside the scope each fail the case. The reader of source
//! text, and what it does not see, is in `standing_scan/mod.rs`: it does not follow a call into
//! another function, so a function that a scoped one calls is read only when it is in the scope.
//!
//! The cases after the first plant a take in a function that may take none, and show the scan
//! reporting it.

#[path = "standing_scan/mod.rs"]
mod scan;

/// The names of the calls that take a lock: the lock itself, a try, and the three functions of
/// this crate that return a held guard.
const TAKES: &[&str] = &["lock", "try_lock", "session", "state", "locked"];

fn roster() -> scan::Roster {
    scan::parse(include_str!("standing_takes.txt"))
}

#[test]
fn the_standing_function_takes_the_locks_the_roster_lists_and_no_other() {
    let violations = scan::violations(&scan::tree(), &roster(), TAKES);
    assert_eq!(
        violations,
        Vec::<String>::new(),
        "the standing function's takes differ from standing_takes.txt"
    );
}

/// The real tree, with `before` replaced by `after` in the file `file`.
fn planted(file: &str, before: &str, after: &str) -> Vec<String> {
    let mut files = scan::tree();
    let (_, source) = files
        .iter_mut()
        .find(|(name, _)| name == file)
        .expect("the file is in the tree");
    assert_eq!(source.matches(before).count(), 1, "{before}");
    *source = source.replace(before, after);
    scan::violations(&files, &roster(), TAKES)
}

#[test]
fn a_take_planted_in_the_pure_wall_reader_is_reported() {
    let found = planted(
        "crates/kr-worker/src/action/time.rs",
        "        self.wall.now_ms().get()\n    }",
        "        let _held = self.readings.lock();\n        self.wall.now_ms().get()\n    }",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("action/time.rs pure_wall_ms calls lock 1 time(s)"),
        "{found:?}"
    );
}

#[test]
fn a_take_planted_in_a_piece_of_the_pass_is_reported() {
    let found = planted(
        "crates/kr-worker/src/service/standing.rs",
        "        self.service.check_envelope(mutation, entry, caller)",
        "        let _held = self.service.runtime.session();\n        self.service.check_envelope(mutation, entry, caller)",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("service/standing.rs envelope calls session 1 time(s)"),
        "{found:?}"
    );
}

#[test]
fn a_take_that_a_row_lists_and_the_source_lacks_is_reported() {
    let mut files = scan::tree();
    let (_, source) = files
        .iter_mut()
        .find(|(name, _)| name == "crates/kr-worker/src/local_gate.rs")
        .expect("the gate");
    let before = "        let bound = self.lock().bound;\n        match bound {\n            Bound::Open => Ok(()),";
    assert_eq!(source.matches(before).count(), 1);
    *source = source.replace(
        before,
        "        let bound = Bound::Open;\n        match bound {\n            Bound::Open => Ok(()),",
    );
    let found = scan::violations(&files, &roster(), TAKES);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("local_gate.rs check_bound lock: the call is not there"),
        "{found:?}"
    );
}
