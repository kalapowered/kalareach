//! The standing function writes what the roster lists and nothing else.
//!
//! `standing_writes.txt` lists, against the source of this crate, every call of a name that
//! changes state that others read (a clock floor, a record, a journal, a question's ledger, an
//! atomic, a wake-up) inside the functions of the standing function and the pure readers it uses,
//! by file, function and callee, with how many there are. A write with no row, a row with no
//! write, a different number of writes, a scope row with no function and a row outside the scope
//! each fail the case. The reader of source text, and what it does not see, is in
//! `standing_scan/mod.rs`: it does not follow a call into another function, so a function that a
//! scoped one calls is read only when it is in the scope.
//!
//! The cases after the first plant a write in a function that may make none, and show the scan
//! reporting it.

#[path = "standing_scan/mod.rs"]
mod scan;

/// The names of the calls that change state which others read.
const WRITES: &[&str] = &[
    "raise",
    "owe",
    "keep",
    "note_journal_failure",
    "note_fenced",
    "sweep",
    "expire_due",
    "accept",
    "reject",
    "settle",
    "advance",
    "mark_dispatching_while",
    "commit_transition",
    "store",
    "fetch_add",
    "swap",
    "send",
    "notify_one",
    "notify_waiters",
    "show",
];

fn roster() -> scan::Roster {
    scan::parse(include_str!("standing_writes.txt"))
}

#[test]
fn the_standing_function_writes_what_the_roster_lists_and_nothing_else() {
    let violations = scan::violations(&scan::tree(), &roster(), WRITES);
    assert_eq!(
        violations,
        Vec::<String>::new(),
        "the standing function's writes differ from standing_writes.txt"
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
    scan::violations(&files, &roster(), WRITES)
}

#[test]
fn a_write_planted_in_the_pure_proven_reader_is_reported() {
    let found = planted(
        "crates/kr-worker/src/action/time.rs",
        "        let state = self.lock();\n        let now = self.pure_wall_ms();",
        "        let state = self.lock();\n        self.readings.lock().unwrap().keep(0, 0);\n        let now = self.pure_wall_ms();",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("action/time.rs pure_proven_ms calls keep 1 time(s)"),
        "{found:?}"
    );
}

#[test]
fn a_write_planted_in_the_standing_comparison_of_the_gate_is_reported() {
    let found = planted(
        "crates/kr-worker/src/service.rs",
        "        self.check_restrictions(caller)\n    }\n\n    /// Refuses a caller admitted under a lease",
        "        self.time.raise(0);\n        self.check_restrictions(caller)\n    }\n\n    /// Refuses a caller admitted under a lease",
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].contains("service.rs check_local_standing calls raise 1 time(s)"),
        "{found:?}"
    );
}
