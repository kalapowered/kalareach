//! The standing function writes what the roster lists and nothing else.
//!
//! `standing_writes.txt` lists, against the source of this crate, every call of a name that
//! changes state that others read (a clock floor, a record, a journal, a question's ledger, an
//! atomic, a wake-up) inside the functions of the standing function and the pure readers it uses,
//! by file, function and callee, with how many there are. A write with no row, a row with no
//! write, a different number of writes, a scope row with no function and a row outside the scope
//! each fail the case. The reader of source text, and what it does not see, is in
//! `standing_scan/mod.rs`: it does not follow a call into another function, but it holds a
//! boundary at each scoped body: a call to a function of this crate that the roster neither reads,
//! declares outside the scope nor allows fails, so a helper cannot hide a write. The functions
//! that make the time contract's writes (the full check, the second raise, the kept reading) are
//! listed by caller across the whole crate.
//!
//! The cases after the first plant a fault in the real source and show the scan reporting it with
//! the one finding that names the place: a write in a function that may make none, each of the
//! time contract's writers called from a pure reader or from the gate's standing comparison, a
//! call to a helper that no row declares, and a new caller of a time-contract writer.

#[path = "standing_scan/mod.rs"]
mod scan;

/// The names of the calls that change state which others read, as the design lists them: a note
/// of a fault, a send, a map or set insert or remove, an atomic store, an execute, the expiry
/// sweep, the clock floor's raise and the owed record, the second raise and the full check of the
/// local owner (which raises and owes), the kept reading and the two functions that make it, a
/// wake-up and a permit or token taken, and a `&mut` parameter, which counts as a write that its
/// function may make. A name that ends in `*` is a prefix.
const WRITES: &[&str] = &[
    "note_*",
    "send",
    "insert",
    "remove",
    "store",
    "fetch_*",
    "swap",
    "execute",
    "expire_due",
    "sweep",
    "raise",
    "owe",
    "settled_utc_ms",
    "check_utc_deadline",
    "publish",
    "wall_reading",
    "proven_wall_ms",
    "keep",
    "notify*",
    "take",
    "accept",
    "reject",
    "settle",
    "advance",
    "mark_dispatching_while",
    "commit_transition",
    "show",
    scan::MUT_PARAMETER,
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

/// The one finding of a plant, which has to name the place.
fn only_finding(found: &[String], names: &str) {
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains(names), "{found:?}");
}

const TIME: &str = "crates/kr-worker/src/action/time.rs";
const GATE: &str = "crates/kr-worker/src/local_gate.rs";
const SERVICE: &str = "crates/kr-worker/src/service.rs";
const PIECES: &str = "crates/kr-worker/src/service/standing.rs";

#[test]
fn a_write_planted_in_the_pure_proven_reader_is_reported() {
    let found = planted(
        TIME,
        "        let state = self.lock();\n        let now = self.pure_wall_ms();",
        "        let state = self.lock();\n        self.readings.lock().unwrap().keep(0, 0);\n        let now = self.pure_wall_ms();",
    );
    only_finding(&found, "action/time.rs pure_proven_ms calls keep 1 time(s)");
}

#[test]
fn a_write_planted_in_the_standing_comparison_of_the_gate_is_reported() {
    let found = planted(
        SERVICE,
        "        self.check_restrictions(caller)\n    }\n\n    /// Refuses a caller admitted under a lease",
        "        self.time.raise(0);\n        self.check_restrictions(caller)\n    }\n\n    /// Refuses a caller admitted under a lease",
    );
    only_finding(
        &found,
        "service.rs check_local_standing calls raise 1 time(s)",
    );
}

#[test]
fn the_proven_reading_planted_in_the_pure_proven_reader_is_reported() {
    // A reader that takes the lock and keeps the reading, which the pure reader may not make.
    let found = planted(
        TIME,
        "        let now = self.pure_wall_ms();\n        state.high_water",
        "        let now = self.pure_wall_ms();\n        let _kept = self.proven_wall_ms(&state);\n        state.high_water",
    );
    only_finding(
        &found,
        "action/time.rs pure_proven_ms calls proven_wall_ms 1 time(s)",
    );
}

#[test]
fn the_kept_reading_planted_in_the_pure_wall_reader_is_reported() {
    let found = planted(
        TIME,
        "        self.wall.now_ms().get()\n    }",
        "        let _kept = self.wall_reading();\n        self.wall.now_ms().get()\n    }",
    );
    only_finding(
        &found,
        "action/time.rs pure_wall_ms calls wall_reading 1 time(s)",
    );
}

#[test]
fn the_second_raise_planted_in_the_gates_standing_comparison_is_reported() {
    let found = planted(
        GATE,
        "        let bound = self.lock().bound;\n        match bound {\n            Bound::Open => Ok(()),\n            Bound::Unannounced => Err(Refused::NotTold),",
        "        let bound = self.lock().bound;\n        let _second = self.time.settled_utc_ms();\n        match bound {\n            Bound::Open => Ok(()),\n            Bound::Unannounced => Err(Refused::NotTold),",
    );
    only_finding(
        &found,
        "local_gate.rs check_bound calls settled_utc_ms 1 time(s)",
    );
}

#[test]
fn the_full_check_planted_in_place_of_the_standing_comparison_is_reported() {
    let found = planted(
        GATE,
        "self.time.utc_deadline_standing(utc_deadline_ms) != UtcDeadline::Ahead",
        "self.time.check_utc_deadline(utc_deadline_ms) != UtcDeadline::Ahead",
    );
    only_finding(
        &found,
        "local_gate.rs check_bound calls check_utc_deadline 1 time(s)",
    );
}

#[test]
fn a_note_of_a_fault_planted_in_the_limits_piece_is_reported() {
    let found = planted(
        PIECES,
        "        self.service\n            .check_admission_limits(held, caller, state, mutation, method, subject, shown)",
        "        self.service.runtime.session().note_journal_failure(1.to_string());\n        self.service\n            .check_admission_limits(held, caller, state, mutation, method, subject, shown)",
    );
    only_finding(
        &found,
        "service/standing.rs limits calls note_journal_failure 1 time(s)",
    );
}

#[test]
fn a_call_to_a_helper_that_no_row_declares_is_reported() {
    let found = planted(
        GATE,
        "    pub fn check_bound(&self) -> Result<(), Refused> {\n        let bound = self.lock().bound;",
        "    fn hidden_reader(&self) {}\n\n    pub fn check_bound(&self) -> Result<(), Refused> {\n        let bound = self.lock().bound;\n        self.hidden_reader();",
    );
    only_finding(
        &found,
        "local_gate.rs check_bound calls hidden_reader, which is neither counted, in the scope, outside it nor allowed",
    );
}

#[test]
fn a_new_caller_of_a_time_contract_writer_is_reported() {
    let found = planted(
        SERVICE,
        "    fn dispatch_accepted(",
        "    fn rogue(&self) {\n        let _ = self.time.check_utc_deadline(0);\n    }\n\n    fn dispatch_accepted(",
    );
    only_finding(
        &found,
        "service.rs rogue calls check_utc_deadline 1 time(s) and no row lists the caller",
    );
}

#[test]
fn an_allow_row_that_no_scoped_body_uses_is_reported() {
    let text = format!(
        "{}\nallow no_such_helper\n",
        include_str!("standing_writes.txt")
    );
    let found = scan::violations(&scan::tree(), &scan::parse(&text), WRITES);
    assert_eq!(
        found,
        vec!["allow no_such_helper: no scoped function calls it".to_owned()]
    );
}

#[test]
fn a_mutable_parameter_planted_in_a_piece_of_the_pass_is_reported() {
    let found = planted(
        PIECES,
        "        session: &Session,\n        state: &ConnectionState,",
        "        session: &mut Session,\n        state: &ConnectionState,",
    );
    only_finding(&found, "service/standing.rs subject calls &mut 1 time(s)");
}
