//! The standing function takes the locks the roster lists and no other.
//!
//! `standing_takes.txt` lists, against the source of this crate, every take of a lock inside the
//! functions of the standing function and the pure readers it uses, by file, function and callee,
//! with how many there are. A take with no row, a row with no take, a different number of takes, a
//! scope row with no function and a row outside the scope each fail the case. The reader of source
//! text, and what it does not see, is in `standing_scan/mod.rs`: it reads the body of every helper
//! that a listed body calls by a name that this crate declares once, and the helpers those call in
//! turn, so a helper that takes a lock is found where it stands; a name that several functions
//! declare has to be a scoped function, an `outside` one or allowed for the one body that calls it.
//!
//! Beside the takes the roster holds the call sites of the pass: the functions that call a piece,
//! the checks that each piece calls, the guards (the dispatch barrier and the session) that a
//! function holds where it calls them, read from the text before the call, and the session that
//! each call hands on, read from the call's argument.
//!
//! The cases after the first plant a fault in the real source and show the scan reporting it with
//! the finding that names the place: a take in a function that may take none, a clock reader that
//! is not pure, a take in a helper that no row declares or that a listed body calls (the time
//! contract's lock function, the attachment list's check), a new caller of a piece, a check made
//! with the wrong guard held, a call that hands on the wrong session, and a call that is gone.

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
fn a_take_planted_in_the_pure_wall_reader_is_reported() {
    let found = planted(
        TIME,
        "        self.wall.now_ms().get()\n    }",
        "        let _held = self.readings.lock();\n        self.wall.now_ms().get()\n    }",
    );
    only_finding(&found, "action/time.rs pure_wall_ms calls lock 1 time(s)");
}

#[test]
fn a_take_planted_in_a_piece_of_the_pass_is_reported() {
    let found = planted(
        PIECES,
        "        self.service\n            .check_envelope(session, mutation, entry, caller)",
        "        let _held = self.service.runtime.session();\n        self.service\n            .check_envelope(session, mutation, entry, caller)",
    );
    only_finding(
        &found,
        "service/standing.rs envelope calls session 1 time(s)",
    );
}

#[test]
fn a_take_that_a_row_lists_and_the_source_lacks_is_reported() {
    let found = planted(
        GATE,
        "        let bound = self.lock().bound;\n        match bound {\n            Bound::Open => Ok(()),",
        "        let bound = Bound::Open;\n        match bound {\n            Bound::Open => Ok(()),",
    );
    only_finding(
        &found,
        "local_gate.rs check_bound lock: the call is not there",
    );
}

#[test]
fn the_proven_reading_planted_in_the_pure_proven_reader_is_reported() {
    // A reader that keeps a reading under the contract's lock: the helper that keeps it is read, and
    // it takes the readings' lock.
    let found = planted(
        TIME,
        "        let now = self.pure_wall_ms();\n        state.high_water",
        "        let now = self.pure_wall_ms();\n        let _kept = self.proven_wall_ms(&state);\n        state.high_water",
    );
    // The reading is kept under the readings' own lock, in a function that the pass now calls.
    only_finding(
        &found,
        "action/time.rs wall_reading calls lock 1 time(s) and no row lists it",
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
        "action/time.rs wall_reading calls lock 1 time(s) and no row lists it",
    );
}

#[test]
fn the_second_raise_planted_in_the_gates_standing_comparison_is_reported() {
    let found = planted(
        GATE,
        "        let bound = self.lock().bound;\n        match bound {\n            Bound::Open => Ok(()),\n            Bound::Unannounced => Err(Refused::NotTold),",
        "        let bound = self.lock().bound;\n        let _second = self.time.settled_utc_ms();\n        match bound {\n            Bound::Open => Ok(()),\n            Bound::Unannounced => Err(Refused::NotTold),",
    );
    // The second raise is read where it stands: it takes the contract's lock and keeps a reading.
    assert_eq!(found.len(), 3, "{found:?}");
    for names in [
        "action/time.rs settled_utc_ms calls lock 1 time(s) and no row lists it",
        "action/time.rs wall_reading calls lock 1 time(s) and no row lists it",
        "local_gate.rs check_bound calls settled_utc_ms 1 time(s) and no row lists the caller",
    ] {
        assert!(found.iter().any(|line| line.contains(names)), "{found:?}");
    }
}

#[test]
fn the_full_check_planted_in_place_of_the_standing_comparison_is_reported() {
    let found = planted(
        GATE,
        "self.time.utc_deadline_standing(utc_deadline_ms) != UtcDeadline::Ahead",
        "self.time.check_utc_deadline(utc_deadline_ms) != UtcDeadline::Ahead",
    );
    // The gate's comparison no longer asks the standing reader, and it calls the full check, which
    // takes the contract's lock and keeps a reading.
    assert_eq!(found.len(), 4, "{found:?}");
    assert!(
        found.iter().any(|line| line.contains(
            "action/time.rs check_utc_deadline calls lock 1 time(s) and no row lists it"
        )),
        "{found:?}"
    );
    assert!(
        found.iter().any(|line| line.contains(
            "local_gate.rs check_bound calls check_utc_deadline 1 time(s) and no row lists the caller"
        )),
        "{found:?}"
    );
    assert!(
        found.iter().any(|line| line
            .contains("caller utc_deadline_standing crates/kr-worker/src/local_gate.rs check_bound: the call is not there")),
        "{found:?}"
    );
}

#[test]
fn a_take_planted_in_a_helper_that_no_row_declares_is_reported() {
    // The helper is new and no row names it: it is read all the same, and what it takes is found.
    let found = planted(
        GATE,
        "    pub fn check_bound(&self) -> Result<(), Refused> {\n        let bound = self.lock().bound;",
        "    fn hidden_reader(&self) {\n        let _held = self.lock();\n    }\n\n    pub fn check_bound(&self) -> Result<(), Refused> {\n        let bound = self.lock().bound;\n        self.hidden_reader();",
    );
    only_finding(
        &found,
        "local_gate.rs hidden_reader calls lock 1 time(s) and no row lists it",
    );
}

#[test]
fn a_take_planted_in_the_time_contracts_lock_function_is_reported() {
    let found = planted(
        TIME,
        "    fn lock(&self) -> std::sync::MutexGuard<'_, TimeState> {\n        self.state",
        "    fn lock(&self) -> std::sync::MutexGuard<'_, TimeState> {\n        let _also = self.readings.lock();\n        self.state",
    );
    only_finding(
        &found,
        "action/time.rs lock calls lock 2 time(s) and its row says 1",
    );
}

#[test]
fn a_take_planted_in_a_helper_below_the_subject_check_is_reported() {
    // `validate` reaches `check_attachment`, which reaches `holds_attachment`.
    let found = planted(
        SERVICE,
        "    fn holds_attachment(&self, attachment_id: AttachmentId) -> bool {\n        self.attachments",
        "    fn holds_attachment(&self, attachment_id: AttachmentId) -> bool {\n        let _also = self.input.lock();\n        self.attachments",
    );
    only_finding(
        &found,
        "service.rs holds_attachment calls lock 2 time(s) and its row says 1",
    );
}

#[test]
fn no_session_handed_to_the_second_limits_call_is_reported() {
    // The session is live at the call, so the `held` row is satisfied, and the check would take it
    // again under that guard.
    let found = planted(
        SERVICE,
        "        self.standing_pass(Mode::Again).limits(\n            Some(&mut *session),",
        "        self.standing_pass(Mode::Again).limits(\n            None,",
    );
    only_finding(
        &found,
        "service.rs admit_and_dispatch calls limits handing None as argument 0 and its supplies row says Some(&mut*session)",
    );
}

#[test]
fn a_session_handed_to_the_first_admissions_limits_is_reported() {
    let found = planted(
        SERVICE,
        "        let limited = first.limits(None, caller,",
        "        let limited = first.limits(Some(&mut *self.runtime.session()), caller,",
    );
    assert!(
        found.iter().any(|line| line.contains(
            "service.rs receipted calls limits handing Some(&mut*self.runtime.session()) as argument 0 and its supplies row says None"
        )),
        "{found:?}"
    );
}

#[test]
fn a_new_caller_of_a_piece_of_the_pass_is_reported() {
    let found = planted(
        SERVICE,
        "    fn dispatch_accepted(",
        "    fn rogue(&self) {\n        let _ = self.standing_pass(Mode::First);\n    }\n\n    fn dispatch_accepted(",
    );
    only_finding(
        &found,
        "service.rs rogue calls standing_pass 1 time(s) and no row lists the caller",
    );
}

#[test]
fn the_uncertain_outcome_asked_again_without_the_session_is_reported() {
    let found = planted(
        SERVICE,
        "        self.standing_pass(Mode::Again).limits(",
        "        drop(session);\n        self.standing_pass(Mode::Again).limits(",
    );
    // The guard is gone for the ask and for the dispatch that follows it: both rows fail.
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found[0].contains(
            "service.rs admit_and_dispatch calls limits holding {} and its held row says {\"SES\"}"
        ) && found[1].contains(
            "service.rs admit_and_dispatch calls dispatch_accepted holding {} and its held row says {\"SES\"}"
        ),
        "{found:?}"
    );
}

#[test]
fn the_first_admissions_limits_planted_under_a_session_of_its_own_is_reported() {
    // The check takes the session itself when it is handed none, so a guard already held at the
    // call would wait on itself.
    let found = planted(
        SERVICE,
        "        let limited = first.limits(None, caller,",
        "        let _held = self.runtime.session();\n        let limited = first.limits(None, caller,",
    );
    // The guard lives to the end of the function: the call of the hold's function fails with it.
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found[0].contains(
            "service.rs receipted calls limits holding {\"BAR\", \"SES\"} and its held row says {\"BAR\"}"
        ) && found[1].contains(
            "service.rs receipted calls admit_and_dispatch holding {\"BAR\", \"SES\"} and its held row says {\"BAR\"}"
        ),
        "{found:?}"
    );
}

#[test]
fn the_second_ask_of_the_uncertain_outcome_deleted_is_reported() {
    let found = planted(
        SERVICE,
        "        self.standing_pass(Mode::Again).limits(\n            Some(&mut *session),\n            caller,\n            state,\n            mutation,\n            method,\n            submission.subject_digest,\n            Some(shown),\n        )?;\n",
        "",
    );
    assert_eq!(found.len(), 4, "{found:?}");
    assert!(
        found.iter().all(|line| line.contains("admit_and_dispatch")),
        "{found:?}"
    );
    assert!(
        found.iter().any(|line| line.starts_with(
            "supplies crates/kr-worker/src/service.rs admit_and_dispatch limits: the call is not there"
        )),
        "{found:?}"
    );
    assert!(
        found.iter().any(|line| line.starts_with(
            "caller limits crates/kr-worker/src/service.rs admit_and_dispatch: the call is not there"
        )),
        "{found:?}"
    );
}

#[test]
fn an_allow_row_that_no_scoped_body_uses_is_reported() {
    let text = format!(
        "{}\nallow {SERVICE} validate no_such_helper\n",
        include_str!("standing_takes.txt")
    );
    let found = scan::violations(&scan::tree(), &scan::parse(&text), TAKES);
    assert_eq!(
        found,
        vec![format!(
            "allow {SERVICE} validate no_such_helper: no function that the scan reads makes the call"
        )]
    );
}
