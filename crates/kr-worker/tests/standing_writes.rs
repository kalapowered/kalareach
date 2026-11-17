//! The standing function writes what the roster lists and nothing else.
//!
//! `standing_writes.txt` lists, against the source of this crate, every call of a name that
//! changes state that others read (a clock floor, a record, a journal, a question's ledger, an
//! atomic, a wake-up) inside the functions of the standing function and the pure readers it uses,
//! by file, function and callee, with how many there are. A write with no row, a row with no
//! write, a different number of writes, a scope row with no function and a row outside the scope
//! each fail the case. The reader of source text, and what it does not see, is in
//! `standing_scan/mod.rs`: it reads the body of every helper that a listed body calls by a name
//! that this crate declares once, and the helpers those call in turn (not the callee of a name
//! that this roster counts), and in every body that is read a call to a name that several
//! functions declare has to be a counted name, an `outside` one, allowed for that body (the
//! standard library's or another crate's) or declared with the file of the definition that the
//! body calls, which is read as well; so a helper that a listed body reaches by either is held to
//! the same rows. What the scan does not follow is named in the header of the reader. The functions that make the time contract's writes
//! (the full check, the second raise, the kept reading) are listed by caller across the whole
//! crate.
//!
//! The cases after the first plant a fault in the real source and show the scan reporting it with
//! the one finding that names the place: a write in a function that may make none, each of the
//! time contract's writers called from a pure reader or from the gate's standing comparison, a
//! write in a helper that no row declares, in a helper that a listed body calls (the time
//! contract's lock function; the question that checks a resolvable request), a write in a function
//! that a `calls` row reaches (the journal's count of outstanding actions, the fence driver's
//! detach, the input domain's fence), a name allowed for one body and called by another, and a new
//! caller of a time-contract writer.

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
    // The note itself, and the session that the plant takes to make it.
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(
        found
            .iter()
            .any(|line| line
                .contains("service/standing.rs limits calls note_journal_failure 1 time(s)")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|line| line.contains("service/standing.rs limits calls session,")),
        "{found:?}"
    );
}

#[test]
fn a_write_planted_in_a_helper_that_no_row_declares_is_reported() {
    // The helper is new and no row names it: it is read all the same, and what it writes is found.
    let found = planted(
        GATE,
        "    pub fn check_bound(&self) -> Result<(), Refused> {\n        let bound = self.lock().bound;",
        "    fn hidden_reader(&self) {\n        self.time.raise(0);\n    }\n\n    pub fn check_bound(&self) -> Result<(), Refused> {\n        let bound = self.lock().bound;\n        self.hidden_reader();",
    );
    only_finding(
        &found,
        "local_gate.rs hidden_reader calls raise 1 time(s) and no row lists it",
    );
}

#[test]
fn a_floor_raise_planted_in_the_time_contracts_lock_function_is_reported() {
    // `pure_proven_ms` calls `lock`, which the roster reads as a function of its own.
    let found = planted(
        TIME,
        "    fn lock(&self) -> std::sync::MutexGuard<'_, TimeState> {\n        self.state",
        "    fn lock(&self) -> std::sync::MutexGuard<'_, TimeState> {\n        if let Some(floor) = &self.floor {\n            floor.raise(0);\n        }\n        self.state",
    );
    only_finding(
        &found,
        "action/time.rs lock calls raise 1 time(s) and no row lists it",
    );
}

#[test]
fn a_sweep_planted_in_the_question_that_checks_a_resolvable_request_is_reported() {
    // `validate` reaches `check_resolvable_reaching` through `check_resolvable`, in the pass's
    // second mode too: a sweep there is a write that the pass does not make.
    let found = planted(
        "crates/kr-worker/src/questions/mod.rs",
        "        let question = self.locked()?.read(question_id)?;\n        if !reaches(&question) {",
        "        let _swept = self.locked()?.expire_due(now, self.agents.as_deref())?;\n        let question = self.locked()?.read(question_id)?;\n        if !reaches(&question) {",
    );
    only_finding(
        &found,
        "questions/mod.rs check_resolvable_reaching calls expire_due 1 time(s) and no row lists it",
    );
}

#[test]
fn a_name_allowed_for_one_body_and_called_by_another_is_reported() {
    // `contains` is allowed for the subject's check and for no other body.
    let found = planted(
        GATE,
        "    pub fn check_bound(&self) -> Result<(), Refused> {\n        let bound = self.lock().bound;",
        "    pub fn check_bound(&self) -> Result<(), Refused> {\n        let bound = self.lock().bound;\n        let _ = [0_u8].contains(&0);",
    );
    only_finding(
        &found,
        "local_gate.rs check_bound calls contains, which several functions of the crate declare",
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
        "{}\nallow {SERVICE} validate no_such_helper\n",
        include_str!("standing_writes.txt")
    );
    let found = scan::violations(&scan::tree(), &scan::parse(&text), WRITES);
    assert_eq!(
        found,
        vec![format!(
            "allow {SERVICE} validate no_such_helper: no function that the scan reads makes the call"
        )]
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

#[test]
fn a_notify_planted_in_the_locked_body_of_the_questions_is_reported() {
    // `locked` is a name that several functions declare: the roster declares which one the
    // questions' checks call, and the scan reads it.
    let found = planted(
        "crates/kr-worker/src/questions/mod.rs",
        "    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Store>> {\n        self.store",
        "    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Store>> {\n        self.changed.notify_waiters();\n        self.store",
    );
    only_finding(
        &found,
        "questions/mod.rs locked calls notify_waiters 1 time(s) and no row lists it",
    );
}

#[test]
fn a_write_planted_in_the_stores_read_below_a_shared_name_is_reported() {
    let found = planted(
        "crates/kr-worker/src/questions/store.rs",
        "    pub fn read(&self, question_id: QuestionId) -> Result<Question> {\n        self.row(question_id)?",
        "    pub fn read(&self, question_id: QuestionId) -> Result<Question> {\n        self.connection.execute(\"\", [])?;\n        self.row(question_id)?",
    );
    only_finding(
        &found,
        "questions/store.rs read calls execute 1 time(s) and no row lists it",
    );
}

#[test]
fn a_call_to_a_shared_name_in_a_followed_body_that_no_row_declares_is_reported() {
    // The decision's check is read by the follow, and the boundary holds in it: a call to a name
    // that two functions declare (the broker's fence check and its note) has no row.
    let found = planted(
        SERVICE,
        "        let reach = caller.disclosure(true);\n        Ok(self\n            .broker",
        "        self.broker.require_rich_work()?;\n        let reach = caller.disclosure(true);\n        Ok(self\n            .broker",
    );
    only_finding(
        &found,
        "service.rs check_decision_reached calls require_rich_work, which several functions of the crate declare",
    );
}

#[test]
fn a_free_function_that_raises_the_floor_is_followed_and_reported() {
    // A counted name called without a path is no counted call, and it is read like any helper: the
    // function that it names is declared once, and what it writes is found where it stands.
    let found = planted(
        TIME,
        "    pub fn utc_deadline_standing(&self, deadline_ms: u64) -> UtcDeadline {\n",
        "    pub fn utc_deadline_standing(&self, deadline_ms: u64) -> UtcDeadline {\n        fn note_floor(time: &TimeContract) {\n            time.floor.raise(0);\n        }\n        note_floor(self);\n",
    );
    only_finding(
        &found,
        "action/time.rs note_floor calls raise 1 time(s) and no row lists it",
    );
}

const JOURNAL: &str = "crates/kr-worker/src/journal.rs";
const DRIVER: &str = "crates/kr-worker/src/fence/driver.rs";
const INPUT_DOMAIN: &str = "crates/kr-worker/src/input_domain.rs";

#[test]
fn a_write_planted_in_the_journals_outstanding_count_is_reported() {
    // The limits read the journal's count of outstanding actions: the body can record a fault, and
    // a write planted beside that note is reported.
    let found = planted(
        JOURNAL,
        "    pub fn outstanding(&self, actor_id: &ActorId) -> Result<usize> {\n",
        "    pub fn outstanding(&self, actor_id: &ActorId) -> Result<usize> {\n        self.note_fault();\n",
    );
    only_finding(
        &found,
        "journal.rs outstanding calls note_fault 1 time(s) and no row lists it",
    );
}

#[test]
fn a_write_planted_in_the_fence_drivers_detach_is_reported() {
    let found = planted(
        DRIVER,
        "    pub fn detach_for_token(&self, presented: &str) -> Option<AttachmentId> {\n",
        "    pub fn detach_for_token(&self, presented: &str) -> Option<AttachmentId> {\n        self.tokens.insert(0, 0);\n",
    );
    only_finding(
        &found,
        "fence/driver.rs detach_for_token calls insert 1 time(s) and no row lists it",
    );
}

#[test]
fn a_write_planted_in_the_input_domains_fence_is_reported() {
    let found = planted(
        INPUT_DOMAIN,
        "    pub const fn fence(&self) -> Option<&FenceDriver> {\n",
        "    pub const fn fence(&self) -> Option<&FenceDriver> {\n        self.note_fenced();\n",
    );
    only_finding(
        &found,
        "input_domain.rs fence calls note_fenced 1 time(s) and no row lists it",
    );
}
