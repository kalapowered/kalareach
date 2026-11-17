//! The standing function takes the locks the roster lists and no other.
//!
//! `standing_takes.txt` lists, against the source of this crate, every take of a lock inside the
//! functions of the standing function and the pure readers it uses, by file, function and callee,
//! with how many there are. A take with no row, a row with no take, a different number of takes, a
//! scope row with no function and a row outside the scope each fail the case. The reader of source
//! text, and what it does not see, is in `standing_scan/mod.rs`: it reads the body of every helper
//! that a listed body calls by a name that this crate declares once, and the helpers those call in
//! turn (not the callee of a name that this roster counts: `lock`, `try_lock`, `session`, `state`
//! and `locked` stand for their callees' bodies, which are not read), so a helper that takes a
//! lock is found where it stands; in every body that is read, scoped or followed, a call to a name
//! that several functions declare has to be a counted name, an `outside` one, allowed for that
//! body (a method of the standard library or of another crate) or given the file of its definition
//! by a `calls` row (a function of this crate).
//!
//! Beside the takes the roster holds the call sites of the pass: the functions that call a piece,
//! the checks that each piece calls, the session guard that a function holds where it calls them,
//! read from the text before the call, and the session that each call hands on, read from the
//! call's argument. The dispatch barrier is not read here: the compiler holds it, because the
//! functions that run under it take a borrow of its guard as a parameter.
//!
//! The cases after the first plant a fault in the real source and show the scan reporting it with
//! the finding that names the place: a take in a function that may take none, a clock reader that
//! is not pure, a take in a helper that no row declares or that a listed body calls (the time
//! contract's lock function, the attachment list's check), a take in a function that a `calls` row
//! reaches (the journal's count, the fence driver's detach, the input domain's fence, the
//! questions' store's read, the binder's count of open work), a new caller of a piece (in the
//! service's file or in a child module of it), a check made with the wrong guard held, a call of
//! an entry into the pass from a child module of the service, a call after a raw byte or C string
//! that holds a quote, a call that hands on the wrong session or the wrong record, and a call that
//! is gone. Two cases plant a reading kept under the contract's lock in the proven or the wall
//! reader; the take that they find is the lock of the helper that keeps the reading
//! (`wall_reading`), so their finding names that helper and not the call that reaches it.

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

/// A finding of a plant that names the place, among the others that the plant brings: a plant that
/// makes the pass reach a function of the time contract's full check puts that function's own
/// shared names under the boundary too.
fn finding_among(found: &[String], names: &str) {
    assert!(found.iter().any(|line| line.contains(names)), "{found:?}");
}

const TIME: &str = "crates/kr-worker/src/action/time.rs";
const GATE: &str = "crates/kr-worker/src/local_gate.rs";
const SERVICE: &str = "crates/kr-worker/src/service.rs";
const PIECES: &str = "crates/kr-worker/src/service/standing.rs";
const OVERTAKE: &str = "crates/kr-worker/src/service/overtake.rs";

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
    finding_among(
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
    finding_among(
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
    for names in [
        "action/time.rs settled_utc_ms calls lock 1 time(s) and no row lists it",
        "action/time.rs wall_reading calls lock 1 time(s) and no row lists it",
        "local_gate.rs check_bound calls settled_utc_ms 1 time(s) and no row lists the caller",
    ] {
        finding_among(&found, names);
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
    finding_among(
        &found,
        "action/time.rs check_utc_deadline calls lock 1 time(s) and no row lists it",
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
        "        self.standing_pass(Mode::Again, barrier).limits(\n            Some(&mut *session),",
        "        self.standing_pass(Mode::Again, barrier).limits(\n            None,",
    );
    only_finding(
        &found,
        "service.rs admit_and_dispatch calls limits handing None as argument 0 and its supplies row says Some(&mut*session)",
    );
}

#[test]
fn a_take_of_the_dispatch_boundary_planted_in_the_first_admission_is_reported() {
    // The first admission runs inside the barrier that its caller holds, so a take of the boundary
    // in its own body would wait on itself: each of its `held` rows fails with the take read before
    // the call. The compiler holds that the guard is a guard; this says that no second one is taken.
    let found = planted(
        SERVICE,
        "        let actor_id = caller.actor_id.clone();\n        self.wait_inside_boundary();\n",
        "        let actor_id = caller.actor_id.clone();\n        let _again = self.take_boundary();\n        self.wait_inside_boundary();\n",
    );
    let held = |callee: &str, live: &str, row: &str| {
        format!(
            "crates/kr-worker/src/service.rs receipted calls {callee} holding {live} and its held row says {row}"
        )
    };
    assert_eq!(
        found,
        [
            held("authority", "{\"TAKE\"}", "{}"),
            held("envelope", "{\"SES\", \"TAKE\"}", "{\"SES\"}"),
            held("limits", "{\"TAKE\"}", "{}"),
            held("admit_and_dispatch", "{\"TAKE\"}", "{}"),
        ]
    );
}

#[test]
fn a_take_of_the_dispatch_boundary_before_the_first_admission_is_reported() {
    // A take in `receipt_once`, before the call of the first admission, also waits on the barrier
    // that the function holds; a `try` is read as a take too.
    let found = planted(
        SERVICE,
        "            Tried::Done(self.receipted(state, mutation, method, entry, caller, freshness, &barrier))",
        "            let _again = self.try_take_boundary();\n            Tried::Done(self.receipted(state, mutation, method, entry, caller, freshness, &barrier))",
    );
    only_finding(
        &found,
        "service.rs receipt_once calls receipted holding {\"TAKE\"} and its held row says {}",
    );
}

#[test]
fn a_session_taken_before_the_call_of_the_prepared_path_is_reported() {
    // The prepared path takes the session where the accept's hold does, inside `continue_prepared`
    // and not before it: a session held in `prepared_once` at the call is not a take of the
    // boundary, and the same row refuses it.
    let found = planted(
        SERVICE,
        "            let ReadyPreparation {\n",
        "            let _session = self.runtime.session();\n            let ReadyPreparation {\n",
    );
    only_finding(
        &found,
        "service.rs prepared_once calls continue_prepared holding {\"SES\"} and its held row says {}",
    );
}

#[test]
fn the_two_entries_begin_with_the_check_that_their_guard_is_the_services_own() {
    // The compiler holds that each entry is handed a guard and not whose it is; the entry says so
    // first, before any work. A unit case in `service/boundary.rs` shows the first admission refusing
    // the guard of another service. The prepared path cannot be built in a unit case (its pending
    // action holds a component's request), so its check is read here, as the first statement.
    let files = scan::tree();
    let (_, source) = files
        .iter()
        .find(|(name, _)| name == SERVICE)
        .expect("the service is in the tree");
    for entry in ["    fn receipted(", "    fn continue_prepared("] {
        assert_eq!(source.matches(entry).count(), 1, "{entry}");
        let after = &source[source.find(entry).expect("the entry")..];
        let end = ") -> Result<Answered> {";
        let open = after.find(end).expect("its signature") + end.len();
        let start: String = after[open..]
            .chars()
            .filter(|c| !c.is_whitespace())
            .take(60)
            .collect();
        assert!(
            start.starts_with("assert!(barrier.is_of(&self.dispatch),"),
            "{entry} begins with {start}"
        );
    }
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
        "        self.standing_pass(Mode::Again, barrier).limits(",
        "        drop(session);\n        self.standing_pass(Mode::Again, barrier).limits(",
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
            "service.rs receipted calls limits holding {\"SES\"} and its held row says {}"
        ) && found[1].contains(
            "service.rs receipted calls admit_and_dispatch holding {\"SES\"} and its held row says {}"
        ),
        "{found:?}"
    );
}

#[test]
fn the_second_ask_of_the_uncertain_outcome_deleted_is_reported() {
    let found = planted(
        SERVICE,
        "        self.standing_pass(Mode::Again, barrier).limits(\n            Some(&mut *session),\n            caller,\n            state,\n            mutation,\n            method,\n            submission.subject_digest,\n            Some(shown),\n        )?;\n",
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

#[test]
fn a_take_planted_in_the_services_own_bound_check_is_reported() {
    // `check_bound` is a name that two functions declare: the authority's check calls the
    // service's, the local owner's standing calls the gate's, and the roster declares both.
    let found = planted(
        SERVICE,
        "    fn check_bound(facts: &ConnectionFacts, authority: &Authority) -> Result<()> {\n",
        "    fn check_bound(facts: &ConnectionFacts, authority: &Authority) -> Result<()> {\n        let _held = facts.attachments.lock();\n",
    );
    only_finding(
        &found,
        "service.rs check_bound calls lock 1 time(s) and no row lists it",
    );
}

#[test]
fn a_broker_take_planted_in_the_decisions_check_is_reported() {
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
fn a_second_caller_of_the_first_admission_is_reported() {
    // The first admission runs inside the barrier that its caller takes with `try_boundary`: its
    // `only` row lets no other function call it, and a function that does fails the row.
    let found = planted(
        SERVICE,
        "    fn receipted(",
        "    fn rogue(&self) {\n        let _ = self.receipted();\n    }\n\n    fn receipted(",
    );
    only_finding(
        &found,
        "service.rs rogue calls receipted 1 time(s) and no row lists the caller",
    );
}

#[test]
fn a_second_caller_of_the_prepared_paths_second_pass_is_reported() {
    // The same for the prepared path's second pass, which `prepared_once` calls under the barrier
    // that it takes.
    let found = planted(
        SERVICE,
        "    fn continue_prepared(",
        "    fn rogue(&self) {\n        let _ = self.continue_prepared();\n    }\n\n    fn continue_prepared(",
    );
    only_finding(
        &found,
        "service.rs rogue calls continue_prepared 1 time(s) and no row lists the caller",
    );
}

#[test]
fn a_caller_of_the_first_admission_in_a_child_module_of_the_service_is_reported() {
    // A child module can call the service's private methods, and a `caller` row reads only the
    // file that it names: the `only` row reads every file of the crate.
    let found = planted(
        PIECES,
        "    /// Starts a pass of the standing function in `mode`, under the dispatch boundary that `barrier`\n",
        "    fn rogue(&self) {\n        let _ = self.receipted();\n    }\n\n    /// Starts a pass of the standing function in `mode`, under the dispatch boundary that `barrier`\n",
    );
    only_finding(
        &found,
        "service/standing.rs rogue calls receipted 1 time(s) and no row lists the caller",
    );
}

#[test]
fn a_caller_of_the_prepared_paths_second_pass_in_a_child_module_of_the_service_is_reported() {
    let found = planted(
        OVERTAKE,
        "impl Overtaking {\n",
        "impl Overtaking {\n    fn rogue(&self) {\n        let _ = self.continue_prepared();\n    }\n\n",
    );
    only_finding(
        &found,
        "service/overtake.rs rogue calls continue_prepared 1 time(s) and no row lists the caller",
    );
}

#[test]
fn a_new_caller_of_the_accepts_hold_is_reported() {
    let found = planted(
        SERVICE,
        "    fn dispatch_accepted(",
        "    fn rogue(&self) {\n        let _ = self.admit_and_dispatch();\n    }\n\n    fn dispatch_accepted(",
    );
    only_finding(
        &found,
        "service.rs rogue calls admit_and_dispatch 1 time(s) and no row lists the caller",
    );
}

#[test]
fn a_new_caller_of_the_dispatch_of_an_accepted_action_is_reported() {
    let found = planted(
        SERVICE,
        "    fn dispatch_accepted(",
        "    fn rogue(&self) {\n        let _ = self.dispatch_accepted();\n    }\n\n    fn dispatch_accepted(",
    );
    only_finding(
        &found,
        "service.rs rogue calls dispatch_accepted 1 time(s) and no row lists the caller",
    );
}

#[test]
fn a_caller_of_the_dispatch_of_an_accepted_action_in_a_child_module_is_reported() {
    // An entry into the pass: its `only` rows read every file of the crate.
    let found = planted(
        OVERTAKE,
        "impl Overtaking {\n",
        "impl Overtaking {\n    fn rogue(&self) {\n        let _ = self.dispatch_accepted();\n    }\n\n",
    );
    only_finding(
        &found,
        "service/overtake.rs rogue calls dispatch_accepted 1 time(s) and no row lists the caller",
    );
}

#[test]
fn a_caller_of_the_standing_pass_in_a_child_module_is_reported() {
    let found = planted(
        OVERTAKE,
        "impl Overtaking {\n",
        "impl Overtaking {\n    fn rogue(&self) {\n        let _ = self.standing_pass(Mode::First);\n    }\n\n",
    );
    only_finding(
        &found,
        "service/overtake.rs rogue calls standing_pass 1 time(s) and no row lists the caller",
    );
}

#[test]
fn a_call_after_a_raw_byte_or_c_string_that_holds_a_quote_is_reported() {
    // `br#"""#` and `cr#"""#` are raw strings with a quote inside. Read as plain strings, that
    // quote opens a string that hides the call after it from the reader, which then finds no
    // caller to report.
    for prefix in ["b", "c"] {
        let found = planted(
            OVERTAKE,
            "impl Overtaking {\n",
            &format!(
                "impl Overtaking {{\n    fn rogue(&self) {{\n        let _text = {prefix}r#\"\"\"#;\n        let _ = self.standing_pass(Mode::First);\n        let _quote = '\"';\n    }}\n\n"
            ),
        );
        only_finding(
            &found,
            "service/overtake.rs rogue calls standing_pass 1 time(s) and no row lists the caller",
        );
    }
}

const METHODS: &str = "crates/kr-worker/src/broker/methods.rs";
const BROKER: &str = "crates/kr-worker/src/broker/mod.rs";

#[test]
fn the_record_at_the_brokers_recheck_replaced_by_one_with_no_grants_is_reported() {
    // The repeat's `checks` call has two `supplies` rows, the record at argument 0 and the ask at
    // argument 3; a record made again from the binding's identity holds neither the package
    // grants nor the deadlines that the admission captured.
    let found = planted(
        METHODS,
        "        self.state()\n            .checks(admitted, request, self.deadline_now(), Ask::Again)\n",
        "        self.state()\n            .checks(&AdmittedAgainst::new(admitted.application_instance_id(), admitted.binding_revision()), request, self.deadline_now(), Ask::Again)\n",
    );
    finding_among(
        &found,
        "methods.rs recheck_broker calls checks handing &AdmittedAgainst::new(admitted.application_instance_id(),admitted.binding_revision()) as argument 0 and its supplies row says admitted",
    );
}

#[test]
fn the_ask_at_the_brokers_recheck_replaced_by_the_first_is_reported() {
    let found = planted(
        METHODS,
        "        self.state()\n            .checks(admitted, request, self.deadline_now(), Ask::Again)\n",
        "        self.state()\n            .checks(admitted, request, self.deadline_now(), Ask::Once)\n",
    );
    only_finding(
        &found,
        "methods.rs recheck_broker calls checks handing Ask::Once as argument 3 and its supplies row says Ask::Again",
    );
}

#[test]
fn the_record_at_the_dispatchs_last_ask_replaced_by_one_with_no_grants_is_reported() {
    let found = planted(
        BROKER,
        "        state.checks(\n            against,\n            request,\n            self.deadline_now(),\n            crate::broker::methods::Ask::Again,\n        )?;\n",
        "        state.checks(\n            &AdmittedAgainst::new(against.application_instance_id(), against.binding_revision()),\n            request,\n            self.deadline_now(),\n            crate::broker::methods::Ask::Again,\n        )?;\n",
    );
    finding_among(
        &found,
        "mod.rs commit_dispatch calls checks handing &AdmittedAgainst::new(against.application_instance_id(),against.binding_revision()) as argument 0 and its supplies row says against",
    );
}

#[test]
fn the_ask_at_the_dispatchs_last_ask_replaced_by_the_first_is_reported() {
    let found = planted(
        BROKER,
        "            self.deadline_now(),\n            crate::broker::methods::Ask::Again,\n        )?;\n",
        "            self.deadline_now(),\n            crate::broker::methods::Ask::Once,\n        )?;\n",
    );
    only_finding(
        &found,
        "mod.rs commit_dispatch calls checks handing crate::broker::methods::Ask::Once as argument 3 and its supplies row says crate::broker::methods::Ask::Again",
    );
}

#[test]
fn a_supplies_row_for_another_argument_of_the_same_call_keeps_the_earlier_row() {
    let rows = scan::parse(
        "supplies a.rs f g 0 first\nsupplies a.rs f g 3 second\nsupplies a.rs f h 0 third\n",
    );
    assert_eq!(rows.supplies.len(), 3);
    let key = |position| ("a.rs".to_owned(), "f".to_owned(), "g".to_owned(), position);
    assert_eq!(
        rows.supplies.get(&key(0)).map(String::as_str),
        Some("first")
    );
    assert_eq!(
        rows.supplies.get(&key(3)).map(String::as_str),
        Some("second")
    );
}

#[test]
fn a_row_that_repeats_the_key_of_an_earlier_row_is_refused() {
    // Each kind that holds one value per key refuses a second row for it, so that a later row
    // never replaces an earlier one unseen.
    for text in [
        "site a.rs f lock 1\nsite a.rs f lock 2\n",
        "supplies a.rs f g 0 first\nsupplies a.rs f g 0 second\n",
        "caller g a.rs f 1\ncaller g a.rs f 2\n",
        "caller g a.rs f 1\nonly g a.rs f 2\n",
        "held a.rs f g SES\nheld a.rs f g none\n",
    ] {
        let refused = std::panic::catch_unwind(|| scan::parse(text));
        assert!(refused.is_err(), "{text}");
    }
}

#[test]
fn a_name_that_a_body_allows_and_declares_a_target_for_is_reported() {
    // The follow skips an allowed name, so a `calls` row beside an `allow` row would read nothing.
    let text = format!(
        "{}\nallow {SERVICE} check_local_standing check_bound\n",
        include_str!("standing_takes.txt")
    );
    let found = scan::violations(&scan::tree(), &scan::parse(&text), TAKES);
    assert!(
        found.iter().any(|line| line.contains(&format!(
            "allow {SERVICE} check_local_standing check_bound and calls {SERVICE} check_local_standing check_bound"
        ))),
        "{found:?}"
    );
}

const JOURNAL: &str = "crates/kr-worker/src/journal.rs";
const DRIVER: &str = "crates/kr-worker/src/fence/driver.rs";
const INPUT_DOMAIN: &str = "crates/kr-worker/src/input_domain.rs";
const STORE: &str = "crates/kr-worker/src/questions/store.rs";

#[test]
fn a_take_planted_in_the_journals_outstanding_count_is_reported() {
    // The limits read the journal's count of outstanding actions, so the count's own body is under
    // the pass; its receiver is a journal of this crate and not a standard method.
    let found = planted(
        JOURNAL,
        "    pub fn outstanding(&self, actor_id: &ActorId) -> Result<usize> {\n",
        "    pub fn outstanding(&self, actor_id: &ActorId) -> Result<usize> {\n        let _held = self.gate.lock();\n",
    );
    only_finding(
        &found,
        "journal.rs outstanding calls lock 1 time(s) and no row lists it",
    );
}

#[test]
fn a_take_planted_in_the_fence_drivers_detach_is_reported() {
    // The presented-token detach reaches the driver's own detach through the input domain's fence.
    let found = planted(
        DRIVER,
        "    pub fn detach_for_token(&self, presented: &str) -> Option<AttachmentId> {\n",
        "    pub fn detach_for_token(&self, presented: &str) -> Option<AttachmentId> {\n        let _held = self.tokens.lock();\n",
    );
    only_finding(
        &found,
        "fence/driver.rs detach_for_token calls lock 1 time(s) and no row lists it",
    );
}

#[test]
fn a_take_planted_in_the_input_domains_fence_is_reported() {
    let found = planted(
        INPUT_DOMAIN,
        "    pub const fn fence(&self) -> Option<&FenceDriver> {\n",
        "    pub const fn fence(&self) -> Option<&FenceDriver> {\n        let _held = self.guard.lock();\n",
    );
    only_finding(
        &found,
        "input_domain.rs fence calls lock 1 time(s) and no row lists it",
    );
}

#[test]
fn a_take_planted_in_the_questions_stores_read_is_reported() {
    // The expiry sweep and the subject's check read a question through the store's `read`, which
    // is a name that several functions declare: its receiver is the store of this crate.
    let found = planted(
        STORE,
        "    pub fn read(&self, question_id: QuestionId) -> Result<Question> {\n",
        "    pub fn read(&self, question_id: QuestionId) -> Result<Question> {\n        let _held = self.connection.lock();\n",
    );
    only_finding(
        &found,
        "questions/store.rs read calls lock 1 time(s) and no row lists it",
    );
}

#[test]
fn a_take_planted_in_the_binders_count_of_open_work_is_reported() {
    let found = planted(
        "crates/kr-worker/src/broker/binder.rs",
        "    fn admitted_open(&self, binding_id: BrokerBindingId) -> bool {\n",
        "    fn admitted_open(&self, binding_id: BrokerBindingId) -> bool {\n        let _held = self.gate.lock();\n",
    );
    only_finding(
        &found,
        "binder.rs admitted_open calls lock 1 time(s) and no row lists it",
    );
}

#[test]
fn a_new_caller_of_the_binders_count_of_open_work_is_reported() {
    let found = planted(
        "crates/kr-worker/src/broker/binder.rs",
        "    fn admitted_open(&self, binding_id: BrokerBindingId) -> bool {\n",
        "    fn rogue(&self, binding_id: BrokerBindingId) -> bool {\n        self.admitted_open(binding_id)\n    }\n\n    fn admitted_open(&self, binding_id: BrokerBindingId) -> bool {\n",
    );
    only_finding(
        &found,
        "binder.rs rogue calls admitted_open 1 time(s) and no row lists the caller",
    );
}
