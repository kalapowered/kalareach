//! What each control of cases 5b and 6b reads and how it judges it.
//!
//! A case gathers an observation through [`Hosted`] and hands it to the judge of its control. A
//! judge returns the control's red, the text the table names, when the observation shows the
//! mutation. Each judge is shown here against an observation that is right and against the
//! observation each mutation of the table makes, with no launch; the mutation itself is run alone
//! on the product by the part that owns the control.

use serde_json::Value;

use super::red_of;

/// The red a control shows: the control's number and the text of the table.
#[derive(Debug, PartialEq, Eq)]
pub struct Red {
    /// The control's number, `5b-1` for example.
    pub id: String,
    /// What the case sees when the control's mutation is made.
    pub text: &'static str,
}

impl std::fmt::Display for Red {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "{}: {}", self.id, self.text)
    }
}

/// The red of control `id`.
pub fn red(id: &str) -> Red {
    Red {
        id: id.to_owned(),
        text: red_of(id),
    }
}

/// Returns the red of control `id` unless `holds`.
fn ensure(holds: bool, id: &str) -> Result<(), Red> {
    if holds { Ok(()) } else { Err(red(id)) }
}

/// The lines of the stand-in's record that are responses to its requests.
fn responses(record: &[Value]) -> Vec<&Value> {
    record
        .iter()
        .filter(|line| line["received"] == "response")
        .collect()
}

/// What the device reads of an instance and of its pending request, each read as the text it is
/// compared by.
#[derive(Debug, PartialEq, Eq)]
pub struct Reads {
    /// The instance the host lists.
    pub instance: String,
    /// The instance's binding.
    pub binding: String,
    /// The identity of the instance's capabilities.
    pub identity: String,
    /// The pending request, with the decoder's whole record of it.
    pub request: String,
}

/// 5b-1: the four reads are equal after the daemon was killed and started again.
pub fn reads_equal_after_a_restart(before: &Reads, after: &Reads) -> Result<(), Red> {
    ensure(before == after, "5b-1")
}

/// 5b-2: the stand-in received one response, with the chosen option.
pub fn one_reply_with_the_chosen_id(record: &[Value], option: &str) -> Result<(), Red> {
    let replies = responses(record);
    ensure(replies.len() == 1 && replies[0]["option"] == option, "5b-2")
}

/// What the device reads after the daemon was killed and then the worker, and the daemon started
/// again.
#[derive(Debug)]
pub struct AfterTheWorkerEnded {
    /// The read of the instance was refused as a closed session's.
    pub instance_refused: bool,
    /// The read of the request was refused as a closed session's.
    pub request_refused: bool,
    /// An answer to the request was accepted.
    pub answer_accepted: bool,
}

/// 5b-3: the restarted daemon refuses the instance and the request as a closed session's, and
/// accepts no answer.
pub fn refused_as_a_closed_sessions(read: &AfterTheWorkerEnded) -> Result<(), Red> {
    ensure(
        read.instance_refused && read.request_refused && !read.answer_accepted,
        "5b-3",
    )
}

/// 5b-11: the agent no longer runs after the session was closed.
pub fn ends_with_the_session(agent_runs: bool) -> Result<(), Red> {
    ensure(!agent_runs, "5b-11")
}

/// 5b-4: of the answers given at once, one was accepted and the stand-in received one response.
pub fn one_answer_wins(accepted: usize, record: &[Value]) -> Result<(), Red> {
    ensure(accepted == 1 && responses(record).len() == 1, "5b-4")
}

/// 5b-7: the same request id in a second instance is a second request.
pub fn the_same_id_is_two_requests(listed: usize) -> Result<(), Red> {
    ensure(listed == 2, "5b-7")
}

/// 5b-8: a fresh request after a restart is the one request pending.
pub fn a_fresh_request_appears(pending: usize) -> Result<(), Red> {
    ensure(pending == 1, "5b-8")
}

/// The host, the daemon, the worker and the stand-in a case works with, started through the ACP
/// launch. No launch exists, so no value of this type does, and a case that reaches the end of
/// [`Hosted::start`] has found the launch and not the code that uses it.
pub enum Hosted {}

impl Hosted {
    /// Starts the stand-in with `script` through the launch. When the script has a turn for a
    /// prompt, it sends a prompt and returns once the agent's first request is pending and read;
    /// when the script holds only turns of the agent's own, it returns once the agent runs, and the
    /// case releases the file that starts the turn.
    pub fn start(_script: &Value) -> Result<Self, &'static str> {
        Err(super::NO_BODY)
    }

    /// The four reads of the instance and its pending request.
    pub fn reads(&mut self) -> Reads {
        match *self {}
    }

    /// Kills the daemon alone.
    pub fn kill_daemon(&mut self) {
        match *self {}
    }

    /// Starts the daemon again, with no client that takes anything from the run.
    pub fn restart_daemon(&mut self) {
        match *self {}
    }

    /// Makes the file of the stand-in's working directory that a tick or a hold waits for.
    pub fn release(&mut self, _name: &str) {
        match *self {}
    }

    /// Answers the pending request by choosing `option` through the device.
    pub fn answer(&mut self, _option: &str) {
        match *self {}
    }

    /// Answers the pending request by choosing `option` from `count` devices at once, and returns
    /// how many answers the host accepted.
    pub fn answer_at_once(&mut self, _option: &str, _count: usize) -> usize {
        match *self {}
    }

    /// The stand-in's record, read from its working directory.
    pub fn record(&self) -> Vec<Value> {
        match *self {}
    }

    /// Closes the session and says whether the agent still runs once the close has finished.
    pub fn closes_the_session(&mut self) -> bool {
        match *self {}
    }

    /// Starts a second session of the same host, with `script`, and its first request pending.
    pub fn second_session(&mut self, _script: &Value) {
        match *self {}
    }

    /// Starts a second instance of the agent in the session, with `script`.
    pub fn second_instance(&mut self, _script: &Value) {
        match *self {}
    }

    /// How many requests the host lists as pending for the session.
    pub fn pending_requests(&mut self) -> usize {
        match *self {}
    }

    /// How many requests the host lists for the session, resolved or not.
    pub fn listed_requests(&mut self) -> usize {
        match *self {}
    }

    /// Kills the daemon, then the worker, starts the daemon again, and reads what it says.
    pub fn kills_the_daemon_then_the_worker(&mut self) -> AfterTheWorkerEnded {
        match *self {}
    }
}

/// The script of a turn that calls a tool, waits for the person's answer, runs the tool when it
/// was allowed, and then asks for a second tool after a release, so that a request is fresh after
/// a restart. The agent also ticks while the daemon is down.
pub fn restart_script() -> Value {
    serde_json::json!({
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "when": { "outcome": "allowed", "then": [
                { "update": { "call": "c1", "status": "in_progress" } },
                { "update": { "call": "c1", "status": "completed" } },
            ] } },
            { "hold": "second" },
            { "call": { "id": "c2", "kind": "execute" } },
            { "ask": "c2" },
            { "end": "end_turn" },
        ]],
        "ticks": [{ "after": "tick1", "say": "tick 1" }],
    })
}

/// Cases 5b-1, 5b-2, 5b-11 and 5b-3 in the order of the Codex case: the reads before and after
/// only the daemon's death, the one answer through the restarted daemon, the close that ends the
/// agent, and, in a second session, the kill of the daemon and then the worker.
pub fn a_daemon_killed_with_a_request_pending(host: &mut Hosted) -> Result<(), Red> {
    let before = host.reads();
    host.kill_daemon();
    host.release("tick1");
    host.restart_daemon();
    reads_equal_after_a_restart(&before, &host.reads())?;
    host.answer("allow-once");
    one_reply_with_the_chosen_id(&host.record(), "allow-once")?;
    ends_with_the_session(host.closes_the_session())?;
    host.second_session(&restart_script());
    refused_as_a_closed_sessions(&host.kills_the_daemon_then_the_worker())
}

/// Case 5b-4: two answers at once, and the same answer again after the daemon reconnected.
pub fn two_answers_at_once(host: &mut Hosted) -> Result<(), Red> {
    let accepted = host.answer_at_once("allow-once", 2);
    host.kill_daemon();
    host.restart_daemon();
    host.answer("allow-once");
    one_answer_wins(accepted, &host.record())
}

/// Case 5b-7: a second instance whose first request carries the id of the first instance's.
pub fn the_same_id_in_a_second_instance(host: &mut Hosted) -> Result<(), Red> {
    host.second_instance(&restart_script());
    the_same_id_is_two_requests(host.listed_requests())
}

/// Case 5b-8: a fresh request after a restart.
pub fn a_fresh_request_after_a_restart(host: &mut Hosted) -> Result<(), Red> {
    host.answer("allow-once");
    host.kill_daemon();
    host.restart_daemon();
    host.release("second");
    a_fresh_request_appears(host.pending_requests())
}

/// A record line that is the response to request 0 with the chosen option.
#[cfg(test)]
fn response_line(option: &str) -> Value {
    response_line_for(0, option)
}

/// A record line that is the response to the request numbered `number` with the chosen option.
#[cfg(test)]
fn response_line_for(number: u64, option: &str) -> Value {
    serde_json::json!({ "received": "response", "id": number, "outcome": "selected", "option": option })
}

/// Reads of an instance that are equal.
#[cfg(test)]
fn reads(request: &str) -> Reads {
    Reads {
        instance: "instance".to_owned(),
        binding: "binding".to_owned(),
        identity: "identity".to_owned(),
        request: request.to_owned(),
    }
}

#[test]
fn the_judge_of_the_four_reads_names_its_red_when_the_request_is_gone_after_the_restart() {
    assert_eq!(
        reads_equal_after_a_restart(&reads("pending"), &reads("pending")),
        Ok(())
    );
    assert_eq!(
        reads_equal_after_a_restart(&reads("pending"), &reads("")),
        Err(red("5b-1"))
    );
}

#[test]
fn the_judge_of_one_reply_names_its_red_when_the_answer_reached_the_stand_in_twice() {
    let once = [response_line("allow-once")];
    let twice = [response_line("allow-once"), response_line("allow-once")];
    assert_eq!(one_reply_with_the_chosen_id(&once, "allow-once"), Ok(()));
    assert_eq!(
        one_reply_with_the_chosen_id(&twice, "allow-once"),
        Err(red("5b-2"))
    );
    assert_eq!(
        one_reply_with_the_chosen_id(&once, "reject-once"),
        Err(red("5b-2")),
        "a reply with another id is not the chosen one"
    );
    assert_eq!(
        one_reply_with_the_chosen_id(&[], "allow-once"),
        Err(red("5b-2")),
        "no reply is not one"
    );
}

#[test]
fn the_judge_of_the_closed_session_names_its_red_when_the_answer_is_accepted() {
    let closed = AfterTheWorkerEnded {
        instance_refused: true,
        request_refused: true,
        answer_accepted: false,
    };
    assert_eq!(refused_as_a_closed_sessions(&closed), Ok(()));
    let kept = AfterTheWorkerEnded {
        request_refused: false,
        answer_accepted: true,
        ..closed
    };
    assert_eq!(refused_as_a_closed_sessions(&kept), Err(red("5b-3")));
}

#[test]
fn the_judge_of_the_close_names_its_red_when_the_agent_keeps_running() {
    assert_eq!(ends_with_the_session(false), Ok(()));
    assert_eq!(ends_with_the_session(true), Err(red("5b-11")));
}

#[test]
fn the_judge_of_the_concurrent_answers_names_its_red_when_both_reach_the_stand_in() {
    let once = [response_line("allow-once")];
    let twice = [response_line("allow-once"), response_line("allow-once")];
    assert_eq!(one_answer_wins(1, &once), Ok(()));
    assert_eq!(one_answer_wins(2, &twice), Err(red("5b-4")));
    assert_eq!(
        one_answer_wins(1, &twice),
        Err(red("5b-4")),
        "one accepted answer and two replies at the stand-in is the red too"
    );
}

#[test]
fn the_judges_of_the_requests_name_their_reds_when_the_id_alone_keys_them_or_a_fresh_one_is_dropped()
 {
    assert_eq!(the_same_id_is_two_requests(2), Ok(()));
    assert_eq!(the_same_id_is_two_requests(1), Err(red("5b-7")));
    assert_eq!(a_fresh_request_appears(1), Ok(()));
    assert_eq!(a_fresh_request_appears(0), Err(red("5b-8")));
}

/// What the receipts of the two answers of [`exit_script`] read after the agent exited.
#[derive(Debug)]
pub struct Receipts {
    /// The answer whose agent sent the evidence that it used it first.
    pub confirmed: String,
    /// The answer that no evidence followed.
    pub unproved: String,
}

/// 5b-9: the request of an agent that exited before the answer was dispatched is `Cancelled`.
pub fn cancelled_when_the_agent_exits_first(state: &str) -> Result<(), Red> {
    ensure(state == "Cancelled", "5b-9")
}

/// 5b-10: after the exit the confirmed answer still reads `applied` and the unproved one reads
/// `unknown`.
pub fn the_exit_leaves_a_confirmed_answer_confirmed(receipts: &Receipts) -> Result<(), Red> {
    ensure(
        receipts.confirmed == "applied" && receipts.unproved == "unknown",
        "5b-10",
    )
}

/// 5b-12: the agent no longer runs once the worker's connection to the launcher ended.
pub fn ends_with_the_workers_connection(agent_runs: bool) -> Result<(), Red> {
    ensure(!agent_runs, "5b-12")
}

impl Hosted {
    /// The state the host lists for the pending request: `Pending`, `Resolved` or `Cancelled`.
    pub fn request_state(&mut self) -> String {
        match *self {}
    }

    /// Answers the next pending request by choosing `option`, and waits until the host shows it
    /// dispatched.
    pub fn answer_next(&mut self, _option: &str) {
        match *self {}
    }

    /// The receipts of the two answers of [`exit_script`].
    pub fn receipts(&mut self) -> Receipts {
        match *self {}
    }

    /// Closes the worker's end of the launcher's connection, as only the harness does, and says
    /// whether the agent still runs once the launcher has had time to end it.
    pub fn ends_the_workers_connection(&mut self) -> bool {
        match *self {}
    }
}

/// The script of an agent that asks for a call and is allowed, sends the call's `in_progress`
/// update as evidence, asks for a second call that nothing follows, and exits when told.
pub fn exit_script() -> Value {
    serde_json::json!({
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "when": { "outcome": "allowed", "then": [
                { "update": { "call": "c1", "status": "in_progress" } },
            ] } },
            { "call": { "id": "c2", "kind": "execute" } },
            { "ask": "c2" },
            { "hold": "never" },
        ]],
        "exit_after": "die",
    })
}

/// Case 5b-9: the agent exits with its first request still pending.
pub fn an_agent_exits_before_dispatch(host: &mut Hosted) -> Result<(), Red> {
    host.release("die");
    cancelled_when_the_agent_exits_first(&host.request_state())
}

/// Case 5b-10: the agent exits after one answer it used and one it did not.
pub fn an_agent_exits_after_dispatch(host: &mut Hosted) -> Result<(), Red> {
    host.answer_next("allow-once");
    host.answer_next("allow-once");
    host.release("die");
    the_exit_leaves_a_confirmed_answer_confirmed(&host.receipts())
}

/// Case 5b-12: the worker's connection to the launcher ends.
pub fn the_launcher_ends_the_agent(host: &mut Hosted) -> Result<(), Red> {
    ends_with_the_workers_connection(host.ends_the_workers_connection())
}

#[test]
fn the_judge_of_an_exit_before_dispatch_names_its_red_when_the_request_stays_pending() {
    assert_eq!(cancelled_when_the_agent_exits_first("Cancelled"), Ok(()));
    assert_eq!(
        cancelled_when_the_agent_exits_first("Pending"),
        Err(red("5b-9"))
    );
}

#[test]
fn the_judge_of_an_exit_after_dispatch_names_its_red_when_a_receipt_is_rewritten_or_not() {
    let receipts = |confirmed: &str, unproved: &str| Receipts {
        confirmed: confirmed.to_owned(),
        unproved: unproved.to_owned(),
    };
    assert_eq!(
        the_exit_leaves_a_confirmed_answer_confirmed(&receipts("applied", "unknown")),
        Ok(())
    );
    assert_eq!(
        the_exit_leaves_a_confirmed_answer_confirmed(&receipts("unknown", "unknown")),
        Err(red("5b-10")),
        "the exit rewrote the confirmed answer"
    );
    assert_eq!(
        the_exit_leaves_a_confirmed_answer_confirmed(&receipts("applied", "applied")),
        Err(red("5b-10")),
        "the unproved answer claims applied"
    );
    assert_eq!(
        the_exit_leaves_a_confirmed_answer_confirmed(&receipts("applied", "dispatching")),
        Err(red("5b-10")),
        "the exit left the unproved answer where it was"
    );
}

#[test]
fn the_judge_of_the_workers_connection_names_its_red_when_the_agent_keeps_running() {
    assert_eq!(ends_with_the_workers_connection(false), Ok(()));
    assert_eq!(ends_with_the_workers_connection(true), Err(red("5b-12")));
}

/// How many lines of the record the stand-in sent, of one kind.
fn sent(record: &[Value], kind: &str) -> usize {
    record.iter().filter(|line| line["sent"] == kind).count()
}

/// The outcome of the response to the request numbered `number`, or none when the stand-in
/// received no response to it.
fn outcome_of(record: &[Value], number: u64) -> Option<&str> {
    responses(record)
        .into_iter()
        .find(|line| line["id"] == number)
        .and_then(|line| line["outcome"].as_str())
}

/// What the host told a cancel and an answer that were sent at the same moment.
#[derive(Debug)]
pub struct Race {
    /// The host accepted the cancel.
    pub cancel_accepted: bool,
    /// The host accepted the answer.
    pub answer_accepted: bool,
}

/// 5b-5: of a cancel and an answer that race on one approval, one was accepted and the other was
/// told, and the stand-in's call settled: it received one response and ended its turn.
pub fn one_winner_and_the_call_settles(race: &Race, record: &[Value]) -> Result<(), Red> {
    ensure(
        race.cancel_accepted != race.answer_accepted
            && responses(record).len() == 1
            && sent(record, "reply") == 1,
        "5b-5",
    )
}

/// 5b-6: the request that the stand-in sent after the cancel was answered `cancelled`, and the
/// stand-in's turn of its own ended.
pub fn a_late_request_is_answered_cancelled(record: &[Value]) -> Result<(), Red> {
    ensure(
        outcome_of(record, 1) == Some("cancelled") && sent(record, "turn end") == 1,
        "5b-6",
    )
}

impl Hosted {
    /// Sends the person's cancel through the device.
    pub fn cancel(&mut self) {
        match *self {}
    }

    /// Sends the person's cancel and an answer that chooses `option` at the same moment, each
    /// through a device of its own, and says what the host told each.
    pub fn cancel_and_answer_at_once(&mut self, _option: &str) -> Race {
        match *self {}
    }

    /// The stand-in's record once it holds a line that the stand-in sent of `kind`, or after five
    /// seconds when it holds none.
    pub fn record_after(&mut self, _kind: &str) -> Vec<Value> {
        match *self {}
    }
}

/// The script of an agent that asks for a call and goes on waiting for the answer after a cancel,
/// and then settles the call by the answer it got.
pub fn race_script() -> Value {
    serde_json::json!({
        "cancel": "wait",
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "when": { "outcome": "allowed", "then": [
                { "update": { "call": "c1", "status": "completed" } },
                { "end": "end_turn" },
            ] } },
            { "when": { "outcome": "cancelled", "then": [
                { "update": { "call": "c1", "status": "cancelled" } },
                { "end": "cancelled" },
            ] } },
            { "end": "end_turn" },
        ]],
    })
}

/// The script of an agent that asks for a call and is cancelled, and that sends a second request,
/// after the cancel ended its turn, when the file `late` appears.
pub fn late_request_script() -> Value {
    serde_json::json!({
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "end": "end_turn" },
        ]],
        "on_cancel": [
            { "hold": "late" },
            { "call": { "id": "c2", "kind": "execute" } },
            { "ask": "c2" },
            { "end": "end_turn" },
        ],
    })
}

/// Case 5b-5: a cancel and an answer at once.
pub fn a_cancel_racing_an_approval(host: &mut Hosted) -> Result<(), Red> {
    let race = host.cancel_and_answer_at_once("allow-once");
    one_winner_and_the_call_settles(&race, &host.record_after("reply"))
}

/// Case 5b-6: the person cancels, and the stand-in then sends a request of the cancelled turn.
pub fn a_request_after_a_cancel(host: &mut Hosted) -> Result<(), Red> {
    host.cancel();
    host.release("late");
    a_late_request_is_answered_cancelled(&host.record_after("turn end"))
}

/// A record line that is a response whose outcome is `cancelled`.
#[cfg(test)]
fn cancelled_response_line(number: u64) -> Value {
    serde_json::json!({ "received": "response", "id": number, "outcome": "cancelled", "option": null })
}

/// A record line that the stand-in sent, of one kind.
#[cfg(test)]
fn sent_line(kind: &str) -> Value {
    serde_json::json!({ "sent": kind })
}

#[test]
fn the_judge_of_the_race_names_its_red_when_the_cancel_leaves_the_call_unsettled_or_both_win() {
    let cancel_won = Race {
        cancel_accepted: true,
        answer_accepted: false,
    };
    let answer_won = Race {
        cancel_accepted: false,
        answer_accepted: true,
    };
    let settled_by_cancel = [cancelled_response_line(0), sent_line("reply")];
    let settled_by_answer = [response_line("allow-once"), sent_line("reply")];
    assert_eq!(
        one_winner_and_the_call_settles(&cancel_won, &settled_by_cancel),
        Ok(())
    );
    assert_eq!(
        one_winner_and_the_call_settles(&answer_won, &settled_by_answer),
        Ok(())
    );
    assert_eq!(
        one_winner_and_the_call_settles(&cancel_won, &[]),
        Err(red("5b-5")),
        "the cancel won and did not answer the approval, so the call never settles"
    );
    let both = Race {
        cancel_accepted: true,
        answer_accepted: true,
    };
    assert_eq!(
        one_winner_and_the_call_settles(&both, &settled_by_answer),
        Err(red("5b-5")),
        "the cancel left the approval pending and the answer settled the call, with both accepted"
    );
    let neither = Race {
        cancel_accepted: false,
        answer_accepted: false,
    };
    assert_eq!(
        one_winner_and_the_call_settles(&neither, &settled_by_cancel),
        Err(red("5b-5"))
    );
}

#[test]
fn the_judge_of_a_late_request_names_its_red_when_the_request_is_left_pending() {
    let answered = [
        cancelled_response_line(0),
        cancelled_response_line(1),
        sent_line("turn end"),
    ];
    assert_eq!(a_late_request_is_answered_cancelled(&answered), Ok(()));
    let pending = [cancelled_response_line(0)];
    assert_eq!(
        a_late_request_is_answered_cancelled(&pending),
        Err(red("5b-6")),
        "the late request is left pending and the stand-in's turn never ends"
    );
    let chosen = [
        cancelled_response_line(0),
        response_line_for(1, "allow-once"),
        sent_line("turn end"),
    ];
    assert_eq!(
        a_late_request_is_answered_cancelled(&chosen),
        Err(red("5b-6")),
        "an answer that chooses an option is not the cancelled answer"
    );
}
