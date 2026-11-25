//! What each control of cases 5b and 6b reads and how it judges it.
//!
//! A case gathers an observation through [`Hosted`] and hands it to the judge of its control. A
//! judge returns the control's red, the text the table names, when the observation shows the
//! mutation. Each judge is shown here against an observation that is right and against the
//! observation each mutation of the table makes, with no launch; the mutation itself is run alone
//! on the product by the part that owns the control.

use serde_json::Value;

use super::{Shape, Source, red_of};

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

/// Stops the case when a condition that it relies on does not hold. That failure is not the
/// control's red, because no mutation of the control makes it.
pub fn requires(id: &str, holds: bool, what: &str) {
    assert!(
        holds,
        "{id}: the case cannot show the control, because {what}"
    );
}

/// The script with the field that keeps the agent running when its input closes, as an agent does
/// that does not exit at the end of its input.
pub fn lingering(mut script: Value) -> Value {
    script["survive_end_of_input"] = Value::Bool(true);
    script
}

/// The integration mode and the launch profile of an agent that the ACP launch started.
pub const ACP: &str = "acp";

/// What the host says of the agent a case started: the integration mode of its instance and the
/// launch profile that was recorded for it.
#[derive(Debug)]
pub struct Launch {
    /// The instance's integration mode.
    pub mode: String,
    /// The launch profile recorded for the instance.
    pub profile: String,
}

/// Says why the agent a case started was not started through the ACP launch, or returns none when
/// it was: its instance has the ACP mode and the ACP launch profile, and its record holds the
/// `initialize` request and then the `session/new` request.
pub fn why_not_an_acp_launch(launch: &Launch, record: &[Value]) -> Option<String> {
    if launch.mode != ACP {
        return Some(format!(
            "the instance's mode is `{}`, not `{ACP}`",
            launch.mode
        ));
    }
    if launch.profile != ACP {
        return Some(format!(
            "the instance's launch profile is `{}`, not `{ACP}`",
            launch.profile
        ));
    }
    let methods: Vec<&str> = record
        .iter()
        .filter(|line| line["received"] == "request")
        .filter_map(|line| line["method"].as_str())
        .collect();
    let at = |method: &str| methods.iter().position(|held| *held == method);
    match (at("initialize"), at("session/new")) {
        (Some(first), Some(second)) if first < second => None,
        (None, _) => Some("the record holds no `initialize` request".to_owned()),
        (_, None) => Some("the record holds no `session/new` request".to_owned()),
        _ => Some("the record holds `session/new` before `initialize`".to_owned()),
    }
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
    /// Starts the stand-in of `shape` with `script` through the launch: the native program for
    /// Qoder, and for Gemini the script package that the interpreter stand-in runs. `source` says
    /// where it runs from: the verified copy, as every agent the host starts does, or the
    /// installation itself, as only the harness can start it. When the script holds no turn of the
    /// agent's own, it sends a prompt and returns once the agent's first request is pending and
    /// read; when it holds one, it returns once the agent runs, and the case releases the file that
    /// starts the turn and sends the prompts it needs.
    pub fn start(_shape: Shape, _source: Source, _script: &Value) -> Result<Self, &'static str> {
        Err(super::NO_HOST)
    }

    /// The integration mode and the launch profile the host lists for the instance.
    pub fn launch(&mut self) -> Launch {
        match *self {}
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

    /// The stand-in's record, read after five seconds, so that a second forward of an answer that
    /// arrives late is in it.
    pub fn record_after_quiet(&mut self) -> Vec<Value> {
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
    host.answer("proceed_once");
    one_reply_with_the_chosen_id(&host.record_after_quiet(), "proceed_once")?;
    requires(
        "5b-11",
        host.agent_runs(),
        "the agent does not run just before the session is closed",
    );
    ends_with_the_session(host.closes_the_session())?;
    host.second_session(&lingering(restart_script()));
    refused_as_a_closed_sessions(&host.kills_the_daemon_then_the_worker())
}

/// Case 5b-4: two answers at once, and the same answer again after the daemon reconnected.
pub fn two_answers_at_once(host: &mut Hosted) -> Result<(), Red> {
    let accepted = host.answer_at_once("proceed_once", 2);
    host.kill_daemon();
    host.restart_daemon();
    host.answer("proceed_once");
    one_answer_wins(accepted, &host.record_after_quiet())
}

/// Case 5b-7: a second instance whose first request carries the id of the first instance's.
pub fn the_same_id_in_a_second_instance(host: &mut Hosted) -> Result<(), Red> {
    host.second_instance(&restart_script());
    the_same_id_is_two_requests(host.listed_requests())
}

/// Case 5b-8: a fresh request after a restart.
pub fn a_fresh_request_after_a_restart(host: &mut Hosted) -> Result<(), Red> {
    host.answer("proceed_once");
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
    let once = [response_line("proceed_once")];
    let twice = [response_line("proceed_once"), response_line("proceed_once")];
    assert_eq!(one_reply_with_the_chosen_id(&once, "proceed_once"), Ok(()));
    assert_eq!(
        one_reply_with_the_chosen_id(&twice, "proceed_once"),
        Err(red("5b-2"))
    );
    assert_eq!(
        one_reply_with_the_chosen_id(&once, "cancel"),
        Err(red("5b-2")),
        "a reply with another id is not the chosen one"
    );
    assert_eq!(
        one_reply_with_the_chosen_id(&[], "proceed_once"),
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
    let once = [response_line("proceed_once")];
    let twice = [response_line("proceed_once"), response_line("proceed_once")];
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

/// 5b-10 and 5b-10g, by `id`: after the exit the confirmed answer still reads `applied` and the
/// unproved one reads `unknown`.
pub fn the_exit_leaves_a_confirmed_answer_confirmed(
    id: &str,
    receipts: &Receipts,
) -> Result<(), Red> {
    ensure(
        receipts.confirmed == "applied" && receipts.unproved == "unknown",
        id,
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
    /// whether the agent still runs once the launcher has had time to end it. The step does not
    /// start the worker's ending ladder, so only the launcher can end the agent.
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
    exits_after_two_answers("5b-10", host)
}

/// Case 5b-10g: the same case with the Gemini-shaped agent.
pub fn a_gemini_shaped_agent_exits_after_dispatch(host: &mut Hosted) -> Result<(), Red> {
    exits_after_two_answers("5b-10g", host)
}

/// The agent exits after one answer it used and one it did not, and the control `id` judges the
/// receipts.
fn exits_after_two_answers(id: &str, host: &mut Hosted) -> Result<(), Red> {
    host.answer_next("proceed_once");
    host.answer_next("proceed_once");
    host.release("die");
    the_exit_leaves_a_confirmed_answer_confirmed(id, &host.receipts())
}

/// Case 5b-12: the worker's connection to the launcher ends.
pub fn the_launcher_ends_the_agent(host: &mut Hosted) -> Result<(), Red> {
    requires(
        "5b-12",
        host.agent_runs(),
        "the agent does not run before the worker's end is closed",
    );
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
    for id in ["5b-10", "5b-10g"] {
        assert_eq!(
            the_exit_leaves_a_confirmed_answer_confirmed(id, &receipts("applied", "unknown")),
            Ok(())
        );
        assert_eq!(
            the_exit_leaves_a_confirmed_answer_confirmed(id, &receipts("unknown", "unknown")),
            Err(red(id)),
            "the exit rewrote the confirmed answer"
        );
        assert_eq!(
            the_exit_leaves_a_confirmed_answer_confirmed(id, &receipts("applied", "applied")),
            Err(red(id)),
            "the unproved answer claims applied"
        );
        assert_eq!(
            the_exit_leaves_a_confirmed_answer_confirmed(id, &receipts("applied", "dispatching")),
            Err(red(id)),
            "the exit left the unproved answer where it was"
        );
    }
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
    let race = host.cancel_and_answer_at_once("proceed_once");
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
    let settled_by_answer = [response_line("proceed_once"), sent_line("reply")];
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
        response_line_for(1, "proceed_once"),
        sent_line("turn end"),
    ];
    assert_eq!(
        a_late_request_is_answered_cancelled(&chosen),
        Err(red("5b-6")),
        "an answer that chooses an option is not the cancelled answer"
    );
}

/// 5b-14: the stand-in aborted the call and the prompt after the answer was dispatched, with no
/// evidence that it took the answer, so the receipt reads `unknown`.
pub fn an_abort_leaves_the_receipt_unknown(receipt: &str) -> Result<(), Red> {
    ensure(receipt == "unknown", "5b-14")
}

/// What the host holds of an answered request of a turn of the agent's own after the deadline of
/// 300 seconds, with no traffic and a live agent.
#[derive(Debug)]
pub struct AtTheDeadline {
    /// The receipt of the answer.
    pub receipt: String,
    /// The host still holds the bytes of the request the answer was made from.
    pub source_bytes_remain: bool,
    /// The agent's process still runs.
    pub agent_runs: bool,
}

/// 5b-20: at the deadline the receipt reads `unknown`, the source bytes are gone and the agent
/// still runs.
pub fn the_deadline_leaves_the_receipt_unknown(held: &AtTheDeadline) -> Result<(), Red> {
    ensure(
        held.receipt == "unknown" && !held.source_bytes_remain && held.agent_runs,
        "5b-20",
    )
}

/// 5b-21: after a decline and the call's `failed` update the receipt reads `unknown`.
pub fn a_failed_update_leaves_a_decline_unknown(receipt: &str) -> Result<(), Red> {
    ensure(receipt == "unknown", "5b-21")
}

/// 5b-22: the receipt read `unknown` after the deadline, and `applied` after the late update.
pub fn a_late_update_moves_unknown_to_applied(before: &str, after: &str) -> Result<(), Red> {
    ensure(before == "unknown" && after == "applied", "5b-22")
}

/// 5b-23 and 5b-23g, by `id`: a `completed` update that arrived after a cancel left the receipt
/// `applied`.
pub fn an_allow_stays_applied_after_a_cancel(id: &str, receipt: &str) -> Result<(), Red> {
    ensure(receipt == "applied", id)
}

impl Hosted {
    /// Waits until the host lists a pending request.
    pub fn waits_for_a_request(&mut self) {
        match *self {}
    }

    /// Advances the service's clock by `seconds` and gives the host time to act on it.
    pub fn advance_clock(&mut self, _seconds: u64) {
        match *self {}
    }

    /// The receipt of the request the case answered last, once it reads `wanted`, or what it reads
    /// after five seconds when it never does.
    pub fn receipt_becoming(&mut self, _wanted: &str) -> String {
        match *self {}
    }

    /// Whether the host still holds the bytes of the request the answered request was made from.
    pub fn source_bytes_remain(&mut self) -> bool {
        match *self {}
    }

    /// Whether the agent's process still runs.
    pub fn agent_runs(&mut self) -> bool {
        match *self {}
    }
}

/// The script of an agent that asks for a call and, after the answer, aborts the call and the turn
/// of its prompt: it sends the call's `cancelled` update and then the prompt's reply with the stop
/// reason `cancelled`.
pub fn abort_script() -> Value {
    serde_json::json!({
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "update": { "call": "c1", "status": "cancelled" } },
            { "end": "cancelled" },
        ]],
    })
}

/// The script of a turn of the agent's own that asks for a call and then sends nothing.
pub fn silent_script() -> Value {
    serde_json::json!({
        "own": [{ "after": "go", "steps": [
            { "say": "own" },
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "hold": "never" },
        ] }],
    })
}

/// The script of a turn of the agent's own that sends the call's `failed` update after a decline.
pub fn failed_script() -> Value {
    serde_json::json!({
        "own": [{ "after": "go", "steps": [
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "when": { "outcome": "declined", "then": [
                { "update": { "call": "c1", "status": "failed" } },
            ] } },
            { "hold": "never" },
        ] }],
    })
}

/// The script of a turn of the agent's own that sends the call's `in_progress` update only when
/// the file `late` appears after an allow.
pub fn late_update_script() -> Value {
    serde_json::json!({
        "own": [{ "after": "go", "steps": [
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "when": { "outcome": "allowed", "then": [
                { "hold": "late" },
                { "update": { "call": "c1", "status": "in_progress" } },
            ] } },
            { "hold": "never" },
        ] }],
    })
}

/// The script of an agent that is cancelled after an allow and sends the call's `completed` update
/// only when the file `done` appears, after the cancel ended its turn.
pub fn completed_after_a_cancel_script() -> Value {
    serde_json::json!({
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "hold": "never" },
        ]],
        "on_cancel": [
            { "hold": "done" },
            { "update": { "call": "c1", "status": "completed" } },
        ],
    })
}

/// Case 5b-14: the agent aborts the call after the answer.
pub fn an_abort_after_the_answer(host: &mut Hosted) -> Result<(), Red> {
    host.answer_next("proceed_once");
    an_abort_leaves_the_receipt_unknown(&host.receipt_becoming("unknown"))
}

/// Case 5b-20: an answered request of a turn of the agent's own, and 300 seconds with no traffic.
pub fn an_answer_and_three_hundred_seconds(host: &mut Hosted) -> Result<(), Red> {
    host.release("go");
    host.waits_for_a_request();
    host.answer_next("proceed_once");
    host.advance_clock(300);
    let receipt = host.receipt_becoming("unknown");
    the_deadline_leaves_the_receipt_unknown(&AtTheDeadline {
        receipt,
        source_bytes_remain: host.source_bytes_remain(),
        agent_runs: host.agent_runs(),
    })
}

/// Case 5b-21: a decline in a turn of the agent's own, and the call's `failed` update.
pub fn a_decline_and_a_failed_update(host: &mut Hosted) -> Result<(), Red> {
    host.release("go");
    host.waits_for_a_request();
    host.answer_next("cancel");
    a_failed_update_leaves_a_decline_unknown(&host.receipt_becoming("unknown"))
}

/// Case 5b-22: an allow in a turn of the agent's own, the deadline, and then an `in_progress`
/// update.
pub fn an_allow_a_deadline_and_a_late_update(host: &mut Hosted) -> Result<(), Red> {
    host.release("go");
    host.waits_for_a_request();
    host.answer_next("proceed_once");
    host.advance_clock(301);
    let before = host.receipt_becoming("unknown");
    host.release("late");
    a_late_update_moves_unknown_to_applied(&before, &host.receipt_becoming("applied"))
}

/// Case 5b-23: an allow, the person's cancel, and then the call's `completed` update.
pub fn a_completed_update_after_a_cancel(host: &mut Hosted) -> Result<(), Red> {
    host.answer_next("proceed_once");
    host.cancel();
    host.release("done");
    an_allow_stays_applied_after_a_cancel("5b-23", &host.receipt_becoming("applied"))
}

/// Every script of the cases in this file.
#[cfg(test)]
fn scripts() -> Vec<(&'static str, Value)> {
    vec![
        ("restart_script", restart_script()),
        ("lingering_restart_script", lingering(restart_script())),
        ("exit_script", exit_script()),
        ("lingering_exit_script", lingering(exit_script())),
        ("race_script", race_script()),
        ("late_request_script", late_request_script()),
        ("abort_script", abort_script()),
        ("silent_script", silent_script()),
        ("failed_script", failed_script()),
        ("late_update_script", late_update_script()),
        (
            "completed_after_a_cancel_script",
            completed_after_a_cancel_script(),
        ),
        (
            "late_request_of_a_waiting_agent_script",
            late_request_of_a_waiting_agent_script(),
        ),
        ("decline_script", decline_script()),
        ("thirty_one_seconds_script", thirty_one_seconds_script()),
        (
            "completed_while_cancelling_script",
            completed_while_cancelling_script(),
        ),
        ("upgrade_script", upgrade_script()),
        ("chunk_script", chunk_script()),
        ("window_script", window_script()),
        ("queued_prompt_script", queued_prompt_script()),
        (
            "prompt_after_a_cancel_script",
            prompt_after_a_cancel_script(),
        ),
    ]
}

#[test]
fn the_check_of_the_launch_names_what_makes_a_start_no_acp_launch() {
    let launch = |mode: &str, profile: &str| Launch {
        mode: mode.to_owned(),
        profile: profile.to_owned(),
    };
    let request = |method: &str| serde_json::json!({ "received": "request", "method": method });
    let record = [request("initialize"), request("session/new")];
    assert_eq!(why_not_an_acp_launch(&launch(ACP, ACP), &record), None);
    let why = |launch: &Launch, record: &[Value]| why_not_an_acp_launch(launch, record);
    assert_eq!(
        why(&launch("terminal", ACP), &record).as_deref(),
        Some("the instance's mode is `terminal`, not `acp`")
    );
    assert_eq!(
        why(&launch(ACP, "default"), &record).as_deref(),
        Some("the instance's launch profile is `default`, not `acp`")
    );
    assert_eq!(
        why(&launch(ACP, ACP), &record[1..]).as_deref(),
        Some("the record holds no `initialize` request")
    );
    assert_eq!(
        why(&launch(ACP, ACP), &record[..1]).as_deref(),
        Some("the record holds no `session/new` request")
    );
    let reversed = [request("session/new"), request("initialize")];
    assert_eq!(
        why(&launch(ACP, ACP), &reversed).as_deref(),
        Some("the record holds `session/new` before `initialize`")
    );
    let not_a_request = [
        request("initialize"),
        serde_json::json!({ "received": "notification", "method": "session/new" }),
    ];
    assert_eq!(
        why(&launch(ACP, ACP), &not_a_request).as_deref(),
        Some("the record holds no `session/new` request"),
        "a notification is no request"
    );
}

#[test]
fn a_lingering_script_keeps_every_field_of_its_script_and_sets_the_one_that_keeps_the_agent_alive()
{
    let script = lingering(exit_script());
    assert_eq!(script["survive_end_of_input"], true);
    assert_eq!(script["exit_after"], exit_script()["exit_after"]);
    assert_eq!(script["turns"], exit_script()["turns"]);
    assert!(
        exit_script().get("survive_end_of_input").is_none(),
        "a script that is not made to linger does not"
    );
}

#[test]
fn a_condition_that_holds_stops_no_case() {
    requires("5b-11", true, "the agent runs");
}

#[test]
#[should_panic(expected = "5b-11: the case cannot show the control, because the agent runs")]
fn a_condition_that_fails_stops_the_case_and_names_why() {
    requires("5b-11", false, "the agent runs");
}

#[test]
fn the_scripts_of_the_cases_are_scripts_the_stand_in_reads() {
    for (name, script) in scripts() {
        if let Err(why) = kr_e2e_agents::acp_agent::check_script(&script) {
            panic!("{name} is not a script of the stand-in: {why}");
        }
    }
}

#[test]
fn the_judge_of_an_abort_names_its_red_when_the_receipt_reads_applied() {
    assert_eq!(an_abort_leaves_the_receipt_unknown("unknown"), Ok(()));
    assert_eq!(
        an_abort_leaves_the_receipt_unknown("applied"),
        Err(red("5b-14")),
        "the reply or the cancelled update was counted as evidence"
    );
    assert_eq!(
        an_abort_leaves_the_receipt_unknown("dispatching"),
        Err(red("5b-14")),
        "the abort did not settle the answer"
    );
}

#[test]
fn the_judge_of_the_deadline_names_its_red_when_the_answer_waits_for_the_agents_exit() {
    let held = |receipt: &str, source_bytes_remain: bool, agent_runs: bool| AtTheDeadline {
        receipt: receipt.to_owned(),
        source_bytes_remain,
        agent_runs,
    };
    assert_eq!(
        the_deadline_leaves_the_receipt_unknown(&held("unknown", false, true)),
        Ok(())
    );
    assert_eq!(
        the_deadline_leaves_the_receipt_unknown(&held("dispatching", true, true)),
        Err(red("5b-20")),
        "the answer waits for the agent's exit"
    );
    assert_eq!(
        the_deadline_leaves_the_receipt_unknown(&held("unknown", true, true)),
        Err(red("5b-20")),
        "the receipt moved but the source bytes remain"
    );
    assert_eq!(
        the_deadline_leaves_the_receipt_unknown(&held("unknown", false, false)),
        Err(red("5b-20")),
        "the agent was ended to settle the answer"
    );
}

#[test]
fn the_judge_of_a_failed_update_names_its_red_when_the_receipt_stays_dispatching() {
    assert_eq!(a_failed_update_leaves_a_decline_unknown("unknown"), Ok(()));
    assert_eq!(
        a_failed_update_leaves_a_decline_unknown("dispatching"),
        Err(red("5b-21")),
        "the terminal result of the call is ignored"
    );
}

#[test]
fn the_judge_of_a_late_update_names_its_red_when_the_receipt_stays_unknown() {
    assert_eq!(
        a_late_update_moves_unknown_to_applied("unknown", "applied"),
        Ok(())
    );
    assert_eq!(
        a_late_update_moves_unknown_to_applied("unknown", "unknown"),
        Err(red("5b-22")),
        "the late update is ignored"
    );
    assert_eq!(
        a_late_update_moves_unknown_to_applied("dispatching", "applied"),
        Err(red("5b-22")),
        "the deadline did not settle the answer first"
    );
}

#[test]
fn the_judge_of_a_completed_update_names_its_red_when_the_receipt_reads_unknown() {
    for id in ["5b-23", "5b-23g"] {
        assert_eq!(an_allow_stays_applied_after_a_cancel(id, "applied"), Ok(()));
        assert_eq!(
            an_allow_stays_applied_after_a_cancel(id, "unknown"),
            Err(red(id)),
            "every update after a cancel is ignored"
        );
        assert_eq!(
            an_allow_stays_applied_after_a_cancel(id, "dispatching"),
            Err(red(id))
        );
    }
}

/// How many `session/cancel` notifications the stand-in received.
fn cancels(record: &[Value]) -> usize {
    record
        .iter()
        .filter(|line| line["received"] == "notification" && line["method"] == "session/cancel")
        .count()
}

/// 5b-15: the person's cancel, 11 seconds after the agent's last traffic, reached the stand-in as
/// `session/cancel`, and the pending approval was answered `cancelled`.
pub fn a_cancel_after_eleven_seconds_reaches_the_agent(record: &[Value]) -> Result<(), Red> {
    ensure(
        cancels(record) == 1 && outcome_of(record, 0) == Some("cancelled"),
        "5b-15",
    )
}

/// 5b-16: the approval at 29 seconds after the cancel was answered `cancelled`, and the approval at
/// 31 seconds got no answer and is listed as pending.
pub fn the_window_closes_thirty_seconds_after_the_cancel(
    record: &[Value],
    pending: usize,
) -> Result<(), Red> {
    ensure(
        outcome_of(record, 1) == Some("cancelled")
            && outcome_of(record, 2).is_none()
            && pending == 1,
        "5b-16",
    )
}

/// 5b-18: the request that the old turn sent after our prompt was answered `cancelled` was itself
/// answered `cancelled`.
pub fn a_prompt_answered_cancelled_leaves_the_window_open(record: &[Value]) -> Result<(), Red> {
    ensure(outcome_of(record, 1) == Some("cancelled"), "5b-18")
}

/// 5b-19: the approval of a prompt sent after the cancel got no answer and is listed as pending.
pub fn a_prompt_after_a_cancel_shows_its_approval(
    record: &[Value],
    pending: usize,
) -> Result<(), Red> {
    ensure(outcome_of(record, 1).is_none() && pending == 1, "5b-19")
}

impl Hosted {
    /// Sends a prompt through the device and waits until the stand-in's record shows that it
    /// received it.
    pub fn send_prompt(&mut self, _text: &str) {
        match *self {}
    }

    /// The stand-in's record once it holds the response to the request numbered `number`, or after
    /// five seconds when it never does.
    pub fn record_after_response(&mut self, _number: u64) -> Vec<Value> {
        match *self {}
    }
}

/// The script of the agent of 5b-16: a turn of its own that asks for a call, goes on waiting for
/// the answer after a cancel, and asks for a second call when the file `t29` appears and for a
/// third when the file `t31` appears. Six ticks, one for each file `tick1` to `tick6`, are the
/// traffic that goes on meanwhile.
pub fn window_script() -> Value {
    let ticks: Vec<Value> = (1..=6)
        .map(|number| {
            serde_json::json!({
                "after": format!("tick{number}"),
                "say": format!("tick {number}"),
            })
        })
        .collect();
    serde_json::json!({
        "cancel": "wait",
        "own": [{ "after": "go", "steps": [
            { "say": "own" },
            { "call": { "id": "c0", "kind": "execute" } },
            { "ask": "c0" },
            { "hold": "t29" },
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "hold": "t31" },
            { "call": { "id": "c2", "kind": "execute" } },
            { "ask": "c2" },
            { "hold": "never" },
        ] }],
        "ticks": ticks,
    })
}

/// The script of the agent of 5b-18: a turn of its own that asks for a call and waits, a prompt of
/// ours that waits behind it, and, after the cancel, a request of the old turn when the file `late`
/// appears.
pub fn queued_prompt_script() -> Value {
    serde_json::json!({
        "own": [{ "after": "go", "steps": [
            { "say": "own" },
            { "call": { "id": "c0", "kind": "execute" } },
            { "ask": "c0" },
            { "hold": "never" },
        ] }],
        "turns": [[{ "say": "ours" }, { "end": "end_turn" }]],
        "on_cancel": [
            { "hold": "late" },
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "end": "end_turn" },
        ],
    })
}

/// The script of the agent of 5b-19: a turn of its own that asks for a call and waits, and a turn
/// for a prompt of ours that asks for a second call.
pub fn prompt_after_a_cancel_script() -> Value {
    serde_json::json!({
        "own": [{ "after": "go", "steps": [
            { "say": "own" },
            { "call": { "id": "c0", "kind": "execute" } },
            { "ask": "c0" },
            { "hold": "never" },
        ] }],
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "end": "end_turn" },
        ]],
    })
}

/// Case 5b-15: 11 seconds with no traffic after a request, and then the person's cancel.
pub fn a_cancel_after_eleven_quiet_seconds(host: &mut Hosted) -> Result<(), Red> {
    host.release("go");
    host.waits_for_a_request();
    host.advance_clock(11);
    host.cancel();
    a_cancel_after_eleven_seconds_reaches_the_agent(&host.record_after_response(0))
}

/// Case 5b-16: a cancel, traffic every 5 seconds, and a request at 29 seconds and one at 31.
pub fn approvals_at_twenty_nine_and_thirty_one_seconds(host: &mut Hosted) -> Result<(), Red> {
    host.release("go");
    host.waits_for_a_request();
    host.cancel();
    for tick in 1..=5 {
        host.advance_clock(5);
        host.release(&format!("tick{tick}"));
    }
    host.advance_clock(4);
    host.release("t29");
    let _ = host.record_after_response(1);
    host.advance_clock(2);
    host.release("tick6");
    host.release("t31");
    let record = host.record_after_response(2);
    the_window_closes_thirty_seconds_after_the_cancel(&record, host.pending_requests())
}

/// Case 5b-18: a prompt of ours waits behind a turn of the agent's own, the cancel answers it
/// `cancelled`, and the old turn sends a request 3 seconds later.
pub fn a_prompt_answered_cancelled_while_the_old_turn_goes_on(
    host: &mut Hosted,
) -> Result<(), Red> {
    host.release("go");
    host.waits_for_a_request();
    host.send_prompt("ours");
    host.cancel();
    host.advance_clock(3);
    host.release("late");
    a_prompt_answered_cancelled_leaves_the_window_open(&host.record_after_response(1))
}

/// Case 5b-19: a cancel, and a prompt of ours 5 seconds later whose turn asks for a call.
pub fn a_prompt_five_seconds_after_a_cancel(host: &mut Hosted) -> Result<(), Red> {
    host.release("go");
    host.waits_for_a_request();
    host.cancel();
    host.advance_clock(5);
    host.send_prompt("again");
    let record = host.record_after_response(1);
    a_prompt_after_a_cancel_shows_its_approval(&record, host.pending_requests())
}

/// A record line that is a `session/cancel` the stand-in received.
#[cfg(test)]
fn cancel_line() -> Value {
    serde_json::json!({ "received": "notification", "method": "session/cancel" })
}

#[test]
fn the_judge_of_a_quiet_cancel_names_its_red_when_the_stand_in_sees_no_cancel() {
    let answered = [cancel_line(), cancelled_response_line(0)];
    assert_eq!(
        a_cancel_after_eleven_seconds_reaches_the_agent(&answered),
        Ok(())
    );
    assert_eq!(
        a_cancel_after_eleven_seconds_reaches_the_agent(&[]),
        Err(red("5b-15")),
        "a quiet period of 10 seconds closed the turn and the cancel was refused as stale"
    );
    assert_eq!(
        a_cancel_after_eleven_seconds_reaches_the_agent(&[cancel_line()]),
        Err(red("5b-15")),
        "the pending approval was not answered"
    );
}

#[test]
fn the_judge_of_the_window_names_its_red_when_it_stays_open_while_traffic_goes_on() {
    let closed = [cancelled_response_line(0), cancelled_response_line(1)];
    assert_eq!(
        the_window_closes_thirty_seconds_after_the_cancel(&closed, 1),
        Ok(())
    );
    let open = [
        cancelled_response_line(0),
        cancelled_response_line(1),
        cancelled_response_line(2),
    ];
    assert_eq!(
        the_window_closes_thirty_seconds_after_the_cancel(&open, 0),
        Err(red("5b-16")),
        "the approval at 31 seconds was answered cancelled"
    );
    assert_eq!(
        the_window_closes_thirty_seconds_after_the_cancel(&closed[..1], 2),
        Err(red("5b-16")),
        "the approval at 29 seconds was not answered cancelled"
    );
    assert_eq!(
        the_window_closes_thirty_seconds_after_the_cancel(&closed, 0),
        Err(red("5b-16")),
        "the approval at 31 seconds is not listed"
    );
}

#[test]
fn the_judge_of_a_queued_prompt_names_its_red_when_the_late_request_shows() {
    let answered = [cancelled_response_line(0), cancelled_response_line(1)];
    assert_eq!(
        a_prompt_answered_cancelled_leaves_the_window_open(&answered),
        Ok(())
    );
    assert_eq!(
        a_prompt_answered_cancelled_leaves_the_window_open(&answered[..1]),
        Err(red("5b-18")),
        "the window closed at the reply to our prompt, so the request at 3 seconds shows"
    );
}

#[test]
fn the_judge_of_a_prompt_after_a_cancel_names_its_red_when_its_approval_is_answered_cancelled() {
    let shown = [cancelled_response_line(0)];
    assert_eq!(
        a_prompt_after_a_cancel_shows_its_approval(&shown, 1),
        Ok(())
    );
    let answered = [cancelled_response_line(0), cancelled_response_line(1)];
    assert_eq!(
        a_prompt_after_a_cancel_shows_its_approval(&answered, 0),
        Err(red("5b-19")),
        "the window ignored the dispatch of the prompt and stayed open"
    );
    assert_eq!(
        a_prompt_after_a_cancel_shows_its_approval(&shown, 0),
        Err(red("5b-19")),
        "the approval of the prompt is not listed"
    );
}

/// 5b-6g: the request that the Gemini-shaped stand-in sent after the cancel was answered
/// `cancelled`, and the stand-in's turn ended with the reply to our prompt.
pub fn a_late_request_of_a_waiting_agent_is_answered_cancelled(
    record: &[Value],
) -> Result<(), Red> {
    ensure(
        outcome_of(record, 1) == Some("cancelled") && sent(record, "reply") == 1,
        "5b-6g",
    )
}

/// What the receipts of three declined requests read, first once each was dispatched and then once
/// its boundary came: the deadline of 300 seconds for the first, the agent's next request for the
/// second and the agent's reply for the third.
#[derive(Debug)]
pub struct Declines {
    /// The receipt of each decline once it was dispatched.
    pub dispatched: [String; 3],
    /// The receipt of each decline once its boundary came.
    pub settled: [String; 3],
}

/// 5b-13: a Gemini-shaped agent sends no update after a decline, so each receipt stays
/// `dispatching` until its boundary. The first reads `unknown` at the deadline. The second reads
/// `applied` at the agent's next request and the third at its reply, because no cancel followed
/// either dispatch and so both are evidence for a decline.
pub fn a_decline_stays_dispatching_until_a_boundary(read: &Declines) -> Result<(), Red> {
    ensure(
        read.dispatched
            .iter()
            .all(|receipt| receipt == "dispatching")
            && read.settled == ["unknown", "applied", "applied"],
        "5b-13",
    )
}

/// 5b-17: with our prompt in flight the window was still open at 31 seconds, so the approval at
/// that time was answered `cancelled`, and a prompt sent meanwhile was refused.
pub fn the_window_stays_open_until_the_prompts_reply(
    record: &[Value],
    prompt_refused: bool,
) -> Result<(), Red> {
    ensure(
        outcome_of(record, 1) == Some("cancelled") && prompt_refused,
        "5b-17",
    )
}

impl Hosted {
    /// Sends a prompt through the device and says whether the host accepted it.
    pub fn sends_a_prompt(&mut self, _text: &str) -> bool {
        match *self {}
    }
}

/// The script of a Gemini-shaped agent that asks for a call, goes on waiting for the answer after
/// a cancel, and sends a request of its own accord when the file `late` appears, before it ends
/// the turn of our prompt `cancelled`.
pub fn late_request_of_a_waiting_agent_script() -> Value {
    serde_json::json!({
        "cancel": "wait",
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "hold": "late" },
            { "call": { "id": "c2", "kind": "execute" } },
            { "ask": "c2" },
            { "end": "cancelled" },
        ]],
    })
}

/// The script of a Gemini-shaped agent that sends no update after a decline: it asks for a call,
/// asks for a second when the file `second` appears and for a third when the file `third` appears,
/// and replies to the prompt when the file `reply` appears.
pub fn decline_script() -> Value {
    serde_json::json!({
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "hold": "second" },
            { "call": { "id": "c2", "kind": "execute" } },
            { "ask": "c2" },
            { "hold": "third" },
            { "call": { "id": "c3", "kind": "execute" } },
            { "ask": "c3" },
            { "hold": "reply" },
            { "end": "end_turn" },
        ]],
    })
}

/// The script of a Gemini-shaped agent that asks for a call, goes on waiting for the answer after a
/// cancel, asks for a second call when the file `t31` appears, and then ends the turn `cancelled`.
pub fn thirty_one_seconds_script() -> Value {
    serde_json::json!({
        "cancel": "wait",
        "turns": [[
            { "call": { "id": "c0", "kind": "execute" } },
            { "ask": "c0" },
            { "hold": "t31" },
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "end": "cancelled" },
        ]],
    })
}

/// The script of a Gemini-shaped agent that asks for a call, goes on waiting after a cancel, and
/// sends the call's `completed` update when the file `done` appears.
pub fn completed_while_cancelling_script() -> Value {
    serde_json::json!({
        "cancel": "wait",
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "hold": "done" },
            { "update": { "call": "c1", "status": "completed" } },
            { "end": "cancelled" },
        ]],
    })
}

/// Case 5b-6g: the person cancels, and the Gemini-shaped agent then sends a request of the turn
/// the cancel did not end.
pub fn a_request_after_a_cancel_of_a_waiting_agent(host: &mut Hosted) -> Result<(), Red> {
    host.cancel();
    host.release("late");
    a_late_request_of_a_waiting_agent_is_answered_cancelled(&host.record_after("reply"))
}

/// Case 5b-13: three declines, and what each receipt reads at its boundary: 300 seconds for the
/// first, the agent's next request for the second and its reply for the third.
pub fn three_declines_and_no_update(host: &mut Hosted) -> Result<(), Red> {
    host.answer_next("cancel");
    let first = host.receipt_becoming("applied");
    host.advance_clock(300);
    let first_settled = host.receipt_becoming("unknown");
    host.release("second");
    host.waits_for_a_request();
    host.answer_next("cancel");
    let second = host.receipt_becoming("applied");
    host.release("third");
    host.waits_for_a_request();
    let second_settled = host.receipt_becoming("applied");
    host.answer_next("cancel");
    let third = host.receipt_becoming("applied");
    host.release("reply");
    let third_settled = host.receipt_becoming("applied");
    a_decline_stays_dispatching_until_a_boundary(&Declines {
        dispatched: [first, second, third],
        settled: [first_settled, second_settled, third_settled],
    })
}

/// Case 5b-17: a cancel with our prompt in flight, 31 seconds, a prompt of ours, and then a request
/// of the agent's.
pub fn an_approval_at_thirty_one_seconds_with_a_prompt_in_flight(
    host: &mut Hosted,
) -> Result<(), Red> {
    host.cancel();
    host.advance_clock(31);
    let refused = !host.sends_a_prompt("meanwhile");
    host.release("t31");
    the_window_stays_open_until_the_prompts_reply(&host.record_after("reply"), refused)
}

/// Case 5b-23g: an allow, the person's cancel, and then the call's `completed` update, with the
/// Gemini-shaped agent.
pub fn a_completed_update_after_a_cancel_of_a_waiting_agent(host: &mut Hosted) -> Result<(), Red> {
    host.answer_next("proceed_once");
    host.cancel();
    host.release("done");
    an_allow_stays_applied_after_a_cancel("5b-23g", &host.receipt_becoming("applied"))
}

#[test]
fn the_judge_of_a_late_request_of_a_waiting_agent_names_its_red_when_the_request_is_left_pending() {
    let answered = [
        cancelled_response_line(0),
        cancelled_response_line(1),
        sent_line("reply"),
    ];
    assert_eq!(
        a_late_request_of_a_waiting_agent_is_answered_cancelled(&answered),
        Ok(())
    );
    assert_eq!(
        a_late_request_of_a_waiting_agent_is_answered_cancelled(&[cancelled_response_line(0)]),
        Err(red("5b-6g")),
        "the late request is left pending and the stand-in blocks, so its turn never ends"
    );
}

#[test]
fn the_judge_of_the_declines_names_its_red_at_dispatch_and_at_each_boundary() {
    let read = |dispatched: [&str; 3], settled: [&str; 3]| Declines {
        dispatched: dispatched.map(str::to_owned),
        settled: settled.map(str::to_owned),
    };
    let held = ["dispatching"; 3];
    let settled = ["unknown", "applied", "applied"];
    assert_eq!(
        a_decline_stays_dispatching_until_a_boundary(&read(held, settled)),
        Ok(())
    );
    for at in 0..3 {
        for wrong in ["applied", "unknown"] {
            let mut counted = held;
            counted[at] = wrong;
            assert_eq!(
                a_decline_stays_dispatching_until_a_boundary(&read(counted, settled)),
                Err(red("5b-13")),
                "decline {at} reads {wrong} at dispatch"
            );
        }
        for wrong in ["dispatching", "unknown", "applied"] {
            if wrong == settled[at] {
                continue;
            }
            let mut other = settled;
            other[at] = wrong;
            assert_eq!(
                a_decline_stays_dispatching_until_a_boundary(&read(held, other)),
                Err(red("5b-13")),
                "decline {at} reads {wrong} at its boundary"
            );
        }
    }
    assert_eq!(
        a_decline_stays_dispatching_until_a_boundary(&read(held, ["unknown"; 3])),
        Err(red("5b-13")),
        "a product that takes the next request and the reply for no evidence reads unknown three times"
    );
}

#[test]
fn the_judge_of_the_gemini_window_names_its_red_when_the_window_is_capped_at_thirty_seconds() {
    let answered = [cancelled_response_line(0), cancelled_response_line(1)];
    assert_eq!(
        the_window_stays_open_until_the_prompts_reply(&answered, true),
        Ok(())
    );
    assert_eq!(
        the_window_stays_open_until_the_prompts_reply(&answered[..1], true),
        Err(red("5b-17")),
        "the approval at 31 seconds shows"
    );
    assert_eq!(
        the_window_stays_open_until_the_prompts_reply(&answered, false),
        Err(red("5b-17")),
        "the prompt sent meanwhile was accepted"
    );
}

/// What the host reads of an agent and of the program it runs: the agent's process identity, the
/// digest of the executable the process runs, the digest of the verified copy the process was
/// started from, and the digest of the installation's file.
#[derive(Debug, PartialEq, Eq)]
pub struct Identity {
    /// The process identity.
    pub process: String,
    /// The digest of the executable the process runs.
    pub executable: String,
    /// The digest of the verified copy.
    pub copy: String,
    /// The digest of the installation's file.
    pub installation: String,
}

/// 6b-1: after the installation's file was replaced in place, the agent's process, its executable
/// and its copy read as they did before.
pub fn the_upgrade_leaves_the_process_and_its_copy(
    before: &Identity,
    after: &Identity,
) -> Result<(), Red> {
    ensure(
        before.process == after.process
            && before.executable == after.executable
            && before.copy == after.copy,
        "6b-1",
    )
}

/// What the host decoded of a request before and after the upgrade.
#[derive(Debug)]
pub struct Decoded {
    /// The options decoded from the request before the upgrade, as text.
    pub before: String,
    /// The options decoded from the fresh request after the upgrade, as text.
    pub after: String,
}

/// The option the stand-in received in its response to the request numbered `number`.
fn option_of(record: &[Value], number: u64) -> Option<&str> {
    responses(record)
        .into_iter()
        .find(|line| line["id"] == number)
        .and_then(|line| line["option"].as_str())
}

/// 6b-2: the options decoded from the fresh request equal those decoded before the upgrade, and the
/// stand-in received the pinned table's identifier for the answer.
pub fn a_fresh_request_is_decoded_by_the_pinned_table(
    decoded: &Decoded,
    record: &[Value],
) -> Result<(), Red> {
    ensure(
        decoded.before == decoded.after && option_of(record, 1) == Some("proceed_once"),
        "6b-2",
    )
}

/// What the host said of a start of a second agent.
#[derive(Debug)]
pub struct Start {
    /// The host admitted the start.
    pub admitted: bool,
    /// What the launcher printed.
    pub message: String,
}

/// 6b-3 and 6b-3g, by `id`: the start of a build outside the range was refused, and the launcher's
/// message names the range.
pub fn a_build_outside_the_range_is_refused(
    id: &str,
    range: &str,
    start: &Start,
) -> Result<(), Red> {
    ensure(!start.admitted && start.message.contains(range), id)
}

/// The version an agent reports and the version of the binding the host made for it.
#[derive(Debug)]
pub struct Versions {
    /// The version in the agent's `initialize` result.
    pub reported: String,
    /// The version of the binding.
    pub binding: String,
}

/// 6b-4: the version the agent reports equals the binding's, and a start of an agent that reports
/// another version was refused.
pub fn the_reported_version_is_the_bindings(versions: &Versions, other: &Start) -> Result<(), Red> {
    ensure(
        versions.reported == versions.binding && !other.admitted,
        "6b-4",
    )
}

impl Hosted {
    /// The identity of the agent's process, its executable and its copy, and the digest of the
    /// installation's file, as the host reads them now.
    pub fn identity(&mut self) -> Identity {
        match *self {}
    }

    /// Replaces the installation's file in place, as an upgrade of the agent does, and stops the
    /// case when the installation's digest did not change.
    pub fn upgrades_the_installation(&mut self) {
        match *self {}
    }

    /// The options of the pending request, as the host decoded them, as text.
    pub fn decoded_options(&mut self) -> String {
        match *self {}
    }

    /// Starts a second agent from the installation as it stands, with `script`, and says whether
    /// the host admitted it and what the launcher printed.
    pub fn starts_a_second_agent(&mut self, _script: &Value) -> Start {
        match *self {}
    }

    /// The version in the agent's `initialize` result.
    pub fn reported_version(&mut self) -> String {
        match *self {}
    }

    /// The version of the agent's binding.
    pub fn binding_version(&mut self) -> String {
        match *self {}
    }
}

/// The script of an agent that asks for a call and waits, and asks for a second call when the file
/// `after` appears.
pub fn upgrade_script() -> Value {
    serde_json::json!({
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "hold": "after" },
            { "call": { "id": "c2", "kind": "execute" } },
            { "ask": "c2" },
            { "hold": "never" },
        ]],
    })
}

/// Case 6b-1: the installation's file is replaced while the agent runs with a request pending.
pub fn an_upgrade_while_the_agent_runs(host: &mut Hosted) -> Result<(), Red> {
    let before = host.identity();
    host.upgrades_the_installation();
    the_upgrade_leaves_the_process_and_its_copy(&before, &host.identity())
}

/// Case 6b-2: a fresh request after the upgrade, answered with the pinned table's identifier.
pub fn a_fresh_request_after_an_upgrade(host: &mut Hosted) -> Result<(), Red> {
    let before = host.decoded_options();
    host.answer_next("proceed_once");
    host.upgrades_the_installation();
    host.release("after");
    host.waits_for_a_request();
    let after = host.decoded_options();
    host.answer_next("proceed_once");
    a_fresh_request_is_decoded_by_the_pinned_table(&Decoded { before, after }, &host.record())
}

/// Case 6b-3: a second agent started after the upgrade.
pub fn a_second_start_after_the_upgrade(host: &mut Hosted) -> Result<(), Red> {
    host.upgrades_the_installation();
    let start = host.starts_a_second_agent(&serde_json::json!({}));
    a_build_outside_the_range_is_refused("6b-3", "=1.1.63", &start)
}

/// Case 6b-4: a second agent that reports another version than the hashed build's.
pub fn a_start_that_reports_another_version(host: &mut Hosted) -> Result<(), Red> {
    let versions = Versions {
        reported: host.reported_version(),
        binding: host.binding_version(),
    };
    let other = host.starts_a_second_agent(&serde_json::json!({ "version": "1.1.64" }));
    the_reported_version_is_the_bindings(&versions, &other)
}

#[test]
fn the_judge_of_the_upgrade_names_its_red_when_the_process_or_its_copy_changes() {
    let identity = |process: &str, executable: &str, copy: &str, installation: &str| Identity {
        process: process.to_owned(),
        executable: executable.to_owned(),
        copy: copy.to_owned(),
        installation: installation.to_owned(),
    };
    let before = identity("p1", "e1", "c1", "i1");
    assert_eq!(
        the_upgrade_leaves_the_process_and_its_copy(&before, &identity("p1", "e1", "c1", "i2")),
        Ok(())
    );
    assert_eq!(
        the_upgrade_leaves_the_process_and_its_copy(&before, &identity("p1", "e2", "c1", "i2")),
        Err(red("6b-1")),
        "the launch ran the installation's file, so the executable changed with the upgrade"
    );
    assert_eq!(
        the_upgrade_leaves_the_process_and_its_copy(&before, &identity("p1", "e1", "c2", "i2")),
        Err(red("6b-1")),
        "the copy changed"
    );
    assert_eq!(
        the_upgrade_leaves_the_process_and_its_copy(&before, &identity("p2", "e1", "c1", "i2")),
        Err(red("6b-1")),
        "the process was replaced"
    );
}

#[test]
fn the_judge_of_a_fresh_request_names_its_red_when_the_upgraded_table_decodes_it() {
    let decoded = |before: &str, after: &str| Decoded {
        before: before.to_owned(),
        after: after.to_owned(),
    };
    let answered = [response_line_for(1, "proceed_once")];
    assert_eq!(
        a_fresh_request_is_decoded_by_the_pinned_table(&decoded("options", "options"), &answered),
        Ok(())
    );
    assert_eq!(
        a_fresh_request_is_decoded_by_the_pinned_table(&decoded("options", "other"), &answered),
        Err(red("6b-2")),
        "the host decoded the fresh request with the table of the upgraded installation"
    );
    assert_eq!(
        a_fresh_request_is_decoded_by_the_pinned_table(
            &decoded("options", "options"),
            &[response_line_for(1, "proceed_always")]
        ),
        Err(red("6b-2")),
        "the answer carried another identifier than the pinned table's"
    );
    assert_eq!(
        a_fresh_request_is_decoded_by_the_pinned_table(&decoded("options", "options"), &[]),
        Err(red("6b-2")),
        "the stand-in received no answer"
    );
}

#[test]
fn the_judge_of_the_range_names_its_red_when_the_second_start_is_admitted_or_names_no_range() {
    let start = |admitted: bool, message: &str| Start {
        admitted,
        message: message.to_owned(),
    };
    for (id, range) in [("6b-3", "=1.1.63"), ("6b-3g", "=0.60.0")] {
        assert_eq!(
            a_build_outside_the_range_is_refused(
                id,
                range,
                &start(false, &format!("this build is outside {range}"))
            ),
            Ok(())
        );
        assert_eq!(
            a_build_outside_the_range_is_refused(id, range, &start(true, "")),
            Err(red(id)),
            "the range is not checked"
        );
        assert_eq!(
            a_build_outside_the_range_is_refused(id, range, &start(false, "refused")),
            Err(red(id)),
            "the refusal leaves the range out"
        );
    }
}

#[test]
fn the_judge_of_the_version_names_its_red_when_a_start_with_another_version_is_admitted() {
    let versions = |reported: &str, binding: &str| Versions {
        reported: reported.to_owned(),
        binding: binding.to_owned(),
    };
    let start = |admitted: bool| Start {
        admitted,
        message: String::new(),
    };
    assert_eq!(
        the_reported_version_is_the_bindings(&versions("1.1.63", "1.1.63"), &start(false)),
        Ok(())
    );
    assert_eq!(
        the_reported_version_is_the_bindings(&versions("1.1.63", "1.1.63"), &start(true)),
        Err(red("6b-4")),
        "the reported version is not compared with the hashed build"
    );
    assert_eq!(
        the_reported_version_is_the_bindings(&versions("1.1.64", "1.1.63"), &start(false)),
        Err(red("6b-4")),
        "the agent reports another version than the binding's"
    );
}

/// The bytes of the installation's chunk before and after the upgrade replaced it.
#[derive(Debug)]
pub struct Chunks {
    /// The bytes before the upgrade.
    pub original: Vec<u8>,
    /// The bytes after the upgrade.
    pub upgraded: Vec<u8>,
}

/// 6b-5: the chunk the Gemini-shaped agent read, from the copy it runs from, holds the bytes the
/// installation's chunk had before the upgrade.
pub fn the_copys_chunk_is_read_after_the_upgrade(
    chunks: &Chunks,
    read: Option<&[u8]>,
) -> Result<(), Red> {
    ensure(read == Some(chunks.original.as_slice()), "6b-5")
}

/// 6b-6: the chunk the Gemini-shaped agent read, started from the installation with no copy, holds
/// the bytes the upgrade put there, so the two starts differ.
pub fn without_the_copy_the_upgraded_chunk_is_read(
    chunks: &Chunks,
    read: Option<&[u8]>,
) -> Result<(), Red> {
    ensure(read == Some(chunks.upgraded.as_slice()), "6b-6")
}

impl Hosted {
    /// Replaces the installation's chunk in place, as an upgrade of the package does, and returns
    /// its bytes before and after. It stops the case when the stand-in has read the chunk already
    /// or the bytes did not change.
    pub fn upgrades_the_package(&mut self) -> Chunks {
        match *self {}
    }

    /// The bytes the stand-in's import step wrote to the marker, or none when it wrote none within
    /// five seconds.
    pub fn chunk_read(&mut self) -> Option<Vec<u8>> {
        match *self {}
    }
}

/// The script of a Gemini-shaped agent that asks for a call and, when the file `import` appears
/// after the answer, reads its chunk.
pub fn chunk_script() -> Value {
    serde_json::json!({
        "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "hold": "import" },
            { "import": "chunk.js" },
            { "end": "end_turn" },
        ]],
    })
}

/// Cases 6b-5 and 6b-3g: the first request is answered, the package is upgraded before the agent
/// reads its chunk, and a second agent is started from the upgraded installation.
pub fn an_upgrade_while_a_gemini_shaped_agent_runs(host: &mut Hosted) -> Result<(), Red> {
    host.answer_next("proceed_once");
    let chunks = host.upgrades_the_package();
    host.release("import");
    the_copys_chunk_is_read_after_the_upgrade(&chunks, host.chunk_read().as_deref())?;
    let start = host.starts_a_second_agent(&serde_json::json!({}));
    a_build_outside_the_range_is_refused("6b-3g", "=0.60.0", &start)
}

/// Case 6b-6: the same upgrade, with the agent started from the installation and not from a copy.
pub fn an_upgrade_while_the_agent_runs_from_the_installation(host: &mut Hosted) -> Result<(), Red> {
    host.answer_next("proceed_once");
    let chunks = host.upgrades_the_package();
    host.release("import");
    without_the_copy_the_upgraded_chunk_is_read(&chunks, host.chunk_read().as_deref())
}

#[test]
fn the_judges_of_the_chunk_name_their_reds_when_the_start_with_the_copy_or_without_it_reads_the_other_chunk()
 {
    let chunks = Chunks {
        original: b"original".to_vec(),
        upgraded: b"upgraded".to_vec(),
    };
    assert_eq!(
        the_copys_chunk_is_read_after_the_upgrade(&chunks, Some(b"original")),
        Ok(())
    );
    assert_eq!(
        the_copys_chunk_is_read_after_the_upgrade(&chunks, Some(b"upgraded")),
        Err(red("6b-5")),
        "the launch ran the installation's package, so the marker holds the replaced chunk"
    );
    assert_eq!(
        the_copys_chunk_is_read_after_the_upgrade(&chunks, None),
        Err(red("6b-5")),
        "the agent read no chunk"
    );
    assert_eq!(
        without_the_copy_the_upgraded_chunk_is_read(&chunks, Some(b"upgraded")),
        Ok(())
    );
    assert_eq!(
        without_the_copy_the_upgraded_chunk_is_read(&chunks, Some(b"original")),
        Err(red("6b-6")),
        "the replaced chunk is not the one the stand-in imports, so the control shows no difference"
    );
    assert_eq!(
        without_the_copy_the_upgraded_chunk_is_read(&chunks, None),
        Err(red("6b-6")),
        "the agent read no chunk"
    );
}
