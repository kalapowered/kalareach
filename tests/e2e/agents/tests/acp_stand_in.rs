//! The stand-in agents for ACP mode, played against over pipes by a test that stands for the
//! worker: what each shape writes, in what order, and what it records of what it received. The
//! cases of ACP mode rest on this traffic, so it is shown here before any launch exists.

#![cfg(unix)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use kr_e2e_agents::acp_agent::{RECORD_FILE, SCRIPT_FILE, check_script};
use serde_json::{Value, json};

/// How long a test waits for a frame that must come.
const WITHIN: Duration = Duration::from_secs(10);

/// How long a test waits to show that a frame does not come.
const QUIET: Duration = Duration::from_millis(400);

/// A stand-in program started with a script, and the test's end of its pipes.
struct Played {
    /// The program.
    child: Child,
    /// Its standard input, until the test closes it.
    input: Option<ChildStdin>,
    /// The lines of its standard output.
    frames: Receiver<String>,
    /// Its working directory.
    directory: tempfile::TempDir,
}

impl Played {
    /// Starts `program` in a working directory that holds `script`.
    fn start(program: &str, script: &Value) -> Self {
        let directory = tempfile::tempdir().expect("a working directory");
        std::fs::write(directory.path().join(SCRIPT_FILE), script.to_string()).expect("the script");
        let mut child = Command::new(program)
            .current_dir(directory.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the stand-in starts");
        let input = child.stdin.take();
        let output = child.stdout.take().expect("its standard output");
        let (lines, frames) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                let Ok(line) = line else { break };
                if lines.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            frames,
            directory,
        }
    }

    /// Sends one frame.
    fn send(&mut self, frame: &Value) {
        let input = self.input.as_mut().expect("the input is open");
        writeln!(input, "{frame}").expect("the stand-in reads its input");
        input.flush().expect("the stand-in reads its input");
    }

    /// The next line the stand-in wrote.
    fn line(&self) -> String {
        self.frames
            .recv_timeout(WITHIN)
            .unwrap_or_else(|why| panic!("no frame within {WITHIN:?}: {why}"))
    }

    /// The next frame the stand-in wrote.
    fn frame(&self) -> Value {
        serde_json::from_str(&self.line()).expect("a frame is json")
    }

    /// Whether the stand-in writes nothing for [`QUIET`].
    fn is_quiet(&self) -> bool {
        self.frames.recv_timeout(QUIET).is_err()
    }

    /// The lines of the record, parsed.
    fn record(&self) -> Vec<Value> {
        std::fs::read_to_string(self.directory.path().join(RECORD_FILE))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).expect("a record line is json"))
            .collect()
    }

    /// Makes the file of the working directory that a `hold` step waits for.
    fn release(&self, name: &str) {
        std::fs::write(self.directory.path().join(name), b"go").expect("the release");
    }

    /// Closes the stand-in's input and waits for it to end.
    fn close(&mut self) -> std::process::ExitStatus {
        drop(self.input.take());
        self.child.wait().expect("the stand-in ends")
    }

    /// Sends the two requests every session starts with and reads their answers.
    fn open_session(&mut self) {
        self.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": 1 } }));
        assert_eq!(self.frame()["id"], 1);
        self.send(&json!({ "jsonrpc": "2.0", "id": 2, "method": "session/new", "params": { "cwd": "/", "mcpServers": [] } }));
        assert_eq!(self.frame()["id"], 2);
    }

    /// Sends a prompt of one text block under request number `id`.
    fn prompt(&mut self, id: u64, text: &str) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "session/prompt",
            "params": { "sessionId": "stand-in-session", "prompt": [{ "type": "text", "text": text }] },
        }));
    }

    /// Answers the agent's request number `id` by choosing `option`.
    fn choose(&mut self, id: u64, option: &str) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": { "outcome": { "outcome": "selected", "optionId": option } },
        }));
    }
}

impl Drop for Played {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The program that stands in for Qoder CLI.
const QODER: &str = env!("CARGO_BIN_EXE_acp-qoder-stand-in");

/// A turn that calls a tool, asks for it, and runs it only when it was allowed.
fn guarded_turn() -> Value {
    json!({ "turns": [[
        { "say": "I will run it" },
        { "call": { "id": "c1", "kind": "execute" } },
        { "ask": "c1" },
        { "when": { "outcome": "allowed", "then": [
            { "update": { "call": "c1", "status": "in_progress" } },
            { "update": { "call": "c1", "status": "completed" } },
        ] } },
        { "when": { "outcome": "declined", "then": [
            { "update": { "call": "c1", "status": "failed" } },
        ] } },
        { "end": "end_turn" },
    ]] })
}

#[test]
fn a_qoder_shaped_stand_in_answers_initialize_with_the_version_the_table_pins() {
    let mut agent = Played::start(QODER, &json!({}));
    agent.send(&json!({ "jsonrpc": "2.0", "id": 7, "method": "initialize", "params": { "protocolVersion": 1 } }));
    let answer = agent.frame();
    assert_eq!(answer["id"], 7);
    assert_eq!(answer["result"]["protocolVersion"], 1);
    assert_eq!(answer["result"]["agentInfo"]["version"], "1.1.63");
    assert_eq!(answer["result"]["agentCapabilities"]["loadSession"], false);
}

#[test]
fn the_stand_in_writes_its_frames_with_the_keys_in_the_order_both_agents_write_them() {
    let mut agent = Played::start(QODER, &guarded_turn());
    agent.send(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }));
    assert!(
        agent
            .line()
            .starts_with(r#"{"jsonrpc":"2.0","id":1,"result":"#),
        "a response writes jsonrpc, id and result"
    );
    agent.send(&json!({ "jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {} }));
    agent.frame();
    agent.prompt(3, "run it");
    assert!(
        agent
            .line()
            .starts_with(r#"{"jsonrpc":"2.0","method":"session/update","params":"#),
        "a notification writes jsonrpc, method and params"
    );
    agent.line();
    assert!(
        agent.line().starts_with(
            r#"{"jsonrpc":"2.0","id":0,"method":"session/request_permission","params":"#
        ),
        "a request writes jsonrpc, id, method and params, and the first id is 0"
    );
}

#[test]
fn an_allowed_request_is_followed_by_the_calls_updates_and_the_prompts_reply() {
    let mut agent = Played::start(QODER, &guarded_turn());
    agent.open_session();
    agent.prompt(3, "run it");
    assert_eq!(
        agent.frame()["params"]["update"]["sessionUpdate"],
        "agent_message_chunk"
    );
    assert_eq!(agent.frame()["params"]["update"]["status"], "pending");
    let request = agent.frame();
    assert_eq!(request["method"], "session/request_permission");
    assert_eq!(request["params"]["toolCall"]["toolCallId"], "c1");
    let kinds: Vec<&str> = request["params"]["options"]
        .as_array()
        .expect("options")
        .iter()
        .filter_map(|option| option["kind"].as_str())
        .collect();
    assert_eq!(kinds, ["allow_once", "allow_always", "reject_once"]);
    assert!(agent.is_quiet(), "the turn waits for the answer");
    agent.choose(0, "allow-once");
    assert_eq!(agent.frame()["params"]["update"]["status"], "in_progress");
    assert_eq!(agent.frame()["params"]["update"]["status"], "completed");
    let reply = agent.frame();
    assert_eq!(reply["id"], 3);
    assert_eq!(reply["result"]["stopReason"], "end_turn");
    let answered: Vec<Value> = agent
        .record()
        .into_iter()
        .filter(|line| line["received"] == "response")
        .collect();
    assert_eq!(answered.len(), 1, "one response was received");
    assert_eq!(answered[0]["option"], "allow-once");
}

#[test]
fn a_declined_request_runs_the_steps_for_a_decline_and_not_those_for_an_allow() {
    let mut agent = Played::start(QODER, &guarded_turn());
    agent.open_session();
    agent.prompt(3, "run it");
    for _ in 0..3 {
        agent.frame();
    }
    agent.choose(0, "reject-once");
    assert_eq!(agent.frame()["params"]["update"]["status"], "failed");
    assert_eq!(agent.frame()["result"]["stopReason"], "end_turn");
    assert!(agent.is_quiet(), "no update of an allowed call follows");
}

#[test]
fn a_cancelled_answer_runs_neither_the_allow_steps_nor_the_decline_steps() {
    let mut agent = Played::start(QODER, &guarded_turn());
    agent.open_session();
    agent.prompt(3, "run it");
    for _ in 0..3 {
        agent.frame();
    }
    agent.send(&json!({
        "jsonrpc": "2.0",
        "id": 0,
        "result": { "outcome": { "outcome": "cancelled" } },
    }));
    assert_eq!(agent.frame()["result"]["stopReason"], "end_turn");
    let answered: Vec<Value> = agent
        .record()
        .into_iter()
        .filter(|line| line["received"] == "response")
        .collect();
    assert_eq!(answered[0]["outcome"], "cancelled");
}

#[test]
fn a_hold_step_waits_for_its_file_and_an_exit_step_ends_the_program_with_its_code() {
    let mut agent = Played::start(
        QODER,
        &json!({ "turns": [[{ "hold": "go" }, { "end": "end_turn" }], [{ "exit": 3 }]] }),
    );
    agent.open_session();
    agent.prompt(3, "first");
    assert!(agent.is_quiet(), "the turn waits for the file");
    agent.release("go");
    assert_eq!(agent.frame()["id"], 3);
    agent.prompt(4, "second");
    assert_eq!(
        agent.child.wait().expect("the stand-in ends").code(),
        Some(3)
    );
}

#[test]
fn an_unknown_method_is_refused_and_a_line_that_is_not_json_is_recorded_and_the_input_ends_it() {
    let mut agent = Played::start(QODER, &json!({}));
    agent.send(&json!({ "jsonrpc": "2.0", "id": 5, "method": "session/close", "params": {} }));
    let refusal = agent.frame();
    assert_eq!(refusal["id"], 5);
    assert_eq!(refusal["error"]["code"], -32601);
    let input = agent.input.as_mut().expect("the input is open");
    writeln!(input, "not json").expect("a line");
    input.flush().expect("a flush");
    assert!(
        agent.is_quiet(),
        "a line that is not json is answered with nothing"
    );
    assert_eq!(agent.close().code(), Some(0));
    let kinds: Vec<String> = agent
        .record()
        .iter()
        .filter_map(|line| line["received"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        kinds,
        ["request", "a line that is not json", "end of input"]
    );
}

#[test]
fn a_tick_is_sent_once_when_its_file_appears_and_the_record_holds_it() {
    let mut agent = Played::start(
        QODER,
        &json!({ "ticks": [{ "after": "t1", "say": "tick 1" }] }),
    );
    agent.open_session();
    assert!(agent.is_quiet(), "no tick comes before its file");
    agent.release("t1");
    assert_eq!(
        agent.frame()["params"]["update"]["content"]["text"],
        "tick 1"
    );
    assert!(agent.is_quiet(), "a tick is sent once");
    let sent = agent
        .record()
        .into_iter()
        .filter(|line| line["sent"] == "tick")
        .count();
    assert_eq!(sent, 1);
}

#[test]
fn the_agent_exits_when_its_exit_file_appears_whatever_its_turn_waits_for() {
    let mut agent = Played::start(
        QODER,
        &json!({ "turns": [[{ "call": { "id": "c1", "kind": "execute" } }, { "ask": "c1" }]], "exit_after": "die" }),
    );
    agent.open_session();
    agent.prompt(3, "run it");
    for _ in 0..2 {
        agent.frame();
    }
    assert!(agent.is_quiet(), "the turn waits for the answer");
    agent.release("die");
    assert_eq!(
        agent.child.wait().expect("the stand-in ends").code(),
        Some(0)
    );
    let sent: Vec<Value> = agent
        .record()
        .into_iter()
        .filter(|line| line["sent"] == "exit")
        .collect();
    assert_eq!(sent.len(), 1, "the record says the agent exited");
}

/// The `params.update.status` of a frame, or the empty text.
fn status(frame: &Value) -> &str {
    frame["params"]["update"]["status"].as_str().unwrap_or("")
}

/// The stop reason of a reply frame, or the empty text.
fn stop(frame: &Value) -> &str {
    frame["result"]["stopReason"].as_str().unwrap_or("")
}

/// The lines of the record that the stand-in sent, of one kind.
fn sent(agent: &Played, kind: &str) -> Vec<Value> {
    agent
        .record()
        .into_iter()
        .filter(|line| line["sent"] == kind)
        .collect()
}

/// A turn that asks for a call and waits.
fn waiting_turn() -> Value {
    json!([
        { "call": { "id": "c1", "kind": "execute" } },
        { "ask": "c1" },
        { "end": "end_turn" },
    ])
}

#[test]
fn a_turn_of_the_agents_own_starts_when_its_file_appears_and_ends_with_no_reply() {
    let mut agent = Played::start(
        QODER,
        &json!({ "own": [{ "after": "go", "steps": [{ "say": "own" }, { "end": "end_turn" }] }] }),
    );
    agent.open_session();
    assert!(agent.is_quiet(), "no turn of its own before its file");
    agent.release("go");
    assert_eq!(agent.frame()["params"]["update"]["content"]["text"], "own");
    assert!(
        agent.is_quiet(),
        "a turn of its own has no prompt to reply to"
    );
    assert_eq!(sent(&agent, "turn end").len(), 1);
}

#[test]
fn a_cancel_settles_a_waiting_request_and_ends_the_turn_cancelled_as_qoder_does() {
    let mut agent = Played::start(QODER, &json!({ "turns": [waiting_turn()] }));
    agent.open_session();
    agent.prompt(3, "run it");
    for _ in 0..2 {
        agent.frame();
    }
    agent.send(&json!({ "jsonrpc": "2.0", "method": "session/cancel", "params": { "sessionId": "stand-in-session" } }));
    assert_eq!(status(&agent.frame()), "cancelled", "the call is cancelled");
    let reply = agent.frame();
    assert_eq!((reply["id"].as_u64(), stop(&reply)), (Some(3), "cancelled"));
    agent.send(
        &json!({ "jsonrpc": "2.0", "id": 0, "result": { "outcome": { "outcome": "cancelled" } } }),
    );
    assert!(
        agent.is_quiet(),
        "a late response to a settled request changes nothing"
    );
    let cancels = agent
        .record()
        .into_iter()
        .filter(|line| line["method"] == "session/cancel")
        .count();
    assert_eq!(cancels, 1);
}

#[test]
fn a_cancel_in_the_wait_mode_leaves_the_request_waiting_until_it_is_answered() {
    let mut agent = Played::start(
        QODER,
        &json!({
            "cancel": "wait",
            "turns": [[
                { "call": { "id": "c1", "kind": "execute" } },
                { "ask": "c1" },
                { "when": { "outcome": "cancelled", "then": [
                    { "update": { "call": "c1", "status": "cancelled" } },
                ] } },
                { "end": "cancelled" },
            ]],
        }),
    );
    agent.open_session();
    agent.prompt(3, "run it");
    for _ in 0..2 {
        agent.frame();
    }
    agent.send(&json!({ "jsonrpc": "2.0", "method": "session/cancel", "params": { "sessionId": "stand-in-session" } }));
    assert!(agent.is_quiet(), "the request still waits");
    agent.send(
        &json!({ "jsonrpc": "2.0", "id": 0, "result": { "outcome": { "outcome": "cancelled" } } }),
    );
    assert_eq!(status(&agent.frame()), "cancelled");
    assert_eq!(stop(&agent.frame()), "cancelled");
}

#[test]
fn a_prompt_sent_behind_a_running_turn_is_queued_and_a_cancel_answers_it_cancelled_first() {
    let mut agent = Played::start(QODER, &json!({ "turns": [waiting_turn()] }));
    agent.open_session();
    agent.prompt(3, "first");
    for _ in 0..2 {
        agent.frame();
    }
    agent.prompt(4, "second");
    assert!(agent.is_quiet(), "a queued prompt is not answered");
    agent.send(&json!({ "jsonrpc": "2.0", "method": "session/cancel", "params": { "sessionId": "stand-in-session" } }));
    let queued = agent.frame();
    assert_eq!(
        (queued["id"].as_u64(), stop(&queued)),
        (Some(4), "cancelled")
    );
    assert_eq!(status(&agent.frame()), "cancelled");
    let running = agent.frame();
    assert_eq!(
        (running["id"].as_u64(), stop(&running)),
        (Some(3), "cancelled")
    );
}

#[test]
fn a_queued_prompt_starts_when_the_turn_before_it_ends() {
    let mut agent = Played::start(
        QODER,
        &json!({ "turns": [
            [{ "hold": "go" }, { "end": "end_turn" }],
            [{ "say": "second" }, { "end": "end_turn" }],
        ] }),
    );
    agent.open_session();
    agent.prompt(3, "first");
    agent.prompt(4, "second");
    assert!(
        agent.is_quiet(),
        "the first turn holds and the second waits"
    );
    agent.release("go");
    assert_eq!(agent.frame()["id"], 3);
    assert_eq!(
        agent.frame()["params"]["update"]["content"]["text"],
        "second"
    );
    assert_eq!(agent.frame()["id"], 4);
}

#[test]
fn steps_of_a_cancel_run_as_a_turn_of_the_agents_own_after_the_settle() {
    let mut agent = Played::start(
        QODER,
        &json!({
            "turns": [waiting_turn()],
            "on_cancel": [
                { "hold": "late" },
                { "call": { "id": "c2", "kind": "execute" } },
                { "ask": "c2" },
            ],
        }),
    );
    agent.open_session();
    agent.prompt(3, "run it");
    for _ in 0..2 {
        agent.frame();
    }
    agent.send(&json!({ "jsonrpc": "2.0", "method": "session/cancel", "params": { "sessionId": "stand-in-session" } }));
    assert_eq!(status(&agent.frame()), "cancelled");
    assert_eq!(stop(&agent.frame()), "cancelled");
    assert!(agent.is_quiet(), "the late request waits for its file");
    agent.release("late");
    assert_eq!(agent.frame()["params"]["update"]["toolCallId"], "c2");
    let late = agent.frame();
    assert_eq!(late["method"], "session/request_permission");
    assert_eq!(
        late["id"], 1,
        "the request of the second call carries the next number"
    );
}

#[test]
fn the_agent_records_what_it_asked_and_how_each_call_and_turn_ended() {
    let mut agent = Played::start(
        QODER,
        &json!({ "turns": [[
            { "call": { "id": "c1", "kind": "execute" } },
            { "ask": "c1" },
            { "update": { "call": "c1", "status": "completed" } },
            { "end": "end_turn" },
        ]] }),
    );
    agent.open_session();
    agent.prompt(3, "run it");
    for _ in 0..2 {
        agent.frame();
    }
    agent.choose(0, "allow-once");
    agent.frame();
    agent.frame();
    let asked = sent(&agent, "request");
    assert_eq!(
        (
            asked.len(),
            asked[0]["id"].as_u64(),
            asked[0]["call"].as_str()
        ),
        (1, Some(0), Some("c1"))
    );
    assert_eq!(sent(&agent, "update")[0]["status"], "completed");
    assert_eq!(sent(&agent, "reply")[0]["stop"], "end_turn");
}

#[test]
fn a_script_with_a_step_the_stand_in_does_not_know_is_refused_before_any_agent_starts() {
    assert_eq!(
        check_script(&json!({ "turns": [[{ "say": "text" }]] })),
        Ok(())
    );
    let why = check_script(&json!({ "turns": [[{ "sya": "text" }]] }))
        .expect_err("a step with a misspelt name is no script");
    assert!(why.contains("sya"), "the refusal names the step: {why}");
}
