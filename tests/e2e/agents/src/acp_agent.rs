//! A stand-in for an agent that speaks the Agent Client Protocol, version 1, over its standard input
//! and output, one JSON object to a line. It stands in for the two agents the host starts in ACP
//! mode, and each of the two has its own [`Shape`].
//!
//! The stand-in reads a script from [`SCRIPT_FILE`] in its working directory and appends one line
//! to [`RECORD_FILE`] there for each frame it receives, for each tick, request, update and reply it
//! sends, for the end of a turn of its own and for the end of its input, so a case reads what the
//! agent saw and did. It reads no environment name: the launcher passes the agent the names of an
//! allowlist and no others.
//!
//! A script is `{"turns": [...], "ticks": [...], "exit_after": "name", "own": [...], "cancel":
//! "settle", "on_cancel": [...], "version": "text", "survive_end_of_input": false}`. The k-th prompt of the client runs the k-th
//! turn, which is a list of steps; a prompt with no turn left is answered at once with the stop
//! reason `end_turn`. A tick is `{"after": "name", "say": "text"}`: when the file `name` appears in
//! the working directory the agent sends an update that says `text`, once, whatever its turn does.
//! When the file `exit_after` names appears the agent ends with the code 0, whatever its turn waits
//! for. The agent reports the version of its shape in `initialize`, unless `version` names another.
//! When the client's input closes the agent ends with the code 0, unless `survive_end_of_input` is
//! true: then it records the end of the input and goes on, as an agent does that does not exit at
//! the end of its input, until `exit_after`, an `exit` step or a signal ends it.
//!
//! A turn of the agent's own is `{"after": "name", "steps": [...]}` in `own`: it starts when the
//! file appears and no turn runs, and it ends with no reply, because it answers no prompt. A
//! prompt that arrives while a turn runs waits in a queue and starts when the turn ends; the
//! Gemini-shaped agent refuses it instead. On `session/cancel` the agent answers each prompt that
//! waits in its queue with the stop reason `cancelled`. Under `"cancel": "settle"`, the default, it
//! then stops waiting on the request of its turn, sends the call's update with the status
//! `cancelled` and ends the turn `cancelled`; under `"cancel": "wait"` it changes nothing more.
//! The steps of `on_cancel` then run once as a turn of the agent's own.
//!
//! The Gemini-shaped agent is a script package that an interpreter runs. [`run`] takes the folder
//! of the package's main file, and an `import` step reads a chunk from that folder only when the
//! step runs, as the real main file imports a chunk only when it first needs it. The bytes the step
//! read go to the marker, so a case shows which folder the host started the agent from.
//!
//! | Step | What the stand-in does |
//! | --- | --- |
//! | `{"say": "text"}` | sends an `agent_message_chunk` update |
//! | `{"call": {"id": "c1", "kind": "execute"}}` | sends a `tool_call` update for a call, pending |
//! | `{"ask": "c1"}` | sends `session/request_permission` for the call and waits for the response, offering `proceed_once`, `proceed_always` and `cancel` |
//! | `{"update": {"call": "c1", "status": "in_progress"}}` | sends a `tool_call_update` |
//! | `{"when": {"outcome": "allowed", "then": [...]}}` | runs its steps if the last answer to a request was `allowed`, `declined` or `cancelled` |
//! | `{"import": "name"}` | reads the file `name` from the folder of the package's main file and writes the bytes it read to [`MARKER_FILE`] |
//! | `{"hold": "name"}` | waits until the file `name` exists in the working directory |
//! | `{"end": "end_turn"}` | answers the prompt with that stop reason |
//! | `{"exit": 0}` | ends the program with that code |

use std::collections::{BTreeMap, VecDeque};
use std::fs::OpenOptions;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

/// The file of the working directory that holds the script.
pub const SCRIPT_FILE: &str = "acp-stand-in.json";

/// The file of the working directory that the stand-in appends its record to.
pub const RECORD_FILE: &str = "acp-stand-in.record";

/// The file of the working directory that an `import` step writes the bytes of the chunk to.
pub const MARKER_FILE: &str = "acp-chunk-loaded";

/// How often a step that waits looks again.
const POLL: Duration = Duration::from_millis(20);

/// The two agents the stand-in can be shaped like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// The native program shaped like Qoder CLI.
    Qoder,
    /// The script package shaped like Gemini CLI.
    Gemini,
}

impl Shape {
    /// The version the agent reports in `initialize`: the build the host's table pins.
    #[must_use]
    pub fn version(self) -> &'static str {
        match self {
            Self::Qoder => "1.1.63",
            Self::Gemini => "0.60.0",
        }
    }

    /// The name the agent reports in `initialize`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Qoder => "qoder-stand-in",
            Self::Gemini => "gemini-stand-in",
        }
    }
}

/// What the client's last answer to a permission request meant.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    /// The client chose an option that allows the call.
    Allowed,
    /// The client chose an option that rejects the call.
    Declined,
    /// The client answered that the request was cancelled.
    Cancelled,
}

/// One step of a turn.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum Step {
    /// An `agent_message_chunk` update.
    Say(String),
    /// A `tool_call` update.
    Call {
        /// The call's identifier.
        id: String,
        /// The call's kind.
        kind: String,
    },
    /// A permission request for a call.
    Ask(String),
    /// A `tool_call_update`.
    Update {
        /// The call's identifier.
        call: String,
        /// The call's status.
        status: String,
    },
    /// Steps that run only after one kind of answer.
    When {
        /// The answer.
        outcome: Outcome,
        /// What runs after it.
        then: Vec<Step>,
    },
    /// A chunk of the package, read from the folder of its main file.
    Import(String),
    /// A wait for a file of the working directory.
    Hold(String),
    /// The prompt's reply.
    End(String),
    /// The end of the program.
    Exit(i32),
}

/// The script of a run.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Script {
    /// The turns, one for each prompt of the client in order.
    #[serde(default)]
    turns: Vec<Vec<Step>>,
    /// The updates the agent sends of its own accord, each when its file appears.
    #[serde(default)]
    ticks: Vec<Tick>,
    /// The agent ends with the code 0 when this file appears, whatever its turn waits for.
    #[serde(default)]
    exit_after: Option<String>,
    /// Turns the agent starts of its own accord, each when its file appears and no turn runs.
    #[serde(default)]
    own: Vec<Own>,
    /// What `session/cancel` does to the request the running turn waits on.
    #[serde(default)]
    cancel: CancelMode,
    /// Steps that run once as a turn of the agent's own, after the first cancel settled its turn.
    #[serde(default)]
    on_cancel: Vec<Step>,
    /// The version the agent reports in `initialize`, in place of its shape's.
    #[serde(default)]
    version: Option<String>,
    /// Whether the agent goes on running when its input closes, as an agent that does not exit at
    /// the end of its input.
    #[serde(default)]
    survive_end_of_input: bool,
}

/// A turn of the agent's own: it answers no prompt, so it ends with no reply.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Own {
    /// The file that starts the turn.
    after: String,
    /// The steps of the turn.
    steps: Vec<Step>,
}

/// What `session/cancel` does to the request the running turn waits on.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum CancelMode {
    /// The agent stops waiting at once, as Qoder does: it cancels the call and ends the turn.
    #[default]
    Settle,
    /// The agent goes on waiting for the client's answer, as Gemini does.
    Wait,
}

/// An update the agent sends once, when a file of the working directory appears, whatever its turn
/// does: the agent's own traffic while the client's daemon is down.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tick {
    /// The file that releases the tick.
    after: String,
    /// The text of the update.
    say: String,
}

/// What a running turn waits for before its next step.
#[derive(Debug)]
enum Waiting {
    /// Nothing: the next step runs.
    Nothing,
    /// The response to the request of the agent's with this number.
    Response(u64),
    /// A file of the working directory.
    File(PathBuf),
}

/// The turn that a prompt of the client started.
#[derive(Debug)]
struct Turn {
    /// The prompt's request identifier, as the client wrote it, or none for a turn of the agent's
    /// own.
    prompt: Option<Value>,
    /// The steps that remain.
    steps: VecDeque<Step>,
    /// What the turn waits for.
    waiting: Waiting,
}

/// What the reading thread passes on.
enum Input {
    /// One line of the client's.
    Line(String),
    /// The client's end of the stream closed.
    Closed,
}

/// The stand-in's state.
struct Agent<W: Write> {
    /// The shape of the agent.
    shape: Shape,
    /// The working directory.
    directory: PathBuf,
    /// The standard output.
    output: W,
    /// The script.
    script: Script,
    /// How many prompts the client has sent.
    prompts: usize,
    /// The number the next request of the agent's carries; both agents count from 0.
    next_request: u64,
    /// The turn that runs.
    turn: Option<Turn>,
    /// The kind of each option offered, by identifier.
    outcomes: BTreeMap<String, Outcome>,
    /// The last answer to a permission request.
    last_answer: Option<Outcome>,
    /// How many ticks have been sent: they go in the order the script lists them.
    ticked: usize,
    /// The prompts that wait behind the running turn, as the client wrote their identifiers.
    queued: VecDeque<Value>,
    /// How many turns of the agent's own have started: they go in the order the script lists them.
    own_started: usize,
    /// The call whose request the running turn waits on.
    pending_call: Option<String>,
    /// Whether a cancel has been taken.
    cancelled: bool,
    /// The folder of the main file of the script package the agent runs from, if it runs from one.
    package: Option<PathBuf>,
}

/// Reads `script` as the stand-in reads the file of its working directory, so that a case finds a
/// script it wrote wrong before any agent starts.
///
/// # Errors
///
/// Returns why the value is not a script.
pub fn check_script(script: &Value) -> Result<(), String> {
    serde_json::from_value::<Script>(script.clone())
        .map(drop)
        .map_err(|why| why.to_string())
}

/// Runs the stand-in to the end of the client's stream or to an `exit` step, and returns the exit
/// code. `package` is the folder of the main file of the script package the agent runs from, if it
/// runs from one.
///
/// # Errors
///
/// Returns why the script could not be read.
pub fn run(
    shape: Shape,
    directory: &Path,
    package: Option<&Path>,
    input: impl BufRead + Send + 'static,
    output: impl Write,
) -> Result<i32, String> {
    let script = match std::fs::read(directory.join(SCRIPT_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|why| format!("the script {SCRIPT_FILE} is not a script: {why}"))?,
        Err(why) if why.kind() == std::io::ErrorKind::NotFound => Script::default(),
        Err(why) => return Err(format!("the script {SCRIPT_FILE}: {why}")),
    };
    let (lines, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in input.lines() {
            let Ok(line) = line else { break };
            if lines.send(Input::Line(line)).is_err() {
                return;
            }
        }
        let _ = lines.send(Input::Closed);
    });
    let mut agent = Agent {
        shape,
        directory: directory.to_path_buf(),
        output,
        script,
        prompts: 0,
        next_request: 0,
        turn: None,
        outcomes: BTreeMap::new(),
        last_answer: None,
        ticked: 0,
        queued: VecDeque::new(),
        own_started: 0,
        pending_call: None,
        cancelled: false,
        package: package.map(Path::to_path_buf),
    };
    let mut input_is_open = true;
    loop {
        if input_is_open {
            match received.recv_timeout(POLL) {
                Ok(Input::Line(line)) => {
                    if let Some(code) = agent.receive(&line) {
                        return Ok(code);
                    }
                }
                Ok(Input::Closed) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                    agent.record(&json!({ "received": "end of input" }));
                    if !agent.script.survive_end_of_input {
                        return Ok(0);
                    }
                    input_is_open = false;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
        } else {
            std::thread::sleep(POLL);
        }
        agent.tick();
        agent.start_next();
        if agent.is_told_to_exit() {
            return Ok(0);
        }
        if let Some(code) = agent.advance() {
            return Ok(code);
        }
    }
}

impl<W: Write> Agent<W> {
    /// Appends one line to the record.
    fn record(&self, line: &Value) {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.directory.join(RECORD_FILE))
        {
            // One write for the line and its newline, so a reader never sees half a line.
            let _ = file.write_all(format!("{line}\n").as_bytes());
        }
    }

    /// Writes one frame and flushes it.
    fn write(&mut self, frame: &str) {
        let _ = writeln!(self.output, "{frame}");
        let _ = self.output.flush();
    }

    /// Sends a response. Both agents write the keys of a response in the order `jsonrpc`, `id`,
    /// `result`.
    fn answer(&mut self, id: &Value, result: &Value) {
        self.write(&format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{result}}}"#
        ));
    }

    /// Sends an error response.
    fn refuse(&mut self, id: &Value, code: i64, message: &str) {
        let error = json!({ "code": code, "message": message });
        self.write(&format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{error}}}"#));
    }

    /// Sends a notification, with the keys in the order both agents write them: `jsonrpc`,
    /// `method`, `params`.
    fn notify(&mut self, method: &str, params: &Value) {
        self.write(&format!(
            r#"{{"jsonrpc":"2.0","method":"{method}","params":{params}}}"#
        ));
    }

    /// Sends a request and returns its number, with the keys in the order `jsonrpc`, `id`,
    /// `method`, `params`.
    fn ask(&mut self, method: &str, params: &Value) -> u64 {
        let id = self.next_request;
        self.next_request += 1;
        self.write(&format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"{method}","params":{params}}}"#
        ));
        id
    }

    /// Sends a `session/update` with `update` as its update.
    fn update(&mut self, update: &Value) {
        self.notify(
            "session/update",
            &json!({ "sessionId": SESSION, "update": update }),
        );
    }

    /// Takes one line of the client's. Returns the exit code if the program ends.
    fn receive(&mut self, line: &str) -> Option<i32> {
        let Ok(frame) = serde_json::from_str::<Value>(line) else {
            self.record(&json!({ "received": "a line that is not json" }));
            return None;
        };
        let id = frame.get("id").cloned();
        let method = frame.get("method").and_then(Value::as_str);
        match (method, id) {
            (Some(method), Some(id)) => {
                let mut line = json!({ "received": "request", "id": id, "method": method });
                if method == "session/prompt" {
                    line["prompt"] = frame["params"]["prompt"].clone();
                }
                self.record(&line);
                self.request(method, &id);
            }
            (Some(method), None) => {
                self.record(&json!({ "received": "notification", "method": method }));
                if method == "session/cancel" {
                    self.cancel();
                }
            }
            (None, Some(id)) => self.response(&id, &frame),
            (None, None) => self.record(&json!({ "received": "a frame of no kind" })),
        }
        None
    }

    /// Answers a request of the client's.
    fn request(&mut self, method: &str, id: &Value) {
        match method {
            "initialize" => {
                let result = json!({
                    "protocolVersion": 1,
                    "agentCapabilities": { "loadSession": false },
                    "agentInfo": {
                        "name": self.shape.name(),
                        "title": self.shape.name(),
                        "version": self.script.version.as_deref().unwrap_or(self.shape.version()),
                    },
                    "authMethods": [],
                });
                self.answer(id, &result);
            }
            "session/new" => self.answer(id, &json!({ "sessionId": SESSION })),
            "session/prompt" => self.prompt(id),
            _ => self.refuse(id, -32601, "method not found"),
        }
    }

    /// Starts the turn of a prompt of the client's.
    fn prompt(&mut self, id: &Value) {
        if self.turn.is_none() {
            self.start_prompt(id.clone());
        } else if self.shape == Shape::Qoder {
            self.queued.push_back(id.clone());
        } else {
            self.refuse(id, -32000, "a prompt is running");
        }
    }

    /// Starts the turn the next prompt of the client runs.
    fn start_prompt(&mut self, id: Value) {
        let steps = self
            .script
            .turns
            .get(self.prompts)
            .cloned()
            .unwrap_or_else(|| vec![Step::End("end_turn".to_owned())]);
        self.prompts += 1;
        self.turn = Some(Turn {
            prompt: Some(id),
            steps: steps.into(),
            waiting: Waiting::Nothing,
        });
    }

    /// Starts a turn when none runs: the prompt that waited longest, else a turn of the agent's own
    /// whose file has appeared.
    fn start_next(&mut self) {
        if self.turn.is_some() {
            return;
        }
        if let Some(id) = self.queued.pop_front() {
            self.start_prompt(id);
        } else if let Some(own) = self.script.own.get(self.own_started)
            && self.directory.join(&own.after).exists()
        {
            self.own_started += 1;
            self.turn = Some(Turn {
                prompt: None,
                steps: own.steps.clone().into(),
                waiting: Waiting::Nothing,
            });
        }
    }

    /// Takes a `session/cancel`. The Qoder-shaped agent answers the prompts that wait in its queue
    /// `cancelled` at once and only then, under `settle`, abandons the request its turn waits on:
    /// the call is cancelled and the turn ends `cancelled`. The steps of `on_cancel` start a turn
    /// of the agent's own the first time.
    fn cancel(&mut self) {
        while let Some(id) = self.queued.pop_front() {
            self.finish(Some(id), "cancelled");
        }
        if self.script.cancel == CancelMode::Settle
            && let Some(turn) = self.turn.take()
        {
            if let Some(call) = self.pending_call.take() {
                self.send_update(&call, "cancelled");
            }
            self.finish(turn.prompt, "cancelled");
        }
        if !self.cancelled && self.turn.is_none() && !self.script.on_cancel.is_empty() {
            self.turn = Some(Turn {
                prompt: None,
                steps: self.script.on_cancel.clone().into(),
                waiting: Waiting::Nothing,
            });
        }
        self.cancelled = true;
    }

    /// Ends a turn: answers its prompt with `stop`, or records the end of a turn of the agent's own.
    fn finish(&mut self, prompt: Option<Value>, stop: &str) {
        if let Some(id) = prompt {
            self.answer(&id, &json!({ "stopReason": stop }));
            self.record(&json!({ "sent": "reply", "id": id, "stop": stop }));
        } else {
            self.record(&json!({ "sent": "turn end" }));
        }
    }

    /// Sends a `tool_call_update` for `call` and records it.
    fn send_update(&mut self, call: &str, status: &str) {
        self.update(&json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": call,
            "status": status,
        }));
        self.record(&json!({ "sent": "update", "call": call, "status": status }));
    }

    /// Takes the client's response to a request of the agent's.
    fn response(&mut self, id: &Value, frame: &Value) {
        let outcome = frame["result"]["outcome"]["outcome"].as_str();
        let option = frame["result"]["outcome"]["optionId"].as_str();
        let answer = match (outcome, option) {
            (Some("cancelled"), _) => Some(Outcome::Cancelled),
            (Some("selected"), Some(option)) => self.outcomes.get(option).copied(),
            _ => None,
        };
        self.record(&json!({
            "received": "response",
            "id": id,
            "outcome": outcome,
            "option": option,
        }));
        let waits = matches!(
            self.turn.as_ref().map(|turn| &turn.waiting),
            Some(Waiting::Response(number)) if Some(*number) == id.as_u64()
        );
        if waits {
            self.pending_call = None;
            self.last_answer = answer;
            if let Some(turn) = &mut self.turn {
                turn.waiting = Waiting::Nothing;
            }
        }
    }

    /// Whether the file that ends the agent has appeared. It records the exit when it has.
    fn is_told_to_exit(&self) -> bool {
        let Some(name) = &self.script.exit_after else {
            return false;
        };
        let told = self.directory.join(name).exists();
        if told {
            self.record(&json!({ "sent": "exit" }));
        }
        told
    }

    /// Sends the next tick whose file has appeared.
    fn tick(&mut self) {
        let Some(tick) = self.script.ticks.get(self.ticked) else {
            return;
        };
        if !self.directory.join(&tick.after).exists() {
            return;
        }
        let text = tick.say.clone();
        self.ticked += 1;
        self.update(&json!({
            "sessionUpdate": "agent_message_chunk",
            "content": { "type": "text", "text": text },
        }));
        self.record(&json!({ "sent": "tick", "text": text }));
    }

    /// Takes steps of the running turn until one waits. Returns the exit code if the program ends.
    fn advance(&mut self) -> Option<i32> {
        loop {
            let turn = self.turn.as_mut()?;
            match &turn.waiting {
                Waiting::Nothing => {}
                Waiting::Response(_) => return None,
                Waiting::File(name) => {
                    if !self.directory.join(name).exists() {
                        return None;
                    }
                    turn.waiting = Waiting::Nothing;
                }
            }
            let step = turn.steps.pop_front()?;
            if let Some(code) = self.take(step) {
                return Some(code);
            }
        }
    }

    /// Takes one step.
    fn take(&mut self, step: Step) -> Option<i32> {
        match step {
            Step::Say(text) => self.update(&json!({
                "sessionUpdate": "agent_message_chunk",
                "content": { "type": "text", "text": text },
            })),
            Step::Call { id, kind } => self.update(&json!({
                "sessionUpdate": "tool_call",
                "toolCallId": id,
                "title": id,
                "kind": kind,
                "status": "pending",
            })),
            Step::Ask(call) => self.ask_for(&call),
            Step::Update { call, status } => self.send_update(&call, &status),
            Step::When { outcome, then } => {
                if self.last_answer == Some(outcome)
                    && let Some(turn) = &mut self.turn
                {
                    for step in then.into_iter().rev() {
                        turn.steps.push_front(step);
                    }
                }
            }
            Step::Import(name) => self.import(&name),
            Step::Hold(name) => {
                if let Some(turn) = &mut self.turn {
                    turn.waiting = Waiting::File(PathBuf::from(name));
                }
            }
            Step::End(reason) => {
                if let Some(turn) = self.turn.take() {
                    self.finish(turn.prompt, &reason);
                }
            }
            Step::Exit(code) => return Some(code),
        }
        None
    }

    /// Reads the chunk `name` from the folder of the package's main file, as the agent's main file
    /// imports a chunk, and writes the bytes it read to the marker. The record says how many bytes
    /// it read, or why it read none.
    fn import(&mut self, name: &str) {
        let read = match &self.package {
            Some(folder) => std::fs::read(folder.join(name)).map_err(|why| why.to_string()),
            None => Err("the agent runs from no package".to_owned()),
        };
        let line = match read {
            Ok(bytes) => match std::fs::write(self.directory.join(MARKER_FILE), &bytes) {
                Ok(()) => json!({ "sent": "import", "file": name, "bytes": bytes.len() }),
                Err(why) => json!({ "sent": "import", "file": name, "error": why.to_string() }),
            },
            Err(why) => json!({ "sent": "import", "file": name, "error": why }),
        };
        self.record(&line);
    }

    /// Sends a permission request for `call` and makes the turn wait for its response.
    fn ask_for(&mut self, call: &str) {
        // The identifiers and kinds that both agents offer, as the host maps them: `proceed_once`
        // allows the call once, `proceed_always` allows it for good, and `cancel` rejects it once.
        let options = [
            ("proceed_once", "Allow once", "allow_once", Outcome::Allowed),
            (
                "proceed_always",
                "Always allow",
                "allow_always",
                Outcome::Allowed,
            ),
            ("cancel", "Reject", "reject_once", Outcome::Declined),
        ];
        self.outcomes = options
            .iter()
            .map(|(id, _, _, outcome)| ((*id).to_owned(), *outcome))
            .collect();
        let number = self.ask(
            "session/request_permission",
            &json!({
                "sessionId": SESSION,
                "toolCall": {
                    "toolCallId": call,
                    "title": call,
                    "kind": "execute",
                    "status": "pending",
                },
                "options": options
                    .iter()
                    .map(|(id, name, kind, _)| json!({ "optionId": id, "name": name, "kind": kind }))
                    .collect::<Vec<_>>(),
            }),
        );
        self.record(&json!({ "sent": "request", "id": number, "call": call }));
        self.pending_call = Some(call.to_owned());
        if let Some(turn) = &mut self.turn {
            turn.waiting = Waiting::Response(number);
        }
    }
}

/// The identifier of the one session the stand-in serves.
const SESSION: &str = "stand-in-session";
