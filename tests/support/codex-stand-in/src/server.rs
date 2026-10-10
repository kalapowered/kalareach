//! The application server: `codex app-server --listen stdio://`.
//!
//! One JSON document per line on standard input and output. It answers the requests a terminal
//! starts a session with, in the order the pinned release requires them, runs one turn that starts
//! the configured command and asks for one approval, and finishes the turn when the approval is
//! answered.

use std::collections::BTreeMap;
use std::process::Stdio;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, Command};
use tokio::signal::unix::{Signal, SignalKind, signal};

use crate::contract::{Contract, Frame, RELEASE, Side};
use crate::variants::{Variants, padded};

/// The identifier of the one approval the server asks for.
const APPROVAL: &str = "approval-1";

/// The program's argument that makes it lead a session of its own and run a command in it.
pub const EXEC_IN_NEW_SESSION: &str = "--exec-in-new-session";

/// Where a connection is in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Nothing has been said.
    Fresh,
    /// `initialize` was answered and `initialized` has not come.
    Initializing,
    /// The session is open.
    Ready,
}

/// A command the server started, and whether it leads a process group of its own.
struct Started {
    child: Child,
    leads_group: bool,
}

struct Server {
    contract: Contract,
    variants: Variants,
    out: tokio::io::Stdout,
    phase: Phase,
    /// The thread the server started, once it has.
    thread: Option<String>,
    /// The terminal's requests the server has not answered, by identifier.
    received: BTreeMap<String, String>,
    /// The server's own requests the terminal has not answered, by identifier.
    sent: BTreeMap<String, String>,
    commands: Vec<Started>,
}

fn thread() -> Value {
    json!({
        "cliVersion": RELEASE,
        "createdAt": 0,
        "cwd": "/",
        "ephemeral": false,
        "id": "thread-1",
        "modelProvider": "stand-in",
        "preview": "",
        "projectId": null,
        "sessionId": "session-1",
        "source": "appServer",
        "status": { "type": "idle" },
        "turns": [],
        "updatedAt": 0
    })
}

fn turn(status: &str) -> Value {
    json!({ "id": "turn-1", "items": [], "status": status })
}

impl Server {
    /// Writes one frame, after checking that the pinned release could have written it.
    async fn send(&mut self, frame: Value) {
        match self.contract.check(Side::Server, &frame, &self.received) {
            Ok(Frame::Response { id, .. } | Frame::Failure { id, .. }) => {
                self.received.remove(&id);
            }
            Ok(_) => {}
            Err(why) => {
                eprintln!(
                    "stand-in: the server would write a frame the pinned release does not: {why}: \
                     {frame}"
                );
                std::process::exit(3);
            }
        }
        let mut line = frame.to_string();
        line.push('\n');
        if self.out.write_all(line.as_bytes()).await.is_err() || self.out.flush().await.is_err() {
            self.finish().await;
        }
    }

    /// Answers a request with an error.
    async fn refuse(&mut self, id: &Value, code: i64, message: &str) {
        self.send(json!({ "id": id, "error": { "code": code, "message": message } }))
            .await;
    }

    /// Ends the server's commands, each with what it started, and exits, as the pinned release
    /// does when it is told to.
    async fn finish(&mut self) -> ! {
        for started in &mut self.commands {
            let leader = started.child.id().and_then(|pid| i32::try_from(pid).ok());
            match leader {
                Some(pid) if started.leads_group => {
                    if let Some(group) = rustix::process::Pid::from_raw(pid) {
                        let _ = rustix::process::kill_process_group(
                            group,
                            rustix::process::Signal::KILL,
                        );
                    }
                }
                _ => {
                    let _ = started.child.start_kill();
                }
            }
        }
        for started in &mut self.commands {
            let _ = started.child.wait().await;
        }
        std::process::exit(0);
    }

    fn start_command(&mut self) {
        let Some(words) = Variants::command() else {
            return;
        };
        let leads_group = !self.variants.command_shares_group;
        let mut command = if leads_group {
            // The program runs itself in a session of its own, which the command then leads: a
            // session leader leads a process group too.
            let mut command = Command::new(std::env::current_exe().expect("this program's path"));
            command.arg(EXEC_IN_NEW_SESSION).args(&words);
            command
        } else {
            let mut command = Command::new(&words[0]);
            command.args(&words[1..]);
            command
        };
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        match command.spawn() {
            Ok(child) => {
                // Said on the error stream, where a test that wants the command's identifier
                // reads it.
                eprintln!(
                    "stand-in: started command {}",
                    child.id().unwrap_or_default()
                );
                self.commands.push(Started { child, leads_group });
            }
            Err(error) => eprintln!("stand-in: the command could not start: {error}"),
        }
    }

    /// Takes a frame the terminal wrote that the pinned release would not have written.
    async fn violation(&mut self, why: &str, frame: &Value) {
        eprintln!(
            "stand-in: the terminal wrote a frame the pinned release does not: {why}: {frame}"
        );
        // A request with an identifier the protocol has is answered, as a server answers a request
        // it cannot read. Anything else is a fault the terminal side cannot be told about.
        let answerable = match frame.get("id") {
            Some(id @ Value::String(_)) => Some(id.clone()),
            Some(id @ Value::Number(number)) if number.is_i64() => Some(id.clone()),
            _ => None,
        };
        match (answerable, frame.get("method")) {
            (Some(id), Some(_)) => {
                self.received.insert(id.to_string(), "invalid".to_owned());
                self.refuse(&id, -32602, &format!("invalid frame: {why}"))
                    .await;
            }
            _ => std::process::exit(3),
        }
    }

    async fn handle(&mut self, frame: Value) {
        let checked = match self.contract.check(Side::Terminal, &frame, &self.sent) {
            Ok(checked) => checked,
            Err(why) => return self.violation(&why, &frame).await,
        };
        match checked {
            Frame::Request { id, method } => {
                self.received.insert(id.clone(), method.clone());
                let id_value: Value = serde_json::from_str(&id).expect("an identifier");
                self.request(&id_value, &method, &frame).await;
            }
            Frame::Notification { method } => {
                // The only notification a terminal writes, and only once, after `initialize`.
                if method == "initialized" && self.phase == Phase::Initializing {
                    self.phase = Phase::Ready;
                } else {
                    eprintln!("stand-in: {method} came when the pinned release does not take it");
                    std::process::exit(3);
                }
            }
            Frame::Response { id, method } | Frame::Failure { id, method } => {
                self.sent.remove(&id);
                if method == "item/commandExecution/requestApproval" {
                    self.send(json!({
                        "method": "turn/completed",
                        "params": { "threadId": "thread-1", "turn": turn("completed") }
                    }))
                    .await;
                }
            }
        }
    }

    async fn request(&mut self, id: &Value, method: &str, frame: &Value) {
        if method == "initialize" {
            if self.phase != Phase::Fresh {
                return self.refuse(id, -32600, "Already initialized").await;
            }
            self.phase = Phase::Initializing;
            self.send(json!({ "id": id, "result": {
                "userAgent": format!("codex-stand-in/{RELEASE}"),
                "codexHome": "/stand-in",
                "platformFamily": "unix",
                "platformOs": std::env::consts::OS
            }}))
            .await;
            self.send(json!({
                "method": "remoteControl/status/changed",
                "params": {
                    "status": "disabled",
                    "serverName": "stand-in",
                    "installationId": "00000000-0000-4000-8000-000000000000",
                    "environmentId": null
                },
                "emittedAtMs": 0
            }))
            .await;
            return;
        }
        if self.phase != Phase::Ready {
            return self.refuse(id, -32600, "Not initialized").await;
        }
        match method {
            "account/read" => {
                self.send(json!({ "id": id, "result": {
                    "account": null, "requiresOpenaiAuth": true
                }}))
                .await;
            }
            "thread/start" if self.thread.is_none() => {
                self.thread = Some("thread-1".to_owned());
                self.send(json!({ "id": id, "result": {
                    "approvalPolicy": "on-request",
                    "approvalsReviewer": "user",
                    "cwd": "/",
                    "model": "stand-in",
                    "modelProvider": "stand-in",
                    "sandbox": { "type": "dangerFullAccess" },
                    "thread": thread()
                }}))
                .await;
                self.send(json!({
                    "method": "thread/started",
                    "params": { "thread": thread() }
                }))
                .await;
            }
            "turn/start" => self.turn(id, frame).await,
            other => {
                self.refuse(id, -32601, &format!("the stand-in does not serve {other}"))
                    .await;
            }
        }
    }

    async fn turn(&mut self, id: &Value, frame: &Value) {
        if frame["params"]["threadId"].as_str() != self.thread.as_deref() {
            return self.refuse(id, -32600, "thread not found").await;
        }
        eprintln!("stand-in: turn started");
        self.start_command();
        if self.variants.die_first {
            std::process::exit(0);
        }
        let approval = json!({
            "id": if self.variants.colliding_ids { id.clone() } else { json!(APPROVAL) },
            "method": "item/commandExecution/requestApproval",
            "params": {
                "itemId": "item-1",
                "startedAtMs": 0,
                "threadId": "thread-1",
                "turnId": "turn-1"
            }
        });
        let asked = approval["id"].to_string();
        let answer = json!({ "id": id, "result": { "turn": turn("inProgress") }});
        let started = json!({
            "method": "turn/started",
            "params": { "threadId": "thread-1", "turn": turn("inProgress") }
        });
        self.sent
            .insert(asked, "item/commandExecution/requestApproval".to_owned());
        // The request for the approval goes before the answer to the terminal's own request when
        // the two share an identifier, so that both are outstanding at once.
        if self.variants.colliding_ids {
            self.send(approval).await;
            self.send(answer).await;
            self.send(started).await;
        } else {
            self.send(answer).await;
            self.send(started).await;
            self.send(approval).await;
        }
        if let Some(size) = Variants::pad() {
            let text = padded(size, |text| {
                json!({
                    "method": "item/agentMessage/delta",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "itemId": "item-1",
                        "delta": text
                    }
                })
                .to_string()
            });
            self.send(json!({
                "method": "item/agentMessage/delta",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "itemId": "item-1",
                    "delta": text
                }
            }))
            .await;
        }
    }
}

/// Waits for the next signal to terminate, for ever when there is none to wait for.
async fn terminated(terminate: &mut Signal) {
    terminate.recv().await;
}

/// Runs the server until its input ends, or for ever when it is told to ignore that.
///
/// The handler for terminate is installed before anything else is done, so that a program that
/// takes a while to start is not one a signal can kill before it is ready for it.
pub async fn run(variants: Variants) -> ! {
    let mut terminate = signal(SignalKind::terminate()).expect("a handler for terminate");
    let contract = Contract::pinned();
    if variants.flood_stderr {
        tokio::task::spawn_blocking(|| {
            let line = format!("{}\n", "stand-in noise ".repeat(64));
            let mut written = 0_usize;
            while written < 16 << 20 {
                eprint!("{line}");
                written += line.len();
            }
        });
    }
    let ignore_term = variants.ignore_term;
    let mut server = Server {
        contract,
        variants,
        out: tokio::io::stdout(),
        phase: Phase::Fresh,
        thread: None,
        received: BTreeMap::new(),
        sent: BTreeMap::new(),
        commands: Vec::new(),
    };
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            () = terminated(&mut terminate) => {
                if !ignore_term {
                    server.finish().await;
                }
            }
            line = lines.next_line() => match line {
                Ok(Some(line)) if line.trim().is_empty() => {}
                Ok(Some(line)) => match serde_json::from_str::<Value>(&line) {
                    Ok(frame) => server.handle(frame).await,
                    Err(error) => {
                        eprintln!("stand-in: a line that is not JSON: {error}");
                        std::process::exit(3);
                    }
                },
                Ok(None) | Err(_) => {
                    if server.variants.ignore_eof {
                        // The input has ended and the server goes on, still answering a terminate.
                        loop {
                            terminated(&mut terminate).await;
                            if !ignore_term {
                                server.finish().await;
                            }
                        }
                    }
                    server.finish().await;
                }
            }
        }
    }
}

/// Runs `words` in a session of its own, which it leads, in place of this program.
pub fn exec_in_new_session(words: &[String]) -> ! {
    use std::os::unix::process::CommandExt as _;
    let _ = rustix::process::setsid();
    let error = std::process::Command::new(&words[0])
        .args(&words[1..])
        .exec();
    eprintln!("stand-in: {} could not run: {error}", words[0]);
    std::process::exit(127);
}
