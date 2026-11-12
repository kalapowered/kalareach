//! The native terminal: `codex --remote unix:///path`.
//!
//! It upgrades a connection to a WebSocket, as the pinned terminal does, starts a session with the
//! requests the pinned terminal starts with, asks for a turn, answers the approval the server asks
//! for, and leaves when the turn completes. Like the pinned terminal it leaves, with an error, when
//! the connection is lost.
//!
//! Where its standard input is a terminal a person is at it: it reads their keys and draws a
//! composer ([`crate::keyboard`]). A line sent from the composer is a prompt, and starts a turn; a
//! command of its list does what the command does (`/fork` and `/new` ask the server for a thread,
//! `/quit` leaves); and the server's request to run a command is shown as a dialog that the person
//! answers with a key, or that goes when the server says the request was answered. Its own turn at
//! the start, and the answers it gives itself to a request that names no command, are as they are
//! where no person is at it.

use std::collections::BTreeMap;

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio_websockets::{ClientBuilder, Message};

use crate::contract::{Contract, Frame, RELEASE, Side};
use crate::keyboard::{self, Command, DIRECTORY, Decoder, Screen, Typed};
use crate::variants::{KEY_VARIABLE, RELEASE_VARIABLE, Variants, padded};

/// The identifiers the terminal gives its requests, after `initialize`'s.
const ACCOUNT: i64 = 1;
const SIGN_IN: i64 = 4;
const THREAD: i64 = 2;
pub(crate) const TURN: i64 = 3;
/// The requests a person's commands make: forking the thread, and starting a new one.
const FORK: i64 = 5;
const NEW: i64 = 6;

/// The request that begins the terminal's conversation: resuming the saved one it was started
/// with (`resume <id>`), or a new one.
fn begin(prompt: &str) -> Value {
    match prompt.strip_prefix("resume ") {
        Some(saved) => {
            json!({ "id": THREAD, "method": "thread/resume", "params": { "threadId": saved } })
        }
        None => json!({ "id": THREAD, "method": "thread/start", "params": {} }),
    }
}

/// Runs the terminal against the server at `socket`, and returns the exit status it ends with.
pub async fn run(contract: Contract, variants: Variants, socket: &str, prompt: &str) -> i32 {
    // Where a person is at the terminal its keys are read and its composer drawn; elsewhere every
    // line is written as it is.
    let mut screen = Screen::open();
    macro_rules! say {
        ($screen:expr, $($arguments:tt)*) => {
            $screen.say(format_args!($($arguments)*))
        };
    }
    if variants.idle {
        // A terminal that was started and never connects, as one that ran as typed does not.
        std::future::pending::<()>().await;
    }
    if variants.tick
        && let Ok(release) = std::env::var(RELEASE_VARIABLE)
    {
        tokio::spawn(async move {
            for number in 1_u64.. {
                let released = format!("{release}.tick{number}");
                while !std::path::Path::new(&released).exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                println!("TUI: tick {number}");
            }
        });
    }
    if variants.wait_to_connect
        && let Ok(release) = std::env::var(RELEASE_VARIABLE)
    {
        say!(screen, "TUI: waiting to connect");
        while !std::path::Path::new(&release).exists() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
    // The first attempt carries an `Origin` header under that variant. A terminal that is refused
    // goes away, or under `retry-plain` tries once more without it, as a person starting it again
    // would.
    let mut origin = variants.origin;
    let mut connection = loop {
        let stream = match tokio::net::UnixStream::connect(socket).await {
            Ok(stream) => stream,
            Err(error) => {
                say!(
                    screen,
                    "Error: remote app server at `unix://{socket}` could not be reached: {error}"
                );
                return 1;
            }
        };
        let mut builder = ClientBuilder::new()
            .uri("ws://localhost/rpc")
            .expect("a URI");
        if origin {
            builder = builder
                .add_header(
                    http::header::ORIGIN,
                    http::HeaderValue::from_static("http://example.test"),
                )
                .expect("an Origin header");
        }
        match builder.connect_on(stream).await {
            Ok((connection, _)) => break connection,
            Err(error) => {
                say!(
                    screen,
                    "Error: remote app server at `unix://{socket}` did not upgrade: {error}"
                );
                if origin && variants.retry_plain {
                    origin = false;
                    continue;
                }
                return 1;
            }
        }
    };
    // The requests this terminal has made and had no answer to, by identifier.
    let mut sent: BTreeMap<String, String> = BTreeMap::new();
    // The server's requests this terminal has not answered, by identifier.
    let mut received: BTreeMap<String, String> = BTreeMap::new();
    // How many requests the server has made of this terminal.
    let mut requests_read = 0_usize;

    macro_rules! send {
        ($frame:expr) => {{
            let frame: Value = $frame;
            match contract.check(Side::Terminal, &frame, &received) {
                Ok(Frame::Request { id, method }) => {
                    sent.insert(id, method);
                }
                Ok(Frame::Response { id, .. } | Frame::Failure { id, .. }) => {
                    received.remove(&id);
                }
                Ok(Frame::Notification { .. }) => {}
                Err(why) => {
                    eprintln!(
                        "stand-in: the terminal would write a frame the pinned release does not: \
                         {why}: {frame}"
                    );
                    return 3;
                }
            }
            if connection
                .send(Message::text(frame.to_string()))
                .await
                .is_err()
            {
                say!(
                    screen,
                    "Error: remote app server transport failed: the connection was lost"
                );
                return 1;
            }
        }};
    }

    send!(json!({
        "id": "initialize",
        "method": "initialize",
        "params": {
            "clientInfo": { "name": "codex-tui", "title": null, "version": RELEASE },
            "capabilities": {
                "experimentalApi": true,
                "requestAttestation": false,
                "optOutNotificationMethods": null
            }
        }
    }));
    // The thread and the turn the server has said it started.
    let mut thread = String::new();
    let mut turn = String::new();
    // Whether the next answer to `account/read` is the one `ping-when-released` asked for.
    let mut pinged = false;
    // What a terminal under `keep-reading` has to say once the file it waits for exists, each with
    // that file: it is sent in the order it was held, and the connection is read meanwhile.
    let mut held: Vec<(String, Value)> = Vec::new();
    // The keys a person types, where one is at the terminal, and the end of a key that came in part.
    let mut typed = screen.is_typed_at().then(keyboard::reader);
    let mut decoder = Decoder::default();
    loop {
        let event = tokio::select! {
            message = connection.next() => Event::Message(message),
            keys = next_keys(&mut typed) => Event::Keys(keys),
            () = tokio::time::sleep(std::time::Duration::from_millis(20)), if !held.is_empty() => {
                Event::Held
            }
        };
        let next = match event {
            Event::Message(message) => message,
            Event::Held => {
                let mut waiting = Vec::new();
                for (release, frame) in std::mem::take(&mut held) {
                    if std::path::Path::new(&release).exists() {
                        send!(frame);
                    } else {
                        waiting.push((release, frame));
                    }
                }
                held = waiting;
                continue;
            }
            Event::Keys(None) => {
                typed = None;
                continue;
            }
            Event::Keys(Some(bytes)) => {
                let mut actions = Vec::new();
                for key in decoder.keys(&bytes) {
                    actions.extend(screen.key(key));
                }
                screen.redraw();
                for action in actions {
                    match action {
                        Typed::Prompt(text) => {
                            if !thread.is_empty() {
                                send!(turn_request(&thread, &text));
                            }
                        }
                        Typed::Command(Command::Directory) => {
                            let directory = std::env::current_dir().unwrap_or_default();
                            say!(screen, "{DIRECTORY} {}", directory.display());
                        }
                        Typed::Command(Command::Fork) => send!(json!({
                            "id": FORK,
                            "method": "thread/fork",
                            "params": { "threadId": thread }
                        })),
                        Typed::Command(Command::New) => {
                            send!(json!({ "id": NEW, "method": "thread/start", "params": {} }));
                        }
                        Typed::Command(Command::Quit) => {
                            // A person quitting closes the connection as it leaves.
                            let _ = connection.send(Message::close(None, "")).await;
                            return 0;
                        }
                        Typed::Decision { request, decision } => {
                            send!(json!({ "id": request, "result": { "decision": decision } }));
                        }
                    }
                }
                continue;
            }
        };
        let message = match next {
            Some(Ok(message)) => message,
            Some(Err(error)) => {
                say!(screen, "Error: remote app server transport failed: {error}");
                return 1;
            }
            None => {
                say!(
                    screen,
                    "Error: remote app server transport failed: the connection ended with the \
                     session unfinished"
                );
                return 1;
            }
        };
        if message.is_close() {
            let code = message.as_close().map_or(0, |(code, _)| u16::from(code));
            say!(
                screen,
                "Error: remote app server closed the connection (close code {code})"
            );
            return 1;
        }
        if message.is_ping() || message.is_pong() {
            continue;
        }
        let Some(text) = message.as_text() else {
            eprintln!("stand-in: a message that is not text");
            return 3;
        };
        let Ok(frame) = serde_json::from_str::<Value>(text) else {
            eprintln!("stand-in: a message that is not JSON: {text}");
            return 3;
        };
        let checked = match contract.check(Side::Server, &frame, &sent) {
            Ok(checked) => checked,
            Err(why) => {
                eprintln!(
                    "stand-in: the server wrote a frame the pinned release does not: {why}: {frame}"
                );
                return 3;
            }
        };
        match checked {
            Frame::Response { id, method } => {
                sent.remove(&id);
                match method.as_str() {
                    "initialize" => {
                        send!(json!({ "method": "initialized" }));
                        send!(json!({ "id": ACCOUNT, "method": "account/read", "params": {} }));
                    }
                    "account/read" if pinged => {
                        pinged = false;
                        say!(screen, "TUI: the server answered after the turn");
                    }
                    "account/read" => {
                        say!(screen, "TUI: signed out; the stand-in goes on");
                        if variants.login {
                            let key = std::env::var(KEY_VARIABLE).unwrap_or_default();
                            send!(json!({
                                "id": SIGN_IN,
                                "method": "account/login/start",
                                "params": { "type": "apiKey", "apiKey": key }
                            }));
                        } else {
                            if variants.hold_before_thread
                                && let Ok(mut release) = std::env::var(RELEASE_VARIABLE)
                            {
                                release.push_str(".thread");
                                say!(screen, "TUI: holding before the thread starts");
                                while !std::path::Path::new(&release).exists() {
                                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                                }
                            }
                            send!(begin(prompt));
                        }
                    }
                    // The thread a person's command forked or started is the one the terminal is on
                    // from here, and no turn begins in it.
                    "thread/fork" | "thread/start"
                        if id == FORK.to_string() || id == NEW.to_string() =>
                    {
                        thread = frame["result"]["thread"]["id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned();
                    }
                    "thread/start" | "thread/resume" => {
                        thread = frame["result"]["thread"]["id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned();
                        screen.begins();
                        // A terminal a person resumes a conversation in starts no turn of its own
                        // with the words typed to resume it.
                        let own = if screen.is_typed_at() && prompt.starts_with("resume ") {
                            ""
                        } else {
                            prompt
                        };
                        let text = match Variants::pad() {
                            Some(size) => {
                                padded(size, |text| turn_request(&thread, text).to_string())
                            }
                            None => own.to_owned(),
                        };
                        send!(turn_request(&thread, &text));
                    }
                    "turn/start" => {
                        turn = frame["result"]["turn"]["id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned();
                        say!(screen, "TUI: a turn is running");
                        if variants.stop_reading {
                            // Nothing more is read from the connection, and nothing is closed.
                            std::future::pending::<()>().await;
                        }
                    }
                    _ => {}
                }
            }
            Frame::Failure { id, method } if method == "account/login/start" => {
                sent.remove(&id);
                say!(screen, "TUI: the sign-in was refused; the stand-in goes on");
                send!(json!({ "id": THREAD, "method": "thread/start", "params": {} }));
            }
            Frame::Failure { method, .. } => {
                say!(screen, "Error: the server refused {method}");
                return 1;
            }
            Frame::Request { id, method } => {
                received.insert(id.clone(), method.clone());
                requests_read += 1;
                // A request to run a command is shown to the person as a dialog, and answered with
                // the key they choose; any other is answered here.
                let asked_of_the_person = screen.is_typed_at()
                    && method == "item/commandExecution/requestApproval"
                    && frame["params"]["command"]
                        .as_str()
                        .is_some_and(|command| !command.is_empty());
                if asked_of_the_person {
                    screen.asks(
                        serde_json::from_str(&id).expect("an identifier"),
                        frame["params"]["command"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned(),
                    );
                }
                say!(screen, "TUI: the server asks for {method}");
                if asked_of_the_person {
                    continue;
                }
                if variants.leave_unanswered
                    || (variants.leave_second_unanswered && requests_read > 1)
                {
                    continue;
                }
                let id_value: Value = serde_json::from_str(&id).expect("an identifier");
                let decision = if variants.decline {
                    "decline"
                } else {
                    "accept"
                };
                let answer = json!({ "id": id_value, "result": { "decision": decision } });
                if variants.answer_when_released
                    && let Ok(mut release) = std::env::var(RELEASE_VARIABLE)
                {
                    if requests_read > 1 {
                        release.push_str(".second");
                    }
                    if variants.keep_reading {
                        say!(screen, "TUI: holding the answer to {method}");
                        held.push((release, answer));
                        continue;
                    }
                    while !std::path::Path::new(&release).exists() {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                }
                send!(answer);
            }
            Frame::Notification { method } => {
                match method.as_str() {
                    "turn/started" => screen.works(true),
                    "turn/completed" => screen.works(false),
                    // The server's word that a request was answered, by whoever answered it.
                    "serverRequest/resolved" => {
                        let request = &frame["params"]["requestId"];
                        received.remove(&request.to_string());
                        screen.resolved(request);
                    }
                    _ => {}
                }
                say!(screen, "TUI: {method}");
                if variants.answer_the_sum
                    && method == "item/agentMessage/delta"
                    && let Some(answer) = frame["params"]["delta"].as_str()
                {
                    say!(screen, "TUI: {answer}");
                }
                let completed = method == "turn/completed"
                    && frame["params"]["threadId"] == thread.as_str()
                    && frame["params"]["turn"]["id"] == turn.as_str();
                if completed && !variants.stay {
                    // A person quitting closes the connection as it leaves.
                    let _ = connection.send(Message::close(None, "")).await;
                    return 0;
                }
                if completed
                    && variants.request_when_released
                    && let Ok(release) = std::env::var(RELEASE_VARIABLE)
                {
                    while !std::path::Path::new(&release).exists() {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                    send!(json!({ "id": ACCOUNT, "method": "account/read", "params": {} }));
                }
                if completed
                    && variants.ping_when_released
                    && let Ok(release) = std::env::var(RELEASE_VARIABLE)
                {
                    if variants.keep_reading {
                        pinged = true;
                        held.push((
                            release,
                            json!({ "id": ACCOUNT, "method": "account/read", "params": {} }),
                        ));
                        continue;
                    }
                    while !std::path::Path::new(&release).exists() {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    }
                    pinged = true;
                    send!(json!({ "id": ACCOUNT, "method": "account/read", "params": {} }));
                }
            }
        }
    }
}

/// What the terminal waits for.
enum Event {
    Message(Option<Result<Message, tokio_websockets::Error>>),
    /// What a person typed, or that nothing more can be.
    Keys(Option<Vec<u8>>),
    /// A moment in which to look at what is held for a file.
    Held,
}

/// The next keys a person types: for ever where none can be.
async fn next_keys(
    keys: &mut Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>,
) -> Option<Vec<u8>> {
    match keys {
        Some(keys) => keys.recv().await,
        None => std::future::pending().await,
    }
}

/// The request that starts a turn on `thread` with `text` for the agent.
fn turn_request(thread: &str, text: &str) -> Value {
    json!({
        "id": TURN,
        "method": "turn/start",
        "params": {
            "threadId": thread,
            "input": [{ "type": "text", "text": text, "text_elements": [] }]
        }
    })
}
