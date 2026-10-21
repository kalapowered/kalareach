//! The native terminal: `codex --remote unix:///path`.
//!
//! It upgrades a connection to a WebSocket, as the pinned terminal does, starts a session with the
//! requests the pinned terminal starts with, asks for a turn, answers the approval the server asks
//! for, and leaves when the turn completes. Like the pinned terminal it leaves, with an error, when
//! the connection is lost.

use std::collections::BTreeMap;

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio_websockets::{ClientBuilder, Message};

use crate::contract::{Contract, Frame, RELEASE, Side};
use crate::variants::{KEY_VARIABLE, RELEASE_VARIABLE, Variants, padded};

/// The identifiers the terminal gives its requests, after `initialize`'s.
const ACCOUNT: i64 = 1;
const SIGN_IN: i64 = 4;
const THREAD: i64 = 2;
pub(crate) const TURN: i64 = 3;

/// Runs the terminal against the server at `socket`, and returns the exit status it ends with.
pub async fn run(contract: Contract, variants: Variants, socket: &str, prompt: &str) -> i32 {
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
        println!("TUI: waiting to connect");
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
                println!(
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
                println!("Error: remote app server at `unix://{socket}` did not upgrade: {error}");
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
                println!("Error: remote app server transport failed: the connection was lost");
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
    loop {
        let next = if held.is_empty() {
            connection.next().await
        } else {
            tokio::select! {
                message = connection.next() => message,
                () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {
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
            }
        };
        let message = match next {
            Some(Ok(message)) => message,
            Some(Err(error)) => {
                println!("Error: remote app server transport failed: {error}");
                return 1;
            }
            None => {
                println!(
                    "Error: remote app server transport failed: the connection ended with the \
                     session unfinished"
                );
                return 1;
            }
        };
        if message.is_close() {
            let code = message.as_close().map_or(0, |(code, _)| u16::from(code));
            println!("Error: remote app server closed the connection (close code {code})");
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
                        println!("TUI: the server answered after the turn");
                    }
                    "account/read" => {
                        println!("TUI: signed out; the stand-in goes on");
                        if variants.login {
                            let key = std::env::var(KEY_VARIABLE).unwrap_or_default();
                            send!(json!({
                                "id": SIGN_IN,
                                "method": "account/login/start",
                                "params": { "type": "apiKey", "apiKey": key }
                            }));
                        } else {
                            send!(json!({ "id": THREAD, "method": "thread/start", "params": {} }));
                        }
                    }
                    "thread/start" => {
                        thread = frame["result"]["thread"]["id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned();
                        let text = match Variants::pad() {
                            Some(size) => {
                                padded(size, |text| turn_request(&thread, text).to_string())
                            }
                            None => prompt.to_owned(),
                        };
                        send!(turn_request(&thread, &text));
                    }
                    "turn/start" => {
                        turn = frame["result"]["turn"]["id"]
                            .as_str()
                            .unwrap_or_default()
                            .to_owned();
                        println!("TUI: a turn is running");
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
                println!("TUI: the sign-in was refused; the stand-in goes on");
                send!(json!({ "id": THREAD, "method": "thread/start", "params": {} }));
            }
            Frame::Failure { method, .. } => {
                println!("Error: the server refused {method}");
                return 1;
            }
            Frame::Request { id, method } => {
                received.insert(id.clone(), method.clone());
                requests_read += 1;
                println!("TUI: the server asks for {method}");
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
                        println!("TUI: holding the answer to {method}");
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
                println!("TUI: {method}");
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
