//! A recording stand-in for Firebase Cloud Messaging on one loopback port.
//!
//! A development gateway sends to the origin it is told (`FCM_SEND_ORIGIN`) in place of Google's,
//! and signs its access-token request for the service account's own `token_uri`, which a device run
//! points here too. This answers both the way the provider does for a message it takes: a token
//! for the account, and the name of each message sent. It keeps every message it was given, whole,
//! so a device run can read what the gateway sent and put it on a phone. No credential of any real
//! project is anywhere in this: the service account is generated for the run.
//!
//! A message for one token can be answered as the provider answers a token it does not know
//! (`UNREGISTERED`), which is how a destination goes out of service.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The access token the stand-in issues, and the only one it accepts a send under.
pub const ACCESS_TOKEN: &str = "stand-in-access-token";

/// One message the gateway sent.
#[derive(Clone, Debug)]
pub struct Sent {
    /// Its order, from 1.
    pub n: usize,
    /// The registration token it was addressed to.
    pub token: String,
    /// The whole body the gateway sent, as the provider received it.
    pub body: serde_json::Value,
    /// The body's length in bytes, which is what the provider's size limit applies to.
    pub bytes: usize,
    /// When the stand-in received it, in UTC milliseconds.
    pub received_at_ms: u64,
    /// Whether it was sent under the access token the stand-in issued.
    pub authorised: bool,
    /// What the stand-in answered.
    pub answered: Answer,
}

/// What the stand-in answers a send with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The message is taken, and named.
    Taken,
    /// The token is not one the provider knows.
    Unregistered,
}

#[derive(Default)]
struct State {
    sent: Vec<Sent>,
    /// The tokens a send is answered `UNREGISTERED` for.
    unknown: BTreeSet<String>,
    /// How many requests for an access token were answered.
    minted: usize,
    /// Every path the stand-in was asked for, in order.
    paths: Vec<String>,
}

/// The stand-in.
pub struct Fcm {
    port: u16,
    state: Arc<Mutex<State>>,
    serving: tokio::task::JoinHandle<()>,
}

impl Drop for Fcm {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

fn now_ms() -> u64 {
    kr_ipc::now_ms().get()
}

impl Fcm {
    /// Starts it on `port`, or on a free one when `port` is zero.
    ///
    /// # Panics
    ///
    /// Panics when the port cannot be bound.
    pub async fn start(port: u16) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("the stand-in's port");
        let port = listener.local_addr().expect("an address").port();
        let state = Arc::new(Mutex::new(State::default()));
        let shared = Arc::clone(&state);
        let serving = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let state = Arc::clone(&shared);
                tokio::spawn(async move { serve(stream, &state).await });
            }
        });
        Self {
            port,
            state,
            serving,
        }
    }

    /// Its origin.
    #[must_use]
    pub fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Every message received so far, in order.
    #[must_use]
    pub fn sent(&self) -> Vec<Sent> {
        self.state
            .lock()
            .expect("the stand-in's state")
            .sent
            .clone()
    }

    /// How many access tokens were issued.
    #[must_use]
    pub fn minted(&self) -> usize {
        self.state.lock().expect("the stand-in's state").minted
    }

    /// Answers every later send to `token` as the provider answers a token it does not know.
    pub fn forget(&self, token: &str) {
        self.state
            .lock()
            .expect("the stand-in's state")
            .unknown
            .insert(token.to_owned());
    }

    /// Takes sends to `token` again.
    pub fn know(&self, token: &str) {
        self.state
            .lock()
            .expect("the stand-in's state")
            .unknown
            .remove(token);
    }

    /// Every path asked for, in order: nothing but the token and the send routes belongs here.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("the stand-in's state")
            .paths
            .clone()
    }
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

fn response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// Reads one request: its head and its body.
async fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    let head_end = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(at) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break at;
        }
        if bytes.len() > 64 * 1024 {
            return None;
        }
    };
    let head = String::from_utf8_lossy(&bytes[..head_end]).into_owned();
    let length = header(&head, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = bytes[head_end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    Some((head, body))
}

async fn serve(mut stream: TcpStream, state: &Arc<Mutex<State>>) {
    let Some((head, body)) = read_request(&mut stream).await else {
        return;
    };
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("")
        .to_owned();
    let authorization = header(&head, "authorization");
    let answer = {
        let mut state = state.lock().expect("the stand-in's state");
        state.paths.push(path.clone());
        if path == "/token" {
            state.minted += 1;
            response(
                200,
                serde_json::json!({
                    "access_token": ACCESS_TOKEN,
                    "expires_in": 3600,
                    "token_type": "Bearer",
                })
                .to_string()
                .as_bytes(),
            )
        } else if path.ends_with("/messages:send") {
            let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let token = parsed["message"]["token"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let n = state.sent.len() + 1;
            let answered = if state.unknown.contains(&token) {
                Answer::Unregistered
            } else {
                Answer::Taken
            };
            state.sent.push(Sent {
                n,
                token,
                bytes: body.len(),
                body: parsed,
                received_at_ms: now_ms(),
                authorised: authorization.as_deref() == Some(&format!("Bearer {ACCESS_TOKEN}")),
                answered,
            });
            match answered {
                Answer::Taken => response(
                    200,
                    serde_json::json!({ "name": format!("projects/stand-in/messages/{n}") })
                        .to_string()
                        .as_bytes(),
                ),
                Answer::Unregistered => response(
                    404,
                    serde_json::json!({
                        "error": {
                            "code": 404,
                            "message": "Requested entity was not found.",
                            "status": "NOT_FOUND",
                            "details": [{
                                "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                                "errorCode": "UNREGISTERED",
                            }],
                        }
                    })
                    .to_string()
                    .as_bytes(),
                ),
            }
        } else {
            response(404, b"{}")
        }
    };
    let _ = stream.write_all(&answer).await;
}
