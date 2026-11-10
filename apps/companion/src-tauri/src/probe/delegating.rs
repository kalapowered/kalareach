//! The legs of the connected run: a call that hands spoken requests to a real host, played by the
//! probe in the application.
//!
//! In the shipped configuration a delegation is answered to the model that nothing was done, and the
//! host is sent nothing. The probe is a debug build, and it turns the acceptance on for its own call
//! through the setter that exists only in debug and test builds, so the gate the owner reads a
//! delegation by can be seen on a simulator and an emulator, end to end. One call is one leg. The
//! probe plays the person and the provider: it writes the provider's events to the call's
//! `oai-events` channel through the peer in this process, has the stand-in voice service announce
//! each delegation on the control socket as the service does, and reads what became of each one from
//! the call's own state. It never decides by a time. Each step waits for the owner's own sign: the
//! row of the delegation reaching a state, the capture word, the peer's report that a drop ran.
//!
//! Each negative leg is read beside its control, a request the same call handed over and the host
//! performed before the break the leg makes. The legs prove what this application does with the
//! gate on; they claim no production stop point, and a simulator or an emulator proves nothing of
//! what a phone's system does to a recording (the Android rule that a silenced recording is a break
//! needs a phone).

use std::future::Future;
use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::path::Path;
use std::pin::Pin;
use std::time::Duration;

use companion_platform::call::CallPlatform;
use serde_json::{Value, json};
use tauri::{AppHandle, Manager as _, Runtime};

use super::harness::{Harness, call_state, until};
use super::{Check, Checks};
use crate::commands;

/// How long a row of a delegation is given to reach the state a leg expects. The call's own wait
/// after a delegation, the proof and the host's answer all come inside it; a leg that stands here
/// stands on a call that did not decide.
const ROW_WITHIN: Duration = Duration::from_secs(60);

/// How long the microphone is given to show as carrying speech, and how long a peer is given to
/// report that a hook ran.
const SIGN_WITHIN: Duration = Duration::from_secs(30);

/// How long an HTTP exchange with the peer or the stand-in is given.
const EXCHANGE_WITHIN: Duration = Duration::from_secs(20);

/// How long audio is taken out of the recorder: above the capture gates' thresholds on both
/// platforms (40 ms between two buffers on Android, 100 ms short of the elapsed time over a second
/// on iOS), which are parameters and not bounds.
const DROP_MS: u64 = 400;

/// The one real session the host holds for the run, as the script names it.
const NO_SESSION: &str = "the host named no session for the run";

/// The audio packets a call must have received before a leg begins: the sign that the connection
/// carries audio and the application's own start is over.
const AUDIO_FLOOR: u64 = 50;

/// What a check says when the call's own recorder broke in a part of a leg that is not about a
/// break. A device script that finds it in a leg's result plays the leg again on a new call: the
/// leg's subject was never reached.
const BROKE_BY_ITSELF: &str = "the recorder broke by itself";

/// What the probe plays a leg through: the provider's data channel, the voice service's
/// announcements and the recorder's drop hook.
pub trait Driver: Send + Sync {
    /// Writes `bytes` to the call's `oai-events` channel as one text message, as the provider does.
    fn provider<'a>(&'a self, bytes: &'a [u8]) -> DriverFuture<'a, ()>;

    /// Has the voice service announce the delegation `id` at `offset_ms` on the control socket.
    fn announce<'a>(&'a self, id: &'a str, offset_ms: u64) -> DriverFuture<'a, ()>;

    /// Takes `milliseconds` out of the call's recorder.
    fn drop_recorder(&self, milliseconds: u64) -> DriverFuture<'_, ()>;

    /// How many drops the recorder has made.
    fn drops_made(&self) -> DriverFuture<'_, u64>;

    /// Whether the call's `oai-events` channel is open, so that the provider's events can be written.
    fn events_open(&self) -> DriverFuture<'_, bool>;

    /// The person muted or unmuted the microphone through the call's own command. A device's native
    /// code tells the news of it by itself, so a driver that plays a device has nothing to do; one
    /// that stands in for native code tells it here.
    fn after_a_mute(&self, muted: bool) -> DriverFuture<'_, ()>;
}

/// What a [`Driver`] step comes to.
pub type DriverFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// What a leg is for. Each is one call.
#[derive(serde::Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Leg {
    /// The shipped configuration: the probe does not turn the acceptance on.
    Production,
    /// No break and not the first utterance: a status said after one throwaway sentence.
    #[default]
    Positive,
    /// The command is the first thing said in the call.
    FirstUtterance,
    /// A mute and an unmute between two parts of a command.
    Mute,
    /// A gap in what the recorder hands the call, from the drop hook.
    Gap,
    /// The provider's answer turns discontinuous transmission on.
    Dtx,
    /// A message on the data channel that is not an event.
    Malformed,
    /// A fragment that belongs to a request arrives after the request was read.
    LateFragment,
    /// The voice service announces a delegation at another offset than the provider's.
    BrokerDisagrees,
}

/// The peer and the stand-in as the application reaches them: over loopback HTTP, with the tokens
/// the script made for the run.
pub struct PeerDriver {
    peer: String,
    peer_token: String,
    service: String,
    service_token: String,
}

impl PeerDriver {
    /// The driver for a run whose peer file is in `data`'s `kr-probe` directory and whose stand-in
    /// is `harness`'s.
    ///
    /// # Errors
    ///
    /// Returns why the peer's file cannot be read or the stand-in's origin is not one this reaches.
    pub fn from_files(data: &Path, harness: &Harness) -> Result<Self, String> {
        let text = std::fs::read_to_string(data.join("kr-probe/peer.json"))
            .map_err(|error| format!("no peer file: {error}"))?;
        let file: Value = serde_json::from_str(&text).map_err(|error| error.to_string())?;
        let port = file["port"]
            .as_u64()
            .ok_or_else(|| "the peer file names no port".to_owned())?;
        let peer_token = file["token"]
            .as_str()
            .ok_or_else(|| "the peer file names no token".to_owned())?
            .to_owned();
        let service = harness
            .origin
            .strip_prefix("http://")
            .ok_or_else(|| "the stand-in's origin is not plain loopback HTTP".to_owned())?
            .trim_end_matches('/')
            .to_owned();
        Ok(Self {
            peer: format!("127.0.0.1:{port}"),
            peer_token,
            service,
            service_token: harness.token.clone(),
        })
    }
}

impl PeerDriver {
    /// What the peer says of itself.
    async fn figures(&self) -> Result<Value, String> {
        let text = ask(
            self.peer.clone(),
            "GET",
            "/figures".to_owned(),
            ("x-peer-token", self.peer_token.clone()),
            Vec::new(),
        )
        .await?;
        serde_json::from_str(&text).map_err(|error| error.to_string())
    }
}

/// One HTTP exchange with a loopback server: the status and the text. Blocking, so it runs on a
/// thread that may block.
fn exchange(
    address: &str,
    method: &str,
    path: &str,
    header: (&str, &str),
    body: &[u8],
) -> Result<(u16, String), String> {
    let target = address
        .to_socket_addrs()
        .map_err(|error| error.to_string())?
        .next()
        .ok_or_else(|| "no address".to_owned())?;
    let mut stream = TcpStream::connect_timeout(&target, EXCHANGE_WITHIN)
        .map_err(|error| format!("no connection to {address}: {error}"))?;
    stream
        .set_read_timeout(Some(EXCHANGE_WITHIN))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(EXCHANGE_WITHIN))
        .map_err(|error| error.to_string())?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nhost: {address}\r\n{}: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        header.0,
        header.1,
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(body))
        .map_err(|error| format!("the request was not sent: {error}"))?;
    let mut bytes = Vec::new();
    stream
        .read_to_end(&mut bytes)
        .map_err(|error| format!("the answer was not read: {error}"))?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "the server answered with no head".to_owned())?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| "the server answered with no status".to_owned())?;
    Ok((status, body.to_owned()))
}

/// An exchange on a thread that may block, with a status that is not a success made an error.
async fn ask(
    address: String,
    method: &'static str,
    path: String,
    header: (&'static str, String),
    body: Vec<u8>,
) -> Result<String, String> {
    let (status, text) = tokio::task::spawn_blocking(move || {
        exchange(&address, method, &path, (header.0, &header.1), &body)
    })
    .await
    .map_err(|error| error.to_string())??;
    if (200..300).contains(&status) {
        Ok(text)
    } else {
        Err(format!("status {status}: {text}"))
    }
}

impl Driver for PeerDriver {
    fn provider<'a>(&'a self, bytes: &'a [u8]) -> DriverFuture<'a, ()> {
        Box::pin(async move {
            ask(
                self.peer.clone(),
                "POST",
                "/events".to_owned(),
                ("x-peer-token", self.peer_token.clone()),
                bytes.to_vec(),
            )
            .await
            .map(|_| ())
        })
    }

    fn announce<'a>(&'a self, id: &'a str, offset_ms: u64) -> DriverFuture<'a, ()> {
        Box::pin(async move {
            ask(
                self.service.clone(),
                "POST",
                "/harness/announce".to_owned(),
                ("authorization", format!("Bearer {}", self.service_token)),
                json!({ "id": id, "offsetMs": offset_ms })
                    .to_string()
                    .into_bytes(),
            )
            .await
            .map(|_| ())
        })
    }

    fn drop_recorder(&self, milliseconds: u64) -> DriverFuture<'_, ()> {
        Box::pin(async move {
            ask(
                self.peer.clone(),
                "POST",
                format!("/drop?ms={milliseconds}"),
                ("x-peer-token", self.peer_token.clone()),
                Vec::new(),
            )
            .await
            .map(|_| ())
        })
    }

    fn drops_made(&self) -> DriverFuture<'_, u64> {
        Box::pin(async move {
            self.figures().await?["dropsDone"]
                .as_u64()
                .ok_or_else(|| "the peer reports no drops".to_owned())
        })
    }

    fn events_open(&self) -> DriverFuture<'_, bool> {
        Box::pin(async move {
            self.figures().await?["eventsOpen"]
                .as_bool()
                .ok_or_else(|| "the peer reports nothing of the events channel".to_owned())
        })
    }

    fn after_a_mute(&self, _muted: bool) -> DriverFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
}

/// The provider's fragment of what the caller said.
fn fragment(start_ms: u64, end_ms: u64, text: &str) -> Value {
    json!({
        "type": "session.input_transcript.delta",
        "event_id": format!("event_{start_ms}"),
        "start_ms": start_ms,
        "end_ms": end_ms,
        "delta": text,
    })
}

/// The provider's delegation event.
fn delegation_event(id: &str, offset_ms: u64) -> Value {
    json!({
        "type": "session.delegation.created",
        "event_id": format!("event_{id}"),
        "offset_ms": offset_ms,
        "delegation": { "id": id, "type": "delegation", "target": "client" },
    })
}

/// The row of the delegation `id` in a call's state.
fn row_of(state: &Value, id: &str) -> Option<Value> {
    state["delegations"]
        .as_array()?
        .iter()
        .find(|row| row["delegation_id"] == id)
        .cloned()
}

/// The rows of a call's state on one line, for a check's detail.
fn rows_in(state: &Value) -> String {
    state["delegations"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    format!(
                        "{} {} {} told {}",
                        row["delegation_id"].as_str().unwrap_or("?"),
                        row["state"].as_str().unwrap_or("?"),
                        row["cause"].as_str().unwrap_or("-"),
                        row["told"]
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        })
        .unwrap_or_default()
}

/// Whether the call's problems name `kind`.
fn has_problem(state: &Value, kind: &str) -> bool {
    state["problems"]
        .as_array()
        .is_some_and(|problems| problems.iter().any(|problem| problem["kind"] == kind))
}

/// What a leg is played with.
struct Play<'a, R: Runtime> {
    app: &'a AppHandle<R>,
    platform: &'a dyn CallPlatform,
    driver: &'a dyn Driver,
}

impl<R: Runtime> Play<'_, R> {
    /// The provider's transcript of `words` from `start_ms`, one fragment of 200 ms for each word
    /// with no silence between them. Returns where the last word ends.
    async fn speak(&self, start_ms: u64, words: &str) -> Result<u64, String> {
        let mut at = start_ms;
        for word in words.split_whitespace() {
            self.driver
                .provider(
                    fragment(at, at + 200, &format!(" {word}"))
                        .to_string()
                        .as_bytes(),
                )
                .await
                .map_err(|error| format!("a fragment was not written to the channel: {error}"))?;
            at += 200;
        }
        Ok(at)
    }

    /// The provider's transcript of `words` said from `start_ms`, and the delegation the model
    /// creates when the last of them was said, at `back_ms` before where it ends. The voice service
    /// announces the delegation first, at `announced_at(offset)`, before any word: the service's frame
    /// and the provider's events come on paths that nothing orders, and the model is told what became
    /// of a delegation the control has not yet heard announced by a request the control turns away.
    /// Returns where the last word ends.
    async fn utter(
        &self,
        id: &str,
        start_ms: u64,
        words: &str,
        back_ms: u64,
        announced_at: impl FnOnce(u64) -> u64,
    ) -> Result<u64, String> {
        let count = u64::try_from(words.split_whitespace().count()).unwrap_or(0);
        let offset = start_ms + 200 * count - back_ms;
        self.driver
            .announce(id, announced_at(offset))
            .await
            .map_err(|error| format!("the voice service announced nothing: {error}"))?;
        self.said(id, start_ms, words, back_ms).await
    }

    /// The same as [`Self::utter`] for a delegation the voice service has already announced.
    ///
    /// A delegation that the call refuses at once, because the call is tainted, is told to the model
    /// as soon as its event is read, and the control turns the request away for good when it has not
    /// yet heard the announcement. The service's frames and the control's answers to the phone's
    /// requests travel one socket in order, so a delegation announced before a request the phone then
    /// sends has been answered is heard by the time that answer is read. A leg that refuses a
    /// delegation at once announces it ahead of the row whose telling it waits for, then says it here.
    async fn said(
        &self,
        id: &str,
        start_ms: u64,
        words: &str,
        back_ms: u64,
    ) -> Result<u64, String> {
        let count = u64::try_from(words.split_whitespace().count()).unwrap_or(0);
        let end = start_ms + 200 * count;
        self.speak(start_ms, words).await?;
        self.driver
            .provider(delegation_event(id, end - back_ms).to_string().as_bytes())
            .await
            .map_err(|error| format!("the delegation was not written to the channel: {error}"))?;
        Ok(end)
    }

    /// Waits until the model was told what became of the delegation `id`, and returns the state with
    /// the row, whatever the row came to: the caller reads it against what the leg expects, so a leg
    /// whose delegation came to something else stops at once and says what. Where the model is never
    /// told, what the row last read.
    async fn row_told(&self, id: &str) -> Result<(Value, Value), String> {
        let app = self.app;
        let last = std::sync::Mutex::new("no row".to_owned());
        let seen = &last;
        let found = until(ROW_WITHIN, || async move {
            let state = call_state(app).await;
            let row = row_of(&state, id)?;
            *seen
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = row.to_string();
            (row["told"] == true).then_some((state, row))
        })
        .await;
        found.ok_or_else(|| {
            last.into_inner()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        })
    }

    /// Waits until native code holds the person's mute and capture no longer shows as capturing. What
    /// capture reads then is the display's own word (muted by the person, or unavailable where the
    /// recorder stopped with the mute); the mute is read as a fact of its own. Returns the word.
    async fn mute_is_held(&self) -> Option<String> {
        let (app, platform) = (self.app, self.platform);
        until(SIGN_WITHIN, || async move {
            let held = platform.held().await.ok()?;
            let word = call_state(app).await["capture"]
                .as_str()
                .unwrap_or("?")
                .to_owned();
            (held.microphone_muted && word != "capturing").then_some(word)
        })
        .await
    }

    /// Waits until the microphone's capture word is `word`.
    async fn capture_is(&self, word: &str) -> bool {
        let app = self.app;
        until(SIGN_WITHIN, || async move {
            (call_state(app).await["capture"] == word).then_some(())
        })
        .await
        .is_some()
    }
}

/// Before a leg says anything, the call carries audio and native code's own record of capture shows
/// no break. Both are readings of the call's own signs, never a wait for a time: a leg's subject is a
/// break the leg makes, and a recorder that broke while the application was starting is not one. A
/// call that fails either is not the leg's to judge, and says so for the device script to play the
/// leg again on a new call.
async fn settled<R: Runtime>(play: &Play<'_, R>, checks: &mut Checks<'_>) -> bool {
    let platform = play.platform;
    let carries = until(SIGN_WITHIN, || async move {
        let media = platform.held().await.ok()?.media;
        // Where native code reads no media there is nothing to wait for.
        media
            .is_none_or(|media| media.packets_received.is_none_or(|n| n >= AUDIO_FLOOR))
            .then_some(())
    })
    .await
    .is_some();
    checks.push(Check::found(
        "the call carries audio before the leg begins",
        carries,
        format!("the call received at least {AUDIO_FLOOR} audio packets"),
    ));
    if !carries {
        return false;
    }
    let read = async {
        let held = platform
            .held()
            .await
            .map_err(|failure| failure.message.clone())?;
        let call = held
            .call
            .ok_or_else(|| "native code holds no call".to_owned())?;
        platform
            .capture_proof(&call, false)
            .await
            .map_err(|failure| failure.message.clone())
    }
    .await;
    let (ok, detail) = match read {
        Ok(proof) => {
            let ok = proof.openings == 1 && proof.breaks == 0;
            let mut detail = format!(
                "openings {} breaks {} state {:?}",
                proof.openings, proof.breaks, proof.state
            );
            if proof.breaks != 0 {
                detail.push_str(&format!("; {BROKE_BY_ITSELF}"));
            }
            (ok, detail)
        }
        Err(why) => (false, why),
    };
    checks.push(Check::found(
        "the recorder delivered without a break before the leg began",
        ok,
        detail,
    ));
    ok
}

/// Reads a row against what a leg expects and records the check.
fn expect_row(
    checks: &mut Checks<'_>,
    name: &'static str,
    read: Result<(Value, Value), String>,
    state: &str,
    cause: Option<&str>,
) -> bool {
    let (ok, detail) = match &read {
        Ok((_, row)) => {
            let ok = row["state"] == state && cause.is_none_or(|cause| row["cause"] == cause);
            let mut detail = format!(
                "state {} cause {} told {}",
                row["state"].as_str().unwrap_or("?"),
                row["cause"].as_str().unwrap_or("-"),
                row["told"]
            );
            // A refusal for a break, where the leg expected anything else, is a break the leg did not
            // make: the leg's subject was never reached.
            if !ok && row["cause"] == "capture_break" && cause != Some("capture_break") {
                detail.push_str(&format!("; {BROKE_BY_ITSELF}"));
            }
            (ok, detail)
        }
        Err(last) => (
            false,
            format!(
                "the model was never told what became of the delegation, which last read {last}{}",
                cause.map_or_else(String::new, |c| format!(" (expected {state} for {c})"))
            ),
        ),
    };
    checks.push(Check::found(name, ok, detail));
    ok
}

/// Plays one leg, once the call runs with its control attached. A step the leg cannot make ends it,
/// and says so as a failed check.
pub(super) async fn run<R: Runtime>(
    app: &AppHandle<R>,
    platform: &dyn CallPlatform,
    driver: &dyn Driver,
    leg: Leg,
    checks: &mut Checks<'_>,
) {
    let play = Play {
        app,
        platform,
        driver,
    };
    // The microphone is carrying speech before anything is said: what the provider is sent before
    // the gate opens is a call the gate refuses for good, and a leg that began so would be about
    // that, not about its own subject.
    let on = play.capture_is("capturing").await;
    let word = call_state(app).await["capture"].clone();
    checks.push(Check::found(
        "native code's capture is on",
        on,
        format!("capture {word}"),
    ));
    if !on {
        return;
    }
    // And the provider's channel is open, so that what the leg writes to it is carried.
    let open = until(SIGN_WITHIN, || async move {
        driver.events_open().await.ok().filter(|open| *open)
    })
    .await
    .is_some();
    checks.push(Check::found(
        "the provider's events channel is open",
        open,
        "the peer reports the call's oai-events channel",
    ));
    if !open {
        return;
    }
    if !settled(&play, checks).await {
        return;
    }
    let stage = match leg {
        Leg::Production => production(&play, checks).await,
        Leg::Positive => positive(&play, checks).await,
        Leg::FirstUtterance => first_utterance(&play, checks).await,
        Leg::Mute => mute(&play, checks).await,
        Leg::Gap => gap(&play, checks).await,
        Leg::Dtx => dtx(&play, checks).await,
        Leg::Malformed => malformed(&play, checks).await,
        Leg::LateFragment => late_fragment(&play, checks).await,
        Leg::BrokerDisagrees => broker_disagrees(&play, checks).await,
    };
    if let Err(reason) = stage {
        checks.push(Check::found("the leg could be played", false, reason));
    }
    let state = call_state(app).await;
    let problems = state["problems"]
        .as_array()
        .map_or_else(String::new, |all| {
            all.iter()
                .map(|problem| problem["kind"].as_str().unwrap_or("?"))
                .collect::<Vec<_>>()
                .join(",")
        });
    checks.push(Check::found(
        "what the call showed of each delegation",
        true,
        format!(
            "{}; control {} capture {} problems [{problems}]",
            rows_in(&state),
            state["control"],
            state["capture"]
        ),
    ));
    if let Ok(held) = platform.held().await {
        checks.push(Check::found(
            "native code held the call to the leg's end",
            held.call.is_some(),
            format!("capture {:?}", held.capture),
        ));
    }
}

/// The first sentence of a call, which the first-utterance rule spends: the model delegates it and
/// it is refused. What is said after it is not the first of the call.
async fn throwaway<R: Runtime>(
    play: &Play<'_, R>,
    checks: &mut Checks<'_>,
) -> Result<bool, String> {
    play.utter("d-0", 0, "hello there", 200, |offset| offset)
        .await?;
    let read = play.row_told("d-0").await;
    Ok(expect_row(
        checks,
        "the first utterance is refused",
        read,
        "refused",
        Some("first_fragment"),
    ))
}

/// A status said from `start_ms`, asked for as the model does when the last word is said.
async fn status<R: Runtime>(play: &Play<'_, R>, id: &str, start_ms: u64) -> Result<u64, String> {
    play.utter(id, start_ms, "what is the status", 200, |offset| offset)
        .await
}

/// Where the model's delegation for a status said from `start_ms` is, which the voice service
/// announces when a leg announces it ahead of the status.
const fn status_offset(start_ms: u64) -> u64 {
    start_ms + 4 * 200 - 200
}

/// A status whose delegation was announced earlier.
async fn status_announced<R: Runtime>(
    play: &Play<'_, R>,
    id: &str,
    start_ms: u64,
) -> Result<u64, String> {
    play.said(id, start_ms, "what is the status", 200).await
}

/// The shipped configuration: the probe does not turn the acceptance on, so a delegation the voice
/// service announces is answered that nothing was done, the data channel's events change nothing,
/// and the host is sent nothing.
async fn production<R: Runtime>(play: &Play<'_, R>, checks: &mut Checks<'_>) -> Result<(), String> {
    play.driver.announce("d-9", 1_200).await?;
    play.speak(0, "hello there").await?;
    let end = play.speak(6_000, "what is the status").await?;
    play.driver
        .provider(delegation_event("d-1", end - 200).to_string().as_bytes())
        .await?;
    play.driver
        .provider(
            json!({ "type": "session.input_audio.muted", "event_id": "event_m" })
                .to_string()
                .as_bytes(),
        )
        .await?;
    let read = play.row_told("d-9").await;
    let ok = expect_row(
        checks,
        "a delegation the service announces is answered that nothing was done",
        read.clone(),
        "not_done",
        None,
    );
    let rows = read.as_ref().map_or(0, |(state, _)| {
        state["delegations"].as_array().map_or(0, Vec::len)
    });
    checks.push(Check::found(
        "what the data channel says changes nothing the call shows",
        ok && rows == 1 && read.is_ok_and(|(_, row)| row["cause"].is_null()),
        format!("{rows} row"),
    ));
    Ok(())
}

/// No break and not the first utterance: a status said after the throwaway is handed to the host.
async fn positive<R: Runtime>(play: &Play<'_, R>, checks: &mut Checks<'_>) -> Result<(), String> {
    if !throwaway(play, checks).await? {
        return Ok(());
    }
    status(play, "d-1", 6_000).await?;
    let read = play.row_told("d-1").await;
    expect_row(
        checks,
        "a status said after it is performed",
        read,
        "performed",
        None,
    );
    Ok(())
}

/// The command is the first thing said: refused. The same command said after it is not.
async fn first_utterance<R: Runtime>(
    play: &Play<'_, R>,
    checks: &mut Checks<'_>,
) -> Result<(), String> {
    status(play, "d-1", 0).await?;
    let read = play.row_told("d-1").await;
    if !expect_row(
        checks,
        "the first utterance is refused",
        read,
        "refused",
        Some("first_fragment"),
    ) {
        return Ok(());
    }
    status(play, "d-2", 12_000).await?;
    let read = play.row_told("d-2").await;
    expect_row(
        checks,
        "the same command said after it is performed",
        read,
        "performed",
        None,
    );
    Ok(())
}

/// What the leg's control shows: a status said after the throwaway is performed.
async fn control<R: Runtime>(play: &Play<'_, R>, checks: &mut Checks<'_>) -> Result<bool, String> {
    if !throwaway(play, checks).await? {
        return Ok(false);
    }
    status(play, "d-1", 6_000).await?;
    let read = play.row_told("d-1").await;
    Ok(expect_row(
        checks,
        "a status said before the break is performed",
        read,
        "performed",
        None,
    ))
}

/// A mute and an unmute between two parts of a command refuse it, and every later one: the call is
/// tainted for good.
async fn mute<R: Runtime>(play: &Play<'_, R>, checks: &mut Checks<'_>) -> Result<(), String> {
    // The last command is refused at once, so it is announced ahead of the rows told before it.
    play.driver.announce("d-3", status_offset(18_000)).await?;
    if !control(play, checks).await? {
        return Ok(());
    }
    // One command in two parts, announced before either: "what is", the mute, "the status".
    play.driver.announce("d-2", 12_000 + 200 * 4 - 200).await?;
    play.speak(12_000, "what is").await?;
    let muted =
        commands::voice_set_muted(play.app.state(), commands::VoiceMute::Microphone, true).await;
    play.driver.after_a_mute(true).await?;
    let shown = play.mute_is_held().await;
    checks.push(Check::found(
        "the person mutes between two parts of a command",
        muted.is_ok() && shown.is_some(),
        format!("mute ok {} held {shown:?}", muted.is_ok()),
    ));
    let unmuted =
        commands::voice_set_muted(play.app.state(), commands::VoiceMute::Microphone, false).await;
    play.driver.after_a_mute(false).await?;
    let back = play.capture_is("capturing").await;
    checks.push(Check::found(
        "the microphone is back to capturing after the unmute",
        unmuted.is_ok() && back,
        format!("unmute ok {} capturing {back}", unmuted.is_ok()),
    ));
    let end = play.speak(12_400, "the status").await?;
    play.driver
        .provider(delegation_event("d-2", end - 200).to_string().as_bytes())
        .await?;
    let read = play.row_told("d-2").await;
    if !expect_row(
        checks,
        "a mute between two parts of a command refuses it",
        read,
        "refused",
        Some("capture_break"),
    ) {
        return Ok(());
    }
    status_announced(play, "d-3", 18_000).await?;
    let read = play.row_told("d-3").await;
    expect_row(
        checks,
        "the call stays refused after the microphone is back",
        read,
        "refused",
        Some("capture_break"),
    );
    Ok(())
}

/// A gap in what the recorder hands the call, above the capture gates' thresholds, refuses the
/// next command. The recorder tells no news of it: native code's record is what shows it.
async fn gap<R: Runtime>(play: &Play<'_, R>, checks: &mut Checks<'_>) -> Result<(), String> {
    if !control(play, checks).await? {
        return Ok(());
    }
    play.driver.drop_recorder(DROP_MS).await?;
    let driver = play.driver;
    let ran = until(SIGN_WITHIN, || async move {
        driver.drops_made().await.ok().filter(|made| *made >= 1)
    })
    .await;
    checks.push(Check::found(
        "the drop hook took audio out of the recorder",
        ran.is_some(),
        format!("drops {ran:?}, {DROP_MS} ms each"),
    ));
    if ran.is_none() {
        return Ok(());
    }
    status(play, "d-2", 12_000).await?;
    let read = play.row_told("d-2").await;
    expect_row(
        checks,
        "a gap in the recorder refuses the command",
        read,
        "refused",
        Some("capture_break"),
    );
    Ok(())
}

/// An answer that turns discontinuous transmission on refuses every delegation of the call.
async fn dtx<R: Runtime>(play: &Play<'_, R>, checks: &mut Checks<'_>) -> Result<(), String> {
    status(play, "d-1", 6_000).await?;
    let read = play.row_told("d-1").await;
    expect_row(
        checks,
        "a command in a call whose answer turns DTX on is refused",
        read,
        "refused",
        Some("dtx"),
    );
    Ok(())
}

/// A message on the data channel that is not an event taints the call.
async fn malformed<R: Runtime>(play: &Play<'_, R>, checks: &mut Checks<'_>) -> Result<(), String> {
    // The command after the message is refused at once, so it is announced ahead of the rows told
    // before it.
    play.driver.announce("d-2", status_offset(12_000)).await?;
    if !control(play, checks).await? {
        return Ok(());
    }
    play.driver.provider(b"not json at all").await?;
    status_announced(play, "d-2", 12_000).await?;
    let read = play.row_told("d-2").await;
    expect_row(
        checks,
        "a message that is not an event refuses the next command",
        read,
        "refused",
        Some("unreadable_event"),
    );
    Ok(())
}

/// A fragment that belongs to a request and arrives after the request was read taints the call and
/// is told. What the host did about the request stands.
async fn late_fragment<R: Runtime>(
    play: &Play<'_, R>,
    checks: &mut Checks<'_>,
) -> Result<(), String> {
    if !throwaway(play, checks).await? {
        return Ok(());
    }
    // The command after the late fragment is refused at once, so it is announced ahead of the row
    // told before it.
    play.driver.announce("d-2", status_offset(12_000)).await?;
    let end = play
        .utter("d-1", 6_000, "what is the status", 0, |offset| offset)
        .await?;
    let read = play.row_told("d-1").await;
    if !expect_row(
        checks,
        "a status said before the late fragment is performed",
        read,
        "performed",
        None,
    ) {
        return Ok(());
    }
    play.driver
        .provider(fragment(end, end + 200, " not").to_string().as_bytes())
        .await?;
    let app = play.app;
    let told = until(ROW_WITHIN, || async move {
        let state = call_state(app).await;
        has_problem(&state, "spoken_requests").then_some(state)
    })
    .await;
    let kept = told
        .as_ref()
        .and_then(|state| row_of(state, "d-1"))
        .is_some_and(|row| row["state"] == "performed");
    checks.push(Check::found(
        "a fragment after the read taints the call and the earlier outcome stands",
        told.is_some() && kept,
        told.as_ref()
            .map_or_else(|| "the call was not told".to_owned(), rows_in),
    ));
    status_announced(play, "d-2", 12_000).await?;
    let read = play.row_told("d-2").await;
    expect_row(
        checks,
        "the next command is refused",
        read,
        "refused",
        Some("late_fragment"),
    );
    Ok(())
}

/// A delegation the voice service does not announce at the provider's offset is refused, and the
/// call is not tainted by it: the next command is performed.
async fn broker_disagrees<R: Runtime>(
    play: &Play<'_, R>,
    checks: &mut Checks<'_>,
) -> Result<(), String> {
    if !control(play, checks).await? {
        return Ok(());
    }
    // The service announces it a second later in the call's time than the provider says it was.
    play.utter("d-2", 12_000, "what is the status", 200, |offset| {
        offset + 1_200
    })
    .await?;
    let read = play.row_told("d-2").await;
    if !expect_row(
        checks,
        "a delegation the voice service does not announce as the provider did is refused",
        read,
        "refused",
        Some("broker_disagrees"),
    ) {
        return Ok(());
    }
    status(play, "d-3", 18_000).await?;
    let read = play.row_told("d-3").await;
    expect_row(
        checks,
        "the refusal leaves the call as it was",
        read,
        "performed",
        None,
    );
    Ok(())
}

/// The real session the host holds for the run, from the request: the one the call is allowed to
/// reach, so that a status can be read.
///
/// # Errors
///
/// Returns why the request names none.
pub fn session_of(harness: &Harness) -> Result<String, &'static str> {
    harness.session_ids.first().cloned().ok_or(NO_SESSION)
}
