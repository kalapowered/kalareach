//! The host and the voice service a phone's call runs against on a simulator or an emulator.
//!
//! This is not a test of the product by itself: it is the machine side of a device run, and a
//! script starts it (`scripts/e2e-voice-call-device.sh`), so it is ignored in an ordinary run.
//! It starts the real daemon, on the loopback interface, and a stand-in for the managed voice
//! service on one loopback port that answers a call's offer with an answer built from the offer's
//! sections. It then issues a direct invitation that a phone pairs with, approves the phone as the
//! host's owner, and stays up while the phone starts a call, until the script says the phone is
//! done. It writes what the voice service and the daemon saw, for the script to judge beside what
//! the phone reported.
//!
//! The script and this suite talk through files in `KR_HARNESS_DIR`, on the internal disk:
//!
//! | File | Written by | Holds |
//! | --- | --- | --- |
//! | `ready.json` | this suite | the voice service's origin and port and the token its control accepts |
//! | `go` | the script | nothing; the phone is installed and the invitation may be issued |
//! | `invitation.txt` | this suite | the direct invitation, with the host reachable at `KR_HARNESS_PEER` |
//! | `figures.txt` | the script | the phone's result lines, for the figure of the first audio |
//! | `down` | the script | nothing; the voice service goes down and stays down |
//! | `finish` | the script | nothing; the phone is done |
//! | `report.json` | this suite | what the voice service saw, and what the phone's peer reported |
//!
//! `KR_HARNESS_PEER` is the name the phone reaches this machine by: `127.0.0.1` for a simulator,
//! which shares the machine's network, and `10.0.2.2` for an emulator. `KR_HARNESS_SECONDS`
//! bounds the whole run. It is for the machines a simulator or an emulator runs on, which are Unix.
//!
//! A run of spoken requests (`KR_HARNESS_SESSIONS`, how many real sessions the host holds, which
//! `ready.json` names) has the host adopt that many sessions, so that a status can be read, and
//! `KR_HARNESS_LEG` names the leg: `dtx` has the peer answer the call's offer with an answer that
//! turns discontinuous transmission on. The report then also holds what the voice service's control
//! was told to carry to the model, and what the host's session workers were sent, in order.
//!
//! A run that names the phone's audio peer (`KR_HARNESS_AUDIO_PORT`, the loopback port on this
//! machine that reaches it, and `KR_HARNESS_AUDIO_TOKEN`) has the voice service ask the peer for
//! each call's answer, so that the call connects and carries audio, and has this suite read what
//! the peer received once a second. Without one the answer leads nowhere and the call fails. The
//! phone's figure of the first audio played out is written, beside the machine it was taken with,
//! as one section of the run's evidence; it asserts no value.
//! No test here makes a live provider call.

#![cfg(unix)]

mod net_support;
mod voice_support;

#[path = "../../../apps/companion/src-tauri/src/probe/answer.rs"]
mod answer;
#[path = "../../../tests/perf/src/record.rs"]
mod record;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_crypto::keys::DeviceKeys;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::pairing::{NetworkHint, QrPayload};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use net_support::pairing::{self as calls, Signer};
use net_support::{Host, proposal};
use voice_support::StandIn;

/// The token the phone's account holds, which the stand-in's control accepts.
const TOKEN: &str = "harness-account-token";

/// How long the phone is given to ask for its invitation after the script says it is installed.
const INVITATION_WAIT: Duration = Duration::from_secs(60);

/// The phone's audio peer on this machine's loopback interface: the port that reaches it and the
/// token it accepts.
#[derive(Clone)]
struct AudioPeer {
    port: u16,
    token: String,
}

impl AudioPeer {
    /// The peer a run names, if it names one.
    fn named() -> Option<Self> {
        let port = std::env::var("KR_HARNESS_AUDIO_PORT").ok()?.parse().ok()?;
        let token = std::env::var("KR_HARNESS_AUDIO_TOKEN").ok()?;
        Some(Self { port, token })
    }

    /// One request to the peer: its status and its text.
    async fn ask(
        &self,
        method: &str,
        path: &str,
        body: &str,
        within: Duration,
    ) -> Result<(u16, String), String> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let exchange = async {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", self.port))
                .await
                .map_err(|error| format!("no connection to the peer: {error}"))?;
            let request = format!(
                "{method} {path} HTTP/1.1\r\nhost: 127.0.0.1\r\nx-peer-token: {}\r\n\
                 content-length: {}\r\nconnection: close\r\n\r\n{body}",
                self.token,
                body.len()
            );
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|error| format!("the request was not sent: {error}"))?;
            let mut bytes = Vec::new();
            stream
                .read_to_end(&mut bytes)
                .await
                .map_err(|error| format!("the answer was not read: {error}"))?;
            let text = String::from_utf8_lossy(&bytes).into_owned();
            let (head, body) = text
                .split_once("\r\n\r\n")
                .ok_or_else(|| "the peer answered with no head".to_owned())?;
            let status = head
                .split_whitespace()
                .nth(1)
                .and_then(|status| status.parse().ok())
                .ok_or_else(|| "the peer answered with no status".to_owned())?;
            Ok((status, body.to_owned()))
        };
        tokio::time::timeout(within, exchange)
            .await
            .map_err(|_| "the peer did not answer in time".to_owned())?
    }
}

/// What the phone's peer was asked and what it said, for the report.
#[derive(Default)]
struct PeerLog {
    /// How many offers were relayed to it, and how many it answered.
    relayed: usize,
    answered: usize,
    /// Why an answer was not got.
    errors: Vec<String>,
    /// When each offer was relayed and each answer came back, in seconds since the run began.
    times: Vec<(String, u64)>,
}

/// The document an operator writes to name the voice service.
fn document_naming(origin: &str) -> ConfigurationDocument {
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.voice.broker_origin = Nullable::some(origin.to_owned());
    document
}

/// Waits until `file` exists, or `within` passes.
async fn appears(file: &Path, within: Duration) -> bool {
    let end = Instant::now() + within;
    while !file.exists() {
        if Instant::now() >= end {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    true
}

/// Writes `text` to `file` where only this user can read it.
fn write_private(file: &Path, text: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut open = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(file)
        .expect("a file in the harness directory");
    open.write_all(text.as_bytes())
        .expect("the file is written");
}

/// The invitation's text with the host reachable at `peer`: the port the host bound, on the name
/// the phone reaches this machine by. The hint is only where to dial; the host's endpoint identity
/// is what authenticates it.
fn invitation_for(invited: &kr_protocol::invitation::PairInviteResult, peer: &str) -> String {
    let mut payload = calls::direct_payload(invited);
    let port = payload
        .network_config
        .direct_addresses
        .first()
        .and_then(|hint| hint.as_str().rsplit_once(':'))
        .map(|(_, port)| port.to_owned())
        .expect("the host names an address to dial");
    payload.network_config.direct_addresses =
        vec![NetworkHint::new(format!("{peer}:{port}")).expect("an address that is a hint")];
    QrPayload::Direct(Box::new(payload))
        .to_text()
        .expect("a payload that is text")
        .to_string()
}

/// The file the figure of the first audio is kept in, under the run's evidence directory.
const RECORD: &str = "kr-voice-first-audio.md";

/// The heading of the section that holds the figure.
const MEASUREMENT: &str = "KR-PERF-010 first audio played out of a phone (stand-in figure)";

/// The check the phone's result names its figure by.
const FIGURE_CHECK: &str = "check=the first audio played out ok=";

/// The section's lines for the figure a phone's result holds: the conditions of the machine the
/// run was made with, then the figure or the reason there is none, with both boundaries it was
/// taken between and the rule that makes it an estimate. It asserts nothing about the value: the
/// stand-in service answers at once and the peer is a full agent, so the figure says how this
/// application's own path behaves against a stand-in, and not what a person hears from a provider.
fn figure_section(
    platform: &str,
    phone_result: &str,
    conditions: &record::Conditions,
) -> Vec<String> {
    let line = phone_result
        .lines()
        .find(|line| line.starts_with(FIGURE_CHECK));
    let figure = line.and_then(|line| {
        line.split_once("figure first_audio_ms=")
            .and_then(|(_, rest)| rest.split(';').next())
            .and_then(|ms| ms.trim().parse::<u64>().ok())
    });
    let mut lines = conditions.lines();
    lines.push(format!(
        "  phone             {platform}, a debug build against the stand-in voice service"
    ));
    lines.push(match (figure, line) {
        (Some(ms), _) => format!("  first audio       {ms} ms, an estimate"),
        (None, Some(line)) => format!(
            "  first audio       not measured: {}",
            line.split_once(" detail=")
                .map_or("no reason given", |(_, why)| why)
        ),
        (None, None) => {
            "  first audio       not measured: the phone's result holds no figure".to_owned()
        }
    });
    lines.push(
        "  from              the entry of the call's start in this application, not the person's press"
            .to_owned(),
    );
    lines.push(
        "  to                this application's receipt of the news that native code observed audio \
         played out, not the observation itself"
            .to_owned(),
    );
    lines.push(match platform {
        "android" => "  rule              the first buffer handed to the speaker side with a sample above a \
                      floor, while playback is on, unmuted and uninterrupted"
            .to_owned(),
        _ => "  rule              the first reading of the connection's statistics in which the audio \
              energy and the playout sample count both grew while playback was on, and the reading did \
              not span a change of that state"
            .to_owned(),
    });
    lines.push(
        "  verdict           recorded, not asserted: the target is a person's release build against the \
         managed service, which no stand-in run measures"
            .to_owned(),
    );
    lines.push(
        "  delegation        latency unavailable: no delegation reaches a host action in this \
         version, and the fixed commentary calls no host"
            .to_owned(),
    );
    lines
}

/// What the peer has received now, with the seconds since the run began; an error is kept as one.
async fn read_figures(peer: &AudioPeer, since: Instant) -> serde_json::Value {
    let seconds = since.elapsed().as_secs();
    match peer
        .ask("GET", "/figures", "", Duration::from_secs(5))
        .await
    {
        Ok((200, text)) => match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(figures) => serde_json::json!({ "seconds": seconds, "figures": figures }),
            Err(error) => serde_json::json!({ "seconds": seconds, "error": error.to_string() }),
        },
        Ok((status, _)) => {
            serde_json::json!({ "seconds": seconds, "error": format!("status {status}") })
        }
        Err(error) => serde_json::json!({ "seconds": seconds, "error": error }),
    }
}

/// Runs the host and the voice service for one phone, from its invitation to its end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "started by scripts/e2e-voice-call-device.sh beside a simulator or an emulator"]
async fn a_phone_is_paired_and_runs_a_call_against_a_real_host() {
    let directory = PathBuf::from(std::env::var("KR_HARNESS_DIR").expect("KR_HARNESS_DIR"));
    let peer = std::env::var("KR_HARNESS_PEER").unwrap_or_else(|_| "127.0.0.1".to_owned());
    let seconds: u64 = std::env::var("KR_HARNESS_SECONDS")
        .ok()
        .and_then(|seconds| seconds.parse().ok())
        .unwrap_or(900);
    let end = Instant::now() + Duration::from_secs(seconds);
    let left = || end.saturating_duration_since(Instant::now());

    let sessions: u64 = std::env::var("KR_HARNESS_SESSIONS")
        .ok()
        .and_then(|sessions| sessions.parse().ok())
        .unwrap_or(0);
    // The answer path the peer is asked for: the leg that has the answer turn discontinuous
    // transmission on asks for it.
    let answer_path = if std::env::var("KR_HARNESS_LEG").as_deref() == Ok("dtx") {
        "/answer?dtx=1"
    } else {
        "/answer"
    };

    let began = Instant::now();
    let window = record::Window::open_without_speed();
    let stand_in = StandIn::start().await;
    let audio = AudioPeer::named();
    let relay = Arc::new(Mutex::new(PeerLog::default()));
    match audio.clone() {
        Some(peer) => {
            let relay = Arc::clone(&relay);
            stand_in.answer_offers_with(move |offer| {
                let (peer, relay) = (peer.clone(), Arc::clone(&relay));
                async move {
                    {
                        let mut log = relay.lock().expect("the relay's log");
                        log.relayed += 1;
                        log.times
                            .push(("offer relayed".to_owned(), began.elapsed().as_secs()));
                    }
                    match peer
                        .ask("POST", answer_path, &offer, Duration::from_secs(45))
                        .await
                    {
                        Ok((200, answer)) => {
                            let mut log = relay.lock().expect("the relay's log");
                            log.answered += 1;
                            log.times
                                .push(("answer back".to_owned(), began.elapsed().as_secs()));
                            answer
                        }
                        Ok((status, text)) => {
                            relay
                                .lock()
                                .expect("the relay's log")
                                .errors
                                .push(format!("the peer answered {status}: {text}"));
                            String::new()
                        }
                        Err(error) => {
                            relay.lock().expect("the relay's log").errors.push(error);
                            String::new()
                        }
                    }
                }
            });
        }
        None => stand_in.answer_offers_with(|offer| async move {
            answer::answer_for(&offer).unwrap_or_default()
        }),
    }
    stand_in.accept_control_token(TOKEN);
    let (host, owner, workers) = if sessions == 0 {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start_with_document(&owner, &document_naming(stand_in.origin())).await;
        (host, owner, Vec::new())
    } else {
        let adopted = net_support::worker::Adopted::start_with_document(
            sessions,
            &document_naming(stand_in.origin()),
        )
        .await;
        (adopted.host, adopted.owner, adopted.workers)
    };
    host.controller()
        .host_account()
        .keep_for_test(stand_in.host_grant())
        .await;

    write_private(
        &directory.join("ready.json"),
        &serde_json::json!({
            "origin": stand_in.origin(),
            "token": TOKEN,
            "session_ids": workers
                .iter()
                .map(|worker| worker.session_id.to_string())
                .collect::<Vec<_>>(),
        })
        .to_string(),
    );
    assert!(
        appears(&directory.join("go"), INVITATION_WAIT.min(left())).await,
        "the script never said the phone was ready"
    );

    // The invitation lives for minutes, so it is issued only now, with the phone installed.
    let mut client = host.client().await;
    let signer = Signer::OwnerDevice(&owner);
    // Paired with the history of a session from its start where the run reads one: what a call is
    // told of a session is decided against the history the pairing reaches, and none reaches nothing.
    let mut proposed = proposal(&[ActionRight::SessionView, ActionRight::AgentPrompt]);
    if sessions > 0 {
        proposed.history.lower_bound_ms = Nullable::some(kr_protocol::scalars::TimestampMs::new(0));
    }
    let invited = calls::invite_direct(
        host.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposed,
        &signer,
    )
    .await
    .expect("a direct invitation");
    write_private(
        &directory.join("invitation.txt"),
        &invitation_for(&invited, &peer),
    );

    // The phone redeems it, and the host's owner approves the device that did.
    let approval = async {
        loop {
            let status = calls::owner_status(&mut client, invited.invitation_id)
                .await
                .expect("the invitation's status");
            if status.owner.0.and_then(|view| view.approval.0).is_some() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    };
    tokio::time::timeout(left(), approval)
        .await
        .expect("the phone redeemed the invitation");
    calls::confirm_candidate(
        host.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the owner approves the phone");

    // The phone runs its call. The script says when the voice service goes down and when the phone
    // is done; while it runs, what the phone's peer has received is read once a second.
    let mut figures = Vec::new();
    let mut went_down = false;
    let started = Instant::now();
    while !directory.join("finish").exists() && !left().is_zero() {
        if !went_down && directory.join("down").exists() {
            stand_in.go_down();
            went_down = true;
        }
        if let Some(peer) = &audio
            && relay.lock().expect("the relay's log").answered > 0
        {
            figures.push(read_figures(peer, started).await);
        }
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
    if let Some(peer) = &audio {
        figures.push(read_figures(peer, started).await);
    }

    // The phone's figure, from the lines the script handed over, kept beside the machine's conditions.
    if let Ok(result) = std::fs::read_to_string(directory.join("figures.txt")) {
        let platform =
            std::env::var("KR_HARNESS_PLATFORM").unwrap_or_else(|_| "unknown".to_owned());
        record::report(
            RECORD,
            MEASUREMENT,
            &figure_section(&platform, &result, &window.close()),
        );
    }

    let control = stand_in.control().report();
    let report = serde_json::json!({
        "creations": stand_in.count("/api/voice/sessions"),
        // The closes the host sent, which it signs with its own account's token: the phone may close
        // a call over HTTP too, with its own, and that is not the host telling the service.
        "host_closes": stand_in
            .seen()
            .iter()
            .filter(|request| {
                request.path == "/api/voice/sessions/call-1/close"
                    && request.authorization.as_deref()
                        == Some(format!("Bearer {}", voice_support::HOST_TOKEN).as_str())
            })
            .count(),
        "control_tokens": control
            .upgrades
            .iter()
            .map(|upgrade| upgrade.authorization.clone())
            .collect::<Vec<_>>(),
        // What the phone asked of the control: its frames, whatever became of them. The route only
        // lets some of them through to the provider, and a close is the service's own.
        "control_commands": control
            .frames
            .iter()
            .filter_map(|frame| serde_json::from_str::<serde_json::Value>(frame).ok())
            .filter_map(|frame| frame["command"].as_str().map(str::to_owned))
            .collect::<Vec<_>>(),
        "token": TOKEN,
        // What the control carried on to the model, whatever it was about: the attach words and the
        // sentence each delegation was answered with, by the delegation's identifier.
        "control_sent": control
            .sent
            .iter()
            .map(|sent| serde_json::json!({
                "id": sent.id,
                "command": sent.command,
                "delegation": sent.delegation,
                "content": sent.content,
            }))
            .collect::<Vec<_>>(),
        // What the host's session workers were sent, in order, by method.
        "worker_received": workers
            .iter()
            .map(|worker| worker
                .service
                .received()
                .iter()
                .map(|(method, _)| method.as_str().to_owned())
                .collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        "went_down": went_down,
        // When each request reached the voice service, for reading a run's delays against the
        // phone's own log.
        "requests": stand_in
            .seen()
            .iter()
            .map(|request| serde_json::json!({ "path": request.path, "at_ms": request.at_ms.to_string() }))
            .collect::<Vec<_>>(),
        "peer": audio.as_ref().map(|_| {
            let log = relay.lock().expect("the relay's log");
            serde_json::json!({
                "relayed": log.relayed,
                "answered": log.answered,
                "errors": log.errors,
                "times": log.times,
                "figures": figures,
            })
        }),
    });
    write_private(&directory.join("report.json"), &report.to_string());
    host.stop().await;
    for worker in workers {
        worker.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conditions() -> record::Conditions {
        record::Conditions::supplied(4, 8192, Some(0.0))
    }

    /// The phone's result becomes one section: the figure with both boundaries it lies between,
    /// labelled an estimate, with the machine's conditions and no verdict on the value.
    #[test]
    fn a_figure_in_the_phones_result_becomes_a_section_with_its_boundaries() {
        let result = "run=r\ncheck=the first audio played out ok=1 detail=figure first_audio_ms=843; \
                      from the entry of the start to the receipt of the news\ndone=1\n";
        let lines = figure_section("android", result, &conditions());
        let text = lines.join("\n");

        assert!(MEASUREMENT.starts_with("KR-PERF-010 "), "{MEASUREMENT}");
        assert!(MEASUREMENT.ends_with("(stand-in figure)"), "{MEASUREMENT}");
        for key in [
            "build",
            "host",
            "processors",
            "memory",
            "load average",
            "stolen share",
        ] {
            assert!(
                lines.iter().any(|line| line.trim_start().starts_with(key)),
                "the condition {key} is kept: {text}"
            );
        }
        assert!(text.contains("843 ms, an estimate"), "{text}");
        assert!(text.contains("the entry of the call's start"), "{text}");
        assert!(text.contains("receipt of the news"), "{text}");
        assert!(text.contains("recorded, not asserted"), "{text}");
        assert!(text.contains("latency unavailable"), "{text}");
    }

    /// A phone that could not measure leaves a section that says so, and no figure.
    #[test]
    fn a_phone_that_measured_no_figure_leaves_a_section_that_says_so() {
        let result = "check=the first audio played out ok=2 detail=native code told of no audio \
                      played out\n";
        let text = figure_section("ios", result, &conditions()).join("\n");

        assert!(
            text.contains("not measured: native code told of no audio played out"),
            "{text}"
        );
        assert!(!text.contains(" ms, an estimate"), "{text}");
        assert!(
            figure_section("ios", "", &conditions())
                .join("\n")
                .contains("the phone's result holds no figure")
        );
    }
}
