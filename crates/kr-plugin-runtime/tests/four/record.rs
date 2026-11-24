//! The frames of the plugin host protocol `kr-plugin-host/4`, kept as bytes and held to them.
//!
//! `tests/recorded/host-4-frames.json` (in `kr-plugin-service`) holds two sessions with this
//! release's own host, one with its writer open and one with it closed, and the two descriptors a
//! host publishes. A session is a worker's client over the fourth protocol, through a tee that keeps
//! every frame as it passed, followed by a raw connection that restores a state with a position, the
//! one request the client never writes. A frame that no longer reads, or that reads and writes back
//! to other bytes, is a change to a protocol whose frames are closed. The record also holds each
//! session's shape (each request and the kind of its answer), which the host is held to as well.
//!
//! `KR_RECORD_PLUGIN_HOST_4_SESSION_FRAMES=1` prints the record from the sessions instead of checking
//! it.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_plugin_runtime::runtime::binding::BindingRequest;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_service::client::PluginClient;
use kr_plugin_service::protocol::{
    ComponentSource, HostDescriptor, HostProtocol, Notice, WireArgument, WireNamedArgument,
};
use kr_plugin_service::protocol4::{
    CallValue4, Frame4, HostDescriptor4, Notice4, RecordState, Request4, ResponseBody4, Through,
};
use kr_protocol::frame::StreamKind;

use super::{Raw4, handle, recording};
use crate::{
    HANG_GUARD, REGISTRATION_PATIENCE, Served, components, documents_until, invocation,
    overflow_behind_a_stopped_pass, pending_request,
};

const RECORD: &str = include_str!("../../../kr-plugin-service/tests/recorded/host-4-frames.json");

/// A frame longer than this is kept as its length and digest: the events that fill a queue to its
/// bound are most of a megabyte each way, and what matters of them is that they are the same.
const LARGE_FRAME: usize = 4096;

/// Every request kind a session carries, with the kind of answer each is recorded with at least once.
const REQUESTS: [&str; 15] = [
    "request:hello",
    "request:verify",
    "request:register_binding",
    "request:event",
    "request:snapshot",
    "request:prepare_action",
    "request:checkpoint",
    "request:restore",
    "request:unbind",
    "request:health",
    "request:decode",
    "request:encode",
    "request:revise_facts",
    "request:revise_attachments",
    "request:privacy",
];

/// The answers and notices both sessions reach.
const REACHED: [&str; 18] = [
    "response:hello",
    "response:verified",
    "response:registered",
    "response:admitted",
    "response:called:document",
    "response:called:plan",
    "response:called:plan:with_arguments",
    "response:called:fault",
    "response:called:encoded",
    "response:unbound",
    "response:revised",
    "response:privacy_set",
    "response:health",
    "response:refused",
    "notice:document",
    "notice:gap",
    "notice:fault",
    "notice:disabled",
];

/// The members of a frame that differ from one run to the next or one machine to the next: the
/// challenge and its signature, a path in a folder made for the run, the identity of the host's
/// process and the machine, the number a worker gave a registration, how long something took, the
/// component a registration carries (built with paths of the machine that built it), and what the
/// engine says of the target it compiles for.
const OF_THE_RUN: [&str; 18] = [
    "component",
    "target",
    "engine_compatibility",
    "resident_bytes",
    "reservation_id",
    "nonce",
    "path",
    "endpoint",
    "environment_id",
    "host_public_key",
    "boot_identity",
    "process_start_identity",
    "pid",
    "start_value",
    "signature",
    "elapsed_ms",
    "uptime_ms",
    "registration",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "{text}");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hexadecimal"))
        .collect()
}

/// What a frame reads as, with each member of the run replaced by what kind of value it is.
fn of_the_run(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::Object(members) => Value::Object(
            members
                .into_iter()
                .map(|(name, member)| {
                    let member = if OF_THE_RUN.contains(&name.as_str()) {
                        match member {
                            Value::Array(items) => Value::from(format!("{} members", items.len())),
                            Value::String(_) => Value::from("text"),
                            Value::Number(_) => Value::from("number"),
                            Value::Object(_) => Value::from("object"),
                            other => Value::from(other.to_string()),
                        }
                    } else {
                        of_the_run(member)
                    };
                    (name, member)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(of_the_run).collect()),
        other => other,
    }
}

/// A frame as data, with what is of the run masked.
fn masked(kind: &str, bytes: &[u8]) -> String {
    let limits = StreamKind::Control.cbor_limits();
    let read = if kind.starts_with("request:") {
        serde_json::to_value(
            kr_cbor::from_canonical_slice::<Request4>(bytes, &limits).expect("a request"),
        )
    } else {
        serde_json::to_value(
            kr_cbor::from_canonical_slice::<Frame4>(bytes, &limits).expect("a frame"),
        )
    };
    of_the_run(read.expect("it reads as data")).to_string()
}

/// What a frame is held to: what it reads as, or, for a long frame, its length and digest (of its
/// bytes for a request, which holds nothing of its run, and of what it reads as for the rest).
fn held_to(kind: &str, bytes: &[u8]) -> String {
    if bytes.len() <= LARGE_FRAME {
        return masked(kind, bytes);
    }
    if kind.starts_with("request:") {
        return format!("{}:{}", bytes.len(), PayloadDigest::of(bytes));
    }
    let text = masked(kind, bytes);
    format!("{}:{}", text.len(), PayloadDigest::of(text.as_bytes()))
}

fn kind_of_response(body: &ResponseBody4) -> String {
    let name = match body {
        ResponseBody4::Hello { .. } => "hello",
        ResponseBody4::Verified(_) => "verified",
        ResponseBody4::Registered { .. } => "registered",
        ResponseBody4::Admitted { .. } => "admitted",
        ResponseBody4::Called {
            value,
            fault,
            record,
            ..
        } => {
            let base = match (fault, value) {
                (Some(_), _) => "fault",
                (None, None) => "none",
                (None, Some(CallValue4::Document)) => "document",
                (None, Some(CallValue4::Plan(plan))) if plan.arguments.is_empty() => "plan",
                (None, Some(CallValue4::Plan(_))) => "plan:with_arguments",
                (None, Some(CallValue4::Checkpointed(checkpointed))) => {
                    if checkpointed.consumed.is_some() {
                        "checkpointed:with_consumed"
                    } else {
                        "checkpointed"
                    }
                }
                (None, Some(CallValue4::Decoded(_))) => "decoded",
                (None, Some(CallValue4::Encoded(_))) => "encoded",
            };
            let record = match record {
                Some(RecordState::Set) => ":record_set",
                Some(RecordState::NotSet) => ":record_not_set",
                None => "",
            };
            return format!("response:called:{base}{record}");
        }
        ResponseBody4::Unbound { .. } => "unbound",
        ResponseBody4::Revised => "revised",
        ResponseBody4::PrivacySet { .. } => "privacy_set",
        ResponseBody4::Health(_) => "health",
        ResponseBody4::Refused { .. } => "refused",
    };
    format!("response:{name}")
}

fn kind_of_notice(notice: &Notice4) -> &'static str {
    match notice {
        Notice4::Document { .. } => "notice:document",
        Notice4::Gap { .. } => "notice:gap",
        Notice4::Fault { .. } => "notice:fault",
        Notice4::Disabled { .. } => "notice:disabled",
        Notice4::Consumed { .. } => "notice:consumed",
    }
}

fn kind_of_frame(frame: &Frame4) -> String {
    match frame {
        Frame4::Response { body, .. } => kind_of_response(body),
        Frame4::Notice(notice) => kind_of_notice(notice).to_owned(),
    }
}

/// Each frame that passed, in the order it was read, with whether the client wrote it.
type Kept = Arc<Mutex<Vec<(bool, Vec<u8>)>>>;

/// Puts a tee between a connection and the host's fourth endpoint: every frame is kept as it
/// passed, and written on as the same message, which has to encode to the bytes it came from.
async fn tee(served: &Served) -> (Connection, Kept, tokio::task::JoinHandle<()>) {
    let environment = served._temp.environment();
    let endpoint = kr_plugin_service::launcher::rendezvous_endpoint(
        &environment,
        kr_protocol::worker::ReservationId::new(kr_ipc::new_uuid()),
    )
    .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("the tee's endpoint");
    let host = kr_ipc::paths::Endpoint::from_path(served.endpoint4()).expect("an endpoint");
    let kept: Kept = Arc::default();
    let task = tokio::spawn({
        let kept = Arc::clone(&kept);
        async move {
            let (inbound, _peer) = listener.accept().await.expect("the client connects");
            let outbound = Connection::connect(&host).await.expect("the host answers");
            let limits = StreamKind::Control.cbor_limits();
            let (mut from_client, mut to_client) = split(inbound, StreamKind::Control);
            let (mut from_host, mut to_host) = split(outbound, StreamKind::Control);
            let up = {
                let kept = Arc::clone(&kept);
                async move {
                    while let Ok(payload) = from_client.read_payload().await {
                        kept.lock().expect("the tee").push((true, payload.clone()));
                        let request: Request4 = kr_cbor::from_canonical_slice(&payload, &limits)
                            .expect("a request of the protocol");
                        if to_host.write_message(&request).await.is_err() {
                            break;
                        }
                    }
                }
            };
            let down = {
                let kept = Arc::clone(&kept);
                async move {
                    while let Ok(payload) = from_host.read_payload().await {
                        kept.lock().expect("the tee").push((false, payload.clone()));
                        let frame: Frame4 = kr_cbor::from_canonical_slice(&payload, &limits)
                            .expect("a frame of the protocol");
                        if to_client.write_message(&frame).await.is_err() {
                            break;
                        }
                    }
                }
            };
            // The client's end is the session's end. A half of the tee that stays open would keep the
            // host's connection open, so the tee leaves with the client.
            tokio::select! {
                () = up => {}
                () = down => {}
            }
        }
    });
    let connection = Connection::connect(&endpoint)
        .await
        .expect("connects to the tee");
    (connection, kept, task)
}

/// What a session said: the frames, and the kind of each request's answer.
#[derive(Default)]
struct Session {
    frames: Vec<(String, Vec<u8>)>,
    shape: Vec<(String, String)>,
    notices: BTreeSet<String>,
}

impl Session {
    /// Adds what one tee kept, which is one connection's frames.
    fn absorb(&mut self, kept: &Kept) {
        let limits = StreamKind::Control.cbor_limits();
        let mut asked: Vec<(u64, String)> = Vec::new();
        let mut answered: std::collections::BTreeMap<u64, String> = Default::default();
        for (written, payload) in kept.lock().expect("the tee").iter() {
            if *written {
                let request: Request4 =
                    kr_cbor::from_canonical_slice(payload, &limits).expect("a request");
                let kind = format!("request:{}", request.body.name());
                asked.push((request.request_id, kind.clone()));
                self.frames.push((kind, payload.clone()));
            } else {
                let frame: Frame4 =
                    kr_cbor::from_canonical_slice(payload, &limits).expect("a frame");
                let kind = kind_of_frame(&frame);
                match &frame {
                    Frame4::Response { reply_to, .. } => {
                        answered.insert(*reply_to, kind.clone());
                    }
                    Frame4::Notice(_) => {
                        self.notices.insert(kind.clone());
                    }
                }
                self.frames.push((kind, payload.clone()));
            }
        }
        self.shape.extend(asked.into_iter().map(|(id, kind)| {
            let answer = answered.get(&id).cloned().unwrap_or_default();
            (kind, answer)
        }));
    }
}

/// The descriptor a worker verifies a host of `served` against over the fourth protocol.
fn descriptor4(served: &Served) -> HostDescriptor4 {
    HostDescriptor4 {
        protocol: HostProtocol::V4.name.to_owned(),
        environment_id: served.descriptor.environment_id,
        reservation_id: served.descriptor.reservation_id,
        endpoint: served.endpoint4().to_owned(),
        boot_identity: served.descriptor.boot_identity.clone(),
        process_start_identity: served.descriptor.process_start_identity.clone(),
        host_public_key: served.descriptor.host_public_key,
        build: Served::build(),
    }
}

async fn bind(
    client: &PluginClient,
    served: &Served,
    plugin: &str,
    wasm: &[u8],
    request: &BindingRequest,
) {
    let (path, digest, bytes) = served.install(plugin, wasm);
    client
        .register(
            request.binding_id,
            &request.identity,
            &request.facts,
            &request.executable,
            &ComponentSource {
                path,
                digest,
                bytes,
            },
        )
        .await
        .expect("the binding registers");
}

/// A session with this host through a tee, as the third protocol's is kept: a worker registers
/// components, delivers an event, takes a snapshot, a checkpoint and a restore, revises facts and
/// attachments, sets privacy mode while a document is held, asks a component to prepare actions,
/// decodes and encodes, faults until a binding is disabled, floods a queue until the host tells of the
/// gap, and unbinds. A raw connection then restores a state with a position into a second registration.
async fn session(served: &Served, open: bool) -> Option<Session> {
    let behaved = components::well_behaved()?;
    let hostile = components::component("hostile-decoder")?;
    let preparing = components::component("preparing")?;
    let recorded = recording(served)?;
    let (connection, kept, tee_task) = tee(served).await;
    let mut client = PluginClient::over_four(connection, descriptor4(served))
        .await
        .expect("the handshake and the challenge")
        .registering_within(REGISTRATION_PATIENCE + core::time::Duration::from_secs(5));
    let deadline = core::time::Duration::from_secs(20);

    let first = components::request("well-behaved", 1);
    bind(&client, served, "well-behaved", &behaved, &first).await;
    client.health().await.expect("a health report");
    client
        .deliver(first.binding_id, &components::scrape("se-1", "building"))
        .await
        .expect("the event is offered");
    documents_until(&mut client, first.binding_id, "bind").await;
    documents_until(&mut client, first.binding_id, "observe").await;
    client
        .snapshot(first.binding_id, deadline)
        .await
        .expect("the snapshot runs");
    documents_until(&mut client, first.binding_id, "snapshot").await;
    let state = client
        .checkpoint(first.binding_id, deadline)
        .await
        .expect("the checkpoint runs")
        .state
        .expect("the component has state");
    client
        .restore(first.binding_id, state, deadline)
        .await
        .expect("the restore runs");
    client
        .revise_facts(first.binding_id, &components::facts("well-behaved"))
        .await
        .expect("the facts are revised");
    client
        .revise_attachments(first.binding_id, &[])
        .await
        .expect("the attachments are revised");
    // Privacy mode is acknowledged while a document is held at the writer, so that its end tells the
    // reader that documents were lost, and a fresh one follows.
    let hold = served.host.hold_notice_writes();
    client
        .snapshot(first.binding_id, deadline)
        .await
        .expect("the snapshot runs");
    tokio::time::timeout(HANG_GUARD, async {
        while !hold.parked() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the writer never took the document off the queue");
    client.privacy(true).await.expect("privacy mode is set");
    hold.release();
    client.privacy(false).await.expect("privacy mode ends");
    tokio::time::timeout(HANG_GUARD, async {
        let mut told = false;
        loop {
            match client.notice().await.expect("the connection is open") {
                Notice::Gap { documents, .. } if documents > 0 => told = true,
                Notice::Document { last: true, .. } if told => break,
                _ => {}
            }
        }
    })
    .await
    .expect("no fresh document followed the end of privacy mode");

    // A component that prepares actions: a plan, a plan that fills in fields, and a fault it
    // declares.
    let third = components::request("preparing", 5);
    bind(&client, served, "preparing", &preparing, &third).await;
    let given = vec![WireNamedArgument {
        name: "reason".to_owned(),
        value: WireArgument::Text("because".to_owned()),
    }];
    for action in ["turn.cancel", "prompt.with.fields", "cancel.fault"] {
        client
            .prepare_action(
                third.binding_id,
                invocation(action),
                given.clone(),
                deadline,
            )
            .await
            .expect("the call runs");
    }
    // A plan that is given no argument.
    client
        .prepare_action(
            third.binding_id,
            invocation("turn.cancel"),
            Vec::new(),
            deadline,
        )
        .await
        .expect("the call runs");

    let second = components::request("hostile-decoder", 14);
    bind(&client, served, "hostile-decoder", &hostile, &second).await;
    let _ = client
        .decode(
            second.binding_id,
            &components::native_request("se-2", "8", "a request"),
            deadline,
        )
        .await;
    client
        .decode(
            second.binding_id,
            &components::native_request("se-3", "9", "!trap"),
            deadline,
        )
        .await
        .expect_err("a decode that traps is refused");
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            if let Notice::Fault { .. } = client.notice().await.expect("the connection is open") {
                break;
            }
        }
    })
    .await
    .expect("the fault was never written");

    // An offered decision is encoded, and a request the component declines to decode is a fault it
    // declares, which is an answer and not a trap.
    let source = components::native_request("se-1", "7", "a request to write");
    client
        .encode(
            second.binding_id,
            pending_request("7", "session/request_permission"),
            "allow",
            Some(&source),
            deadline,
        )
        .await
        .expect("an offered decision is encoded");
    let _ = client
        .decode(
            second.binding_id,
            &components::native_request("se-5", "10", "!decline"),
            deadline,
        )
        .await;

    // The third fault disables a binding, and the host tells the reader so.
    let fourth = components::request("hostile-decoder", 16);
    bind(&client, served, "hostile-decoder", &hostile, &fourth).await;
    for index in 0..3 {
        client
            .decode(
                fourth.binding_id,
                &components::native_request(&format!("se-{}", 6 + index), "11", "!trap"),
                deadline,
            )
            .await
            .expect_err("a decode that traps is refused");
    }
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            if let Notice::Disabled { .. } = client.notice().await.expect("the connection is open")
            {
                break;
            }
        }
    })
    .await
    .expect("the host never said the binding was disabled");

    // A queue that overflows behind a pass that has not taken anything: the host tells the reader
    // how much was lost, and a snapshot follows.
    let fifth = components::request("hostile-decoder", 17);
    bind(&client, served, "hostile-decoder", &hostile, &fifth).await;
    let stop = overflow_behind_a_stopped_pass(served, &client, &fifth).await;
    stop.release();
    tokio::time::timeout(HANG_GUARD, async {
        let mut told = false;
        loop {
            match client.notice().await.expect("the connection is open") {
                Notice::Gap { events, .. } if events > 0 => told = true,
                Notice::Document { last: true, .. } if told => break,
                _ => {}
            }
        }
    })
    .await
    .expect("no snapshot followed the gap");

    assert!(client.unbind(first.binding_id).await.expect("an unbind"));
    assert!(!client.unbind(first.binding_id).await.expect("an unbind"));
    assert!(client.unbind(second.binding_id).await.expect("an unbind"));
    assert!(client.unbind(third.binding_id).await.expect("an unbind"));
    let _ = client.unbind(fourth.binding_id).await.expect("an unbind");
    assert!(client.unbind(fifth.binding_id).await.expect("an unbind"));
    drop(client);
    tokio::time::timeout(HANG_GUARD, tee_task)
        .await
        .expect("the tee ends with the client")
        .expect("the tee runs");
    let mut session = Session::default();
    session.absorb(&kept);

    // The request the client never writes: a state restored with a position into a registration of
    // another binding, which an open host sets a record from and a closed one does not.
    let (connection, kept, tee_task) = tee(served).await;
    let (reader, writer) = split(connection, StreamKind::Control);
    let mut raw = Raw4 {
        reader,
        writer,
        next: 0,
        answers: HashMap::new(),
        notices: Vec::new(),
    };
    let saved_from = components::request("recording", 33);
    raw.register(&saved_from, &recorded, 7).await;
    raw.event(&saved_from, "se-1", "x").await;
    raw.event(&saved_from, "se-2", "y").await;
    let saved = loop {
        let saved = raw.checkpoint(&saved_from).await;
        if !open
            || saved
                .consumed
                .as_ref()
                .is_some_and(|consumed| consumed.terminal == Some(handle("se-2")))
        {
            break saved;
        }
        tokio::task::yield_now().await;
    };
    let moved_into = components::request("recording", 34);
    raw.register(&moved_into, &recorded, 8).await;
    // What the answer says is held by the record: the shape of the session and the frames.
    let _ = raw
        .restore(
            &moved_into,
            8,
            saved.state.clone(),
            Some(Through {
                native: None,
                terminal: Some(handle("se-2")),
            }),
        )
        .await;
    raw.unbind(&saved_from).await;
    raw.unbind(&moved_into).await;
    drop(raw);
    tokio::time::timeout(HANG_GUARD, tee_task)
        .await
        .expect("the tee ends with the connection")
        .expect("the tee runs");
    session.absorb(&kept);
    Some(session)
}

fn entries(frames: &[(String, Vec<u8>)]) -> Vec<serde_json::Value> {
    frames
        .iter()
        .map(|(kind, bytes)| {
            if bytes.len() > LARGE_FRAME {
                let held = held_to(kind, bytes);
                let (length, digest) = held.split_once(':').expect("a length and a digest");
                serde_json::json!({
                    "kind": kind,
                    "length": length.parse::<u64>().expect("a length"),
                    "digest": digest,
                })
            } else {
                serde_json::json!({ "kind": kind, "hex": hex(bytes) })
            }
        })
        .collect()
}

/// The frames of a recorded session, each held to what it reads as.
fn recorded_frames(session: &serde_json::Value) -> Vec<(String, String)> {
    session["frames"]
        .as_array()
        .expect("the frames")
        .iter()
        .map(|entry| {
            let kind = entry["kind"].as_str().expect("a kind").to_owned();
            let held = match entry["hex"].as_str() {
                Some(hexed) => held_to(&kind, &unhex(hexed)),
                None => format!(
                    "{}:{}",
                    entry["length"].as_u64().expect("a length"),
                    entry["digest"].as_str().expect("a digest")
                ),
            };
            (kind, held)
        })
        .collect()
}

/// KR-REQ-24.24: every frame of the recorded sessions reads in this build and writes back to the bytes
/// it was recorded as, each kind of request, answer and notice is in them, and the descriptors read
/// and write back.
#[test]
fn kr_req_24_24_every_recorded_frame_of_the_fourth_plugin_host_protocol_reads_and_writes_back() {
    let record: serde_json::Value = serde_json::from_str(RECORD).expect("the record");
    let limits = StreamKind::Control.cbor_limits();
    for which in ["open", "closed"] {
        let mut kinds = BTreeSet::new();
        for entry in record[which]["frames"].as_array().expect("the frames") {
            let kind = entry["kind"].as_str().expect("a kind");
            let Some(hexed) = entry["hex"].as_str() else {
                // A frame too long to keep is held as its length and digest.
                assert!(
                    entry["length"].as_u64().is_some_and(|length| length > 8)
                        && entry["digest"]
                            .as_str()
                            .is_some_and(|digest| digest.len() > 8),
                    "{which}: {kind} holds neither its bytes nor its length and digest"
                );
                kinds.insert(kind.to_owned());
                continue;
            };
            let bytes = unhex(hexed);
            let read = if kind.starts_with("request:") {
                let request: Request4 = kr_cbor::from_canonical_slice(&bytes, &limits)
                    .unwrap_or_else(|why| {
                        panic!("{which}: {kind} is not read by this build: {why}")
                    });
                assert_eq!(
                    kr_cbor::to_canonical_vec(&request).expect("it encodes"),
                    bytes,
                    "{which}: {kind} writes back to the bytes it was recorded as"
                );
                format!("request:{}", request.body.name())
            } else {
                let frame: Frame4 =
                    kr_cbor::from_canonical_slice(&bytes, &limits).unwrap_or_else(|why| {
                        panic!("{which}: {kind} is not read by this build: {why}")
                    });
                assert_eq!(
                    kr_cbor::to_canonical_vec(&frame).expect("it encodes"),
                    bytes,
                    "{which}: {kind} writes back to the bytes it was recorded as"
                );
                kind_of_frame(&frame)
            };
            assert_eq!(
                read, kind,
                "{which}: the frame is the kind it was recorded as"
            );
            kinds.insert(read);
        }
        for kind in REQUESTS.iter().chain(&REACHED) {
            assert!(
                kinds.contains(*kind),
                "the {which} session holds no frame of {kind}"
            );
        }
        let wanted = if which == "open" {
            [
                "notice:consumed",
                "response:called:checkpointed:with_consumed",
            ]
        } else {
            ["response:called:checkpointed", "response:hello"]
        };
        for kind in wanted {
            assert!(
                kinds.contains(kind),
                "the {which} session holds no frame of {kind}"
            );
        }
        let record_kind = if which == "open" {
            ":record_set"
        } else {
            ":record_not_set"
        };
        assert!(
            kinds.iter().any(|kind| kind.ends_with(record_kind)),
            "no restore of the {which} session was answered with a record that is {record_kind}"
        );
        assert_eq!(
            kinds.contains("notice:consumed"),
            which == "open",
            "only a host with its writer open writes a report of what was consumed"
        );
    }

    let third = &record["descriptors"]["plugin-host-3.json"];
    let read: HostDescriptor = serde_json::from_value(third.clone()).expect("the third descriptor");
    assert_eq!(&serde_json::to_value(&read).expect("it writes"), third);
    assert_eq!(read.protocol, HostProtocol::V3.name);
    let fourth = &record["descriptors"]["plugin-host-4.json"];
    let read: HostDescriptor4 =
        serde_json::from_value(fourth.clone()).expect("the fourth descriptor");
    assert_eq!(&serde_json::to_value(&read).expect("it writes"), fourth);
    assert_eq!(read.protocol, HostProtocol::V4.name);
    assert!(
        fourth.get("build").is_some() && third.get("build").is_none(),
        "the fourth descriptor states its build and the third's has no such member"
    );
}

/// KR-REQ-24.24: the host answers a session the way the record says. Requests are the session's own
/// and are the requests that were recorded; each is answered with the kind of answer it was recorded
/// with, and the answers and notices are the ones that were recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_24_the_fourth_protocol_host_answers_its_sessions_the_way_the_record_says() {
    let mut sessions = Vec::new();
    let mut hellos = Vec::new();
    let mut third = None;
    for open in [true, false] {
        let served = Served::start_dual(open).await;
        let Some(session) = session(&served, open).await else {
            return;
        };
        third = Some(serde_json::to_value(&served.descriptor).expect("a descriptor"));
        let limits = StreamKind::Control.cbor_limits();
        let hello = session
            .frames
            .iter()
            .find(|(kind, _)| kind == "response:hello")
            .map(|(_, bytes)| {
                kr_cbor::from_canonical_slice::<Frame4>(bytes, &limits).expect("a frame")
            });
        let Some(Frame4::Response {
            body: ResponseBody4::Hello { descriptor, .. },
            ..
        }) = hello
        else {
            panic!("the session holds no hello");
        };
        hellos.push(serde_json::to_value(&*descriptor).expect("a descriptor"));
        sessions.push(session);
    }
    if std::env::var_os("KR_RECORD_PLUGIN_HOST_4_SESSION_FRAMES").is_some() {
        let of = |session: &Session| {
            serde_json::json!({
                "frames": entries(&session.frames),
                "shape": session.shape,
                "notices": session.notices,
            })
        };
        let record = serde_json::json!({
            "descriptors": {
                "plugin-host-3.json": third,
                "plugin-host-4.json": hellos[0],
            },
            "open": of(&sessions[0]),
            "closed": of(&sessions[1]),
        });
        println!(
            "RECORD-BEGIN\n{}\nRECORD-END",
            serde_json::to_string_pretty(&record).expect("the record")
        );
        return;
    }
    let record: serde_json::Value = serde_json::from_str(RECORD).expect("the record");
    for (which, session) in ["open", "closed"].into_iter().zip(&sessions) {
        let recorded = &record[which];
        let shape: Vec<(String, String)> =
            serde_json::from_value(recorded["shape"].clone()).expect("the recorded shape");
        assert_eq!(
            session.shape, shape,
            "{which}: each request is answered with the kind of answer it was recorded with"
        );
        let live: Vec<(String, String)> = session
            .frames
            .iter()
            .map(|(kind, bytes)| (kind.clone(), held_to(kind, bytes)))
            .collect();
        let recorded = recorded_frames(recorded);
        let requests = |frames: &[(String, String)]| {
            frames
                .iter()
                .filter(|(kind, _)| kind.starts_with("request:"))
                .cloned()
                .collect::<Vec<_>>()
        };
        let (live_requests, recorded_requests) = (requests(&live), requests(&recorded));
        assert_eq!(
            live_requests.len(),
            recorded_requests.len(),
            "{which}: the session asked for another number of things than it did when it was recorded"
        );
        for (at, (asked, was)) in live_requests.iter().zip(&recorded_requests).enumerate() {
            assert!(
                asked == was,
                "{which}: request {at} ({}) is not the request that was recorded",
                asked.0
            );
        }
        // Answers and notices are a multiset: when a notice is written beside an answer is not what
        // the protocol fixes.
        for (what, prefix) in [("answer", "response:"), ("notice", "notice:")] {
            let mut counts: std::collections::BTreeMap<(String, String), i64> = Default::default();
            for (kind, held) in &live {
                if kind.starts_with(prefix) {
                    *counts.entry((kind.clone(), held.clone())).or_default() += 1;
                }
            }
            for (kind, held) in &recorded {
                if kind.starts_with(prefix) {
                    *counts.entry((kind.clone(), held.clone())).or_default() -= 1;
                }
            }
            let differing: Vec<(&str, i64)> = counts
                .iter()
                .filter(|(_, left)| **left != 0)
                .map(|((kind, _), left)| (kind.as_str(), *left))
                .collect();
            assert!(
                differing.is_empty(),
                "{which}: these {what}s were written more times (positive) or fewer (negative) than they were recorded: {differing:?}"
            );
        }
    }
    // The descriptors this host publishes are the ones that were recorded, but for what is of the run.
    let held = |value: &serde_json::Value| of_the_run(value.clone());
    assert_eq!(
        held(&hellos[0]),
        held(&record["descriptors"]["plugin-host-4.json"]),
        "the fourth descriptor is the one that was recorded"
    );
    assert_eq!(
        held(third.as_ref().expect("a third descriptor")),
        held(&record["descriptors"]["plugin-host-3.json"]),
        "the third descriptor is the one that was recorded"
    );
}
