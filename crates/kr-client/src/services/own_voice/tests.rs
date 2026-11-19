//! Cases of the own-key provider, against a stand-in for OpenAI and a record in memory. Time is
//! paused, so a bound passes by the clock and never by waiting.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kr_protocol::ids::ActionId;
use kr_protocol::scalars::Uuid;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::stand_in::{
    CreateScript, HangupScript, MemoryLedger, STAND_IN_MARKER, StandIn, StaticKey, created_body,
    not_found_body,
};
use super::*;
use crate::services::own_registry::RegistryState;

const KEY: &str = "sk-test-sentinel-key-0001";

struct World {
    provider: OwnVoiceProvider,
    stand_in: StandIn,
    ledger: Arc<MemoryLedger>,
    keys: Arc<StaticKey>,
}

fn fresh() -> World {
    let stand_in = StandIn::new();
    let ledger = MemoryLedger::new();
    let keys = StaticKey::holding(Some(KEY));
    let registry = CallRegistry::new(ledger.clone());
    let provider = OwnVoiceProvider::new(
        ledger.clone(),
        registry,
        keys.clone(),
        Arc::new(stand_in.clone()),
        Arc::new(|| 1_700_000_000_000),
    );
    World {
        provider,
        stand_in,
        ledger,
        keys,
    }
}

fn fixture() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/voice/gpt-live-1-session-create.json"
    );
    serde_json::from_slice(&std::fs::read(path).expect("the vendored request")).expect("json")
}

fn request(action: u8) -> VoiceSessionRequest {
    VoiceSessionRequest {
        offer_sdp: fixture()["offer"].as_str().expect("the offer").to_owned(),
        host_id: "host".to_owned(),
        duration_seconds: 300,
        reasoning_budget_minor: None,
        device_id: Some("device-1".to_owned()),
        action_id: ActionId::new(Uuid::from_bytes([action; 16])),
        expected_rate_version: None,
    }
}

async fn start(world: &World, action: u8) -> Result<VoiceStart> {
    let request = request(action);
    let attempt = world.provider.begin(&request).await?;
    world.provider.dispatch(attempt, &request).await
}

async fn started(world: &World) -> OwnSession {
    match start(world, 1).await.expect("a start") {
        VoiceStart::StartedOwn(own) => *own,
        other => panic!("a working start gave {other:?}"),
    }
}

fn states(world: &World) -> Vec<CallState> {
    world
        .ledger
        .rows()
        .expect("rows")
        .iter()
        .map(|row| row.state)
        .collect()
}

#[test]
fn a_call_is_created_with_the_pinned_request_and_the_offer_unchanged() {
    let fixture = fixture();
    let offer = fixture["offer"].as_str().expect("offer");
    assert_eq!(creation_body(offer), fixture["request"]);
    let hash: String = Sha256::digest(CONVERSATION_INSTRUCTIONS.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(fixture["instructions_sha256"], json!(hash));
    assert_eq!(fixture["instructions"], json!(CONVERSATION_INSTRUCTIONS));
    assert_eq!(creation_body(offer)["transport"]["sdp"], json!(offer));
}

#[test]
fn the_production_transport_names_the_pinned_origin_and_a_testing_build_refuses_it() {
    assert_eq!(OPENAI_ORIGIN, "https://api.openai.com");
    let before = stand_in::TESTING_REFUSALS.load(Ordering::Relaxed);
    let refusal = connect_production(None).expect_err("a testing build refuses");
    assert!(refusal.to_string().contains("does not reach OpenAI"));
    assert_eq!(
        stand_in::TESTING_REFUSALS.load(Ordering::Relaxed),
        before + 1
    );
}

#[test]
fn the_six_commands_are_the_provider_schemas_commands_and_nothing_else() {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/voice/gpt-live-1/schemas/client/"
    );
    for command in VoiceCommand::ALL {
        let text = command.carries_text().then(|| "words".to_owned());
        let delegation = command.carries_text().then(|| "del_1".to_owned());
        let frame = VoiceContextFrame::new("id-1", *command, delegation, text).expect("frame");
        let written = command_json(&frame);
        let kind = written["type"].as_str().expect("type").to_owned();
        let schema: Value =
            serde_json::from_slice(&std::fs::read(format!("{dir}{kind}.json")).expect("schema"))
                .expect("json");
        assert_eq!(schema["properties"]["type"]["const"], json!(kind));
        let keys: Vec<&String> = written.as_object().expect("object").keys().collect();
        for required in schema["required"].as_array().expect("required") {
            assert!(
                keys.iter()
                    .any(|key| *key == required.as_str().expect("name"))
            );
        }
        for key in keys {
            assert!(
                schema["properties"].get(key).is_some(),
                "{kind} writes {key}"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_creation_that_is_unknown_keeps_its_row_with_no_id_and_a_refused_one_deletes_it() {
    let unknowns = [
        CreateScript::Lost,
        CreateScript::Answer(429, None),
        CreateScript::Answer(500, Some(b"x".to_vec())),
        CreateScript::Answer(503, None),
        CreateScript::Answer(201, Some(b"not json".to_vec())),
        CreateScript::Answer(201, Some(br#"{"session":{"id":"live_1"}}"#.to_vec())),
        CreateScript::Answer(201, None),
    ];
    for script in unknowns {
        let world = fresh();
        world.stand_in.script_create(script.clone());
        let outcome = start(&world, 1).await.expect("an answer");
        assert!(
            matches!(outcome, VoiceStart::CreationUnknown { .. }),
            "{script:?}"
        );
        let rows = world.ledger.rows().expect("rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, CallState::Creating);
        assert!(rows[0].provider_session_id.is_none());
        assert_eq!(world.stand_in.recorded().creates.len(), 1, "no retry");
        assert!(world.stand_in.recorded().hangups.is_empty());
    }
    for status in [400_u16, 401, 403, 404, 302] {
        for body in [Some(b"{}".to_vec()), None] {
            let world = fresh();
            world
                .stand_in
                .script_create(CreateScript::Answer(status, body));
            let VoiceStart::Refused(refusal) = start(&world, 1).await.expect("an answer") else {
                panic!("{status} is a refusal");
            };
            assert!(world.ledger.rows().expect("rows").is_empty(), "{status}");
            if status == 401 || status == 403 {
                assert_eq!(refusal.message, words::refused_with_this_key(status));
            } else {
                assert_eq!(refusal.message, words::not_accepted(status));
            }
            assert!(!refusal.message.contains(KEY));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn a_working_start_records_the_id_proves_the_channel_and_a_second_start_is_a_conflict() {
    let world = fresh();
    let own = started(&world).await;
    assert_eq!(own.model, OPENAI_MODEL);
    assert_eq!(states(&world), [CallState::Open]);
    assert_eq!(
        world.ledger.rows().expect("rows")[0]
            .provider_session_id
            .as_deref(),
        Some("live_u1_stand_in")
    );
    let recorded = world.stand_in.recorded();
    assert_eq!(recorded.creates[0].0, KEY);
    assert_eq!(
        recorded.creates[0].1["transport"]["sdp"],
        fixture()["offer"]
    );
    let probe = &recorded.commands[0];
    assert_eq!(probe["type"], "session.input_audio.unmute");
    let control = world
        .provider
        .host_control(&own.call_id)
        .expect("a side channel");
    assert_eq!(control.state(), SidebandState::Ready);
    assert!(
        world
            .provider
            .call_is_open(&own.call_id)
            .await
            .expect("open")
    );
    // A second start from any device is refused and closes nothing.
    let refusal = start(&world, 2).await.expect_err("a conflict");
    assert_eq!(refusal.code(), ErrorCode::DraftConflict);
    let said = refusal.to_string();
    assert!(said.contains("device-1") && said.contains("not confirmed closed"));
    assert!(world.stand_in.recorded().hangups.is_empty());
    assert_eq!(states(&world), [CallState::Open]);
}

#[tokio::test(start_paused = true)]
async fn a_stop_marks_the_row_closed_before_it_is_deleted_and_hangs_up_only_when_closed_never_came()
{
    let world = fresh();
    let own = started(&world).await;
    world.provider.close(&own.call_id).await.expect("closed");
    assert!(world.ledger.rows().expect("rows").is_empty());
    assert!(
        world.stand_in.recorded().hangups.is_empty(),
        "closed was heard, so no hangup"
    );
    assert_eq!(world.provider.registry().state(), RegistryState::Idle);
    // The same with no closing event: the drain passes and the host hangs up.
    let world = fresh();
    world.stand_in.answer_close(false);
    let own = started(&world).await;
    world
        .provider
        .close(&own.call_id)
        .await
        .expect("closed by hangup");
    assert_eq!(world.stand_in.recorded().hangups.len(), 1);
    assert!(world.ledger.rows().expect("rows").is_empty());
    // And a hangup that is not a recognised closure leaves the row unresolved and says so.
    let world = fresh();
    world.stand_in.answer_close(false);
    world
        .stand_in
        .script_hangup(HangupScript::Answer(404, Some(Vec::new())));
    let own = started(&world).await;
    assert!(world.provider.close(&own.call_id).await.is_err());
    assert_eq!(states(&world), [CallState::Unresolved]);
    // An empty 404 is not a closure; a 404 with the recorded code is.
    let world = fresh();
    world.stand_in.answer_close(false);
    world
        .stand_in
        .script_hangup(HangupScript::Answer(404, Some(not_found_body())));
    let own = started(&world).await;
    world
        .provider
        .close(&own.call_id)
        .await
        .expect("a recorded 404 is a closure");
}

#[tokio::test(start_paused = true)]
async fn readiness_needs_the_configuration_back_as_asked_and_the_probe_under_its_own_id() {
    // A configuration that came back different.
    let world = fresh();
    world.stand_in.send_started(false);
    let stand_in = world.stand_in.clone();
    let task = async { start(&world, 1).await.expect("an answer") };
    let sender = async {
        tokio::task::yield_now().await;
        stand_in.event(&json!({"type":"session.started","event_id":"e","session":{
            "id":"live_u1_stand_in","model":"gpt-live-1","status":"active","expires_at":1,
            "delegation":{"type":"client"},"store":true,
            "client":{"data_channel":{"allowed_client_events":[],"allowed_server_events":[]}}}}));
    };
    let (outcome, ()) = tokio::join!(task, sender);
    let VoiceStart::Refused(refusal) = outcome else {
        panic!("different configuration")
    };
    assert_eq!(refusal.reason, VoiceRefusalReason::ReadinessUnavailable);
    assert_eq!(
        world.stand_in.recorded().hangups.len(),
        1,
        "the session is hung up"
    );
    assert!(
        world.ledger.rows().expect("rows").is_empty(),
        "closed, then deleted"
    );
    // An acknowledgement under another id is not readiness.
    let world = fresh();
    world.stand_in.acknowledge(false);
    let stand_in = world.stand_in.clone();
    let task = async { start(&world, 1).await.expect("an answer") };
    let sender = async {
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        stand_in.event(&json!({"type":"session.input_audio.unmuted","event_id":"e","client_event_id":"another"}));
    };
    let (outcome, ()) = tokio::join!(task, sender);
    assert!(matches!(outcome, VoiceStart::Refused(_)));
    // The failed hangup leaves the row unresolved.
    let world = fresh();
    world.stand_in.acknowledge(false);
    world.stand_in.script_hangup(HangupScript::Lost);
    let outcome = start(&world, 1).await.expect("an answer");
    assert!(matches!(outcome, VoiceStart::Refused(_)));
    assert_eq!(states(&world), [CallState::Unresolved]);
}

#[tokio::test(start_paused = true)]
async fn an_id_that_cannot_be_written_hangs_the_session_up_and_stays_unmarked_until_closed() {
    let world = fresh();
    world.ledger.failing("record_id", true);
    let outcome = start(&world, 1).await.expect("an answer");
    assert!(matches!(outcome, VoiceStart::Refused(_)));
    assert_eq!(world.stand_in.recorded().hangups.len(), 1);
    assert!(
        world.ledger.rows().expect("rows").is_empty(),
        "closed, then deleted"
    );
    let world = fresh();
    world.ledger.failing("record_id", true);
    world.stand_in.script_hangup(HangupScript::Lost);
    let _ = start(&world, 1).await.expect("an answer");
    assert_eq!(
        states(&world),
        [CallState::Creating],
        "it blocks until the owner forgets it"
    );
}

#[tokio::test(start_paused = true)]
async fn an_attempt_given_up_before_anything_was_sent_deletes_its_row_and_asks_nothing() {
    let world = fresh();
    let request = request(1);
    let attempt = world.provider.begin(&request).await.expect("begin");
    assert_eq!(states(&world), [CallState::Creating]);
    world.provider.abandon(attempt).await.expect("abandon");
    assert!(world.ledger.rows().expect("rows").is_empty());
    assert!(world.stand_in.recorded().creates.is_empty());
    assert_eq!(world.provider.registry().state(), RegistryState::Idle);
    // A dropped attempt does the same.
    let attempt = world.provider.begin(&request).await.expect("begin");
    drop(attempt);
    assert!(world.ledger.rows().expect("rows").is_empty());
    assert_eq!(world.provider.registry().state(), RegistryState::Idle);
}

#[tokio::test(start_paused = true)]
async fn a_start_that_a_removal_fenced_hangs_a_late_creation_up_with_the_original_key() {
    let world = fresh();
    world.stand_in.script_create(CreateScript::After(
        Duration::from_secs(10),
        Box::new(CreateScript::Answer(201, Some(created_body("live_late")))),
    ));
    let request = request(1);
    let attempt = world.provider.begin(&request).await.expect("begin");
    let provider = &world.provider;
    let dispatch = provider.dispatch(attempt, &request);
    let removal = async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let fence = provider.registry().fence().expect("a fence");
        assert_eq!(fence.before, RegistryState::Starting);
        let settled = provider.settle().await;
        provider.registry().unfence();
        settled
    };
    let (outcome, settled) = tokio::join!(dispatch, removal);
    assert!(matches!(
        outcome.expect("an answer"),
        VoiceStart::Refused(_)
    ));
    assert_eq!(settled, Settled::LateSessionClosed);
    let hangups = world.stand_in.recorded().hangups;
    assert_eq!(hangups.len(), 1);
    assert_eq!(hangups[0].1, "live_late");
    assert_eq!(hangups[0].0, KEY, "the original key");
    assert!(
        world.ledger.rows().expect("rows").is_empty(),
        "no row for the late session"
    );
}

#[tokio::test(start_paused = true)]
async fn a_start_that_is_never_answered_settles_as_may_still_run() {
    let world = fresh();
    world.stand_in.script_create(CreateScript::After(
        Duration::from_secs(60),
        Box::new(CreateScript::Lost),
    ));
    let request = request(1);
    let attempt = world.provider.begin(&request).await.expect("begin");
    let provider = &world.provider;
    let dispatch = provider.dispatch(attempt, &request);
    let removal = async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _fence = provider.registry().fence().expect("a fence");
        provider.settle().await
    };
    let (outcome, settled) = tokio::join!(dispatch, removal);
    assert!(matches!(
        outcome.expect("answer"),
        VoiceStart::CreationUnknown { .. }
    ));
    assert_eq!(settled, Settled::MayStillRun);
    assert_eq!(states(&world), [CallState::Creating]);
}

#[tokio::test(start_paused = true)]
async fn a_lost_side_channel_is_attached_again_under_a_higher_revision_and_a_close_after_closed_is_no_loss()
 {
    let world = fresh();
    let own = started(&world).await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    assert_eq!(control.revision(), 1);
    world.stand_in.drop_socket();
    tokio::time::sleep(Duration::from_millis(1)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(control.state(), SidebandState::Ready);
    assert_eq!(control.revision(), 2);
    assert_eq!(world.stand_in.recorded().attaches, 2);
    // A write under the old revision is stale.
    let frame = VoiceContextFrame::new(
        "w-1",
        VoiceCommand::Thinking,
        None,
        Some("hello".to_owned()),
    )
    .expect("frame");
    assert_eq!(
        control.write(1, frame.clone()).await,
        Err(WriteRefusal::Stale)
    );
    let acks = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&acks);
    control.listen(Arc::new(move |event| {
        seen.lock().expect("acks").push(event)
    }));
    assert_eq!(control.write(2, frame).await, Ok(()));
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert!(acks.lock().expect("acks").iter().any(|event| matches!(
        event, HostCallEvent::WriteAcknowledged { write_id } if write_id == "w-1")));
    // The provider says it closed; the socket closing after it is not a loss.
    world
        .stand_in
        .event(&json!({"type":"session.closed","event_id":"e","reason":"expired"}));
    world.stand_in.drop_socket();
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        control.state(),
        SidebandState::Closed(SidebandEnd::ProviderClosed)
    );
    assert_eq!(
        world.stand_in.recorded().attaches,
        2,
        "no reattach after closed"
    );
    assert!(world.ledger.rows().expect("rows").is_empty());
    assert_eq!(world.provider.registry().state(), RegistryState::Idle);
}

#[tokio::test(start_paused = true)]
async fn a_channel_that_is_not_back_in_ten_seconds_has_its_call_hung_up() {
    let world = fresh();
    let own = started(&world).await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    for _ in 0..80 {
        world.stand_in.fail_attach(AttachFault::Unavailable);
    }
    world.stand_in.drop_socket();
    tokio::time::sleep(Duration::from_secs(12)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        control.state(),
        SidebandState::Closed(SidebandEnd::HostClosed)
    );
    assert_eq!(world.stand_in.recorded().hangups.len(), 1);
    assert!(world.ledger.rows().expect("rows").is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_delegation_is_heard_by_what_the_provider_announced_and_not_by_a_guess() {
    let world = fresh();
    let own = started(&world).await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    assert_eq!(control.heard("del_1"), None);
    assert_eq!(
        control.heard_within("del_1", Duration::from_secs(5)).await,
        None
    );
    let announce = json!({"type":"session.delegation.created","event_id":"e","offset_ms":1234,
        "delegation":{"id":"del_1","type":"delegation","target":"client"}});
    let waiting = control.heard_within("del_1", Duration::from_secs(5));
    let sending = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        world.stand_in.event(&announce);
    };
    let (heard, ()) = tokio::join!(waiting, sending);
    assert_eq!(heard, Some(1234));
}

#[tokio::test(start_paused = true)]
async fn no_transcript_audio_or_error_message_reaches_an_event_a_count_or_a_rendering() {
    let world = fresh();
    let own = started(&world).await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    let events = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&events);
    control.listen(Arc::new(move |event| {
        seen.lock().expect("events").push(format!("{event:?}"))
    }));
    let secret = "SENTINEL-WORDS-SPOKEN";
    for event in [
        json!({"type":"session.input_transcript.delta","event_id":"e","delta":secret}),
        json!({"type":"session.output_transcript.delta","event_id":"e","delta":secret}),
        json!({"type":"session.usage.updated","event_id":"e","usage":{"seconds":1}}),
        json!({"type":"error","event_id":"e","error":{"type":"x","message":format!("{KEY} {secret}")}}),
        json!({"type":format!("unknown.{secret}"),"event_id":"e"}),
    ] {
        world.stand_in.event(&event);
    }
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(world.provider.unknown_events(&own.call_id), Some(1));
    let shown = format!(
        "{:?} {:?} {:?} {:?}",
        events.lock().expect("events"),
        control,
        world.provider,
        own
    );
    assert!(!shown.contains(secret) && !shown.contains(KEY));
}

#[tokio::test(start_paused = true)]
async fn a_start_checks_what_it_can_before_it_writes_anything_and_a_standing_row_blocks() {
    let world = fresh();
    let mut long = request(1);
    long.duration_seconds = 1_801;
    assert!(world.provider.begin(&long).await.is_err());
    let mut rated = request(1);
    rated.expected_rate_version = Some("v1".to_owned());
    assert!(world.provider.begin(&rated).await.is_err());
    let mut bad = request(1);
    bad.offer_sdp = "o=nothing".to_owned();
    assert!(world.provider.begin(&bad).await.is_err());
    assert!(world.ledger.rows().expect("rows").is_empty());
    assert_eq!(world.provider.registry().state(), RegistryState::Idle);
    // No key: nothing is written.
    world.keys.set(None);
    let refusal = world.provider.begin(&request(1)).await.expect_err("no key");
    assert_eq!(refusal.code(), ErrorCode::HostNotConfigured);
    assert!(world.ledger.rows().expect("rows").is_empty());
    // A row from an earlier start blocks, and a closed one does not.
    world.keys.set(Some(KEY));
    let counter = AtomicU64::new(0);
    let _ = counter.fetch_add(1, Ordering::Relaxed);
    let _ = start(&world, 3).await.expect("an answer");
    world.provider.close("any").await.ok();
    let own = world.provider.begin(&request(4)).await;
    assert_eq!(own.expect_err("blocked").code(), ErrorCode::DraftConflict);
}

/// The lines of `source` that use the stand-in and sit in an item that does not carry exactly
/// `#[cfg(feature = "testing")]`. The item is the nearest enclosing one, found by indentation, and
/// its attributes are the ones directly above it: a `cfg(any(..))`, a `cfg_attr` and a `cfg(test)`
/// are not the gate.
fn ungated_stand_in_uses(source: &str) -> Vec<usize> {
    let lines: Vec<&str> = source.lines().collect();
    let indent = |line: &str| line.len() - line.trim_start().len();
    let starts_an_item = |line: &str| {
        let line = line.trim_start();
        let line = line.strip_prefix("pub(crate) ").unwrap_or(line);
        let line = line.strip_prefix("pub ").unwrap_or(line);
        let line = line.strip_prefix("async ").unwrap_or(line);
        [
            "fn ", "mod ", "impl", "static ", "const ", "use ", "struct ", "enum ",
        ]
        .iter()
        .any(|keyword| line.starts_with(keyword))
    };
    let mut found = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let code = line.split("//").next().unwrap_or_default();
        if !(code.contains("stand_in::") || code.contains("mod stand_in")) {
            continue;
        }
        let item = (0..=at)
            .rev()
            .find(|&before| {
                starts_an_item(lines[before])
                    && (before == at || indent(lines[before]) < indent(lines[at]))
            })
            .unwrap_or(at);
        let mut gated = false;
        let mut above = item;
        while above > 0 {
            above -= 1;
            let attribute = lines[above].trim();
            if attribute.starts_with("///") {
                continue;
            }
            if !attribute.starts_with("#[") {
                break;
            }
            if attribute == "#[cfg(feature = \"testing\")]" {
                gated = true;
            }
        }
        if !gated {
            found.push(at + 1);
        }
    }
    found
}

#[test]
fn the_working_path_is_compiled_only_under_the_testing_gate() {
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/src/services/");
    let product = std::fs::read_to_string(format!("{base}own_voice.rs")).expect("source");
    assert!(
        !product.contains("STAND_IN_MARKER"),
        "the marker is used by the stand-in alone"
    );
    assert_eq!(
        ungated_stand_in_uses(&product),
        Vec::<usize>::new(),
        "a use of the stand-in sits outside the testing gate"
    );
    let stand_in = std::fs::read_to_string(format!("{base}own_voice/stand_in.rs")).expect("source");
    assert!(stand_in.contains("black_box(STAND_IN_MARKER)"));
}

#[test]
fn the_gate_check_finds_a_use_whatever_cfg_surrounds_it() {
    let gated = "#[cfg(feature = \"testing\")]\nfn f() {\n    stand_in::X;\n}\n";
    assert!(ungated_stand_in_uses(gated).is_empty());
    for plant in [
        "fn f() {\n    stand_in::X;\n}\n",
        "#[cfg(any(feature = \"testing\", test))]\nfn f() {\n    stand_in::X;\n}\n",
        "#[cfg_attr(feature = \"testing\", allow(dead_code))]\nfn f() {\n    stand_in::X;\n}\n",
        "#[cfg(test)]\nfn f() {\n    stand_in::X;\n}\n",
        "#[cfg(not(feature = \"testing\"))]\npub mod stand_in;\n",
    ] {
        assert_eq!(ungated_stand_in_uses(plant).len(), 1, "{plant}");
    }
}

fn stored(world: &World, byte: u8, state: CallState, session: Option<&str>) {
    world.ledger.put(super::super::own_call::CallRow {
        call: NewCall {
            call_id: format!("call-{byte}"),
            attempt_id: format!("attempt-{byte}"),
            action_id: ActionId::new(Uuid::from_bytes([byte; 16])),
            device_id: "device-1".to_owned(),
            asked_ms: 1_000,
            closes_at_ms: 2_000,
        },
        state,
        provider_session_id: session.map(str::to_owned),
        provider_expires_ms: None,
        closed_ms: (state == CallState::Closed).then_some(1),
    });
}

#[tokio::test(start_paused = true)]
async fn a_removal_closes_each_stored_call_with_the_key_and_says_what_stands_afterwards() {
    // A call that OpenAI confirms closed is marked and deleted, and nothing stands.
    let world = fresh();
    stored(&world, 1, CallState::Open, Some("live_a"));
    stored(&world, 2, CallState::Closed, Some("live_b"));
    assert_eq!(
        world.provider.close_stored_calls().await,
        StoredCalls::NoneLeft
    );
    assert!(world.ledger.rows().expect("rows").is_empty());
    let hangups = world.stand_in.recorded().hangups;
    assert_eq!(hangups.len(), 1, "a closed row needs no request");
    assert_eq!(hangups[0], (KEY.to_owned(), "live_a".to_owned()));
    // A creation never learned has nothing to hang up, and the key stays.
    let world = fresh();
    stored(&world, 3, CallState::Creating, None);
    assert_eq!(
        world.provider.close_stored_calls().await,
        StoredCalls::OnlyCreating
    );
    assert!(world.stand_in.recorded().hangups.is_empty());
    // A hangup that is not confirmed leaves the call unresolved and the key kept.
    let world = fresh();
    stored(&world, 4, CallState::Open, Some("live_c"));
    world.stand_in.script_hangup(HangupScript::Lost);
    assert_eq!(
        world.provider.close_stored_calls().await,
        StoredCalls::NotConfirmed
    );
    assert_eq!(states(&world), [CallState::Unresolved]);
    // With no key held nothing is confirmed.
    let world = fresh();
    stored(&world, 5, CallState::Open, Some("live_d"));
    world.keys.set(None);
    assert_eq!(
        world.provider.close_stored_calls().await,
        StoredCalls::NotConfirmed
    );
    assert!(world.stand_in.recorded().hangups.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_reconcile_closes_stored_calls_that_no_live_call_owns_and_deletes_closed_rows_without_a_request()
 {
    let world = fresh();
    stored(&world, 1, CallState::Closed, Some("live_a"));
    stored(&world, 2, CallState::Open, Some("live_b"));
    stored(&world, 3, CallState::Creating, None);
    world.provider.reconcile().await;
    assert_eq!(states(&world), [CallState::Creating]);
    assert_eq!(world.stand_in.recorded().hangups.len(), 1);
    // An empty 404 is no closure: the call is unresolved, and the doctor names the command.
    let world = fresh();
    stored(&world, 4, CallState::Open, Some("live_c"));
    world
        .stand_in
        .script_hangup(HangupScript::Answer(404, Some(Vec::new())));
    world.provider.reconcile().await;
    assert_eq!(states(&world), [CallState::Unresolved]);
    // A mark that cannot be written keeps the row's earlier state.
    let world = fresh();
    stored(&world, 5, CallState::Open, Some("live_d"));
    world.ledger.failing("record_closed", true);
    world.provider.reconcile().await;
    assert_eq!(states(&world), [CallState::Open]);
}

#[tokio::test(start_paused = true)]
async fn a_reconcile_at_start_refuses_starts_while_it_runs_and_leaves_the_registry_idle_after() {
    let world = fresh();
    stored(&world, 1, CallState::Open, Some("live_a"));
    world.provider.reconcile_at_start().await;
    assert!(world.ledger.rows().expect("rows").is_empty());
    assert_eq!(world.provider.registry().state(), RegistryState::Idle);
    assert_eq!(world.stand_in.recorded().hangups.len(), 1);
    // A removal that holds the fence closes its own calls: the start pass does nothing then.
    let world = fresh();
    stored(&world, 2, CallState::Open, Some("live_b"));
    let fence = world.provider.registry().fence().expect("a fence");
    assert_eq!(fence.before, RegistryState::Idle);
    world.provider.reconcile_at_start().await;
    assert!(world.stand_in.recorded().hangups.is_empty());
    assert_eq!(world.provider.registry().state(), RegistryState::Settling);
    // While the fence stands, a start is told the approved sentence.
    let refusal = world
        .provider
        .begin(&request(3))
        .await
        .expect_err("a start during a settle");
    assert!(refusal.to_string().contains(words::SETTLING));
}

#[tokio::test(start_paused = true)]
async fn a_start_stays_open_until_its_caller_has_published_the_call() {
    let world = fresh();
    let own = started(&world).await;
    let provider = &world.provider;
    let begun = Instant::now();
    let publishing = async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        provider.start_published(&own.call_id);
    };
    let settling = async {
        let _fence = provider.registry().fence().expect("a fence");
        provider.settle().await
    };
    let (settled, ()) = tokio::join!(settling, publishing);
    assert_eq!(settled, Settled::NothingStarting);
    assert!(
        Instant::now() - begun >= Duration::from_secs(5),
        "the settle waited for the publication"
    );
}

#[tokio::test(start_paused = true)]
async fn a_late_session_a_fence_finds_keeps_its_id_and_its_row_when_the_hangup_is_not_confirmed() {
    let world = fresh();
    world.stand_in.script_create(CreateScript::After(
        Duration::from_secs(10),
        Box::new(CreateScript::Answer(201, Some(created_body("live_late")))),
    ));
    world.stand_in.script_hangup(HangupScript::Lost);
    let request = request(1);
    let attempt = world.provider.begin(&request).await.expect("begin");
    let provider = &world.provider;
    let dispatch = provider.dispatch(attempt, &request);
    let removal = async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let _fence = provider.registry().fence().expect("a fence");
        provider.settle().await
    };
    let (_, settled) = tokio::join!(dispatch, removal);
    assert_eq!(settled, Settled::MayStillRun);
    let rows = world.ledger.rows().expect("rows");
    assert_eq!(rows.len(), 1, "the late session keeps its row");
    assert_eq!(rows[0].state, CallState::Unresolved);
    assert_eq!(rows[0].provider_session_id.as_deref(), Some("live_late"));
    assert_eq!(
        provider.close_stored_calls().await,
        StoredCalls::NoneLeft,
        "a later removal closes it with the same key"
    );
}

#[tokio::test(start_paused = true)]
async fn a_fence_during_readiness_reports_what_the_hangup_came_to() {
    for (script, expected) in [
        (HangupScript::Lost, Settled::MayStillRun),
        (HangupScript::Answer(200, None), Settled::LateSessionClosed),
    ] {
        let world = fresh();
        world.stand_in.acknowledge(false);
        world.stand_in.script_hangup(script);
        let request = request(1);
        let attempt = world.provider.begin(&request).await.expect("begin");
        let provider = &world.provider;
        let dispatch = provider.dispatch(attempt, &request);
        let removal = async {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let _fence = provider.registry().fence().expect("a fence");
            provider.settle().await
        };
        let (outcome, settled) = tokio::join!(dispatch, removal);
        assert!(matches!(
            outcome.expect("an answer"),
            VoiceStart::Refused(_)
        ));
        assert_eq!(settled, expected);
    }
}

#[tokio::test(start_paused = true)]
async fn only_a_session_closed_the_profile_defines_closes_the_call() {
    let world = fresh();
    let own = started(&world).await;
    let control = world.provider.host_control(&own.call_id).expect("control");
    world.stand_in.event(&json!({ "type": "session.closed" }));
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        control.state(),
        SidebandState::Ready,
        "a bare type is not a closure"
    );
    assert_eq!(world.provider.unknown_events(&own.call_id), Some(1));
    world.stand_in.event(&json!({
        "type": "session.closed", "event_id": "e1", "reason": "expired",
        "session": { "id": "live_1", "model": "gpt-live-1", "status": "active", "expires_at": 1 },
        "usage": { "seconds": 3 },
    }));
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        control.state(),
        SidebandState::Closed(SidebandEnd::ProviderClosed)
    );
    assert!(world.stand_in.recorded().hangups.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_start_that_sent_nothing_or_was_refused_marks_its_row_closed_before_deleting_it() {
    let world = fresh();
    world.ledger.failing("delete", true);
    world
        .stand_in
        .script_create(CreateScript::Answer(401, None));
    let _ = start(&world, 1).await.expect("an answer");
    assert_eq!(
        states(&world),
        [CallState::Closed],
        "a closed row blocks nothing"
    );
    let request = request(2);
    let attempt = world
        .provider
        .begin(&request)
        .await
        .expect("a closed row blocks nothing");
    drop(attempt);
    assert_eq!(
        world.provider.registry().state(),
        RegistryState::Idle,
        "the abandoned attempt released the registry"
    );
}

#[tokio::test(start_paused = true)]
async fn a_slot_a_normal_end_leaves_is_not_told_by_a_later_settle() {
    let world = fresh();
    world.stand_in.script_create(CreateScript::Lost);
    let outcome = start(&world, 1).await.expect("an answer");
    assert!(matches!(outcome, VoiceStart::CreationUnknown { .. }));
    assert_eq!(
        world.provider.settle().await,
        Settled::NothingStarting,
        "the unanswered start left a row, and no slot for a removal to tell again"
    );
    assert_eq!(states(&world), [CallState::Creating]);
}
