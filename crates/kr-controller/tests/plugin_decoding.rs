//! A request the connector's table does not read alone is read by the component of the binding that
//! is trusted to decode it, and nothing the component says is believed.
//!
//! The same world as the observation suite: a real daemon, this test process as the worker it
//! started, a real plugin host started by the daemon, and real components. The upstream is the one
//! thing played, behind the production gateway transport; the native terminal on the other end reads
//! everything the worker forwards to it and answers the requests it is asked. Everything between
//! them is the product: the broker, the decode queue and the task that asks components, the link,
//! the plugin service protocol, and the engine that runs the component.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.21 | a request the upstream waits on is read by the binding's component into an approval whose summary is the component's and whose decisions carry the connector table's labels; the ledger names the decoding package and keeps the request's bytes; the component sent nothing |
//! | KR-REQ-06.07 | the component was given the request's own bytes under the provenance the broker recorded them with, and the identifier the upstream gave |
//! | KR-ACC-016 | a decoder that names another request, offers a decision the table does not map or one twice, offers none, writes a summary over the bound, declines, or traps makes no approval and no ledger entry, the terminal answers the request, and the binding's report names the kind and none of the component's words; a request that waits for its decode is not given to a component whose binding loses the trust to decode it meanwhile |
//! | KR-REQ-11.26 | a request answered natively while its decode is held is not interpreted afterwards; a request made in privacy mode marks the component's view as made in it whenever it is decoded; one binding's flood is refused past its share of the queue and counted |
//! | KR-REQ-11.21 and KR-REQ-11.33 | the answer to an approval a component read is the bytes that component encoded, written to the upstream once; an approval the connector's table read is answered with the table's bytes, and no component is asked to encode it |
//! | KR-REQ-11.33 | a native answer that comes while the component encodes wins, and the component's answer is not sent; the thread changing, the grant or the decoder's trust being withdrawn while it encodes each refuse the answer before the marker, and nothing is sent |
//! | KR-REQ-11.21 and KR-ACC-016 | bytes that name another request, the right one as another JSON type, a method, an error in place of a result or beside one, a member twice or a line break are refused by the core and nothing is sent; a component that traps, declines or never returns makes no answer, the terminal answers, and the third fault disables the binding |

#![cfg(unix)]

mod plugin_world;

use kr_protocol::broker::BrokerGrant;
use kr_protocol::envelope::Outcome;
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{PendingResource, PendingState};
use kr_protocol::local::ControllerConnectionRole;
use kr_worker::broker::decoding::NotDecoded;
use plugin_world::observing::{
    Observing, Options, Spec, binding, digest, instance, package, request, request_noting,
};
use plugin_world::{PATIENCE, until};

/// The recorded request the upstream gave `id`, whatever has become of it.
fn resource_for(world: &Observing, id: &str) -> Option<PendingResource> {
    world
        .broker()
        .pending_resources()
        .into_iter()
        .find(|resource| resource.request.upstream.as_str() == id)
}

/// The approval the request the upstream gave `id` has become, once it is one.
fn approval_for(world: &Observing, id: &str) -> Option<PendingResource> {
    resource_for(world, id).filter(|resource| resource.interpretation_verified)
}

/// Waits until the request the upstream gave `id` has become an approval, and says where the
/// request, the component and the binding's report stand when it never does.
async fn approved(world: &Observing, id: &str) -> PendingResource {
    let found = tokio::time::timeout(PATIENCE, async {
        loop {
            if let Some(approval) = approval_for(world, id) {
                return approval;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    match found {
        Ok(approval) => approval,
        Err(_) => panic!(
            "waited {PATIENCE:?} for request {id} to become an approval; the record has it as \
             {:?}; the component's account is {:?}; {}",
            resource_for(world, id)
                .map(|resource| (resource.state, resource.interpretation_verified)),
            world.raw_account(1).await,
            world.diagnostics(1)
        ),
    }
}

/// What the native terminal answers a request with.
fn answer(id: u64) -> serde_json::Value {
    serde_json::json!({ "id": id, "result": { "outcome": "allow" } })
}

/// Waits until the upstream has been written an answer to request `id`.
async fn until_answered(world: &Observing, id: u64) {
    let wanted = format!("\"id\":{id},\"result\"");
    until("the upstream to be written the answer", || async {
        world
            .written
            .lock()
            .expect("not poisoned")
            .iter()
            .any(|line| line.contains(&wanted))
            .then_some(())
    })
    .await;
}

/// KR-REQ-11.21 and KR-REQ-06.07: the component of the binding that is trusted to decode the
/// connector's approval request reads it, and the request becomes an approval a person can answer.
///
/// The binding's package ships the component and holds the decoding trust; the upstream sends a
/// request it waits on once the component is registered and ready: a request that finds its
/// component unavailable stays opaque, and the world's link is unavailable for the first moments
/// of the session, while the daemon learns of the worker.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_21_a_request_the_connector_leaves_to_its_component_becomes_the_approval_the_component_read()
 {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let frame = request(7);
    world.send(&frame);
    let approval = approved(&world, "7").await;
    assert_eq!(approval.state, PendingState::Pending);

    // The decoder is named, the request's bytes are kept whole, and the projection is the
    // component's summary over the table's decisions in the table's words.
    let entry = world
        .broker()
        .decoding(approval.resource_id)
        .expect("the ledger reads")
        .expect("the interpretation is recorded with its decoder");
    assert_eq!(entry.plugin_id, package());
    assert_eq!(entry.binding_id, binding(1));
    assert_eq!(
        entry.package_digest,
        kr_protocol::scalars::Digest256::from_bytes([5; 32]),
        "the hash the decoding package was installed under"
    );
    assert_eq!(
        Some(entry.source_generation.get()),
        world.broker().component_generation(binding(1)),
        "the generation of the source the decoder read is the instance's"
    );
    assert_eq!(
        entry.projection.schema_version,
        kr_worker::broker::connectors::component_schema()
    );
    assert!(
        entry.projection.summary.contains("a request of"),
        "{}",
        entry.projection.summary
    );
    let offered: Vec<(&str, &str)> = entry
        .projection
        .decisions
        .iter()
        .map(|decision| (decision.option_id.as_str(), decision.label.as_str()))
        .collect();
    assert_eq!(offered, [("allow", "Allow"), ("deny", "Deny")]);
    let sent = frame.to_string();
    assert_eq!(entry.source_bytes.as_slice(), sent.as_bytes());
    assert_eq!(
        entry.source_digest,
        kr_protocol::scalars::Digest256::from_bytes(kr_cbor::sha256(sent.as_bytes())),
        "the digest names the bytes the decoder read"
    );

    // The component was given the request as the broker recorded it, and decoded it once.
    let account = world.raw_account(1).await.expect("the component answers");
    let given = format!(
        "decode=1;encode=0;last=native_protocol/7/{}/{:016x}",
        sent.len(),
        digest(sent.as_bytes())
    );
    assert!(account.contains(&given), "{account} does not say {given}");
    // And sent nothing: nothing was written to the upstream, whose answer is the terminal's or
    // a person's to give.
    assert!(
        world.written.lock().expect("not poisoned").is_empty(),
        "the upstream was written {:?}",
        world.written.lock().expect("not poisoned")
    );
}

/// KR-ACC-016: a decoder that answers what it was not asked makes no approval, and the terminal
/// answers the request as it would have without it.
///
/// An honest request goes first, so that nothing being made below is the decoder's doing. Each of
/// the others sets the component to answer one wrong way. For each the record keeps the request as
/// the opaque request it was, the ledger holds no interpretation, the native terminal's answer
/// reaches the upstream, and the binding's report names the kind of the refusal and carries none of
/// the words the component chose.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_acc_016_a_decoder_that_answers_what_it_was_not_asked_makes_no_approval_and_the_terminal_answers_the_request()
 {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    world.send(&request(100));
    approved(&world, "100").await;

    let wrong = [
        ("!other-request", NotDecoded::OtherRequest),
        ("!unmapped", NotDecoded::UnmappedDecision),
        ("!duplicate", NotDecoded::DuplicateDecision),
        ("!no-decisions", NotDecoded::NoDecisions),
        ("!long-summary", NotDecoded::SummaryTooLong),
        ("!decline", NotDecoded::Declined),
        ("!trap", NotDecoded::Failed),
    ];
    for (number, (marker, kind)) in (101_u64..).zip(wrong) {
        world.send(&request_noting(number, marker));
        world.until_reason(1, kind.words()).await;
        let resource = until("the request to be recorded", || async {
            resource_for(&world, &number.to_string())
        })
        .await;
        assert!(
            !resource.interpretation_verified,
            "{marker} became an approval"
        );
        assert!(
            world
                .broker()
                .decoding(resource.resource_id)
                .expect("the ledger reads")
                .is_none(),
            "{marker} left a ledger entry"
        );
        world.terminal.write(&answer(number)).await;
        until_answered(&world, number).await;
    }

    // What the report carries of the component is counts and kinds. The identifiers and decisions
    // the component chose are not in it.
    let reason = world.reason(1);
    for chosen in ["another-request", "root-access"] {
        assert!(!reason.contains(chosen), "{reason}");
    }
    assert!(reason.contains("7 requests were not decoded"), "{reason}");
}

/// KR-ACC-016: a request that waits for its decode is not given to a component whose binding loses
/// the grant and the trust to decode it meanwhile, and the terminal's answer reaches the upstream
/// as it would have.
///
/// The task that asks components is held, the request is queued, the interpreter grant is
/// withdrawn, and the hold is released. The binding's report says why the request was refused, and
/// the component's account shows that it was never asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_acc_016_a_request_waiting_for_its_decode_is_not_given_to_a_component_whose_trust_was_withdrawn()
 {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let queue = world.broker().decode_queue();
    let hold = queue.hold();
    world.send(&request(61));
    until("the request to be queued for its decode", || async {
        (queue.len() == 1).then_some(())
    })
    .await;
    world
        .broker()
        .withdraw_grant(binding(1), BrokerGrant::ApprovalInterpreter)
        .expect("the grant is withdrawn");
    hold.release();

    world.until_reason(1, NotDecoded::Refused.words()).await;
    let account = world.raw_account(1).await.expect("the component answers");
    assert!(
        account.starts_with("decode=0;"),
        "the component was given a request after its trust was withdrawn: {account}"
    );
    let resource = resource_for(&world, "61").expect("the request is recorded");
    assert!(!resource.interpretation_verified);
    world.terminal.write(&answer(61)).await;
    until_answered(&world, 61).await;
}

/// KR-REQ-11.26: a request that the terminal answered while its decode was held is not interpreted
/// afterwards, and the native path went on.
///
/// The task that asks components is held, the upstream's request is recorded and queued, and the
/// native terminal answers it. When the hold is released the decode finds a request that is no
/// longer pending and asks nobody; the next request is decoded after it, so that the first has been
/// dealt with by then.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_26_a_request_answered_natively_while_its_decode_is_held_is_not_interpreted_afterwards()
 {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let queue = world.broker().decode_queue();
    let hold = queue.hold();
    world.send(&request(21));
    until("the request to be queued for its decode", || async {
        (queue.len() == 1).then_some(())
    })
    .await;

    world.terminal.write(&answer(21)).await;
    until_answered(&world, 21).await;
    hold.release();

    world.send(&request(22));
    approved(&world, "22").await;
    let first = resource_for(&world, "21").expect("the first request is recorded");
    assert!(!first.interpretation_verified);
    assert_ne!(first.state, PendingState::Pending, "{first:?}");
    assert!(
        world
            .broker()
            .decoding(first.resource_id)
            .expect("the ledger reads")
            .is_none()
    );
    let account = world.raw_account(1).await.expect("the component answers");
    assert!(
        account.contains("decode=1;"),
        "the component was asked about the answered request: {account}"
    );
}

/// KR-REQ-24.27 and KR-REQ-11.26: what a component is handed of a request made in privacy mode is
/// made in it, however long the request waited and whatever privacy mode is when it is decoded.
///
/// A request made outside privacy mode marks nothing. A request recorded in it, whose decode is
/// held until privacy mode has ended, marks the component's view as holding content made in it,
/// which is what keeps its state from being taken afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_27_a_request_made_in_privacy_mode_marks_the_component_whenever_it_is_decoded() {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    world.send(&request(31));
    approved(&world, "31").await;
    assert!(!lane.is_marked(binding(1)));

    let queue = world.broker().decode_queue();
    let hold = queue.hold();
    let mut authority = world
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;
    world.tell_privacy(&mut authority, 1, true).await;
    world.send(&request(32));
    until("the request to be queued for its decode", || async {
        (queue.len() == 1).then_some(())
    })
    .await;
    world.tell_privacy(&mut authority, 2, false).await;
    assert!(!lane.is_private());
    hold.release();

    approved(&world, "32").await;
    assert!(
        lane.is_marked(binding(1)),
        "the component was handed a request made in privacy mode and is not marked"
    );
}

/// KR-REQ-11.26: one binding's flood costs the others no more than its share of the queue, and
/// what is refused is counted where a person reads it.
///
/// The task that asks components is held and nine requests arrive for one binding. Eight are
/// queued and the ninth is refused and counted; when the hold is released the eight are decoded and
/// the ninth stays the opaque request it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_26_a_binding_has_a_share_of_the_decode_queue_and_a_request_past_it_is_counted() {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let queue = world.broker().decode_queue();
    let hold = queue.hold();
    for number in 41..=49 {
        world.send(&request(number));
    }
    world.until_reason(1, NotDecoded::QueueFull.words()).await;
    assert_eq!(queue.len(), 8);
    hold.release();

    for number in 41..=48 {
        approved(&world, &number.to_string()).await;
    }
    let refused = resource_for(&world, "49").expect("the refused request is recorded");
    assert!(!refused.interpretation_verified);
    assert!(
        world.reason(1).contains("1 request was not decoded"),
        "{}",
        world.reason(1)
    );
}

/// The lines the upstream was written that answer request `id`.
fn answers_to(world: &Observing, id: u64) -> Vec<String> {
    let wanted = format!("\"id\":{id},\"result\"");
    world
        .written
        .lock()
        .expect("not poisoned")
        .iter()
        .filter(|line| line.contains(&wanted))
        .cloned()
        .collect()
}

/// KR-REQ-11.21 and KR-REQ-11.33: the answer to an approval a component read is the bytes that
/// component encoded, and the upstream is written them once.
///
/// The component marks what it writes, so the case tells its bytes from the connector table's. It is
/// asked once to decode and once to encode.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_33_an_approval_a_component_read_is_answered_with_the_bytes_that_component_encoded()
 {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    world.send(&request_noting(7, "!answer"));
    let approval = approved(&world, "7").await;
    let mut owner = world.owner().await;
    let outcome = world
        .respond(&mut owner, approval.resource_id, "allow")
        .await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");

    until_answered(&world, 7).await;
    let answers = answers_to(&world, 7);
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert!(
        answers[0].contains(r#""via":"component""#),
        "the upstream was written the table's answer and not the component's: {}",
        answers[0]
    );
    let account = world.raw_account(1).await.expect("the component answers");
    assert!(
        account.starts_with("decode=1;encode=1;"),
        "the component was asked once to decode and once to encode: {account}"
    );
}

/// KR-REQ-11.21: an approval the connector's table read is answered with the table's bytes, and the
/// plugin host is not asked to encode it, though another package's binding on the instance ships a
/// component that could.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_21_an_approval_the_table_read_is_answered_with_the_tables_bytes_and_no_encode_is_made()
 {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::interpreter(1),
        Spec::decoder(2, "hostile-decoder").of_another_package(),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(2).await;
    world.send(&request_noting(8, "!answer"));
    let approval = approved(&world, "8").await;
    let mut owner = world.owner().await;
    let outcome = world
        .respond(&mut owner, approval.resource_id, "allow")
        .await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");

    until_answered(&world, 8).await;
    assert_eq!(
        answers_to(&world, 8),
        [r#"{"id":8,"result":{"outcome":"allow"}}"#]
    );
    let account = world.raw_account(2).await.expect("the component answers");
    assert!(
        account.starts_with("decode=0;encode=0;"),
        "no component was asked about a request the table read: {account}"
    );
}

/// Asks `world` to answer request `id` with its component's bytes, runs `disturb` while the
/// encoding is held after the component has replied, and returns what the answer came to.
async fn answered_while(
    world: &Observing,
    id: u64,
    disturb: impl AsyncFnOnce(&Observing, &PendingResource),
) -> Outcome {
    world.send(&request_noting(id, "!answer"));
    let approval = approved(world, &id.to_string()).await;
    let hold = world.broker().component_calls().hold_encodings();
    let mut owner = world.owner().await;
    let responding = world.respond(&mut owner, approval.resource_id, "allow");
    let disturbing = async {
        until("the encoding to be held", || async {
            hold.parked().then_some(())
        })
        .await;
        disturb(world, &approval).await;
        hold.release();
    };
    let (outcome, ()) = tokio::join!(responding, disturbing);
    outcome
}

/// What a failed call says it failed with.
fn failed_with(outcome: &Outcome) -> ErrorCode {
    match outcome {
        Outcome::Error(error) => error.code,
        Outcome::Ok(_) => panic!("the answer was accepted"),
    }
}

/// KR-REQ-11.33: a native answer that arrives while the component encodes wins. The request is
/// resolved by it, the component's answer is refused as the answer to a resolved request, and the
/// upstream is written one answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_33_a_native_answer_that_comes_while_the_component_encodes_wins() {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let outcome = answered_while(&world, 30, async |world, _| {
        world.terminal.write(&answer(30)).await;
        until_answered(world, 30).await;
        until("the request to be resolved", || async {
            resource_for(world, "30").filter(|resource| resource.state == PendingState::Resolved)
        })
        .await;
    })
    .await;
    assert_eq!(failed_with(&outcome), ErrorCode::QuestionResolved);
    let answers = answers_to(&world, 30);
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert!(
        !answers[0].contains("via"),
        "the one answer upstream is the terminal's: {}",
        answers[0]
    );
}

/// KR-REQ-11.33: the conversation the terminal is in changing while the component encodes leaves the
/// answer unsent. The answer was written for a request of the conversation that has been left.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_33_a_thread_that_changes_while_the_component_encodes_leaves_the_answer_unsent() {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let outcome = answered_while(&world, 31, async |world, _| {
        world
            .broker()
            .advance_binding(
                instance(),
                Some(kr_protocol::ids::AgentThreadId::new("thread-2").expect("a thread")),
                kr_protocol::scalars::TimestampMs::new(9),
            )
            .expect("the terminal selects another conversation");
    })
    .await;
    failed_with(&outcome);
    assert!(answers_to(&world, 31).is_empty());
}

/// KR-REQ-11.33: the grant to interpret approvals being withdrawn while the component encodes
/// leaves the answer unsent, and the terminal answers the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_33_a_grant_withdrawn_while_the_component_encodes_leaves_the_answer_unsent() {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let outcome = answered_while(&world, 32, async |world, _| {
        world
            .broker()
            .withdraw_grant(binding(1), BrokerGrant::ApprovalInterpreter)
            .expect("the grant is withdrawn");
    })
    .await;
    failed_with(&outcome);
    assert!(answers_to(&world, 32).is_empty());
    world.terminal.write(&answer(32)).await;
    until_answered(&world, 32).await;
}

/// KR-REQ-11.33: the decoder's trust to answer being withdrawn while the component encodes leaves
/// the answer unsent, and the terminal answers the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_33_a_trust_withdrawn_while_the_component_encodes_leaves_the_answer_unsent() {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let outcome = answered_while(&world, 33, async |world, _| {
        world
            .broker()
            .withdraw_answering(binding(1))
            .expect("the trust to answer is withdrawn");
    })
    .await;
    failed_with(&outcome);
    assert!(answers_to(&world, 33).is_empty());
    world.terminal.write(&answer(33)).await;
    until_answered(&world, 33).await;
}

/// KR-REQ-11.21: bytes a component returns are data, and become an answer only if they are one. Each
/// of these is refused by the core with nothing sent: an answer to another request, to the right
/// one with its identifier as another JSON type, one that is a request, one that is an error, one
/// that is both a result and an error, one that names a member twice and one that holds a line
/// break. The request stays the opaque one it was, the terminal answers it, and the binding's
/// report says only that the bytes were not an answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_21_bytes_that_are_not_an_answer_to_the_request_are_refused_and_nothing_is_sent()
{
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let mut owner = world.owner().await;
    let spoilt = [
        "!answer-other-id",
        "!answer-retyped-id",
        "!answer-method",
        "!answer-error",
        "!answer-both",
        "!answer-twice",
        "!answer-newline",
    ];
    for (number, marker) in (50_u64..).zip(spoilt) {
        world.send(&request_noting(number, marker));
        let approval = approved(&world, &number.to_string()).await;
        let outcome = world
            .respond(&mut owner, approval.resource_id, "allow")
            .await;
        failed_with(&outcome);
        assert!(
            answers_to(&world, number).is_empty(),
            "{marker} was sent: {:?}",
            answers_to(&world, number)
        );
        world.terminal.write(&answer(number)).await;
        until_answered(&world, number).await;
    }
    let reason = world.reason(1);
    assert!(
        reason.contains(kr_worker::broker::encode::NotEncoded::NotAnAnswer.words()),
        "{reason}"
    );
    assert!(reason.contains("7 answers were not written"), "{reason}");

    // The same request, answered by a component that returns a true answer, is sent.
    world.send(&request_noting(60, "!answer"));
    let approval = approved(&world, "60").await;
    let outcome = world
        .respond(&mut owner, approval.resource_id, "allow")
        .await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
}

/// KR-REQ-11.21 and KR-ACC-016: a component that traps, declines or never returns writes no
/// answer. Nothing is sent, the terminal answers the request, and the third fault within a minute
/// disables the binding. A fault the component declares itself is not one of the three.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_acc_016_a_component_that_faults_while_it_encodes_writes_no_answer_and_is_disabled_at_the_third()
 {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let mut owner = world.owner().await;
    for (number, marker) in (70_u64..).zip([
        "!encode-decline",
        "!encode-trap",
        "!encode-spin",
        "!encode-trap",
    ]) {
        world.send(&request_noting(number, marker));
        let approval = approved(&world, &number.to_string()).await;
        let outcome = world
            .respond(&mut owner, approval.resource_id, "allow")
            .await;
        failed_with(&outcome);
        assert!(
            answers_to(&world, number).is_empty(),
            "{marker} sent an answer"
        );
        world.terminal.write(&answer(number)).await;
        until_answered(&world, number).await;
    }
    until("the third fault to disable the binding", || async {
        (world.report(1)?.state == kr_protocol::admission::ComponentState::Disabled).then_some(())
    })
    .await;
}

/// KR-REQ-11.21 and KR-REQ-11.33: the action a package declares to answer an approval is answered
/// by the component that read the request, as the approval method is. The upstream is written the
/// component's bytes once, and a native answer that comes while the component encodes wins here
/// too.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_33_the_action_that_answers_an_approval_is_answered_by_the_component_that_read_it()
 {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::decoder(1, "hostile-decoder").answering(),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    let mut owner = world.owner().await;

    world.send(&request_noting(80, "!answer"));
    let approval = approved(&world, "80").await;
    let outcome = world
        .invoke_answer(&mut owner, approval.resource_id, "allow")
        .await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
    until_answered(&world, 80).await;
    let answers = answers_to(&world, 80);
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert!(
        answers[0].contains(r#""via":"component""#),
        "{}",
        answers[0]
    );

    world.send(&request_noting(81, "!answer"));
    let approval = approved(&world, "81").await;
    let hold = world.broker().component_calls().hold_encodings();
    let responding = world.invoke_answer(&mut owner, approval.resource_id, "allow");
    let natively = async {
        until("the encoding to be held", || async {
            hold.parked().then_some(())
        })
        .await;
        world.terminal.write(&answer(81)).await;
        until_answered(&world, 81).await;
        until("the request to be resolved", || async {
            resource_for(&world, "81").filter(|resource| resource.state == PendingState::Resolved)
        })
        .await;
        hold.release();
    };
    let (outcome, ()) = tokio::join!(responding, natively);
    assert_eq!(failed_with(&outcome), ErrorCode::QuestionResolved);
    let answers = answers_to(&world, 81);
    assert_eq!(answers.len(), 1, "{answers:?}");
    assert!(!answers[0].contains("via"), "{}", answers[0]);
}

/// KR-REQ-11.25: a binding that holds no trust to decode reads no request into an approval,
/// whatever component it ships. The request stays the opaque one it was, the rich answer to it is
/// refused, the component is not asked and the binding's report counts nothing as not decoded, and
/// the terminal answers the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_25_a_binding_without_decoding_trust_reads_no_request_and_the_rich_answer_is_refused()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::observer(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    world.send(&request(95));
    let recorded = until("the request to be recorded", || async {
        resource_for(&world, "95")
    })
    .await;
    // The upstream's frames are read in order, so the terminal's round trip is answered after the
    // request has been recorded and given to whoever decodes it.
    world.terminal.round_trip(96).await;
    assert!(
        !resource_for(&world, "95")
            .expect("the request is recorded")
            .interpretation_verified
    );
    let mut owner = world.owner().await;
    let outcome = world
        .respond(&mut owner, recorded.resource_id, "allow")
        .await;
    failed_with(&outcome);
    assert!(answers_to(&world, 95).is_empty());
    assert!(
        !world.reason(1).contains("not decoded"),
        "no request was given to the component: {}",
        world.reason(1)
    );
    world.terminal.write(&answer(95)).await;
    until_answered(&world, 95).await;
}

/// KR-REQ-11.26: a request whose conversation changed while it waited for its decode is not given
/// to the component: it was made in a generation the instance has left. The request made after the
/// change is decoded.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_26_a_request_of_a_generation_the_instance_has_left_is_not_given_to_the_component()
 {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let queue = world.broker().decode_queue();
    let hold = queue.hold();
    world.send(&request(97));
    until("the request to be queued for its decode", || async {
        (queue.len() == 1).then_some(())
    })
    .await;
    world
        .broker()
        .advance_binding(
            instance(),
            Some(kr_protocol::ids::AgentThreadId::new("thread-3").expect("a thread")),
            kr_protocol::scalars::TimestampMs::new(9),
        )
        .expect("the terminal selects another conversation");
    hold.release();

    world.send(&request(98));
    approved(&world, "98").await;
    assert!(
        resource_for(&world, "97").is_none_or(|resource| !resource.interpretation_verified),
        "a request of the conversation that was left became an approval"
    );
    let account = world.raw_account(1).await.expect("the component answers");
    assert!(
        account.starts_with("decode=1;"),
        "the component was given the request of the conversation that was left: {account}"
    );
}
