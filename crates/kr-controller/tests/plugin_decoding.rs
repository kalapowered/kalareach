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
//! | KR-ACC-016 | a decoder that names another request, offers a decision the table does not map or one twice, offers none, writes a summary over the bound, declines, or traps makes no approval and no ledger entry, the terminal answers the request, and the binding's report names the kind and none of the component's words |
//! | KR-REQ-11.26 | a request answered natively while its decode is held is not interpreted afterwards; a request made in privacy mode marks the component's view as made in it whenever it is decoded; one binding's flood is refused past its share of the queue and counted |

#![cfg(unix)]

mod plugin_world;

use kr_protocol::gateway::{PendingResource, PendingState};
use kr_protocol::local::ControllerConnectionRole;
use kr_worker::broker::decoding::NotDecoded;
use plugin_world::observing::{
    Observing, Options, Spec, binding, digest, package, request, request_noting,
};
use plugin_world::until;

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
/// request it waits on. The component is not told to be registered first: the request waits for
/// the registration, which is what a session's first approval does.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_21_a_request_the_connector_leaves_to_its_component_becomes_the_approval_the_component_read()
 {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    let frame = request(7);
    world.send(&frame);
    let approval = until("the request to be read into an approval", || async {
        approval_for(&world, "7")
    })
    .await;
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
    world.send(&request(100));
    until("the honest request to be read", || async {
        approval_for(&world, "100")
    })
    .await;

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
    until("the next request to be read", || async {
        approval_for(&world, "22")
    })
    .await;
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
    let lane = world.broker().observation();
    world.send(&request(31));
    until("the request to be read", || async {
        approval_for(&world, "31")
    })
    .await;
    let view = lane.view(binding(1)).expect("the component has a view");
    assert!(!view.private_content, "{view:?}");

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

    until("the request made in privacy mode to be read", || async {
        approval_for(&world, "32")
    })
    .await;
    let view = lane.view(binding(1)).expect("the component has a view");
    assert!(
        view.private_content,
        "the component was handed a request made in privacy mode and its view is not marked: {view:?}"
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
    let queue = world.broker().decode_queue();
    let hold = queue.hold();
    for number in 41..=49 {
        world.send(&request(number));
    }
    world.until_reason(1, NotDecoded::QueueFull.words()).await;
    assert_eq!(queue.len(), 8);
    hold.release();

    for number in 41..=48 {
        until("a queued request to be read", || async {
            approval_for(&world, &number.to_string())
        })
        .await;
    }
    let refused = resource_for(&world, "49").expect("the refused request is recorded");
    assert!(!refused.interpretation_verified);
    assert!(
        world.reason(1).contains("1 request was not decoded"),
        "{}",
        world.reason(1)
    );
}
