//! Sharing a session from the companion, and accepting a share on a device it is shared with,
//! called the way the page calls it.
//!
//! The daemon is kr-controller's in-process host with its test support included by path. The
//! person's computer is this crate's backend on the mock runtime, connected to the daemon's own
//! socket; the device the session is shared with is a second backend on a paired connection of its
//! own. What a test puts of its own between a backend and the daemon is a transport that loses what
//! the host answers to one mutation, or the mutation before it leaves: the daemon, its store and
//! its answers are the product's.
//!
//! Each case carries, in a comment of its own, the requirement rows its assertions show.

#![cfg(unix)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

include!("support/sharing_harness.rs");

/// The ceremony of an owner device, whose person confirms or does not as the test says.
struct Person {
    confirms: AtomicBool,
}

impl kr_client::pairing::owner::Ceremony for Person {
    fn kind(&self) -> kr_client::pairing::owner::CeremonyKind {
        kr_client::pairing::owner::CeremonyKind::TouchId
    }

    fn verify<'a>(
        &'a self,
        _reason: &'a str,
        _within: Duration,
    ) -> kr_client::pairing::BoxFuture<'a, kr_client::pairing::owner::CeremonyOutcome> {
        let confirmed = self.confirms.load(Ordering::SeqCst);
        Box::pin(async move {
            if confirmed {
                kr_client::pairing::owner::CeremonyOutcome::Confirmed
            } else {
                kr_client::pairing::owner::CeremonyOutcome::NotConfirmed
            }
        })
    }
}

/// The companion of the person who owns the scene's host, as a second computer of theirs: it lists
/// what the host holds open for its owner devices and answers through `person`.
fn owner_companion(
    scene: &Scene,
    data: &std::path::Path,
    person: &Arc<Person>,
) -> support::Companion {
    let secrets: Arc<dyn kr_crypto::store::SecretStore> =
        Arc::new(kr_crypto::store::MemoryStore::new());
    kr_crypto::store::store_device_keys(&*secrets, "device", &scene.owner)
        .expect("the owner's keys are kept");
    let companion = support::Companion::start(
        data,
        support::parts(secrets, Arc::new(scene.host.room.clone())),
        Arc::clone(person) as Arc<dyn kr_client::pairing::owner::Ceremony>,
        support::StubIntake::holding("", false),
    );
    support::record_owned(&companion.device(), &scene.host, "the test host");
    companion
}

/// KR-REQ-18.12, KR-REQ-18.13: the owner's invitation, naming a device and a role, its acceptance
/// and its withdrawal reach the page as the methods' own results, in shapes the protocol defines,
/// and the device sees only what the host tells it. An invitation the host answers at once leaves
/// no record behind. The person's computer issues and the device holds, and neither does the
/// other's part.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_typed_result_reaches_the_page_and_a_share_is_accepted_and_taken_back() {
    let scene = Scene::start().await;

    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("the invitation is issued");
    assert_eq!(made["attempt"]["phase"], "closed");
    assert_eq!(made["attempt"]["outcome"], "happened");
    let created: GrantCreateResult = typed(&made["value"]);
    assert_eq!(created.grant.recipient_device_id, scene.record.device_id);
    assert!(created.preview.single_use);
    assert!(
        scene.issuer.attempts().await.is_empty(),
        "an answer the host gave at once leaves no record"
    );
    assert_eq!(
        scene
            .issuer
            .state()
            .connection()
            .expect("connected")
            .session()
            .submitted_actions()
            .await
            .len(),
        0,
        "and the action is settled in the connection's book"
    );

    // The device is told what it is offered, and nothing of the text its issuer was shown.
    let held = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    let offers: GrantHeldResult = typed(&json!({
        "offers": held["offers"], "offers_more": false,
        "shares": held["shares"], "shares_more": false,
    }));
    assert_eq!(offers.offers.len(), 1);
    assert_eq!(
        offers.offers[0].invitation_id,
        created.preview.invitation_id
    );
    assert!(offers.shares.is_empty());

    let accepted = scene
        .phone
        .call(
            "grant_redeem",
            json!({ "params": serde_json::to_value(&GrantRedeemParams {
                invitation_id: created.preview.invitation_id,
            }).expect("encodes") }),
        )
        .await
        .expect("the invitation is accepted");
    assert_eq!(accepted["attempt"]["outcome"], "happened");
    let redeemed: GrantRedeemResult = typed(&accepted["value"]);
    assert_eq!(redeemed.grant.grant_id, created.grant.grant_id);
    let held = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    assert_eq!(held["offers"].as_array().expect("offers").len(), 0);
    assert_eq!(held["shares"].as_array().expect("shares").len(), 1);

    let revoked = scene
        .issuer
        .call(
            "grant_revoke",
            json!({ "params": serde_json::to_value(&GrantRevokeParams {
                grant_id: created.grant.grant_id,
            }).expect("encodes") }),
        )
        .await
        .expect("the share is taken back");
    let result: RevocationResult = typed(&revoked["value"]);
    assert!(result.barrier.holds(), "no worker owes a fence here");
    let held = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    assert_eq!(held["shares"].as_array().expect("shares").len(), 0);

    // Each side does its own part and not the other's.
    let refused = scene
        .phone
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect_err("a device it is paired with does not issue from here");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED", "{refused}");
    let refused = scene
        .issuer
        .call("grant_held", json!({}))
        .await
        .expect_err("the host's own computer holds no share of it");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED", "{refused}");
    scene.stop().await;
}

/// The host's answer to an invitation is lost, and the application, which kept the request before
/// it sent it, asks the host again with the same request on a connection opened for it. The host
/// answers from the record it kept, so the invitation exists once, and the page reads the host's
/// own result from the attempt. The record stays until the page removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_reply_is_asked_about_again_and_answered_from_the_hosts_record() {
    let scene = Scene::start().await;
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);

    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("the application answers though the host's answer was lost");
    assert_ne!(
        sent["attempt"]["phase"], "closed",
        "the answer was lost, so nothing is known yet"
    );
    assert_eq!(sent["value"], Value::Null);

    let done = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(done["outcome"], "happened");
    let created: GrantCreateResult = typed(&done["result"]);
    assert_eq!(created.grant.recipient_device_id, scene.record.device_id);
    let listed = scene.listed().await;
    assert_eq!(
        listed.grants.len(),
        1,
        "the host performed it once, however often it was asked"
    );
    assert_eq!(listed.grants[0].grant.grant_id, created.grant.grant_id);

    // The grant the application would have looked for is the one the host wrote.
    let uid = scene
        .issuer
        .state()
        .connection()
        .expect("connected")
        .actor()
        .expect("an actor");
    let (grant_id, _) = share_identities(&uid, uuid_of(&done["action_id"]));
    assert_eq!(grant_id, created.grant.grant_id);

    scene
        .issuer
        .call(
            "attempt_remove",
            json!({ "actionId": done["action_id"].as_str().expect("an action") }),
        )
        .await
        .expect("the record is removed once the page has read it");
    assert!(scene.issuer.attempts().await.is_empty());
    assert_eq!(
        scene
            .issuer
            .state()
            .connection()
            .expect("connected")
            .session()
            .submitted_actions()
            .await
            .len(),
        0,
        "the lost action is settled in the book once the attempt is over"
    );
    scene.stop().await;
}

fn uuid_of(value: &Value) -> kr_protocol::scalars::Uuid {
    value
        .as_str()
        .expect("a uuid")
        .parse::<kr_protocol::ids::ActionId>()
        .expect("an action identifier")
        .get()
}

/// KR-REQ-18.13: the device's acceptance is committed by the host and its answer is lost; the
/// application finds it accepted by asking again, and the share is held once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_accepted_invitation_whose_reply_was_lost_is_found_accepted() {
    let mut scene = Scene::start().await;
    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("issued");
    let created: GrantCreateResult = typed(&made["value"]);
    scene.phone_faults.answer.store(true, Ordering::SeqCst);

    let sent = scene
        .phone
        .call(
            "grant_redeem",
            json!({ "params": serde_json::to_value(&GrantRedeemParams {
                invitation_id: created.preview.invitation_id,
            }).expect("encodes") }),
        )
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");

    let done = scene
        .phone
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(done["outcome"], "happened");
    let redeemed: GrantRedeemResult = typed(&done["result"]);
    assert_eq!(redeemed.grant.grant_id, created.grant.grant_id);
    // The connection that lost the answer is gone, and the application takes one up again.
    scene.reconnect_phone().await;
    let held = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    assert_eq!(held["shares"].as_array().expect("shares").len(), 1);
    scene.stop().await;
}

/// KR-REQ-23.49: the application is stopped after the host committed and before the answer
/// arrived. Started again, it reads the attempt back from what it kept, shows it as unfinished and
/// sends nothing by itself; *Ask the host* is the person's choice, and it is answered from the host's
/// record. That holds for each of the four actions.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_application_restarted_after_the_host_committed_asks_the_host_and_is_answered() {
    let mut scene = Scene::start().await;

    // An invitation.
    scene.issuer.state().shares().pace_at(FOR_A_WHILE);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1, "the attempt is read back");
    assert_eq!(back[0]["action_id"], action.as_str());
    assert_eq!(back[0]["kind"], "invite");
    assert_ne!(back[0]["phase"], "closed");
    assert_eq!(
        scene.listed().await.grants.len(),
        1,
        "the host committed it"
    );
    let asked = scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("the host answers from its record");
    let created: GrantCreateResult = typed(&asked["value"]);
    assert!(
        scene.issuer.attempts().await.is_empty(),
        "the result is the page's, so there is no record of it"
    );
    assert_eq!(scene.listed().await.grants.len(), 1);

    // Its acceptance, on the device.
    scene.phone.state().shares().pace_at(FOR_A_WHILE);
    scene.phone_faults.answer.store(true, Ordering::SeqCst);
    let sent = scene
        .phone
        .call(
            "grant_redeem",
            json!({ "params": serde_json::to_value(&GrantRedeemParams {
                invitation_id: created.preview.invitation_id,
            }).expect("encodes") }),
        )
        .await
        .expect("answered");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    scene.restart_phone().await;
    let back = scene.phone.attempts().await;
    assert_eq!(back.len(), 1);
    assert_eq!(back[0]["kind"], "redeem");
    let asked = scene
        .phone
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("answered from the host's record");
    let redeemed: GrantRedeemResult = typed(&asked["value"]);
    assert_eq!(redeemed.grant.grant_id, created.grant.grant_id);

    // Its withdrawal.
    scene.issuer.state().shares().pace_at(FOR_A_WHILE);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call(
            "grant_revoke",
            json!({ "params": serde_json::to_value(&GrantRevokeParams {
                grant_id: created.grant.grant_id,
            }).expect("encodes") }),
        )
        .await
        .expect("answered");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1);
    assert_eq!(back[0]["kind"], "revoke");
    let asked = scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("answered from the host's record");
    let revoked: RevocationResult = typed(&asked["value"]);
    assert!(revoked.barrier.holds());
    assert!(
        scene
            .listed()
            .await
            .grants
            .iter()
            .any(|summary| summary.grant.grant_id == created.grant.grant_id
                && summary.state == GrantState::Revoked)
    );
    scene.stop().await;
}

/// KR-REQ-23.49: a second invitation of the same session to the same device is not started while
/// the first can still happen, whatever the person did to the row: hiding it takes it out of view
/// and releases nothing, and a restart keeps it. The host performed the first once, and the person
/// who asks about it gets its result.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_invitation_is_not_started_while_the_first_can_still_happen() {
    let mut scene = Scene::start().await;
    scene.issuer.state().shares().pace_at(FOR_A_WHILE);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    let first = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    let action = first["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    scene.reconnect_issuer().await;

    let refused = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect_err("the first can still happen");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED", "{refused}");
    assert_eq!(
        scene.listed().await.grants.len(),
        1,
        "and nothing else was written"
    );

    let hidden = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect("hidden");
    assert_eq!(hidden["hidden"], true);
    let refused = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect_err("hiding it releases nothing");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED");

    scene.restart_issuer().await;
    let refused = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect_err("a restart keeps the gate");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED");

    // A record that can still happen is not removed either.
    let kept = scene
        .issuer
        .call("attempt_remove", json!({ "actionId": action }))
        .await
        .expect_err("it can still happen");
    assert_eq!(code_of(&kept), "PERMISSION_DENIED");

    // The host's answer closes it, and a closed attempt gates nothing.
    scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("answered");
    let again = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Controller))
        .await;
    assert!(again.is_ok(), "{again:?}");
    scene.stop().await;
}

/// KR-REQ-23.49: an action the host never saw is not reported as not done before the bound the
/// window sets has passed, however often the host is asked and however often a read finds nothing;
/// after it, the application says it did not happen as far as the host shows, and nothing is
/// written.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_action_the_host_never_saw_is_not_done_only_after_the_bound() {
    let scene = Scene::start().await;
    scene.issuer_faults.request.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();

    // It is asked about, finds nothing, and keeps reading: the host's window for it has not ended.
    let checking = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "checking")
        .await;
    assert_eq!(checking["action_id"], action.as_str());
    tokio::time::sleep(Duration::from_millis(400)).await;
    let still = scene.issuer.attempts().await;
    assert_eq!(still.len(), 1);
    assert_eq!(
        still[0]["phase"], "checking",
        "an absent grant proves nothing before the bound: {still:?}"
    );
    assert!(still[0]["can_happen_until_ms"].is_string());

    // The clock that counts the bound passes it.
    scene
        .issuer
        .state()
        .shares()
        .advance(Duration::from_secs(3600));
    let closed = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(closed["outcome"], "not_done");
    assert_eq!(closed["result"], Value::Null);
    assert!(
        scene.listed().await.grants.is_empty(),
        "and nothing was written"
    );
    scene.stop().await;
}

/// KR-REQ-18.15: handing a session over asks an owner device to confirm exactly the plan the host
/// describes, and the transfer is sent only after it answered. The giving device loses the session,
/// the receiving device holds it, and the page is answered with the host's result. Cancelling
/// before the owner answers sends nothing, and a reference is spent by the one transfer it sends.
/// KR-REQ-02.09, the application's half: the application that hands a session over, which enlarges
/// what another device holds, asks an owner device for its confirmation first and sends the
/// transfer to the host only with that answer; the host's own refusal without it is shown by the
/// daemon's cases.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_asks_an_owner_device_and_sends_only_what_it_confirmed() {
    use kr_protocol::confirmation::{ConfirmationDisplay, TransferControlPlan};
    use net_support::pairing as calls;

    let scene = Scene::start().await;
    // The device holds the session as an owner of it, and another device is to receive it.
    let (_share, giving) =
        owned_by(&scene.host, scene.session_id, &scene.device, &scene.record).await;
    let (_taker, taker_record) = recipient(&scene.host, &scene.owner).await;
    let held: GrantListResult = scene.listed().await;
    let from = held
        .grants
        .iter()
        .find(|summary| summary.state == GrantState::Active)
        .expect("the device's share")
        .grant
        .grant_id;
    let params = GrantTransferParams {
        session_id: scene.session_id,
        from_grant_id: from,
        to_device_id: taker_record.device_id,
    };
    let body = json!({
        "params": serde_json::to_value(&params).expect("encodes"),
        "subject": { "sessionId": scene.session_id.to_string(), "sessionEpoch": "1" },
    });

    let asked = scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect("the owner devices are asked");
    let reference = asked["reference"].as_str().expect("a reference").to_owned();
    assert_eq!(asked["attempt"]["phase"], "asking");
    let waiting = scene
        .issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await
        .expect("read");
    assert_eq!(waiting["state"], "waiting");
    assert_eq!(
        waiting["plan"]["to_device_name"], asked["to_device_name"],
        "the plan the host describes is the sheet's"
    );
    let early = scene
        .issuer
        .call("transfer_finish", json!({ "reference": reference }))
        .await
        .expect_err("nothing is sent before an owner device answered");
    assert_eq!(code_of(&early), "OWNER_CONFIRMATION_REQUIRED", "{early}");
    let still_waiting = scene
        .issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await;
    assert_eq!(
        still_waiting.map(|answer| answer["state"].clone()).ok(),
        Some(json!("waiting")),
        "the early finish sent nothing, so the hand-over still waits for its answer"
    );
    assert_eq!(
        scene.listed().await.grants.len(),
        1,
        "and nothing was written"
    );

    // The plan the host holds open for the owner devices.
    let mut client = scene.host.client().await;
    let pending = calls::pending(&mut client).await.expect("readable").pending;
    assert_eq!(pending.len(), 1);
    let ConfirmationDisplay::TransferControl(plan) = &pending[0].display else {
        panic!("the owner device is shown a transfer of control");
    };
    let plan: &TransferControlPlan = plan;
    assert_eq!(plan.source_grant_id, from);
    assert_eq!(plan.to_device_id, taker_record.device_id);

    // The owner device is a companion of its own: it lists what the host holds open, and what it
    // lists is that plan, in its own screen's words, before anything is confirmed.
    let owner_data = tempfile::tempdir().expect("a directory");
    let person = Arc::new(Person {
        confirms: AtomicBool::new(false),
    });
    let as_owner = owner_companion(&scene, owner_data.path(), &person);
    let request = as_owner
        .listed(|request| request["checkable"] == true)
        .await;
    assert_eq!(
        request["title"], "Hand control of a session to another device",
        "{request}"
    );
    let fact = |label: &str| -> String {
        request["facts"]
            .as_array()
            .expect("facts")
            .iter()
            .find(|each| each["label"] == label)
            .and_then(|each| each["value"].as_str())
            .unwrap_or_else(|| panic!("the sheet shows {label}: {request}"))
            .to_owned()
    };
    assert_eq!(fact("Session"), plan.session_id.to_string());
    assert_eq!(fact("From"), plan.from_device_name.as_str());
    assert_eq!(fact("To"), plan.to_device_name.as_str());
    let detail = request["detail"].as_str().expect("the sheet's sentence");
    // The giving device holds the session as an owner of it, the only role whose rights include
    // sharing and so the only one a hand-over can start from; its list is longer than a dialog's
    // line, so the line names the role, and the sheet lists each kind of action beside it.
    assert!(
        detail.contains("who may act as the session's owner for"),
        "the sheet says what the receiving device may do: {detail}"
    );
    assert_eq!(
        fact("Allows"),
        "type in terminals, direct agents, answer agents' approval requests and questions, \
         share sessions with others, create, rename and close sessions, read files, resize \
         terminals, change terminal colours and view sessions"
    );

    // A person who does not confirm leaves everything as it was: nothing is answered, nothing is
    // sent, and the session stays with the giving device.
    let request_reference = request["reference"]
        .as_str()
        .expect("a reference")
        .to_owned();
    assert_eq!(
        as_owner.call(
            "owner_confirmation_review",
            json!({ "request": { "reference": request_reference } })
        ),
        Ok(json!("not_confirmed"))
    );
    let declined = scene
        .issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await
        .expect("read");
    assert_eq!(declined["state"], "waiting");
    assert!(net_support::holds(&scene.host, from));

    // The person confirms, and the application sends what was confirmed.
    person.confirms.store(true, Ordering::SeqCst);
    assert_eq!(
        as_owner.call(
            "owner_confirmation_review",
            json!({ "request": { "reference": request_reference } })
        ),
        Ok(json!("confirmed"))
    );

    let answered = scene
        .issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await
        .expect("read");
    assert_eq!(answered["state"], "answered");
    let done = scene
        .issuer
        .call("transfer_finish", json!({ "reference": reference }))
        .await
        .expect("the confirmed transfer is sent");
    assert_eq!(done["attempt"]["outcome"], "happened");
    let result: GrantTransferResult = typed(&done["value"]);
    assert_eq!(
        result.replacement.recipient_device_id,
        taker_record.device_id
    );
    assert!(net_support::holds(&scene.host, result.replacement.grant_id));
    assert!(
        !net_support::holds(&scene.host, from),
        "the giving device no longer holds the session"
    );
    assert!(scene.issuer.attempts().await.is_empty());

    // The reference is spent: it sends nothing again, and cancelling it undoes nothing.
    let again = scene
        .issuer
        .call("transfer_finish", json!({ "reference": reference }))
        .await
        .expect_err("a hand-over is sent once");
    assert_eq!(code_of(&again), "INVALID_ARGUMENT", "{again}");
    let cancelled = scene
        .issuer
        .call("transfer_cancel", json!({ "reference": reference }))
        .await
        .expect_err("a hand-over that was sent is not cancelled");
    assert_eq!(code_of(&cancelled), "INVALID_ARGUMENT", "{cancelled}");
    assert!(net_support::holds(&scene.host, result.replacement.grant_id));
    giving.close();
    scene.stop().await;
}

/// KR-REQ-18.15, KR-REQ-23.49: the host's answer to the transfer is lost. The application asks
/// again with the same request, on a connection opened for it, and the host answers from its record,
/// so the session changes hands once. While the transfer can still happen no second hand-over of the
/// session is started, and the application, stopped and started again, asks and is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lost_reply_to_a_hand_over_is_answered_from_the_hosts_record_and_gates_a_second() {
    let mut scene = Scene::start().await;
    let hand_over = scene.confirmed_hand_over().await;
    scene.issuer.state().shares().pace_at(FOR_A_WHILE);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call(
            "transfer_finish",
            json!({ "reference": hand_over.reference }),
        )
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();

    // No second hand-over of the session while this one can still happen.
    scene.reconnect_issuer().await;
    let asked = scene
        .issuer
        .call(
            "transfer_ask",
            json!({
                "params": serde_json::to_value(&GrantTransferParams {
                    session_id: scene.session_id,
                    from_grant_id: hand_over.from,
                    to_device_id: hand_over.taker_record.device_id,
                }).expect("encodes"),
                "subject": {
                    "sessionId": scene.session_id.to_string(), "sessionEpoch": "1",
                },
            }),
        )
        .await
        .expect_err("a hand-over of this session can still happen");
    assert_eq!(code_of(&asked), "PERMISSION_DENIED", "{asked}");

    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1);
    assert_eq!(back[0]["kind"], "transfer");
    assert_ne!(back[0]["phase"], "closed");
    let done = scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect("answered from the host's record");
    let result: GrantTransferResult = typed(&done["value"]);
    assert_eq!(
        result.replacement.recipient_device_id,
        hand_over.taker_record.device_id
    );
    assert!(net_support::holds(&scene.host, result.replacement.grant_id));
    assert!(!net_support::holds(&scene.host, hand_over.from));
    hand_over.giving.close();
    scene.stop().await;
}

/// KR-REQ-18.15, KR-REQ-23.49: a transfer the host never saw is not reported as a hand-over because
/// the receiving device already holds another grant of the session: the state check looks for the
/// grant the plan names, not for any grant of the receiver's. Before the bound it is unfinished;
/// after it, the application says it did not happen, and the giving device still holds the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_the_host_never_saw_is_not_done_though_the_receiver_holds_another_grant() {
    let scene = Scene::start().await;
    let hand_over = scene.confirmed_hand_over().await;
    // The receiving device holds a grant of the session of its own.
    let (_other, _held) = owned_by(
        &scene.host,
        scene.session_id,
        &hand_over.taker,
        &hand_over.taker_record,
    )
    .await;
    scene.issuer_faults.request.store(true, Ordering::SeqCst);
    let sent = scene
        .issuer
        .call(
            "transfer_finish",
            json!({ "reference": hand_over.reference }),
        )
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");

    let checking = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "checking")
        .await;
    assert_eq!(checking["kind"], "transfer");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        scene.issuer.attempts().await[0]["phase"],
        "checking",
        "the receiver's other grant is not the transfer, and the bound has not passed"
    );
    scene
        .issuer
        .state()
        .shares()
        .advance(Duration::from_secs(3600));
    let closed = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(closed["outcome"], "not_done");
    assert!(
        net_support::holds(&scene.host, hand_over.from),
        "the giving device still holds the session"
    );
    hand_over.giving.close();
    scene.stop().await;
}

/// KR-REQ-18.15: cancelling a hand-over before an owner device answers sends nothing, forgets the
/// reference, and leaves no record that gates the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_a_hand_over_sends_nothing_and_leaves_no_record() {
    let scene = Scene::start().await;
    let (_share, giving) =
        owned_by(&scene.host, scene.session_id, &scene.device, &scene.record).await;
    let (_taker, taker_record) = recipient(&scene.host, &scene.owner).await;
    let from = scene
        .listed()
        .await
        .grants
        .iter()
        .find(|summary| summary.state == GrantState::Active)
        .expect("the device's share")
        .grant
        .grant_id;
    let body = json!({
        "params": serde_json::to_value(&GrantTransferParams {
            session_id: scene.session_id,
            from_grant_id: from,
            to_device_id: taker_record.device_id,
        }).expect("encodes"),
        "subject": { "sessionId": scene.session_id.to_string(), "sessionEpoch": "1" },
    });
    let asked = scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect("asked");
    let reference = asked["reference"].as_str().expect("a reference").to_owned();
    assert_eq!(
        scene.issuer.attempts().await.len(),
        1,
        "the hand-over holds its place"
    );
    scene
        .issuer
        .call("transfer_cancel", json!({ "reference": reference }))
        .await
        .expect("cancelled");
    assert!(scene.issuer.attempts().await.is_empty());
    let spent = scene
        .issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await
        .expect_err("the reference is forgotten");
    assert_eq!(code_of(&spent), "INVALID_ARGUMENT", "{spent}");
    assert!(
        net_support::holds(&scene.host, from),
        "and the giving device still holds the session"
    );
    // The next hand-over is not gated by the one cancelled.
    scene
        .issuer
        .call("transfer_ask", body)
        .await
        .expect("asked again");
    giving.close();
    scene.stop().await;
}

/// KR-REQ-18.15: a hand-over whose challenge the host no longer has, because the host restarted
/// while the owner devices were being asked, is ended when the page next reads it. The page is told
/// it is gone, the record that held the session's place goes with it, and the next hand-over of the
/// session is not refused as still under way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_whose_challenge_the_host_lost_is_ended_and_can_be_asked_again() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (device, record) = recipient(&host, &owner).await;
    let (session_id, _) = an_open_session(&host);
    let (_share, giving) = owned_by(&host, session_id, &device, &record).await;
    let (_taker, taker_record) = recipient(&host, &owner).await;
    let held: GrantListResult = net_support::pairing::read(
        &mut host.client().await,
        kr_protocol::method::Method::GrantList,
        &GrantListParams {
            session_id: Nullable::some(session_id),
            include_resolved: true,
        },
    )
    .await
    .expect("the list is read");
    let from = held
        .grants
        .iter()
        .find(|summary| summary.state == GrantState::Active)
        .expect("the device's share")
        .grant
        .grant_id;
    let issuer = Page::start(
        local_connection(&host, None).await,
        Arc::new(tempfile::tempdir().expect("a data directory")),
        WorkerLinks::at(host.tree().environment()),
    );
    issuer.state().shares().pace_at(AT_ONCE);
    let body = json!({
        "params": serde_json::to_value(&GrantTransferParams {
            session_id,
            from_grant_id: from,
            to_device_id: taker_record.device_id,
        }).expect("encodes"),
        "subject": { "sessionId": session_id.to_string(), "sessionEpoch": "1" },
    });
    let asked = issuer
        .call("transfer_ask", body.clone())
        .await
        .expect("the owner devices are asked");
    let reference = asked["reference"].as_str().expect("a reference").to_owned();
    assert_eq!(issuer.attempts().await.len(), 1, "it holds its place");

    // The challenge lives in the host's memory alone, so a restart ends it.
    issuer
        .state()
        .connection()
        .expect("connected")
        .session()
        .close();
    giving.close();
    let host = host.restart().await;
    issuer
        .state()
        .connected(local_connection(&host, None).await);
    let read = issuer
        .call("transfer_answered", json!({ "reference": reference }))
        .await
        .expect("read");
    assert_eq!(read["state"], "gone");
    assert!(
        issuer.attempts().await.is_empty(),
        "the record that held the session's place is gone with the hand-over"
    );
    issuer
        .call("transfer_ask", body)
        .await
        .expect("a hand-over of the session is not refused as still under way");

    issuer
        .state()
        .connection()
        .expect("connected")
        .session()
        .close();
    drop(issuer);
    host.stop().await;
}

/// KR-REQ-23.49: an invitation whose answer was lost and which the host is never asked about again,
/// because no connection can be opened for it, is found by reading the host's state, and the
/// application says it happened without the host's result: the grant is there, so it is not done
/// again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invitation_found_by_a_read_closes_as_happened_without_the_hosts_result() {
    let mut scene = Scene::start().await;
    // The first three connections the application opens for an exact repeat fail; the next, which
    // reads the host's state, is made.
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reopen: Reopen = {
        let host_endpoint = scene.host.endpoint().clone();
        let opened = Arc::clone(&opened);
        Arc::new(move || {
            let endpoint = host_endpoint.clone();
            let opened = Arc::clone(&opened);
            Box::pin(async move {
                if opened.fetch_add(1, Ordering::SeqCst) < 3 {
                    return Err(companion_tauri::CommandError::unavailable("no connection"));
                }
                let transport = IpcTransport::connect_app(
                    &endpoint,
                    companion_tauri::connection::build_id().expect("a build identity"),
                )
                .await
                .map_err(companion_tauri::CommandError::from)?;
                Connection::over(transport)
            })
        })
    };
    let faults = Arc::new(Faults::default());
    let inner = local_connection(&scene.host, Some(&faults)).await;
    scene.issuer.state().connected(inner.reopening(reopen));
    scene.issuer_faults = faults;
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);

    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let done = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(
        done["outcome"], "happened",
        "the grant is on the host's list"
    );
    assert_eq!(
        done["result"],
        Value::Null,
        "and the host's result was never read"
    );
    assert_eq!(
        done["follow_up"], false,
        "an invitation without the live view needs none"
    );
    assert_eq!(scene.listed().await.grants.len(), 1);
    assert_eq!(
        opened.load(Ordering::SeqCst),
        4,
        "three repeats could not be made"
    );
    scene
        .issuer
        .call(
            "attempt_remove",
            json!({ "actionId": done["action_id"].as_str().expect("an action") }),
        )
        .await
        .expect("removed");
    scene.stop().await;
}

/// The attention read of a device paired as a guest is refused by the host as it refuses
/// everything a guest has no right to, so a page can treat it as nothing of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guests_attention_read_is_the_hosts_refusal() {
    let scene = Scene::start().await;
    let refused = scene
        .phone
        .call("attention_read", json!({ "params": {} }))
        .await;
    assert!(
        refused.is_err(),
        "a guest has no attention inbox of its own: {refused:?}"
    );
    scene.stop().await;
}

/// KR-REQ-18.15, KR-REQ-23.49: an application stopped while an owner device was being asked to
/// confirm a hand-over starts with the record of it and none of the reference the page held. The
/// record holds the session's place, is not something the host can be asked about, and cannot be
/// hidden away: the person cancels it, and the next hand-over of the session is not refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hand_over_being_confirmed_when_the_application_stopped_is_cancelled_from_its_record() {
    let mut scene = Scene::start().await;
    let (body, giving) = scene.hand_over_body().await;
    scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect("the owner devices are asked");

    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1, "the record is read back");
    assert_eq!(back[0]["phase"], "asking");
    let action = back[0]["action_id"].as_str().expect("an action").to_owned();

    let asked = scene
        .issuer
        .call("attempt_ask", json!({ "actionId": action }))
        .await
        .expect_err("a hand-over still being confirmed is not asked about");
    assert_eq!(code_of(&asked), "INVALID_ARGUMENT", "{asked}");
    let hidden = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect_err("it is cancelled, not hidden away with its place held");
    assert_eq!(code_of(&hidden), "INVALID_ARGUMENT", "{hidden}");
    let held = scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect_err("it still holds the session's place");
    assert_eq!(code_of(&held), "PERMISSION_DENIED", "{held}");

    scene
        .issuer
        .call("attempt_remove", json!({ "actionId": action }))
        .await
        .expect("the person cancels it");
    assert!(scene.issuer.attempts().await.is_empty());
    scene
        .issuer
        .call("transfer_ask", body)
        .await
        .expect("and the session can be handed over again");
    assert!(
        net_support::holds(&scene.host, giving_grant(&scene).await),
        "and the giving device still holds the session"
    );
    giving.close();
    scene.stop().await;
}

/// The grant the device's share of the session is held under.
async fn giving_grant(scene: &Scene) -> GrantId {
    scene
        .listed()
        .await
        .grants
        .iter()
        .find(|summary| {
            summary.state == GrantState::Active
                && summary.grant.recipient_device_id == scene.record.device_id
        })
        .expect("the device's share")
        .grant
        .grant_id
}

/// KR-REQ-23.49: what a person does to an attempt, hiding it or showing it, is theirs, and the task
/// carrying the attempt on does not undo it by writing the copy of the record it began with. An
/// attempt that ends is shown whatever was done to it, since its end is what the person is owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attempt_is_hidden_and_shown_by_the_person_and_not_undone_by_the_task_carrying_it_on() {
    let mut scene = Scene::start().await;
    // The first connection the application opens for a repeat waits for the test; every one after
    // it fails until the test lets one be made.
    let parked = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let open = Arc::new(AtomicBool::new(false));
    let opened = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reopen: Reopen = {
        let endpoint = scene.host.endpoint().clone();
        let (parked, release, open, opened) = (
            Arc::clone(&parked),
            Arc::clone(&release),
            Arc::clone(&open),
            Arc::clone(&opened),
        );
        Arc::new(move || {
            let endpoint = endpoint.clone();
            let (parked, release, open, opened) = (
                Arc::clone(&parked),
                Arc::clone(&release),
                Arc::clone(&open),
                Arc::clone(&opened),
            );
            Box::pin(async move {
                if opened.fetch_add(1, Ordering::SeqCst) == 0 {
                    parked.notify_one();
                    release.notified().await;
                }
                if !open.load(Ordering::SeqCst) {
                    return Err(companion_tauri::CommandError::unavailable("no connection"));
                }
                let transport = IpcTransport::connect_app(
                    &endpoint,
                    companion_tauri::connection::build_id().expect("a build identity"),
                )
                .await
                .map_err(companion_tauri::CommandError::from)?;
                Connection::over(transport)
            })
        })
    };
    let faults = Arc::new(Faults::default());
    let inner = local_connection(&scene.host, Some(&faults)).await;
    scene.issuer.state().connected(inner.reopening(reopen));
    scene.issuer_faults = faults;
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);

    let sent = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("answered");
    assert_ne!(sent["attempt"]["phase"], "closed");
    let action = sent["attempt"]["action_id"]
        .as_str()
        .expect("an action")
        .to_owned();
    // The task is waiting to repeat the request, with the record as it was when it began.
    parked.notified().await;
    let hidden = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect("hidden");
    assert_eq!(hidden["hidden"], true);

    // It goes on, and writes what it learns: the person's choice stands.
    release.notify_one();
    let after = scene
        .issuer
        .attempt_where(|attempt| attempt["repeats"].as_u64() >= Some(1))
        .await;
    assert_eq!(
        after["hidden"], true,
        "the task's write left the person's choice alone: {after}"
    );

    // Showing it is as much theirs, and the task's next writes leave that alone too.
    let shown = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": false }),
        )
        .await
        .expect("shown");
    assert_eq!(shown["hidden"], false);
    let later = scene
        .issuer
        .attempt_where(|attempt| attempt["repeats"].as_u64() >= Some(3))
        .await;
    assert_eq!(later["hidden"], false);

    // Hidden again, and then it ends: the end is shown.
    scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect("hidden again");
    open.store(true, Ordering::SeqCst);
    let done = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(done["hidden"], false, "an attempt that is over is shown");
    let refused = scene
        .issuer
        .call(
            "attempt_set_hidden",
            json!({ "actionId": action, "hidden": true }),
        )
        .await
        .expect_err("an attempt that is over is removed, not hidden");
    assert_eq!(code_of(&refused), "INVALID_ARGUMENT", "{refused}");
    scene.stop().await;
}

/// KR-REQ-23.49: what the host's result carries, which the end of an attempt does not say, is owed
/// to the person until the page has taken it. A revocation whose result was recovered in the
/// background and held in memory is still one the host can be asked for when the application
/// stops before the page read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_recovered_in_the_background_can_still_be_asked_for_after_a_restart() {
    let mut scene = Scene::start().await;
    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("issued");
    let created: GrantCreateResult = typed(&made["value"]);
    scene.issuer_faults.answer.store(true, Ordering::SeqCst);
    scene
        .issuer
        .call(
            "grant_revoke",
            json!({ "params": serde_json::to_value(&GrantRevokeParams {
                grant_id: created.grant.grant_id,
            }).expect("encodes") }),
        )
        .await
        .expect("answered though the host's answer was lost");
    let done = scene
        .issuer
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(done["outcome"], "happened");
    let in_memory: RevocationResult = typed(&done["result"]);
    assert!(in_memory.barrier.holds());
    assert_eq!(
        done["follow_up"], true,
        "the page has not taken the result, so the host can still be asked for it"
    );

    scene.restart_issuer().await;
    let back = scene.issuer.attempts().await;
    assert_eq!(back.len(), 1);
    assert_eq!(
        back[0]["result"],
        Value::Null,
        "the result in memory is gone"
    );
    assert_eq!(back[0]["follow_up"], true);
    let asked = scene
        .issuer
        .call(
            "attempt_ask",
            json!({ "actionId": back[0]["action_id"].as_str().expect("an action") }),
        )
        .await
        .expect("the host answers from its record");
    let result: RevocationResult = typed(&asked["value"]);
    assert!(result.barrier.holds());
    assert!(
        scene.issuer.attempts().await.is_empty(),
        "and the record goes once the result is the page's"
    );
    scene.stop().await;
}

/// KR-REQ-18.15: a refusal is the host's answer to the confirmation request only when it answers
/// the first send. The request never reached the host, so every repeat is a first admission on a
/// connection the window does not belong to and is refused; that is not the host saying no owner
/// device was asked, and when the repeats are used up nothing is known of it. The record that held
/// the session's place goes, since nothing was or will be sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_to_a_repeat_of_the_confirmation_request_is_not_the_hosts_answer() {
    let mut scene = Scene::start().await;
    let (body, giving) = scene.hand_over_body().await;
    scene.issuer_faults.request.store(true, Ordering::SeqCst);
    let unknown = scene
        .issuer
        .call("transfer_ask", body.clone())
        .await
        .expect_err("nothing is known of the request");
    assert_eq!(code_of(&unknown), "RESOURCE_UNAVAILABLE", "{unknown}");
    assert!(
        unknown["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not known whether an owner device was asked"),
        "{unknown}"
    );
    assert!(scene.issuer.attempts().await.is_empty());
    scene.reconnect_issuer().await;
    scene
        .issuer
        .call("transfer_ask", body)
        .await
        .expect("and the session can be handed over again");
    giving.close();
    scene.stop().await;
}

#[allow(dead_code, reason = "the types a page's parameters are written from")]
const _: fn(&GrantId, &InvitationId, &GrantCreateParams) = |_, _, _| {};
#[allow(dead_code, reason = "the actor a local caller is")]
const _: fn(u64) -> kr_protocol::ids::ActorId = local_actor;

/// Writes `count` invitations of `session_id` to the device `to`, all at one moment and below the
/// host's own checks, so that a list longer than a page exists without a session for each.
fn invitations(
    host: &Host,
    session_id: SessionId,
    to: DeviceId,
    count: usize,
) -> Vec<GrantCreateResult> {
    let now_ms = kr_ipc::now_ms().get();
    (0..count)
        .map(|_| {
            let selection = RoleSelection::plain(SessionRole::Viewer);
            host.controller()
                .sharing()
                .share(
                    &kr_controller::sharing::ShareRequest {
                        invitation_id: InvitationId::new(kr_ipc::new_uuid()),
                        grant_id: GrantId::new(kr_ipc::new_uuid()),
                        environment_id: host.environment_id,
                        session_id,
                        issuer_device_id: host.controller().sharing().host_device_id(),
                        recipient_device_id: to,
                        parent_grant_id: None,
                        accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                        selection,
                        lifetime_ms: Some(3_600_000),
                        live_screen: None,
                        named_questions: Vec::new(),
                        named_approvals: Vec::new(),
                        authority_revision: host.controller().policy().authority_revision(),
                        owner_confirmed: false,
                        now_ms,
                    },
                    || Ok(()),
                )
                .expect("the invitation is written")
        })
        .collect()
}

/// Every invitation of `created` accepted over a connection of the device's own.
async fn accept_all(scene: &Scene, created: &[GrantCreateResult]) {
    let connection = RawDevice::connect(&scene.host, &scene.device, &scene.record).await;
    for each in created {
        connection
            .mutate(
                Method::GrantRedeem,
                ActionId::new(kr_ipc::new_uuid()),
                on_the_host(&scene.host),
                &GrantRedeemParams {
                    invitation_id: each.preview.invitation_id,
                },
            )
            .await
            .expect("the invitation is accepted");
    }
    connection.close();
}

/// A read of the whole inbox as the page makes it: nothing narrowed, the first page.
fn well_formed_inbox_read() -> Value {
    json!({
        "params": {
            "session_id": null,
            "include_acknowledged": false,
            "max_items": "200",
            "after": null,
        },
    })
}

/// KR-REQ-18.13: a device with more invitations, and then more shares, than one page holds is told
/// every one of them by one command, each once, however many pages the host answered it in.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_list_of_offers_and_shares_longer_than_a_page_is_read_whole() {
    let scene = Scene::start().await;
    let created = invitations(&scene.host, scene.session_id, scene.record.device_id, 70);

    let answered = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    let held = held_of(&answered);
    assert_eq!(held.offers.len(), 70, "both pages of offers");
    assert!(held.shares.is_empty());
    let mut offered: Vec<_> = held
        .offers
        .iter()
        .map(|offer| offer.invitation_id)
        .collect();
    offered.sort();
    offered.dedup();
    assert_eq!(offered.len(), 70, "no offer is listed twice");

    accept_all(&scene, &created).await;
    let answered = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    let held = held_of(&answered);
    assert!(held.offers.is_empty());
    assert_eq!(held.shares.len(), 70, "both pages of shares");
    let mut grants: Vec<_> = held
        .shares
        .iter()
        .map(|share| share.grant.grant_id)
        .collect();
    grants.sort();
    grants.dedup();
    assert_eq!(grants.len(), 70, "no share is listed twice");
    scene.stop().await;
}

/// KR-REQ-18.13: a read that loses its connection between two pages answers with nothing at all,
/// not with the first page, so that what is missing from a list can never be taken for ended; the
/// next read, on a connection taken up again, answers with every one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_fails_between_pages_answers_nothing_and_the_next_answers_all() {
    let mut scene = Scene::start().await;
    invitations(&scene.host, scene.session_id, scene.record.device_id, 70);

    scene.phone_faults.cut_at_read.store(2, Ordering::SeqCst);
    let refused = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect_err("a list with a page missing is not an answer");
    assert!(
        refused.get("offers").is_none(),
        "no part of the list: {refused}"
    );

    scene.reconnect_phone().await;
    let answered = scene
        .phone
        .call("grant_held", json!({}))
        .await
        .expect("held");
    assert_eq!(held_of(&answered).offers.len(), 70);
    scene.stop().await;
}

/// The marker the session's terminal is made to show.
const MARKER: &str = "kalareach-on-the-screen";

/// KR-REQ-25.10, KR-REQ-18.12: the screen the person is shown before an invitation exists is the
/// session's own, read by the session's worker for the command, and shown whole when it fits. The
/// command is sent a well-formed request, as the Sharing tab sends it, against the real daemon and
/// a real worker whose terminal shows a line; asked for an invitation without the live view it
/// reads no screen.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_screen_preview_is_read_from_a_real_worker_through_the_command() {
    let adopted = Adopted::start(1).await;
    let session_id = adopted.workers[0].session_id;
    let _typing = type_into(
        &adopted.host,
        &adopted.owner,
        session_id,
        &format!("{MARKER}\n"),
    )
    .await;
    let issuer = Page::start(
        local_connection(&adopted.host, None).await,
        Arc::new(tempfile::tempdir().expect("a data directory")),
        WorkerLinks::at(adopted.host.tree().environment()),
    );
    let asking = |include_live_screen: bool| {
        json!({
            "params": {
                "session_id": session_id.to_string(),
                "selection": serde_json::to_value(&RoleSelection {
                    include_live_screen,
                    ..RoleSelection::plain(SessionRole::Viewer)
                }).expect("encodes"),
            },
        })
    };

    // The terminal draws what was typed when the worker has got to it, so the command is asked
    // until it shows it.
    let shown = tokio::time::timeout(WATCHDOG, async {
        loop {
            let answered = issuer
                .call("session_screen_preview", asking(true))
                .await
                .expect("the preview is read");
            let preview: SessionScreenPreviewResult = typed(&answered);
            if let Some(screen) = preview.screen.0
                && screen.lines.iter().any(|line| line.contains(MARKER))
            {
                return screen;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the screen shows what was typed");
    assert!(!shown.truncated, "a screen of a few lines is shown whole");

    // Asked for an invitation without the live view, the worker is not asked for a screen.
    let answered = issuer
        .call("session_screen_preview", asking(false))
        .await
        .expect("the preview is read");
    let preview: SessionScreenPreviewResult = typed(&answered);
    assert!(preview.screen.0.is_none(), "{answered}");

    issuer
        .state()
        .connection()
        .expect("connected")
        .session()
        .close();
    adopted.stop().await;
}

/// KR-REQ-18.13, KR-REQ-25.28: a device paired as a guest reaches no session and no screen of its
/// host, and is told what an invitation to it carries before it accepts: the actions, that the
/// live view is included, where its history begins, and none of the text on the screen its issuer
/// was shown. The screen is a real worker's, and the issuer is shown its line.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_offer_to_a_guest_tells_what_it_carries_and_none_of_the_screen_the_issuer_was_shown() {
    let adopted = Adopted::start(1).await;
    let host = &adopted.host;
    let session_id = adopted.workers[0].session_id;
    let _typing = type_into(host, &adopted.owner, session_id, &format!("{MARKER}\n")).await;
    let environment = host.tree().environment();
    let issuer = Page::start(
        local_connection(host, None).await,
        Arc::new(tempfile::tempdir().expect("a data directory")),
        WorkerLinks::at(environment.clone()),
    );
    let guest = Device::create().await;
    let record = net_support::pair_with(
        host,
        &guest,
        &adopted.owner,
        kr_pairing::grants::guest_grant(
            kr_ipc::now_ms().get(),
            24 * 60 * 60 * 1000,
            host.environment_id,
        )
        .expect("a guest grant"),
    )
    .await;
    let phone = Page::start(
        paired_connection(host, &guest, &record, None).await,
        Arc::new(tempfile::tempdir().expect("a data directory")),
        WorkerLinks::at(environment),
    );

    // A guest reaches no session of the host, and none is listed for it, until one is shared.
    let own = || json!({ "params": { "environment_id": null, "include_closed": false } });
    let refused = phone
        .call("session_list", own())
        .await
        .expect_err("a guest lists no session");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED", "{refused}");
    // The session is waiting for an answer, which is what an inbox is for. The host's owner sees it,
    // which is the control: the guest's inbox is empty because the host leaves the item out of it,
    // and not because there is nothing to leave out.
    adopted.workers[0].ask("is this the plan you meant?");
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let inbox = issuer
                .call("attention_read", well_formed_inbox_read())
                .await
                .expect("the owner's inbox is read");
            if inbox["items"]
                .as_array()
                .is_some_and(|items| !items.is_empty())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the owner is shown what the session is waiting for");
    let inbox = phone
        .call("attention_read", well_formed_inbox_read())
        .await
        .expect("a guest's inbox is read");
    assert_eq!(
        inbox["items"],
        json!([]),
        "the host answers a guest with an inbox that has nothing in it: {inbox}"
    );
    // The session itself is not one the guest can read, shared or not, until one is shared with it.
    let refused = phone
        .call(
            "session_read",
            json!({ "params": { "session_id": session_id.to_string() } }),
        )
        .await
        .expect_err("a guest reads no session of its host");
    assert_eq!(code_of(&refused), "PERMISSION_DENIED", "{refused}");
    let nothing = held_of(&phone.call("grant_held", json!({})).await.expect("held"));
    assert!(nothing.offers.is_empty() && nothing.shares.is_empty());

    // The line is on the session's screen, as the issuer's preview shows.
    let selection = RoleSelection {
        include_live_screen: true,
        ..RoleSelection::plain(SessionRole::Viewer)
    };
    let preview = json!({
        "params": {
            "session_id": session_id.to_string(),
            "selection": serde_json::to_value(&selection).expect("encodes"),
        },
    });
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let answered = issuer
                .call("session_screen_preview", preview.clone())
                .await
                .expect("read");
            let shown: SessionScreenPreviewResult = typed(&answered);
            if shown
                .screen
                .0
                .is_some_and(|screen| screen.lines.iter().any(|line| line.contains(MARKER)))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the screen shows the line");

    let invited = issuer
        .call(
            "grant_create",
            json!({
                "params": serde_json::to_value(&GrantCreateParams {
                    session_id,
                    recipient_device_id: record.device_id,
                    parent_grant_id: Nullable::null(),
                    accepted_notices: AuthorityNotice::for_actions(&selection.actions()),
                    selection,
                    lifetime_ms: Nullable::null(),
                    owner_confirmation: Nullable::null(),
                }).expect("encodes"),
                "subject": { "sessionId": session_id.to_string(), "sessionEpoch": "1" },
            }),
        )
        .await
        .expect("the invitation is issued");
    let created: GrantCreateResult = typed(&invited["value"]);
    // The control for the search below: it finds the line where the issuer was shown it.
    assert!(invited.to_string().contains(MARKER), "{invited}");
    let shown = created
        .preview
        .live_screen
        .0
        .expect("the issuer is shown the screen");
    assert!(
        shown.lines.iter().any(|line| line.contains(MARKER)),
        "the issuer's preview carries the line: {shown:?}"
    );

    // The guest is told what it is offered, that the live view is included, and not one character of
    // the screen the issuer saw.
    let answered = phone.call("grant_held", json!({})).await.expect("held");
    let offers = held_of(&answered).offers;
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].invitation_id, created.preview.invitation_id);
    assert!(offers[0].includes_live_screen);
    assert!(
        offers[0]
            .actions
            .iter()
            .any(|action| *action == ActionRight::SessionView)
    );
    assert!(
        !answered.to_string().contains(MARKER),
        "the offer carries no text of the screen: {answered}"
    );
    // Offered, it reaches nothing yet.
    phone
        .call("session_list", own())
        .await
        .expect_err("an offer lists no session");

    phone
        .state()
        .connection()
        .expect("connected")
        .session()
        .close();
    issuer
        .state()
        .connection()
        .expect("connected")
        .session()
        .close();
    adopted.stop().await;
}

/// A share taken back by the person at the host leaves the device's main connection as it was.
/// What the device is told it holds is read on that connection under its pairing and never under
/// the share, so the host has nothing of the share to withdraw the connection with: the same
/// connection reads the list again, without the share, and no connection was taken up in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_share_taken_back_ends_nothing_on_the_main_connection() {
    let scene = Scene::start().await;
    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("the invitation is issued");
    let created: GrantCreateResult = typed(&made["value"]);
    scene
        .phone
        .call(
            "grant_redeem",
            json!({ "params": serde_json::to_value(&GrantRedeemParams {
                invitation_id: created.preview.invitation_id,
            }).expect("encodes") }),
        )
        .await
        .expect("accepted");
    let main_connection = scene
        .phone
        .state()
        .connection()
        .expect("connected")
        .session();
    let held = held_of(
        &scene
            .phone
            .call("grant_held", json!({}))
            .await
            .expect("held"),
    );
    assert_eq!(held.shares.len(), 1);

    scene
        .issuer
        .call(
            "grant_revoke",
            json!({ "params": serde_json::to_value(&GrantRevokeParams {
                grant_id: created.grant.grant_id,
            }).expect("encodes") }),
        )
        .await
        .expect("the share is taken back");

    // The share has left the list, read on the connection the device had before.
    for _ in 0..2 {
        let held = held_of(
            &scene
                .phone
                .call("grant_held", json!({}))
                .await
                .expect("held"),
        );
        assert!(held.offers.is_empty() && held.shares.is_empty());
    }
    assert!(
        Arc::ptr_eq(
            &main_connection,
            &scene
                .phone
                .state()
                .connection()
                .expect("connected")
                .session()
        ),
        "the device kept its connection"
    );
    scene.stop().await;
}

/// KR-REQ-18.13: the host refuses the first send of an acceptance, because the invitation was
/// withdrawn after the device read its list. The device is answered with an acceptance that is not
/// settled and carries the host's sentence, not with a claim that nothing was accepted: the paired
/// door can replace the result of an acceptance it committed with a refusal, so only what the host
/// lists decides. With neither the invitation nor a share listed once the bound has passed, the
/// outcome stays unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_of_the_first_send_of_an_acceptance_is_the_hosts_sentence_and_the_rows_decide() {
    let scene = Scene::start().await;
    let made = scene
        .issuer
        .call("grant_create", scene.invitation(SessionRole::Viewer))
        .await
        .expect("the invitation is issued");
    let created: GrantCreateResult = typed(&made["value"]);

    let parked = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    *scene
        .phone_faults
        .hold_next
        .lock()
        .unwrap_or_else(PoisonError::into_inner) =
        Some((Arc::clone(&parked), Arc::clone(&release)));
    let accepting = scene.phone.call(
        "grant_redeem",
        json!({ "params": serde_json::to_value(&GrantRedeemParams {
            invitation_id: created.preview.invitation_id,
        }).expect("encodes") }),
    );
    let withdrawing = async {
        parked.notified().await;
        scene
            .issuer
            .call(
                "grant_revoke",
                json!({ "params": serde_json::to_value(&GrantRevokeParams {
                    grant_id: created.grant.grant_id,
                }).expect("encodes") }),
            )
            .await
            .expect("the invitation is withdrawn");
        release.notify_one();
    };
    let (answered, ()) = tokio::join!(accepting, withdrawing);

    let answered = answered.expect("the device is answered with the attempt, not refused");
    assert_eq!(answered["value"], Value::Null, "{answered}");
    assert_ne!(answered["attempt"]["phase"], "closed", "{answered}");
    assert!(
        answered["attempt"]["refusal"].is_string(),
        "the host's own sentence rides on the attempt: {answered}"
    );

    // Neither the invitation nor a share is listed, so once the bound has passed it is unknown and
    // never "not accepted".
    scene
        .phone
        .state()
        .shares()
        .advance(Duration::from_secs(3600));
    let closed = scene
        .phone
        .attempt_where(|attempt| attempt["phase"] == "closed")
        .await;
    assert_eq!(closed["outcome"], "unknown", "{closed}");
    let held = held_of(
        &scene
            .phone
            .call("grant_held", json!({}))
            .await
            .expect("held"),
    );
    assert!(held.offers.is_empty() && held.shares.is_empty());
    scene.stop().await;
}
