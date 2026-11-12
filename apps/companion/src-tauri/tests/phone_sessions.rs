//! A phone opens a paired host's sessions.
//!
//! The host is kr-controller's in-process daemon with a real session worker behind it: the
//! worker's own service, its question ledger and its broker, which a test gives one agent whose
//! upstream it records. The phone is this crate's backend on the mock runtime, paired with the
//! host, and every call below is made the way the page makes it, through the invoke path. A second
//! paired device holds a share of the same session where a test needs one.

#![cfg(unix)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::sync::Arc;
use std::time::Duration;

use companion_tauri::connection::{Connection, Unopened};
use kr_protocol::agent::{AgentMutationTarget, AgentPromptParams, PromptText};
use kr_protocol::ids::{
    ActionId, AgentBindingRevision, ApplicationInstanceId, GrantId, InvitationId, SessionId,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::sharing::{GrantRedeemParams, RoleSelection, SessionRole};
use net_support::worker::{Adopted, Upstream, offer, revoke};
use net_support::{Host, proposal};
use serde_json::{Value, json};
use support::{
    Companion, LinkControl, Phone, WATCHDOG, pair_under, unpaired_phone, unpaired_phone_controlled,
};

/// A pairing grant over every session whose history reaches back to the start, holding `rights`.
fn pairing(rights: &[ActionRight]) -> kr_protocol::pairing::ProposedGrant {
    let mut grant = proposal(rights);
    grant.history.lower_bound_ms = Nullable::some(TimestampMs::new(0));
    grant
}

/// A phone paired with the host under `grant`, and in contact with it.
async fn phone_under(adopted: &Adopted, grant: kr_protocol::pairing::ProposedGrant) -> Phone {
    let phone = unpaired_phone(&adopted.host);
    pair_under(&phone, &adopted.host, &adopted.owner, grant).await;
    connected(&phone.companion).await;
    phone
}

/// Waits until the phone's main connection is up.
async fn connected(companion: &Companion) {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = companion
                .call("connection_state", json!({}))
                .expect("the connection's state");
            if state["connected"] == true {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the connection comes up");
}

/// Calls a command that opens, leaves or reads about a session, as the page does.
fn open(
    companion: &Companion,
    session: SessionId,
    grant: Option<GrantId>,
    opening: &str,
) -> Result<Value, Value> {
    companion.call(
        "session_open",
        json!({
            "sessionId": session.to_string(),
            "grantId": grant.map(|grant| grant.to_string()),
            "opening": opening,
        }),
    )
}

fn leave(companion: &Companion, session: SessionId, opening: &str) {
    companion
        .call(
            "session_leave",
            json!({ "sessionId": session.to_string(), "opening": opening }),
        )
        .expect("a leave is accepted");
}

/// The session's subject, as the page names it in an agent call.
fn subject(session: SessionId, instance: ApplicationInstanceId) -> Value {
    json!({
        "session_id": session.to_string(),
        "application_instance_id": instance.to_string(),
    })
}

/// A prompt carrying its own text, for the agent `instance` of `session`.
fn prompt(session: SessionId, instance: ApplicationInstanceId, text: &str) -> Value {
    serde_json::to_value(AgentPromptParams {
        target: AgentMutationTarget {
            subject: kr_worker::broker::subject(session, instance),
            binding_revision: AgentBindingRevision::new(1),
        },
        draft_id: Nullable::null(),
        text: Nullable::some(PromptText::new(text).expect("a prompt")),
    })
    .expect("encodes")
}

/// The code a refusal carries.
fn code(refusal: &Value) -> &str {
    refusal["code"].as_str().expect("a refusal carries a code")
}

/// Redeems `invitation` as the phone, over a connection of the phone's own, as its Accept flow does.
async fn redeem(phone: &Phone, host: &Host, invitation_id: InvitationId) {
    let device = phone.companion.device();
    let paired = device.host_in_use().expect("a host in use");
    let identity = device.pairing().paired_identity_for(&paired);
    let session = device
        .pairing()
        .link
        .connect_paired(&paired, &identity)
        .await
        .expect("the phone connects");
    session
        .mutate(
            kr_protocol::method::Method::GrantRedeem,
            kr_protocol::envelope::ActionTarget::environment(host.environment_id),
            None,
            &json!({}),
            &GrantRedeemParams { invitation_id },
            kr_protocol::scalars::DurationMs::new(60_000),
        )
        .await
        .expect("the share is redeemed");
    session.close();
}

/// A share of `session` the host issues to the phone and the phone redeems.
async fn shared_with(
    adopted: &Adopted,
    phone: &Phone,
    session: SessionId,
    selection: RoleSelection,
) -> kr_protocol::grant::Grant {
    let paired = phone.companion.device().host_in_use().expect("a host");
    let record = adopted
        .host
        .network()
        .devices()
        .record_for_device(paired.device_id)
        .expect("readable")
        .expect("the phone's record");
    let offered = offer(&adopted.host, session, &record, selection).await;
    redeem(phone, &adopted.host, offered.preview.invitation_id).await;
    offered.grant
}

/// Waits until `until` accepts a standing event for the opening, and returns it.
async fn heard(companion: &Companion, opening: &str, until: impl Fn(&Value) -> bool) -> Value {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            for text in companion.standing.texts() {
                let event: Value = serde_json::from_str(&text).expect("an event");
                if event["opening"] == opening && until(&event["standing"]) {
                    return event;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the page is told")
}

/// KR-REQ-19.08: a phone paired with a host reads a session's conversation, prompts its agent and
/// answers its question over the paired connection, as the page does, with a real worker behind the
/// daemon. The screen's open says what the host decided and not what the pairing proposed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_phone_reads_prompts_and_answers_a_paired_hosts_session() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(Upstream::default());
    let instance = worker.register_agent(Arc::clone(&upstream));
    worker
        .service
        .broker()
        .observe(
            instance,
            "message",
            "ready when you are",
            TimestampMs::new(2),
        )
        .expect("the agent has said something");
    let question = worker.ask("push-after-failures");
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[
            ActionRight::SessionView,
            ActionRight::AgentPrompt,
            ActionRight::QuestionRespond,
        ]),
    )
    .await;
    let companion = &phone.companion;

    // Opened, the screen is told what the host decided.
    let standing = open(companion, session, None, "first-opening").expect("the session opens");
    assert_eq!(standing["state"], "open", "{standing}");
    assert_eq!(standing["via"], "pairing");
    let mut actions: Vec<String> =
        serde_json::from_value(standing["actions"].clone()).expect("rights");
    actions.sort();
    assert_eq!(
        actions,
        ["agent.prompt", "question.respond", "session.view"]
    );

    // The conversation: the instance, its capabilities, what it said.
    let agents = companion
        .call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": "first-opening" }),
        )
        .expect("the agents are read");
    assert_eq!(
        agents["instances"]["instances"][0]["application_instance_id"],
        instance.to_string()
    );
    let capabilities = companion
        .call(
            "agent_capabilities",
            json!({ "params": { "subject": subject(session, instance) }, "opening": "first-opening" }),
        )
        .expect("the capabilities are read");
    assert_eq!(capabilities["binding"]["binding_revision"], "1");
    let snapshot = companion
        .call(
            "agent_snapshot",
            json!({
                "params": { "subject": subject(session, instance), "from_node": null },
                "opening": "first-opening",
            }),
        )
        .expect("the conversation is read");
    assert_eq!(snapshot["entries"].as_array().map(Vec::len), Some(1));

    // The composer: a prompt reaches the agent's upstream once, and its receipt settles.
    let settled = companion
        .call(
            "agent_prompt_submit",
            json!({ "params": prompt(session, instance, "run the tests"), "opening": "first-opening" }),
        )
        .expect("the prompt is submitted");
    assert!(
        settled["value"].is_object() || settled["receipt"].is_object(),
        "{settled}"
    );
    assert_eq!(upstream.prompts(), ["run the tests"]);

    // The agent's question, read on the screen's link and answered.
    let read = companion
        .call(
            "question_read",
            json!({
                "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
                "opening": "first-opening",
            }),
        )
        .expect("the questions are read");
    let listed = &read["questions"][0];
    assert_eq!(listed["question_id"], question.question_id.to_string());
    let answered = companion
        .call(
            "question_answer",
            json!({
                "params": {
                    "session_id": session.to_string(),
                    "question_id": question.question_id.to_string(),
                    "expected_revision": listed["revision"],
                    "answer": { "kind": "decision", "decided": true },
                },
                "opening": "first-opening",
            }),
        )
        .expect("the question is answered");
    assert_eq!(answered["outcome"], "taken", "{answered}");

    leave(companion, session, "first-opening");
    adopted.stop().await;
}

/// KR-REQ-19.08: commands from outside a session screen reach the sessions of a paired host over
/// links of their own. Two sessions answer `question.read` on one phone, which one connection
/// could not do, and a share-only session is not reachable from there.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_phone_reads_the_questions_of_two_sessions_without_opening_either() {
    let adopted = Adopted::start(2).await;
    let (first, second) = (&adopted.workers[0], &adopted.workers[1]);
    first.ask("one");
    second.ask("two");
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    for worker in [first, second] {
        let read = phone
            .companion
            .call(
                "question_read",
                json!({
                    "params": {
                        "session_id": worker.session_id.to_string(),
                        "question_id": null,
                        "include_resolved": false,
                    },
                }),
            )
            .expect("each session's questions are read");
        assert_eq!(
            read["questions"].as_array().map(Vec::len),
            Some(1),
            "{read}"
        );
    }
    adopted.stop().await;
}

/// KR-REQ-19.08: a share ends the screen that runs under it and nothing else. The page is told
/// with the host's reason; the main connection still lists the sessions, and the phone's other
/// session, opened under the pairing, is still served.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_shares_end_is_told_to_its_screen_and_ends_nothing_else() {
    let adopted = Adopted::start(2).await;
    let (shared, own) = (&adopted.workers[0], &adopted.workers[1]);
    shared.ask("shared");
    own.ask("own");
    let mut grant = pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]);
    grant.session_selector = kr_protocol::grant::SessionSelector::These {
        session_ids: [own.session_id].into_iter().collect(),
    };
    let phone = phone_under(&adopted, grant).await;
    let companion = &phone.companion;
    let share = shared_with(
        &adopted,
        &phone,
        shared.session_id,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;

    let under_share = open(
        companion,
        shared.session_id,
        Some(share.grant_id),
        "share-1",
    )
    .expect("the share opens");
    assert_eq!(under_share["via"], "share", "{under_share}");
    open(companion, own.session_id, None, "own-1").expect("the pairing opens its own session");
    let questions = |session: SessionId, opening: &str| {
        companion.call(
            "question_read",
            json!({
                "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
                "opening": opening,
            }),
        )
    };
    questions(shared.session_id, "share-1").expect("served under the share");
    questions(own.session_id, "own-1").expect("served under the pairing");

    revoke(&adopted.host, share.grant_id).await;

    let told = heard(companion, "share-1", |standing| {
        standing["state"] == "ended"
    })
    .await;
    assert_eq!(told["standing"]["reason"], "revoked");
    let refused = questions(shared.session_id, "share-1").expect_err("the screen's commands stop");
    assert_eq!(code(&refused), "PERMISSION_DENIED", "{refused}");
    questions(own.session_id, "own-1").expect("the other session's link stands");
    let listed = companion
        .call(
            "session_list",
            json!({ "params": { "environment_id": null, "include_closed": false } }),
        )
        .expect("the main connection stands");
    assert_eq!(listed["sessions"].as_array().map(Vec::len), Some(1));
    adopted.stop().await;
}

/// KR-REQ-19.08: a link lost without the grant ending is reached again as the same opening, and the
/// page is told both. The screen's commands work again on the new link.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_lost_link_is_reached_again_as_the_same_opening() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    worker.ask("one");
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "kept-opening").expect("the session opens");
    let read = || {
        companion.call(
            "question_read",
            json!({
                "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
                "opening": "kept-opening",
            }),
        )
    };
    read().expect("served");

    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_links()
        .lose_connection(session);

    heard(companion, "kept-opening", |standing| {
        standing["state"] == "reconnecting"
    })
    .await;
    let again = tokio::time::timeout(WATCHDOG, async {
        loop {
            let texts = companion.standing.texts();
            let last: Value =
                serde_json::from_str(texts.last().expect("an event")).expect("an event");
            if last["standing"]["state"] == "open" {
                return last;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the session is reached again");
    assert_eq!(again["opening"], "kept-opening");
    read().expect("served on the new link");
    adopted.stop().await;
}

/// KR-REQ-19.08: a command belongs to the opening it names. After another opening of the session
/// replaces it, a command prepared under the first executes nowhere: the agent is prompted by the
/// second and not by the first. A token is used once, one that is not well formed is refused, and
/// a leave that arrives before its open leaves no link.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_command_prepared_under_a_replaced_opening_executes_nowhere() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(Upstream::default());
    let instance = worker.register_agent(Arc::clone(&upstream));
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
    )
    .await;
    let companion = &phone.companion;
    let submit = |text: &str, opening: &str| {
        companion.call(
            "agent_prompt_submit",
            json!({ "params": prompt(session, instance, text), "opening": opening }),
        )
    };

    open(companion, session, None, "opening-a").expect("the first opening");
    submit("from a", "opening-a").expect("served under the first opening");
    open(companion, session, None, "opening-b").expect("the second opening replaces it");
    let stale = submit("from a, late", "opening-a").expect_err("the first opening is replaced");
    assert_eq!(code(&stale), "STALE_SESSION", "{stale}");
    submit("from b", "opening-b").expect("served under the second opening");
    assert_eq!(upstream.prompts(), ["from a", "from b"]);

    // A token is used once, and is chosen from letters, digits and dashes.
    let reused = open(companion, session, None, "opening-a").expect_err("a used token");
    assert_eq!(code(&reused), "INVALID_ARGUMENT", "{reused}");
    let badly_formed = open(companion, session, None, "not a token!").expect_err("a bad token");
    assert_eq!(code(&badly_formed), "INVALID_ARGUMENT", "{badly_formed}");

    // A leave that arrives before its open marks the token, so the open that follows installs
    // nothing and a command under it executes nowhere.
    leave(companion, session, "opening-c");
    let late = open(companion, session, None, "opening-c").expect_err("a token already left");
    assert_eq!(code(&late), "INVALID_ARGUMENT", "{late}");
    let after_leave = submit("from c", "opening-c").expect_err("no such opening");
    assert_eq!(code(&after_leave), "STALE_SESSION", "{after_leave}");
    assert_eq!(upstream.prompts(), ["from a", "from b"]);
    adopted.stop().await;
}

/// KR-REQ-19.08: an approval the agent asks for is found among the session's requests, inspected
/// and decided by the phone, over the paired connection, and the worker's broker takes the decision.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_phone_decides_an_approval_the_agent_asked_for() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(Upstream::default());
    let instance = worker.register_agent(Arc::clone(&upstream));
    let resource = worker.offer_approval(instance, Arc::clone(&upstream) as _, None);
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::AgentApprovalRespond]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "approval-screen").expect("the session opens");

    let agents = companion
        .call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": "approval-screen" }),
        )
        .expect("the agents are read");
    let pending: Vec<&str> = agents["resources"]
        .as_array()
        .expect("resources")
        .iter()
        .filter_map(|resource| resource["resource_id"].as_str())
        .collect();
    assert_eq!(pending, [resource.to_string()]);
    let inspected = companion
        .call(
            "agent_approval_inspect",
            json!({
                "params": { "subject": subject(session, instance), "resource_id": resource.to_string() },
                "opening": "approval-screen",
            }),
        )
        .expect("the approval is inspected");
    assert!(inspected.is_object(), "{inspected}");

    let decided = companion
        .call(
            "agent_approval_respond",
            json!({
                "params": {
                    "target": { "subject": subject(session, instance), "binding_revision": "1" },
                    "resource_id": resource.to_string(),
                    "option_id": "allow",
                },
                "opening": "approval-screen",
            }),
        )
        .expect("the decision is taken");
    assert!(
        decided["value"].is_object() || decided["receipt"].is_object(),
        "{decided}"
    );
    assert_ne!(
        worker
            .service
            .broker()
            .pending(resource)
            .expect("held")
            .state,
        kr_protocol::gateway::PendingState::Pending,
        "the broker took the decision"
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: a phone that holds a share and nothing else prompts the share's session, and the
/// host decides the prompt under the share: a pairing that admits no session could not.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_phone_acts_under_the_share_it_opened_the_session_with() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(Upstream::default());
    let instance = worker.register_agent(Arc::clone(&upstream));
    let session = worker.session_id;
    let mut grant = pairing(&[ActionRight::SessionView]);
    grant.session_selector = kr_protocol::grant::SessionSelector::None;
    let phone = phone_under(&adopted, grant).await;
    let companion = &phone.companion;
    let asked = worker.ask("under-the-share");
    let share = shared_with(
        &adopted,
        &phone,
        session,
        RoleSelection {
            include_question_respond: true,
            named_questions: [asked.question_id].into_iter().collect(),
            ..RoleSelection::plain(SessionRole::Controller)
        },
    )
    .await;

    // The pairing admits no session, so the screen is opened under the share it names.
    let refused = open(companion, session, None, "no-share").expect_err("the pairing admits none");
    assert_eq!(code(&refused), "PERMISSION_DENIED", "{refused}");
    let standing = open(companion, session, Some(share.grant_id), "under-share").expect("opens");
    assert_eq!(standing["via"], "share", "{standing}");
    assert_eq!(standing["grant_id"], share.grant_id.to_string());
    companion
        .call(
            "agent_prompt_submit",
            json!({ "params": prompt(session, instance, "under the share"), "opening": "under-share" }),
        )
        .expect("the prompt is decided under the share");
    assert_eq!(upstream.prompts(), ["under the share"]);

    // A question is answered under the share too: the pairing holds no right to answer.
    let read = companion
        .call(
            "question_read",
            json!({
                "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
                "opening": "under-share",
            }),
        )
        .expect("the question is read under the share");
    let listed = &read["questions"][0];
    assert_eq!(listed["question_id"], asked.question_id.to_string());
    let answered = companion
        .call(
            "question_answer",
            json!({
                "params": {
                    "session_id": session.to_string(),
                    "question_id": asked.question_id.to_string(),
                    "expected_revision": listed["revision"],
                    "answer": { "kind": "decision", "decided": true },
                },
                "opening": "under-share",
            }),
        )
        .expect("the answer is decided under the share");
    assert_eq!(answered["outcome"], "taken", "{answered}");

    // A command from outside a screen is decided under the pairing, which admits no session.
    let ambient = companion
        .call(
            "question_read",
            json!({
                "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
            }),
        )
        .expect_err("a share-only session is not reachable from outside its screen");
    assert_eq!(code(&ambient), "PERMISSION_DENIED", "{ambient}");
    adopted.stop().await;
}

/// KR-REQ-19.08: leaving a screen with a prompt in flight does not turn the prompt into an unknown
/// outcome: the link closes after the worker has answered, and the screen's commands stop at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_leave_waits_for_the_prompt_in_flight() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(net_support::worker::HeldUpstream::default());
    let instance = worker.register_agent_on(Arc::clone(&upstream) as _);
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "leaving-screen").expect("the session opens");

    let sending = companion.start_call(
        "agent_prompt_submit",
        json!({ "params": prompt(session, instance, "in flight"), "opening": "leaving-screen" }),
    );
    tokio::time::timeout(WATCHDOG, async {
        while upstream.prompts().is_empty() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the prompt reaches the agent's upstream");

    leave(companion, session, "leaving-screen");
    let stopped = companion
        .call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": "leaving-screen" }),
        )
        .expect_err("the screen's commands stop at once");
    assert_eq!(code(&stopped), "STALE_SESSION", "{stopped}");
    assert!(!sending.is_finished(), "the prompt is still in flight");

    upstream.release();
    let settled = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the prompt is answered")
        .expect("the call ran")
        .expect("the prompt is not turned into a refusal by the leave");
    assert!(
        settled["value"].is_object() || settled["receipt"].is_object(),
        "{settled}"
    );
    adopted.stop().await;
}

/// KR-REQ-19.08 and section 9: a prompt the host cannot establish reaches the page as an action it
/// has an identifier for, not as a refusal, and the screen's link goes on standing. The page can ask
/// what became of it under the same opening, and is told what the host's record says.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_prompt_the_host_cannot_establish_reaches_the_page_with_its_action() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(net_support::worker::HeldUpstream::default());
    let instance = worker.register_agent_on(Arc::clone(&upstream) as _);
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "unknown-screen").expect("the session opens");

    // The agent's upstream takes the frame and never answers, so the worker, at its own deadline,
    // answers that the outcome cannot be established.
    let settled = companion
        .call(
            "agent_prompt_submit",
            json!({ "params": prompt(session, instance, "never answered"), "opening": "unknown-screen" }),
        )
        .expect("an outcome nobody can establish is an answer with its action, not a refusal");
    assert_eq!(
        upstream.prompts().len(),
        1,
        "the frame reached the upstream once"
    );
    assert!(settled["receipt"].is_null(), "{settled}");
    assert!(settled["value"].is_null(), "{settled}");
    let action_id = settled["action_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the answer names the action: {settled}"))
        .to_owned();

    // The link the answer came on is still the screen's: the answer said nothing against it.
    companion
        .call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": "unknown-screen" }),
        )
        .expect("the screen's link stands");
    // And the host's record of the action is read on it, under the opening.
    let read = companion
        .call(
            "action_read",
            json!({
                "params": { "action_id": action_id, "session_id": session.to_string() },
                "opening": "unknown-screen",
            }),
        )
        .expect("the receipt is read under the opening");
    assert_eq!(read["receipt"]["state"], "unknown", "{read}");
    // A record that still says unknown does not settle it: the link goes on counting the action.
    {
        use tauri::Manager as _;
        let state = companion.app.state::<companion_tauri::AppState>();
        assert_eq!(
            state
                .paired_links()
                .unresolved(session, "unknown-screen")
                .await,
            Some(1),
            "the action nobody knows the end of stays in the link's book"
        );
    }

    upstream.release();
    adopted.stop().await;
}

/// KR-REQ-23.24: a prompt whose outcome the host cannot establish is an uncertain outcome, and a
/// later prompt for the same conversation is admitted only as an explicit later request that names
/// that action and the revision of its record the phone read. The command sends the quote it is
/// given and none of its own: the host refuses a later prompt that names nothing, and one that names
/// a revision the phone was not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_24_a_later_prompt_after_an_unknown_one_is_admitted_only_with_the_quote_of_what_was_read()
 {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(net_support::worker::HeldUpstream::default());
    let instance = worker.register_agent_on(Arc::clone(&upstream) as _);
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "screen").expect("the session opens");

    // The first prompt's outcome nobody can establish: the answer names the action.
    let first = companion
        .call(
            "agent_prompt_submit",
            json!({ "params": prompt(session, instance, "first"), "opening": "screen" }),
        )
        .expect("an outcome nobody can establish is an answer with its action");
    let action_id = first["action_id"]
        .as_str()
        .unwrap_or_else(|| panic!("the answer names the action: {first}"))
        .to_owned();
    // The phone reads the host's record of it: this is what the person is shown.
    let read = companion
        .call(
            "action_read",
            json!({
                "params": { "action_id": action_id, "session_id": session.to_string() },
                "opening": "screen",
            }),
        )
        .expect("the record is read under the opening");
    assert_eq!(read["receipt"]["state"], "unknown", "{read}");
    let shown: u64 = read["receipt"]["revision"]
        .as_str()
        .expect("a revision")
        .parse()
        .expect("a number");

    let later = |text: &str, quote: Option<Value>| {
        let mut call = json!({ "params": prompt(session, instance, text), "opening": "screen" });
        if let Some(quote) = quote {
            call["supersedes"] = quote;
        }
        companion.call("agent_prompt_submit", call)
    };

    // A later prompt that names nothing is the host's refusal, and nothing reached the agent.
    let bare = later("second", None).expect_err("the earlier outcome has not been shown");
    assert_eq!(code(&bare), "DRAFT_CONFLICT", "{bare}");
    // So is one that names a revision the phone was never shown: the command sends what it is
    // given, and does not mend it.
    let unseen = later(
        "second",
        Some(json!({ "action_id": action_id, "revision": (shown + 7).to_string() })),
    )
    .expect_err("a revision nobody read shows nothing");
    assert_eq!(code(&unseen), "DRAFT_CONFLICT", "{unseen}");
    assert_eq!(
        upstream.prompts(),
        vec!["first".to_owned()],
        "neither refused prompt reached the agent"
    );

    // The explicit later request, naming what the person was shown, is admitted: the host hands
    // it to the agent. (This agent answers nothing, so the new action is itself unknown.)
    let admitted = later(
        "second",
        Some(json!({ "action_id": action_id, "revision": shown.to_string() })),
    )
    .expect("a request that shows the earlier result is admitted");
    assert_ne!(
        admitted["action_id"].as_str(),
        Some(action_id.as_str()),
        "a new action: the earlier one is not replaced"
    );
    assert_eq!(
        upstream.prompts(),
        vec!["first".to_owned(), "second".to_owned()],
        "the quoted prompt reached the agent"
    );

    upstream.release();
    adopted.stop().await;
}

/// The conversation the host reports for `session`, read as the page reads it to bind a draft: the
/// live instance and its binding revision.
fn conversation(companion: &Companion, session: SessionId, opening: &str) -> (String, String) {
    let agents = companion
        .call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": opening }),
        )
        .expect("the session's agents are read");
    let instance = agents["instances"]["instances"][0]["application_instance_id"]
        .as_str()
        .unwrap_or_else(|| panic!("a live instance: {agents}"))
        .to_owned();
    let facts = companion
        .call(
            "agent_capabilities",
            json!({
                "params": { "subject": { "session_id": session.to_string(), "application_instance_id": instance } },
                "opening": opening,
            }),
        )
        .expect("the agent's capabilities are read");
    let binding = facts["binding"]["binding_revision"]
        .as_str()
        .unwrap_or_else(|| panic!("a binding revision: {facts}"))
        .to_owned();
    (instance, binding)
}

/// KR-REQ-13.13: a draft kept on the phone is the device's own: it is written and read back whole
/// while the host is out of contact, the host's facts the page rebinds it from are read again once
/// it returns, and when the agent has moved to another conversation the draft follows it only by
/// the person's explicit retarget. A prompt at the conversation the draft was written for is the
/// host's to refuse, and nothing is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_13_a_draft_outlives_the_host_being_out_of_contact_and_follows_its_conversation_only_when_retargeted()
 {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(Upstream::default());
    let instance = worker.register_agent(Arc::clone(&upstream));
    let session = worker.session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "screen").expect("the session opens");

    // The page writes the draft for the conversation the host reports.
    let (first_instance, first_binding) = conversation(companion, session, "screen");
    assert_eq!(first_instance, instance.to_string());
    let save =
        |id: Option<&str>, revision: Option<&str>, binding: &str, state: &str, text: &str| {
            companion.call(
                "device_draft_save",
                json!({ "params": {
                "id": id,
                "expectedRevision": revision,
                "sessionId": session.to_string(),
                "applicationInstanceId": instance.to_string(),
                "agentBindingRevision": binding,
                "state": state,
                "text": text,
                "attachments": []
            } }),
            )
        };
    let saved =
        save(None, None, &first_binding, "open", "half a thought").expect("the draft is kept");
    let id = saved["draft"]["id"].as_str().expect("an id").to_owned();

    // The host stops answering and the connection for the host alone ends.
    control.unreachable(true);
    let (_, _, main) = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_snapshot()
        .expect("a connection");
    main.close();
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = companion
                .call("connection_state", json!({}))
                .expect("the connection's state");
            if state["connected"] == false {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the connection ends");

    // The draft is the device's: it is written to and read back whole with no host.
    save(
        Some(&id),
        Some("1"),
        &first_binding,
        "open",
        "half a thought, and more",
    )
    .expect("the draft is kept while the host is out of contact");
    let kept = companion
        .call("device_drafts", json!(null))
        .expect("the drafts are read");
    let drafts = kept["drafts"].as_array().expect("a list of drafts");
    assert_eq!(drafts.len(), 1, "{kept}");
    assert_eq!(drafts[0]["text"], "half a thought, and more");
    assert_eq!(drafts[0]["state"], "open");

    // The host returns, and what the page rebinds the draft from is the same conversation.
    control.unreachable(false);
    connected(companion).await;
    open(companion, session, None, "screen-again").expect("the session opens again");
    assert_eq!(
        conversation(companion, session, "screen-again"),
        (first_instance.clone(), first_binding.clone())
    );

    // The agent moves to another conversation. The host reports it, a prompt at the old one is the
    // host's to refuse, and the store will not move the draft to the new one on a save.
    worker
        .service
        .broker()
        .advance_binding(
            instance,
            Some(kr_protocol::ids::AgentThreadId::new("thread-2").expect("a thread")),
            kr_ipc::now_ms(),
        )
        .expect("the binding advances");
    let (_, moved_binding) = conversation(companion, session, "screen-again");
    assert_ne!(
        moved_binding, first_binding,
        "the host reports the new conversation"
    );
    let refused = companion
        .call(
            "agent_prompt_submit",
            json!({ "params": prompt(session, instance, "half a thought, and more"), "opening": "screen-again" }),
        )
        .expect_err("the host refuses a prompt for a conversation that has moved on");
    assert!(
        matches!(code(&refused), "DRAFT_CONFLICT" | "STALE_SESSION"),
        "{refused}"
    );
    assert!(upstream.prompts().is_empty(), "nothing reached the agent");
    let followed = save(
        Some(&id),
        Some("2"),
        &moved_binding,
        "open",
        "half a thought, and more",
    )
    .expect_err("a draft with text does not follow the agent on a save");
    assert_eq!(code(&followed), "DRAFT_CONFLICT", "{followed}");

    // The person's retarget names the version they were shown, and is the one way across.
    save(
        Some(&id),
        Some("2"),
        &first_binding,
        "conflicted",
        "half a thought, and more",
    )
    .expect("the page marks the draft conflicted");
    let moved = companion
        .call(
            "device_draft_retarget",
            json!({ "params": {
                "id": id,
                "expectedRevision": "3",
                "sessionId": session.to_string(),
                "applicationInstanceId": instance.to_string(),
                "agentBindingRevision": moved_binding
            } }),
        )
        .expect("the draft is retargeted by the person");
    assert_eq!(moved["state"], "open");
    assert_eq!(moved["agentBindingRevision"], moved_binding.as_str());
    assert_eq!(moved["text"], "half a thought, and more");
    assert!(
        upstream.prompts().is_empty(),
        "nothing was sent by the move"
    );
    adopted.stop().await;
}

/// KR-REQ-13.03: a draft written in a paired host's conversation is the same draft, with the same
/// revision, while the person is in the terminal and after they are back. The terminal is a view on
/// a connection of its own, which takes the input lease and ends with the view: opening it, typing
/// into it and closing it leave the draft, the conversation the draft is bound to and the host's
/// agent as they were, and send the agent nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_13_03_a_draft_is_the_same_after_a_visit_to_the_terminal() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(Upstream::default());
    let instance = worker.register_agent(Arc::clone(&upstream));
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[
            ActionRight::SessionView,
            ActionRight::TerminalInput,
            ActionRight::AgentPrompt,
        ]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "screen").expect("the session opens");

    // The page writes the draft for the conversation the host reports.
    let (conversation_instance, binding) = conversation(companion, session, "screen");
    assert_eq!(conversation_instance, instance.to_string());
    companion
        .call(
            "device_draft_save",
            json!({ "params": {
                "id": null,
                "expectedRevision": null,
                "sessionId": session.to_string(),
                "applicationInstanceId": instance.to_string(),
                "agentBindingRevision": binding,
                "state": "open",
                "text": "a thought for the agent",
                "attachments": []
            } }),
        )
        .expect("the draft is kept");
    let the_draft = || {
        let kept = companion
            .call("device_drafts", json!(null))
            .expect("the drafts are read");
        let drafts = kept["drafts"].as_array().expect("a list of drafts").clone();
        assert_eq!(drafts.len(), 1, "{kept}");
        drafts[0].clone()
    };
    let before = the_draft();
    assert_eq!(before["text"], "a thought for the agent");
    assert_eq!(before["state"], "open");

    // The person switches to the terminal, takes control and types into the program.
    let view = open_view(companion, session, "screen", 13).expect("the view opens");
    companion
        .state_where(13, |state| state["state"] == "showing")
        .await;
    companion
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": { "kind": "take", "number": 1 } }),
        )
        .expect("the take is taken");
    companion
        .state_where(13, |state| state["control"]["state"] == "controlling")
        .await;
    companion
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": { "kind": "text", "take": 1, "text": "typed in the terminal" } }),
        )
        .expect("the text is taken");
    companion
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": {
                "kind": "key", "take": 1, "key": "Enter", "base": null, "keypad": null,
                "shift": false, "alt": false, "control": false, "caps_lock": false,
                "num_lock": false, "event": "press",
            } }),
        )
        .expect("the key is taken");
    // `cat` is the session's shell: what it writes back is what reached the program.
    companion
        .state_where(13, |state| {
            text_of(state)
                .iter()
                .any(|line| line.contains("typed in the terminal"))
        })
        .await;
    assert_eq!(
        the_draft(),
        before,
        "the terminal's input is the program's and is not the draft"
    );

    // The person switches back: the view ends with its attachment, and the draft is as they left it.
    companion
        .call("terminal_view_close", json!({ "view": view }))
        .expect("the view closes");
    tokio::time::timeout(WATCHDOG, async {
        while worker.attachments() != 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the daemon shows no attachment once the view is closed");
    assert_eq!(the_draft(), before, "the draft after the terminal");
    assert_eq!(
        conversation(companion, session, "screen"),
        (conversation_instance, binding.clone()),
        "the draft is still bound to the host's conversation"
    );

    assert!(upstream.prompts().is_empty(), "the visit sent nothing");
    adopted.stop().await;
}

/// KR-REQ-19.08: the companion, paired with a host, opens that host's session over its paired
/// connection and holds at most `HOST_CONNECTIONS` connections to it at once, every dial counted: a
/// pending open, a superseded one and a link left while its requests finish included, one place of
/// them the main link's alone. The host lets a device use that many and holds at least twice as
/// many live ones, so that every connection in use may linger once beside its replacement, and it
/// ends none that it heard from lately for a new one.
#[test]
fn kr_req_19_08_the_hosts_bound_on_a_devices_connections_covers_the_phones_links() {
    let in_use = kr_controller::service::net::DEVICE_CONNECTIONS_IN_USE;
    let held = kr_controller::service::net::DEVICE_LIVE_CONNECTIONS;
    let total = companion_tauri::places::HOST_CONNECTIONS;
    assert!(
        total <= in_use,
        "the phone holds {total} connections to a host and the host lets a device use {in_use}"
    );
    assert!(
        held >= 2 * total,
        "the host's bound of {held} live connections is less than twice the {total} the phone \
         holds, so a connection in use cannot linger once beside its replacement"
    );
}

/// KR-REQ-19.08: the phone holds at most four ambient links and eight opened ones. Five sessions
/// asked about at once from outside any screen are all answered, with no more than four links held;
/// a ninth session opened is refused until one is left.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_the_phone_holds_no_more_links_than_its_limits() {
    use tauri::Manager as _;

    let adopted = Adopted::start(9).await;
    for worker in &adopted.workers {
        worker.ask("one");
    }
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;
    let reads: Vec<_> = adopted
        .workers
        .iter()
        .take(5)
        .map(|worker| {
            companion.start_call(
                "question_read",
                json!({
                    "params": {
                        "session_id": worker.session_id.to_string(),
                        "question_id": null,
                        "include_resolved": false,
                    },
                }),
            )
        })
        .collect();
    for read in reads {
        let read = read.await.expect("the call ran").expect("each is answered");
        assert_eq!(
            read["questions"].as_array().map(Vec::len),
            Some(1),
            "{read}"
        );
    }
    let state = companion.app.state::<companion_tauri::AppState>();
    assert!(
        state.paired_links().ambient() <= 4,
        "at most four ambient links are held"
    );

    for (index, worker) in adopted.workers.iter().take(8).enumerate() {
        open(
            companion,
            worker.session_id,
            None,
            &format!("screen-{index}"),
        )
        .expect("opens");
    }
    let ninth = adopted.workers[8].session_id;
    let refused = open(companion, ninth, None, "screen-eight").expect_err("a ninth is refused");
    assert_eq!(code(&refused), "RESOURCE_UNAVAILABLE", "{refused}");
    leave(companion, adopted.workers[0].session_id, "screen-0");
    open(companion, ninth, None, "screen-nine").expect("room is made by a leave");
    adopted.stop().await;
}

/// KR-REQ-11.63: on a paired host the links held for a session are the ones the host's connections
/// gave it, the link its screen opened and its ambient link, and not this application's own slot
/// for the session, which a phone has none of. A session the phone holds nothing for has none.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_63_the_links_held_for_a_session_on_a_paired_host_are_its_openings_and_ambient_link()
 {
    use tauri::Manager as _;

    let adopted = Adopted::start(2).await;
    let session = adopted.workers[0].session_id;
    let other = adopted.workers[1].session_id;
    adopted.workers[0].ask("held");
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;
    let state = companion.app.state::<companion_tauri::AppState>();
    let links = companion.app.state::<companion_tauri::agent::WorkerLinks>();
    assert_eq!(
        links.held_for_count(&state, session),
        0,
        "nothing is held yet"
    );

    // A read that names no opening goes over the session's ambient link.
    companion
        .call(
            "question_read",
            json!({
                "params": {
                    "session_id": session.to_string(),
                    "question_id": null,
                    "include_resolved": false,
                },
            }),
        )
        .expect("the question is read");
    assert_eq!(links.held_for_count(&state, session), 1, "the ambient link");

    open(companion, session, None, "screen").expect("opens");
    assert_eq!(
        links.held_for_count(&state, session),
        2,
        "the screen's link and the ambient link"
    );
    assert_eq!(links.held_for_count(&state, other), 0, "another session's");
    assert_eq!(links.held(), 0, "none through this application's own slots");
    adopted.stop().await;
}

/// KR-REQ-19.08: the rights the phone is told are the ones the host decided, on the main connection
/// and on a screen's link alike, and not the ones its pairing proposed: a host whose configuration
/// takes a right away shows the phone one less.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_the_rights_a_phone_is_told_are_the_hosts_decision() {
    let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
    document.revision = 1;
    document.ceilings.grant_rights = Nullable::some(
        [ActionRight::SessionView, ActionRight::AgentPrompt]
            .iter()
            .map(|right| right.as_str().to_owned())
            .collect(),
    );
    let adopted = Adopted::start_with_document(1, &document).await;
    let session = adopted.workers[0].session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[
            ActionRight::SessionView,
            ActionRight::AgentPrompt,
            ActionRight::TerminalInput,
        ]),
    )
    .await;
    let main = phone
        .companion
        .call("connection_state", json!({}))
        .expect("the connection's state");
    let mut told: Vec<String> = serde_json::from_value(main["rights"].clone()).expect("rights");
    told.sort();
    assert_eq!(told, ["agent.prompt", "session.view"], "{main}");

    let standing = open(&phone.companion, session, None, "ceiling-screen").expect("opens");
    let mut told: Vec<String> =
        serde_json::from_value(standing["actions"].clone()).expect("rights");
    told.sort();
    assert_eq!(told, ["agent.prompt", "session.view"], "{standing}");
    adopted.stop().await;
}

/// The text of the lines a view state shows.
fn text_of(state: &Value) -> Vec<String> {
    state["screen"]["lines"]
        .as_array()
        .map(|lines| {
            lines
                .iter()
                .map(|line| {
                    line["pieces"]
                        .as_array()
                        .expect("pieces")
                        .iter()
                        .map(|piece| piece["text"].as_str().expect("text").to_owned())
                        .collect::<String>()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Opens a raw terminal view of `session` from the screen holding `opening`, publishing on
/// `channel`, and returns its handle.
fn open_view(
    companion: &Companion,
    session: SessionId,
    opening: &str,
    channel: u32,
) -> Result<String, Value> {
    companion
        .call(
            "terminal_view_open",
            json!({
                "sessionId": session.to_string(),
                "columns": 40,
                "rows": 8,
                "opening": opening,
                "onState": format!("__CHANNEL__:{channel}"),
            }),
        )
        .map(|handle| handle.as_str().expect("the view's handle").to_owned())
}

/// KR-REQ-19.08: a phone draws the terminal of a paired host's session, takes the input lease,
/// types a line that reaches the shell, and detaches, on a connection of the view's own: the
/// session's link and the view's are two, and the host shows no attachment once the view is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_phone_draws_a_paired_hosts_terminal_and_types_into_it() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[
            ActionRight::SessionView,
            ActionRight::TerminalInput,
            ActionRight::AgentPrompt,
        ]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "terminal-screen").expect("the session opens");

    let view = open_view(companion, session, "terminal-screen", 11).expect("the view opens");
    companion
        .state_where(11, |state| state["state"] == "showing")
        .await;
    companion
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": { "kind": "take", "number": 1 } }),
        )
        .expect("the take is taken");
    companion
        .state_where(11, |state| state["control"]["state"] == "controlling")
        .await;
    companion
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": { "kind": "text", "take": 1, "text": "kalareach-typed" } }),
        )
        .expect("the text is taken");
    companion
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": {
                "kind": "key", "take": 1, "key": "Enter", "base": null, "keypad": null,
                "shift": false, "alt": false, "control": false, "caps_lock": false,
                "num_lock": false, "event": "press",
            } }),
        )
        .expect("the key is taken");
    // `cat` is the session's shell: it writes back what reached it.
    let echoed = companion
        .state_where(11, |state| {
            text_of(state)
                .iter()
                .any(|line| line.contains("kalareach-typed"))
        })
        .await;
    assert_eq!(echoed["state"], "showing");

    // One attachment, the view's, and it goes with the view.
    let attachments = || worker.attachments();
    assert_eq!(attachments(), 1, "the view's attachment");
    companion
        .call("terminal_view_close", json!({ "view": view }))
        .expect("the view closes");
    let gone = tokio::time::timeout(WATCHDOG, async {
        while attachments() != 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await;
    assert!(
        gone.is_ok(),
        "the daemon shows no attachment once the view is closed"
    );
    adopted.stop().await;
}

/// KR-REQ-01.01: a session outlives the client that attached to it, and the companion's own screens
/// attach again. A phone types a line into a paired host's session and exits: its view, its screen
/// and its connection end, and the host's worker keeps the session and shows no attachment. The
/// application then starts again over the same records and secrets, reaches the host it chose
/// before, finds the session live, and its terminal view draws the line it left.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_01_01_a_phone_that_exited_finds_the_session_it_left_and_attaches_again() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let session = worker.session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[
            ActionRight::SessionView,
            ActionRight::TerminalInput,
            ActionRight::AgentPrompt,
        ]),
    )
    .await;
    let first = &phone.companion;
    open(first, session, None, "first-run").expect("the session opens");
    let view = open_view(first, session, "first-run", 11).expect("the view opens");
    first
        .state_where(11, |state| state["state"] == "showing")
        .await;
    first
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": { "kind": "take", "number": 1 } }),
        )
        .expect("the take is taken");
    first
        .state_where(11, |state| state["control"]["state"] == "controlling")
        .await;
    first
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": { "kind": "text", "take": 1, "text": "left-before-the-exit" } }),
        )
        .expect("the text is taken");
    first
        .state_where(11, |state| {
            text_of(state)
                .iter()
                .any(|line| line.contains("left-before-the-exit"))
        })
        .await;

    // The client exits: its view, its screen's link and its connection to the host all end, and it
    // reaches the host no more.
    control.unreachable(true);
    first
        .call("terminal_view_close", json!({ "view": view }))
        .expect("the view closes");
    leave(first, session, "first-run");
    let (_, _, main) = first
        .app
        .state::<companion_tauri::AppState>()
        .paired_snapshot()
        .expect("a connection");
    main.close();
    tokio::time::timeout(WATCHDOG, async {
        while worker.attachments() != 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the host shows no attachment once the client has gone");

    // The application starts again over the same records and secrets, and takes the host up.
    let again = Companion::start(
        phone.data.path(),
        support::parts(Arc::clone(&phone.secrets), Arc::clone(&phone.room)),
        Arc::new(support::NoOwner),
        support::StubIntake::holding("", false),
    );
    companion_tauri::hosts::resume(again.app.handle());
    connected(&again).await;

    // The session is still the host's, live, and the screen attaches to it again.
    let listed = again
        .call(
            "session_list",
            json!({ "params": { "environment_id": null, "include_closed": false } }),
        )
        .expect("the host lists its sessions");
    let sessions = listed["sessions"].as_array().expect("sessions");
    assert!(
        sessions
            .iter()
            .any(|each| each["session_id"] == session.to_string() && each["state"] == "live"),
        "{listed}"
    );
    open(&again, session, None, "second-run").expect("the session opens again");
    open_view(&again, session, "second-run", 11).expect("the view opens again");
    again
        .state_where(11, |state| {
            text_of(state)
                .iter()
                .any(|line| line.contains("left-before-the-exit"))
        })
        .await;
    assert_eq!(worker.attachments(), 1, "the new view's attachment alone");
    adopted.stop().await;
}

/// KR-REQ-19.08: under a share that includes the live screen and carries no terminal input, a
/// phone draws the session's terminal and is refused the input lease: the host holds the view to
/// the grant it was opened under, whatever the page asks.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_viewer_share_draws_the_terminal_and_is_refused_the_lease() {
    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let mut grant = pairing(&[ActionRight::SessionView]);
    grant.session_selector = kr_protocol::grant::SessionSelector::None;
    let phone = phone_under(&adopted, grant).await;
    let companion = &phone.companion;
    let share = shared_with(
        &adopted,
        &phone,
        session,
        RoleSelection {
            include_live_screen: true,
            ..RoleSelection::plain(SessionRole::Viewer)
        },
    )
    .await;
    open(companion, session, Some(share.grant_id), "viewer-screen").expect("the share opens");

    let view = open_view(companion, session, "viewer-screen", 21).expect("the view opens");
    companion
        .state_where(21, |state| state["state"] == "showing")
        .await;
    companion
        .call(
            "terminal_view_input",
            json!({ "view": view, "input": { "kind": "take", "number": 1 } }),
        )
        .expect("the take is taken by the view");
    let refused = companion
        .state_where(21, |state| {
            state["control"]["number"] == 1 && state["control"]["state"] == "watching"
        })
        .await;
    assert!(
        refused["control"]["ended"]
            .as_str()
            .is_some_and(|words| !words.is_empty()),
        "the host's refusal is told: {refused}"
    );
    companion
        .call("terminal_view_close", json!({ "view": view }))
        .expect("the view closes");
    adopted.stop().await;
}

/// KR-REQ-19.08: a share that does not include the live screen has no terminal to draw: the view
/// ends with the host's words and nothing was attached.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_share_without_the_live_screen_opens_no_view() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let session = worker.session_id;
    let mut grant = pairing(&[ActionRight::SessionView]);
    grant.session_selector = kr_protocol::grant::SessionSelector::None;
    let phone = phone_under(&adopted, grant).await;
    let companion = &phone.companion;
    let share = shared_with(
        &adopted,
        &phone,
        session,
        RoleSelection::plain(SessionRole::Viewer),
    )
    .await;
    open(companion, session, Some(share.grant_id), "dark-screen").expect("the share opens");

    open_view(companion, session, "dark-screen", 31).expect("a handle comes back at once");
    let ended = companion
        .state_where(31, |state| state["state"] == "ended")
        .await;
    assert!(
        ended["reason"]
            .as_str()
            .is_some_and(|words| words.contains("live screen")),
        "the host's words reach the page: {ended}"
    );
    assert_eq!(worker.attachments(), 0, "nothing was attached");
    adopted.stop().await;
}

/// KR-REQ-19.08: a share's end ends the view it carried and no other. The phone's view of its own
/// pairing's session, and that session's link, stand.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_shares_end_ends_its_view_and_not_another() {
    let adopted = Adopted::start(2).await;
    let (shared, own) = (&adopted.workers[0], &adopted.workers[1]);
    let mut grant = pairing(&[ActionRight::SessionView, ActionRight::TerminalInput]);
    grant.session_selector = kr_protocol::grant::SessionSelector::These {
        session_ids: [own.session_id].into_iter().collect(),
    };
    let phone = phone_under(&adopted, grant).await;
    let companion = &phone.companion;
    let share = shared_with(
        &adopted,
        &phone,
        shared.session_id,
        RoleSelection {
            include_live_screen: true,
            ..RoleSelection::plain(SessionRole::Viewer)
        },
    )
    .await;
    open(
        companion,
        shared.session_id,
        Some(share.grant_id),
        "share-screen",
    )
    .expect("opens");
    open(companion, own.session_id, None, "own-screen").expect("opens");
    let under_share = open_view(companion, shared.session_id, "share-screen", 41).expect("opens");
    let under_pairing = open_view(companion, own.session_id, "own-screen", 42).expect("opens");
    for channel in [41, 42] {
        companion
            .state_where(channel, |state| state["state"] == "showing")
            .await;
    }
    assert_eq!(shared.attachments(), 1);

    revoke(&adopted.host, share.grant_id).await;

    companion
        .state_where(41, |state| state["state"] == "ended")
        .await;
    heard(companion, "share-screen", |standing| {
        standing["state"] == "ended"
    })
    .await;
    assert_eq!(
        companion
            .states(42)
            .iter()
            .filter(|state| state["state"] == "ended")
            .count(),
        0,
        "the other view stands"
    );
    // The surviving view still takes the lease and types.
    companion
        .call(
            "terminal_view_input",
            json!({ "view": under_pairing, "input": { "kind": "take", "number": 1 } }),
        )
        .expect("taken");
    companion
        .state_where(42, |state| state["control"]["state"] == "controlling")
        .await;
    let _ = under_share;
    adopted.stop().await;
}

/// KR-REQ-19.08: a view whose own connection ends while its session's link and a prompt in flight
/// on it stand is recovered by the host being asked again on the link: the page is told the screen
/// is open and opens a new view, with a new attachment, and the prompt is not turned into anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_views_lost_connection_leaves_the_link_and_its_prompt_standing() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(net_support::worker::HeldUpstream::default());
    let instance = worker.register_agent_on(Arc::clone(&upstream) as _);
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[
            ActionRight::SessionView,
            ActionRight::AgentPrompt,
            ActionRight::TerminalInput,
        ]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "recovering-screen").expect("opens");
    let first = open_view(companion, session, "recovering-screen", 51).expect("opens");
    companion
        .state_where(51, |state| state["state"] == "showing")
        .await;

    let sending = companion.start_call(
        "agent_prompt_submit",
        json!({ "params": prompt(session, instance, "survives"), "opening": "recovering-screen" }),
    );
    tokio::time::timeout(WATCHDOG, async {
        while upstream.prompts().is_empty() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the prompt reaches the agent's upstream");

    let told = |state: &str| {
        companion
            .standing
            .texts()
            .iter()
            .filter(|text| {
                let event: Value = serde_json::from_str(text).expect("an event");
                event["opening"] == "recovering-screen" && event["standing"]["state"] == state
            })
            .count()
    };
    assert_eq!(
        told("open"),
        0,
        "an open that is not told again is not a recovery"
    );

    companion
        .app
        .state::<companion_tauri::terminal::TerminalViews>()
        .lose_connection(&first);
    companion
        .state_where(51, |state| state["state"] == "ended")
        .await;
    assert!(
        !sending.is_finished(),
        "the view's loss does not end the prompt on the link"
    );

    // The host answers one request at a time on a connection, so the question the phone asks again
    // on the live link is answered once the prompt is.
    upstream.release();
    let settled = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("answered")
        .expect("ran")
        .expect("the prompt was not turned into a refusal by the view's loss");
    assert!(
        settled["value"].is_object() || settled["receipt"].is_object(),
        "{settled}"
    );
    // The host is asked again on the live link and says the screen is open: the page opens a view
    // again.
    heard(companion, "recovering-screen", |standing| {
        standing["state"] == "open"
    })
    .await;
    let second = open_view(companion, session, "recovering-screen", 52).expect("opens again");
    companion
        .state_where(52, |state| state["state"] == "showing")
        .await;
    assert_ne!(first, second);
    assert_eq!(told("open"), 1);
    adopted.stop().await;
}

/// KR-REQ-19.08: a phone whose host holds a share for it sends each command that reaches a session
/// by the route the host accepts. The host-wide reads are answered on the main connection; each
/// command about a session goes on the link of the opening that session runs under, and the
/// worker answers it, or refuses it in its own words; what a paired host does not serve a device is
/// refused in words before anything is sent. A command that went over the main connection would be
/// refused by the host for serving no session. The share then ends, and the main connection still
/// answers the host-wide reads and the other session's link stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_every_command_that_reaches_a_session_goes_by_the_route_the_host_accepts() {
    use std::collections::BTreeSet;

    let adopted = Adopted::start(3).await;
    let (shared, own, spare) = (
        &adopted.workers[0],
        &adopted.workers[1],
        &adopted.workers[2],
    );
    let upstream = Arc::new(Upstream::default());
    let instance = shared.register_agent(Arc::clone(&upstream));
    shared.ask("shared");
    own.ask("own");
    let mut grant = pairing(&[
        ActionRight::SessionView,
        ActionRight::AgentPrompt,
        ActionRight::QuestionRespond,
        ActionRight::SessionClose,
    ]);
    grant.session_selector = kr_protocol::grant::SessionSelector::These {
        session_ids: [own.session_id, spare.session_id].into_iter().collect(),
    };
    let phone = phone_under(&adopted, grant).await;
    let companion = &phone.companion;
    let share = shared_with(
        &adopted,
        &phone,
        shared.session_id,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;
    open(
        companion,
        shared.session_id,
        Some(share.grant_id),
        "tour-share",
    )
    .expect("opens");
    open(companion, own.session_id, None, "tour-own").expect("opens");
    open(companion, spare.session_id, None, "tour-spare").expect("opens");
    let session = shared.session_id.to_string();

    // The commands the tour has called, to be held against the list of those that reach a session.
    let toured = std::cell::RefCell::new(BTreeSet::<&str>::new());
    let call = |command: &'static str, body: Value| {
        toured.borrow_mut().insert(command);
        companion.call(command, body)
    };
    let about = |command: &'static str, params: Value| {
        call(
            command,
            json!({ "params": params, "opening": "tour-share" }),
        )
    };
    // The worker's own refusal of what a bare call asks of it: the call reached the session's
    // worker on its opening's link, and was refused there in the worker's words.
    let refused_by_the_worker =
        |command: &str, answer: Result<Value, Value>, refusal_code: &str, words: &str| {
            let refusal = answer.expect_err("the worker refuses what the tour asks of it");
            assert_eq!(code(&refusal), refusal_code, "{command}: {refusal}");
            assert!(
                refusal["message"]
                    .as_str()
                    .is_some_and(|said| said.contains(words)),
                "{command} was refused in the worker's words, {words}: {refusal}"
            );
        };

    // The host-wide reads, on the main connection, whatever session they name.
    companion
        .call("host_info", json!({}))
        .expect("the host describes itself");
    companion
        .call("grant_held", json!({}))
        .expect("what the device holds is read on the host's connection");
    companion
        .call(
            "session_list",
            json!({ "params": { "environment_id": null, "include_closed": false } }),
        )
        .expect("the sessions are listed");
    companion
        .call(
            "session_read",
            json!({ "params": { "session_id": own.session_id.to_string() } }),
        )
        .expect("the pairing's session is read");
    companion
        .call(
            "session_describe",
            json!({ "params": { "session_id": own.session_id.to_string() } }),
        )
        .expect("the pairing's session is described");
    let unreachable = companion
        .call(
            "session_describe",
            json!({ "params": { "session_id": session } }),
        )
        .expect_err("a session only a share admits is not described on the host's connection");
    assert_eq!(code(&unreachable), "INVALID_ARGUMENT", "{unreachable}");
    companion
        .call(
            "attention_read",
            json!({ "params": {
                "session_id": null, "include_acknowledged": false, "max_items": 10, "after": null,
            } }),
        )
        .expect("the inbox is read");
    companion
        .call(
            "review_read",
            json!({ "params": {
                "session_id": null, "subject": null, "max_reviews": 10, "after": null,
            } }),
        )
        .expect("the reviews are read");

    // The commands about the shared session, on the link of its opening.
    call(
        "session_agents",
        json!({ "sessionId": session, "opening": "tour-share" }),
    )
    .expect("the agents are read");
    about(
        "agent_capabilities",
        json!({ "subject": subject(shared.session_id, instance) }),
    )
    .expect("the capabilities are read");
    about(
        "agent_commands",
        json!({ "subject": subject(shared.session_id, instance) }),
    )
    .expect("the commands are read");
    about(
        "agent_snapshot",
        json!({ "subject": subject(shared.session_id, instance), "from_node": null }),
    )
    .expect("the conversation is read");
    about(
        "question_read",
        json!({ "session_id": session, "question_id": null, "include_resolved": false }),
    )
    .expect("the questions are read");
    about(
        "agent_prompt_submit",
        prompt(shared.session_id, instance, "tour"),
    )
    .expect("the prompt is submitted");
    refused_by_the_worker(
        "agent_prompt_queue",
        about(
            "agent_prompt_queue",
            prompt(shared.session_id, instance, "queued"),
        ),
        "UNSUPPORTED_CAPABILITY",
        "agent.prompt.queue",
    );
    let target =
        json!({ "subject": subject(shared.session_id, instance), "binding_revision": "1" });
    refused_by_the_worker(
        "agent_turn_steer",
        about(
            "agent_turn_steer",
            json!({ "target": target, "turn_id": "turn-1", "text": "stop" }),
        ),
        "DRAFT_CONFLICT",
        "is not the turn this instance is running",
    );
    refused_by_the_worker(
        "agent_turn_cancel",
        about(
            "agent_turn_cancel",
            json!({ "target": target, "turn_id": "turn-1" }),
        ),
        "DRAFT_CONFLICT",
        "is not the turn this instance is running",
    );
    let none = ActionId::new(kr_ipc::new_uuid()).to_string();
    refused_by_the_worker(
        "agent_approval_inspect",
        about(
            "agent_approval_inspect",
            json!({ "subject": subject(shared.session_id, instance), "resource_id": none }),
        ),
        "STALE_SESSION",
        "no interpreted approval",
    );
    refused_by_the_worker(
        "agent_approval_respond",
        about(
            "agent_approval_respond",
            json!({ "target": target, "resource_id": none, "option_id": "approve" }),
        ),
        "STALE_SESSION",
        "no pending resource",
    );
    refused_by_the_worker(
        "plugin_action_invoke",
        about(
            "plugin_action_invoke",
            json!({
                "target": target,
                "plugin_id": "kalareach.codex",
                "action": "turn.cancel",
                "draft_id": null,
                "resource_id": null,
                "parameters": "e30",
            }),
        ),
        "STALE_SESSION",
        "is not an action",
    );
    // A receipt the worker does not hold is the worker's own answer: the read reached it on the
    // session's link and was not refused on the way.
    let unheld = ActionId::new(kr_ipc::new_uuid()).to_string();
    let unknown = about(
        "action_read",
        json!({ "action_id": unheld, "session_id": session }),
    )
    .expect_err("the worker holds no such receipt");
    assert!(
        unknown["message"]
            .as_str()
            .is_some_and(|words| words.contains("no receipt")),
        "the worker says it holds no receipt: {unknown}"
    );
    let unnamed = call(
        "action_read",
        json!({ "params": { "action_id": unheld, "session_id": session } }),
    )
    .expect_err("a receipt is not read without the screen it belongs to");
    assert_eq!(code(&unnamed), "INVALID_ARGUMENT", "{unnamed}");
    refused_by_the_worker(
        "action_cancel",
        call(
            "action_cancel",
            json!({
                "params": { "action_id": unheld },
                "subject": { "sessionId": session, "sessionEpoch": "1" },
                "opening": "tour-share",
            }),
        ),
        "INVALID_ARGUMENT",
        "no receipt for action",
    );
    call(
        "question_settle",
        json!({ "params": { "sessionId": session }, "opening": "tour-share" }),
    )
    .expect("the kept answers are settled");
    // Nothing is kept here, so this is refused by the application with words; a kept answer is
    // settled and sent on the screen's link by its own test.
    let none_kept = call(
        "question_send_kept",
        json!({
            "params": { "questionId": ActionId::new(kr_ipc::new_uuid()).to_string(), "draftedAtMs": 1 },
            "opening": "tour-share",
        }),
    )
    .expect_err("no answer is kept");
    assert_eq!(code(&none_kept), "INVALID_ARGUMENT", "{none_kept}");
    // A question of the pairing's own session is read and answered on that session's link.
    let read = call(
        "question_read",
        json!({
            "params": { "session_id": own.session_id.to_string(), "question_id": null, "include_resolved": false },
            "opening": "tour-own",
        }),
    )
    .expect("the questions are read");
    let listed = &read["questions"][0];
    let answered = call(
        "question_answer",
        json!({
            "params": {
                "session_id": own.session_id.to_string(),
                "question_id": listed["question_id"],
                "expected_revision": listed["revision"],
                "answer": { "kind": "decision", "decided": true },
            },
            "opening": "tour-own",
        }),
    )
    .expect("the question is answered on its session's link");
    assert_eq!(answered["outcome"], "taken", "{answered}");
    // A session is closed on the link of the opening it runs under.
    call(
        "session_close",
        json!({
            "params": { "session_id": spare.session_id.to_string() },
            "subject": { "sessionId": spare.session_id.to_string(), "sessionEpoch": "1" },
            "opening": "tour-spare",
        }),
    )
    .expect("the session is closed on the link of its opening");

    // A page of retained output is read on the link of the opening, and the host narrows it to the
    // share's history, which begins when the share was issued: the session has written nothing
    // since, so the page is whole and holds none of it.
    let page = about(
        "history_page",
        json!({ "session_id": session, "from_cursor": "0", "max_bytes": "4096" }),
    )
    .expect("the page is read on the link of the share's opening");
    assert_eq!(page["bytes"], "", "{page}");

    // The launch surface is read on the share's own link, and the host forwards the read to the
    // session's worker.
    let surface = about("launch_surface", json!({ "session_id": session }))
        .expect("the launch surface is read on the link of the share's opening");
    assert_eq!(surface["state"], "served", "{surface}");

    // What a paired host does not serve a device is refused in words, before anything is sent.
    for (command, body) in [
        ("draft_create", json!({ "params": {}, "subject": {} })),
        (
            "draft_add_attachment",
            json!({ "params": {}, "subject": {} }),
        ),
        (
            "attachment_upload",
            json!({ "path": "/tmp/none", "subject": {}, "sessionId": session }),
        ),
        ("attachment_upload_bytes", json!({})),
    ] {
        let refused = call(command, body).expect_err("not offered over a paired host");
        assert_eq!(
            code(&refused),
            "RESOURCE_UNAVAILABLE",
            "{command}: {refused}"
        );
    }

    // Every command that reaches a session was called, except the ones the terminal tests call
    // (a view is opened under an opening there) and the opening's own two.
    let elsewhere = ["terminal_view_open", "session_open", "session_leave"];
    let missed: Vec<_> = companion_tauri::commands::SESSION_BOUND_COMMANDS
        .iter()
        .filter(|command| !elsewhere.contains(command) && !toured.borrow().contains(**command))
        .collect();
    assert!(missed.is_empty(), "the tour did not call {missed:?}");

    // The share ends: the host-wide reads and the other session's link are untouched.
    revoke(&adopted.host, share.grant_id).await;
    heard(companion, "tour-share", |standing| {
        standing["state"] == "ended"
    })
    .await;
    companion
        .call(
            "session_list",
            json!({ "params": { "environment_id": null, "include_closed": false } }),
        )
        .expect("the main connection stands");
    companion
        .call(
            "session_describe",
            json!({ "params": { "session_id": own.session_id.to_string() } }),
        )
        .expect("the pairing's session is still described");
    companion
        .call(
            "question_read",
            json!({
                "params": { "session_id": own.session_id.to_string(), "question_id": null, "include_resolved": false },
                "opening": "tour-own",
            }),
        )
        .expect("the other session's link stands");
    adopted.stop().await;
}

/// KR-REQ-19.08: the sessions opened on a host are let go with it. Once the host in use is
/// forgotten, a screen's commands are refused and no link is kept for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_forgetting_the_host_lets_its_sessions_go() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let phone = phone_under(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    open(companion, session, None, "forgotten-screen").expect("the session opens");
    let agents = |opening: &str| {
        companion.call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": opening }),
        )
    };
    agents("forgotten-screen").expect("the screen is served");
    let held = || {
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .opened()
    };
    assert_eq!(held(), 1);

    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let reference = view["hosts"][0]["reference"].as_str().expect("a reference");
    companion
        .call("hosts_forget", json!({ "reference": reference }))
        .expect("the host in use is forgotten");

    assert_eq!(held(), 0, "no link is kept for a host that was forgotten");
    agents("forgotten-screen").expect_err("the screen is no longer served");
    adopted.stop().await;
}

/// A phone paired with the host under `grant`, in contact with it, whose connections to the host
/// the test governs once it says so.
async fn phone_governed(
    adopted: &Adopted,
    grant: kr_protocol::pairing::ProposedGrant,
) -> (Phone, Arc<LinkControl>) {
    let control = LinkControl::new();
    let phone = unpaired_phone_controlled(&adopted.host, &control);
    pair_under(&phone, &adopted.host, &adopted.owner, grant).await;
    connected(&phone.companion).await;
    (phone, control)
}

/// Waits until `held` connections are held.
async fn held(control: &LinkControl, count: usize) {
    tokio::time::timeout(WATCHDOG, async {
        while control.held() != count {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{count} connections are held, not {}", control.held()));
}

/// The call that opens `session` for `opening`, made and left to answer.
fn opening_call(
    companion: &Companion,
    session: SessionId,
    grant: Option<GrantId>,
    opening: &str,
) -> tokio::task::JoinHandle<Result<Value, Value>> {
    companion.start_call(
        "session_open",
        json!({
            "sessionId": session.to_string(),
            "grantId": grant.map(|grant| grant.to_string()),
            "opening": opening,
        }),
    )
}

/// KR-REQ-19.08: a place among the eight is held from the call to open, not from the link made. Nine
/// sessions opened together are refused at the ninth whichever connection answers first, and the
/// host is asked for eight connections and no more.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_nine_opens_made_together_hold_eight() {
    use tauri::Manager as _;

    let adopted = Adopted::start(9).await;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    let asked = control.asked();
    control.hold();

    let calls: Vec<_> = adopted
        .workers
        .iter()
        .enumerate()
        .map(|(n, worker)| opening_call(companion, worker.session_id, None, &format!("many-{n}")))
        .collect();
    held(&control, 8).await;
    // The ninth was refused before any connection was asked for.
    let refused: Vec<_> = tokio::time::timeout(WATCHDOG, async {
        loop {
            let done: Vec<_> = calls.iter().filter(|call| call.is_finished()).collect();
            if !done.is_empty() {
                return done.len();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .map(|count| vec![count])
    .expect("the ninth is refused at once");
    assert_eq!(refused, [1]);
    assert_eq!(control.asked() - asked, 8, "the host is asked for eight");

    control.stop_holding();
    control.release_all();
    let mut opened = 0;
    let mut turned_away = Vec::new();
    for call in calls {
        match call.await.expect("the call ran") {
            Ok(standing) => {
                assert_eq!(standing["state"], "open", "{standing}");
                opened += 1;
            }
            Err(refusal) => turned_away.push(refusal),
        }
    }
    assert_eq!(opened, 8);
    assert_eq!(turned_away.len(), 1, "{turned_away:?}");
    assert_eq!(code(&turned_away[0]), "RESOURCE_UNAVAILABLE");
    assert_eq!(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .opened(),
        8
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: another opening of a session is the session's from the moment it is asked for. The
/// first opening is over then: its commands are refused while the second is still being made, and
/// when the second fails nothing is left of the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_an_opening_that_replaces_another_ends_it_at_once() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "first").expect("the first opens");
    let read = |opening: &str| {
        companion.call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": opening }),
        )
    };
    read("first").expect("the first is served");

    control.hold();
    let second = opening_call(companion, session, None, "second");
    held(&control, 1).await;
    let stale = read("first").expect_err("the first is over while the second is being made");
    assert_eq!(code(&stale), "STALE_SESSION", "{stale}");
    let links = || {
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .opened()
    };
    assert_eq!(links(), 0, "the first's link is let go at once");

    // The host refuses the second at the handshake, and nothing of the first comes back.
    control.refuse(Some(kr_protocol::error::ErrorCode::PermissionDenied));
    control.stop_holding();
    control.release_all();
    let refused = second
        .await
        .expect("the call ran")
        .expect_err("the second is refused");
    assert_eq!(code(&refused), "PERMISSION_DENIED", "{refused}");
    assert_eq!(links(), 0);
    let gone = read("first").expect_err("the first stays over");
    assert_eq!(code(&gone), "STALE_SESSION", "{gone}");
    adopted.stop().await;
}

/// KR-REQ-19.08: two openings of one session whose connections complete in the other order leave
/// the later one's link. The earlier one's open answers that it was superseded and installs nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_two_opens_that_complete_in_reverse_order_leave_the_later_one() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;

    control.hold();
    let first = opening_call(companion, session, None, "earlier");
    held(&control, 1).await;
    let second = opening_call(companion, session, None, "later");
    held(&control, 2).await;

    // The later one's connection completes first.
    control.release(1);
    let later = second
        .await
        .expect("the call ran")
        .expect("the later opens");
    assert_eq!(later["state"], "open", "{later}");
    control.release(0);
    let earlier = first.await.expect("the call ran").expect("an answer");
    assert_eq!(earlier["state"], "superseded", "{earlier}");

    let agents = |opening: &str| {
        companion.call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": opening }),
        )
    };
    agents("later").expect("the later is served");
    let stale = agents("earlier").expect_err("the earlier is not");
    assert_eq!(code(&stale), "STALE_SESSION", "{stale}");
    assert_eq!(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .opened(),
        1
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: a screen left while its open is still being made leaves no link: the open answers
/// that it was superseded, and the connection it made is closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_leave_while_the_open_is_in_flight_leaves_no_link() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;

    control.hold();
    let opening = opening_call(companion, session, None, "left-early");
    held(&control, 1).await;
    leave(companion, session, "left-early");
    control.stop_holding();
    control.release_all();
    let answered = opening.await.expect("the call ran").expect("an answer");
    assert_eq!(answered["state"], "superseded", "{answered}");
    assert_eq!(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .opened(),
        0
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: a host that cannot be reached when a session is opened does not fail the open: the
/// opening stands as `reconnecting`, its commands say it is being reached, and it is reached again
/// as the same opening when the host can be, with no second call from the page.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_an_open_made_while_the_host_is_down_reaches_it_when_it_can() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    worker.ask("one");
    let session = worker.session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;

    control.unreachable(true);
    let standing = open(companion, session, None, "waiting").expect("the open is not refused");
    assert_eq!(standing["state"], "reconnecting", "{standing}");
    let read = || {
        companion.call(
            "question_read",
            json!({
                "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
                "opening": "waiting",
            }),
        )
    };
    let waiting = read().expect_err("a screen with no link yet has nothing to ask");
    assert_eq!(code(&waiting), "RESOURCE_UNAVAILABLE", "{waiting}");

    control.unreachable(false);
    let reached = heard(companion, "waiting", |standing| standing["state"] == "open").await;
    assert_eq!(reached["standing"]["via"], "pairing", "{reached}");
    read().expect("the opening is served on the link it reached");
    adopted.stop().await;
}

/// KR-REQ-19.08: a host that refuses the device at admission is told as a refusal only once a
/// second probe agrees: one refusal can be a grant changing between the host's reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_refusal_is_told_after_two_probes_agree() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    open(companion, session, None, "probed").expect("the session opens");

    control.refuse(Some(kr_protocol::error::ErrorCode::PermissionDenied));
    let before = control.asked();
    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_links()
        .lose_connection(session);
    let told = heard(companion, "probed", |standing| {
        standing["state"] == "refused"
    })
    .await;
    assert_eq!(told["standing"]["code"], "PERMISSION_DENIED", "{told}");
    assert_eq!(control.asked() - before, 2, "two probes agreed");
    adopted.stop().await;
}

/// KR-REQ-19.08: a host's refusal of a connection that is not for now, which a session's first open
/// reads, does not end the opening. A revocation that lands between the device's handshake and its
/// admission, and a daemon that has stopped while its listener still accepts, each refuse once and
/// not again: the opening stands as reconnecting and reaches the host again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_refusal_at_the_first_open_that_does_not_repeat_leaves_the_opening_standing()
{
    use kr_protocol::error::ErrorCode;

    for code in [ErrorCode::PermissionDenied, ErrorCode::HostNotConfigured] {
        let adopted = Adopted::start(1).await;
        let session = adopted.workers[0].session_id;
        let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
        let companion = &phone.companion;

        control.refuse_the_connection(Some(code));
        let standing = open(companion, session, None, "first")
            .unwrap_or_else(|refused| panic!("{code:?} at the first open ended it: {refused}"));
        assert_eq!(standing["state"], "reconnecting", "{code:?}: {standing}");
        control.refuse_the_connection(None);
        let reached = heard(companion, "first", |standing| standing["state"] == "open").await;
        assert_eq!(reached["standing"]["via"], "pairing", "{code:?}: {reached}");
        adopted.stop().await;
    }
}

/// What the page was told of the opening `opening` so far, in the order it was told.
fn told_of(companion: &Companion, opening: &str) -> Vec<Value> {
    companion
        .standing
        .texts()
        .iter()
        .map(|text| serde_json::from_str::<Value>(text).expect("an event"))
        .filter(|event| event["opening"] == opening)
        .map(|event| event["standing"].clone())
        .collect()
}

/// Waits until the host has been asked for `count` connections since `before`.
async fn asked_since(control: &LinkControl, before: usize, count: usize) {
    tokio::time::timeout(WATCHDOG, async {
        while control.asked() - before < count {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the host was asked {} times", control.asked() - before));
}

/// KR-REQ-19.08: a refusal of the connection at its admission that repeats does not end a session's
/// opening either: the host decided about the connection, not about the opening, so the opening
/// stands as reconnecting, as it did when the refusal was not read, and its watch asks on, with the
/// host's words as the reason it shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_refusal_at_admission_that_repeats_leaves_the_opening_standing() {
    use kr_protocol::error::ErrorCode;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;

    control.refuse_the_connection(Some(ErrorCode::PermissionDenied));
    let before = control.asked();
    let standing = open(companion, session, None, "repeated").expect("the first open stands");
    assert_eq!(standing["state"], "reconnecting", "{standing}");
    asked_since(&control, before, 4).await;
    for told in told_of(companion, "repeated") {
        assert_eq!(told["state"], "reconnecting", "never refused: {told}");
        assert!(
            told["reason"]
                .as_str()
                .is_some_and(|reason| reason.contains("the host refused the connection")),
            "the host's words stay the reason: {told}"
        );
    }
    control.refuse_the_connection(None);
    let reached = heard(companion, "repeated", |standing| {
        standing["state"] == "open"
    })
    .await;
    assert_eq!(reached["standing"]["via"], "pairing", "{reached}");
    adopted.stop().await;
}

/// KR-REQ-19.08: a refusal at the handshake (a version, a pairing) is the host's decision about this
/// device, and ends a session's first open at once with its words, as it did before the host's
/// refusal of a connection was read.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_refusal_at_the_handshake_ends_the_first_open_at_once() {
    use kr_protocol::error::ErrorCode;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;

    control.refuse(Some(ErrorCode::PermissionDenied));
    let before = control.asked();
    let refused =
        open(companion, session, None, "handshake").expect_err("the host's refusal ends the open");
    assert_eq!(code(&refused), "PERMISSION_DENIED", "{refused}");
    assert_eq!(control.asked() - before, 1, "the host was asked once");
    adopted.stop().await;
}

/// KR-REQ-19.08: a command that names no opening is served on the session's ambient link, and when
/// the host refuses the connection that link needs at its admission, for a reason that is not its
/// bound, the command is answered as it is when a connection is lost: with the code and the retry
/// category of a host that cannot be reached for now and with the host's words. The code that the
/// host refused the connection with is for the connection, not for the command, and the page ends
/// or refuses on a `PERMISSION_DENIED` that it never got from the command.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_an_ambient_command_whose_connection_the_host_refuses_at_admission_is_answered_as_a_lost_one()
 {
    use kr_protocol::error::ErrorCode;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;

    for code in [ErrorCode::PermissionDenied, ErrorCode::HostNotConfigured] {
        control.refuse_the_connection(Some(code));
        let refused = companion
            .call(
                "question_read",
                json!({
                    "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
                }),
            )
            .expect_err("the host refused the connection the command needed");
        assert_eq!(
            refused["code"], "RESOURCE_UNAVAILABLE",
            "{code:?}: {refused}"
        );
        assert_eq!(refused["retry"], "transient", "{code:?}: {refused}");
        assert!(
            refused["message"]
                .as_str()
                .is_some_and(|words| words.contains("the host refused the connection")),
            "{code:?}: the host's words: {refused}"
        );
    }
    control.refuse_the_connection(None);
    adopted.stop().await;
}

/// KR-REQ-19.08: a device that the host revokes between its handshake and its admission is refused
/// at admission once, and then answered as an unpaired peer, which ends each later connection as a
/// connection lost. The opening stands, and the words the person reads stay the host's first, not a
/// statement that the host was not reached. The revocation is the host's own: the device's record
/// is withdrawn at the host while it holds the connection before it registers it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_device_revoked_before_its_admission_keeps_the_hosts_words_at_its_first_open()
 {
    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    let device_id = companion.device().host_in_use().expect("a host").device_id;

    let (arrived, release) = adopted.host.controller().pause_connection_registration();
    let opening = opening_call(companion, session, None, "revoked");
    arrived
        .await
        .expect("the host holds the connection before it registers it");
    adopted
        .host
        .controller()
        .revoke_device_authority(device_id, None, None)
        .await
        .expect("the revocation is recorded");
    release.send(()).expect("the host is still holding it");
    let standing = opening
        .await
        .expect("the call ends")
        .expect("the first open stands");
    assert_eq!(standing["state"], "reconnecting", "{standing}");
    let first = standing["reason"]
        .as_str()
        .expect("the host's words")
        .to_owned();
    assert!(first.contains("withdrawn"), "the host's words: {first}");

    // Each ask that follows is answered as an unpaired peer's: it does not reach the host.
    let before = control.asked();
    asked_since(&control, before, 3).await;
    for told in told_of(companion, "revoked") {
        assert_eq!(told["state"], "reconnecting", "{told}");
        assert_eq!(
            told["reason"],
            first.as_str(),
            "the first words stay: {told}"
        );
    }
    adopted.stop().await;
}

/// KR-REQ-19.08: an ambient call whose connection was being made when the host changed serves
/// nothing and leaves no link: the host it was made for is not the host in use.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_an_ambient_open_the_host_changed_under_serves_nothing() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    worker.ask("one");
    let session = worker.session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;

    control.hold();
    let asking = companion.start_call(
        "question_read",
        json!({
            "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
        }),
    );
    held(&control, 1).await;
    let view = companion
        .call("pairing_view", json!({}))
        .expect("the pairing screen");
    let reference = view["hosts"][0]["reference"].as_str().expect("a reference");
    companion
        .call("hosts_forget", json!({ "reference": reference }))
        .expect("the host in use is forgotten");
    control.stop_holding();
    control.release_all();

    let refused = asking
        .await
        .expect("the call ran")
        .expect_err("a connection made for the host that was forgotten serves nothing");
    assert_eq!(code(&refused), "RESOURCE_UNAVAILABLE", "{refused}");
    assert_eq!(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .ambient(),
        0
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: the main connection being down does not take a screen's own link with it: a
/// question is read and answered on the link of the opening, which is the paired route whether or
/// not the connection for the host alone is up.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_question_is_answered_on_the_screens_link_while_the_main_connection_is_down()
{
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let asked = worker.ask("main-down");
    let session = worker.session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "alone").expect("the session opens");

    // The host cannot be reached again, and the connection for the host alone ends.
    control.unreachable(true);
    let (_, _, main) = companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_snapshot()
        .expect("a connection");
    main.close();
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let state = companion
                .call("connection_state", json!({}))
                .expect("the connection's state");
            if state["connected"] == false {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the connection for the host alone ends");

    let read = companion
        .call(
            "question_read",
            json!({
                "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
                "opening": "alone",
            }),
        )
        .expect("read on the screen's link");
    let listed = &read["questions"][0];
    assert_eq!(listed["question_id"], asked.question_id.to_string());
    let answered = companion
        .call(
            "question_answer",
            json!({
                "params": {
                    "session_id": session.to_string(),
                    "question_id": asked.question_id.to_string(),
                    "expected_revision": listed["revision"],
                    "answer": { "kind": "decision", "decided": true },
                },
                "opening": "alone",
            }),
        )
        .expect("answered on the screen's link");
    assert_eq!(answered["outcome"], "taken", "{answered}");
    adopted.stop().await;
}

/// KR-REQ-19.08: calls made together from outside any screen for one session share one connection:
/// the host is asked for one, and every call is answered on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_ambient_calls_for_one_session_share_one_open() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    worker.ask("one");
    let session = worker.session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;
    let asked = control.asked();
    control.hold();

    let calls: Vec<_> = (0..3)
        .map(|_| {
            companion.start_call(
                "question_read",
                json!({
                    "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
                }),
            )
        })
        .collect();
    held(&control, 1).await;
    control.stop_holding();
    control.release_all();
    for call in calls {
        call.await.expect("the call ran").expect("answered");
    }
    // The three calls were answered, and the host was asked for one connection among them.
    assert_eq!(control.asked() - asked, 1, "one connection is asked for");
    assert_eq!(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .ambient(),
        1
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: a place among the four ambient links is not made by letting go of a link a call is
/// using. With four calls using the four and a fifth wanting a place, the fifth waits, and every
/// call is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_busy_ambient_link_is_not_let_go_for_a_fifth() {
    use tauri::Manager as _;

    let adopted = Adopted::start(5).await;
    for worker in &adopted.workers {
        worker.ask("one");
    }
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;
    let asked = control.asked();
    control.hold();

    let calls: Vec<_> = adopted
        .workers
        .iter()
        .map(|worker| {
            companion.start_call(
                "question_read",
                json!({
                    "params": { "session_id": worker.session_id.to_string(), "question_id": null, "include_resolved": false },
                }),
            )
        })
        .collect();
    held(&control, 4).await;
    // One of the four is answered, which frees its place: only then is a connection asked for the
    // fifth, and none of the four was let go for it.
    control.release(0);
    tokio::time::timeout(WATCHDOG, async {
        while control.asked() - asked != 5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the fifth is asked for once a place is free");
    control.stop_holding();
    control.release_all();
    for call in calls {
        call.await
            .expect("the call ran")
            .expect("answered on a link nobody let go");
    }
    assert!(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .ambient()
            <= 4
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: another opening of a session ends the first under a prompt it has in flight. The
/// prompt is not answered as taken: it ends as a connection that ended does, and the second
/// opening is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_second_opening_ends_the_first_under_its_pending_prompt() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(net_support::worker::HeldUpstream::default());
    let instance = worker.register_agent_on(Arc::clone(&upstream) as _);
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "first-of-two").expect("opens");

    let sending = companion.start_call(
        "agent_prompt_submit",
        json!({ "params": prompt(session, instance, "pending"), "opening": "first-of-two" }),
    );
    tokio::time::timeout(WATCHDOG, async {
        while upstream.prompts().is_empty() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the prompt reaches the agent's upstream");

    open(companion, session, None, "second-of-two").expect("the second opens");
    // The first's link was closed under its prompt: the answer names the action and carries no
    // receipt and no result, which the page reads as an outcome nobody knows. It is not a taken
    // prompt.
    let answer = tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("answered")
        .expect("ran")
        .expect("the prompt ends as a connection that ended does");
    assert!(answer["action_id"].is_string(), "{answer}");
    assert!(
        answer["receipt"].is_null() && answer["value"].is_null(),
        "{answer}"
    );
    let stale = companion
        .call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": "first-of-two" }),
        )
        .expect_err("the first is over");
    assert_eq!(code(&stale), "STALE_SESSION", "{stale}");
    companion
        .call(
            "session_agents",
            json!({ "sessionId": session.to_string(), "opening": "second-of-two" }),
        )
        .expect("the second is served");
    upstream.release();
    adopted.stop().await;
}

/// KR-REQ-19.08: a view that ends because the session detached it is not a lost connection: the
/// page is told why and the host is not asked again what the opening allows, so a view that
/// stopped for another reason is not opened again by the page.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_detached_view_is_not_taken_for_a_lost_connection() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::TerminalInput]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "detached-screen").expect("opens");
    let view = open_view(companion, session, "detached-screen", 61).expect("opens");
    companion
        .state_where(61, |state| state["state"] == "showing")
        .await;

    worker.detach_attachments();
    let ended = companion
        .state_where(61, |state| state["state"] == "ended")
        .await;
    assert!(
        ended["reason"]
            .as_str()
            .is_some_and(|words| words.contains("detached")),
        "{ended}"
    );
    // Nothing asks the host again: the view is over, and no view that lost its connection has had
    // the host asked about it.
    companion
        .call("terminal_view_close", json!({ "view": view }))
        .expect("the view is closed");
    assert_eq!(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .rechecks(),
        0
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: a view whose own connection ends as it is made, before it has drawn a screen, is
/// a lost connection too: the host is asked again on the opening's live link, and the page opens a
/// view again once the connection holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_view_whose_connection_ends_as_it_is_made_is_recovered() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::TerminalInput]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "dropped-screen").expect("opens");

    control.end_connections(true);
    let view = open_view(companion, session, "dropped-screen", 62).expect("a handle comes back");
    companion
        .state_where(62, |state| state["state"] == "ended")
        .await;
    // The host is asked on the live link, and says the screen is open: the page opens a view again.
    heard(companion, "dropped-screen", |standing| {
        standing["state"] == "open"
    })
    .await;
    assert_eq!(
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_links()
            .rechecks(),
        1
    );
    control.end_connections(false);
    let again = open_view(companion, session, "dropped-screen", 63).expect("opens again");
    assert_ne!(view, again);
    companion
        .state_where(63, |state| state["state"] == "showing")
        .await;
    adopted.stop().await;
}

/// KR-REQ-19.08: a view whose own connection cannot be made, because the host cannot be reached for
/// it while the screen's link stands, is recovered the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_view_whose_connection_cannot_be_made_is_recovered() {
    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::TerminalInput]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "unreached-screen").expect("opens");

    control.unreachable(true);
    open_view(companion, session, "unreached-screen", 64).expect("a handle comes back");
    companion
        .state_where(64, |state| state["state"] == "ended")
        .await;
    heard(companion, "unreached-screen", |standing| {
        standing["state"] == "open"
    })
    .await;
    control.unreachable(false);
    open_view(companion, session, "unreached-screen", 65).expect("opens again");
    companion
        .state_where(65, |state| state["state"] == "showing")
        .await;
    adopted.stop().await;
}

/// KR-REQ-19.08: a host that refuses the connection a raw view opens, because it holds as many from
/// this computer as it allows, is told to the view as that: the refusal the host sent, from the view's
/// own wire, whether the request's write failed or not. The same code on a refusal of the connection
/// for another reason is not the host's bound, and the view says that refusal's words.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_view_whose_connection_the_host_refuses_says_why() {
    use kr_protocol::error::ErrorCode;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::TerminalInput]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "refused-screen").expect("opens");

    control.refuse_the_connection(Some(ErrorCode::ResourceUnavailable));
    open_view(companion, session, "refused-screen", 66).expect("a handle comes back");
    let ended = companion
        .state_where(66, |state| state["state"] == "ended")
        .await;
    let reason = ended["reason"]
        .as_str()
        .expect("the view says why")
        .to_owned();
    assert!(
        reason.contains("cannot take another connection"),
        "the host's bound, and not the connection having ended: {reason}"
    );

    control.refuse_the_connection(Some(ErrorCode::PermissionDenied));
    open_view(companion, session, "refused-screen", 67).expect("a handle comes back");
    let ended = companion
        .state_where(67, |state| state["state"] == "ended")
        .await;
    let reason = ended["reason"]
        .as_str()
        .expect("the view says why")
        .to_owned();
    assert!(
        !reason.contains("cannot take another connection") && !reason.contains("connection ended"),
        "a refusal of the connection for another reason says its own words: {reason}"
    );
    control.refuse_the_connection(None);
    adopted.stop().await;
}

/// KR-REQ-19.08: a raw view's own connection that the host refuses at its admission, for a reason
/// that is not its bound (an authority withdrawn since the handshake, a daemon that has stopped
/// while its listener accepts), is a lost connection, as it was before the host's refusal was read:
/// the view ends with the host's words, the host is asked again on the opening's live link, and the
/// page opens a view again. It holds whether the refusal reaches the view before its first request
/// is written or after the write has failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_view_whose_connection_the_host_refuses_at_admission_is_lost_and_opened_again()
 {
    use kr_protocol::error::ErrorCode;
    use tauri::Manager as _;

    for (n, (code, write_fails)) in [
        (ErrorCode::PermissionDenied, false),
        (ErrorCode::PermissionDenied, true),
        (ErrorCode::HostNotConfigured, false),
        (ErrorCode::HostNotConfigured, true),
    ]
    .into_iter()
    .enumerate()
    {
        let adopted = Adopted::start(1).await;
        let session = adopted.workers[0].session_id;
        let (phone, control) = phone_governed(
            &adopted,
            pairing(&[ActionRight::SessionView, ActionRight::TerminalInput]),
        )
        .await;
        let companion = &phone.companion;
        let opening = format!("admission-{n}");
        open(companion, session, None, &opening).expect("opens");

        control.refuse_the_connection(Some(code));
        control.end_connections(write_fails);
        let channel = 70 + u32::try_from(n).expect("a small number");
        open_view(companion, session, &opening, channel).expect("a handle comes back");
        let ended = companion
            .state_where(channel, |state| state["state"] == "ended")
            .await;
        let reason = ended["reason"].as_str().expect("the view says why");
        assert!(
            reason.contains("the host refused the connection"),
            "{code:?}, write fails {write_fails}: the host's words stay the reason: {reason}"
        );
        // The view is lost, so the host is asked on the opening's live link, and says the screen is
        // open: the page opens a view again.
        heard(companion, &opening, |standing| standing["state"] == "open").await;
        assert_eq!(
            companion
                .app
                .state::<companion_tauri::AppState>()
                .paired_links()
                .rechecks(),
            1,
            "{code:?}, write fails {write_fails}: the view was lost, not ended for good"
        );
        control.refuse_the_connection(None);
        control.end_connections(false);
        open_view(companion, session, &opening, channel + 10).expect("opens again");
        companion
            .state_where(channel + 10, |state| state["state"] == "showing")
            .await;
        adopted.stop().await;
    }
}

/// What the connection's state says: whether the main connection is up, and why not.
fn connection_reason(companion: &Companion) -> (bool, Option<String>) {
    let state = companion
        .call("connection_state", json!({}))
        .expect("the connection's state");
    (
        state["connected"] == true,
        state["reason"].as_str().map(str::to_owned),
    )
}

/// Waits until the main connection is down with a reason that `holds`.
async fn connection_down_where(companion: &Companion, holds: impl Fn(&str) -> bool) -> String {
    tokio::time::timeout(WATCHDOG, async {
        loop {
            if let (false, Some(reason)) = connection_reason(companion)
                && holds(&reason)
            {
                return reason;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the connection's reason is told")
}

/// KR-REQ-19.08: the words a person reads while the main connection is not made are the host's for a
/// connection that it did not admit, and they stay while the tries that follow do not reach the
/// host. A connection that opens clears them, and any other cause (the host's bound) replaces them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_the_main_connection_keeps_the_hosts_words_while_later_tries_do_not_reach_the_host()
 {
    use kr_protocol::error::ErrorCode;
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    let host_words = |reason: &str| reason.contains("the host refused the connection");
    let end_main_connection = || {
        companion
            .app
            .state::<companion_tauri::AppState>()
            .paired_snapshot()
            .expect("a connection")
            .2
            .close();
    };

    // The host refuses the connection it is asked for at its admission: the words are the host's.
    control.refuse_the_connection(Some(ErrorCode::PermissionDenied));
    end_main_connection();
    let first = connection_down_where(companion, host_words).await;

    // The tries that follow do not reach the host: the host's words stay.
    control.refuse_the_connection(None);
    control.unreachable(true);
    let before = control.asked();
    asked_since(&control, before, 3).await;
    assert_eq!(
        connection_reason(companion),
        (false, Some(first.clone())),
        "the host's words stay while the tries do not reach it"
    );

    // A connection that opens clears them.
    control.unreachable(false);
    connected(companion).await;
    assert_eq!(connection_reason(companion), (true, None));

    // Silent from the start, the words are that the host was not reached.
    control.unreachable(true);
    end_main_connection();
    let silent = connection_down_where(companion, |reason| !host_words(reason)).await;
    assert_ne!(silent, first);

    // The host's bound replaces the host's words: it is another cause.
    control.unreachable(false);
    connected(companion).await;
    control.refuse_the_connection(Some(ErrorCode::PermissionDenied));
    end_main_connection();
    connection_down_where(companion, host_words).await;
    control.refuse_the_connection(Some(ErrorCode::ResourceUnavailable));
    let bound = connection_down_where(companion, |reason| !host_words(reason)).await;
    assert!(!bound.is_empty(), "the bound says why");
    control.refuse_the_connection(None);
    adopted.stop().await;
}

/// KR-REQ-19.08: a raw view that is opened again after its connection was refused at the host's
/// admission says the host's words, and keeps them while the tries that follow do not reach the host.
/// A view that opens clears them, and the host's bound replaces them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_view_opened_again_keeps_the_hosts_words_while_later_tries_do_not_reach_the_host()
 {
    use kr_protocol::error::ErrorCode;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::TerminalInput]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "kept-words").expect("opens");
    let reason_of = |state: &Value| {
        state["reason"]
            .as_str()
            .expect("the view says why")
            .to_owned()
    };

    control.refuse_the_connection(Some(ErrorCode::PermissionDenied));
    open_view(companion, session, "kept-words", 90).expect("a handle comes back");
    let first = reason_of(
        &companion
            .state_where(90, |state| state["state"] == "ended")
            .await,
    );
    assert!(
        first.contains("the host refused the connection"),
        "the host's words: {first}"
    );

    // The page opens a view again, and the host is not reached.
    control.refuse_the_connection(None);
    control.unreachable(true);
    open_view(companion, session, "kept-words", 91).expect("a handle comes back");
    let second = reason_of(
        &companion
            .state_where(91, |state| state["state"] == "ended")
            .await,
    );
    assert!(
        second.contains("the host refused the connection"),
        "the host's words stay while a try does not reach the host: {second}"
    );

    // The host's bound is another cause, and replaces them.
    control.unreachable(false);
    control.refuse_the_connection(Some(ErrorCode::ResourceUnavailable));
    open_view(companion, session, "kept-words", 92).expect("a handle comes back");
    let bound = reason_of(
        &companion
            .state_where(92, |state| state["state"] == "ended")
            .await,
    );
    assert!(
        !bound.contains("the host refused the connection"),
        "the bound replaces the host's words: {bound}"
    );

    // A view that opens clears them: the next try that does not reach the host says so.
    control.refuse_the_connection(Some(ErrorCode::PermissionDenied));
    open_view(companion, session, "kept-words", 93).expect("a handle comes back");
    companion
        .state_where(93, |state| state["state"] == "ended")
        .await;
    control.refuse_the_connection(None);
    open_view(companion, session, "kept-words", 94).expect("a handle comes back");
    companion
        .state_where(94, |state| state["state"] == "showing")
        .await;
    control.unreachable(true);
    open_view(companion, session, "kept-words", 95).expect("a handle comes back");
    let silent = reason_of(
        &companion
            .state_where(95, |state| state["state"] == "ended")
            .await,
    );
    assert!(
        !silent.contains("the host refused the connection"),
        "a view that opened cleared the host's words: {silent}"
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: an answer given while the screen's link is being reached again is kept on the
/// device, and once the link is back it is settled against the worker's question and sent, on the
/// link of the opening, by the person.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_kept_answer_is_settled_and_sent_on_the_screens_link() {
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let asked = worker.ask("kept");
    let session = worker.session_id;
    let (phone, control) = phone_governed(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::QuestionRespond]),
    )
    .await;
    let companion = &phone.companion;
    open(companion, session, None, "keeping").expect("opens");
    let read = companion
        .call(
            "question_read",
            json!({
                "params": { "session_id": session.to_string(), "question_id": null, "include_resolved": false },
                "opening": "keeping",
            }),
        )
        .expect("the question is read");
    let revision = read["questions"][0]["revision"].clone();

    // The link is lost and cannot be made again, so the answer is not confirmed.
    control.unreachable(true);
    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_links()
        .lose_connection(session);
    heard(companion, "keeping", |standing| {
        standing["state"] == "reconnecting"
    })
    .await;
    let kept = companion
        .call(
            "question_answer",
            json!({
                "params": {
                    "session_id": session.to_string(),
                    "question_id": asked.question_id.to_string(),
                    "expected_revision": revision,
                    "answer": { "kind": "decision", "decided": true },
                },
                "opening": "keeping",
            }),
        )
        .expect("the answer is kept");
    assert_eq!(kept["outcome"], "kept", "{kept}");

    control.unreachable(false);
    heard(companion, "keeping", |standing| standing["state"] == "open").await;
    let settled = companion
        .call(
            "question_settle",
            json!({ "params": { "sessionId": session.to_string() }, "opening": "keeping" }),
        )
        .expect("the kept answer is settled against the worker's question");
    assert_eq!(settled.as_array().map(Vec::len), Some(1), "{settled}");
    let drafted = kept["draft"]["drafted_at_ms"].clone();
    let sent = companion
        .call(
            "question_send_kept",
            json!({
                "params": { "questionId": asked.question_id.to_string(), "draftedAtMs": drafted },
                "opening": "keeping",
            }),
        )
        .expect("the kept answer is sent on the screen's link");
    assert_eq!(sent["outcome"], "taken", "{sent}");
    adopted.stop().await;
}

/// KR-REQ-19.08: a page that loads again has lost the openings it made, and native code lets each
/// go, so its places among the eight and its watches are not kept for tokens nobody holds. The
/// screens of the new page open the sessions again with tokens of their own.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_page_that_loads_again_leaves_its_openings() {
    use tauri::Manager as _;

    let adopted = Adopted::start(2).await;
    let first = adopted.workers[0].session_id;
    let second = adopted.workers[1].session_id;
    let phone = phone_under(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    open(companion, first, None, "before-1").expect("opens");
    open(companion, second, None, "before-2").expect("opens");
    let state = companion.app.state::<companion_tauri::AppState>();
    let links = state.paired_links();
    assert_eq!(links.opened(), 2);

    links.leave_all();

    assert_eq!(links.opened(), 0);
    let stale = companion
        .call(
            "session_agents",
            json!({ "sessionId": first.to_string(), "opening": "before-1" }),
        )
        .expect_err("the page's earlier opening is over");
    assert_eq!(code(&stale), "STALE_SESSION", "{stale}");
    // The new page opens the session again with a token of its own, and is served.
    open(companion, first, None, "after-1").expect("opens again");
    companion
        .call(
            "session_agents",
            json!({ "sessionId": first.to_string(), "opening": "after-1" }),
        )
        .expect("served");
    adopted.stop().await;
}

/// The host the phone holds its main connection to.
fn host_of(companion: &Companion) -> kr_protocol::ids::DeviceId {
    companion
        .device()
        .host_in_use()
        .expect("a host in use")
        .host_device_id
}

/// Waits until `count` places are held on `host`.
async fn places_held(host: kr_protocol::ids::DeviceId, count: usize) {
    let places = companion_tauri::places::budget();
    tokio::time::timeout(WATCHDOG, async {
        while places.held_on(host) != count {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{count} places are held, not {}",
            companion_tauri::places::budget().held_on(host)
        )
    });
}

/// KR-REQ-19.08: an opening whose link is lost, while every place of this computer's budget on the
/// host is held by others, tells the page the budget's own cause while its watch waits for a place,
/// and not that contact was lost for as long as the wait lasts; it reaches the host when a place is
/// free.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_watch_that_waits_on_the_budget_tells_the_budget_while_it_waits() {
    use companion_tauri::places::Kind;
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, _control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    let host = host_of(companion);
    open(companion, session, None, "waiting-screen").expect("the session opens");
    let places = companion_tauri::places::budget();

    // Every place the other kinds may take is held but the opening's own, and the place that the
    // opening's link gives back when it is lost goes to a taker that is already waiting, so the
    // watch finds none free when it looks.
    let mut held: Vec<_> = std::iter::from_fn(|| places.try_take(host, Kind::Other)).collect();
    let mut taker = Box::pin(places.take(host, Kind::Other, WATCHDOG));
    tokio::select! {
        biased;
        _ = &mut taker => panic!("no place is free yet"),
        () = std::future::ready(()) => {}
    }
    companion
        .app
        .state::<companion_tauri::AppState>()
        .paired_links()
        .lose_connection(session);
    held.push(taker.await.expect("the link's place goes to the taker"));

    let told = heard(companion, "waiting-screen", |standing| {
        standing["state"] == "reconnecting" && standing["capacity"] == true
    })
    .await;
    assert!(
        told["standing"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("already holds as many connections")),
        "the budget's own cause while the watch waits: {told}"
    );

    // A place frees, and the watch reaches the host: the opening is served on a link again.
    drop(held);
    tokio::time::timeout(WATCHDOG, async {
        loop {
            let read = companion.call(
                "session_agents",
                json!({ "sessionId": session.to_string(), "opening": "waiting-screen" }),
            );
            if read.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the opening is served again once a place is free");
    adopted.stop().await;
}

/// KR-REQ-19.08: a link the person left keeps its place on the host's bound while a mutation it
/// carries is in flight, and gives it back once the mutation is answered and the link closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_left_link_keeps_its_place_until_its_mutation_answers() {
    let adopted = Adopted::start(1).await;
    let worker = &adopted.workers[0];
    let upstream = Arc::new(net_support::worker::HeldUpstream::default());
    let instance = worker.register_agent_on(Arc::clone(&upstream) as _);
    let session = worker.session_id;
    let phone = phone_under(
        &adopted,
        pairing(&[ActionRight::SessionView, ActionRight::AgentPrompt]),
    )
    .await;
    let companion = &phone.companion;
    let host = host_of(companion);
    let places = companion_tauri::places::budget();
    let main_only = places.held_on(host);
    open(companion, session, None, "left-with-a-mutation").expect("the session opens");
    assert!(
        places.held_on(host) > main_only,
        "the opened link holds a place of its own"
    );

    let sending = companion.start_call(
        "agent_prompt_submit",
        json!({ "params": prompt(session, instance, "in flight"), "opening": "left-with-a-mutation" }),
    );
    tokio::time::timeout(WATCHDOG, async {
        while upstream.prompts().is_empty() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("the prompt reaches the agent's upstream");

    leave(companion, session, "left-with-a-mutation");
    assert!(!sending.is_finished(), "the prompt is still in flight");
    assert!(
        places.held_on(host) > main_only,
        "the link that was left keeps its place while its mutation is in flight"
    );

    upstream.release();
    tokio::time::timeout(WATCHDOG, sending)
        .await
        .expect("the prompt is answered")
        .expect("the call ran")
        .expect("the prompt is answered");
    places_held(host, main_only).await;
    adopted.stop().await;
}

/// How long a dial that is no longer wanted may take to stop: well inside the 20 seconds a dial is
/// otherwise given, which is what tells stopping at once from stopping at its own limit.
const STOPS_AT_ONCE: Duration = Duration::from_secs(10);

/// KR-REQ-19.08: a dial that another opening or a leave has made no longer wanted stops, though its
/// connection is still being made, and gives its place back at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_dial_that_is_superseded_or_left_stops_and_gives_its_place_back() {
    let adopted = Adopted::start(1).await;
    let session = adopted.workers[0].session_id;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    let host = host_of(companion);
    let places = companion_tauri::places::budget();
    let main_only = places.held_on(host);

    control.hold();
    let first = opening_call(companion, session, None, "first");
    held(&control, 1).await;
    assert_eq!(
        places.held_on(host),
        main_only + 1,
        "a dial holds a place while its connection is being made"
    );

    // A later opening replaces the first, which stops where it is: the connection it asked for is
    // still held, and its place is back.
    let second = opening_call(companion, session, None, "second");
    held(&control, 2).await;
    let superseded = tokio::time::timeout(STOPS_AT_ONCE, first)
        .await
        .expect("the superseded dial stops")
        .expect("the call ran")
        .expect("an answer");
    assert_eq!(superseded["state"], "superseded", "{superseded}");
    assert_eq!(
        places.held_on(host),
        main_only + 1,
        "only the second dial holds a place"
    );

    // A leave stops the second the same way.
    leave(companion, session, "second");
    let left = tokio::time::timeout(STOPS_AT_ONCE, second)
        .await
        .expect("the dial that was left stops")
        .expect("the call ran")
        .expect("an answer");
    assert_eq!(left["state"], "superseded", "{left}");
    assert_eq!(places.held_on(host), main_only, "every place went back");
    control.stop_holding();
    control.release_all();
    adopted.stop().await;
}

/// KR-REQ-19.08: a connection the host ends gives its place back. A share's end ends the link that
/// carried it, and the phone's main connection and its place stand.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_link_the_host_ends_gives_its_place_back() {
    let adopted = Adopted::start(2).await;
    let (shared, own) = (&adopted.workers[0], &adopted.workers[1]);
    let mut grant = pairing(&[ActionRight::SessionView]);
    grant.session_selector = kr_protocol::grant::SessionSelector::These {
        session_ids: [own.session_id].into_iter().collect(),
    };
    let phone = phone_under(&adopted, grant).await;
    let companion = &phone.companion;
    let host = host_of(companion);
    let places = companion_tauri::places::budget();
    let main_only = places.held_on(host);
    let share = shared_with(
        &adopted,
        &phone,
        shared.session_id,
        RoleSelection::plain(SessionRole::Controller),
    )
    .await;
    places_held(host, main_only).await;
    open(
        companion,
        shared.session_id,
        Some(share.grant_id),
        "share-1",
    )
    .expect("the share opens");
    assert!(
        places.held_on(host) > main_only,
        "the link the share carries holds a place"
    );

    revoke(&adopted.host, share.grant_id).await;
    heard(companion, "share-1", |standing| {
        standing["state"] == "ended"
    })
    .await;
    places_held(host, main_only).await;
    adopted.stop().await;
}

/// A refusal's code, as a call that failed returns it.
fn code_of(error: &companion_tauri::error::CommandError) -> kr_protocol::error::ErrorCode {
    error.code
}

/// KR-REQ-19.08: one place of the budget is the main link's alone. With every place the other kinds
/// may take held, and a further dial of another kind waiting, a dial of the main link does not wait
/// and is given its place, and the other kind is never given it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_the_main_links_dial_does_not_wait_behind_other_dials() {
    use kr_protocol::error::ErrorCode;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let device = phone.companion.device();
    // A host this phone holds no connection to, so that every place on it is free; the dials reach
    // the governed link and never the real host.
    let mut elsewhere = device.host_in_use().expect("a host in use");
    elsewhere.host_device_id = kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid());
    let places = companion_tauri::places::budget();
    let others = companion_tauri::places::HOST_CONNECTIONS - 1;

    control.hold();
    let asked = control.asked();
    let fillers: Vec<_> = (0..others)
        .map(|_| {
            let (device, elsewhere) = (Arc::clone(&device), elsewhere.clone());
            tokio::spawn(async move { Connection::paired(&device, &elsewhere).await })
        })
        .collect();
    held(&control, others).await;
    assert_eq!(places.held_on(elsewhere.host_device_id), others);

    let waiting = tokio::spawn({
        let (device, elsewhere) = (Arc::clone(&device), elsewhere.clone());
        async move { Connection::paired(&device, &elsewhere).await }
    });
    let main = tokio::spawn({
        let (device, elsewhere) = (Arc::clone(&device), elsewhere.clone());
        async move {
            companion_tauri::places::as_the_main_link(Connection::paired(&device, &elsewhere)).await
        }
    });
    // The main link's dial reaches the connection while the other kind's still waits for a place.
    held(&control, others + 1).await;
    assert!(!waiting.is_finished(), "the other dial is still waiting");

    // The other dial is turned away when its own time limit ends, with every place still held: it
    // was never given the main link's.
    let turned_away = waiting
        .await
        .expect("the dial ran")
        .expect_err("the other dial is refused");
    assert!(
        matches!(turned_away, Unopened::BudgetFull),
        "it was never given the main link's place, and says that the budget is used: {turned_away:?}"
    );
    assert_eq!(
        turned_away.into_error().retry,
        kr_protocol::error::RetryCategory::Transient
    );
    assert_eq!(
        control.asked() - asked,
        others + 1,
        "it never reached the connection"
    );

    control.refuse(Some(ErrorCode::PermissionDenied));
    control.stop_holding();
    control.release_all();
    let reached = main
        .await
        .expect("the dial ran")
        .expect_err("the governed link refuses");
    assert_eq!(
        code_of(&reached.into_error()),
        ErrorCode::PermissionDenied,
        "the main link's dial was given its place and reached the link"
    );
    for filler in fillers {
        filler.await.expect("the dial ran").expect_err("refused");
    }
    assert_eq!(
        places.held_on(elsewhere.host_device_id),
        0,
        "every place went back"
    );
    adopted.stop().await;
}

/// KR-REQ-19.08: callers that each hold a connection and ask for another, with every place the
/// other kinds may take held, are each refused for now inside their own time limit with the code
/// the host refuses with; every place goes back, and the next dial is made.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_holders_that_ask_for_another_connection_are_refused_and_every_place_returns()
{
    use kr_protocol::error::ErrorCode;

    const HOLDERS: usize = 3;
    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let device = phone.companion.device();
    let paired = device.host_in_use().expect("a host in use");
    let host = paired.host_device_id;
    let places = companion_tauri::places::budget();
    let main_only = places.held_on(host);

    let mut holders = Vec::new();
    for _ in 0..HOLDERS {
        holders.push(
            Connection::paired(&device, &paired)
                .await
                .expect("a connection within the budget"),
        );
    }
    // The main link holds its place, and the other kinds may hold all but one more of the budget.
    let fillers_needed = companion_tauri::places::HOST_CONNECTIONS - 1 - HOLDERS;
    control.hold();
    let fillers: Vec<_> = (0..fillers_needed)
        .map(|_| {
            let (device, paired) = (Arc::clone(&device), paired.clone());
            tokio::spawn(async move { Connection::paired(&device, &paired).await })
        })
        .collect();
    held(&control, fillers_needed).await;
    assert_eq!(
        places.held_on(host),
        companion_tauri::places::HOST_CONNECTIONS,
        "every place is held"
    );

    let asks: Vec<_> = holders
        .iter()
        .map(|holder| tokio::time::timeout(WATCHDOG, holder.another()))
        .collect();
    for ask in futures_util::future::join_all(asks).await {
        let error = ask
            .expect("each holder is answered inside its own time limit")
            .expect_err("and refused");
        assert!(
            matches!(error, Unopened::BudgetFull),
            "refused for this computer's own budget: {error:?}"
        );
        assert_eq!(
            error.into_error().retry,
            kr_protocol::error::RetryCategory::Transient
        );
    }

    control.refuse(Some(ErrorCode::PermissionDenied));
    control.stop_holding();
    control.release_all();
    for filler in fillers {
        filler.await.expect("the dial ran").expect_err("refused");
    }
    drop(holders);
    places_held(host, main_only).await;
    control.refuse(None);
    Connection::paired(&device, &paired)
        .await
        .expect("the next dial is made");
    adopted.stop().await;
}

/// KR-REQ-19.08: the phone's main connection is reached again while dials of other kinds hold every
/// place they may take. The main link is the one connection without which the phone cannot reach the
/// host, so its reconnection is never held back by the others.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_the_main_link_reconnects_while_other_dials_hold_every_other_place() {
    use kr_protocol::error::ErrorCode;
    use tauri::Manager as _;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    let device = companion.device();
    let paired = device.host_in_use().expect("a host in use");
    let host = paired.host_device_id;
    let places = companion_tauri::places::budget();

    // Every place the other kinds may take is held by a dial that is still being made.
    control.hold();
    let mut fillers = Vec::new();
    for _ in 1..companion_tauri::places::HOST_CONNECTIONS {
        let (device, paired) = (Arc::clone(&device), paired.clone());
        fillers.push(tokio::spawn(async move {
            Connection::paired(&device, &paired).await
        }));
        held(&control, fillers.len()).await;
    }
    assert_eq!(
        places.held_on(host),
        companion_tauri::places::HOST_CONNECTIONS,
        "every place is held"
    );
    control.stop_holding();

    // The main connection is lost; its place goes back, and the phone reconnects on it.
    let asked = control.asked();
    companion
        .app
        .state::<companion_tauri::AppState>()
        .connection()
        .expect("connected")
        .session()
        .close();
    tokio::time::timeout(WATCHDOG, async {
        while control.asked() == asked {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the main link is dialled again though every other place is held");
    connected(companion).await;

    control.refuse(Some(ErrorCode::PermissionDenied));
    control.release_all();
    for filler in fillers {
        filler.await.expect("the dial ran").expect_err("refused");
    }
    adopted.stop().await;
}

/// KR-REQ-19.08: a connection that was not opened says why, from where the cause is known. The host
/// refuses a connection it cannot take with an error of request identifier zero, which the session
/// keeps: that refusal is the host's bound and no other error is. The same code answering a request,
/// a host that does not answer, a refusal of the connection for another reason and this computer's
/// own budget are each told apart, and none is told as another.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_connection_that_was_not_opened_says_why() {
    use companion_tauri::connection::Asked;
    use kr_protocol::error::{ErrorCode, ProtocolError};
    use kr_protocol::method::Method;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let device = phone.companion.device();
    let host = device.host_in_use().expect("a host in use");
    let dial = || async { Connection::paired(&device, &host).await.map(|_| ()) };

    // The host refuses the connection for its bound.
    control.refuse_the_connection(Some(ErrorCode::ResourceUnavailable));
    let cause = dial().await.expect_err("the host refused the connection");
    assert!(
        matches!(cause, Unopened::HostFull),
        "the host's bound, and not a refusal of a request: {cause:?}"
    );

    // The host refuses the connection for another reason: not its bound, so the connection is as
    // good as lost, with the host's own words as the reason.
    control.refuse_the_connection(Some(ErrorCode::PermissionDenied));
    let cause = dial().await.expect_err("the host refused the connection");
    assert!(
        cause.for_now() && !matches!(cause, Unopened::HostFull),
        "a refusal of the connection at admission for another reason is a connection lost: {cause:?}"
    );
    let answer = cause.into_error();
    assert_eq!(
        answer.code,
        ErrorCode::ResourceUnavailable,
        "a command that needed it is answered as a lost connection is"
    );
    assert!(
        answer.message.contains("the host refused the connection"),
        "the host's words are kept: {answer:?}"
    );
    control.refuse_the_connection(None);

    // The same code that the host's bound has, answering one request: a refusal of that request.
    control.refuse_request(Some((
        Method::HostInfo,
        ProtocolError::new(
            ErrorCode::ResourceUnavailable,
            "another session holds the work",
        ),
    )));
    let cause = dial().await.expect_err("the host refused the request");
    assert!(
        matches!(&cause, Unopened::Refused(Asked::HostInfo, error)
            if error.code == ErrorCode::ResourceUnavailable),
        "a request's own refusal is not the host's bound: {cause:?}"
    );
    control.refuse_request(None);

    // A host that does not answer.
    control.unreachable(true);
    let cause = dial().await.expect_err("the host was not reached");
    assert!(
        matches!(cause, Unopened::Unreached(_)),
        "a host that did not answer is not full: {cause:?}"
    );
    control.unreachable(false);
    adopted.stop().await;
}

/// KR-REQ-19.08: the reserved place belongs to the main link that is current. A former main link
/// that something still holds, as a pending share's acceptance holds its connection, gives the
/// reservation up when a newer one is dialled: after a change of host and back, the new main link
/// reaches its connection at once with every other place held, and is not made to wait and refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_the_current_main_link_is_given_its_place_while_a_former_one_is_held() {
    use kr_protocol::error::ErrorCode;

    let adopted = Adopted::start(1).await;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let device = phone.companion.device();
    // A host this phone holds no connection to, so that every place on it is free; the dials reach
    // the governed link and never the real host.
    let mut elsewhere = device.host_in_use().expect("a host in use");
    elsewhere.host_device_id = kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid());
    let places = companion_tauri::places::budget();
    let others = companion_tauri::places::HOST_CONNECTIONS - 1;
    let dial = |main: bool| {
        let (device, elsewhere) = (Arc::clone(&device), elsewhere.clone());
        tokio::spawn(async move {
            if main {
                companion_tauri::places::as_the_main_link(Connection::paired(&device, &elsewhere))
                    .await
            } else {
                Connection::paired(&device, &elsewhere).await
            }
        })
    };

    control.hold();
    let fillers: Vec<_> = (0..others).map(|_| dial(false)).collect();
    held(&control, others).await;
    let former = dial(true);
    held(&control, others + 1).await;
    assert_eq!(
        places.held_on(elsewhere.host_device_id),
        companion_tauri::places::HOST_CONNECTIONS,
        "every place is held, the former main link's among them"
    );

    // The main link that replaces it reaches its connection with no wait, though the former one is
    // still held and every other place is held.
    let current = dial(true);
    held(&control, others + 2).await;
    assert_eq!(
        places.held_on(elsewhere.host_device_id),
        companion_tauri::places::HOST_CONNECTIONS + 1,
        "the former link is counted with the others while it is held"
    );

    control.refuse(Some(ErrorCode::PermissionDenied));
    control.stop_holding();
    control.release_all();
    for held_dial in fillers.into_iter().chain([former, current]) {
        held_dial.await.expect("the dial ran").expect_err("refused");
    }
    adopted.stop().await;
}

/// KR-REQ-19.08: every path that ends an opening stops its dial under way, and the dial's places go
/// back at once: a page that loads again leaves its openings, and a change of host ends them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_19_08_a_reload_or_a_change_of_host_stops_the_dials_under_way() {
    use tauri::Manager as _;

    let adopted = Adopted::start(2).await;
    let first = adopted.workers[0].session_id;
    let second = adopted.workers[1].session_id;
    let (phone, control) = phone_governed(&adopted, pairing(&[ActionRight::SessionView])).await;
    let companion = &phone.companion;
    let host = host_of(companion);
    let places = companion_tauri::places::budget();
    let main_only = places.held_on(host);
    let state = companion.app.state::<companion_tauri::AppState>();
    let links = state.paired_links();

    control.hold();
    let before = [
        opening_call(companion, first, None, "before-1"),
        opening_call(companion, second, None, "before-2"),
    ];
    held(&control, 2).await;
    assert_eq!(places.held_on(host), main_only + 2);

    // The page loads again: its openings are left, and the dials they were making stop where they
    // are, with their places.
    links.leave_all();
    for call in before {
        let stopped = tokio::time::timeout(STOPS_AT_ONCE, call)
            .await
            .expect("the dial of a reloaded page stops")
            .expect("the call ran")
            .expect("an answer");
        assert_eq!(stopped["state"], "superseded", "{stopped}");
    }
    assert_eq!(places.held_on(host), main_only, "every place went back");

    // The host changes: the same.
    let after = [
        opening_call(companion, first, None, "after-1"),
        opening_call(companion, second, None, "after-2"),
    ];
    held(&control, 4).await;
    assert_eq!(places.held_on(host), main_only + 2);
    links.close_all();
    for call in after {
        let stopped = tokio::time::timeout(STOPS_AT_ONCE, call)
            .await
            .expect("the dial of a host that changed stops")
            .expect("the call ran")
            .expect("an answer");
        assert_eq!(stopped["state"], "superseded", "{stopped}");
    }
    assert_eq!(places.held_on(host), main_only, "every place went back");
    control.stop_holding();
    control.release_all();
    adopted.stop().await;
}
