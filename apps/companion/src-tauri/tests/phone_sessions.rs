//! A phone opens a paired host's sessions.
//!
//! The host is kr-controller's in-process daemon with a real session worker behind it: the
//! worker's own service, its question ledger and its broker, which a test gives one agent whose
//! upstream it records. The phone is this crate's backend on the mock runtime, paired with the
//! host, and every call below is made the way the page makes it, through the invoke path. A second
//! paired device holds a share of the same session where a test needs one.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-19.08 | the `kr_req_19_08_` tests here |

#![cfg(unix)]

#[path = "../../../../crates/kr-controller/tests/net_support/mod.rs"]
mod net_support;
mod support;

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::agent::{AgentMutationTarget, AgentPromptParams, PromptText};
use kr_protocol::ids::{
    AgentBindingRevision, ApplicationInstanceId, GrantId, InvitationId, SessionId,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::sharing::{GrantRedeemParams, RoleSelection, SessionRole};
use net_support::worker::{Adopted, Upstream, offer, revoke};
use net_support::{Host, proposal};
use serde_json::{Value, json};
use support::{Companion, Phone, WATCHDOG, pair_under, unpaired_phone};

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
    let identity = device.pairing().candidate.paired_identity(paired.device_id);
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
    let resource = worker.offer_approval(instance, Arc::clone(&upstream) as _);
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
    let share = shared_with(
        &adopted,
        &phone,
        session,
        RoleSelection::plain(SessionRole::Controller),
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
