//! The contract a component is held to, from the side that hosts components.
//!
//! The rules themselves live in `kr_protocol::broker`, which is what both sides share, and the
//! gate that applies them to a live binding is the worker's broker. What this suite establishes is
//! the contract as a component's host reads it: which grant permits which call, what a trust
//! record does and does not cover, what a token binds, and that an external fixture binds and runs
//! under this host's own bounds.
//!
//! Rows: KR-REQ-11.24, KR-REQ-11.25, KR-REQ-11.28 for the contract, and the external-fixture half
//! of KR-ACC-016. The worker's arbitration, its durable ledger and the live enforcement are
//! `crates/kr-worker/tests/{broker,gateway}.rs`.

mod components;

use std::sync::Arc;

use kr_plugin_runtime::runtime::binding::{
    BindingOwner, DEFAULT_EVENT_QUEUE, Runtime, RuntimeConfig,
};
use kr_protocol::broker::{
    ActionName, ActionToken, ActionTokenClaim, BrokerGrant, BrokerGrants, DecodedProjection,
    DecodingTrust, OfferedDecision, TokenError,
};
use kr_protocol::ids::{
    ActionTokenId, ActorId, AgentBindingRevision, ApplicationInstanceId, GrantId, PluginId,
    PublisherId, UpstreamMethod,
};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};

fn method(name: &str) -> UpstreamMethod {
    UpstreamMethod::new(name).expect("a valid method name")
}

fn permission() -> UpstreamMethod {
    method("session/request_permission")
}

fn trust(may_encode: bool) -> DecodingTrust {
    DecodingTrust {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        package_digest: Digest256::from_bytes([5; 32]),
        methods: [permission()].into_iter().collect(),
        schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
        max_decisions: U64::new(2),
        may_encode_response: may_encode,
        granted_at: TimestampMs::new(1),
    }
}

fn projection(schema: &str, decisions: &[&str]) -> DecodedProjection {
    DecodedProjection {
        schema_version: schema.to_owned(),
        summary: "the agent wants to write a file".to_owned(),
        decisions: decisions
            .iter()
            .map(|option_id| OfferedDecision {
                option_id: (*option_id).to_owned(),
                label: format!("choose {option_id}"),
            })
            .collect(),
    }
}

fn token() -> ActionToken {
    ActionToken {
        token_id: ActionTokenId::new("act-1").expect("valid"),
        actor_id: ActorId::new("device-1").expect("valid"),
        grant: BrokerGrant::UpstreamAction,
        grant_id: Nullable::some(GrantId::new(Uuid::from_bytes([7; 16]))),
        application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
        binding_revision: AgentBindingRevision::new(4),
        action: ActionName::new("prompt.submit").expect("valid"),
        parameter_hash: Digest256::from_bytes([1; 32]),
        draft_id: Nullable::null(),
        issued_at: TimestampMs::new(1),
    }
}

/// KR-REQ-11.24: the three grants are separate, and holding one is never holding another.
#[test]
fn kr_req_11_24_the_three_grants_are_separate() {
    let display_only = BrokerGrants::granted([BrokerGrant::Observation]);
    assert!(display_only.is_display_only());
    display_only
        .require(BrokerGrant::Observation)
        .expect("an observation binding may be given observations");
    assert!(display_only.require(BrokerGrant::UpstreamAction).is_err());
    assert!(
        display_only
            .require(BrokerGrant::ApprovalInterpreter)
            .is_err()
    );

    let acting = BrokerGrants::granted([BrokerGrant::UpstreamAction]);
    acting
        .require(BrokerGrant::UpstreamAction)
        .expect("an acting binding may prepare an effect");
    assert!(
        acting.require(BrokerGrant::Observation).is_err(),
        "preparing effects is not permission to read output"
    );
    assert!(!BrokerGrant::Observation.may_create_approval());
    assert!(!BrokerGrant::UpstreamAction.may_create_approval());
    assert!(BrokerGrant::ApprovalInterpreter.may_create_approval());
}

/// KR-REQ-11.25: a trust record names the package, the method and whether answering is included.
#[test]
fn kr_req_11_25_trust_names_the_package_the_method_and_whether_it_may_answer() {
    let interpret_only = trust(false);
    assert!(interpret_only.covers(&permission()));
    assert!(!interpret_only.covers(&method("fs/write_text_file")));
    assert!(
        !interpret_only.may_encode_response,
        "interpreting a request is not permission to answer it"
    );
    assert!(trust(true).may_encode_response);

    // One package's trust is never another's, at the bytes it was granted to.
    assert!(interpret_only.belongs_to(
        &PluginId::new("kalareach.codex").expect("valid"),
        &PublisherId::new("kalareach").expect("valid"),
        &Digest256::from_bytes([5; 32])
    ));
    assert!(!interpret_only.belongs_to(
        &PluginId::new("someone.else").expect("valid"),
        &PublisherId::new("kalareach").expect("valid"),
        &Digest256::from_bytes([5; 32])
    ));
    assert!(!interpret_only.belongs_to(
        &PluginId::new("kalareach.codex").expect("valid"),
        &PublisherId::new("kalareach").expect("valid"),
        &Digest256::from_bytes([6; 32])
    ));
}

/// KR-ACC-016, the decoder's own output: what a component returns is checked against the trust
/// that authorised the call, not believed because the call was authorised.
///
/// The projections here are written rather than produced by a hostile component, because what is
/// under test is the policy: a decoder's output is only ever these values, however it arrived at
/// them. A live component driven through the gate is `crates/kr-worker/tests/broker.rs`.
#[test]
fn kr_acc_016_a_decoders_output_is_bounded_by_the_trust_that_invited_it() {
    let trust = trust(true);
    trust
        .check_projection(&projection("kr-approval/1", &["allow", "deny"]))
        .expect("a projection inside the policy is accepted");

    // A schema the trust does not cover.
    assert!(
        trust
            .check_projection(&projection("kr-approval/99", &["allow"]))
            .is_err()
    );
    // More decisions than the trust permits.
    assert!(
        trust
            .check_projection(&projection("kr-approval/1", &["a", "b", "c"]))
            .is_err()
    );
    // Two decisions wearing one identifier, which would make an answer ambiguous.
    assert!(
        trust
            .check_projection(&projection("kr-approval/1", &["allow", "allow"]))
            .is_err()
    );
    // And an empty offer, which is not a decision to make.
    assert!(
        trust
            .check_projection(&projection("kr-approval/1", &[]))
            .is_err()
    );
}

/// KR-REQ-11.28: an action token binds five things, and a claim that changes any of them fails.
///
/// The spending itself is the worker's, and `crates/kr-worker/tests/broker.rs` drives it through
/// the broker. What this establishes is the type's own contract, which both sides share.
#[test]
fn kr_req_11_28_a_token_binds_actor_grant_revision_action_and_parameters() {
    let issued = token();
    issued
        .check(&ActionTokenClaim::from(&issued))
        .expect("the invocation it was given is the one it may spend");

    let mut another_actor = ActionTokenClaim::from(&issued);
    another_actor.actor_id = ActorId::new("device-2").expect("valid");
    assert_eq!(
        issued.check(&another_actor),
        Err(TokenError::Mismatch { field: "actor_id" })
    );

    let mut another_grant = ActionTokenClaim::from(&issued);
    another_grant.grant = BrokerGrant::ApprovalInterpreter;
    assert_eq!(
        issued.check(&another_grant),
        Err(TokenError::Mismatch { field: "grant" })
    );

    let mut another_action = ActionTokenClaim::from(&issued);
    another_action.action = ActionName::new("turn.cancel").expect("valid");
    assert_eq!(
        issued.check(&another_action),
        Err(TokenError::Mismatch { field: "action" })
    );

    let mut other_parameters = ActionTokenClaim::from(&issued);
    other_parameters.parameter_hash = Digest256::from_bytes([2; 32]);
    assert_eq!(
        issued.check(&other_parameters),
        Err(TokenError::Mismatch {
            field: "parameter_hash"
        })
    );

    let mut later_thread = ActionTokenClaim::from(&issued);
    later_thread.binding_revision = AgentBindingRevision::new(5);
    assert!(matches!(
        issued.check(&later_thread),
        Err(TokenError::StaleBinding { .. })
    ));

    // And the revision in force decides, not the one the component reports.
    assert!(matches!(
        issued.check_current_revision(AgentBindingRevision::new(5)),
        Err(TokenError::StaleBinding { .. })
    ));
}

/// KR-ACC-016, the external fixture harness: a component from a workspace outside this one is
/// bound and bounded like any other.
///
/// The harness is the directory itself: `scripts/build-plugin-fixtures.sh` builds a workspace that
/// is not part of this one, and the runtime loads its output by path. A vendor adding a fixture
/// adds a directory, not a core release. When the components have not been built this test says so
/// and returns; continuous integration sets `KR_REQUIRE_PLUGIN_FIXTURES=1`, which makes that a
/// failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_acc_016_an_external_fixture_is_bound_under_this_hosts_own_bounds() {
    let Some(bytes) = components::component("well-behaved") else {
        return;
    };
    let directory = tempfile::tempdir().expect("a temporary directory");
    let runtime = Arc::new(
        Runtime::new(RuntimeConfig::new(directory.path().join("plugin-cache"))).expect("a runtime"),
    );
    let owner = BindingOwner::next();
    let (events, _received) = tokio::sync::mpsc::channel(DEFAULT_EVENT_QUEUE);
    let request = components::request("well-behaved", 1);
    let binding_id = request.binding_id;
    let binding = runtime
        .prepare(
            owner,
            request,
            bytes.clone(),
            core::time::Duration::from_secs(60),
            events,
        )
        .await
        .expect("the external fixture binds");

    // It runs under this host's bounds, not its own: a snapshot answers inside the deadline the
    // caller set, and the caller's deadline is what stops it.
    binding
        .snapshot(core::time::Duration::from_millis(100))
        .await
        .expect("the snapshot answers inside its deadline");

    runtime.unbind(owner, binding_id);
    runtime.release_owner(owner);
}
