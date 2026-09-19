//! The broker's grants, decoding trust and action tokens as a component meets them, and the
//! runtime bounds a malicious one runs under.
//!
//! Requirement rows closed here: KR-REQ-11.24, KR-REQ-11.25, KR-REQ-11.28, KR-REQ-11.31 (the
//! runtime half) and the KR-ACC-016 harness. What is not here is the worker's arbitration and its
//! durable ledger, which are `crates/kr-worker/tests/broker.rs` and `gateway.rs`.

mod components;

use std::sync::Arc;

use kr_plugin_runtime::broker::{AuthorityError, ComponentAuthority, RichCapability};
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
use kr_protocol::scalars::{Digest256, TimestampMs, U64, Uuid};

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
        grant_id: GrantId::new(Uuid::from_bytes([7; 16])),
        application_instance_id: ApplicationInstanceId::new(Uuid::from_bytes([2; 16])),
        binding_revision: AgentBindingRevision::new(4),
        action: ActionName::new("prompt.submit").expect("valid"),
        parameter_hash: Digest256::from_bytes([1; 32]),
        issued_at: TimestampMs::new(1),
    }
}

/// KR-REQ-11.24: the three grants are separate, and a component is never invited to do what its
/// binding does not hold.
#[test]
fn kr_req_11_24_a_component_is_never_asked_for_what_its_grants_do_not_permit() {
    let display_only =
        ComponentAuthority::observing(BrokerGrants::granted([BrokerGrant::Observation]));
    display_only
        .may_observe()
        .expect("an observation binding may be given observations");
    assert!(matches!(
        display_only.may_prepare_action(),
        Err(AuthorityError::Grant(_))
    ));
    assert!(matches!(
        display_only.may_decode(&permission()),
        Err(AuthorityError::Grant(_))
    ));

    let acting =
        ComponentAuthority::observing(BrokerGrants::granted([BrokerGrant::UpstreamAction]));
    acting
        .may_prepare_action()
        .expect("an acting binding may prepare an effect");
    assert!(
        matches!(acting.may_observe(), Err(AuthorityError::Grant(_))),
        "preparing effects is not permission to read output"
    );
}

/// KR-REQ-11.25: decoding trust is explicit, names the method, and answering is separate from
/// interpreting.
#[test]
fn kr_req_11_25_trust_names_the_method_and_answering_is_its_own_permission() {
    let interpreter = ComponentAuthority {
        grants: BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
        trust: Some(trust(false)),
    };
    interpreter
        .may_decode(&permission())
        .expect("a trusted method may be interpreted");
    assert!(matches!(
        interpreter.may_decode(&method("fs/write_text_file")),
        Err(AuthorityError::NotTrusted { .. })
    ));
    assert!(
        matches!(
            interpreter.may_encode(&permission()),
            Err(AuthorityError::MayNotAnswer { .. })
        ),
        "interpreting a request is not permission to answer it"
    );

    let answering = ComponentAuthority {
        grants: BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
        trust: Some(trust(true)),
    };
    answering
        .may_encode(&permission())
        .expect("a binding granted both may answer");

    // The interpreter grant without a record is not trust.
    let ungranted =
        ComponentAuthority::observing(BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]));
    assert!(matches!(
        ungranted.may_decode(&permission()),
        Err(AuthorityError::NotTrusted { .. })
    ));
}

/// KR-ACC-016, the malicious decoder: what a component returns is checked against the trust that
/// authorised the call, not believed because the call was authorised.
#[test]
fn kr_acc_016_a_malicious_decoder_is_bounded_by_the_trust_that_invited_it() {
    let interpreter = ComponentAuthority {
        grants: BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
        trust: Some(trust(true)),
    };
    interpreter
        .check_projection(
            &permission(),
            &projection("kr-approval/1", &["allow", "deny"]),
        )
        .expect("a projection inside the policy is accepted");

    // A schema the trust does not cover.
    assert!(matches!(
        interpreter.check_projection(&permission(), &projection("kr-approval/99", &["allow"])),
        Err(AuthorityError::Trust(_))
    ));
    // More decisions than the trust permits.
    assert!(matches!(
        interpreter.check_projection(
            &permission(),
            &projection("kr-approval/1", &["a", "b", "c"])
        ),
        Err(AuthorityError::Trust(_))
    ));
    // Two decisions wearing one identifier, which would make an answer ambiguous.
    assert!(matches!(
        interpreter.check_projection(
            &permission(),
            &projection("kr-approval/1", &["allow", "allow"])
        ),
        Err(AuthorityError::Trust(_))
    ));
    // And a projection of a method it was never trusted for.
    assert!(matches!(
        interpreter.check_projection(
            &method("fs/write_text_file"),
            &projection("kr-approval/1", &["allow"])
        ),
        Err(AuthorityError::NotTrusted { .. })
    ));
}

/// KR-REQ-11.28: an action token binds five things, and a component that changes any of them
/// spends nothing.
#[test]
fn kr_req_11_28_a_component_cannot_widen_the_invocation_it_was_given() {
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

/// KR-REQ-11.31 and KR-ACC-016, the Wasm fault: a fault disables the rich capability and is
/// invisible to anything the native path reads.
#[test]
fn kr_req_11_31_a_fault_disables_rich_work_and_nothing_else() {
    let mut rich = RichCapability::available();
    rich.require().expect("rich work is available");

    rich.disable("three faults in one minute");
    assert!(!rich.is_available());
    assert!(matches!(
        rich.require(),
        Err(AuthorityError::RichDisabled { .. })
    ));
    assert_eq!(rich.disabled_reason(), Some("three faults in one minute"));

    // A later fault does not overwrite the reason the binding was first stopped for.
    rich.disable("something else");
    assert_eq!(rich.disabled_reason(), Some("three faults in one minute"));

    // A disabled binding is not re-enabled by waiting. It is re-enabled by being bound again.
    rich.restore();
    rich.require().expect("a fresh binding starts available");

    // The authority a binding holds is untouched by a fault: what stopped is the rich capability,
    // and the grants are still what they were.
    let authority = ComponentAuthority {
        grants: BrokerGrants::granted([BrokerGrant::Observation, BrokerGrant::ApprovalInterpreter]),
        trust: Some(trust(true)),
    };
    let mut faulted = RichCapability::available();
    faulted.disable("the component trapped");
    authority
        .may_observe()
        .expect("observation is not what a rich fault stops");
    assert!(faulted.require().is_err());
}

/// KR-ACC-016, the runtime budgets and the external fixture harness: a component from a directory
/// outside this repository is bound and bounded like any other.
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
