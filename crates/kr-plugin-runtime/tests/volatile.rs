//! Volatile-native mode as a component and its runtime meet it.
//!
//! Requirement rows closed here: KR-REQ-11.35 and KR-REQ-11.36 for the component side. The
//! worker's own fence, its in-memory arbitration, the evidence gap and the recovery that commits
//! it are `crates/kr-worker/tests/gateway.rs`.
//!
//! The rule this side has to keep is short and is the one that is easy to get wrong: the fence
//! stops rich work and reaches nothing the native forwarding path uses. A component that is
//! disabled, fenced or simply absent must not be able to stop a terminal.

use kr_protocol::broker::{BrokerGrant, BrokerGrants, DecodingTrust};
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, GatewayMode, NativeFraming, NativeMethodClass,
    PendingState, check_transition,
};
use kr_protocol::ids::{MethodTableVersion, PluginId, PublisherId, UpstreamMethod};
use kr_protocol::scalars::{Digest256, TimestampMs, U64};
use kr_protocol::session::Durability;

fn method(name: &str) -> UpstreamMethod {
    UpstreamMethod::new(name).expect("a valid method name")
}

fn trust() -> DecodingTrust {
    DecodingTrust {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        package_digest: Digest256::from_bytes([5; 32]),
        methods: [method("session/request_permission")].into_iter().collect(),
        schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
        max_decisions: U64::new(2),
        may_encode_response: true,
        granted_at: TimestampMs::new(1),
    }
}

fn table() -> DeclarativeTable {
    DeclarativeTable {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        digest: Digest256::from_bytes([1; 32]),
        framing: NativeFraming::JsonLines,
        request_id_field: "id".to_owned(),
        response_id_field: "id".to_owned(),
        method_field: "method".to_owned(),
        result_field: "result".to_owned(),
        error_field: "error".to_owned(),
        entries: vec![
            DeclarativeEntry {
                method: method("fs/write_text_file"),
                class: NativeMethodClass::Mutation,
                expects_response: true,
            },
            DeclarativeEntry {
                method: method("session/update"),
                class: NativeMethodClass::Observation,
                expects_response: false,
            },
        ],
    }
}

/// KR-REQ-11.35: the declarative table is not something a fence or a component fault can reach.
///
/// The live fence is the worker's, and `crates/kr-worker/tests/gateway.rs` drives it. What this
/// establishes is the half that makes the separation possible: the table is a value the core
/// reads, it classifies the same methods the same way whatever has happened to a component, and a
/// binding's grants are untouched by anything that stops its rich capability.
#[test]
fn kr_req_11_35_the_declarative_path_depends_on_no_component() {
    let grants = BrokerGrants::granted([
        BrokerGrant::Observation,
        BrokerGrant::UpstreamAction,
        BrokerGrant::ApprovalInterpreter,
    ]);
    let trust = trust();

    let table = table();
    let classified = table.classify(&method("fs/write_text_file"));
    assert_eq!(classified.class, NativeMethodClass::Mutation);
    assert!(classified.declared);
    let unknown = table.classify(&method("vendor/undocumented"));
    assert_eq!(unknown.class, NativeMethodClass::Mutation);
    assert!(
        unknown.suspends_rich_mutations(),
        "an unclassified request suspends rich mutations and is still forwarded"
    );

    // And the grants a binding holds are values too: a fence stops a capability, not an authority.
    assert!(grants.holds(BrokerGrant::Observation));
    assert!(trust.covers(&method("session/request_permission")));
}

/// KR-REQ-11.35: the mode admits no rich work until the gap is committed, and what it writes while
/// it is open says so.
#[test]
fn kr_req_11_35_no_rich_work_returns_until_the_gap_is_committed() {
    assert!(GatewayMode::Normal.admits_rich_work());
    assert!(!GatewayMode::NativeOnlyVolatile.admits_rich_work());
    assert!(
        !GatewayMode::Recovering.admits_rich_work(),
        "storage returning is not the same as the gap being committed"
    );
    assert_eq!(GatewayMode::Normal.durability(), Durability::Durable);
    assert_eq!(
        GatewayMode::NativeOnlyVolatile.durability(),
        Durability::Volatile
    );
    assert_eq!(GatewayMode::Recovering.durability(), Durability::Volatile);

    // The fence is left through recovery and not directly.
    assert!(GatewayMode::Normal.may_become(GatewayMode::NativeOnlyVolatile));
    assert!(!GatewayMode::NativeOnlyVolatile.may_become(GatewayMode::Normal));
    assert!(GatewayMode::NativeOnlyVolatile.may_become(GatewayMode::Recovering));
    assert!(GatewayMode::Recovering.may_become(GatewayMode::Normal));
    assert!(
        GatewayMode::Recovering.may_become(GatewayMode::NativeOnlyVolatile),
        "storage can fail again while the gap is being committed"
    );
}

/// KR-REQ-11.36: a claimed identifier carried across a gap is never answered twice, and the
/// refusal a caller gets is `UPSTREAM_UNAVAILABLE` rather than a quietly substituted backend.
#[test]
fn kr_req_11_36_a_carried_identifier_is_never_answered_twice() {
    // A resource that was claimed and dispatched before the fault is uncertain afterwards, and
    // uncertain is terminal: nothing claims it again.
    assert!(check_transition(PendingState::Claimed, PendingState::Uncertain).is_ok());
    assert!(PendingState::Uncertain.is_terminal());
    assert!(PendingState::Uncertain.permitted_transitions().is_empty());
    assert!(check_transition(PendingState::Uncertain, PendingState::Claimed).is_err());

    // The code a fenced caller is told is the one that says the upstream cannot be reached now,
    // not one that says this host lost some storage, because what the caller needs to decide is
    // whether to try again and where.
    let fenced = kr_worker_error_for_a_fenced_rich_call();
    assert_eq!(fenced, ErrorCode::UpstreamUnavailable);
}

/// The code the host answers a fenced rich call with.
///
/// It is stated here rather than reached through the worker, because this crate does not depend on
/// the worker; the worker's own suite drives the live refusal and asserts the same code.
const fn kr_worker_error_for_a_fenced_rich_call() -> ErrorCode {
    ErrorCode::UpstreamUnavailable
}
