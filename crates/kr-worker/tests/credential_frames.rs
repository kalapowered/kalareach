//! A frame of the credential class passes through the broker and is kept nowhere.
//!
//! Section 11: credentials stay in the broker and never appear in component memory. A request that
//! carries one (an API key a login hands the application, the tokens an application asks its
//! terminal to refresh) is forwarded as it is, because login has to work, and nothing of it is
//! retained as a source event, written to the journal, shown to a view or readable by a decoder.
//!
//! The broker, its connection and its owner here are the ones a session runs; the two ends of the
//! connection are in-memory pipes this test reads, and the journal is a file whose bytes are
//! searched for the secrets after the broker is dropped.

use std::sync::Arc;

use kr_protocol::broker::{
    BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust, IntegrationMode, OfferedDecision,
};
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, NativeFraming, NativeMethodClass, RichMethodEntry,
    RichMethodTable,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ApplicationInstanceId, BrokerBindingId, EnvironmentId, GatewayConnectionId, MethodTableVersion,
    PluginId, PublisherId, SessionId, UpstreamMethod,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_worker::broker::{
    Broker, BrokerTransport, Carried, Credential, Duplex, Framing, ManagedProcess, TransportHandle,
};
use kr_worker::persistence::JournalHealth;
use tokio::io::AsyncReadExt as _;

const CREDENTIAL: [u8; 32] = [9; 32];

/// What the login request carries and the refresh request carries: the secrets nothing may keep.
const API_KEY: &str = "sk-SECRET-LOGIN-KEY-7f3a";
const ACCESS_TOKEN: &str = "SECRET-ACCESS-TOKEN-91bc";

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn method(name: &str) -> UpstreamMethod {
    UpstreamMethod::new(name).expect("a valid method")
}

fn identity() -> ProcessStartIdentity {
    ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900)
}

fn plugin() -> PluginId {
    PluginId::new("kalareach.codex").expect("valid")
}

fn publisher() -> PublisherId {
    PublisherId::new("kalareach").expect("valid")
}

fn installed() -> kr_worker::broker::PackageIdentity {
    kr_worker::broker::PackageIdentity {
        plugin_id: plugin(),
        publisher_id: publisher(),
        package_digest: Digest256::from_bytes([5; 32]),
    }
}

fn entry(name: &str, class: NativeMethodClass) -> DeclarativeEntry {
    DeclarativeEntry {
        method: method(name),
        class,
        expects_response: true,
        approval_option_field: Nullable::null(),
        reverse: Nullable::null(),
    }
}

fn table() -> DeclarativeTable {
    let mut entries = vec![
        entry(
            "account/chatgptAuthTokens/refresh",
            NativeMethodClass::CredentialOrConfiguration,
        ),
        entry(
            "account/login/start",
            NativeMethodClass::CredentialOrConfiguration,
        ),
        entry("session/request_permission", NativeMethodClass::Mutation),
    ];
    entries.sort_by(|first, second| first.method.cmp(&second.method));
    let mut table = DeclarativeTable {
        plugin_id: plugin(),
        publisher_id: publisher(),
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        digest: Digest256::from_bytes([1; 32]),
        framing: NativeFraming::JsonLines,
        request_id_field: "id".to_owned(),
        response_id_field: "id".to_owned(),
        method_field: "method".to_owned(),
        params_field: "params".to_owned(),
        result_field: "result".to_owned(),
        error_field: "error".to_owned(),
        entries,
    };
    table.digest = table.canonical_digest().expect("encodable");
    table
}

fn rich() -> RichMethodTable {
    RichMethodTable {
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        entries: vec![RichMethodEntry {
            method: method("session/prompt"),
            class: NativeMethodClass::Mutation,
            required_right: ActionRight::AgentPrompt,
            operation: Nullable::some(kr_protocol::gateway::RichOperation::PromptSubmit),
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        }],
    }
}

/// A decoder trusted for the two methods the test asks it to read: the credential refresh, so that
/// what keeps it from reading that one is the broker and not a trust it lacks, and the permission
/// request it reads as the control.
fn trust() -> DecodingTrust {
    DecodingTrust {
        plugin_id: plugin(),
        publisher_id: publisher(),
        package_digest: Digest256::from_bytes([5; 32]),
        methods: [
            method("account/chatgptAuthTokens/refresh"),
            method("session/request_permission"),
        ]
        .into_iter()
        .collect(),
        schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
        max_decisions: U64::new(4),
        may_encode_response: true,
        granted_at: TimestampMs::new(1),
    }
}

fn projection() -> DecodedProjection {
    DecodedProjection {
        schema_version: "kr-approval/1".to_owned(),
        summary: "the agent asks".to_owned(),
        decisions: vec![OfferedDecision {
            option_id: "allow".to_owned(),
            label: "Allow".to_owned(),
        }],
    }
}

fn binding() -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([9; 16]))
}

/// A broker over a journal file, with one instance, one pinned table, one decoder bound to it and
/// one authenticated native connection.
fn broker(journal: &std::path::Path) -> (Arc<Broker>, GatewayConnectionId) {
    let broker = Arc::new(
        Broker::open(Some(journal), session(), JournalHealth::shared()).expect("the broker opens"),
    );
    broker
        .register_instance(
            instance(),
            IntegrationMode::Gateway,
            None,
            Some(ManagedProcess::new(
                instance(),
                identity(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: instance(),
                    executable_digest: Digest256::from_bytes([3; 32]),
                    process: identity(),
                },
                Credential::from_bytes(CREDENTIAL),
                true,
                TimestampMs::new(1),
            )),
        )
        .expect("the instance is registered");
    broker
        .bind_descriptor(
            binding(),
            instance(),
            plugin(),
            publisher(),
            Digest256::from_bytes([5; 32]),
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            Some(trust()),
            TimestampMs::new(1),
        )
        .expect("the binding is recorded");
    broker
        .pin_table(instance(), installed(), table(), rich())
        .expect("the tables are pinned");
    let connection = broker
        .open_native_connection(instance(), &CREDENTIAL, &identity(), &plugin(), "1")
        .expect("the connection is authenticated");
    (broker, connection)
}

/// Reads what has reached one end of the connection, up to its end of line.
async fn line(end: &mut tokio::io::DuplexStream) -> String {
    let mut text = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = tokio::time::timeout(std::time::Duration::from_secs(60), end.read(&mut byte))
            .await
            .expect("a frame arrives")
            .expect("the end reads");
        if read == 0 || byte[0] == b'\n' {
            return String::from_utf8_lossy(&text).into_owned();
        }
        text.push(byte[0]);
    }
}

/// Everything the journal file holds, with its write-ahead log.
fn journal_bytes(journal: &std::path::Path) -> Vec<u8> {
    let mut all = std::fs::read(journal).unwrap_or_default();
    let mut wal = journal.as_os_str().to_owned();
    wal.push("-wal");
    all.extend(std::fs::read(std::path::PathBuf::from(wal)).unwrap_or_default());
    all
}

fn carries(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}

/// KR-REQ-11.23. A credential-class request from the terminal, and the terminal's answer to a
/// credential-class request of the server's (the tokens it was asked to refresh), are forwarded
/// whole, so login and token refresh work, and are retained nowhere: not as a source event, not in
/// the journal, and a decoder is refused the request it would read.
#[tokio::test]
async fn kr_req_11_23_a_credential_request_is_forwarded_whole_and_kept_nowhere() {
    let directory = std::env::temp_dir().join(format!("kr-cred-{}", kr_ipc::new_uuid()));
    kr_ipc::paths::create_private_directory(&directory).expect("a private directory");
    let journal = directory.join("broker.sqlite");
    {
        let (broker, connection) = broker(&journal);
        let (upstream_end, upstream_here) = tokio::io::duplex(1 << 16);
        let (client_end, client_here) = tokio::io::duplex(1 << 16);
        let (mut upstream_end, mut client_end) = (upstream_end, client_end);
        let (owner, writes) = Duplex::new(
            Arc::clone(&broker),
            connection,
            Framing::new(NativeFraming::JsonLines),
            upstream_here,
            client_here,
            EnvironmentId::new(Uuid::from_bytes([4; 16])),
            "agent-user",
        );
        let drained = tokio::spawn(writes);

        // The terminal asks its server to log in with a key: forwarded whole, kept nowhere.
        let login = format!(
            r#"{{"id":7,"method":"account/login/start","params":{{"type":"apiKey","apiKey":"{API_KEY}"}}}}"#
        );
        let carried = owner
            .from_client(login.as_bytes(), TimestampMs::new(2))
            .await
            .expect("the login request is carried");
        assert!(matches!(carried, Carried::ClientRequest { .. }));
        let arrived = line(&mut upstream_end).await;
        assert!(
            arrived.contains(API_KEY) && arrived.contains("account/login/start"),
            "the server received the key, or login would not work: {arrived}"
        );
        // The control: an ordinary request of the terminal's own is retained as a source event.
        let control = r#"{"id":8,"method":"session/set_mode","params":{"mode":"CONTROL-FRAME"}}"#;
        owner
            .from_client(control.as_bytes(), TimestampMs::new(3))
            .await
            .expect("the control request is carried");
        let _ = line(&mut upstream_end).await;
        let intents = broker.client_requests().expect("the records read");
        let login_intent = intents
            .iter()
            .find(|intent| intent.method == method("account/login/start"))
            .expect("the login request was recorded");
        let control_intent = intents
            .iter()
            .find(|intent| intent.method == method("session/set_mode"))
            .expect("the control request was recorded");
        assert!(
            broker.source(instance(), &control_intent.source).is_some(),
            "the control: an ordinary request's bytes are retained as a source event"
        );
        assert!(
            broker.source(instance(), &login_intent.source).is_none(),
            "the login request's bytes, which carry a key, are retained nowhere"
        );

        // The server asks its terminal to refresh its tokens: the request is forwarded whole and
        // the terminal's answer, which carries them, is forwarded whole too.
        let refresh = r#"{"id":"r1","method":"account/chatgptAuthTokens/refresh","params":{"reason":"unauthorized","previousAccountId":null}}"#;
        let Carried::UpstreamRequest {
            resource_id: Some(refresh_resource),
            ..
        } = owner
            .from_upstream(refresh.as_bytes(), TimestampMs::new(4))
            .await
            .expect("the refresh request is carried")
        else {
            panic!("a request the upstream expects an answer to creates a resource");
        };
        let arrived = line(&mut client_end).await;
        assert!(
            arrived.contains("account/chatgptAuthTokens/refresh"),
            "the terminal received the token request, or refresh would not work: {arrived}"
        );
        let permission = r#"{"id":"r2","method":"session/request_permission","params":{"tool":"CONTROL-FRAME"}}"#;
        let Carried::UpstreamRequest {
            resource_id: Some(permission_resource),
            ..
        } = owner
            .from_upstream(permission.as_bytes(), TimestampMs::new(5))
            .await
            .expect("the permission request is carried")
        else {
            panic!("a request the upstream expects an answer to creates a resource");
        };
        let _ = line(&mut client_end).await;

        // A decoder is refused the credential request, though it is trusted for its method, and
        // reads the control.
        assert!(
            broker
                .interpret(
                    binding(),
                    refresh_resource,
                    projection(),
                    None,
                    TimestampMs::new(6)
                )
                .is_err(),
            "a decoder cannot read a request that carries a credential"
        );
        broker
            .interpret(
                binding(),
                permission_resource,
                projection(),
                None,
                TimestampMs::new(7),
            )
            .expect("the control: a decoder reads an ordinary request");

        // The terminal then answers the refresh request with the tokens, which is forwarded whole.
        // That is after the decoder was asked: an answered request is a resolved one, and no
        // decoder reads it whatever was kept.
        let answer = format!(
            r#"{{"id":"r1","result":{{"accessToken":"{ACCESS_TOKEN}","chatgptAccountId":"account-1","chatgptPlanType":null}}}}"#
        );
        let carried = owner
            .from_client(answer.as_bytes(), TimestampMs::new(8))
            .await
            .expect("the terminal's answer is carried");
        assert!(matches!(carried, Carried::ClientAnswer { .. }));
        let arrived = line(&mut upstream_end).await;
        assert!(
            arrived.contains(ACCESS_TOKEN),
            "the server received the tokens, or refresh would not work: {arrived}"
        );

        owner.shutdown();
        let _ = drained.await;
    }
    let held = journal_bytes(&journal);
    assert!(
        carries(&held, "account/login/start"),
        "the control: the journal holds what was recorded of the login request, its method"
    );
    assert!(
        !carries(&held, API_KEY) && !carries(&held, ACCESS_TOKEN),
        "the journal holds neither secret"
    );
    let _ = std::fs::remove_dir_all(&directory);
}
