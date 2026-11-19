//! The key for voice calls on the owner's own account.
//!
//! The owner hands the host one OpenAI key at this machine. The host keeps it in its secret store,
//! answers with the provider and whether it holds the key, and with nothing else: not the key, not
//! a prefix of it, not a length. Everything runs on this machine's loopback interface and in
//! temporary directories on the internal disk. No provider is contacted and no real key is used.

mod net_support;

use std::path::Path;
use std::sync::Arc;

use kr_controller::voice::VoiceCredentials;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::open_store_in;
use kr_ipc::client::LocalClient;
use kr_protocol::delivery::SecretText;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::voice_credential::{
    VoiceCredentialKind, VoiceCredentialRemoveParams, VoiceCredentialRemoveResult,
    VoiceCredentialSetParams, VoiceCredentialSetResult,
};

/// A value no real key has, so finding any part of it outside the secret store is a leak.
const SENTINEL: &str = "kr-test-voice-key-0123456789abcdef";

fn params(key: &str) -> VoiceCredentialSetParams {
    VoiceCredentialSetParams {
        kind: VoiceCredentialKind::OpenaiLive,
        key: SecretText::new(key).expect("a key"),
    }
}

fn credentials_of(host: &net_support::Host) -> VoiceCredentials {
    let store = open_store_in(&host.tree().environment().secrets_dir())
        .expect("the store the daemon keeps its secrets in");
    VoiceCredentials::new(Arc::from(store.store), host.environment_id)
}

async fn set(
    control: &mut LocalClient,
    host: &net_support::Host,
    params: &VoiceCredentialSetParams,
) -> Result<ParamsValue, ProtocolError> {
    control
        .mutate(
            Method::VoiceCredentialSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            params,
        )
        .await
        .expect("the call reaches the daemon")
}

/// Every file under `root`, read whole, that is not under `except`.
fn files_outside(root: &Path, except: &Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(folder) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&folder) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.starts_with(except) {
                continue;
            }
            if path.is_dir() {
                pending.push(path);
            } else if let Ok(bytes) = std::fs::read(&path) {
                found.push((path, bytes));
            }
        }
    }
    found
}

fn holds(bytes: &[u8], text: &str) -> bool {
    bytes
        .windows(text.len())
        .any(|window| window == text.as_bytes())
}

/// P1-1 and P1-2: the owner at this machine sets a key; the answer names the provider and says the
/// host holds it, and carries none of it; the secret store holds the item; no other file of the
/// environment's state holds a byte window of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voice_credential_set_on_the_local_socket_is_held_and_answers_with_its_kind_only() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;

    let answer = set(&mut control, &host, &params(SENTINEL)).await;
    let rendered = format!("{answer:?}");
    let value = answer.expect("the owner keeps a key");
    let stored: VoiceCredentialSetResult = value.to_typed().expect("the result decodes");
    assert_eq!(stored.kind, VoiceCredentialKind::OpenaiLive);
    assert!(stored.in_force, "the host holds the key after the call");
    let whole = format!(
        "{rendered} {}",
        serde_json::to_string(&stored).expect("the result renders")
    );
    for window in [
        &SENTINEL[..8],
        &SENTINEL[12..20],
        &SENTINEL[SENTINEL.len() - 8..],
    ] {
        assert!(
            !whole.contains(window),
            "the answer carries {window:?}: {whole}"
        );
    }

    let held = credentials_of(&host)
        .get(VoiceCredentialKind::OpenaiLive)
        .expect("the store reads")
        .expect("the key is kept");
    assert_eq!(held.expose(), SENTINEL);

    let environment = host.tree().environment();
    let secrets = environment.secrets_dir();
    for (path, bytes) in files_outside(environment.state_dir(), &secrets) {
        for window in [
            &SENTINEL[..8],
            &SENTINEL[12..20],
            &SENTINEL[SENTINEL.len() - 8..],
        ] {
            assert!(
                !holds(&bytes, window),
                "{} holds a window of the key",
                path.display()
            );
        }
    }
}

/// P1-4 and P1-5: parameters that do not read get one fixed sentence and a key of the wrong shape
/// is refused before any claim, with neither echoed; a good key is then held. P1-6: a replaced key
/// replaces the item whole, and removing one leaves none; removing nothing is answered the same.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_key_of_the_wrong_shape_is_refused_and_a_replaced_or_removed_key_leaves_one_item() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;

    let long = "k".repeat(257);
    for bad in [
        "",
        "short-key-012345678",
        "has a space in the key 123456",
        long.as_str(),
    ] {
        if let Ok(key) = SecretText::new(bad) {
            let refused = set(&mut control, &host, &params(key.expose())).await;
            let text = format!("{refused:?}");
            assert!(refused.is_err(), "{bad:?} is refused");
            assert!(
                !text.contains("short-key"),
                "the refusal repeats the key: {text}"
            );
        }
    }
    assert!(
        credentials_of(&host)
            .get(VoiceCredentialKind::OpenaiLive)
            .expect("the store reads")
            .is_none(),
        "a refused key is not held"
    );

    // Parameters that are not the method's: one fixed sentence, none of what was sent.
    let wrong = control
        .mutate(
            Method::VoiceCredentialSet,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &serde_json::json!({ "key": SENTINEL, "extra": SENTINEL }),
        )
        .await
        .expect("the call reaches the daemon");
    let text = format!("{wrong:?}");
    assert!(wrong.is_err());
    assert!(
        !text.contains(&SENTINEL[..8]),
        "the refusal repeats the key: {text}"
    );

    let first = "kr-test-voice-key-first-0123456789";
    let second = "kr-test-voice-key-second-012345678";
    set(&mut control, &host, &params(first))
        .await
        .expect("held");
    set(&mut control, &host, &params(second))
        .await
        .expect("replaced");
    let credentials = credentials_of(&host);
    assert_eq!(
        credentials
            .get(VoiceCredentialKind::OpenaiLive)
            .expect("reads")
            .expect("held")
            .expose(),
        second
    );

    for expected in [true, false] {
        let removed: VoiceCredentialRemoveResult = control
            .mutate(
                Method::VoiceCredentialRemove,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &VoiceCredentialRemoveParams {
                    kind: VoiceCredentialKind::OpenaiLive,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .expect("removing is answered")
            .to_typed()
            .expect("the result decodes");
        assert_eq!(removed.removed, expected);
    }
    assert!(
        credentials
            .get(VoiceCredentialKind::OpenaiLive)
            .expect("reads")
            .is_none(),
        "a removed key leaves none"
    );
}

/// P1-3: the key is taken on the owner's local socket and refused from a paired device that holds
/// every right, with the refusal every other environment method gives it, and a refused call holds
/// nothing. The control is the same call on the local socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_voice_credential_is_refused_from_a_paired_device_with_the_ingress_refusal_and_taken_on_the_local_socket()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(kr_protocol::rights::ActionRight::ALL),
    )
    .await;
    let session = net_support::RawDevice::connect(&host, &device, &record).await;
    session.claim();

    let refused = net_support::refusal(
        session
            .mutate(
                Method::VoiceCredentialSet,
                ActionId::new(kr_ipc::new_uuid()),
                net_support::on_the_host(&host),
                &params(SENTINEL),
            )
            .await,
    );
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused:?}"
    );
    assert!(
        !format!("{refused:?}").contains(&SENTINEL[..8]),
        "the refusal repeats the key"
    );
    let removed = net_support::refusal(
        session
            .mutate(
                Method::VoiceCredentialRemove,
                ActionId::new(kr_ipc::new_uuid()),
                net_support::on_the_host(&host),
                &VoiceCredentialRemoveParams {
                    kind: VoiceCredentialKind::OpenaiLive,
                },
            )
            .await,
    );
    assert_eq!(
        removed.code,
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    assert!(
        credentials_of(&host)
            .get(VoiceCredentialKind::OpenaiLive)
            .expect("the store reads")
            .is_none(),
        "a refused call keeps nothing"
    );

    session.close();
    let mut control = host.client().await;
    set(&mut control, &host, &params(SENTINEL))
        .await
        .expect("the same call on the local socket is taken");
    assert!(
        credentials_of(&host)
            .get(VoiceCredentialKind::OpenaiLive)
            .expect("the store reads")
            .is_some()
    );
}

/// P1-12: the digest the host keeps of a claimed set is not the digest of its parameters alone, so
/// it cannot be used to test a guess of the key, and a second call with the same key claims under
/// a digest of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_stored_claim_digest_of_a_credential_set_is_not_the_digest_of_its_params_alone() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;

    let value = params(SENTINEL);
    let alone = kr_cbor::sha256(&kr_cbor::encode(
        &kr_cbor::to_canonical_value(&value).expect("the parameters encode"),
    ));
    let on_the_key = kr_cbor::sha256(SENTINEL.as_bytes());

    let mut stored = Vec::new();
    for _ in 0..2 {
        let action = ActionId::new(kr_ipc::new_uuid());
        control
            .mutate(
                Method::VoiceCredentialSet,
                action,
                ActionTarget::environment(host.environment_id),
                &value,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the key is kept");
        let connection = rusqlite::Connection::open_with_flags(
            host.registry_database(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("the registry opens");
        let digest: Vec<u8> = connection
            .query_row(
                "SELECT payload_digest FROM authority_receipts WHERE action_id = ?1",
                [action.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("the set was claimed");
        assert_eq!(digest.len(), 32, "a digest");
        assert_ne!(digest, alone.to_vec(), "the digest of the parameters alone");
        assert_ne!(digest, on_the_key.to_vec(), "the digest of the key alone");
        stored.push(digest);
    }
    assert_ne!(
        stored[0], stored[1],
        "a second claim of the same key has its own digest"
    );
}

fn stored_call(state_dir: &Path, byte: u8, session: Option<&str>) {
    use kr_client::services::{NewCall, OwnCallLedger};
    let calls = kr_controller::voice::own_key_calls::OwnKeyCalls::open(state_dir)
        .expect("the record of calls opens beside the daemon");
    let call = NewCall {
        call_id: format!("call-{byte}"),
        attempt_id: format!("attempt-{byte}"),
        action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([byte; 16])),
        device_id: "device-1".to_owned(),
        asked_ms: 1_700_000_000_000,
        closes_at_ms: 1_700_000_300_000,
    };
    calls.begin(&call).expect("a row is written");
    if let Some(session) = session {
        calls
            .record_id(&call.call_id, session, None)
            .expect("its id is written");
    }
}

fn rows_of(state_dir: &Path) -> usize {
    use kr_client::services::OwnCallLedger;
    kr_controller::voice::own_key_calls::OwnKeyCalls::open(state_dir)
        .expect("the record opens")
        .rows()
        .expect("rows")
        .len()
}

async fn remove_key(
    control: &mut LocalClient,
    host: &net_support::Host,
) -> Result<ParamsValue, ProtocolError> {
    control
        .mutate(
            Method::VoiceCredentialRemove,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &VoiceCredentialRemoveParams {
                kind: VoiceCredentialKind::OpenaiLive,
            },
        )
        .await
        .expect("the call reaches the daemon")
}

/// A call the host cannot show is closed keeps the key: `set` and `remove` refuse with the
/// approved sentences, and `forget_calls` forgets every row and keeps the key. The test daemon
/// reaches no provider, so no hangup is ever confirmed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forget_calls_forgets_every_row_and_keeps_the_key_while_set_and_remove_refuse_over_a_standing_call()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = net_support::Host::start(&owner).await;
    let mut control = host.client().await;
    let state_dir = host.tree().environment().state_dir().to_path_buf();
    let held = "kr-test-voice-key-held-01234567890";
    set(&mut control, &host, &params(held)).await.expect("held");
    let credentials = credentials_of(&host);

    // A call with a session id that cannot be confirmed closed.
    stored_call(&state_dir, 1, Some("live_unconfirmed"));
    let replaced = set(
        &mut control,
        &host,
        &params("kr-test-voice-key-other-0123456789"),
    )
    .await;
    assert!(
        replaced
            .expect_err("a key in use is not replaced")
            .message
            .contains("A call is using this key; replace it after the call has ended"),
    );
    let refused = remove_key(&mut control, &host)
        .await
        .expect_err("a call that is not confirmed closed keeps the key");
    assert!(refused.message.contains("could not be confirmed closed"));
    assert!(
        refused
            .message
            .contains("run kr voice credential forget-calls, then remove the key again")
    );
    assert_eq!(
        credentials
            .get(VoiceCredentialKind::OpenaiLive)
            .expect("reads")
            .expect("kept")
            .expose(),
        held
    );
    assert_eq!(rows_of(&state_dir), 1, "the row stays");

    // A creation that never learned its id.
    stored_call(&state_dir, 2, None);
    let forgotten: kr_protocol::voice_credential::VoiceCredentialForgetCallsResult = control
        .mutate(
            Method::VoiceCredentialForgetCalls,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &kr_protocol::voice_credential::VoiceCredentialForgetCallsParams {
                kind: VoiceCredentialKind::OpenaiLive,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("forgetting is answered")
        .to_typed()
        .expect("the result decodes");
    assert_eq!(forgotten.calls_forgotten, 2);
    assert_eq!(
        forgotten.late_start,
        kr_protocol::voice_credential::VoiceLateStart::None
    );
    assert_eq!(rows_of(&state_dir), 0);
    assert_eq!(
        credentials
            .get(VoiceCredentialKind::OpenaiLive)
            .expect("reads")
            .expect("kept")
            .expose(),
        held
    );

    // With no row, the key is replaced and then removed.
    set(
        &mut control,
        &host,
        &params("kr-test-voice-key-other-0123456789"),
    )
    .await
    .expect("replaced");
    let creating_only = {
        stored_call(&state_dir, 3, None);
        remove_key(&mut control, &host)
            .await
            .expect_err("a creation never learned keeps the key")
    };
    assert!(
        creating_only
            .message
            .contains("did not learn whether OpenAI created it")
    );
    assert!(
        credentials
            .get(VoiceCredentialKind::OpenaiLive)
            .expect("reads")
            .is_some()
    );
    let _ = forgotten;
}
