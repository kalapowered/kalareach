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
