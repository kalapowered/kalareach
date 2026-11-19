//! Where the key for voice calls on the owner's own account is kept: the host's secret store.
//!
//! One item per provider kind, inside this environment's scope, holding the provider and the key,
//! and nowhere else: not in the configuration document, not in a journal, a log, a report or an
//! answer. A store write replaces the value whole, so a replaced key leaves no old copy under
//! another name. The key is a [`SecretText`] while the daemon holds it decoded and a [`SecretVec`]
//! in this layer, and every read of it goes through `expose`, so each place that uses it is one a
//! reviewer can find.

use std::fmt;
use std::sync::Arc;

use kr_crypto::secret::SecretVec;
use kr_crypto::store::{SecretName, SecretStore};
use kr_protocol::delivery::SecretText;
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::voice_credential::VoiceCredentialKind;
use serde::{Deserialize, Serialize};

use crate::error::{ControllerError, Result};

/// What an item holds. It carries the kind beside the key so an item that is not the one asked for
/// is refused rather than used.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredItem {
    kind: VoiceCredentialKind,
    key: SecretText,
}

/// The keys this environment's host holds for calls on the owner's own account.
#[derive(Clone)]
pub struct VoiceCredentials {
    store: Arc<dyn SecretStore>,
    scope: String,
}

impl fmt::Debug for VoiceCredentials {
    /// Names the store and the scope, and never an item's value.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VoiceCredentials")
            .field("store", &self.store.describe())
            .field("scope", &self.scope)
            .finish()
    }
}

/// The key as the own-key provider reads it: from the store, for each use, never held between.
#[derive(Debug)]
pub struct OwnKey(VoiceCredentials);

impl OwnKey {
    /// A key source over the host's voice credentials.
    #[must_use]
    pub const fn new(credentials: VoiceCredentials) -> Self {
        Self(credentials)
    }
}

impl kr_client::services::own_voice::OwnKeySource for OwnKey {
    fn key(
        &self,
    ) -> std::result::Result<Option<SecretText>, kr_client::services::own_voice::KeyUnreadable>
    {
        self.0
            .get(VoiceCredentialKind::OpenaiLive)
            .map_err(|_| kr_client::services::own_voice::KeyUnreadable)
    }
}

impl VoiceCredentials {
    /// Keeps keys in `store`, inside the scope of one environment.
    #[must_use]
    pub fn new(store: Arc<dyn SecretStore>, environment_id: EnvironmentId) -> Self {
        Self {
            store,
            scope: format!("{environment_id}/voice-credential"),
        }
    }

    /// The item one provider's key is kept under.
    fn name(&self, kind: VoiceCredentialKind) -> Result<SecretName> {
        SecretName::new(format!("{}/{}", self.scope, kind.as_str())).map_err(unavailable)
    }

    /// Keeps the key for `kind`, replacing the one held.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the store refuses the write. The error names the
    /// store's reason and never the key.
    pub fn put(&self, kind: VoiceCredentialKind, key: &SecretText) -> Result<()> {
        // The encoded item holds the key, so it lives in a buffer that clears itself.
        let encoded = SecretVec::new(
            serde_json::to_vec(&StoredItem {
                kind,
                key: key.clone(),
            })
            .map_err(|_| ControllerError::Storage {
                operation: "keep a voice key",
                detail: "the key could not be encoded".to_owned(),
            })?,
        );
        self.store
            .set(&self.name(kind)?, encoded.expose())
            .map_err(unavailable)
    }

    /// Reads the key for `kind`, or `None` when none is held.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the store cannot be read or holds an item this
    /// build cannot read.
    pub fn get(&self, kind: VoiceCredentialKind) -> Result<Option<SecretText>> {
        let Some(held) = self.store.get(&self.name(kind)?).map_err(unavailable)? else {
            return Ok(None);
        };
        // The refusal says the item is unreadable and nothing about what it holds.
        let item: StoredItem =
            serde_json::from_slice(held.expose()).map_err(|_| ControllerError::Storage {
                operation: "read a voice key",
                detail: "the stored item is not one this build writes".to_owned(),
            })?;
        if item.kind != kind {
            return Err(ControllerError::Storage {
                operation: "read a voice key",
                detail: "the stored item is for another provider".to_owned(),
            });
        }
        Ok(Some(item.key))
    }

    /// Whether the key for `kind` is held.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the store cannot be read or holds an item this
    /// build cannot read, so an unreadable store is never reported as an empty one.
    pub fn held(&self, kind: VoiceCredentialKind) -> Result<bool> {
        self.get(kind).map(|held| held.is_some())
    }

    /// What `kr doctor` says of the key: whether the host holds one, holds none, or could not tell.
    ///
    /// A store that refuses the read is "unreadable" and never "none", so a host whose store is
    /// broken does not read as one with no key. The words are literals: nothing a store returns
    /// reaches the report.
    #[must_use]
    pub fn doctor_check(&self) -> DoctorCheck {
        let (status, detail) = match self.held(VoiceCredentialKind::OpenaiLive) {
            Ok(true) => (DoctorStatus::Ok, "held for openai-live"),
            Ok(false) => (DoctorStatus::NotApplicable, "none"),
            Err(_) => (
                DoctorStatus::Warning,
                "unreadable (the secret store refused)",
            ),
        };
        DoctorCheck::new(
            "voice-credential",
            "The voice key this host holds",
            status,
            Sentence::new().stated(detail),
            None,
        )
    }

    /// Deletes the key for `kind` and says whether one was held.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the store refuses the read or the deletion.
    pub fn delete(&self, kind: VoiceCredentialKind) -> Result<bool> {
        let name = self.name(kind)?;
        let was_held = self.store.get(&name).map_err(unavailable)?.is_some();
        self.store.delete(&name).map_err(unavailable)?;
        Ok(was_held)
    }
}

fn unavailable(error: kr_crypto::CryptoError) -> ControllerError {
    ControllerError::Storage {
        operation: "use this host's secret store",
        detail: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use kr_crypto::store::MemoryStore;
    use kr_protocol::scalars::Uuid;
    use kr_protocol::voice_credential::VoiceCredentialSetParams;

    use super::*;

    /// A value no real key has, so finding any part of it in text is a leak.
    const SENTINEL: &str = "kr-test-voice-key-0123456789abcdef";

    /// A store that takes writes, deletions and reads only when it is let.
    #[derive(Debug, Default)]
    struct Flaky {
        inner: MemoryStore,
        refusing_writes: AtomicBool,
        refusing_reads: AtomicBool,
        refusing_deletes: AtomicBool,
    }

    impl SecretStore for Flaky {
        fn set(&self, name: &SecretName, secret: &[u8]) -> kr_crypto::Result<()> {
            if self.refusing_writes.load(Ordering::SeqCst) {
                return Err(kr_crypto::CryptoError::SecretStore {
                    message: "the store refuses writes".to_owned(),
                });
            }
            self.inner.set(name, secret)
        }

        fn get(&self, name: &SecretName) -> kr_crypto::Result<Option<SecretVec>> {
            if self.refusing_reads.load(Ordering::SeqCst) {
                return Err(kr_crypto::CryptoError::SecretStore {
                    message: "the store cannot be read".to_owned(),
                });
            }
            self.inner.get(name)
        }

        fn delete(&self, name: &SecretName) -> kr_crypto::Result<()> {
            if self.refusing_deletes.load(Ordering::SeqCst) {
                return Err(kr_crypto::CryptoError::SecretStore {
                    message: "the store refuses deletions".to_owned(),
                });
            }
            self.inner.delete(name)
        }

        fn describe(&self) -> String {
            "a flaky store".to_owned()
        }
    }

    fn credentials(store: &Arc<Flaky>) -> VoiceCredentials {
        VoiceCredentials::new(
            Arc::clone(store) as Arc<dyn SecretStore>,
            EnvironmentId::new(Uuid::from_bytes([7; 16])),
        )
    }

    fn key() -> SecretText {
        SecretText::new(SENTINEL).expect("a key")
    }

    /// P1-7: a store that refuses a write, a read or a deletion answers with its own reason and
    /// never the key, and a store that cannot be read is never taken for an empty one.
    #[test]
    fn a_store_that_refuses_the_write_answers_with_its_reason_and_never_the_key() {
        let store = Arc::new(Flaky::default());
        let held = credentials(&store);

        // The control: the same call with a store that takes it.
        held.put(VoiceCredentialKind::OpenaiLive, &key())
            .expect("a store that takes writes keeps the key");
        assert_eq!(
            held.get(VoiceCredentialKind::OpenaiLive)
                .expect("reads")
                .expect("held")
                .expose(),
            SENTINEL
        );

        store.refusing_writes.store(true, Ordering::SeqCst);
        let refused = held
            .put(VoiceCredentialKind::OpenaiLive, &key())
            .expect_err("a refusing store refuses");
        let text = format!("{refused} {refused:?}");
        assert!(text.contains("the store refuses writes"), "{text}");
        assert!(
            !text.contains("sentinel") && !text.contains(SENTINEL),
            "{text}"
        );
        // The key held before is the key held after: a refused write replaced nothing.
        store.refusing_writes.store(false, Ordering::SeqCst);
        assert_eq!(
            held.get(VoiceCredentialKind::OpenaiLive)
                .expect("reads")
                .expect("held")
                .expose(),
            SENTINEL
        );

        store.refusing_reads.store(true, Ordering::SeqCst);
        let unreadable = held
            .held(VoiceCredentialKind::OpenaiLive)
            .expect_err("an unreadable store is not an empty one");
        assert!(unreadable.to_string().contains("the store cannot be read"));
        store.refusing_reads.store(false, Ordering::SeqCst);

        store.refusing_deletes.store(true, Ordering::SeqCst);
        let kept = held
            .delete(VoiceCredentialKind::OpenaiLive)
            .expect_err("a refusing store keeps the item");
        assert!(kept.to_string().contains("the store refuses deletions"));
        store.refusing_deletes.store(false, Ordering::SeqCst);
        assert!(
            held.held(VoiceCredentialKind::OpenaiLive).expect("reads"),
            "a refused deletion left the key held"
        );
    }

    /// An item this build cannot read is refused with a fixed sentence that carries none of what
    /// the item holds.
    #[test]
    fn an_item_this_build_cannot_read_is_refused_without_repeating_it() {
        let store = Arc::new(Flaky::default());
        let held = credentials(&store);
        let name = held.name(VoiceCredentialKind::OpenaiLive).expect("a name");
        store
            .inner
            .set(&name, SENTINEL.as_bytes())
            .expect("a store takes an item");
        let refused = held
            .get(VoiceCredentialKind::OpenaiLive)
            .expect_err("an item that is not a stored key is refused");
        let text = format!("{refused} {refused:?}");
        assert!(!text.contains("sentinel"), "{text}");
        assert!(held.held(VoiceCredentialKind::OpenaiLive).is_err());
    }

    /// P1-10: no type that carries the key prints it in its debug or display form, whatever the
    /// form: the key's own type, the set method's parameters, the value they become before they are
    /// encoded, the credentials' own handle, and a refusal the store gave while the key was held.
    #[test]
    fn no_voice_credential_type_prints_its_key_in_debug_or_display() {
        let store = Arc::new(Flaky::default());
        let held = credentials(&store);
        held.put(VoiceCredentialKind::OpenaiLive, &key())
            .expect("kept");
        let params = VoiceCredentialSetParams {
            kind: VoiceCredentialKind::OpenaiLive,
            key: key(),
        };
        let value = kr_protocol::envelope::ParamsValue::from_typed(&params).expect("a value");
        store.refusing_writes.store(true, Ordering::SeqCst);
        let refusal = held
            .put(VoiceCredentialKind::OpenaiLive, &key())
            .expect_err("refused");
        let forms = [
            format!("{:?}", key()),
            format!("{:#?}", key()),
            format!("{params:?}"),
            format!("{params:#?}"),
            format!("{value:?}"),
            format!("{value:#?}"),
            format!("{held:?}"),
            format!("{held:#?}"),
            format!("{refusal}"),
            format!("{refusal:?}"),
        ];
        for form in forms {
            for window in [
                &SENTINEL[..8],
                &SENTINEL[12..20],
                &SENTINEL[SENTINEL.len() - 8..],
                SENTINEL,
            ] {
                assert!(!form.contains(window), "a form prints {window:?}: {form}");
            }
        }
    }
}
