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
