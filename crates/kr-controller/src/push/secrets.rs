//! Where an external destination's credential is kept: the host's secret store.
//!
//! Slack, Discord, Telegram and email each send through a credential, and a destination's endpoint
//! is never one. So the credential lives in the store section 10 keeps every host secret in - the
//! platform's own credential store, or the owner-only directory where the platform has none - as
//! one item per destination, and nowhere else: not in the delivery journal, not in its backups,
//! not in an answer or a log.
//!
//! The item's name is a digest of the destination's identifier inside this environment's scope, so
//! an identifier of any spelling becomes a name the store accepts, and two environments of one
//! account never share an item. The item holds the credential and a [`CredentialStamp`] beside it.
//! The stamp is random and is copied onto the destination record when the destination is
//! configured, which is how a pass knows the credential it reads is the one the destination was
//! configured with, and how a replaced credential becomes a new binding in the journal without the
//! journal holding anything derived from the credential.
//!
//! One item per destination, replaced in place: a store write replaces the value whole, so there is
//! never an old credential left behind under another name when a new one is stored.

use std::fmt;
use std::sync::Arc;

use kr_crypto::secret::SecretVec;
use kr_crypto::store::{SecretName, SecretStore};
use kr_delivery::destination::{CredentialStamp, DestinationId};
use kr_protocol::delivery::DestinationSecret;
use kr_protocol::ids::EnvironmentId;

use crate::error::{ControllerError, Result};

/// The credentials this environment's external destinations send with.
#[derive(Clone)]
pub struct DestinationSecrets {
    store: Arc<dyn SecretStore>,
    scope: String,
}

impl fmt::Debug for DestinationSecrets {
    /// Names the store and the scope, and never an item's value.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DestinationSecrets")
            .field("store", &self.store.describe())
            .field("scope", &self.scope)
            .finish()
    }
}

/// A credential as the store holds it, with the stamp it was stored under.
#[derive(Debug)]
pub struct HeldSecret {
    /// The stamp written beside it.
    pub stamp: CredentialStamp,
    /// The credential.
    pub secret: DestinationSecret,
}

/// The form an item takes in the store.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredItem {
    stamp: String,
    secret: DestinationSecret,
}

impl DestinationSecrets {
    /// Keeps credentials in `store`, inside the scope of one environment.
    #[must_use]
    pub fn new(store: Arc<dyn SecretStore>, environment_id: EnvironmentId) -> Self {
        Self {
            store,
            scope: format!("{environment_id}/delivery-destination"),
        }
    }

    /// The item one destination's credential is kept under.
    fn name(&self, destination_id: &DestinationId) -> Result<SecretName> {
        let digest = kr_cbor::sha256(destination_id.as_str().as_bytes());
        let hex = digest.iter().fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        });
        SecretName::new(format!("{}/{hex}", self.scope)).map_err(unavailable)
    }

    /// Stores one destination's credential under a stamp nothing has used before, replacing
    /// whatever was stored for it, and returns the stamp.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the store refuses the write. The error names the
    /// store's reason and never the credential.
    pub fn put(
        &self,
        destination_id: &DestinationId,
        secret: &DestinationSecret,
    ) -> Result<CredentialStamp> {
        let stamp = CredentialStamp::fresh();
        let item = StoredItem {
            stamp: stamp.as_str().to_owned(),
            secret: secret.clone(),
        };
        // The encoded item holds the credential, so it lives in a buffer that clears itself.
        let encoded =
            SecretVec::new(
                serde_json::to_vec(&item).map_err(|_| ControllerError::Storage {
                    operation: "keep a destination's credential",
                    detail: "the credential could not be encoded".to_owned(),
                })?,
            );
        self.store
            .set(&self.name(destination_id)?, encoded.expose())
            .map_err(unavailable)?;
        Ok(stamp)
    }

    /// Reads one destination's credential and the stamp it was stored under, or `None` when none
    /// is stored.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the store cannot be read or holds an item this
    /// build cannot read.
    pub fn get(&self, destination_id: &DestinationId) -> Result<Option<HeldSecret>> {
        let Some(held) = self
            .store
            .get(&self.name(destination_id)?)
            .map_err(unavailable)?
        else {
            return Ok(None);
        };
        // The refusal says the item is unreadable and nothing about what it holds.
        let item: StoredItem =
            serde_json::from_slice(held.expose()).map_err(|_| ControllerError::Storage {
                operation: "read a destination's credential",
                detail: "the stored item is not one this build writes".to_owned(),
            })?;
        let stamp =
            CredentialStamp::new(item.stamp.clone()).map_err(|_| ControllerError::Storage {
                operation: "read a destination's credential",
                detail: "the stored item's stamp is not one this build writes".to_owned(),
            })?;
        Ok(Some(HeldSecret {
            stamp,
            secret: item.secret,
        }))
    }

    /// Deletes one destination's credential. Deleting one that is not stored succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Storage`] when the store refuses the deletion.
    pub fn remove(&self, destination_id: &DestinationId) -> Result<()> {
        self.store
            .delete(&self.name(destination_id)?)
            .map_err(unavailable)
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
    use super::*;
    use kr_crypto::store::MemoryStore;
    use kr_protocol::delivery::SecretText;

    fn secrets(store: &Arc<MemoryStore>, environment: u8) -> DestinationSecrets {
        DestinationSecrets::new(
            Arc::clone(store) as Arc<dyn SecretStore>,
            EnvironmentId::new(kr_protocol::scalars::Uuid::from_bytes([environment; 16])),
        )
    }

    fn token(text: &str) -> DestinationSecret {
        DestinationSecret::Telegram {
            bot_token: SecretText::new(text).expect("a token"),
        }
    }

    #[test]
    fn a_credential_is_kept_replaced_in_place_and_removed() {
        let store = Arc::new(MemoryStore::new());
        let secrets = secrets(&store, 1);
        let id = DestinationId::new("Team alerts, #ops").expect("an identifier");
        assert!(secrets.get(&id).expect("a read").is_none());
        let first = secrets.put(&id, &token("1:first")).expect("a write");
        let held = secrets.get(&id).expect("a read").expect("stored");
        assert_eq!(held.stamp, first);
        assert_eq!(held.secret, token("1:first"));

        let second = secrets.put(&id, &token("1:second")).expect("a write");
        assert_ne!(first, second, "every credential stored is a new stamp");
        let held = secrets.get(&id).expect("a read").expect("stored");
        assert_eq!((held.stamp, held.secret), (second, token("1:second")));

        secrets.remove(&id).expect("a deletion");
        assert!(secrets.get(&id).expect("a read").is_none());
        secrets
            .remove(&id)
            .expect("deleting what is not there succeeds");
    }

    #[test]
    fn two_environments_never_share_an_item() {
        let store = Arc::new(MemoryStore::new());
        let id = DestinationId::new("alerts").expect("an identifier");
        secrets(&store, 1)
            .put(&id, &token("1:one"))
            .expect("a write");
        assert!(secrets(&store, 2).get(&id).expect("a read").is_none());
    }

    #[test]
    fn nothing_about_the_credential_is_in_a_debug_rendering() {
        let store = Arc::new(MemoryStore::new());
        let secrets = secrets(&store, 1);
        let id = DestinationId::new("alerts").expect("an identifier");
        secrets.put(&id, &token("1:do-not-print")).expect("a write");
        let held = secrets.get(&id).expect("a read").expect("stored");
        for rendered in [format!("{secrets:?}"), format!("{held:?}")] {
            assert!(!rendered.contains("do-not-print"), "{rendered}");
        }
    }
}
