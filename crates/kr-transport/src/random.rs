//! Fresh identifiers and nonces.
//!
//! Every value here comes from libsodium's generator by way of `kr-crypto`, which is the only
//! source of randomness this product uses. A connection challenge that a peer could predict would
//! defeat the replay check, and a predictable action identifier would defeat de-duplication, so
//! neither is generated from anything weaker.

use kr_crypto::secret::Secret;
use kr_protocol::ids::{ActionId, ActionWindowId, ConnectionId, RemoteDispatchLeaseId};
use kr_protocol::scalars::{Nonce256, Uuid};

use crate::error::Result;

/// Returns a fresh 256-bit nonce.
///
/// # Errors
///
/// Returns a cryptography error when the generator is unavailable.
pub fn fresh_nonce() -> Result<Nonce256> {
    let secret = Secret::<32>::random()?;
    Ok(Nonce256::from_bytes(*secret.expose()))
}

/// Returns a fresh unsigned 64-bit value.
///
/// # Errors
///
/// Returns a cryptography error when the generator is unavailable.
pub fn fresh_u64() -> Result<u64> {
    let secret = Secret::<8>::random()?;
    Ok(u64::from_be_bytes(*secret.expose()))
}

/// Returns a cryptographically generated UUIDv4.
///
/// Section 9: 128-bit representation with 122 random bits. The version and variant bits are set
/// after the random draw, which is what makes the other 122 bits the entire identity.
///
/// # Errors
///
/// Returns a cryptography error when the generator is unavailable.
pub fn fresh_uuid_v4() -> Result<Uuid> {
    let secret = Secret::<16>::random()?;
    let mut bytes = *secret.expose();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

/// Returns a fresh connection identity.
///
/// # Errors
///
/// As [`fresh_uuid_v4`].
pub fn fresh_connection_id() -> Result<ConnectionId> {
    Ok(ConnectionId::new(fresh_uuid_v4()?))
}

/// Returns a fresh action identity.
///
/// # Errors
///
/// As [`fresh_uuid_v4`].
pub fn fresh_action_id() -> Result<ActionId> {
    Ok(ActionId::new(fresh_uuid_v4()?))
}

/// Returns a fresh remote dispatch lease identity.
///
/// # Errors
///
/// As [`fresh_uuid_v4`].
pub fn fresh_lease_id() -> Result<RemoteDispatchLeaseId> {
    Ok(RemoteDispatchLeaseId::new(fresh_uuid_v4()?))
}

/// Returns a fresh action window identity.
///
/// The window identity is an opaque host-issued string, so it is rendered as the hyphenated form
/// of a fresh UUIDv4: unguessable, and readable in a diagnostic.
///
/// # Errors
///
/// As [`fresh_uuid_v4`].
pub fn fresh_action_window_id() -> Result<ActionWindowId> {
    let uuid = fresh_uuid_v4()?;
    Ok(ActionWindowId::new(uuid.to_string())
        .expect("a hyphenated UUID is a valid opaque identifier"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_generated_uuid_declares_version_four() {
        let uuid = fresh_uuid_v4().expect("a UUID");
        assert_eq!(uuid.version(), 4);
        assert_eq!(uuid.as_bytes()[8] & 0xc0, 0x80);
    }

    #[test]
    fn two_draws_differ() {
        let first = fresh_uuid_v4().expect("a UUID");
        let second = fresh_uuid_v4().expect("a UUID");
        assert_ne!(first, second);
        assert_ne!(
            fresh_nonce().expect("a nonce"),
            fresh_nonce().expect("a nonce")
        );
    }

    #[test]
    fn a_window_identity_is_the_text_form_of_its_uuid() {
        let window = fresh_action_window_id().expect("a window identity");
        assert_eq!(window.as_str().len(), 36);
    }
}
