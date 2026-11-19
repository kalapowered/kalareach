//! The identity a committed device is given.
//!
//! The host assigns it, but it does not draw it at random: it is derived from the invitation that
//! was redeemed and from the authorisation key the candidate was committed under. A device that
//! was committed while it was not listening can therefore compute the identity it was given and
//! prove it by connecting under it, and a connection that cannot prove that key learns nothing
//! from the derivation.

use kr_cbor::CanonicalValue;
use kr_protocol::ids::{DeviceId, InvitationId};
use kr_protocol::scalars::{AuthorisationKey, Uuid};

use crate::Result;

/// The domain the committed device identity is derived under.
pub const DEVICE_ID_DOMAIN: &str = "kr-pair/device-id/1";

/// Returns the identity a candidate is committed under.
///
/// It is the first 16 bytes of `SHA-256(CBOR([domain, invitation identifier, authorisation key]))`,
/// with both identifiers as byte strings. A [`DeviceId`] has no version rule, so the bytes are
/// used as they are.
///
/// # Errors
///
/// Returns an encoding error only when the assembled value breaks the encoding's profile.
pub fn committed_device_id(
    invitation_id: InvitationId,
    authorisation: &AuthorisationKey,
) -> Result<DeviceId> {
    let digest = kr_cbor::signing_digest(
        DEVICE_ID_DOMAIN,
        vec![
            CanonicalValue::bytes(invitation_id.get().as_bytes().to_vec()),
            CanonicalValue::bytes(authorisation.as_bytes().to_vec()),
        ],
    )?;
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Ok(DeviceId::new(Uuid::from_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invitation(byte: u8) -> InvitationId {
        InvitationId::new(Uuid::from_bytes([byte; 16]))
    }

    /// The literal is the first 16 bytes of the SHA-256 of the bytes `83`, `73`, the 19 characters
    /// of the domain, `50`, 16 bytes of `0x11`, `58 20` and 32 bytes of `0x22`: the encoding
    /// written out by hand and hashed outside this workspace.
    #[test]
    fn the_identity_is_the_known_answer_of_the_encoding_written_out_by_hand() {
        let derived =
            committed_device_id(invitation(0x11), &AuthorisationKey::from_bytes([0x22; 32]))
                .expect("an identity");
        assert_eq!(
            derived.get().as_bytes(),
            &KNOWN_ANSWER,
            "the derivation is the one the design states"
        );
    }

    #[test]
    fn another_invitation_or_another_key_is_another_identity() {
        let key = AuthorisationKey::from_bytes([0x22; 32]);
        let base = committed_device_id(invitation(0x11), &key).expect("an identity");
        assert_eq!(
            base,
            committed_device_id(invitation(0x11), &key).expect("an identity"),
            "the same inputs give the same identity"
        );
        assert_ne!(
            base,
            committed_device_id(invitation(0x12), &key).expect("an identity")
        );
        assert_ne!(
            base,
            committed_device_id(invitation(0x11), &AuthorisationKey::from_bytes([0x23; 32]))
                .expect("an identity")
        );
    }

    const KNOWN_ANSWER: [u8; 16] = [
        0x36, 0xdc, 0x1e, 0x31, 0x54, 0x64, 0x40, 0xd8, 0x94, 0xe4, 0xef, 0x4c, 0xfd, 0x68, 0x38,
        0xcc,
    ];
}
