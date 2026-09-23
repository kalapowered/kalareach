//! The SPAKE2 exchange, on the pinned RustCrypto `spake2` crate.
//!
//! # The profile, stated plainly
//!
//! This is the `spake2` crate's own `Spake2<Ed25519Group>` profile, version 0.4.0, with explicit A
//! and B roles. It is **not** the RFC 9382 P-256 ciphersuite. The crate's documentation references
//! its earlier draft profile, discloses the absence of an independent security audit, and cautions
//! that its implementation is probably not constant-time. External review of this profile, its
//! side-channel behaviour and its integration here is a release gate, and its status stays open
//! until that evidence and the remediation decisions exist. A different RFC name or a longer ad
//! hoc shared secret is not an automatic substitute.
//!
//! No PAKE is implemented here. This module holds the state machine's rules about the library:
//!
//! * the host is role A and calls `start_a`; the candidate is role B and calls `start_b`;
//! * both pass the same two identities, host first, and the six ASCII secret characters;
//! * each side sends its library-produced message unchanged;
//! * `finish` is called exactly once, which the type system enforces by consuming the state;
//! * every attempt uses fresh library-generated randomness, and a state or a message is never
//!   reused after a timeout, a failure or a reconnection.
//!
//! Malformed messages, a wrong role and invalid group elements are rejected through the library's
//! own error path: [`SpakeState::finish`] calls `finish` and turns any error into the one
//! ambiguous authentication failure.

use spake2::{Ed25519Group, Identity, Password, Spake2};
use zeroize::Zeroizing;

use kr_protocol::pairing::PairingContext;

use crate::code::CodeSecret;
use crate::error::{PairingError, Result};
use crate::transcript::SharedKey;

/// Which side of the exchange a device is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// The host, role A.
    Host,
    /// The candidate, role B.
    Client,
}

/// One attempt's PAKE state and the message it produced.
///
/// The state is consumed by [`Self::finish`], so the compiler enforces "exactly once". A state
/// that is dropped without finishing is simply gone; nothing can resume it, which is what
/// section 10 requires after a timeout, a failure or a reconnection.
pub struct SpakeState {
    state: Spake2<Ed25519Group>,
    role: Role,
    message: Vec<u8>,
}

impl core::fmt::Debug for SpakeState {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "SpakeState({:?}, {} message bytes)",
            self.role,
            self.message.len()
        )
    }
}

impl SpakeState {
    /// Starts an attempt in `role` from the context both devices built.
    ///
    /// The library draws its own randomness for every call, so two attempts under one invitation
    /// never share a scalar.
    #[must_use]
    pub fn start(role: Role, context: &PairingContext, secret: &CodeSecret) -> Self {
        // The password is the six ASCII characters, and the identities are the two role values
        // section 10 fixes, passed in the same order by both sides.
        let password = Password::new(secret.expose());
        let host_identity = Identity::new(&context.host_identity());
        let client_identity = Identity::new(&context.client_identity());
        let (state, message) = match role {
            Role::Host => {
                Spake2::<Ed25519Group>::start_a(&password, &host_identity, &client_identity)
            }
            Role::Client => {
                Spake2::<Ed25519Group>::start_b(&password, &host_identity, &client_identity)
            }
        };
        Self {
            state,
            role,
            message,
        }
    }

    /// Returns the library-produced message, which is sent unchanged.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Returns the role this state was started in.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Finishes the exchange with the peer's message, consuming the state.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::AuthenticationFailed`] for a malformed message, a wrong role and an
    /// invalid group element alike. The library distinguishes them; this does not, because telling
    /// a caller which one it was would tell an attacker the same thing.
    pub fn finish(self, peer_message: &[u8]) -> Result<SharedKey> {
        let key = Zeroizing::new(
            self.state
                .finish(peer_message)
                .map_err(|_| PairingError::AuthenticationFailed)?,
        );
        SharedKey::from_library(&key)
    }
}

/// The version of the `spake2` crate this build is pinned to.
///
/// The release manifest records it alongside the resolved dependency graph, because the profile is
/// the crate's own and a different version could be a different profile.
pub const SPAKE2_VERSION: &str = "0.4.0";

/// The profile name this build uses. Not RFC 9382.
pub const SPAKE2_PROFILE: &str = "Spake2<Ed25519Group>";

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::{AttemptId, InvitationId};
    use kr_protocol::pairing::{Locator, RendezvousOrigin};
    use kr_protocol::scalars::{Nonce256, Uuid};

    fn context(attempt: u8) -> PairingContext {
        PairingContext {
            rendezvous_origin: RendezvousOrigin::new("https://reach.kala.to").expect("an origin"),
            locator: Locator::new("aB3x").expect("a locator"),
            invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            attempt_id: AttemptId::new(Uuid::from_bytes([attempt; 16])),
            host_nonce: Nonce256::from_bytes([3; 32]),
            client_nonce: Nonce256::from_bytes([4; 32]),
        }
    }

    fn secret(text: &str) -> CodeSecret {
        CodeSecret::new(text).expect("six alphabet characters")
    }

    /// KR-REQ-10.09: the host starts role A and the candidate role B, and the same code gives one
    /// key.
    #[test]
    fn the_same_password_gives_the_same_key() {
        let context = context(2);
        let password = secret("Yz79Qw");
        let host = SpakeState::start(Role::Host, &context, &password);
        let client = SpakeState::start(Role::Client, &context, &password);
        let host_message = host.message().to_vec();
        let client_message = client.message().to_vec();

        let host_key = host.finish(&client_message).expect("a shared key");
        let client_key = client.finish(&host_message).expect("a shared key");
        assert_eq!(host_key.expose(), client_key.expose());
    }

    #[test]
    fn a_different_password_gives_different_keys() {
        let context = context(2);
        let host = SpakeState::start(Role::Host, &context, &secret("Yz79Qw"));
        let client = SpakeState::start(Role::Client, &context, &secret("Yz79Qx"));
        let host_message = host.message().to_vec();
        let client_message = client.message().to_vec();

        // `finish` succeeds either way: it is the confirmation tags that detect this, which is
        // exactly why section 10 requires them.
        let host_key = host.finish(&client_message).expect("a key");
        let client_key = client.finish(&host_message).expect("a key");
        assert_ne!(host_key.expose(), client_key.expose());
    }

    #[test]
    fn a_different_context_gives_different_keys() {
        let password = secret("Yz79Qw");
        let host = SpakeState::start(Role::Host, &context(2), &password);
        let client = SpakeState::start(Role::Client, &context(9), &password);
        let host_message = host.message().to_vec();
        let client_message = client.message().to_vec();
        assert_ne!(
            host.finish(&client_message).expect("a key").expose(),
            client.finish(&host_message).expect("a key").expose()
        );
    }

    /// KR-REQ-10.09, KR-REQ-10.21: a message from the wrong role is refused by the library.
    #[test]
    fn a_wrong_role_is_rejected_through_the_library() {
        let context = context(2);
        let password = secret("Yz79Qw");
        let first = SpakeState::start(Role::Host, &context, &password);
        let second = SpakeState::start(Role::Host, &context, &password);
        let second_message = second.message().to_vec();
        // Two role-A messages: the library refuses to finish against its own side.
        assert!(matches!(
            first.finish(&second_message),
            Err(PairingError::AuthenticationFailed)
        ));
    }

    /// KR-REQ-10.21: malformed messages and invalid group elements are refused by the library.
    #[test]
    fn a_malformed_or_truncated_message_is_rejected() {
        let context = context(2);
        let password = secret("Yz79Qw");
        let client = SpakeState::start(Role::Client, &context, &password);
        let host = SpakeState::start(Role::Host, &context, &password);
        let mut message = client.message().to_vec();

        assert!(matches!(
            host.finish(&message[..message.len() - 1]),
            Err(PairingError::AuthenticationFailed)
        ));

        // An element that is not on the curve is refused by the library's own decoder. The role
        // byte stays correct, so this exercises element validation rather than the role check:
        // the compressed y-coordinate 2 has no point on the curve.
        let host = SpakeState::start(Role::Host, &context, &password);
        message.iter_mut().for_each(|byte| *byte = 0);
        message[0] = b'B';
        message[1] = 2;
        assert!(matches!(
            host.finish(&message),
            Err(PairingError::AuthenticationFailed)
        ));

        // The same encoding with a valid element is accepted by the library, which is what shows
        // the rejection above came from the element and not from the framing.
        let host = SpakeState::start(Role::Host, &context, &password);
        let peer = SpakeState::start(Role::Client, &context, &password);
        assert!(host.finish(peer.message()).is_ok());
    }

    /// KR-REQ-10.21: every attempt draws fresh library randomness.
    #[test]
    fn every_attempt_draws_fresh_randomness() {
        let context = context(2);
        let password = secret("Yz79Qw");
        let first = SpakeState::start(Role::Host, &context, &password);
        let second = SpakeState::start(Role::Host, &context, &password);
        assert_ne!(first.message(), second.message());
    }

    /// KR-REQ-10.21: a PAKE state is consumed by `finish` and cannot be reused.
    #[test]
    fn the_role_is_recorded_and_the_state_is_consumed_by_finishing() {
        let context = context(2);
        let password = secret("Yz79Qw");
        let host = SpakeState::start(Role::Host, &context, &password);
        assert_eq!(host.role(), Role::Host);
        assert!(format!("{host:?}").contains("Host"));
        let client = SpakeState::start(Role::Client, &context, &password);
        let client_message = client.message().to_vec();
        // `finish` takes `self`, so a second call does not compile. This is the whole rule.
        assert!(host.finish(&client_message).is_ok());
    }

    /// KR-REQ-10.09: the profile and version this build uses are recorded.
    #[test]
    fn the_pinned_profile_is_recorded() {
        assert_eq!(SPAKE2_VERSION, "0.4.0");
        assert_eq!(SPAKE2_PROFILE, "Spake2<Ed25519Group>");
    }
}
