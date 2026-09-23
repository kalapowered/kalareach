//! The pairing PAKE is the pinned `spake2` crate's own exchange, and nothing of this crate's.
//!
//! Each side of a pairing here is driven twice: once through this crate's state machine and once
//! by the library directly, with nothing of this crate in between. The two interoperate in both
//! roles, and the key this crate hands on is byte for byte the key the library derived, so the
//! group operations, the password mapping and the key derivation are all the library's.

use kr_pairing::code::CodeSecret;
use kr_pairing::spake::{Role, SPAKE2_PROFILE, SPAKE2_VERSION, SpakeState};
use kr_protocol::ids::{AttemptId, InvitationId};
use kr_protocol::pairing::{Locator, PairingContext, RendezvousOrigin};
use kr_protocol::scalars::{Nonce256, Uuid};
use spake2::{Ed25519Group, Identity, Password, Spake2};

const SECRET: &str = "Yz79Qw";

fn context() -> PairingContext {
    PairingContext {
        rendezvous_origin: RendezvousOrigin::new("https://reach.kala.to").expect("an origin"),
        locator: Locator::new("aB3x").expect("a locator"),
        invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
        attempt_id: AttemptId::new(Uuid::from_bytes([2; 16])),
        host_nonce: Nonce256::from_bytes([3; 32]),
        client_nonce: Nonce256::from_bytes([4; 32]),
    }
}

fn secret() -> CodeSecret {
    CodeSecret::new(SECRET).expect("six alphabet characters")
}

/// The library started directly, in role A for the host or role B for the candidate, with the
/// identities and the password section 10 fixes.
fn library(
    role: Role,
    context: &PairingContext,
    password: &str,
) -> (Spake2<Ed25519Group>, Vec<u8>) {
    let password = Password::new(password.as_bytes());
    let host = Identity::new(&context.host_identity());
    let client = Identity::new(&context.client_identity());
    match role {
        Role::Host => Spake2::<Ed25519Group>::start_a(&password, &host, &client),
        Role::Client => Spake2::<Ed25519Group>::start_b(&password, &host, &client),
    }
}

/// KR-REQ-20.03: the PAKE is the pinned library's. This crate's host completes an exchange with a
/// candidate the library drives on its own, and this crate's candidate with a host the library
/// drives on its own; in both the key this crate returns is exactly the library's, and a library
/// peer with another password derives a different key.
#[test]
fn the_pairing_exchange_is_the_spake2_librarys_own() {
    assert_eq!(SPAKE2_VERSION, "0.4.0");
    assert_eq!(SPAKE2_PROFILE, "Spake2<Ed25519Group>");
    let context = context();

    // This crate's host against the library's candidate.
    let host = SpakeState::start(Role::Host, &context, &secret());
    let host_message = host.message().to_vec();
    let (candidate, candidate_message) = library(Role::Client, &context, SECRET);
    let library_key = candidate
        .finish(&host_message)
        .expect("the library accepts this crate's message");
    let host_key = host
        .finish(&candidate_message)
        .expect("this crate accepts the library's message");
    assert_eq!(host_key.expose().as_slice(), library_key.as_slice());

    // This crate's candidate against the library's host.
    let candidate = SpakeState::start(Role::Client, &context, &secret());
    let candidate_message = candidate.message().to_vec();
    let (host, host_message) = library(Role::Host, &context, SECRET);
    let library_key = host
        .finish(&candidate_message)
        .expect("the library accepts this crate's message");
    let candidate_key = candidate
        .finish(&host_message)
        .expect("this crate accepts the library's message");
    assert_eq!(candidate_key.expose().as_slice(), library_key.as_slice());

    // The same library peer with another password: both sides finish, and the keys differ, which
    // is what the confirmation tags then catch.
    let host = SpakeState::start(Role::Host, &context, &secret());
    let host_message = host.message().to_vec();
    let (candidate, candidate_message) = library(Role::Client, &context, "Yz79Qx");
    let library_key = candidate
        .finish(&host_message)
        .expect("the library finishes");
    let host_key = host
        .finish(&candidate_message)
        .expect("this crate finishes");
    assert_ne!(host_key.expose().as_slice(), library_key.as_slice());
}
