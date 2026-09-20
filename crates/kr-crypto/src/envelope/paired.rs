//! The sender keys a device has paired with, and the only way an envelope is opened against one.
//!
//! Section 20: *decrypt only against previously paired sender keys*. A mailbox item arrives with a
//! routing record the service wrote, and that record names a sender. The record is untrusted, so
//! the name is used for one thing only: to **look up** a key this device already holds.
//! [`PairedSenders`] is that set, and [`open_delivered_envelope`] is the entry point a service's
//! delivery goes through, so nothing an envelope carries can introduce the key it is opened
//! against.
//!
//! [`super::open_envelope`] stays public beneath it, for a caller that already knows which key it
//! means: the vector generator opens a published envelope, and a host that has selected a sender
//! some other way opens with it directly. That caller takes on the two duties this entry point
//! discharges, selecting the sender from what it has paired with and recording the replay
//! identifier.
//!
//! The order is the contract:
//!
//! 1. the keyless rules of the item's own shape, before any key is touched;
//! 2. the sender key, selected from the paired set and never from the item;
//! 3. the box, the padding, the bindings and the expiry, which [`super::open_envelope`] holds;
//! 4. the replay identifier, recorded once the item has been accepted and not before.

use std::collections::BTreeMap;

use kr_protocol::mailbox::{EnvelopePlaintext, SealedEnvelope};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{KeyId, StoredEnvelopeKey};

use super::{ReplayLedger, open_envelope};
use crate::error::{CryptoError, Result};
use crate::keys::{StoredEnvelopeKeyPair, key_id};

/// The stored-envelope keys of the devices this one has paired with.
///
/// Keyed by the identifier this crate derives from each key rather than by one a caller passed in,
/// so a key can only ever be found under its own name. A pairing record is what puts a key here;
/// nothing an envelope carries can.
#[derive(Clone, Debug, Default)]
pub struct PairedSenders {
    by_key_id: BTreeMap<KeyId, StoredEnvelopeKey>,
}

impl PairedSenders {
    /// Returns an empty set, which opens nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a paired device's stored-envelope key, returning the key it replaced.
    ///
    /// The identifier is derived here. A caller that supplied one could file a key under another
    /// key's name, and every lookup after that would answer with the wrong key. What the caller
    /// still vouches for is the pairing itself: this set holds the keys it is given, and section 10
    /// is what puts a key in a caller's hands.
    pub fn pair(&mut self, key: StoredEnvelopeKey) -> Option<StoredEnvelopeKey> {
        let id = key_id(KeyPurpose::StoredEnvelope, key.as_bytes());
        self.by_key_id.insert(id, key)
    }

    /// Forgets a key, so envelopes from it stop opening.
    ///
    /// Unpairing is how a revoked device stops being a sender. It does not reach the items that
    /// were already opened, and section 20 does not claim it does.
    pub fn unpair(&mut self, key_id: KeyId) -> Option<StoredEnvelopeKey> {
        self.by_key_id.remove(&key_id)
    }

    /// Returns the paired key one identifier names, when this device holds it.
    #[must_use]
    pub fn get(&self, key_id: KeyId) -> Option<&StoredEnvelopeKey> {
        self.by_key_id.get(&key_id)
    }

    /// Returns true when this device has paired with the key that identifier names.
    #[must_use]
    pub fn contains(&self, key_id: KeyId) -> bool {
        self.by_key_id.contains_key(&key_id)
    }

    /// Returns how many senders are paired.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_key_id.len()
    }

    /// Returns true when nothing is paired.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_key_id.is_empty()
    }

    /// Returns every paired identifier, in order.
    pub fn key_ids(&self) -> impl Iterator<Item = KeyId> + '_ {
        self.by_key_id.keys().copied()
    }
}

/// Opens one delivered mailbox item against the senders this device has paired with.
///
/// This is the whole reading path for an item that came from a service, and it is deliberately the
/// only one that takes a [`ReplayLedger`]: an item that is accepted is recorded, because a caller
/// that could open without recording could be given the same item twice.
///
/// `verify_payload` carries the issuer's own verification for an authority-bearing payload, exactly
/// as [`super::open_envelope`] requires. [`super::verify_authority_payload`] is what a host passes.
/// It verifies and applies nothing: a refused item can be delivered again, so anything the callback
/// did would be done again with it.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when the item's shape is not one this contract admits,
/// when its routing record names a sender this device has not paired with, when a field inside the
/// envelope does not match the one outside it, when the expiry has passed or when the replay
/// identifier has been seen; [`CryptoError::Authentication`] when the box or the payload's own
/// signature does not verify.
pub fn open_delivered_envelope<F>(
    recipient: &StoredEnvelopeKeyPair,
    senders: &PairedSenders,
    ledger: &mut ReplayLedger,
    sealed_envelope: &SealedEnvelope,
    now_ms: u64,
    verify_payload: F,
) -> Result<EnvelopePlaintext>
where
    F: FnOnce(&EnvelopePlaintext) -> Result<()>,
{
    // Everything a reader can settle without a key, first. The declared bucket, the ciphertext's
    // length, the lifetime and the coalescing rule are the service's own admission rules, and a
    // recipient that did not apply them would accept an item the service should never have stored.
    sealed_envelope
        .check_structure(now_ms)
        .map_err(|_| CryptoError::BindingMismatch {
            what: "the shape of a delivered envelope",
        })?;

    // A redelivery of something already accepted is refused here, on the identifier the record
    // claims, so a service that offers one back does not cost a decryption and a signature check
    // every time. The claim is untrusted and this is only an early exit: what settles acceptance
    // is the admission at the end, on the identifier the box authenticated. A record that claimed
    // a spent identifier falsely is refused, which is a service suppressing its own item.
    if ledger.contains(sealed_envelope.routing.envelope_id) {
        return Err(CryptoError::BindingMismatch {
            what: "a replayed envelope identifier",
        });
    }

    // The routing record is untrusted, so the sender it names selects a key rather than supplying
    // one. A name this device has no key for is where an unpaired sender stops, before any
    // decryption is attempted.
    let sender =
        senders
            .get(sealed_envelope.routing.sender_key_id)
            .ok_or(CryptoError::BindingMismatch {
                what: "the sender of a delivered envelope, which this device has not paired with",
            })?;

    let plaintext = open_envelope(recipient, sender, sealed_envelope, now_ms, verify_payload)?;

    // Last, because an envelope refused for a reason that may pass, such as an issuer key this
    // host has not learnt yet, must still be openable when it does. An envelope that was accepted
    // is one that will never be accepted again.
    ledger.admit(&plaintext, now_ms)?;
    Ok(plaintext)
}
