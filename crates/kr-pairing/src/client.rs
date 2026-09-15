//! The candidate's short-code state machine and its own attempt budget.
//!
//! The host limits guesses against one invitation. This limits guesses *from* one device, and the
//! two are separate by design: the host's bound is not an aggregate across clients, so reusing a
//! code on several devices increases the total guessing opportunities unless each device limits
//! itself. Section 10's rules, stated here as code:
//!
//! * five attempts per entered code, and no automatic retry after a failed key confirmation;
//! * the counter is keyed by an HMAC of the locally configured origin and the normalised full
//!   code, under a distinct random local key from secure storage, never a transport or control
//!   key, and never by the service-supplied invitation identity or expiry;
//! * the five-minute window starts at local first entry, on monotonic time and the boot identity;
//! * the count survives an application restart and a reconnection, and an operating-system reboot
//!   expires an unfinished entry;
//! * an exhausted or expired entry leaves a tombstone for 24 hours, so another advertised expiry
//!   cannot reset the counter;
//! * a new manual attempt keeps that budget until it expires, and an exhausted entry needs a newly
//!   issued code.
//!
//! The candidate also verifies the host's confirmation tag **before** it trusts any host metadata.
//! Until then the invitation identity and the expiry the service returned are the service's word.

use kr_crypto::kdf;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::ids::AttemptId;
use kr_protocol::pairing::{
    BundleMessageType, CLIENT_TOMBSTONE_MS, ClientBundle, INVITATION_LIFETIME_MS,
    MAX_CLIENT_ATTEMPTS, PairFinishRequest, PairingContext, RendezvousOrigin, SignedHostBundle,
    finish_mac_input, verification_value,
};
use kr_protocol::scalars::{Digest256, EndpointKey, Mac256, Nonce256};

use crate::bundles::{self, BundleFrame, ExchangeBudget};
use crate::code::EnteredCode;
use crate::error::{PairingError, Result};
use crate::host::{new_attempt_id, new_nonce};
use crate::platform::{
    ClientAttemptRecord, ClientBudgetStore, LivePeer, LocatorRecord, PairingClock, RendezvousClient,
};
use crate::spake::{Role, SpakeState};
use crate::transcript::AttemptKeys;

/// The domain the client attempt counter is keyed under.
///
/// The key is this device's own random local key, so the tag says nothing to anyone who has not
/// got it: a service cannot tell which codes a device has tried, and neither can anything that
/// saw a transport key.
pub const CLIENT_BUDGET_DOMAIN: &str = "kr-pair/client-budget/1";

/// Returns the counter key for one origin and one entered code.
///
/// # Errors
///
/// Returns [`PairingError::Store`] when the local key cannot be read.
pub fn budget_key(
    store: &dyn ClientBudgetStore,
    origin: &RendezvousOrigin,
    code: &EnteredCode,
) -> Result<Mac256> {
    let key = store.budget_key()?;
    // The origin and the code are both inside the tag: the same ten characters at two origins are
    // two entries, because they are two different invitations.
    let message = kr_cbor::encode(&kr_cbor::signing_value(
        CLIENT_BUDGET_DOMAIN,
        vec![
            kr_cbor::CanonicalValue::text(origin.as_str()),
            kr_cbor::CanonicalValue::text(code.normalised()),
        ],
    ));
    Ok(kdf::hmac_sha256(&key, &message))
}

/// Charges one attempt against this device's budget for a code.
///
/// Returns how many attempts are left after this one.
///
/// # Errors
///
/// Returns [`PairingError::ClientAttemptsExhausted`] when the code is spent, and
/// [`PairingError::Store`] when the record cannot be read or written.
pub fn charge_attempt(
    store: &dyn ClientBudgetStore,
    clock: &dyn PairingClock,
    origin: &RendezvousOrigin,
    code: &EnteredCode,
) -> Result<u32> {
    let now = clock.monotonic_ms();
    let boot = clock.boot_identity();
    store.expire(now, boot)?;

    let key = budget_key(store, origin, code)?;
    let mut record = match store.load(&key)? {
        Some(record) if record.boot_identity != boot => {
            // A reboot expires an unfinished entry: its monotonic values belong to another boot,
            // and a tombstone that outlived the reboot is gone with it.
            fresh_record(now, boot)
        }
        Some(record) if record.exhausted => {
            // The tombstone is the point: another advertised expiry does not reset the counter.
            return Err(PairingError::ClientAttemptsExhausted);
        }
        Some(record)
            if now.saturating_sub(record.first_entry_monotonic_ms) >= INVITATION_LIFETIME_MS =>
        {
            // The window ran out. The entry becomes a tombstone rather than a fresh start.
            let mut spent = record;
            spent.exhausted = true;
            spent.retain_until_monotonic_ms = now.saturating_add(CLIENT_TOMBSTONE_MS);
            store.save(&key, &spent)?;
            return Err(PairingError::ClientAttemptsExhausted);
        }
        Some(record) => record,
        None => fresh_record(now, boot),
    };

    if record.attempts >= MAX_CLIENT_ATTEMPTS {
        record.exhausted = true;
        record.retain_until_monotonic_ms = now.saturating_add(CLIENT_TOMBSTONE_MS);
        store.save(&key, &record)?;
        return Err(PairingError::ClientAttemptsExhausted);
    }
    record.attempts += 1;
    let remaining = MAX_CLIENT_ATTEMPTS - record.attempts;
    if remaining == 0 {
        record.exhausted = true;
    }
    // A tombstone outlives the window, so an exhausted or expired entry is still refused a day
    // later.
    record.retain_until_monotonic_ms = record
        .first_entry_monotonic_ms
        .saturating_add(INVITATION_LIFETIME_MS)
        .saturating_add(CLIENT_TOMBSTONE_MS);
    store.save(&key, &record)?;
    Ok(remaining)
}

fn fresh_record(now: u64, boot: crate::platform::BootIdentity) -> ClientAttemptRecord {
    ClientAttemptRecord {
        attempts: 0,
        first_entry_monotonic_ms: now,
        boot_identity: boot,
        retain_until_monotonic_ms: now
            .saturating_add(INVITATION_LIFETIME_MS)
            .saturating_add(CLIENT_TOMBSTONE_MS),
        exhausted: false,
    }
}

/// Where the candidate's attempt has reached.
#[derive(Debug, PartialEq, Eq)]
enum ClientPhase {
    /// The candidate has sent its PAKE message and is waiting for the host's.
    AwaitingHostPake,
    /// The candidate has sent its confirmation tag and is waiting for the host's.
    AwaitingHostConfirmation,
    /// The tags matched. Until this point nothing the host said was trusted.
    Confirmed,
    /// The host's bundle is in.
    HostBundleReceived,
}

impl ClientPhase {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::AwaitingHostPake => "the host's PAKE message",
            Self::AwaitingHostConfirmation => "the host's confirmation tag",
            Self::Confirmed => "the bundle exchange",
            Self::HostBundleReceived => "pair.finish",
        }
    }
}

/// What a candidate sends the host to be admitted.
///
/// Section 10 has the candidate create both: a random 128-bit attempt identity and a 256-bit
/// nonce. The host adds its own nonce and admits the attempt under the invitation's budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientAdmission {
    /// The candidate's attempt identity.
    pub attempt_id: AttemptId,
    /// The candidate's nonce.
    pub client_nonce: Nonce256,
}

/// One candidate's attempt at one code.
///
/// `Debug` names the phase and nothing else: the attempt holds the five derived keys, and a
/// derived rendering would put them where a log can find them.
pub struct ClientAttempt {
    context: PairingContext,
    phase: ClientPhase,
    spake: Option<SpakeState>,
    transcript: Option<Digest256>,
    keys: Option<AttemptKeys>,
    budget: ExchangeBudget,
    host_bundle: Option<SignedHostBundle>,
    host_bundle_hash: Option<Digest256>,
    client_bundle_hash: Option<Digest256>,
    remaining_attempts: u32,
}

impl core::fmt::Debug for ClientAttempt {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "ClientAttempt(awaiting {}, {} attempts left)",
            self.phase.as_str(),
            self.remaining_attempts
        )
    }
}

impl ClientAttempt {
    /// Starts an attempt: looks the locator up, charges the budget and builds the context.
    ///
    /// Only the four locator characters reach the service. What it answers is untrusted until the
    /// host's confirmation tag verifies, which is why the invitation identity it returns goes
    /// straight into the context and nowhere else.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::ClientAttemptsExhausted`], [`PairingError::RendezvousUnavailable`],
    /// [`PairingError::Store`] or a crypto error.
    pub fn start(
        store: &dyn ClientBudgetStore,
        clock: &dyn PairingClock,
        rendezvous: &dyn RendezvousClient,
        origin: &RendezvousOrigin,
        code: &EnteredCode,
    ) -> Result<(Self, ClientAdmission, LocatorRecord)> {
        let remaining_attempts = charge_attempt(store, clock, origin, code)?;
        let record = rendezvous.lookup(origin, code.locator())?;
        let context = PairingContext {
            rendezvous_origin: origin.clone(),
            locator: code.locator().clone(),
            invitation_id: record.invitation_id,
            attempt_id: new_attempt_id()?,
            // The host's nonce is not known yet; it arrives with the host's admission and is set
            // by `with_host_nonce` before either side derives anything.
            host_nonce: Nonce256::from_bytes([0; 32]),
            client_nonce: new_nonce()?,
        };
        let attempt = Self {
            context,
            phase: ClientPhase::AwaitingHostPake,
            spake: None,
            transcript: None,
            keys: None,
            budget: ExchangeBudget::new(),
            host_bundle: None,
            host_bundle_hash: None,
            client_bundle_hash: None,
            remaining_attempts,
        };
        let admission = ClientAdmission {
            attempt_id: attempt.context.attempt_id,
            client_nonce: attempt.context.client_nonce,
        };
        Ok((attempt, admission, record))
    }

    /// Records the host's nonce and produces the candidate's PAKE message.
    ///
    /// The candidate builds `C` itself from its own configured origin and its own nonce; the host
    /// nonce and the attempt identity are the only members either side takes from the other, and
    /// both are covered by the transcript that the confirmation tags authenticate.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`] when the attempt has moved on.
    pub fn with_host_nonce(&mut self, host_nonce: Nonce256, code: &EnteredCode) -> Result<Vec<u8>> {
        if self.phase != ClientPhase::AwaitingHostPake || self.spake.is_some() {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::AwaitingHostPake.as_str(),
                actual: self.phase.as_str(),
            });
        }
        self.context.host_nonce = host_nonce;
        let spake = SpakeState::start(Role::Client, &self.context, code.secret());
        let message = spake.message().to_vec();
        self.spake = Some(spake);
        Ok(message)
    }

    /// Returns the context this candidate built.
    #[must_use]
    pub const fn context(&self) -> &PairingContext {
        &self.context
    }

    /// Returns how many attempts this device has left for the code.
    #[must_use]
    pub const fn remaining_attempts(&self) -> u32 {
        self.remaining_attempts
    }

    /// Takes the host's PAKE message and returns the candidate's confirmation tag.
    ///
    /// The candidate confirms first, which is the order section 10 fixes.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`] or [`PairingError::AuthenticationFailed`].
    pub fn receive_host_pake(&mut self, host_message: &[u8]) -> Result<Mac256> {
        if self.phase != ClientPhase::AwaitingHostPake {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::AwaitingHostPake.as_str(),
                actual: self.phase.as_str(),
            });
        }
        let spake = self.spake.take().ok_or(PairingError::WrongPhase {
            expected: ClientPhase::AwaitingHostPake.as_str(),
            actual: self.phase.as_str(),
        })?;
        let client_message = spake.message().to_vec();
        let shared = spake.finish(host_message)?;
        let transcript = self.context.transcript(host_message, &client_message);
        let keys = AttemptKeys::derive(shared.expose(), transcript)?;
        let tag = keys.client_confirmation(transcript);
        self.transcript = Some(transcript);
        self.keys = Some(keys);
        self.phase = ClientPhase::AwaitingHostConfirmation;
        Ok(tag)
    }

    /// Verifies the host's confirmation tag.
    ///
    /// Nothing the host said is trusted before this returns. There is no automatic retry after it
    /// fails: a failed key confirmation ends the attempt, and another attempt is a deliberate act
    /// that charges the budget again.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`] or [`PairingError::AuthenticationFailed`].
    pub fn verify_host_confirmation(&mut self, tag: &Mac256) -> Result<()> {
        if self.phase != ClientPhase::AwaitingHostConfirmation {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::AwaitingHostConfirmation.as_str(),
                actual: self.phase.as_str(),
            });
        }
        let (Some(keys), Some(transcript)) = (self.keys.as_ref(), self.transcript) else {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::AwaitingHostConfirmation.as_str(),
                actual: self.phase.as_str(),
            });
        };
        keys.verify_host_confirmation(transcript, tag)?;
        self.phase = ClientPhase::Confirmed;
        Ok(())
    }

    /// Opens and verifies the host's signed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`], [`PairingError::ReplayedSequence`],
    /// [`PairingError::TooLarge`], [`PairingError::AuthenticationFailed`] or
    /// [`PairingError::ContextMismatch`] when the bundle answers another invitation.
    pub fn open_host_bundle(&mut self, frame: &BundleFrame) -> Result<SignedHostBundle> {
        if self.phase != ClientPhase::Confirmed {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::Confirmed.as_str(),
                actual: self.phase.as_str(),
            });
        }
        let (Some(keys), Some(transcript)) = (self.keys.as_ref(), self.transcript) else {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::Confirmed.as_str(),
                actual: self.phase.as_str(),
            });
        };
        let signed: SignedHostBundle = bundles::open_bundle(
            &keys.host_to_client,
            transcript,
            BundleMessageType::HostBundle,
            &mut self.budget,
            frame,
        )?;
        bundles::verify_host_bundle(&signed, transcript)?;
        if signed.bundle.invitation_id != self.context.invitation_id {
            return Err(PairingError::ContextMismatch {
                what: "the invitation a host bundle answers",
            });
        }
        if !signed.bundle.keys.purposes_are_distinct() {
            return Err(PairingError::ContextMismatch {
                what: "a host's key purposes, two of which share a key",
            });
        }
        self.host_bundle_hash = Some(bundles::bundle_hash(&signed.bundle)?);
        self.host_bundle = Some(signed.clone());
        self.phase = ClientPhase::HostBundleReceived;
        Ok(signed)
    }

    /// Seals the candidate's signed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`], an encoding error or a library error.
    pub fn seal_client_bundle(
        &mut self,
        authorisation: &AuthorisationKeyPair,
        bundle: ClientBundle,
    ) -> Result<BundleFrame> {
        if self.phase != ClientPhase::HostBundleReceived {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::HostBundleReceived.as_str(),
                actual: self.phase.as_str(),
            });
        }
        let (Some(keys), Some(transcript)) = (self.keys.as_ref(), self.transcript) else {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::HostBundleReceived.as_str(),
                actual: self.phase.as_str(),
            });
        };
        let signed = bundles::sign_client_bundle(authorisation, bundle, transcript)?;
        self.client_bundle_hash = Some(bundles::bundle_hash(&signed.bundle)?);
        bundles::seal_bundle(
            &keys.client_to_host,
            transcript,
            BundleMessageType::ClientBundle,
            &mut self.budget,
            &signed,
        )
    }

    /// Builds `pair.finish` and checks the live host endpoint against the authenticated bundle.
    ///
    /// The candidate connects to the endpoint the *authenticated* bundle pinned, not to one the
    /// service supplied, and checks that the peer it reached is that endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`] and [`PairingError::EndpointMismatch`].
    pub fn finish_request(
        &self,
        live_peer: &dyn LivePeer,
        client_endpoint: &EndpointKey,
    ) -> Result<PairFinishRequest> {
        let (
            Some(keys),
            Some(transcript),
            Some(host_bundle),
            Some(host_bundle_hash),
            Some(client_bundle_hash),
        ) = (
            self.keys.as_ref(),
            self.transcript,
            self.host_bundle.as_ref(),
            self.host_bundle_hash,
            self.client_bundle_hash,
        )
        else {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::HostBundleReceived.as_str(),
                actual: self.phase.as_str(),
            });
        };
        if live_peer.live_endpoint()? != host_bundle.bundle.endpoint_id {
            return Err(PairingError::EndpointMismatch { side: "host" });
        }
        let message = finish_mac_input(
            self.context.invitation_id,
            self.context.attempt_id,
            transcript,
            &host_bundle.bundle.endpoint_id,
            client_endpoint,
            host_bundle_hash,
            client_bundle_hash,
        );
        Ok(PairFinishRequest {
            invitation_id: self.context.invitation_id,
            attempt_id: self.context.attempt_id,
            transcript,
            host_bundle_hash,
            client_bundle_hash,
            binding_tag: keys.binding_tag(&message),
        })
    }

    /// Returns the eight hexadecimal characters this device displays.
    ///
    /// Both devices show the same value. It helps the owner identify the request; the PAKE
    /// authentication and the endpoint binding do not depend on those eight characters alone.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`] before both bundles are in.
    pub fn verification_value(&self) -> Result<String> {
        let (Some(transcript), Some(host), Some(client)) = (
            self.transcript,
            self.host_bundle_hash,
            self.client_bundle_hash,
        ) else {
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::HostBundleReceived.as_str(),
                actual: self.phase.as_str(),
            });
        };
        Ok(verification_value(transcript, host, client))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{TestClient, TestClientBudgetStore, TestClock};
    use kr_protocol::ids::InvitationId;
    use kr_protocol::scalars::{TimestampMs, Uuid};

    fn origin() -> RendezvousOrigin {
        RendezvousOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn code() -> EnteredCode {
        EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code")
    }

    #[test]
    fn a_device_gets_five_attempts_per_code() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        for expected in (0..MAX_CLIENT_ATTEMPTS).rev() {
            assert_eq!(
                charge_attempt(&store, &clock, &origin(), &code()).expect("an attempt"),
                expected
            );
        }
        assert!(matches!(
            charge_attempt(&store, &clock, &origin(), &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));
    }

    #[test]
    fn the_counter_survives_a_restart_and_is_not_keyed_by_the_service() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        charge_attempt(&store, &clock, &origin(), &code()).expect("an attempt");
        // A "restart" is a new state machine over the same store: the record is what carries the
        // count, and nothing the service said is part of its key.
        assert_eq!(
            charge_attempt(&store, &clock, &origin(), &code()).expect("an attempt"),
            MAX_CLIENT_ATTEMPTS - 2
        );
    }

    #[test]
    fn the_same_code_at_another_origin_is_another_entry() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        let elsewhere = RendezvousOrigin::new("https://elsewhere.example").expect("an origin");
        for _ in 0..MAX_CLIENT_ATTEMPTS {
            charge_attempt(&store, &clock, &origin(), &code()).expect("an attempt");
        }
        assert!(charge_attempt(&store, &clock, &origin(), &code()).is_err());
        assert_eq!(
            charge_attempt(&store, &clock, &elsewhere, &code()).expect("an attempt"),
            MAX_CLIENT_ATTEMPTS - 1
        );
    }

    #[test]
    fn two_spellings_of_one_code_share_a_counter() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        let grouped = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");
        let spaced = EnteredCode::parse(" aB3x Yz7 9Qw ").expect("a code");
        charge_attempt(&store, &clock, &origin(), &grouped).expect("an attempt");
        assert_eq!(
            charge_attempt(&store, &clock, &origin(), &spaced).expect("an attempt"),
            MAX_CLIENT_ATTEMPTS - 2
        );
    }

    #[test]
    fn the_window_starts_at_first_entry_and_a_tombstone_outlives_it() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        charge_attempt(&store, &clock, &origin(), &code()).expect("an attempt");

        clock.advance(INVITATION_LIFETIME_MS - 1);
        assert!(charge_attempt(&store, &clock, &origin(), &code()).is_ok());

        clock.advance(1);
        assert!(matches!(
            charge_attempt(&store, &clock, &origin(), &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));

        // A day later the tombstone still refuses the code: another advertised expiry cannot
        // reset the counter.
        clock.advance(CLIENT_TOMBSTONE_MS - 1);
        assert!(matches!(
            charge_attempt(&store, &clock, &origin(), &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));
    }

    #[test]
    fn a_tombstone_is_dropped_once_its_retention_ends() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        for _ in 0..MAX_CLIENT_ATTEMPTS {
            charge_attempt(&store, &clock, &origin(), &code()).expect("an attempt");
        }
        assert!(charge_attempt(&store, &clock, &origin(), &code()).is_err());
        clock.advance(INVITATION_LIFETIME_MS + CLIENT_TOMBSTONE_MS);
        // The record is gone, so an entirely new code entry starts fresh. The invitation itself
        // is long expired by then, which is what makes this safe.
        assert!(charge_attempt(&store, &clock, &origin(), &code()).is_ok());
    }

    #[test]
    fn a_reboot_expires_an_unfinished_entry() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        charge_attempt(&store, &clock, &origin(), &code()).expect("an attempt");
        charge_attempt(&store, &clock, &origin(), &code()).expect("an attempt");
        clock.reboot(9);
        assert_eq!(
            charge_attempt(&store, &clock, &origin(), &code()).expect("an attempt"),
            MAX_CLIENT_ATTEMPTS - 1
        );
    }

    #[test]
    fn the_counter_key_is_not_the_code_and_not_the_origin() {
        let store = TestClientBudgetStore::new().expect("a store");
        let key = budget_key(&store, &origin(), &code()).expect("a key");
        let text = hex::encode(key.as_bytes());
        assert!(!text.contains(&hex::encode(code().normalised())));
        assert!(!text.contains(&hex::encode(origin().as_str())));

        // Another device's key gives another tag for the same code.
        let other = TestClientBudgetStore::new().expect("a store");
        assert_ne!(key, budget_key(&other, &origin(), &code()).expect("a key"));
    }

    #[test]
    fn a_lookup_sends_only_the_locator() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        let rendezvous = TestClient::new(LocatorRecord {
            invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            advertised_expires_at_ms: TimestampMs::new(9_999),
        });
        let (attempt, admission, record) =
            ClientAttempt::start(&store, &clock, &rendezvous, &origin(), &code())
                .expect("an attempt");
        assert_eq!(admission.attempt_id, attempt.context().attempt_id);
        assert_eq!(rendezvous.looked_up(), vec!["aB3x".to_owned()]);
        assert_eq!(attempt.context().invitation_id, record.invitation_id);
        assert_eq!(attempt.remaining_attempts(), MAX_CLIENT_ATTEMPTS - 1);
    }
}
