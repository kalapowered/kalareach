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
//! "Expires an unfinished entry" is not "forgets it". A reboot ends the window and leaves a
//! tombstone, exactly as running out of time does; the tombstone's retention is on the wall clock,
//! because a monotonic deadline from the previous boot means nothing after one.
//!
//! The candidate also verifies the host's confirmation tag **before** it trusts any host metadata.
//! Until then the invitation identity and the expiry the service returned are the service's word.

use core::cell::Cell;

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
use crate::code::{CodeSecret, EnteredCode};
use crate::error::{PairingError, Result};
use crate::host::{HANDSHAKE_DEADLINE_MS, new_attempt_id, new_nonce};
use crate::platform::{
    BootIdentity, ClientAttemptRecord, ClientBudgetStore, LivePeer, LocatorRecord, PairingClock,
    RendezvousClient, require_completed_handshake,
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
/// The message the tag covers is assembled by hand into a buffer that clears itself: the code is
/// in it, and handing it to an encoder would copy it into buffers no caller can reach.
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
    // `CBOR([domain, origin, code])`, written out so the code reaches no encoder. The origin and
    // the code are both inside the tag: the same ten characters at two origins are two entries,
    // because they are two different invitations.
    let mut message = zeroize::Zeroizing::new(Vec::with_capacity(128));
    message.push(0x83);
    message.extend_from_slice(&kr_cbor::encode(&kr_cbor::CanonicalValue::text(
        CLIENT_BUDGET_DOMAIN,
    )));
    message.extend_from_slice(&kr_cbor::encode(&kr_cbor::CanonicalValue::text(
        origin.as_str(),
    )));
    let normalised = code.normalised().as_bytes();
    message.push(0x60 | u8::try_from(normalised.len()).expect("ten characters fit in a byte"));
    message.extend_from_slice(normalised);
    Ok(kdf::hmac_sha256(&key, &message))
}

/// Charges one attempt against this device's budget for a code.
///
/// Returns how many attempts are left after this one. The read, the decision and the write are one
/// atomic transition through [`ClientBudgetStore::update`], so two entries of the same code cannot
/// both see four attempts and both proceed. A refusal is a write too: the window running out and a
/// reboot both leave a tombstone, recorded inside the same transition.
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
    let wall = clock.wall_clock_ms();
    store.expire(now, boot, wall)?;

    let key = budget_key(store, origin, code)?;
    // The decision runs inside the store's lock, so this is how its outcome gets out. The store
    // may call the closure more than once while it retries; the last call is the one it wrote.
    let permitted = Cell::new(false);
    let record = store.update(&key, &|current| {
        let (next, allowed) = next_record(current, now, boot, wall);
        permitted.set(allowed);
        Ok(next)
    })?;
    if !permitted.get() {
        return Err(PairingError::ClientAttemptsExhausted);
    }
    Ok(MAX_CLIENT_ATTEMPTS.saturating_sub(record.attempts))
}

/// Decides what one code's record becomes, and whether the attempt may proceed.
///
/// This is the whole budget rule in one pure function. Every path returns a record to write: a
/// refusal that left nothing behind would let the next entry start the five minutes again.
fn next_record(
    current: Option<ClientAttemptRecord>,
    now: u64,
    boot: BootIdentity,
    wall: u64,
) -> (ClientAttemptRecord, bool) {
    let Some(record) = current else {
        return (charge(fresh(now, boot, wall), now, wall), true);
    };
    // A record from an earlier boot is anchored to this one the first time it is seen: the reboot
    // ended its window, and from here its retention runs on a clock a wall-clock jump cannot move.
    let record = record.anchored(now, boot);
    if record.exhausted {
        // Spent. Another advertised expiry does not reset the counter, and neither does anything
        // else: an exhausted entry needs a newly issued code.
        return (record, false);
    }
    // The window ran out, or the five attempts did. Either way the entry becomes a tombstone
    // rather than a fresh start.
    if now.saturating_sub(record.first_entry_monotonic_ms) >= INVITATION_LIFETIME_MS
        || record.attempts >= MAX_CLIENT_ATTEMPTS
    {
        return (tombstone(record, now, wall), false);
    }
    (charge(record, now, wall), true)
}

/// Returns the record a first entry creates.
const fn fresh(now: u64, boot: BootIdentity, wall: u64) -> ClientAttemptRecord {
    ClientAttemptRecord {
        attempts: 0,
        first_entry_monotonic_ms: now,
        boot_identity: boot,
        retain_until_monotonic_ms: now,
        retain_until_wall_ms: wall,
        exhausted: false,
    }
}

/// Adds one attempt to a record and extends its retention.
fn charge(record: ClientAttemptRecord, now: u64, wall: u64) -> ClientAttemptRecord {
    let attempts = record.attempts.saturating_add(1);
    let retention = INVITATION_LIFETIME_MS.saturating_add(CLIENT_TOMBSTONE_MS);
    ClientAttemptRecord {
        attempts,
        exhausted: attempts >= MAX_CLIENT_ATTEMPTS,
        // A spent entry outlives its window by the tombstone period. Both clocks are written: the
        // monotonic one governs while the machine is up, the wall one after a reboot.
        retain_until_monotonic_ms: now.saturating_add(retention),
        retain_until_wall_ms: wall.saturating_add(retention),
        ..record
    }
}

/// Marks a record spent and keeps it for the tombstone period.
///
/// Both clocks again, and for the same reason: a wall clock that jumps forward must not delete a
/// tombstone while the machine that wrote it is still up, and a monotonic deadline from the
/// previous boot means nothing after one.
fn tombstone(record: ClientAttemptRecord, now: u64, wall: u64) -> ClientAttemptRecord {
    ClientAttemptRecord {
        exhausted: true,
        retain_until_monotonic_ms: now.saturating_add(CLIENT_TOMBSTONE_MS),
        retain_until_wall_ms: wall.saturating_add(CLIENT_TOMBSTONE_MS),
        ..record
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
    /// The attempt is over: it failed, expired or completed. Nothing resumes it.
    Finished,
}

impl ClientPhase {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::AwaitingHostPake => "the host's PAKE message",
            Self::AwaitingHostConfirmation => "the host's confirmation tag",
            Self::Confirmed => "the bundle exchange",
            Self::HostBundleReceived => "pair.finish",
            Self::Finished => "nothing: this attempt is over",
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
/// The code's secret is bound at creation, so a later step cannot substitute another code against
/// the budget this attempt charged. Every failure is terminal: there is no automatic retry after a
/// failed key confirmation, and another attempt charges the budget again.
///
/// `Debug` names the phase and nothing else: the attempt holds the code secret and the five
/// derived keys, and a derived rendering would put them where a log can find them.
pub struct ClientAttempt {
    context: PairingContext,
    secret: CodeSecret,
    phase: ClientPhase,
    spake: Option<SpakeState>,
    transcript: Option<Digest256>,
    keys: Option<AttemptKeys>,
    budget: ExchangeBudget,
    host_bundle: Option<SignedHostBundle>,
    host_bundle_hash: Option<Digest256>,
    client_bundle_hash: Option<Digest256>,
    remaining_attempts: u32,
    deadline_monotonic_ms: u64,
    boot_identity: BootIdentity,
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
            secret: code.secret().clone(),
            phase: ClientPhase::AwaitingHostPake,
            spake: None,
            transcript: None,
            keys: None,
            budget: ExchangeBudget::new(),
            host_bundle: None,
            host_bundle_hash: None,
            client_bundle_hash: None,
            remaining_attempts,
            // The candidate's own handshake deadline. The host has one too, and neither extends it
            // on progress.
            deadline_monotonic_ms: clock.monotonic_ms().saturating_add(HANDSHAKE_DEADLINE_MS),
            boot_identity: clock.boot_identity(),
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
    /// nonce is the only member it takes from the other side, and it is covered by the transcript
    /// the confirmation tags authenticate.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`] when the attempt has moved on or already produced a
    /// message, and [`PairingError::Expired`] past its handshake deadline.
    pub fn with_host_nonce(
        &mut self,
        host_nonce: Nonce256,
        clock: &dyn PairingClock,
    ) -> Result<Vec<u8>> {
        self.require_phase(ClientPhase::AwaitingHostPake, clock)?;
        if self.spake.is_some() {
            // One exchange per attempt. Starting another would run a second guess against the
            // budget this attempt already charged.
            self.phase = ClientPhase::Finished;
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::AwaitingHostPake.as_str(),
                actual: "an attempt that has already produced its message",
            });
        }
        self.context.host_nonce = host_nonce;
        let spake = SpakeState::start(Role::Client, &self.context, &self.secret);
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

    /// Returns true when the attempt is over.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.phase == ClientPhase::Finished
    }

    /// Takes the host's PAKE message and returns the candidate's confirmation tag.
    ///
    /// The candidate confirms first, which is the order section 10 fixes.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`], [`PairingError::Expired`] or
    /// [`PairingError::AuthenticationFailed`], after which the attempt is over.
    pub fn receive_host_pake(
        &mut self,
        host_message: &[u8],
        clock: &dyn PairingClock,
    ) -> Result<Mac256> {
        self.require_phase(ClientPhase::AwaitingHostPake, clock)?;
        let Some(spake) = self.spake.take() else {
            self.phase = ClientPhase::Finished;
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::AwaitingHostPake.as_str(),
                actual: "an attempt with no message of its own",
            });
        };
        let client_message = spake.message().to_vec();
        let shared = self.terminal(spake.finish(host_message))?;
        let transcript = self.context.transcript(host_message, &client_message);
        let keys = self.terminal(AttemptKeys::derive(shared.expose(), transcript))?;
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
    /// Returns [`PairingError::WrongPhase`], [`PairingError::Expired`] or
    /// [`PairingError::AuthenticationFailed`].
    pub fn verify_host_confirmation(
        &mut self,
        tag: &Mac256,
        clock: &dyn PairingClock,
    ) -> Result<()> {
        self.require_phase(ClientPhase::AwaitingHostConfirmation, clock)?;
        let (Some(keys), Some(transcript)) = (self.keys.as_ref(), self.transcript) else {
            self.phase = ClientPhase::Finished;
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::AwaitingHostConfirmation.as_str(),
                actual: "an attempt with no derived keys",
            });
        };
        let outcome = keys.verify_host_confirmation(transcript, tag);
        self.terminal(outcome)?;
        self.phase = ClientPhase::Confirmed;
        Ok(())
    }

    /// Opens and verifies the host's signed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`], [`PairingError::Expired`],
    /// [`PairingError::ReplayedSequence`], [`PairingError::TooLarge`],
    /// [`PairingError::AuthenticationFailed`] or [`PairingError::ContextMismatch`] when the bundle
    /// answers another invitation or declares an endpoint that is not its own transport key.
    pub fn open_host_bundle(
        &mut self,
        frame: &BundleFrame,
        clock: &dyn PairingClock,
    ) -> Result<SignedHostBundle> {
        self.require_phase(ClientPhase::Confirmed, clock)?;
        let (Some(keys), Some(transcript)) = (self.keys.as_ref(), self.transcript) else {
            self.phase = ClientPhase::Finished;
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::Confirmed.as_str(),
                actual: "an attempt with no derived keys",
            });
        };
        let opened = bundles::open_bundle::<SignedHostBundle>(
            &keys.host_to_client,
            transcript,
            BundleMessageType::HostBundle,
            &mut self.budget,
            frame,
        );
        let signed = self.terminal(opened)?;
        let verified = bundles::verify_host_bundle(&signed, transcript);
        self.terminal(verified)?;
        if signed.bundle.invitation_id != self.context.invitation_id {
            self.phase = ClientPhase::Finished;
            return Err(PairingError::ContextMismatch {
                what: "the invitation a host bundle answers",
            });
        }
        let hash = bundles::bundle_hash(&signed.bundle);
        self.host_bundle_hash = Some(self.terminal(hash)?);
        self.host_bundle = Some(signed.clone());
        self.phase = ClientPhase::HostBundleReceived;
        Ok(signed)
    }

    /// Seals the candidate's signed bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`], [`PairingError::Expired`],
    /// [`PairingError::ContextMismatch`] when the bundle's endpoint is not its own transport key,
    /// an encoding error or a library error.
    pub fn seal_client_bundle(
        &mut self,
        authorisation: &AuthorisationKeyPair,
        bundle: ClientBundle,
        clock: &dyn PairingClock,
    ) -> Result<BundleFrame> {
        self.require_phase(ClientPhase::HostBundleReceived, clock)?;
        let (Some(keys), Some(transcript)) = (self.keys.as_ref(), self.transcript) else {
            self.phase = ClientPhase::Finished;
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::HostBundleReceived.as_str(),
                actual: "an attempt with no derived keys",
            });
        };
        let sealed = (|| {
            bundles::require_consistent_client_bundle(&bundle)?;
            let signed = bundles::sign_client_bundle(authorisation, bundle, transcript)?;
            let hash = bundles::bundle_hash(&signed.bundle)?;
            let frame = bundles::seal_bundle(
                &keys.client_to_host,
                transcript,
                BundleMessageType::ClientBundle,
                &mut self.budget,
                &signed,
            )?;
            Ok((hash, frame))
        })();
        let (hash, frame) = self.terminal(sealed)?;
        self.client_bundle_hash = Some(hash);
        Ok(frame)
    }

    /// Builds `pair.finish` and checks the live host endpoint against the authenticated bundle.
    ///
    /// The candidate connects to the endpoint the *authenticated* bundle pinned, not to one the
    /// service supplied, and checks that the peer it reached is that endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::WrongPhase`], [`PairingError::Expired`],
    /// [`PairingError::EarlyData`] and [`PairingError::EndpointMismatch`].
    pub fn finish_request(
        &mut self,
        live_peer: &dyn LivePeer,
        client_endpoint: &EndpointKey,
        clock: &dyn PairingClock,
    ) -> Result<PairFinishRequest> {
        self.require_phase(ClientPhase::HostBundleReceived, clock)?;
        // Early data is replayable, and a missing peer means there is no authenticated connection
        // at all. Neither is something to retry on this attempt.
        let handshake = require_completed_handshake(live_peer);
        self.terminal(handshake)?;
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
            self.phase = ClientPhase::Finished;
            return Err(PairingError::WrongPhase {
                expected: ClientPhase::HostBundleReceived.as_str(),
                actual: "an attempt with no exchanged bundles",
            });
        };
        let live = live_peer.live_endpoint();
        let live = match live {
            Ok(endpoint) => endpoint,
            Err(error) => {
                self.phase = ClientPhase::Finished;
                return Err(error);
            }
        };
        if live != host_bundle.bundle.endpoint_id {
            self.phase = ClientPhase::Finished;
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

    /// Ends the attempt, so nothing resumes it after a disconnection or a timeout.
    pub fn abandon(&mut self) {
        self.phase = ClientPhase::Finished;
    }

    /// Checks the phase and the handshake deadline, ending the attempt when either fails.
    fn require_phase(&mut self, expected: ClientPhase, clock: &dyn PairingClock) -> Result<()> {
        if self.phase != expected {
            let actual = self.phase.as_str();
            self.phase = ClientPhase::Finished;
            return Err(PairingError::WrongPhase {
                expected: expected.as_str(),
                actual,
            });
        }
        // A reboot invalidates the deadline, and no progress message extends it.
        if clock.boot_identity() != self.boot_identity
            || clock.monotonic_ms() >= self.deadline_monotonic_ms
        {
            self.phase = ClientPhase::Finished;
            return Err(PairingError::Expired);
        }
        Ok(())
    }

    /// Ends the attempt when `outcome` failed.
    fn terminal<T>(&mut self, outcome: Result<T>) -> Result<T> {
        if outcome.is_err() {
            self.phase = ClientPhase::Finished;
        }
        outcome
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

    /// Charges an attempt against the default origin.
    fn charge(store: &TestClientBudgetStore, clock: &TestClock, code: &EnteredCode) -> Result<u32> {
        charge_attempt(store, clock, &origin(), code)
    }

    /// KR-REQ-10.32: a device caps one entered code at five attempts.
    #[test]
    fn a_device_gets_five_attempts_per_code() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        for expected in [4, 3, 2, 1, 0] {
            assert_eq!(
                charge(&store, &clock, &code()).expect("an attempt"),
                expected
            );
        }
        assert!(matches!(
            charge(&store, &clock, &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));
    }

    /// KR-REQ-10.32: the count lives in the budget store rather than in an attempt, so a new
    /// attempt over the same store continues it.
    #[test]
    fn the_counter_survives_a_restart_and_is_not_keyed_by_the_service() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        charge(&store, &clock, &code()).expect("an attempt");
        // A "restart" is a new state machine over the same store: the record is what carries the
        // count, and nothing the service said is part of its key.
        assert_eq!(
            charge(&store, &clock, &code()).expect("an attempt"),
            MAX_CLIENT_ATTEMPTS - 2
        );
    }

    /// KR-REQ-10.32: the configured origin is part of the counter key.
    #[test]
    fn the_same_code_at_another_origin_is_another_entry() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        let elsewhere = RendezvousOrigin::new("https://elsewhere.example").expect("an origin");
        for _ in 0..MAX_CLIENT_ATTEMPTS {
            charge(&store, &clock, &code()).expect("an attempt");
        }
        assert!(charge(&store, &clock, &code()).is_err());
        assert_eq!(
            charge_attempt(&store, &clock, &elsewhere, &code()).expect("an attempt"),
            MAX_CLIENT_ATTEMPTS - 1
        );
    }

    /// KR-REQ-10.32: the normalised code is part of the counter key.
    #[test]
    fn two_spellings_of_one_code_share_a_counter() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        let grouped = EnteredCode::parse("aB3x-Yz7-9Qw").expect("a code");
        let spaced = EnteredCode::parse(" aB3x Yz7 9Qw ").expect("a code");
        charge(&store, &clock, &grouped).expect("an attempt");
        assert_eq!(
            charge(&store, &clock, &spaced).expect("an attempt"),
            MAX_CLIENT_ATTEMPTS - 2
        );
    }

    /// KR-REQ-10.32: the five-minute window starts at first entry and a tombstone outlives it.
    #[test]
    fn the_window_starts_at_first_entry_and_a_tombstone_outlives_it() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        charge(&store, &clock, &code()).expect("an attempt");

        clock.advance(INVITATION_LIFETIME_MS - 1);
        assert!(charge(&store, &clock, &code()).is_ok());

        clock.advance(1);
        assert!(matches!(
            charge(&store, &clock, &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));

        // A day later the tombstone still refuses the code: another advertised expiry cannot
        // reset the counter.
        clock.advance(CLIENT_TOMBSTONE_MS - 1);
        assert!(matches!(
            charge(&store, &clock, &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));
    }

    /// KR-REQ-10.32: a reboot expires the entry and leaves a tombstone.
    #[test]
    fn a_reboot_expires_the_entry_and_leaves_a_tombstone() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        charge(&store, &clock, &code()).expect("an attempt");
        charge(&store, &clock, &code()).expect("an attempt");

        clock.reboot(9);
        // A reboot ends the window. It does not hand back the three remaining attempts.
        assert!(matches!(
            charge(&store, &clock, &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));
        // And the tombstone outlives the reboot, because its retention is on the wall clock.
        clock.advance(CLIENT_TOMBSTONE_MS - 1);
        assert!(matches!(
            charge(&store, &clock, &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));
    }

    /// KR-REQ-10.32: the window runs on monotonic time, not the wall clock.
    #[test]
    fn a_wall_clock_that_jumps_forward_does_not_restore_attempts() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        for _ in 0..MAX_CLIENT_ATTEMPTS {
            charge(&store, &clock, &code()).expect("an attempt");
        }
        // A year on the wall clock, no time at all on the monotonic one. Within this boot the
        // monotonic deadline governs, so the tombstone is not swept and the code stays spent.
        clock.skew_wall_clock(365 * 24 * 60 * 60 * 1000);
        assert!(matches!(
            charge(&store, &clock, &code()),
            Err(PairingError::ClientAttemptsExhausted)
        ));
        assert_eq!(store.len(), 1, "the tombstone is still there");
    }

    /// KR-REQ-10.32: a tombstone is kept for 24 hours and then dropped.
    #[test]
    fn a_tombstone_is_dropped_once_its_retention_ends() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        for _ in 0..MAX_CLIENT_ATTEMPTS {
            charge(&store, &clock, &code()).expect("an attempt");
        }
        assert!(charge(&store, &clock, &code()).is_err());
        let day = 24 * 60 * 60 * 1_000;
        assert_eq!(CLIENT_TOMBSTONE_MS, day);
        // The window closes five minutes after first entry, and the tombstone holds for a day
        // after that: one millisecond short of it the code is still refused.
        clock.advance(5 * 60 * 1_000 + day - 1);
        assert!(charge(&store, &clock, &code()).is_err());
        clock.advance(2);
        // The record is gone, so an entirely new code entry starts fresh. The invitation itself
        // is long expired by then, which is what makes this safe.
        assert!(charge(&store, &clock, &code()).is_ok());
    }

    /// KR-REQ-10.32: the counter key reveals neither the code nor the origin, and differs per
    /// device.
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

    /// KR-REQ-10.32: the counter key is HMAC-SHA256 under this device's own random local key over
    /// the configured origin and the normalised full code, and nothing the service supplies is part
    /// of it: two lookups that advertise different invitations and expiries share one budget.
    #[test]
    fn the_counter_is_keyed_by_origin_and_code_under_a_local_key_and_nothing_the_service_says() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        let key = store.budget_key().expect("the local key");
        let mut message = vec![0x83];
        message.extend_from_slice(&kr_cbor::encode(&kr_cbor::CanonicalValue::text(
            CLIENT_BUDGET_DOMAIN,
        )));
        message.extend_from_slice(&kr_cbor::encode(&kr_cbor::CanonicalValue::text(
            origin().as_str(),
        )));
        message.extend_from_slice(&kr_cbor::encode(&kr_cbor::CanonicalValue::text(
            code().normalised(),
        )));
        assert_eq!(
            budget_key(&store, &origin(), &code()).expect("a key"),
            kdf::hmac_sha256(&key, &message)
        );

        for (invitation, expiry) in [([1u8; 16], 9_999u64), ([2u8; 16], u64::MAX)] {
            let rendezvous = TestClient::new(LocatorRecord {
                invitation_id: InvitationId::new(Uuid::from_bytes(invitation)),
                advertised_expires_at_ms: TimestampMs::new(expiry),
            });
            ClientAttempt::start(&store, &clock, &rendezvous, &origin(), &code())
                .expect("an attempt");
        }
        assert_eq!(
            charge(&store, &clock, &code()).expect("an attempt"),
            MAX_CLIENT_ATTEMPTS - 3,
            "two advertised invitations spent one budget"
        );
    }

    /// KR-REQ-10.16: the lookup sends only the four locator characters.
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
        assert_eq!(rendezvous.looked_up(), vec!["aB3x".to_owned()]);
        assert_eq!(admission.attempt_id, attempt.context().attempt_id);
        assert_eq!(attempt.context().invitation_id, record.invitation_id);
        assert_eq!(attempt.remaining_attempts(), MAX_CLIENT_ATTEMPTS - 1);
        assert!(!attempt.is_finished());
    }

    /// KR-REQ-10.21: one attempt runs one exchange; its PAKE state is never reused.
    #[test]
    fn an_attempt_cannot_start_a_second_exchange() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        let rendezvous = TestClient::new(LocatorRecord {
            invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            advertised_expires_at_ms: TimestampMs::new(9_999),
        });
        let (mut attempt, _, _) =
            ClientAttempt::start(&store, &clock, &rendezvous, &origin(), &code())
                .expect("an attempt");
        assert!(
            attempt
                .with_host_nonce(Nonce256::from_bytes([1; 32]), &clock)
                .is_ok()
        );
        assert!(matches!(
            attempt.with_host_nonce(Nonce256::from_bytes([2; 32]), &clock),
            Err(PairingError::WrongPhase { .. })
        ));
        assert!(attempt.is_finished());
    }

    #[test]
    fn an_attempt_expires_at_its_handshake_deadline() {
        let store = TestClientBudgetStore::new().expect("a store");
        let clock = TestClock::new();
        let rendezvous = TestClient::new(LocatorRecord {
            invitation_id: InvitationId::new(Uuid::from_bytes([1; 16])),
            advertised_expires_at_ms: TimestampMs::new(9_999),
        });
        let (mut attempt, _, _) =
            ClientAttempt::start(&store, &clock, &rendezvous, &origin(), &code())
                .expect("an attempt");
        clock.advance(HANDSHAKE_DEADLINE_MS);
        assert!(matches!(
            attempt.with_host_nonce(Nonce256::from_bytes([1; 32]), &clock),
            Err(PairingError::Expired)
        ));
        assert!(attempt.is_finished());
    }
}
