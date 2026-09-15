//! Everything this crate depends on and does not own.
//!
//! The rendezvous transport, the clock, the durable stores, the live transport peer and the
//! user-verification ceremony are all platform code. They arrive here as traits so the state
//! machines can be exercised without a network, a disk, a real clock or a person, and so the
//! Cloudflare `PairingRoom` client, the controller's databases and the companion application's
//! native ceremonies can be written against a fixed contract.
//!
//! Each trait has an in-test implementation in this module's tests and in the state machines'
//! tests. None of them is a default: a host that forgets to supply one does not compile.

use std::collections::BTreeMap;
use std::sync::Mutex;

use kr_crypto::secret::SymmetricKey;
use kr_protocol::ids::{AttemptId, InvitationId};
use kr_protocol::pairing::{
    Locator, OwnerConfirmationProof, OwnerConfirmationRequest, RendezvousOrigin,
};
use kr_protocol::scalars::{Digest256, EndpointKey, Mac256, TimestampMs};

use crate::error::{PairingError, Result};

/// An opaque identity for one boot of one machine.
///
/// Section 10 keys the client's attempt window by monotonic time *and* the boot identity, because
/// a monotonic clock restarts at a reboot: without the identity, a reboot would make an old
/// deadline look like a future one. A reboot expires an unfinished entry, and this is how the
/// state machine notices.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootIdentity(pub [u8; 32]);

/// A monotonic clock, its boot identity, and the wall clock for absolute wire deadlines.
///
/// Deadlines inside this crate are monotonic. The wall clock appears only in objects that leave
/// the host, where an absolute time is the only thing another device can read, and it is never
/// what a host trusts: "the host deadline remains authoritative even if the service lies about
/// expiry", and clock uncertainty cannot extend an invitation.
pub trait PairingClock {
    /// Returns milliseconds on a monotonic, suspend-aware clock.
    fn monotonic_ms(&self) -> u64;

    /// Returns the identity of this boot.
    fn boot_identity(&self) -> BootIdentity;

    /// Returns the wall clock in UTC milliseconds, for an absolute expiry another device reads.
    fn wall_clock_ms(&self) -> u64;
}

/// What a rendezvous lookup returns.
///
/// Every field is untrusted until the PAKE confirms it. The client sends only the four locator
/// characters to get this, and the six secret characters never enter the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocatorRecord {
    /// The invitation the service says the locator names.
    pub invitation_id: InvitationId,
    /// The expiry the service advertises. The host's own deadline is the authoritative one.
    pub advertised_expires_at_ms: TimestampMs,
}

/// A reserved locator and the token that controls its record.
///
/// The service stores the locator, the invitation identity, the expiry and a hash of this token.
/// A request that modifies the record proves possession of the token, and the token controls only
/// the rendezvous record: it confers nothing about the invitation, which the host owns.
#[derive(Debug)]
pub struct LocatorReservation {
    /// The locator the service accepted.
    pub locator: Locator,
    /// The 256-bit control token. It never leaves the host.
    pub control_token: SymmetricKey,
}

impl LocatorReservation {
    /// Returns the hash of the control token, which is what the service stores.
    #[must_use]
    pub fn control_token_hash(&self) -> Digest256 {
        Digest256::from_bytes(kr_cbor::sha256(self.control_token.expose()))
    }
}

/// The host's side of the rendezvous service.
pub trait RendezvousHost {
    /// Reserves `locator` for `invitation_id`, atomically.
    ///
    /// Returns `Ok(false)` when the locator is already taken, which makes the host generate
    /// another one rather than fail the invitation.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::RendezvousUnavailable`] when the service cannot be reached.
    fn reserve_locator(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        invitation_id: InvitationId,
        advertised_expires_at_ms: TimestampMs,
        control_token_hash: Digest256,
    ) -> Result<bool>;

    /// Releases a reservation, proving possession of the control token.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::RendezvousUnavailable`].
    fn release_locator(&self, locator: &Locator, control_token: &SymmetricKey) -> Result<()>;
}

/// The candidate's side of the rendezvous service.
pub trait RendezvousClient {
    /// Looks a locator up at the configured origin.
    ///
    /// Only the four locator characters travel. An unknown locator answers with the same socket
    /// admission, timeout and error shape as a known one, so this never becomes a cheap
    /// existence oracle.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::RendezvousUnavailable`].
    fn lookup(&self, origin: &RendezvousOrigin, locator: &Locator) -> Result<LocatorRecord>;
}

/// The durable record of one invitation.
///
/// Section 10 requires the failure count and the invitation state to survive a restart, and a
/// consumed record to stay consumed. A host restart cancels an unfinished invitation, which the
/// state machine does when it loads one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationRecord {
    /// The invitation.
    pub invitation_id: InvitationId,
    /// The locator the service reserved.
    pub locator: Locator,
    /// The state it is in.
    pub state: InvitationState,
    /// How many client confirmation tags have verified and failed.
    pub failed_confirmations: u32,
    /// The monotonic deadline this host enforces.
    pub deadline_monotonic_ms: u64,
    /// The boot this deadline belongs to.
    pub boot_identity: BootIdentity,
}

/// Where an invitation is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvitationState {
    /// Open, with no candidate holding it.
    Open,
    /// One candidate holds it and owner approval is pending.
    AwaitingApproval {
        /// The candidate that holds it.
        attempt_id: AttemptId,
    },
    /// Committed: the owner approved and the device record and grant were written.
    Committed,
    /// Consumed without a grant.
    Consumed {
        /// Why.
        reason: kr_protocol::pairing::PairingConsumedReason,
    },
}

/// Where the host keeps invitation state across a restart.
pub trait InvitationStore {
    /// Writes a record, replacing any earlier one for the same invitation.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] when the write fails. A failed write is a failed step: the
    /// state machine does not proceed on state it could not persist.
    fn save(&self, record: &InvitationRecord) -> Result<()>;

    /// Reads a record.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn load(&self, invitation_id: InvitationId) -> Result<Option<InvitationRecord>>;

    /// Returns every invitation this host has not finished.
    ///
    /// A host cancels these when it starts, because a candidate's attempt state lives only in
    /// memory and nothing can resume it.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn unfinished(&self) -> Result<Vec<InvitationRecord>>;
}

impl<T: InvitationStore + ?Sized> InvitationStore for &T {
    fn save(&self, record: &InvitationRecord) -> Result<()> {
        (**self).save(record)
    }

    fn load(&self, invitation_id: InvitationId) -> Result<Option<InvitationRecord>> {
        (**self).load(invitation_id)
    }

    fn unfinished(&self) -> Result<Vec<InvitationRecord>> {
        (**self).unfinished()
    }
}

impl<T: PairingClock + ?Sized> PairingClock for &T {
    fn monotonic_ms(&self) -> u64 {
        (**self).monotonic_ms()
    }

    fn boot_identity(&self) -> BootIdentity {
        (**self).boot_identity()
    }

    fn wall_clock_ms(&self) -> u64 {
        (**self).wall_clock_ms()
    }
}

/// The client's durable record for one entered code.
///
/// It is keyed by an HMAC of the configured origin and the normalised code under a distinct random
/// local key, never by the service-supplied invitation identity or expiry. A service that
/// advertises a new identity for the same code therefore cannot reset the counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientAttemptRecord {
    /// How many attempts this device has made with this code.
    pub attempts: u32,
    /// When the window started, on the monotonic clock.
    pub first_entry_monotonic_ms: u64,
    /// The boot that monotonic value belongs to.
    pub boot_identity: BootIdentity,
    /// When the record may be forgotten, on the monotonic clock. A tombstone outlives the window.
    pub retain_until_monotonic_ms: u64,
    /// True once the code is spent, so a later entry is refused rather than restarted.
    pub exhausted: bool,
}

/// Where the client keeps its own attempt budget.
pub trait ClientBudgetStore {
    /// Returns the local key the budget is keyed under.
    ///
    /// It is a random key of this device's own, from secure storage, and never a transport or
    /// control key. Keying the counter with one of those would let anything that saw a transport
    /// key recompute which codes this device has tried.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn budget_key(&self) -> Result<SymmetricKey>;

    /// Reads the record for one code key.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn load(&self, code_key: &Mac256) -> Result<Option<ClientAttemptRecord>>;

    /// Writes the record for one code key.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn save(&self, code_key: &Mac256, record: &ClientAttemptRecord) -> Result<()>;

    /// Drops records whose retention has ended.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn expire(&self, now_monotonic_ms: u64, boot_identity: BootIdentity) -> Result<()>;
}

/// The identity of the peer on the connection a step arrived on.
///
/// Section 10 requires the host to check that the live iroh peer equals the authenticated client
/// endpoint, and the client to check the host likewise. Neither check can read the connection from
/// here, so both ask this.
pub trait LivePeer {
    /// Returns the endpoint identity of the authenticated transport peer.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no authenticated peer, which is itself a failure: a pairing
    /// mutation never arrives outside one.
    fn live_endpoint(&self) -> Result<EndpointKey>;
}

/// The protected user-verification ceremony.
///
/// Section 10 prefers a native ceremony on the unlocked owner device or an approval from a
/// separately paired owner device, and refuses to accept a click that desktop automation can
/// synthesize. None of that is decidable here, so the ceremony is platform code and this crate
/// only checks what it returns.
pub trait OwnerConfirmation {
    /// Runs the ceremony for one challenge and returns the proof.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::OwnerConfirmationRequired`] when the owner declined, the ceremony
    /// is unavailable, or the platform has no way to establish user presence.
    fn confirm(&self, request: &OwnerConfirmationRequest) -> Result<OwnerConfirmationProof>;
}

/// A clock that a test drives by hand.
#[derive(Debug)]
pub struct TestClock {
    monotonic_ms: Mutex<u64>,
    boot: Mutex<BootIdentity>,
    wall_clock_ms: Mutex<u64>,
}

impl TestClock {
    /// Creates a clock at zero, on boot `0`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            monotonic_ms: Mutex::new(0),
            boot: Mutex::new(BootIdentity([0; 32])),
            wall_clock_ms: Mutex::new(1_764_000_000_000),
        }
    }

    /// Moves both clocks forward.
    pub fn advance(&self, milliseconds: u64) {
        *self.monotonic_ms.lock().expect("a test clock") += milliseconds;
        *self.wall_clock_ms.lock().expect("a test clock") += milliseconds;
    }

    /// Reboots: the monotonic clock restarts and the boot identity changes.
    pub fn reboot(&self, identity: u8) {
        *self.monotonic_ms.lock().expect("a test clock") = 0;
        *self.boot.lock().expect("a test clock") = BootIdentity([identity; 32]);
    }

    /// Moves only the wall clock, which a host must never trust for a deadline.
    pub fn skew_wall_clock(&self, milliseconds: i64) {
        let mut wall = self.wall_clock_ms.lock().expect("a test clock");
        *wall = wall.saturating_add_signed(milliseconds);
    }
}

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingClock for TestClock {
    fn monotonic_ms(&self) -> u64 {
        *self.monotonic_ms.lock().expect("a test clock")
    }

    fn boot_identity(&self) -> BootIdentity {
        *self.boot.lock().expect("a test clock")
    }

    fn wall_clock_ms(&self) -> u64 {
        *self.wall_clock_ms.lock().expect("a test clock")
    }
}

/// An in-memory invitation store for tests, which can also be made to fail.
#[derive(Debug, Default)]
pub struct TestInvitationStore {
    records: Mutex<BTreeMap<InvitationId, InvitationRecord>>,
    failing: Mutex<bool>,
}

impl TestInvitationStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every operation fail, so a test can check that a failed write stops a step.
    pub fn set_failing(&self, failing: bool) {
        *self.failing.lock().expect("a test store") = failing;
    }

    /// Returns a copy of the stored records, which is what survives a restart.
    #[must_use]
    pub fn snapshot(&self) -> Vec<InvitationRecord> {
        self.records
            .lock()
            .expect("a test store")
            .values()
            .cloned()
            .collect()
    }

    fn check(&self) -> Result<()> {
        if *self.failing.lock().expect("a test store") {
            return Err(PairingError::Store {
                reason: "the test store is failing".to_owned(),
            });
        }
        Ok(())
    }
}

impl InvitationStore for TestInvitationStore {
    fn save(&self, record: &InvitationRecord) -> Result<()> {
        self.check()?;
        self.records
            .lock()
            .expect("a test store")
            .insert(record.invitation_id, record.clone());
        Ok(())
    }

    fn load(&self, invitation_id: InvitationId) -> Result<Option<InvitationRecord>> {
        self.check()?;
        Ok(self
            .records
            .lock()
            .expect("a test store")
            .get(&invitation_id)
            .cloned())
    }

    fn unfinished(&self) -> Result<Vec<InvitationRecord>> {
        self.check()?;
        Ok(self
            .records
            .lock()
            .expect("a test store")
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    InvitationState::Open | InvitationState::AwaitingApproval { .. }
                )
            })
            .cloned()
            .collect())
    }
}

/// An in-memory client budget store for tests.
#[derive(Debug)]
pub struct TestClientBudgetStore {
    key: SymmetricKey,
    records: Mutex<BTreeMap<[u8; 32], ClientAttemptRecord>>,
}

impl TestClientBudgetStore {
    /// Creates a store with a fresh random local key.
    ///
    /// # Errors
    ///
    /// Returns an error when libsodium is unavailable.
    pub fn new() -> Result<Self> {
        Ok(Self {
            key: SymmetricKey::random()?,
            records: Mutex::new(BTreeMap::new()),
        })
    }

    /// Returns how many records the store holds, including tombstones.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.lock().expect("a test store").len()
    }

    /// Returns true when the store holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ClientBudgetStore for TestClientBudgetStore {
    fn budget_key(&self) -> Result<SymmetricKey> {
        Ok(self.key.clone())
    }

    fn load(&self, code_key: &Mac256) -> Result<Option<ClientAttemptRecord>> {
        Ok(self
            .records
            .lock()
            .expect("a test store")
            .get(code_key.as_bytes())
            .cloned())
    }

    fn save(&self, code_key: &Mac256, record: &ClientAttemptRecord) -> Result<()> {
        self.records
            .lock()
            .expect("a test store")
            .insert(*code_key.as_bytes(), record.clone());
        Ok(())
    }

    fn expire(&self, now_monotonic_ms: u64, boot_identity: BootIdentity) -> Result<()> {
        self.records
            .lock()
            .expect("a test store")
            .retain(|_, record| {
                // A record from another boot is expired: its monotonic values mean nothing now.
                record.boot_identity == boot_identity
                    && record.retain_until_monotonic_ms > now_monotonic_ms
            });
        Ok(())
    }
}

/// A rendezvous client for tests, which records the locators it was asked about.
#[derive(Debug)]
pub struct TestClient {
    record: LocatorRecord,
    looked_up: Mutex<Vec<String>>,
}

impl TestClient {
    /// Creates a client that answers every lookup with `record`.
    #[must_use]
    pub fn new(record: LocatorRecord) -> Self {
        Self {
            record,
            looked_up: Mutex::new(Vec::new()),
        }
    }

    /// Returns every locator this client was asked about.
    ///
    /// A test asserts on it to show that the six secret characters never reach the service.
    #[must_use]
    pub fn looked_up(&self) -> Vec<String> {
        self.looked_up.lock().expect("a test client").clone()
    }
}

impl RendezvousClient for TestClient {
    fn lookup(&self, _origin: &RendezvousOrigin, locator: &Locator) -> Result<LocatorRecord> {
        self.looked_up
            .lock()
            .expect("a test client")
            .push(locator.as_str().to_owned());
        Ok(self.record.clone())
    }
}

/// A rendezvous host for tests, which reserves every locator once.
#[derive(Debug, Default)]
pub struct TestRendezvousHost {
    reserved: Mutex<BTreeMap<String, InvitationId>>,
    released: Mutex<Vec<String>>,
    reject_first: Mutex<usize>,
}

impl TestRendezvousHost {
    /// Creates an empty service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes the next `count` reservations collide, so a test can watch the host try again.
    pub fn collide_next(&self, count: usize) {
        *self.reject_first.lock().expect("a test service") = count;
    }

    /// Returns the locators this service reserved.
    #[must_use]
    pub fn reserved(&self) -> Vec<String> {
        self.reserved
            .lock()
            .expect("a test service")
            .keys()
            .cloned()
            .collect()
    }

    /// Returns the locators this service released.
    #[must_use]
    pub fn released(&self) -> Vec<String> {
        self.released.lock().expect("a test service").clone()
    }
}

impl RendezvousHost for TestRendezvousHost {
    fn reserve_locator(
        &self,
        _origin: &RendezvousOrigin,
        locator: &Locator,
        invitation_id: InvitationId,
        _advertised_expires_at_ms: TimestampMs,
        _control_token_hash: Digest256,
    ) -> Result<bool> {
        let mut remaining = self.reject_first.lock().expect("a test service");
        if *remaining > 0 {
            *remaining -= 1;
            return Ok(false);
        }
        drop(remaining);
        let mut reserved = self.reserved.lock().expect("a test service");
        if reserved.contains_key(locator.as_str()) {
            return Ok(false);
        }
        reserved.insert(locator.as_str().to_owned(), invitation_id);
        Ok(true)
    }

    fn release_locator(&self, locator: &Locator, _control_token: &SymmetricKey) -> Result<()> {
        self.reserved
            .lock()
            .expect("a test service")
            .remove(locator.as_str());
        self.released
            .lock()
            .expect("a test service")
            .push(locator.as_str().to_owned());
        Ok(())
    }
}

/// A live peer a test sets by hand.
#[derive(Debug)]
pub struct TestLivePeer(Mutex<Option<EndpointKey>>);

impl TestLivePeer {
    /// Creates a peer with the given endpoint identity.
    #[must_use]
    pub fn new(endpoint: EndpointKey) -> Self {
        Self(Mutex::new(Some(endpoint)))
    }

    /// Replaces the endpoint, so a test can substitute a different peer.
    pub fn set(&self, endpoint: Option<EndpointKey>) {
        *self.0.lock().expect("a test peer") = endpoint;
    }
}

impl LivePeer for TestLivePeer {
    fn live_endpoint(&self) -> Result<EndpointKey> {
        self.0
            .lock()
            .expect("a test peer")
            .ok_or(PairingError::EndpointMismatch { side: "transport" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_clock_reboots_the_way_a_machine_does() {
        let clock = TestClock::new();
        clock.advance(5_000);
        assert_eq!(clock.monotonic_ms(), 5_000);
        let before = clock.boot_identity();
        clock.reboot(1);
        assert_eq!(clock.monotonic_ms(), 0);
        assert_ne!(clock.boot_identity(), before);
    }

    #[test]
    fn a_wall_clock_skew_does_not_move_the_monotonic_clock() {
        let clock = TestClock::new();
        clock.advance(1_000);
        let monotonic = clock.monotonic_ms();
        clock.skew_wall_clock(-86_400_000);
        assert_eq!(clock.monotonic_ms(), monotonic);
    }

    #[test]
    fn a_reservation_publishes_only_the_hash_of_its_token() {
        let reservation = LocatorReservation {
            locator: Locator::new("aB3x").expect("a locator"),
            control_token: SymmetricKey::from_bytes([5; 32]),
        };
        let hash = reservation.control_token_hash();
        assert_eq!(hash.as_bytes(), &kr_cbor::sha256(&[5u8; 32]));
        assert_ne!(hash.as_bytes().as_slice(), &[5u8; 32]);
    }

    #[test]
    fn the_client_store_forgets_a_record_from_another_boot() {
        let store = TestClientBudgetStore::new().expect("a store");
        let key = Mac256::from_bytes([1; 32]);
        store
            .save(
                &key,
                &ClientAttemptRecord {
                    attempts: 1,
                    first_entry_monotonic_ms: 0,
                    boot_identity: BootIdentity([0; 32]),
                    retain_until_monotonic_ms: 1_000_000,
                    exhausted: false,
                },
            )
            .expect("a write");
        assert_eq!(store.len(), 1);
        store
            .expire(0, BootIdentity([9; 32]))
            .expect("an expiry sweep");
        assert!(store.is_empty());
    }

    #[test]
    fn a_failing_store_reports_a_store_error() {
        let store = TestInvitationStore::new();
        store.set_failing(true);
        assert!(matches!(
            store.load(InvitationId::new(kr_protocol::scalars::Uuid::NIL)),
            Err(PairingError::Store { .. })
        ));
    }

    #[test]
    fn a_missing_live_peer_is_a_mismatch_rather_than_a_pass() {
        let peer = TestLivePeer::new(EndpointKey::from_bytes([1; 32]));
        assert!(peer.live_endpoint().is_ok());
        peer.set(None);
        assert!(matches!(
            peer.live_endpoint(),
            Err(PairingError::EndpointMismatch { .. })
        ));
    }
}
