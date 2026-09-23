//! Everything this crate depends on and does not own.
//!
//! The rendezvous transport, the clock, the durable stores, the live transport peer and the
//! user-verification ceremony are all platform code. They arrive here as traits so the state
//! machines can be exercised without a network, a disk, a real clock or a person, and so the
//! Cloudflare `PairingRoom` client, the controller's databases and the companion application's
//! native ceremonies can be written against a fixed contract.
//!
//! Two of the contracts are about atomicity rather than about mechanism, because the rules they
//! carry cannot be enforced from here:
//!
//! * [`InvitationStore::transition`] and [`InvitationStore::commit`] write only when the stored
//!   record is still exactly the one the caller decided from. One invitation may be served by two
//!   state machines at once, so a plain write would let the slower one undo a lock, a spent guess
//!   or a consumption the other had already recorded.
//! * [`InvitationStore::commit`] also writes the device record, the validated grant, the consumed
//!   invitation, the owner's proof and the security event in one transaction. A pairing reports
//!   success only after it returns.
//! * [`ClientBudgetStore::update`] applies one read-modify-write to a code's counter atomically. A
//!   separate read and write would let two entries of the same code both see four attempts.

use std::collections::BTreeMap;
use std::sync::Mutex;

use kr_crypto::secret::SymmetricKey;
use kr_protocol::grant::Grant;
use kr_protocol::ids::{AttemptId, DeviceId, InvitationId};
use kr_protocol::pairing::{
    CLIENT_TOMBSTONE_MS, ClientBundle, DevicePublicKeys, Locator, OwnerConfirmationProof,
    OwnerConfirmationRequest, ProposedGrant, RendezvousOrigin,
};
use kr_protocol::scalars::{Digest256, EndpointKey, Mac256, TimestampMs};

use crate::error::{PairingError, Result};

/// An opaque identity for one boot of one machine.
///
/// Section 10 keys the client's attempt window by monotonic time *and* the boot identity, because
/// a monotonic clock restarts at a reboot: without the identity, a reboot would make an old
/// deadline look like a future one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootIdentity(pub [u8; 32]);

/// A monotonic clock, its boot identity, and the wall clock.
///
/// Deadlines *within* one boot are monotonic, because a wall clock that moves must not extend an
/// invitation. Retention that has to outlive a reboot is on the wall clock, because a monotonic
/// value from another boot means nothing; a wall clock that runs backwards only lengthens such a
/// retention, which is the safe direction.
pub trait PairingClock {
    /// Returns milliseconds on a monotonic, suspend-aware clock.
    fn monotonic_ms(&self) -> u64;

    /// Returns the identity of this boot.
    fn boot_identity(&self) -> BootIdentity;

    /// Returns the wall clock in UTC milliseconds.
    fn wall_clock_ms(&self) -> u64;
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
/// The service stores the locator, the invitation identity, the expiry and a hash of this token. A
/// request that modifies the record proves possession of the token, and the token controls only
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

    /// Releases a reservation at `origin`, proving possession of the control token.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::RendezvousUnavailable`].
    fn release_locator(
        &self,
        origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> Result<()>;
}

/// The candidate's side of the rendezvous service.
pub trait RendezvousClient {
    /// Looks a locator up at the configured origin.
    ///
    /// Only the four locator characters travel. An unknown locator answers with the same socket
    /// admission, timeout and error shape as a known one, so this never becomes a cheap existence
    /// oracle.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::RendezvousUnavailable`].
    fn lookup(&self, origin: &RendezvousOrigin, locator: &Locator) -> Result<LocatorRecord>;
}

/// The durable record of one invitation.
///
/// It is the single authority on an invitation's state, which matters when one invitation offers
/// both entry modes: each flow reloads it before every transition and writes it back, so the two
/// routes share one candidate and one consumption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationRecord {
    /// The invitation.
    pub invitation_id: InvitationId,
    /// The locator the service reserved, for a short-code invitation.
    pub locator: Option<Locator>,
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
    /// One candidate holds it.
    ///
    /// Section 10 locks the invitation at successful PAKE, before the owner is asked, and cancels
    /// the competing candidates then.
    Locked {
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

impl InvitationState {
    /// Returns the candidate holding the invitation, when one does.
    #[must_use]
    pub const fn locked_attempt(self) -> Option<AttemptId> {
        match self {
            Self::Locked { attempt_id } => Some(attempt_id),
            _ => None,
        }
    }
}

/// What one completed pairing wrote.
///
/// Section 10 commits the device record, the grant and the consumed-invitation state atomically,
/// and every completed pairing produces a durable attention and security event. All of that is one
/// transaction, and this is its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PairingCommitment {
    /// The invitation that produced it.
    pub invitation_id: InvitationId,
    /// The candidate that was approved.
    pub attempt_id: AttemptId,
    /// The device record the host created.
    pub device_id: DeviceId,
    /// The grant the host issued, validated and narrowed against its parent before it was written.
    pub grant: Grant,
    /// The candidate's complete purpose-key bundle.
    pub client_keys: DevicePublicKeys,
    /// The candidate's display bundle, for a short-code pairing. Display text, never authority.
    pub client_bundle: Option<ClientBundle>,
    /// The rights the invitation proposed, unchanged.
    pub proposed_grant: ProposedGrant,
    /// The value both devices displayed, recorded so the security event can name it.
    pub verification_value: String,
    /// The owner confirmation this pairing was accepted under.
    ///
    /// Section 10 makes user-presence verification and the challenge-consumption transition part
    /// of the host's acceptance record, so the proof is written with the pairing rather than
    /// checked and forgotten: afterwards the host can show which challenge, which channel and
    /// which signer authorised this exact device.
    pub owner_confirmation: OwnerConfirmationProof,
    /// When the host committed it, in UTC milliseconds.
    pub committed_at_ms: TimestampMs,
}

/// What a conditional write did.
///
/// Neither a stale outcome nor a refusal is a failure of the store. A stale outcome means another
/// writer moved the record first, and it carries what the record now says so the caller can decide
/// what that means. A refusal means the store decided, before writing anything, not to write: a
/// check of its own on the authority the write is made under failed. In both cases nothing was
/// written and nothing about the write is uncertain, so the invitation is not fenced; only a failed
/// write, whose outcome the caller cannot know, fences it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionOutcome {
    /// The record was exactly as expected and the new one was written.
    Written,
    /// The record had moved. Nothing was written; this is what it says now.
    Stale(InvitationRecord),
    /// The store refused the write before writing anything, for this reason. The record is as it
    /// was.
    Refused(PairingError),
}

/// Where the host keeps invitation state across a restart.
pub trait InvitationStore {
    /// Writes a record for an invitation that has none yet, with the confirmation it was issued
    /// under.
    ///
    /// Issuing a persistent invitation is one of the actions section 10 gives a fresh owner
    /// confirmation, and user-presence verification and the challenge-consumption transition are
    /// part of the host's acceptance record. An implementation writes the record and that
    /// confirmation's consumption in one transaction, so an invitation never exists without the
    /// approval that authorised it on record.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] when the write fails or the invitation already exists. A
    /// failed write is a failed step: the state machine does not proceed on state it could not
    /// persist.
    fn create(
        &self,
        record: &InvitationRecord,
        issued_under: &OwnerConfirmationProof,
    ) -> Result<()>;

    /// Reads a record.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn load(&self, invitation_id: InvitationId) -> Result<Option<InvitationRecord>>;

    /// Replaces `expected` with `next`, and only if the stored record is still exactly `expected`.
    ///
    /// The comparison and the write are one transaction. One invitation may offer a short code and
    /// a direct QR, and both routes decide from a record they read a moment earlier; without this
    /// the slower writer would quietly undo the faster one's lock, spent guess or consumption.
    /// A store that checks the authority a write is made under reports a failed check as
    /// [`TransitionOutcome::Refused`], having written nothing.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] when the transaction fails.
    fn transition(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
    ) -> Result<TransitionOutcome>;

    /// Commits a pairing: the record and the commitment together, conditional on `expected`.
    ///
    /// The device record, the validated grant, the consumed invitation, the owner's proof and the
    /// security event are one transition, and a pairing reports success only after this returns.
    /// An implementation that wrote them separately would let a crash leave a device with no
    /// grant, a grant with no device, or a completed pairing with no security event. A store that
    /// checks the authority the commit is made under, the owner confirmation's included, reports a
    /// failed check as [`TransitionOutcome::Refused`], having written nothing.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`] when the transaction does not commit.
    fn commit(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
        commitment: &PairingCommitment,
    ) -> Result<TransitionOutcome>;

    /// Reads the commitment of an invitation that was committed.
    ///
    /// A transport retry retrieves the committed result through this, including after a restart
    /// that lost every in-memory invitation.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn commitment(&self, invitation_id: InvitationId) -> Result<Option<PairingCommitment>>;

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
    fn create(
        &self,
        record: &InvitationRecord,
        issued_under: &OwnerConfirmationProof,
    ) -> Result<()> {
        (**self).create(record, issued_under)
    }

    fn load(&self, invitation_id: InvitationId) -> Result<Option<InvitationRecord>> {
        (**self).load(invitation_id)
    }

    fn transition(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
    ) -> Result<TransitionOutcome> {
        (**self).transition(expected, next)
    }

    fn commit(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
        commitment: &PairingCommitment,
    ) -> Result<TransitionOutcome> {
        (**self).commit(expected, next, commitment)
    }

    fn commitment(&self, invitation_id: InvitationId) -> Result<Option<PairingCommitment>> {
        (**self).commitment(invitation_id)
    }

    fn unfinished(&self) -> Result<Vec<InvitationRecord>> {
        (**self).unfinished()
    }
}

/// The client's durable record for one entered code.
///
/// It is keyed by an HMAC of the configured origin and the normalised full code under a distinct
/// random local key, never by the service-supplied invitation identity or expiry. A service that
/// advertises a new identity for the same code therefore cannot reset the counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientAttemptRecord {
    /// How many attempts this device has made with this code.
    pub attempts: u32,
    /// When the window started, on the monotonic clock.
    pub first_entry_monotonic_ms: u64,
    /// The boot that monotonic value belongs to.
    pub boot_identity: BootIdentity,
    /// When the record may be forgotten, on the monotonic clock of [`Self::boot_identity`].
    ///
    /// This is the deadline that governs while the machine is still up, so moving the wall clock
    /// forward cannot delete a record whose window is open.
    pub retain_until_monotonic_ms: u64,
    /// When the record may be forgotten after a reboot, on the **wall** clock.
    ///
    /// A tombstone outlives a reboot, and a monotonic value cannot: it restarts. This is the only
    /// clock left once the boot identity has changed, and a wall clock that runs backwards only
    /// lengthens the retention.
    pub retain_until_wall_ms: u64,
    /// True once the code is spent, so a later entry is refused rather than restarted.
    pub exhausted: bool,
}

impl ClientAttemptRecord {
    /// Returns this record anchored to the current boot, which is what a reboot does to it.
    ///
    /// A monotonic deadline from an earlier boot means nothing, so the record is given a full
    /// fresh tombstone period on *this* boot's monotonic clock. Reading the remaining time off the
    /// wall clock instead would hand an attacker the answer: jump the clock forward before the
    /// first sweep after a reboot and the remaining time is zero. The wall deadline is kept
    /// unchanged beside it, and [`Self::is_expired`] needs both, so a reboot and a forward jump
    /// can only ever lengthen retention.
    ///
    /// Repeated reboots therefore keep a tombstone alive longer than the required 24 hours. That
    /// is the safe direction: the entry refuses a code that is already spent, and the owner issues
    /// a new one rather than reusing it.
    ///
    /// Anchoring also ends the window, because section 10 says a reboot expires an unfinished
    /// entry: what survives the reboot is a tombstone, not a fresh five minutes.
    #[must_use]
    pub fn anchored(&self, now_monotonic_ms: u64, boot: BootIdentity) -> Self {
        if self.boot_identity == boot {
            return self.clone();
        }
        Self {
            boot_identity: boot,
            first_entry_monotonic_ms: now_monotonic_ms,
            exhausted: true,
            retain_until_monotonic_ms: now_monotonic_ms.saturating_add(CLIENT_TOMBSTONE_MS),
            ..self.clone()
        }
    }

    /// Returns true when this record may be forgotten.
    ///
    /// Both clocks have to agree that the retention is over, and the record has to belong to this
    /// boot. A forward wall-clock jump is held by the monotonic deadline, a backward one lengthens
    /// retention, and a record from another boot is never dropped at all until it is anchored.
    #[must_use]
    pub fn is_expired(&self, now_monotonic_ms: u64, boot: BootIdentity, now_wall_ms: u64) -> bool {
        self.boot_identity == boot
            && now_monotonic_ms >= self.retain_until_monotonic_ms
            && now_wall_ms >= self.retain_until_wall_ms
    }
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

    /// Applies one read-modify-write to a code's record, atomically.
    ///
    /// The implementation reads the current record, calls `decide` once, and persists whatever it
    /// returns before any other caller can read the same key. Two entries of the same code
    /// therefore cannot both see four attempts and both proceed. A `decide` that returns an error
    /// leaves the stored record untouched.
    ///
    /// # Errors
    ///
    /// Returns whatever `decide` returns, and [`PairingError::Store`] when the transaction fails.
    fn update(
        &self,
        code_key: &Mac256,
        decide: &dyn Fn(Option<ClientAttemptRecord>) -> Result<ClientAttemptRecord>,
    ) -> Result<ClientAttemptRecord>;

    /// Reads the record for one code key, without changing it.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn load(&self, code_key: &Mac256) -> Result<Option<ClientAttemptRecord>>;

    /// Anchors records from earlier boots and drops those whose retention has ended.
    ///
    /// An implementation applies [`ClientAttemptRecord::anchored`] to each record it keeps and
    /// [`ClientAttemptRecord::is_expired`] to decide. Anchoring is a write: a sweep is the first
    /// thing that sees a record after a reboot, and it is where that record stops depending on the
    /// wall clock.
    ///
    /// # Errors
    ///
    /// Returns [`PairingError::Store`].
    fn expire(&self, now_monotonic_ms: u64, boot: BootIdentity, now_wall_ms: u64) -> Result<()>;
}

impl<T: ClientBudgetStore + ?Sized> ClientBudgetStore for &T {
    fn budget_key(&self) -> Result<SymmetricKey> {
        (**self).budget_key()
    }

    fn update(
        &self,
        code_key: &Mac256,
        decide: &dyn Fn(Option<ClientAttemptRecord>) -> Result<ClientAttemptRecord>,
    ) -> Result<ClientAttemptRecord> {
        (**self).update(code_key, decide)
    }

    fn load(&self, code_key: &Mac256) -> Result<Option<ClientAttemptRecord>> {
        (**self).load(code_key)
    }

    fn expire(&self, now_monotonic_ms: u64, boot: BootIdentity, now_wall_ms: u64) -> Result<()> {
        (**self).expire(now_monotonic_ms, boot, now_wall_ms)
    }
}

/// The transport peer a pairing step arrived on.
///
/// Section 10 requires the host to check that the live iroh peer equals the authenticated client
/// endpoint, and the client to check the host likewise. It also refuses a pairing mutation in QUIC
/// 0-RTT data, which a state machine cannot see either, so the transport says so here.
pub trait LivePeer {
    /// Returns the endpoint identity of the authenticated transport peer.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no authenticated peer, which is itself a failure: a pairing
    /// mutation never arrives outside one.
    fn live_endpoint(&self) -> Result<EndpointKey>;

    /// Returns true when this step arrived in early data, before the handshake completed.
    ///
    /// Version 1 accepts no application mutation in QUIC 0-RTT, and a pairing mutation least of
    /// all: early data is replayable by anyone who captured it.
    fn arrived_in_early_data(&self) -> bool;
}

/// Checks that a step may change state at all.
///
/// # Errors
///
/// Returns [`PairingError::EarlyData`] when the step arrived before the handshake completed.
pub fn require_completed_handshake(peer: &dyn LivePeer) -> Result<()> {
    if peer.arrived_in_early_data() {
        return Err(PairingError::EarlyData);
    }
    Ok(())
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
    ///
    /// The wall clock does not, which is what a real reboot does too.
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
    state: Mutex<TestInvitationState>,
    failing: Mutex<bool>,
    failing_writes: Mutex<bool>,
    interleaved: Mutex<Option<InvitationRecord>>,
    refusal: Mutex<Option<PairingError>>,
}

#[derive(Debug, Default)]
struct TestInvitationState {
    records: BTreeMap<InvitationId, InvitationRecord>,
    commitments: BTreeMap<InvitationId, PairingCommitment>,
}

impl TestInvitationStore {
    /// Creates an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every operation fail, so a test can check that a failed read stops a step.
    pub fn set_failing(&self, failing: bool) {
        *self.failing.lock().expect("a test store") = failing;
    }

    /// Applies `record` inside the next conditional write, before it compares.
    ///
    /// This is the race a conditional write exists for: another writer lands between the moment a
    /// caller read the record and the moment it writes its decision back. A test cannot produce
    /// that by calling the store in order, so the store produces it.
    pub fn interleave(&self, record: InvitationRecord) {
        *self.interleaved.lock().expect("a test store") = Some(record);
    }

    /// Makes the next conditional write a refusal: the store decides not to write, and says why.
    pub fn refuse_next_write(&self, refusal: PairingError) {
        *self.refusal.lock().expect("a test store") = Some(refusal);
    }

    /// Makes writes fail while reads keep working, which is the interesting half.
    ///
    /// A host that can read its record and cannot write it is the case that decides whether a
    /// spent guess comes back: the decision is made and cannot be recorded.
    pub fn set_failing_writes(&self, failing: bool) {
        *self.failing_writes.lock().expect("a test store") = failing;
    }

    /// Returns a copy of the stored records, which is what survives a restart.
    #[must_use]
    pub fn snapshot(&self) -> Vec<InvitationRecord> {
        self.state
            .lock()
            .expect("a test store")
            .records
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

    /// Applies a pending interleaved write, as another writer racing this one would.
    fn interleave_now(&self, state: &mut TestInvitationState) {
        if let Some(record) = self.interleaved.lock().expect("a test store").take() {
            state.records.insert(record.invitation_id, record);
        }
    }

    fn check_write(&self) -> Result<()> {
        self.check()?;
        if *self.failing_writes.lock().expect("a test store") {
            return Err(PairingError::Store {
                reason: "the test store cannot write".to_owned(),
            });
        }
        Ok(())
    }
}

impl InvitationStore for TestInvitationStore {
    fn create(
        &self,
        record: &InvitationRecord,
        _issued_under: &OwnerConfirmationProof,
    ) -> Result<()> {
        self.check_write()?;
        let mut state = self.state.lock().expect("a test store");
        if state.records.contains_key(&record.invitation_id) {
            return Err(PairingError::Store {
                reason: "that invitation already exists".to_owned(),
            });
        }
        state.records.insert(record.invitation_id, record.clone());
        Ok(())
    }

    fn load(&self, invitation_id: InvitationId) -> Result<Option<InvitationRecord>> {
        self.check()?;
        Ok(self
            .state
            .lock()
            .expect("a test store")
            .records
            .get(&invitation_id)
            .cloned())
    }

    fn transition(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
    ) -> Result<TransitionOutcome> {
        self.check_write()?;
        if let Some(refusal) = self.refusal.lock().expect("a test store").take() {
            return Ok(TransitionOutcome::Refused(refusal));
        }
        // The comparison and the write are under one lock, which is the whole point of this
        // method: another writer cannot slip between them.
        let mut state = self.state.lock().expect("a test store");
        self.interleave_now(&mut state);
        match state.records.get(&expected.invitation_id) {
            Some(current) if current == expected => {
                state.records.insert(next.invitation_id, next.clone());
                Ok(TransitionOutcome::Written)
            }
            Some(current) => Ok(TransitionOutcome::Stale(current.clone())),
            None => Err(PairingError::Store {
                reason: "that invitation has no record".to_owned(),
            }),
        }
    }

    fn commit(
        &self,
        expected: &InvitationRecord,
        next: &InvitationRecord,
        commitment: &PairingCommitment,
    ) -> Result<TransitionOutcome> {
        self.check_write()?;
        if let Some(refusal) = self.refusal.lock().expect("a test store").take() {
            return Ok(TransitionOutcome::Refused(refusal));
        }
        // One lock over both maps: the record and the commitment appear together or not at all.
        let mut state = self.state.lock().expect("a test store");
        self.interleave_now(&mut state);
        match state.records.get(&expected.invitation_id) {
            Some(current) if current == expected => {
                state.records.insert(next.invitation_id, next.clone());
                state
                    .commitments
                    .insert(commitment.invitation_id, commitment.clone());
                Ok(TransitionOutcome::Written)
            }
            Some(current) => Ok(TransitionOutcome::Stale(current.clone())),
            None => Err(PairingError::Store {
                reason: "that invitation has no record".to_owned(),
            }),
        }
    }

    fn commitment(&self, invitation_id: InvitationId) -> Result<Option<PairingCommitment>> {
        self.check()?;
        Ok(self
            .state
            .lock()
            .expect("a test store")
            .commitments
            .get(&invitation_id)
            .cloned())
    }

    fn unfinished(&self) -> Result<Vec<InvitationRecord>> {
        self.check()?;
        Ok(self
            .state
            .lock()
            .expect("a test store")
            .records
            .values()
            .filter(|record| {
                matches!(
                    record.state,
                    InvitationState::Open | InvitationState::Locked { .. }
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

    fn update(
        &self,
        code_key: &Mac256,
        decide: &dyn Fn(Option<ClientAttemptRecord>) -> Result<ClientAttemptRecord>,
    ) -> Result<ClientAttemptRecord> {
        // The lock is held across the decision, which is the whole point of this method.
        let mut records = self.records.lock().expect("a test store");
        let updated = decide(records.get(code_key.as_bytes()).cloned())?;
        records.insert(*code_key.as_bytes(), updated.clone());
        Ok(updated)
    }

    fn load(&self, code_key: &Mac256) -> Result<Option<ClientAttemptRecord>> {
        Ok(self
            .records
            .lock()
            .expect("a test store")
            .get(code_key.as_bytes())
            .cloned())
    }

    fn expire(&self, now_monotonic_ms: u64, boot: BootIdentity, now_wall_ms: u64) -> Result<()> {
        self.records
            .lock()
            .expect("a test store")
            .retain(|_, record| {
                *record = record.anchored(now_monotonic_ms, boot);
                !record.is_expired(now_monotonic_ms, boot, now_wall_ms)
            });
        Ok(())
    }
}

/// A live peer a test sets by hand.
#[derive(Debug)]
pub struct TestLivePeer {
    endpoint: Mutex<Option<EndpointKey>>,
    early_data: Mutex<bool>,
}

impl TestLivePeer {
    /// Creates a peer with the given endpoint identity, past its handshake.
    #[must_use]
    pub fn new(endpoint: EndpointKey) -> Self {
        Self {
            endpoint: Mutex::new(Some(endpoint)),
            early_data: Mutex::new(false),
        }
    }

    /// Replaces the endpoint, so a test can substitute a different peer.
    pub fn set(&self, endpoint: Option<EndpointKey>) {
        *self.endpoint.lock().expect("a test peer") = endpoint;
    }

    /// Says whether this peer's steps arrive in early data.
    pub fn set_early_data(&self, early: bool) {
        *self.early_data.lock().expect("a test peer") = early;
    }
}

impl LivePeer for TestLivePeer {
    fn live_endpoint(&self) -> Result<EndpointKey> {
        self.endpoint
            .lock()
            .expect("a test peer")
            .ok_or(PairingError::EndpointMismatch { side: "transport" })
    }

    fn arrived_in_early_data(&self) -> bool {
        *self.early_data.lock().expect("a test peer")
    }
}

/// A rendezvous client for tests, which records the locators it was asked about.
#[derive(Debug)]
pub struct TestClient {
    record: LocatorRecord,
    looked_up: Mutex<Vec<String>>,
    unreachable: bool,
}

impl TestClient {
    /// Creates a client that answers every lookup with `record`.
    #[must_use]
    pub fn new(record: LocatorRecord) -> Self {
        Self {
            record,
            looked_up: Mutex::new(Vec::new()),
            unreachable: false,
        }
    }

    /// Creates a client whose service cannot be reached: every lookup fails.
    #[must_use]
    pub fn unreachable() -> Self {
        Self {
            record: LocatorRecord {
                invitation_id: InvitationId::new(kr_protocol::scalars::Uuid::from_bytes([0; 16])),
                advertised_expires_at_ms: TimestampMs::new(0),
            },
            looked_up: Mutex::new(Vec::new()),
            unreachable: true,
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
        if self.unreachable {
            return Err(PairingError::RendezvousUnavailable {
                reason: "the rendezvous service could not be reached".to_owned(),
            });
        }
        Ok(self.record.clone())
    }
}

/// One reservation request exactly as a rendezvous service receives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationRequest {
    /// The origin the request was sent to.
    pub origin: String,
    /// The locator it asked for.
    pub locator: String,
    /// The invitation it named.
    pub invitation_id: InvitationId,
    /// The expiry it asked the service to advertise.
    pub advertised_expires_at_ms: TimestampMs,
    /// The hash of the record-control token.
    pub control_token_hash: Digest256,
}

/// A rendezvous host for tests, which reserves every locator once.
///
/// It records every reservation request with all of its arguments, whether or not the locator was
/// granted, and it releases a reservation only for the token whose hash the reservation was made
/// with, which is how a real service checks possession of the control token.
#[derive(Debug, Default)]
pub struct TestRendezvousHost {
    reserved: Mutex<BTreeMap<String, (InvitationId, Digest256)>>,
    requests: Mutex<Vec<ReservationRequest>>,
    released: Mutex<Vec<String>>,
    reject_first: Mutex<usize>,
    fail_next: Mutex<usize>,
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

    /// Makes the next `count` requests fail as a service that cannot be reached would.
    pub fn fail_next(&self, count: usize) {
        *self.fail_next.lock().expect("a test service") = count;
    }

    /// Returns every reservation request this service received, in order, granted or not.
    #[must_use]
    pub fn requests(&self) -> Vec<ReservationRequest> {
        self.requests.lock().expect("a test service").clone()
    }

    /// Takes one pending failure, if a test asked for one.
    fn unreachable(&self) -> Result<()> {
        let mut remaining = self.fail_next.lock().expect("a test service");
        if *remaining > 0 {
            *remaining -= 1;
            return Err(PairingError::RendezvousUnavailable {
                reason: "the rendezvous service could not be reached".to_owned(),
            });
        }
        Ok(())
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
        origin: &RendezvousOrigin,
        locator: &Locator,
        invitation_id: InvitationId,
        advertised_expires_at_ms: TimestampMs,
        control_token_hash: Digest256,
    ) -> Result<bool> {
        self.unreachable()?;
        self.requests
            .lock()
            .expect("a test service")
            .push(ReservationRequest {
                origin: origin.as_str().to_owned(),
                locator: locator.as_str().to_owned(),
                invitation_id,
                advertised_expires_at_ms,
                control_token_hash,
            });
        let mut remaining = self.reject_first.lock().expect("a test service");
        if *remaining > 0 {
            *remaining -= 1;
            return Ok(false);
        }
        drop(remaining);
        // The check and the insertion happen under one lock, so two requests for one locator
        // cannot both be granted.
        let mut reserved = self.reserved.lock().expect("a test service");
        if reserved.contains_key(locator.as_str()) {
            return Ok(false);
        }
        reserved.insert(
            locator.as_str().to_owned(),
            (invitation_id, control_token_hash),
        );
        Ok(true)
    }

    fn release_locator(
        &self,
        _origin: &RendezvousOrigin,
        locator: &Locator,
        control_token: &SymmetricKey,
    ) -> Result<()> {
        self.unreachable()?;
        let mut reserved = self.reserved.lock().expect("a test service");
        let presented = Digest256::from_bytes(kr_cbor::sha256(control_token.expose()));
        match reserved.get(locator.as_str()) {
            Some((_, held)) if *held == presented => {}
            _ => {
                return Err(PairingError::RendezvousUnavailable {
                    reason: "no reservation is held for that locator and control token".to_owned(),
                });
            }
        }
        reserved.remove(locator.as_str());
        self.released
            .lock()
            .expect("a test service")
            .push(locator.as_str().to_owned());
        Ok(())
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
        let wall = clock.wall_clock_ms();
        clock.reboot(1);
        assert_eq!(clock.monotonic_ms(), 0);
        assert_ne!(clock.boot_identity(), before);
        assert_eq!(
            clock.wall_clock_ms(),
            wall,
            "a reboot does not reset the wall clock"
        );
    }

    #[test]
    fn a_wall_clock_skew_does_not_move_the_monotonic_clock() {
        let clock = TestClock::new();
        clock.advance(1_000);
        let monotonic = clock.monotonic_ms();
        clock.skew_wall_clock(-86_400_000);
        assert_eq!(clock.monotonic_ms(), monotonic);
    }

    /// KR-REQ-10.13, KR-REQ-10.12: the service holds only the hash of the 256-bit record-control
    /// token.
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

    /// A spent record kept until monotonic 500 of boot 0, or wall 1_000_000 after a reboot.
    fn tombstone(store: &TestClientBudgetStore, key: Mac256) {
        store
            .update(&key, &|_| {
                Ok(ClientAttemptRecord {
                    attempts: 5,
                    first_entry_monotonic_ms: 0,
                    boot_identity: BootIdentity([0; 32]),
                    retain_until_monotonic_ms: 500,
                    retain_until_wall_ms: 1_000_000,
                    exhausted: true,
                })
            })
            .expect("a write");
    }

    #[test]
    fn the_client_store_keeps_a_tombstone_across_a_reboot() {
        let store = TestClientBudgetStore::new().expect("a store");
        let key = Mac256::from_bytes([1; 32]);
        tombstone(&store, key);
        // Another boot. The monotonic deadline from the old one means nothing, so the record gets
        // a full fresh period on this boot's clock rather than whatever the wall clock suggests.
        let rebooted = BootIdentity([9; 32]);
        store.expire(0, rebooted, 900_000).expect("an expiry sweep");
        assert_eq!(store.len(), 1);
        let anchored = store.load(&key).expect("a read").expect("a record");
        assert_eq!(anchored.boot_identity, rebooted);
        assert_eq!(anchored.retain_until_monotonic_ms, CLIENT_TOMBSTONE_MS);
        assert!(anchored.exhausted);

        // A wall clock jumped years forward deletes nothing: both deadlines have to pass.
        store
            .expire(CLIENT_TOMBSTONE_MS - 1, rebooted, u64::MAX)
            .expect("an expiry sweep");
        assert_eq!(store.len(), 1);
        store
            .expire(CLIENT_TOMBSTONE_MS, rebooted, u64::MAX)
            .expect("an expiry sweep");
        assert!(store.is_empty());
    }

    #[test]
    fn a_clock_jumped_forward_before_the_first_sweep_deletes_nothing() {
        let store = TestClientBudgetStore::new().expect("a store");
        let key = Mac256::from_bytes([1; 32]);
        tombstone(&store, key);
        // The wall clock is jumped past the record's retention and *then* the machine reboots, so
        // the very first sweep of the new boot sees a deadline that has already passed.
        let rebooted = BootIdentity([9; 32]);
        store
            .expire(0, rebooted, u64::MAX)
            .expect("an expiry sweep");
        assert_eq!(store.len(), 1, "the code is still spent");

        // And another reboot does not help either.
        let again = BootIdentity([10; 32]);
        store.expire(0, again, u64::MAX).expect("an expiry sweep");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_reboot_leaves_a_tombstone_even_for_an_unfinished_entry() {
        let store = TestClientBudgetStore::new().expect("a store");
        let key = Mac256::from_bytes([2; 32]);
        store
            .update(&key, &|_| {
                Ok(ClientAttemptRecord {
                    attempts: 2,
                    first_entry_monotonic_ms: 0,
                    boot_identity: BootIdentity([0; 32]),
                    retain_until_monotonic_ms: 500,
                    retain_until_wall_ms: 1_000_000,
                    exhausted: false,
                })
            })
            .expect("a write");
        let rebooted = BootIdentity([9; 32]);
        store.expire(0, rebooted, 0).expect("an expiry sweep");
        let anchored = store.load(&key).expect("a read").expect("a record");
        assert!(anchored.exhausted, "a reboot expires an unfinished entry");
        assert_eq!(anchored.attempts, 2, "and it does not hand attempts back");
    }

    #[test]
    fn a_backward_wall_clock_only_lengthens_retention() {
        let store = TestClientBudgetStore::new().expect("a store");
        let key = Mac256::from_bytes([1; 32]);
        tombstone(&store, key);
        let boot = BootIdentity([0; 32]);
        // The monotonic deadline has passed; the wall one has not, because the clock went back.
        store.expire(500, boot, 0).expect("an expiry sweep");
        assert_eq!(store.len(), 1);
        store.expire(500, boot, 1_000_000).expect("an expiry sweep");
        assert!(store.is_empty());
    }

    #[test]
    fn a_wall_clock_jump_does_not_delete_a_tombstone_of_this_boot() {
        let store = TestClientBudgetStore::new().expect("a store");
        let key = Mac256::from_bytes([1; 32]);
        tombstone(&store, key);
        let boot = BootIdentity([0; 32]);
        // The wall clock jumps a year forward. Within the boot that wrote the record, the
        // monotonic deadline is what decides, so the tombstone stays.
        store
            .expire(499, boot, 1_000_000_000)
            .expect("an expiry sweep");
        assert_eq!(store.len(), 1);
        store
            .expire(500, boot, 1_000_000_000)
            .expect("an expiry sweep");
        assert!(store.is_empty());
    }

    #[test]
    fn an_update_that_refuses_leaves_the_record_untouched() {
        let store = TestClientBudgetStore::new().expect("a store");
        let key = Mac256::from_bytes([1; 32]);
        assert!(
            store
                .update(&key, &|_| Err(PairingError::ClientAttemptsExhausted))
                .is_err()
        );
        assert!(store.load(&key).expect("a read").is_none());
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
        assert!(require_completed_handshake(&peer).is_ok());
        peer.set(None);
        assert!(matches!(
            peer.live_endpoint(),
            Err(PairingError::EndpointMismatch { .. })
        ));
    }

    #[test]
    fn a_step_in_early_data_changes_nothing() {
        let peer = TestLivePeer::new(EndpointKey::from_bytes([1; 32]));
        peer.set_early_data(true);
        assert!(matches!(
            require_completed_handshake(&peer),
            Err(PairingError::EarlyData)
        ));
    }
}
