//! Relay leases, consumption receipts and relay instance registration: the objects of section 17.
//!
//! A relay forwards encrypted payloads between two authenticated endpoints. Admitting an endpoint
//! to a relay is not authority to send traffic through it and is not proof that anybody agreed to
//! pay for it, so before a payload crosses a forwarding boundary the relay must hold a current
//! [`SignedRelayLease`] that binds the endpoint pair, the route, the payer, a reserved block of
//! bytes and a deadline. The relay answers with [`SignedRelayConsumptionReceipt`]s that say how
//! much of the block it actually used.
//!
//! # The three keys
//!
//! | Key | Held by | Signs |
//! | --- | --- | --- |
//! | Service admission key ([`ServiceAdmissionKey`]) | the managed service | leases and revocations |
//! | Relay instance key ([`RelayInstanceKey`]) | one relay host, generated there | consumption receipts and its own registration |
//! | Endpoint keys ([`EndpointKey`]) | the two peers | nothing here; they are what a lease names |
//!
//! The relay pins the issuer keys it accepts; the service records the instance key it accepts.
//! Neither side infers a key from the message that arrives carrying it.
//!
//! # One reservation, one running total
//!
//! A reservation is the unit of money. [`RelayLease::byte_ceiling`] is its **cumulative** limit and
//! [`RelayConsumptionReceipt::bytes_consumed`] is its **cumulative** spend, so the two are figures
//! on one scale and a relay decides whether to forward by comparing them. A refill raises the
//! ceiling of the same reservation rather than opening a second one; entering grace raises it
//! again, by at most [`MAX_GRACE_BYTES`]. That is what makes a replacement unambiguous: a new
//! revision that keeps the reservation keeps its spend, and one that changes the payer, the pair or
//! the metering boundary must take a new reservation, because those are the facts the reservation
//! was priced against.
//!
//! # What a relay must keep across a restart
//!
//! A signed lease and a set of pinned keys are not enough to forward safely. A relay also keeps,
//! durably: the highest lease revision it has seen for each lease identity, whether that identity
//! is revoked, the cumulative bytes it has counted for each reservation, and the receipts it has
//! not yet had acknowledged. Without the first two a replayed older lease would reopen a closed
//! ceiling; without the last two a restart would either lose consumption or invent it. A relay that
//! has lost that state cannot resume the reservation: the service settles it conservatively, and
//! section 17 forbids that settlement from minting a new grace period.
//!
//! # Profile decisions
//!
//! Section 17 fixes the fields each object binds and leaves the encoding to the implementation.
//! What it fixes is the field list; what it does not fix is decided here, once, and frozen by the
//! vectors under `fixtures/relay/`:
//!
//! | Decision | Choice | Why |
//! | --- | --- | --- |
//! | The four signature domains | `kr-relay/lease/1`, `kr-relay/revoke/1`, `kr-relay/receipt/1`, `kr-relay/instance/1` | One shared domain would let a receipt verify as a lease |
//! | The signed shape | `CBOR([domain, <the unsigned object as a map>])` | The objects are closed maps, so their canonical encoding already follows from their field names; a positional list would be a second encoding to keep in step |
//! | Ceilings and receipts | Both cumulative per reservation | Two scales, one per revision and one per reservation, cannot be compared without knowing which revisions a relay saw |
//! | The relay scope | The two named positions of one route, not a set of permitted instances | A set admits a relay that is on no route the lease describes, which is a relay that can forward without the metering boundary ever seeing the payload |
//! | Registration proof | The relay instance signs its own registration | The operator submits the registration under service-admin authority, so the signature is what proves the host actually holds the key being registered |
//!
//! # What this module does not do
//!
//! It carries no cryptography and no accounting state. It defines what is signed, what a receiver
//! can check from the object alone, and the bounds section 17 states. Verifying a signature is
//! `kr-crypto`'s; reserving bytes and settling them is the managed service's; enforcing a lease at
//! a forwarding boundary is the relay's.

use kr_cbor::{CborError, signing_value};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    AccountId, InstallationId, PayerAuthorisationId, RelayInstanceId, RelayLeaseId,
    RelayLeaseRevision, RelayReceiptSequence, RelayRegion, RelayRegistrationRevision,
    RelayReservationId,
};
use crate::pairing::NetworkHint;
use crate::scalars::{
    EndpointKey, Nullable, RelayInstanceKey, ServiceAdmissionKey, Signature64, TimestampMs, U64,
};

/// The domain a relay lease signature covers.
pub const RELAY_LEASE_DOMAIN: &str = "kr-relay/lease/1";

/// The domain a relay lease revocation signature covers.
pub const RELAY_REVOKE_DOMAIN: &str = "kr-relay/revoke/1";

/// The domain a relay consumption receipt signature covers.
pub const RELAY_RECEIPT_DOMAIN: &str = "kr-relay/receipt/1";

/// The domain a relay instance registration signature covers.
pub const RELAY_INSTANCE_DOMAIN: &str = "kr-relay/instance/1";

/// The largest aggregate of outstanding reserved bytes one principal may hold, in bytes.
///
/// Section 17 sets 8 MiB, subdividable across any admitted relay instances. It bounds what is
/// *outstanding*, not what a reservation may spend over its life: a refill raises the same
/// reservation's cumulative ceiling, so the figure this caps is the ceiling minus what has already
/// been reported. It is the bound on how much consumption can be unknown at once, so a service that
/// lost contact with every relay holding a principal's reservations can be wrong by at most this
/// much.
pub const MAX_OUTSTANDING_RESERVED_BYTES: u64 = 8 * 1024 * 1024;

/// The longest bounded grace a principal gets after exhaustion, in milliseconds.
pub const MAX_GRACE_DURATION_MS: u64 = 15 * 60 * 1000;

/// The most bytes a principal may forward inside its bounded grace.
pub const MAX_GRACE_BYTES: u64 = 100 * 1024 * 1024;

/// The lowest sequence a consumption receipt may carry.
pub const FIRST_RECEIPT_SEQUENCE: u64 = 1;

/// The most receipts one consumption report may carry.
pub const MAX_RECEIPTS_PER_REPORT: usize = 256;

/// Which way a lease permits a payload to travel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayDirection {
    /// Only from the source endpoint to the destination endpoint.
    SourceToDestination,
    /// Both ways between the two endpoints.
    Bidirectional,
}

/// A forwarding boundary inside one relay instance.
///
/// A payload crosses two boundaries at a relay: it is read from the sending connection and it is
/// written to the receiving one. They are not the same event. A payload counted as it arrives may
/// still be fenced by a revocation, dropped for a full queue or lost to a closing connection before
/// it is delivered, so which boundary counts decides what the payer pays for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MeteringRole {
    /// Count the payload as it is read from the sending connection.
    Ingress,
    /// Count the payload as it is written to the receiving connection.
    Egress,
}

/// The two relay positions one lease is valid at.
///
/// This is the lease's relay scope. It names positions rather than a set of permitted instances,
/// because a set says which relays may forward without saying which route they are forwarding on:
/// a pair could then use a second relay of the set and never pass the boundary that counts. The
/// ingress position is where the source endpoint's payloads enter the relay tier and the egress
/// position is where they leave it. A single-relay route names the same instance twice, which is
/// the ordinary case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayScope {
    /// The relay instance the source endpoint is connected to.
    pub ingress_relay_instance_id: RelayInstanceId,
    /// The relay instance the destination endpoint is connected to.
    pub egress_relay_instance_id: RelayInstanceId,
}

impl RelayScope {
    /// Returns true when `relay_instance_id` holds either position.
    #[must_use]
    pub fn includes(&self, relay_instance_id: RelayInstanceId) -> bool {
        self.ingress_relay_instance_id == relay_instance_id
            || self.egress_relay_instance_id == relay_instance_id
    }

    /// Returns true when the route uses one relay rather than two.
    #[must_use]
    pub fn is_single_relay(&self) -> bool {
        self.ingress_relay_instance_id == self.egress_relay_instance_id
    }
}

/// Who pays for a lease.
///
/// Section 17 bills one account or one anonymous installation. An installation is not proof of a
/// new person, which is why anonymous capacity carries its own global and per-network budgets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PayerPrincipal {
    /// A managed account.
    Account {
        /// The account that is billed.
        account_id: AccountId,
    },
    /// An anonymous installation drawing on the free allowance.
    Installation {
        /// The installation that is billed.
        installation_id: InstallationId,
    },
}

/// Why this payer is the one billed.
///
/// A relay credential cannot move the bill to another account. A sponsored lease names the
/// authorisation the sponsor gave, so the service can show which record made the transfer lawful
/// and can refuse a lease that names none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PayerAuthorisation {
    /// The host's own selected account or installation pays, which is the default.
    HostSelected,
    /// Another principal sponsors this pair under a recorded authorisation.
    Sponsored {
        /// The sponsor's authorisation record.
        authorisation_id: PayerAuthorisationId,
    },
}

/// The bounded grace a principal is inside, as the service has told this relay.
///
/// Section 17 grants a principal up to fifteen minutes or 100 MiB after exhaustion, whichever ends
/// first, shared across every connection of that principal. It starts at the first exhaustion
/// event, and reconnects, new endpoints and other regions cannot restart it: only the service knows
/// when the principal first exhausted its allowance, and a relay only ever receives what is left of
/// one grace period as a slice of it.
///
/// The slice is expressed as a raised cumulative ceiling on the same reservation, so the relay has
/// one number to compare its running total against whether the lease is in grace or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayGrace {
    /// When the principal's grace began, in UTC milliseconds.
    pub started_at_ms: TimestampMs,
    /// When it ends, in UTC milliseconds.
    pub ends_at_ms: TimestampMs,
    /// The cumulative bytes this reservation may reach inside the grace. Never below the lease's
    /// own ceiling, and above it by at most [`MAX_GRACE_BYTES`].
    pub byte_ceiling: U64,
}

impl RelayGrace {
    /// The milliseconds this grace lasts, or null when its dates are inverted.
    #[must_use]
    fn duration_ms(&self) -> Option<u64> {
        self.ends_at_ms.get().checked_sub(self.started_at_ms.get())
    }

    /// Returns true when the grace is inside the section 17 bounds, given the ceiling it raises.
    #[must_use]
    pub fn is_bounded(&self, reservation_ceiling: u64) -> bool {
        let Some(duration) = self.duration_ms() else {
            return false;
        };
        let Some(granted) = self.byte_ceiling.get().checked_sub(reservation_ceiling) else {
            return false;
        };
        duration <= MAX_GRACE_DURATION_MS && granted <= MAX_GRACE_BYTES
    }
}

/// A signed service capability to forward between one pair of endpoints.
///
/// This is the object section 17 requires a relay to hold before it forwards a peer payload. Every
/// field is inside the signature, so a relay that trusts its pinned issuer keys, and keeps the
/// durable state named at the top of this module, needs nothing else to decide whether a payload
/// may cross a boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayLease {
    /// The lease identity. One lease covers one endpoint pair for one payer.
    pub lease_id: RelayLeaseId,
    /// The revision of this lease. Strictly increasing per lease identity; a relay keeps the
    /// highest revision it has seen and refuses anything lower, so a replaced lease cannot be
    /// rolled back to an earlier ceiling or an earlier deadline.
    pub revision: RelayLeaseRevision,
    /// The reserved block this lease spends from. It is bound for its lifetime to this lease, this
    /// payer, this pair and this metering boundary; changing any of them takes a new reservation.
    pub reservation_id: RelayReservationId,
    /// The endpoint that may send.
    pub source_endpoint_key: EndpointKey,
    /// The endpoint that may receive.
    pub destination_endpoint_key: EndpointKey,
    /// Whether the reverse direction is permitted too.
    pub direction: RelayDirection,
    /// Who is billed.
    pub payer: PayerPrincipal,
    /// Why that principal is the one billed.
    pub payer_authorisation: PayerAuthorisation,
    /// The cumulative bytes this reservation may reach at the metering boundary. A refill raises
    /// it; it never falls.
    pub byte_ceiling: U64,
    /// When the lease stops being valid, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
    /// The two relay positions this lease is valid at.
    pub relay_scope: RelayScope,
    /// The relay instance that counts the bytes. One of the two positions in the scope.
    pub metering_relay_instance_id: RelayInstanceId,
    /// Which of that instance's own boundaries takes the count.
    pub metering_role: MeteringRole,
    /// The bounded grace this pair is inside, or null when the principal is not in grace.
    pub grace: Nullable<RelayGrace>,
    /// The service admission key that signs this lease. A relay accepts it only when the key is
    /// one it pins.
    pub issuer_key: ServiceAdmissionKey,
}

impl RelayLease {
    /// Builds the canonical bytes this lease's signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the lease cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            RELAY_LEASE_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Returns true when the lease's own fields are consistent.
    ///
    /// This is what a receiver can check without any state: the endpoints differ, the metering
    /// instance holds one of the two route positions, and any grace raises the reservation's
    /// ceiling by an amount section 17 permits. A lease that fails this is refused before its
    /// signature is worth checking.
    ///
    /// The 8 MiB aggregate is deliberately not checked here. It bounds what is outstanding, which
    /// is the ceiling minus what has already been reported, and a stateless check cannot know the
    /// second half of that. [`Self::outstanding_bytes`] is the check a relay makes against its own
    /// running total.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.source_endpoint_key != self.destination_endpoint_key
            && self.relay_scope.includes(self.metering_relay_instance_id)
            && self
                .grace
                .0
                .is_none_or(|grace| grace.is_bounded(self.byte_ceiling.get()))
    }

    /// The bytes this lease still has outstanding once `bytes_consumed` have been counted.
    ///
    /// This is the figure section 17's 8 MiB aggregate bounds, per principal across every relay it
    /// is using. A relay checks its own share of it against what it has actually counted, because
    /// that is the only side of the subtraction it holds.
    #[must_use]
    pub fn outstanding_bytes(&self, bytes_consumed: u64) -> u64 {
        self.bytes_remaining(bytes_consumed)
    }

    /// Returns true when the lease permits a payload from `source` to `destination`.
    ///
    /// This is the pair rule alone. A forwarding boundary also checks the route, which
    /// [`Self::admits_payload`] does.
    #[must_use]
    pub fn admits_pair(&self, source: EndpointKey, destination: EndpointKey) -> bool {
        self.orientation(source, destination).is_some()
    }

    /// Returns true when the lease permits this payload on this route.
    ///
    /// `ingress` is the relay the payload entered the tier at and `egress` is the relay it leaves
    /// at; for a single-relay route both are the forwarding relay itself. Checking them is what
    /// stops a pair from using a relay the lease names and bypassing the one that counts: on the
    /// reverse direction of a two-way lease the positions swap with the payload, so the metering
    /// instance stays on the route either way.
    #[must_use]
    pub fn admits_payload(
        &self,
        source: EndpointKey,
        destination: EndpointKey,
        ingress: RelayInstanceId,
        egress: RelayInstanceId,
    ) -> bool {
        match self.orientation(source, destination) {
            Some(true) => {
                ingress == self.relay_scope.ingress_relay_instance_id
                    && egress == self.relay_scope.egress_relay_instance_id
            }
            Some(false) => {
                ingress == self.relay_scope.egress_relay_instance_id
                    && egress == self.relay_scope.ingress_relay_instance_id
            }
            None => false,
        }
    }

    /// `Some(true)` for the lease's own direction, `Some(false)` for the permitted reverse.
    fn orientation(&self, source: EndpointKey, destination: EndpointKey) -> Option<bool> {
        if source == self.source_endpoint_key && destination == self.destination_endpoint_key {
            Some(true)
        } else if self.direction == RelayDirection::Bidirectional
            && source == self.destination_endpoint_key
            && destination == self.source_endpoint_key
        {
            Some(false)
        } else {
            None
        }
    }

    /// Returns true when `relay_instance_id` holds a position on this lease's route.
    #[must_use]
    pub fn admits_relay(&self, relay_instance_id: RelayInstanceId) -> bool {
        self.relay_scope.includes(relay_instance_id)
    }

    /// Returns true when this relay, at this boundary, is the one that counts the payload.
    ///
    /// Exactly one instance and one boundary answer true for a lease, which is how a two-relay
    /// route charges a payload once rather than at both ends.
    #[must_use]
    pub fn meters_here(&self, relay_instance_id: RelayInstanceId, boundary: MeteringRole) -> bool {
        self.metering_relay_instance_id == relay_instance_id && self.metering_role == boundary
    }

    /// The deadline the relay enforces, in UTC milliseconds.
    ///
    /// A lease in grace stops at whichever comes first, its own expiry or the end of the
    /// principal's shared grace.
    #[must_use]
    pub fn effective_deadline_ms(&self) -> u64 {
        match self.grace.0 {
            Some(grace) => self.expires_at_ms.get().min(grace.ends_at_ms.get()),
            None => self.expires_at_ms.get(),
        }
    }

    /// The cumulative bytes this reservation may reach under this revision.
    ///
    /// Grace raises the reservation's ceiling rather than opening a second allowance, so a relay
    /// compares its running total against this one number in either state.
    #[must_use]
    pub fn effective_byte_ceiling(&self) -> u64 {
        match self.grace.0 {
            Some(grace) => grace.byte_ceiling.get().max(self.byte_ceiling.get()),
            None => self.byte_ceiling.get(),
        }
    }

    /// The bytes still forwardable once `bytes_consumed` have been counted for the reservation.
    #[must_use]
    pub fn bytes_remaining(&self, bytes_consumed: u64) -> u64 {
        self.effective_byte_ceiling().saturating_sub(bytes_consumed)
    }

    /// Returns true when the lease is still inside its deadline at `now_ms`.
    #[must_use]
    pub fn is_valid_at(&self, now_ms: u64) -> bool {
        now_ms < self.effective_deadline_ms()
    }

    /// Returns true when the relay may admit a new relay session for this pair.
    ///
    /// Section 17 stops admitting new sessions at exhaustion and lets the connections that already
    /// exist run out the bounded grace. A lease carrying a grace is therefore a lease that keeps
    /// current connections alive and starts no new ones.
    #[must_use]
    pub fn admits_new_session(&self) -> bool {
        self.grace.0.is_none()
    }

    /// The milliseconds of grace left at `now_ms`, or null when the pair is not in grace.
    ///
    /// It counts down to the deadline the relay actually enforces, not to the end of the grace
    /// window, so a lease that expires first never advertises an interval it will not honour.
    /// Section 17 requires that interval to be visible before the relay closes.
    #[must_use]
    pub fn grace_remaining_ms(&self, now_ms: u64) -> Nullable<U64> {
        match self.grace.0 {
            Some(_) => Nullable::some(U64::new(
                self.effective_deadline_ms().saturating_sub(now_ms),
            )),
            None => Nullable::null(),
        }
    }

    /// Returns true when `self` may replace `previous` at a relay.
    ///
    /// A replacement names the same lease and carries a strictly higher revision. Beyond that the
    /// rule follows from the reservation being the unit of money: a replacement that keeps the
    /// reservation inherits its running total, so it must keep everything that total was priced
    /// against and may only raise the ceiling. A replacement that takes a new reservation is a new
    /// allocation, and the service settles the one it closed.
    ///
    /// A grace already in force is carried unchanged. Section 17 gives a principal one grace,
    /// starting at its first exhaustion, that reconnects and new endpoints cannot restart; a
    /// replacement that could move either end of the window would be exactly that restart, taken
    /// one revision at a time.
    #[must_use]
    pub fn supersedes(&self, previous: &Self) -> bool {
        if self.lease_id != previous.lease_id || self.revision.get() <= previous.revision.get() {
            return false;
        }
        if !self.continues_grace_of(previous) {
            return false;
        }
        if self.reservation_id != previous.reservation_id {
            return true;
        }
        self.binds_reservation_as(previous)
            && self.effective_byte_ceiling() >= previous.effective_byte_ceiling()
    }

    /// Returns true when `self` carries `previous`'s grace window unchanged, or leaves grace on
    /// terms that mean the allowance was actually restored.
    ///
    /// Two rules, and the second is the one that matters. A grace still in force keeps its start
    /// and may only end sooner: moving either end would be the restart section 17 forbids. And a
    /// replacement may drop the grace only by raising the reservation's ceiling above what the
    /// grace itself permitted, because that is what "the allowance was restored" means as a figure.
    /// Without that rule, a revision that dropped the grace while restoring nothing would leave the
    /// next revision free to open a second window, and one exhaustion event would become as many
    /// graces as the service cared to issue.
    #[must_use]
    pub fn continues_grace_of(&self, previous: &Self) -> bool {
        match (self.grace.0, previous.grace.0) {
            (_, None) => true,
            (None, Some(current)) => self.byte_ceiling.get() > current.byte_ceiling.get(),
            (Some(next), Some(current)) => {
                next.started_at_ms == current.started_at_ms
                    && next.ends_at_ms.get() <= current.ends_at_ms.get()
            }
        }
    }

    /// Returns true when both leases bind their reservation to the same facts.
    ///
    /// These are the facts a reservation is priced against: who pays, which pair, which route and
    /// which boundary counts. A running total carried from one revision to another is only
    /// meaningful while they hold.
    #[must_use]
    pub fn binds_reservation_as(&self, other: &Self) -> bool {
        self.source_endpoint_key == other.source_endpoint_key
            && self.destination_endpoint_key == other.destination_endpoint_key
            && self.direction == other.direction
            && self.payer == other.payer
            && self.relay_scope == other.relay_scope
            && self.metering_relay_instance_id == other.metering_relay_instance_id
            && self.metering_role == other.metering_role
    }
}

/// A lease and the service admission signature that authorises it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedRelayLease {
    /// The lease.
    pub lease: RelayLease,
    /// The Ed25519 signature over `CBOR(["kr-relay/lease/1", lease])`, by the lease's issuer key.
    pub signature: Signature64,
}

/// A service instruction to stop forwarding under a lease.
///
/// Revocation carries the revision it installs, so it orders against lease installation on one
/// scale: a relay that has already seen a higher revision ignores it, and a lease that arrives
/// afterwards at a lower revision is ignored in turn.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayLeaseRevocation {
    /// The lease to stop forwarding under.
    pub lease_id: RelayLeaseId,
    /// The revision this revocation installs. Strictly higher than the revision it fences.
    pub revision: RelayLeaseRevision,
    /// The relay instance this revocation is addressed to, so one relay's copy cannot be replayed
    /// at another.
    pub relay_instance_id: RelayInstanceId,
    /// When the service issued it, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// The service admission key that signs it.
    pub issuer_key: ServiceAdmissionKey,
}

impl RelayLeaseRevocation {
    /// Builds the canonical bytes this revocation's signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the revocation cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            RELAY_REVOKE_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Returns true when this revocation fences `lease` at the relay reading it.
    ///
    /// `relay_instance_id` is the relay applying the revocation. A revocation addressed to one
    /// instance says nothing at another, so the target is checked before the revision: the same
    /// signed bytes replayed elsewhere fence nothing.
    #[must_use]
    pub fn fences(&self, lease: &RelayLease, relay_instance_id: RelayInstanceId) -> bool {
        self.relay_instance_id == relay_instance_id
            && self.lease_id == lease.lease_id
            && self.revision.get() > lease.revision.get()
    }
}

/// A revocation and the service admission signature that authorises it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedRelayLeaseRevocation {
    /// The revocation.
    pub revocation: RelayLeaseRevocation,
    /// The Ed25519 signature over `CBOR(["kr-relay/revoke/1", revocation])`.
    pub signature: Signature64,
}

/// What the payer's client sends to a relay's control endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayLeaseRequest {
    /// Install a lease, or replace an installed one with a higher revision.
    Install {
        /// The lease to install. Boxed because a lease is much the larger of the two requests and
        /// an unboxed variant would make every revocation carry its size.
        lease: Box<SignedRelayLease>,
    },
    /// Stop forwarding under a lease and fence traffic that is queued but not yet forwarded.
    Revoke {
        /// The revocation to apply.
        revocation: SignedRelayLeaseRevocation,
    },
}

/// What a relay holds for a lease identity after a control request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelayLeaseState {
    /// The revision is installed and forwarding.
    Installed,
    /// A higher revision replaced this one.
    Superseded,
    /// The service revoked it.
    Revoked,
    /// Its deadline passed.
    Expired,
    /// Its reserved bytes are spent.
    Exhausted,
}

/// A relay's answer to a control request.
///
/// An exact retry of an installation answers with the same state and the same running figures: the
/// relay keeps what it has counted, so re-sending a lease can never restore a spent ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayLeaseAck {
    /// The lease the request named.
    pub lease_id: RelayLeaseId,
    /// The revision the relay now holds.
    pub revision: RelayLeaseRevision,
    /// What the relay holds for that lease.
    pub state: RelayLeaseState,
    /// The cumulative bytes counted for its reservation so far.
    pub bytes_consumed: U64,
    /// The bytes still forwardable under it.
    pub bytes_remaining: U64,
    /// The milliseconds of grace left, or null when the pair is not in grace. Section 17 requires
    /// the remaining interval to be visible before the relay closes.
    pub grace_remaining_ms: Nullable<U64>,
}

/// A relay's signed statement of what one reservation has spent.
///
/// The count is cumulative for the reservation, so a duplicate delivery of a receipt costs nothing
/// and a later receipt states the whole figure rather than an increment. It does not make a missing
/// receipt harmless: the service records receipts in order, and a relay that cannot supply the one
/// in between has lost the evidence for that stretch, which is settled conservatively rather than
/// assumed away.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayConsumptionReceipt {
    /// The relay instance that counted the bytes.
    pub relay_instance_id: RelayInstanceId,
    /// The reservation the bytes were spent from.
    pub reservation_id: RelayReservationId,
    /// The position of this receipt in that reservation's own sequence. It starts at
    /// [`FIRST_RECEIPT_SEQUENCE`] and increases by one, so a gap is detectable and a repeat is
    /// recognisable.
    pub sequence: RelayReceiptSequence,
    /// The bytes spent from the reservation so far. Cumulative and never decreasing.
    pub bytes_consumed: U64,
    /// The lease revision that was in force when the count was taken.
    pub lease_revision: RelayLeaseRevision,
    /// When the relay took the count, in UTC milliseconds.
    pub observed_at_ms: TimestampMs,
}

impl RelayConsumptionReceipt {
    /// Builds the canonical bytes this receipt's signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the receipt cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            RELAY_RECEIPT_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Returns true when this receipt could be the first one of its reservation.
    #[must_use]
    pub fn is_first(&self) -> bool {
        self.sequence.get() == FIRST_RECEIPT_SEQUENCE
    }

    /// Returns true when this receipt is the one that follows `previous`.
    ///
    /// The next receipt of a reservation comes from the same instance, sits one position later,
    /// reports no less than the total before it and was taken under a lease revision no older.
    #[must_use]
    pub fn follows(&self, previous: &Self) -> bool {
        let Some(expected) = previous.sequence.get().checked_add(1) else {
            return false;
        };
        self.relay_instance_id == previous.relay_instance_id
            && self.reservation_id == previous.reservation_id
            && self.sequence.get() == expected
            && self.bytes_consumed.get() >= previous.bytes_consumed.get()
            && self.lease_revision.get() >= previous.lease_revision.get()
    }

    /// Returns true when this receipt is a repeat of `previous` rather than a conflict.
    ///
    /// Reports are idempotent by reservation and sequence. A second delivery of a receipt already
    /// recorded is ignored; the same position carrying different figures is not a repeat, it is
    /// two relays or two histories claiming one position.
    #[must_use]
    pub fn repeats(&self, previous: &Self) -> bool {
        self.reservation_id == previous.reservation_id
            && self.sequence == previous.sequence
            && self == previous
    }
}

/// A receipt and the relay instance signature that authenticates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedRelayConsumptionReceipt {
    /// The receipt.
    pub receipt: RelayConsumptionReceipt,
    /// The Ed25519 signature over `CBOR(["kr-relay/receipt/1", receipt])`, by the registered key
    /// of the receipt's relay instance.
    pub signature: Signature64,
}

/// What a relay posts to the service to report consumption.
///
/// A report carries receipts for one reservation in ascending order. Reporting is idempotent, so a
/// relay that is unsure whether a report arrived sends it again rather than skipping it, and a
/// relay resuming after a restart replays from the last position the service acknowledged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayConsumptionReport {
    /// The relay instance reporting.
    pub relay_instance_id: RelayInstanceId,
    /// The reservation being reported.
    pub reservation_id: RelayReservationId,
    /// The receipts, in ascending sequence order.
    pub receipts: Vec<SignedRelayConsumptionReceipt>,
}

impl RelayConsumptionReport {
    /// Returns true when the report's own shape is consistent.
    ///
    /// Every receipt names the reservation and the instance the report names, every sequence is a
    /// real position, the receipts ascend with no repeats, and the batch is bounded.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        if self.receipts.is_empty() || self.receipts.len() > MAX_RECEIPTS_PER_REPORT {
            return false;
        }
        let mut previous: Option<&RelayConsumptionReceipt> = None;
        for signed in &self.receipts {
            let receipt = &signed.receipt;
            if receipt.relay_instance_id != self.relay_instance_id
                || receipt.reservation_id != self.reservation_id
                || receipt.sequence.get() < FIRST_RECEIPT_SEQUENCE
            {
                return false;
            }
            if let Some(previous) = previous
                && receipt.sequence.get() <= previous.sequence.get()
            {
                return false;
            }
            previous = Some(receipt);
        }
        true
    }

    /// Returns true when the receipts form one unbroken run.
    ///
    /// A report may be a batch, but a batch with a hole inside it is a batch the service cannot
    /// record: it would have to accept a later position while the one before it is still missing.
    #[must_use]
    pub fn is_contiguous(&self) -> bool {
        self.is_well_formed()
            && self
                .receipts
                .windows(2)
                .all(|pair| pair[1].receipt.follows(&pair[0].receipt))
    }
}

/// The service's answer to a consumption report.
///
/// It states what the service has recorded rather than what the report contained, so a relay
/// recovering from a crash learns from one exchange exactly which position to replay from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayConsumptionAck {
    /// The reservation the report was about.
    pub reservation_id: RelayReservationId,
    /// The highest sequence recorded for it, or null when none has been.
    pub recorded_through: Nullable<RelayReceiptSequence>,
    /// The next sequence the service will accept. A relay resumes from here.
    pub next_sequence: RelayReceiptSequence,
    /// The cumulative bytes recorded for the reservation.
    pub bytes_recorded: U64,
    /// True when the service is holding out for receipts it has not been given. The reservation
    /// stays outstanding until they arrive or until it is settled conservatively.
    pub awaiting_receipts: bool,
}

/// A successor key and the window in which both keys are accepted.
///
/// Rotation cannot be instantaneous: receipts signed before the change are still in flight when the
/// new key starts signing. The overlap is that window, stated in advance and ending at a recorded
/// time rather than whenever somebody remembers to retire the old key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayKeySuccession {
    /// The key that takes over.
    pub instance_key: RelayInstanceKey,
    /// When the successor starts being accepted, in UTC milliseconds.
    pub overlap_from_ms: TimestampMs,
    /// When the key it replaces stops being accepted, in UTC milliseconds.
    pub predecessor_retires_at_ms: TimestampMs,
}

impl RelayKeySuccession {
    /// Returns true when the overlap window is ordered and non-empty.
    #[must_use]
    pub fn is_ordered(&self) -> bool {
        self.overlap_from_ms.get() < self.predecessor_retires_at_ms.get()
    }
}

/// A relay instance's registration with the service.
///
/// The instance key is generated on the relay host and never leaves it, so the service learns the
/// public half here and verifies every later receipt against it.
///
/// A registration is replaced rather than amended, and [`Self::replaces`] is the whole rule for
/// when one may replace another. Two things make that rule necessary: a registration is a signed
/// document, so without a revision an old one could be replayed to cancel a rotation, and a
/// successor that could install itself the moment its overlap opened would strand every receipt its
/// predecessor had signed but not yet delivered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelayInstanceRegistration {
    /// The instance identity. Stable across key rotation.
    pub relay_instance_id: RelayInstanceId,
    /// The revision of this registration. Strictly increasing per instance, so a registration the
    /// instance has replaced cannot be replayed to undo the replacement. The same revision is
    /// accepted again only for a byte-identical retry.
    pub revision: RelayRegistrationRevision,
    /// The public half of the key this instance signs receipts with.
    pub instance_key: RelayInstanceKey,
    /// The URL clients reach this instance at.
    pub relay_url: NetworkHint,
    /// The deployment region this instance serves.
    pub region: RelayRegion,
    /// When the registration starts being valid, in UTC milliseconds.
    pub valid_from_ms: TimestampMs,
    /// When it stops being valid, in UTC milliseconds.
    pub valid_until_ms: TimestampMs,
    /// The successor key and its overlap window, or null when no rotation is announced.
    pub successor: Nullable<RelayKeySuccession>,
}

impl RelayInstanceRegistration {
    /// Builds the canonical bytes this registration's signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the registration cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            RELAY_INSTANCE_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Returns true when the registration's own dates and keys are consistent.
    ///
    /// The validity window is non-empty, and any announced rotation names a different key, is
    /// ordered, and finishes inside that window. A successor equal to its predecessor would leave
    /// the retired key accepted through the successor's own branch, which is a retirement that
    /// retires nothing.
    #[must_use]
    pub fn is_well_formed(&self) -> bool {
        self.valid_from_ms.get() < self.valid_until_ms.get()
            && self.successor.0.is_none_or(|successor| {
                successor.instance_key != self.instance_key
                    && successor.is_ordered()
                    && successor.overlap_from_ms.get() >= self.valid_from_ms.get()
                    && successor.predecessor_retires_at_ms.get() <= self.valid_until_ms.get()
            })
    }

    /// Returns true when `self` may replace `previous` at `now_ms`.
    ///
    /// Beyond the revision, four rules hold, and each one closes a way of taking an instance over:
    ///
    /// - The key being registered is one `previous` still accepts, so a key nobody announced never
    ///   becomes the key receipts are checked against, and a key that has retired cannot put itself
    ///   back. A later registration may announce it again as a successor, which is an ordinary
    ///   rotation back and needs the current key's signature like any other.
    /// - The announced successor may name itself only once the recorded retirement has passed, so
    ///   the overlap the predecessor announced is the overlap it gets.
    /// - A replacement that keeps the registered key keeps the succession that key announced,
    ///   unless the overlap has not started, in which case there is nothing relying on it yet.
    /// - A succession it announces retires in the future. One that had already finished would hand
    ///   sole authority to a key on the strength of a single submission.
    ///
    /// Together these mean the key that signed a replacement is still accepted afterwards: no
    /// submission can hand an instance to a key that has proved nothing.
    ///
    /// The caller separately requires the submission to be signed by a key `previous` accepts at
    /// `now_ms`: this states which registrations may follow which, not who may submit one.
    #[must_use]
    pub fn replaces(&self, previous: &Self, now_ms: u64) -> bool {
        if self.relay_instance_id != previous.relay_instance_id
            || self.revision.get() <= previous.revision.get()
            || !self.takes_effect_at(now_ms)
            || !previous.accepts_key(self.instance_key, now_ms)
        {
            return false;
        }
        if let Some(successor) = self.successor.0
            && successor.predecessor_retires_at_ms.get() <= now_ms
        {
            return false;
        }
        match previous.successor.0 {
            None => true,
            Some(successor) => {
                if self.instance_key == successor.instance_key {
                    now_ms >= successor.predecessor_retires_at_ms.get()
                } else if now_ms < successor.overlap_from_ms.get() {
                    // Nothing is signing under the successor yet, so the announcement may be
                    // withdrawn or replaced outright.
                    true
                } else {
                    self.successor.0 == Some(successor)
                }
            }
        }
    }

    /// The only key this registration accepts at `now_ms`, or null when it accepts two.
    ///
    /// A registration that accepts one key has handed that key sole authority over the instance.
    /// Which is why [`Self::replaces`] refuses a replacement that would do that to a key other than
    /// the one submitting it.
    #[must_use]
    pub fn sole_accepted_key(&self, now_ms: u64) -> Nullable<RelayInstanceKey> {
        let mut accepted = [self.instance_key, self.instance_key]
            .into_iter()
            .take(1)
            .chain(self.successor.0.map(|successor| successor.instance_key))
            .filter(|key| self.accepts_key(*key, now_ms));
        match (accepted.next(), accepted.next()) {
            (Some(only), None) => Nullable::some(only),
            _ => Nullable::null(),
        }
    }

    /// Returns true when this registration is in force at `now_ms`.
    ///
    /// A registration takes effect when it is recorded, so one that starts in the future would
    /// leave the instance with no accepted key at all between now and then.
    #[must_use]
    pub fn takes_effect_at(&self, now_ms: u64) -> bool {
        self.valid_from_ms.get() <= now_ms && now_ms < self.valid_until_ms.get()
    }

    /// Returns true when `key` is accepted for this instance at `now_ms`.
    ///
    /// Inside the overlap both keys are accepted; after the recorded retirement only the successor
    /// is.
    #[must_use]
    pub fn accepts_key(&self, key: RelayInstanceKey, now_ms: u64) -> bool {
        if now_ms < self.valid_from_ms.get() || now_ms >= self.valid_until_ms.get() {
            return false;
        }
        match self.successor.0 {
            None => key == self.instance_key,
            Some(successor) => {
                let predecessor_live = now_ms < successor.predecessor_retires_at_ms.get();
                let successor_live = now_ms >= successor.overlap_from_ms.get();
                (predecessor_live && key == self.instance_key)
                    || (successor_live && key == successor.instance_key)
            }
        }
    }
}

/// A registration and the instance signature that proves the host holds the key.
///
/// The operator submits this under service-admin authority. The authority says the submission is
/// permitted; the signature says the key being registered is one a relay host actually has, so a
/// mistyped key cannot become the key every later receipt is checked against.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SignedRelayInstanceRegistration {
    /// The registration.
    pub registration: RelayInstanceRegistration,
    /// The Ed25519 signature over `CBOR(["kr-relay/instance/1", registration])`, by the instance
    /// key the registration currently holds.
    pub signature: Signature64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scalars::Uuid;

    fn instance(byte: u8) -> RelayInstanceId {
        RelayInstanceId::new(Uuid::from_bytes([byte; 16]))
    }

    const FRANKFURT: u8 = 0x31;
    const ASHBURN: u8 = 0x32;
    const SINGAPORE: u8 = 0x33;

    fn source() -> EndpointKey {
        EndpointKey::from_bytes([0x21; 32])
    }

    fn destination() -> EndpointKey {
        EndpointKey::from_bytes([0x22; 32])
    }

    /// A two-relay route: in at Frankfurt, out at Ashburn, counted where it enters.
    fn lease() -> RelayLease {
        RelayLease {
            lease_id: RelayLeaseId::new(Uuid::from_bytes([0x10; 16])),
            revision: RelayLeaseRevision::new(1),
            reservation_id: RelayReservationId::new(Uuid::from_bytes([0x11; 16])),
            source_endpoint_key: source(),
            destination_endpoint_key: destination(),
            direction: RelayDirection::Bidirectional,
            payer: PayerPrincipal::Account {
                account_id: AccountId::new("acct_7Qw").expect("account id"),
            },
            payer_authorisation: PayerAuthorisation::HostSelected,
            byte_ceiling: U64::new(4 * 1024 * 1024),
            expires_at_ms: TimestampMs::new(1_800_000_000_000),
            relay_scope: RelayScope {
                ingress_relay_instance_id: instance(FRANKFURT),
                egress_relay_instance_id: instance(ASHBURN),
            },
            metering_relay_instance_id: instance(FRANKFURT),
            metering_role: MeteringRole::Ingress,
            grace: Nullable::null(),
            issuer_key: ServiceAdmissionKey::from_bytes([0x41; 32]),
        }
    }

    fn receipt(sequence: u64, bytes: u64) -> RelayConsumptionReceipt {
        RelayConsumptionReceipt {
            relay_instance_id: instance(FRANKFURT),
            reservation_id: RelayReservationId::new(Uuid::from_bytes([0x11; 16])),
            sequence: RelayReceiptSequence::new(sequence),
            bytes_consumed: U64::new(bytes),
            lease_revision: RelayLeaseRevision::new(1),
            observed_at_ms: TimestampMs::new(1_700_000_000_000),
        }
    }

    #[test]
    fn a_lease_admits_only_the_pair_it_names() {
        let lease = lease();
        let stranger = EndpointKey::from_bytes([0x23; 32]);

        assert!(lease.admits_pair(source(), destination()));
        assert!(lease.admits_pair(destination(), source()));
        assert!(!lease.admits_pair(source(), stranger));
        assert!(!lease.admits_pair(stranger, destination()));
    }

    #[test]
    fn a_one_way_lease_does_not_carry_the_reverse_direction() {
        let mut lease = lease();
        lease.direction = RelayDirection::SourceToDestination;

        assert!(lease.admits_pair(source(), destination()));
        assert!(!lease.admits_pair(destination(), source()));
        assert!(!lease.admits_payload(
            destination(),
            source(),
            instance(ASHBURN),
            instance(FRANKFURT)
        ));
    }

    #[test]
    fn a_payload_must_travel_the_route_the_lease_names() {
        let lease = lease();

        assert!(lease.admits_payload(
            source(),
            destination(),
            instance(FRANKFURT),
            instance(ASHBURN)
        ));
        // The reverse direction swaps the positions with the payload, so the metering instance is
        // still on the route.
        assert!(lease.admits_payload(
            destination(),
            source(),
            instance(ASHBURN),
            instance(FRANKFURT)
        ));
        // A route that never touches Frankfurt is refused, which is what stops a pair from
        // forwarding past the boundary that counts.
        assert!(!lease.admits_payload(
            source(),
            destination(),
            instance(ASHBURN),
            instance(ASHBURN)
        ));
        assert!(!lease.admits_payload(
            source(),
            destination(),
            instance(SINGAPORE),
            instance(ASHBURN)
        ));
        // The right relays in the wrong positions are still the wrong route.
        assert!(!lease.admits_payload(
            source(),
            destination(),
            instance(ASHBURN),
            instance(FRANKFURT)
        ));
    }

    #[test]
    fn a_single_relay_route_names_one_instance_twice() {
        let mut lease = lease();
        lease.relay_scope = RelayScope {
            ingress_relay_instance_id: instance(FRANKFURT),
            egress_relay_instance_id: instance(FRANKFURT),
        };

        assert!(lease.is_well_formed());
        assert!(lease.relay_scope.is_single_relay());
        assert!(lease.admits_payload(
            source(),
            destination(),
            instance(FRANKFURT),
            instance(FRANKFURT)
        ));
        assert!(!lease.admits_payload(
            source(),
            destination(),
            instance(FRANKFURT),
            instance(ASHBURN)
        ));
    }

    #[test]
    fn exactly_one_boundary_of_one_instance_counts_a_payload() {
        let lease = lease();

        assert!(lease.meters_here(instance(FRANKFURT), MeteringRole::Ingress));
        assert!(!lease.meters_here(instance(FRANKFURT), MeteringRole::Egress));
        assert!(!lease.meters_here(instance(ASHBURN), MeteringRole::Ingress));
        assert!(!lease.meters_here(instance(ASHBURN), MeteringRole::Egress));
        assert!(lease.admits_relay(instance(ASHBURN)));
        assert!(!lease.admits_relay(instance(SINGAPORE)));
    }

    #[test]
    fn a_meter_off_the_route_is_malformed() {
        let mut lease = lease();
        assert!(lease.is_well_formed());

        lease.metering_relay_instance_id = instance(SINGAPORE);
        assert!(!lease.is_well_formed());
    }

    #[test]
    fn what_is_outstanding_is_the_ceiling_less_what_has_been_reported() {
        let mut lease = lease();
        lease.byte_ceiling = U64::new(MAX_OUTSTANDING_RESERVED_BYTES);

        assert_eq!(lease.outstanding_bytes(0), MAX_OUTSTANDING_RESERVED_BYTES);
        assert_eq!(
            lease.outstanding_bytes(1024),
            MAX_OUTSTANDING_RESERVED_BYTES - 1024
        );

        // A refill raises the same reservation's cumulative ceiling, so a lease may name a ceiling
        // above the aggregate while holding no more than the aggregate outstanding. A stateless
        // check on the ceiling alone would refuse a lawful refill.
        lease.byte_ceiling = U64::new(MAX_OUTSTANDING_RESERVED_BYTES * 4);
        assert!(lease.is_well_formed());
        assert_eq!(
            lease.outstanding_bytes(MAX_OUTSTANDING_RESERVED_BYTES * 3),
            MAX_OUTSTANDING_RESERVED_BYTES
        );
        assert_eq!(
            lease.outstanding_bytes(MAX_OUTSTANDING_RESERVED_BYTES * 5),
            0
        );
    }

    #[test]
    fn a_grace_beyond_the_section_17_bounds_is_malformed() {
        let mut lease = lease();
        let ceiling = lease.byte_ceiling.get();

        lease.grace = Nullable::some(RelayGrace {
            started_at_ms: TimestampMs::new(1_700_000_000_000),
            ends_at_ms: TimestampMs::new(1_700_000_000_000 + MAX_GRACE_DURATION_MS + 1),
            byte_ceiling: U64::new(ceiling),
        });
        assert!(!lease.is_well_formed());

        lease.grace = Nullable::some(RelayGrace {
            started_at_ms: TimestampMs::new(1_700_000_000_000),
            ends_at_ms: TimestampMs::new(1_700_000_000_000 + MAX_GRACE_DURATION_MS),
            byte_ceiling: U64::new(ceiling + MAX_GRACE_BYTES + 1),
        });
        assert!(!lease.is_well_formed());

        // A grace that lowers the reservation's ceiling is not a grace at all.
        lease.grace = Nullable::some(RelayGrace {
            started_at_ms: TimestampMs::new(1_700_000_000_000),
            ends_at_ms: TimestampMs::new(1_700_000_000_000 + MAX_GRACE_DURATION_MS),
            byte_ceiling: U64::new(ceiling - 1),
        });
        assert!(!lease.is_well_formed());
    }

    #[test]
    fn a_lease_in_grace_raises_the_ceiling_and_stops_at_the_nearer_deadline() {
        let mut lease = lease();
        let now = 1_700_000_000_000;
        let ceiling = lease.byte_ceiling.get();
        lease.expires_at_ms = TimestampMs::new(now + MAX_GRACE_DURATION_MS);
        lease.grace = Nullable::some(RelayGrace {
            started_at_ms: TimestampMs::new(now),
            ends_at_ms: TimestampMs::new(now + MAX_GRACE_DURATION_MS),
            byte_ceiling: U64::new(ceiling + 1024),
        });

        assert!(lease.is_well_formed());
        assert_eq!(lease.effective_byte_ceiling(), ceiling + 1024);
        assert_eq!(lease.bytes_remaining(ceiling), 1024);
        assert_eq!(lease.bytes_remaining(ceiling + 4096), 0);
        assert!(!lease.admits_new_session());
        assert_eq!(
            lease.grace_remaining_ms(now + 1000),
            Nullable::some(U64::new(MAX_GRACE_DURATION_MS - 1000))
        );
        assert!(!lease.is_valid_at(now + MAX_GRACE_DURATION_MS));
    }

    #[test]
    fn a_lease_that_expires_first_advertises_only_the_time_it_will_honour() {
        let mut lease = lease();
        let now = 1_700_000_000_000;
        lease.expires_at_ms = TimestampMs::new(now + 60_000);
        lease.grace = Nullable::some(RelayGrace {
            started_at_ms: TimestampMs::new(now),
            ends_at_ms: TimestampMs::new(now + MAX_GRACE_DURATION_MS),
            byte_ceiling: lease.byte_ceiling,
        });

        assert_eq!(lease.effective_deadline_ms(), now + 60_000);
        assert_eq!(
            lease.grace_remaining_ms(now),
            Nullable::some(U64::new(60_000))
        );
        assert_eq!(
            lease.grace_remaining_ms(now + 120_000),
            Nullable::some(U64::new(0))
        );
    }

    #[test]
    fn a_lease_out_of_grace_shows_no_remaining_interval() {
        let lease = lease();

        assert!(lease.admits_new_session());
        assert_eq!(
            lease.grace_remaining_ms(1_700_000_000_000),
            Nullable::null()
        );
        assert_eq!(lease.effective_byte_ceiling(), 4 * 1024 * 1024);
    }

    #[test]
    fn only_a_higher_revision_of_the_same_lease_replaces_it() {
        let first = lease();
        let mut second = lease();
        second.revision = RelayLeaseRevision::new(2);
        let mut other = lease();
        other.lease_id = RelayLeaseId::new(Uuid::from_bytes([0x12; 16]));
        other.revision = RelayLeaseRevision::new(2);

        assert!(second.supersedes(&first));
        assert!(!first.supersedes(&second));
        assert!(!first.supersedes(&first));
        assert!(!other.supersedes(&first));
    }

    #[test]
    fn a_refill_keeps_the_reservation_and_only_raises_its_ceiling() {
        let first = lease();
        let mut refill = lease();
        refill.revision = RelayLeaseRevision::new(2);
        refill.byte_ceiling = U64::new(first.byte_ceiling.get() + 1024);
        assert!(refill.supersedes(&first));

        let mut shrunk = refill.clone();
        shrunk.byte_ceiling = U64::new(first.byte_ceiling.get() - 1);
        assert!(!shrunk.supersedes(&first));
    }

    #[test]
    fn a_replacement_that_keeps_the_reservation_keeps_what_it_was_priced_against() {
        let first = lease();

        for change in [
            |lease: &mut RelayLease| {
                lease.payer = PayerPrincipal::Installation {
                    installation_id: InstallationId::new(Uuid::from_bytes([0x14; 16])),
                }
            },
            |lease: &mut RelayLease| lease.metering_role = MeteringRole::Egress,
            |lease: &mut RelayLease| {
                lease.metering_relay_instance_id = instance(ASHBURN);
            },
            |lease: &mut RelayLease| {
                lease.destination_endpoint_key = EndpointKey::from_bytes([0x25; 32])
            },
            |lease: &mut RelayLease| {
                lease.relay_scope = RelayScope {
                    ingress_relay_instance_id: instance(ASHBURN),
                    egress_relay_instance_id: instance(FRANKFURT),
                };
            },
        ] {
            let mut changed = lease();
            changed.revision = RelayLeaseRevision::new(2);
            change(&mut changed);
            assert!(
                !changed.supersedes(&first),
                "a changed reservation binding must take a new reservation"
            );

            // With a new reservation the same change is an ordinary new allocation.
            changed.reservation_id = RelayReservationId::new(Uuid::from_bytes([0x15; 16]));
            assert!(changed.supersedes(&first));
        }
    }

    #[test]
    fn a_replacement_cannot_restart_a_grace_that_is_still_running() {
        let now = 1_700_000_000_000;
        let grace = RelayGrace {
            started_at_ms: TimestampMs::new(now),
            ends_at_ms: TimestampMs::new(now + MAX_GRACE_DURATION_MS),
            byte_ceiling: U64::new(4 * 1024 * 1024 + 1024),
        };
        let mut first = lease();
        first.expires_at_ms = TimestampMs::new(now + MAX_GRACE_DURATION_MS);
        first.grace = Nullable::some(grace);

        let mut moved = first.clone();
        moved.revision = RelayLeaseRevision::new(2);
        moved.grace = Nullable::some(RelayGrace {
            started_at_ms: TimestampMs::new(now + 60_000),
            ends_at_ms: TimestampMs::new(now + 60_000 + MAX_GRACE_DURATION_MS),
            ..grace
        });
        assert!(!moved.supersedes(&first), "a grace cannot be restarted");

        let mut extended = first.clone();
        extended.revision = RelayLeaseRevision::new(2);
        extended.grace = Nullable::some(RelayGrace {
            ends_at_ms: TimestampMs::new(now + MAX_GRACE_DURATION_MS + 1),
            ..grace
        });
        assert!(!extended.supersedes(&first), "a grace cannot be extended");

        let mut shortened = first.clone();
        shortened.revision = RelayLeaseRevision::new(2);
        shortened.grace = Nullable::some(RelayGrace {
            ends_at_ms: TimestampMs::new(now + 60_000),
            ..grace
        });
        assert!(shortened.supersedes(&first), "a grace may be cut short");

        // Leaving grace is the allowance being restored, which means a ceiling above what the
        // grace itself permitted. A replacement that drops the grace while restoring nothing is
        // refused, because the revision after it could then open a second window.
        let mut hollow = first.clone();
        hollow.revision = RelayLeaseRevision::new(2);
        hollow.grace = Nullable::null();
        hollow.byte_ceiling = U64::new(grace.byte_ceiling.get());
        assert!(!hollow.supersedes(&first), "nothing was restored");

        let mut restored = hollow.clone();
        restored.byte_ceiling = U64::new(grace.byte_ceiling.get() + 1);
        assert!(restored.supersedes(&first));

        // And the three-revision walk that the hollow step would have opened: out of grace at a
        // ceiling that restores nothing, then into a fresh window.
        let mut second_window = restored.clone();
        second_window.revision = RelayLeaseRevision::new(3);
        second_window.expires_at_ms = TimestampMs::new(now + 2 * MAX_GRACE_DURATION_MS);
        second_window.grace = Nullable::some(RelayGrace {
            started_at_ms: TimestampMs::new(now + MAX_GRACE_DURATION_MS),
            ends_at_ms: TimestampMs::new(now + 2 * MAX_GRACE_DURATION_MS),
            byte_ceiling: U64::new(restored.byte_ceiling.get() + 1024),
        });
        // It is only reachable through a step that restored a real allowance, which is a new
        // exhaustion rather than a continuation of the first one.
        assert!(second_window.supersedes(&restored));
        assert!(!second_window.supersedes(&first));
    }

    #[test]
    fn a_revocation_fences_only_lower_revisions_of_its_own_lease_at_its_own_relay() {
        let lease = lease();
        let revocation = RelayLeaseRevocation {
            lease_id: lease.lease_id,
            revision: RelayLeaseRevision::new(2),
            relay_instance_id: instance(FRANKFURT),
            issued_at_ms: TimestampMs::new(1_700_000_000_000),
            issuer_key: ServiceAdmissionKey::from_bytes([0x41; 32]),
        };

        assert!(revocation.fences(&lease, instance(FRANKFURT)));
        // The same signed bytes replayed at the other relay of the route fence nothing.
        assert!(!revocation.fences(&lease, instance(ASHBURN)));

        let mut later = lease.clone();
        later.revision = RelayLeaseRevision::new(3);
        assert!(!revocation.fences(&later, instance(FRANKFURT)));

        let mut other = lease.clone();
        other.lease_id = RelayLeaseId::new(Uuid::from_bytes([0x12; 16]));
        assert!(!revocation.fences(&other, instance(FRANKFURT)));
    }

    #[test]
    fn receipts_follow_one_another_by_sequence_and_never_report_less() {
        let first = receipt(1, 1024);
        let second = receipt(2, 2048);
        let flat = receipt(2, 1024);
        let shrunk = receipt(2, 512);
        let skipped = receipt(3, 4096);

        assert!(first.is_first());
        assert!(second.follows(&first));
        assert!(flat.follows(&first));
        assert!(!shrunk.follows(&first));
        assert!(!skipped.follows(&first));
        assert!(!first.follows(&second));
    }

    #[test]
    fn the_last_representable_sequence_has_no_successor() {
        let last = receipt(u64::MAX, 4096);
        let wrapped = receipt(0, 8192);

        assert!(!wrapped.follows(&last));
        assert!(!last.is_first());
    }

    #[test]
    fn a_repeat_is_the_same_receipt_and_a_conflict_is_not() {
        let first = receipt(1, 1024);
        let repeat = receipt(1, 1024);
        let conflict = receipt(1, 2048);

        assert!(repeat.repeats(&first));
        assert!(!conflict.repeats(&first));
    }

    #[test]
    fn a_report_is_one_reservation_in_ascending_order() {
        let signature = Signature64::from_bytes([0x51; 64]);
        let signed = |receipt| SignedRelayConsumptionReceipt { receipt, signature };
        let mut report = RelayConsumptionReport {
            relay_instance_id: instance(FRANKFURT),
            reservation_id: RelayReservationId::new(Uuid::from_bytes([0x11; 16])),
            receipts: vec![signed(receipt(1, 1024)), signed(receipt(2, 2048))],
        };
        assert!(report.is_well_formed());
        assert!(report.is_contiguous());

        report.receipts.reverse();
        assert!(!report.is_well_formed());

        report.receipts = vec![signed(receipt(1, 1024)), signed(receipt(1, 1024))];
        assert!(!report.is_well_formed());

        report.receipts = vec![signed(receipt(0, 0))];
        assert!(!report.is_well_formed());

        report.receipts = Vec::new();
        assert!(!report.is_well_formed());
    }

    #[test]
    fn a_batch_with_a_hole_inside_it_is_not_contiguous() {
        let signature = Signature64::from_bytes([0x51; 64]);
        let signed = |receipt| SignedRelayConsumptionReceipt { receipt, signature };
        let report = RelayConsumptionReport {
            relay_instance_id: instance(FRANKFURT),
            reservation_id: RelayReservationId::new(Uuid::from_bytes([0x11; 16])),
            receipts: vec![signed(receipt(1, 1024)), signed(receipt(3, 4096))],
        };

        assert!(report.is_well_formed());
        assert!(!report.is_contiguous());
    }

    #[test]
    fn a_report_whose_receipts_name_another_reservation_is_malformed() {
        let mut stray = receipt(1, 1024);
        stray.reservation_id = RelayReservationId::new(Uuid::from_bytes([0x13; 16]));
        let report = RelayConsumptionReport {
            relay_instance_id: instance(FRANKFURT),
            reservation_id: RelayReservationId::new(Uuid::from_bytes([0x11; 16])),
            receipts: vec![SignedRelayConsumptionReceipt {
                receipt: stray,
                signature: Signature64::from_bytes([0x51; 64]),
            }],
        };

        assert!(!report.is_well_formed());
    }

    fn registration(successor: Nullable<RelayKeySuccession>) -> RelayInstanceRegistration {
        RelayInstanceRegistration {
            relay_instance_id: instance(FRANKFURT),
            revision: RelayRegistrationRevision::new(1),
            instance_key: RelayInstanceKey::from_bytes([0x61; 32]),
            relay_url: NetworkHint::new("https://relay-1.reach.kala.to").expect("a relay URL"),
            region: RelayRegion::new("eu-central").expect("a region"),
            valid_from_ms: TimestampMs::new(1_000),
            valid_until_ms: TimestampMs::new(9_000),
            successor,
        }
    }

    #[test]
    fn a_rotation_accepts_both_keys_only_inside_the_overlap() {
        let old = RelayInstanceKey::from_bytes([0x61; 32]);
        let new = RelayInstanceKey::from_bytes([0x62; 32]);
        let registration = registration(Nullable::some(RelayKeySuccession {
            instance_key: new,
            overlap_from_ms: TimestampMs::new(4_000),
            predecessor_retires_at_ms: TimestampMs::new(6_000),
        }));

        assert!(registration.is_well_formed());
        assert!(!registration.accepts_key(old, 999));
        assert!(registration.accepts_key(old, 1_000));
        assert!(!registration.accepts_key(new, 3_999));
        assert!(registration.accepts_key(new, 4_000));
        assert!(registration.accepts_key(old, 5_999));
        assert!(!registration.accepts_key(old, 6_000));
        assert!(registration.accepts_key(new, 8_999));
        assert!(!registration.accepts_key(new, 9_000));
    }

    #[test]
    fn a_registration_with_no_successor_accepts_only_its_own_key() {
        let registration = registration(Nullable::null());

        assert!(registration.is_well_formed());
        assert!(registration.accepts_key(RelayInstanceKey::from_bytes([0x61; 32]), 5_000));
        assert!(!registration.accepts_key(RelayInstanceKey::from_bytes([0x62; 32]), 5_000));
    }

    #[test]
    fn a_rotation_that_retires_nothing_or_outlives_its_registration_is_malformed() {
        let same_key = registration(Nullable::some(RelayKeySuccession {
            instance_key: RelayInstanceKey::from_bytes([0x61; 32]),
            overlap_from_ms: TimestampMs::new(4_000),
            predecessor_retires_at_ms: TimestampMs::new(6_000),
        }));
        assert!(!same_key.is_well_formed());

        let too_late = registration(Nullable::some(RelayKeySuccession {
            instance_key: RelayInstanceKey::from_bytes([0x62; 32]),
            overlap_from_ms: TimestampMs::new(4_000),
            predecessor_retires_at_ms: TimestampMs::new(9_001),
        }));
        assert!(!too_late.is_well_formed());

        let inverted = registration(Nullable::some(RelayKeySuccession {
            instance_key: RelayInstanceKey::from_bytes([0x62; 32]),
            overlap_from_ms: TimestampMs::new(6_000),
            predecessor_retires_at_ms: TimestampMs::new(4_000),
        }));
        assert!(!inverted.is_well_formed());
    }

    #[test]
    fn a_registration_is_replaced_only_by_a_higher_revision_that_is_in_force() {
        let previous = registration(Nullable::null());
        let mut next = registration(Nullable::null());
        next.revision = RelayRegistrationRevision::new(2);

        assert!(next.replaces(&previous, 5_000));
        assert!(!previous.replaces(&previous, 5_000));
        assert!(!previous.replaces(&next, 5_000));

        // A replay of the registration already replaced cannot undo the replacement.
        assert!(!previous.replaces(&next, 5_000));

        // A registration that has not started, or has ended, leaves no accepted key at all.
        let mut later = next.clone();
        later.valid_from_ms = TimestampMs::new(6_000);
        assert!(!later.replaces(&previous, 5_000));
        assert!(later.replaces(&previous, 6_000));
        assert!(!next.replaces(&previous, 9_000));
    }

    #[test]
    fn only_an_announced_successor_becomes_the_registered_key() {
        let successor = RelayInstanceKey::from_bytes([0x62; 32]);
        let stranger = RelayInstanceKey::from_bytes([0x63; 32]);
        let previous = registration(Nullable::some(RelayKeySuccession {
            instance_key: successor,
            overlap_from_ms: TimestampMs::new(4_000),
            predecessor_retires_at_ms: TimestampMs::new(6_000),
        }));

        let mut promoted = registration(Nullable::null());
        promoted.revision = RelayRegistrationRevision::new(2);
        promoted.instance_key = successor;

        // Inside the overlap the predecessor is still answering for receipts it has signed, so the
        // successor may not install itself early.
        assert!(!promoted.replaces(&previous, 5_000));
        assert!(promoted.replaces(&previous, 6_000));

        // A key nobody announced never becomes the key receipts are checked against.
        let mut imposed = promoted.clone();
        imposed.instance_key = stranger;
        assert!(!imposed.replaces(&previous, 6_000));

        // The registered key may withdraw a rotation before anything starts signing under it, and
        // not afterwards: inside the overlap the successor may already have signed a receipt.
        let mut cancelled = registration(Nullable::null());
        cancelled.revision = RelayRegistrationRevision::new(2);
        assert!(cancelled.replaces(&previous, 3_000));
        assert!(!cancelled.replaces(&previous, 5_000));
    }

    #[test]
    fn a_retired_key_is_never_restored_and_a_live_succession_is_never_dropped() {
        let old = RelayInstanceKey::from_bytes([0x61; 32]);
        let new = RelayInstanceKey::from_bytes([0x62; 32]);
        let announced = registration(Nullable::some(RelayKeySuccession {
            instance_key: new,
            overlap_from_ms: TimestampMs::new(4_000),
            predecessor_retires_at_ms: TimestampMs::new(6_000),
        }));

        // After the retirement the predecessor answers for nothing, so it cannot be put back.
        let mut restored = registration(Nullable::null());
        restored.revision = RelayRegistrationRevision::new(2);
        restored.instance_key = old;
        assert!(!restored.replaces(&announced, 7_000));

        // Inside the overlap the successor may already be signing, so the announcement stands.
        let mut dropped = registration(Nullable::null());
        dropped.revision = RelayRegistrationRevision::new(2);
        assert!(!dropped.replaces(&announced, 5_000));
        // Before it opens, nothing relies on it yet.
        assert!(dropped.replaces(&announced, 3_000));

        // The same announcement may be restated while the overlap runs.
        let mut restated = announced.clone();
        restated.revision = RelayRegistrationRevision::new(2);
        restated.relay_url = NetworkHint::new("https://relay-2.reach.kala.to").expect("a URL");
        assert!(restated.replaces(&announced, 5_000));
    }

    #[test]
    fn a_succession_that_has_already_finished_cannot_be_announced() {
        let previous = registration(Nullable::null());
        let mut sneaked = registration(Nullable::some(RelayKeySuccession {
            instance_key: RelayInstanceKey::from_bytes([0x63; 32]),
            overlap_from_ms: TimestampMs::new(1_500),
            predecessor_retires_at_ms: TimestampMs::new(2_000),
        }));
        sneaked.revision = RelayRegistrationRevision::new(2);

        // It is well formed, and it would hand sole authority to a key that has proved nothing.
        assert!(sneaked.is_well_formed());
        assert_eq!(
            sneaked.sole_accepted_key(5_000),
            Nullable::some(RelayInstanceKey::from_bytes([0x63; 32]))
        );
        assert!(!sneaked.replaces(&previous, 5_000));

        // Announced for the future, the key that submits it keeps answering in the meantime.
        let mut proper = sneaked.clone();
        proper.successor = Nullable::some(RelayKeySuccession {
            instance_key: RelayInstanceKey::from_bytes([0x63; 32]),
            overlap_from_ms: TimestampMs::new(6_000),
            predecessor_retires_at_ms: TimestampMs::new(7_000),
        });
        assert!(proper.replaces(&previous, 5_000));
        assert_eq!(proper.sole_accepted_key(5_000), Nullable::some(old_key()));
    }

    fn old_key() -> RelayInstanceKey {
        RelayInstanceKey::from_bytes([0x61; 32])
    }

    #[test]
    fn each_object_signs_under_its_own_domain() {
        let lease = lease();
        let lease_input = lease.signing_input().expect("a lease signing input");
        let receipt_input = receipt(1, 1024)
            .signing_input()
            .expect("a receipt signing input");

        let domain_of = |input: &[u8], domain: &str| {
            let encoded = kr_cbor::encode(&kr_cbor::CanonicalValue::text(domain));
            input[1..].starts_with(&encoded)
        };

        assert!(domain_of(&lease_input, RELAY_LEASE_DOMAIN));
        assert!(domain_of(&receipt_input, RELAY_RECEIPT_DOMAIN));
        assert!(!domain_of(&receipt_input, RELAY_LEASE_DOMAIN));
    }
}
