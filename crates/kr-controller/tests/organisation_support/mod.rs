//! An organisation's policy-signing authority as the managed service holds it, for the host's
//! tests: real keys, a chain whose every link is signed by the revision before it, heads, and
//! leases signed for one device's authorisation key.
//!
//! Each suite that includes this module uses some of it, not all.
#![allow(dead_code)]

use kr_controller::grants::HostPolicy;
use kr_controller::grants::organisation::LeasePresentation;
use kr_controller::service::net::devices::ObservedUtc;
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::SigningTranscript;
use kr_protocol::account::{
    MEMBERSHIP_LEASE_DOMAIN, MEMBERSHIP_LEASE_MAX_LIFETIME_MS, MembershipLease,
    MembershipLeasePayload, POLICY_AUTHORITY_DOMAIN, POLICY_AUTHORITY_HEAD_DOMAIN,
    POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS, PolicyAuthority, PolicyAuthorityHead,
    PolicyAuthorityHeadPayload, PolicyAuthorityLink, PolicyAuthorityLinkPayload, TeamRole,
};
use kr_protocol::ids::{AccountId, ControllerGeneration, OrganisationId, PolicyKeyRevision};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, Nullable, Signature64, TimestampMs, Uuid};
use kr_transport::clock::ContinuousInstant;

/// The moment the tests' clocks start from: 2026-01-01T00:00:00Z, in UTC milliseconds.
pub const T: u64 = 1_767_225_600_000;

/// A minute, in milliseconds.
pub const MINUTE_MS: u64 = 60 * 1000;

/// The longest a lease lasts.
pub const LEASE_MS: u64 = MEMBERSHIP_LEASE_MAX_LIFETIME_MS;

/// An organisation's policy-signing authority, with the private half of every revision.
pub struct Organisation {
    /// The organisation.
    pub organisation_id: OrganisationId,
    keys: Vec<AuthorisationKeyPair>,
    /// Every revision's link, in order from the first.
    pub chain: Vec<PolicyAuthorityLink>,
}

impl Organisation {
    /// An organisation named by `byte`, whose first revision takes over at `first_ms`.
    #[must_use]
    pub fn new(byte: u8, first_ms: u64) -> Self {
        let organisation_id = OrganisationId::new(Uuid::from_bytes([byte; 16]));
        let key = AuthorisationKeyPair::generate().expect("a policy-signing key");
        let payload = PolicyAuthorityLinkPayload {
            organisation_id,
            key_revision: PolicyKeyRevision::new(1),
            previous_key_revision: Nullable::null(),
            public_key: *key.public(),
            not_before_ms: TimestampMs::new(first_ms),
        };
        let link = PolicyAuthorityLink {
            signature: sign(&key, POLICY_AUTHORITY_DOMAIN, payload.signing_input()),
            payload,
        };
        Self {
            organisation_id,
            keys: vec![key],
            chain: vec![link],
        }
    }

    /// Rotates to the next revision, which takes over at `not_before_ms`; the current revision
    /// signs its link. Returns the new revision.
    pub fn rotate(&mut self, not_before_ms: u64) -> u64 {
        let previous = self.current();
        let key = AuthorisationKeyPair::generate().expect("a policy-signing key");
        let payload = PolicyAuthorityLinkPayload {
            organisation_id: self.organisation_id,
            key_revision: PolicyKeyRevision::new(previous + 1),
            previous_key_revision: Nullable::some(PolicyKeyRevision::new(previous)),
            public_key: *key.public(),
            not_before_ms: TimestampMs::new(not_before_ms),
        };
        let link = PolicyAuthorityLink {
            signature: sign(
                self.key(previous),
                POLICY_AUTHORITY_DOMAIN,
                payload.signing_input(),
            ),
            payload,
        };
        self.keys.push(key);
        self.chain.push(link);
        previous + 1
    }

    /// The newest revision.
    #[must_use]
    pub fn current(&self) -> u64 {
        u64::try_from(self.keys.len()).expect("a small chain")
    }

    /// The private half of `revision`.
    #[must_use]
    pub fn key(&self, revision: u64) -> &AuthorisationKeyPair {
        &self.keys[usize::try_from(revision - 1).expect("a small chain")]
    }

    /// The link of `revision`.
    #[must_use]
    pub fn link(&self, revision: u64) -> &PolicyAuthorityLink {
        &self.chain[usize::try_from(revision - 1).expect("a small chain")]
    }

    /// A head naming `revision`, signed by it, issued at `issued_ms` for the longest a head lasts.
    #[must_use]
    pub fn head(&self, revision: u64, issued_ms: u64) -> PolicyAuthorityHead {
        let payload = PolicyAuthorityHeadPayload {
            organisation_id: self.organisation_id,
            key_revision: PolicyKeyRevision::new(revision),
            issued_at_ms: TimestampMs::new(issued_ms),
            expires_at_ms: TimestampMs::new(issued_ms + POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS),
        };
        PolicyAuthorityHead {
            signature: sign(
                self.key(revision),
                POLICY_AUTHORITY_HEAD_DOMAIN,
                payload.signing_input(),
            ),
            payload,
        }
    }

    /// The published authority as it stood when `revision` was the newest: every link up to it
    /// and a head by it issued at `issued_ms`.
    #[must_use]
    pub fn authority_at(&self, revision: u64, issued_ms: u64) -> PolicyAuthority {
        PolicyAuthority {
            organisation_id: self.organisation_id,
            chain: self.chain[..usize::try_from(revision).expect("a small chain")].to_vec(),
            head: self.head(revision, issued_ms),
        }
    }

    /// The published authority now: the whole chain and a head by the newest revision.
    #[must_use]
    pub fn authority(&self, issued_ms: u64) -> PolicyAuthority {
        self.authority_at(self.current(), issued_ms)
    }

    /// A payload for `account` on the device holding `device_key`, signed by `revision`, issued at
    /// `issued_ms` and lasting `lifetime_ms`, carrying `rights` under the owner role.
    #[must_use]
    pub fn payload(
        &self,
        revision: u64,
        account: &AccountId,
        device_key: AuthorisationKey,
        issued_ms: u64,
        lifetime_ms: u64,
        rights: &[ActionRight],
    ) -> MembershipLeasePayload {
        MembershipLeasePayload {
            organisation_id: self.organisation_id,
            account_id: account.clone(),
            device_key,
            role: TeamRole::Owner,
            maximum_grants: rights.iter().copied().collect(),
            issued_at_ms: TimestampMs::new(issued_ms),
            expires_at_ms: TimestampMs::new(issued_ms + lifetime_ms),
            key_revision: PolicyKeyRevision::new(revision),
        }
    }

    /// A fifteen-minute lease, signed by `revision`, for `account` on the device holding
    /// `device_key`.
    #[must_use]
    pub fn lease(
        &self,
        revision: u64,
        account: &AccountId,
        device_key: AuthorisationKey,
        issued_ms: u64,
        rights: &[ActionRight],
    ) -> MembershipLease {
        self.sign(
            revision,
            self.payload(revision, account, device_key, issued_ms, LEASE_MS, rights),
        )
    }

    /// Signs `payload`, whatever it says, with `revision`'s key.
    #[must_use]
    pub fn sign(&self, revision: u64, payload: MembershipLeasePayload) -> MembershipLease {
        MembershipLease {
            signature: sign(
                self.key(revision),
                MEMBERSHIP_LEASE_DOMAIN,
                payload.signing_input(),
            ),
            payload,
        }
    }

    /// Enrols `policy` in this organisation from the authority published at `at_ms`.
    pub fn enrol(&self, policy: &mut HostPolicy, at_ms: u64) {
        let verified = policy
            .verify_enrolment(&self.authority(at_ms), Some(&reading(at_ms)))
            .expect("the published chain verifies");
        policy.enrol(verified).expect("the host enrols");
    }
}

/// Signs a signing input under `domain` with `key`.
pub fn sign(
    key: &AuthorisationKeyPair,
    domain: &str,
    signing_input: Result<Vec<u8>, kr_cbor::CborError>,
) -> Signature64 {
    let transcript =
        SigningTranscript::from_canonical_bytes(domain, signing_input.expect("a signing input"))
            .expect("a transcript");
    kr_crypto::sign::sign(key, &transcript).expect("a signature")
}

/// A device's authorisation keypair.
#[must_use]
pub fn device() -> AuthorisationKeyPair {
    AuthorisationKeyPair::generate().expect("a device key")
}

/// This host's reading of UTC at `ms`, as its clock trust gives it while it trusts the clock.
#[must_use]
pub const fn reading(ms: u64) -> ObservedUtc {
    ObservedUtc {
        now: TimestampMs::new(ms),
        behind_ms: 0,
    }
}

/// A member account.
#[must_use]
pub fn member(name: &str) -> AccountId {
    AccountId::new(name).expect("an account identifier")
}

/// The controller generation `n`.
#[must_use]
pub const fn generation(n: u64) -> ControllerGeneration {
    ControllerGeneration::new(n)
}

/// `lease`, presented by a connection that proved `proven_key`, with UTC read at `utc_ms` and the
/// continuous clock at `now`, in controller generation `run`.
#[must_use]
pub fn presented<'a>(
    lease: &'a MembershipLease,
    proven_key: &'a AuthorisationKey,
    utc_ms: u64,
    now: ContinuousInstant,
    run: u64,
) -> LeasePresentation<'a> {
    LeasePresentation {
        lease,
        proven_key,
        reading: Some(reading(utc_ms)),
        now,
        generation: generation(run),
    }
}
