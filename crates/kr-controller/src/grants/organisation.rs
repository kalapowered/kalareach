//! An organisation this host is enrolled in: the policy-signing chain it pinned, the rotations it
//! followed, and the membership leases it verified against them.
//!
//! Section 17 lets a host opt into an organisation's policy by pinning that organisation's
//! policy-signing authority, and section 25 has the service keep a signed rotation chain for the
//! authority. A host pins keys, not numbers. It verifies the whole published chain once, when the
//! owner enrols it, and keeps the link of the revision signing then as its anchor. From then on it
//! follows a rotation only through links the anchor's own key signed, and the keys those links
//! establish: a chain that does not carry the anchor byte for byte is about some other pin and is
//! refused, so a leaked retired key cannot re-authorise a fork.
//!
//! A lease is honoured only when every one of these holds, checked in this order:
//!
//! 1. the host is enrolled in the lease's organisation;
//! 2. the lease names a revision this host authenticated that way, and verifies under its key;
//! 3. it names the authorisation key of the device presenting it, so a host that receives a
//!    member's lease cannot pass it to a device it controls;
//! 4. the revision that signed it was the signing revision when it was issued;
//! 5. it is inside its own rules: at most fifteen minutes long, and inside its role's ceiling;
//! 6. it is inside its window on this host's clock, which must be trusted, and not issued more than
//!    five seconds in this host's future;
//! 7. it names the account and key the presenting device is bound to, or, when the device is bound
//!    to nobody in that organisation, it binds the device to its account and key;
//! 8. it is newer than every lease this host has installed for that member and device: a lease
//!    digest is installed at most once on a host, whatever either clock says, so an expired lease
//!    presented again never revives, not after a restart and not after a new enrolment.
//!
//! The binding is what a grant's recipient is resolved through at every ingress: a grant that
//! requires an organisation answers to the lease of the account and key its recipient device is
//! bound to, and to no other.

use std::collections::BTreeMap;
use std::time::Duration;

use kr_crypto::sign::SigningTranscript;
use kr_protocol::account::{
    ChainError, MEMBERSHIP_LEASE_DOMAIN, MEMBERSHIP_LEASE_MAX_LIFETIME_MS, MembershipLease,
    POLICY_AUTHORITY_DOMAIN, POLICY_AUTHORITY_HEAD_DOMAIN, PolicyAuthority, PolicyAuthorityHead,
    PolicyAuthorityLink,
};
use kr_protocol::ids::{
    AccountId, AuthorityRevision, ControllerGeneration, DeviceId, OrganisationId, PolicyKeyRevision,
};
use kr_protocol::scalars::{AuthorisationKey, Digest256, Signature64};
use kr_transport::clock::ContinuousInstant;

use super::durable::{StoredBinding, StoredEnrolment, StoredLeaseRecord};
use crate::service::net::devices::ObservedUtc;

/// How far this host's clock may be behind a lease's issue time, and how much earlier than its
/// signed expiry a lease ends on the continuous clock, in milliseconds.
///
/// The same five seconds this host's clock trust tolerates before it distrusts a step back
/// ([`crate::service::net::devices::CLOCK_TOLERANCE_MS`]). The subtraction is conservative early
/// expiry and nothing more: it bounds nothing about slew or steps, and a UTC deadline that arrives
/// first still ends the lease.
pub const LEASE_CLOCK_MARGIN_MS: u64 = crate::service::net::devices::CLOCK_TOLERANCE_MS;

/// Why a published policy-signing chain was not pinned or not followed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainRefused {
    /// The host is not enrolled in the chain's organisation.
    NotEnrolled,
    /// The host is already enrolled in that organisation; withdraw first.
    AlreadyEnrolled,
    /// A rule the chain breaks before any signature is looked at.
    Structure(ChainError),
    /// The chain does not carry the link this host anchored at, byte for byte.
    AnchorMissing,
    /// A link does not verify under the key it must: the first link under its own, every later
    /// one under its predecessor's.
    LinkSignature {
        /// The revision the link establishes.
        revision: PolicyKeyRevision,
    },
    /// The head does not verify under the key of the revision it names.
    HeadSignature,
    /// The head is not valid at this host's reading of the clock.
    HeadNotCurrent,
    /// This host's clock went backwards and has not been established again.
    ClockUntrusted,
    /// The clock floor this decision would stand on is owed its record.
    FloorUnrecorded,
}

impl core::fmt::Display for ChainRefused {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotEnrolled => {
                formatter.write_str("this host is not enrolled in that organisation")
            }
            Self::AlreadyEnrolled => formatter
                .write_str("this host is already enrolled in that organisation; withdraw first"),
            Self::Structure(error) => {
                write!(formatter, "the authority chain is malformed: {error}")
            }
            Self::AnchorMissing => formatter.write_str(
                "the authority chain does not carry the revision this host is anchored at",
            ),
            Self::LinkSignature { revision } => write!(
                formatter,
                "the link of revision {} is not signed by the revision before it",
                revision.get()
            ),
            Self::HeadSignature => {
                formatter.write_str("the head is not signed by the revision it names")
            }
            Self::HeadNotCurrent => formatter.write_str("the head is not current"),
            Self::ClockUntrusted => formatter
                .write_str("this host's clock went backwards and has not been established again"),
            Self::FloorUnrecorded => formatter.write_str(super::FLOOR_UNRECORDED),
        }
    }
}

/// Why a membership lease was not installed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseRefused {
    /// This host is not enrolled in the lease's organisation.
    NotEnrolled,
    /// The presenting device holds no live grant on this host that requires that organisation.
    NoOrganisationGrant,
    /// The lease names a revision this host has not authenticated from its anchor.
    UnauthenticatedRevision,
    /// The signature is not the named revision's over the lease's signing input.
    BadSignature,
    /// The lease names another device's key than the one the presenting connection proved.
    DeviceMismatch,
    /// The lease was issued before the revision that signed it took over.
    IssuedBeforeActivation,
    /// The lease was issued after the revision that signed it was succeeded.
    SignedAfterSuccessor,
    /// The lease lasts longer than the fifteen minutes section 17 permits.
    TooLong,
    /// The lease grants more than its own role's ceiling.
    AboveRoleCeiling,
    /// This host's clock went backwards and has not been established again.
    ClockUntrusted,
    /// The clock floor this decision would stand on is owed its record.
    FloorUnrecorded,
    /// The lease was issued more than five seconds in this host's future.
    NotYetValid,
    /// The lease has ended, on either clock.
    ///
    /// A caller answers this only once the floor on disk covers the moment the lease ended, as
    /// every refusal the clock decided is answered: before that, the clock floor is owed its
    /// record and the answer is [`Self::FloorUnrecorded`].
    Expired,
    /// This host installed this lease in an earlier run; the member's client fetches a new one.
    InstalledEarlier,
    /// A lease with the same issue time and another digest is already recorded.
    AmbiguousIssue,
    /// A newer lease for that member and device is already recorded.
    Superseded,
    /// The presenting device is bound to another member account in that organisation.
    AccountMismatch,
}

impl LeaseRefused {
    /// The sentence a presenting device is told.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        match self {
            Self::NotEnrolled => "this host is not enrolled in that organisation",
            Self::NoOrganisationGrant => {
                "this device holds no grant on this host that requires that organisation"
            }
            Self::UnauthenticatedRevision => {
                "the lease names a policy-signing revision this host has not authenticated"
            }
            Self::BadSignature => "the lease is not signed by the revision it names",
            Self::DeviceMismatch => "the lease is for another device",
            Self::IssuedBeforeActivation => {
                "the lease was issued before its signing revision took over"
            }
            Self::SignedAfterSuccessor => {
                "the lease was issued after its signing revision was succeeded"
            }
            Self::TooLong => "the lease lasts longer than fifteen minutes",
            Self::AboveRoleCeiling => "the lease grants more than its role allows",
            Self::ClockUntrusted => {
                "this host's clock went backwards and has not been established again"
            }
            Self::FloorUnrecorded => super::FLOOR_UNRECORDED,
            Self::NotYetValid => "the lease was issued in this host's future",
            Self::Expired => "the lease has expired",
            Self::InstalledEarlier => {
                "this host installed that lease before it restarted; fetch a new lease"
            }
            Self::AmbiguousIssue => "another lease with the same issue time is already recorded",
            Self::Superseded => "a newer lease for this device is already recorded",
            Self::AccountMismatch => "this device is bound to another member of that organisation",
        }
    }
}

/// A lease this host installed, and when it ends on the continuous clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledLease {
    lease: MembershipLease,
    digest: Digest256,
    continuous_deadline: ContinuousInstant,
}

impl InstalledLease {
    /// The lease as it was presented.
    #[must_use]
    pub const fn lease(&self) -> &MembershipLease {
        &self.lease
    }

    /// The SHA-256 digest of its signing input.
    #[must_use]
    pub const fn digest(&self) -> Digest256 {
        self.digest
    }

    /// When it ends on the continuous clock.
    #[must_use]
    pub const fn continuous_deadline(&self) -> ContinuousInstant {
        self.continuous_deadline
    }

    /// Whether it is in force at both readings: before its continuous deadline, and before its
    /// signed expiry on UTC.
    ///
    /// Its issue time is not asked again. Installation accepted it up to five seconds in this
    /// host's future ([`LEASE_CLOCK_MARGIN_MS`]), so a lease is in force from the moment it is
    /// installed, not from the moment this host's clock reaches its issue time.
    #[must_use]
    pub fn in_force(&self, now: ContinuousInstant, utc_ms: u64) -> bool {
        now < self.continuous_deadline && self.unexpired_at(utc_ms)
    }

    /// Whether its signed expiry is still ahead of `utc_ms`.
    #[must_use]
    pub fn unexpired_at(&self, utc_ms: u64) -> bool {
        utc_ms < self.lease.payload.expires_at_ms.get()
    }

    /// Its two deadlines, as a decision under it carries them.
    #[must_use]
    pub fn bound(&self) -> LeaseBound {
        LeaseBound {
            continuous_deadline: self.continuous_deadline,
            expires_at_ms: self.lease.payload.expires_at_ms.get(),
        }
    }
}

/// The two deadlines of the lease a decision was taken under: when it ends on the continuous
/// clock, and its signed expiry on UTC. A decision holds only while both are ahead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseBound {
    /// When the lease ends on the continuous clock.
    pub continuous_deadline: ContinuousInstant,
    /// Its signed expiry, in UTC milliseconds.
    pub expires_at_ms: u64,
}

/// One device bound to a member account, by the first verified lease it presented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    /// The member account.
    pub account_id: AccountId,
    /// The authorisation key the binding lease named and the presenting connection proved.
    pub device_key: AuthorisationKey,
    /// When this host bound it, in UTC milliseconds.
    pub bound_at_ms: u64,
    /// The SHA-256 digest of the lease that bound it.
    pub lease_digest: Digest256,
}

/// Why a device's lease does not answer for a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberLease {
    /// The device is bound to no member account in that organisation.
    Unbound,
    /// It is bound, and this host holds no lease for its account and key.
    NoLease,
    /// Its lease has ended on either clock.
    Expired,
}

/// The newest lease this host installed for one member's device, and the run that installed it.
///
/// It is written before the lease it names is installed, and it moves only to later issue times,
/// so a lease with a later issue time than its record has never been installed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseRecord {
    /// When the recorded lease was issued, in UTC milliseconds.
    pub issued_at_ms: u64,
    /// When it expires, in UTC milliseconds.
    pub expires_at_ms: u64,
    /// The SHA-256 digest of its signing input.
    pub digest: Digest256,
    /// The controller generation that installed it.
    pub installed_in: ControllerGeneration,
}

/// Who a lease record is for: one member account on one device.
pub type LeaseHolder = (OrganisationId, AccountId, AuthorisationKey);

/// An enrolment verified against its whole published chain.
///
/// Only [`verify_enrolment`] builds one, so a host cannot store an enrolment it did not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEnrolment {
    organisation_id: OrganisationId,
    root: PolicyAuthorityLink,
    anchor: PolicyAuthorityLink,
}

impl VerifiedEnrolment {
    /// The organisation.
    #[must_use]
    pub const fn organisation_id(&self) -> OrganisationId {
        self.organisation_id
    }

    /// The first revision's link: the organisation's identity.
    #[must_use]
    pub const fn root(&self) -> &PolicyAuthorityLink {
        &self.root
    }

    /// The link of the revision the head named: what rotation is followed from.
    #[must_use]
    pub const fn anchor(&self) -> &PolicyAuthorityLink {
        &self.anchor
    }
}

/// Verifies a whole published chain for a new enrolment, at `settled_ms`, this host's reading of
/// UTC through its floor.
///
/// Before anything is shown or stored: the chain's structure; the first link under its own key;
/// every later link under its predecessor's key; the head under the last link's key, current at
/// `settled_ms` (the head's lifetime is part of the structure).
///
/// # Errors
///
/// Returns the first rule the chain breaks.
pub fn verify_enrolment(
    authority: &PolicyAuthority,
    settled_ms: u64,
) -> Result<VerifiedEnrolment, ChainRefused> {
    authority
        .check_structure()
        .map_err(ChainRefused::Structure)?;
    let root = authority
        .chain
        .first()
        .ok_or(ChainRefused::Structure(ChainError::Empty))?;
    if !link_verifies(root, &root.payload.public_key) {
        return Err(ChainRefused::LinkSignature {
            revision: root.payload.key_revision,
        });
    }
    let anchor = follow(&authority.chain)?;
    head_holds(&authority.head, anchor, settled_ms)?;
    Ok(VerifiedEnrolment {
        organisation_id: authority.organisation_id,
        root: root.clone(),
        anchor: anchor.clone(),
    })
}

/// Verifies every link after the first under its predecessor's key, and returns the last.
fn follow(links: &[PolicyAuthorityLink]) -> Result<&PolicyAuthorityLink, ChainRefused> {
    for pair in links.windows(2) {
        let (previous, next) = (&pair[0], &pair[1]);
        if !link_verifies(next, &previous.payload.public_key) {
            return Err(ChainRefused::LinkSignature {
                revision: next.payload.key_revision,
            });
        }
    }
    links
        .last()
        .ok_or(ChainRefused::Structure(ChainError::Empty))
}

/// Checks the head against the last link: signed by that revision and current at `settled_ms`.
fn head_holds(
    head: &PolicyAuthorityHead,
    last: &PolicyAuthorityLink,
    settled_ms: u64,
) -> Result<(), ChainRefused> {
    let signed = head.payload.signing_input().ok().is_some_and(|input| {
        verifies(
            POLICY_AUTHORITY_HEAD_DOMAIN,
            input,
            &last.payload.public_key,
            &head.signature,
        )
    });
    if !signed {
        return Err(ChainRefused::HeadSignature);
    }
    if !head.payload.is_valid_at(settled_ms) {
        return Err(ChainRefused::HeadNotCurrent);
    }
    Ok(())
}

fn link_verifies(link: &PolicyAuthorityLink, key: &AuthorisationKey) -> bool {
    link.payload
        .signing_input()
        .ok()
        .is_some_and(|input| verifies(POLICY_AUTHORITY_DOMAIN, input, key, &link.signature))
}

/// Verifies an Ed25519 signature over exactly `signing_input`, which must be the transcript of
/// `domain`.
fn verifies(
    domain: &str,
    signing_input: Vec<u8>,
    key: &AuthorisationKey,
    signature: &Signature64,
) -> bool {
    SigningTranscript::from_canonical_bytes(domain, signing_input)
        .and_then(|transcript| kr_crypto::sign::verify(key, &transcript, signature))
        .is_ok()
}

/// What accepting a published chain came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainOutcome {
    /// The chain names the head this host already accepted: nothing was checked or changed.
    Unchanged,
    /// The chain names an older head than this host accepted. It changes nothing, and a lease
    /// presented beside it is judged against this host's own links.
    Stale {
        /// The highest head revision this host holds.
        held: PolicyKeyRevision,
    },
    /// The chain moved this host's anchor forward.
    Advanced {
        /// The revision the anchor moved to.
        to: PolicyKeyRevision,
        /// The installed leases the new links show were signed after their revision was
        /// succeeded, now dropped. Dropping a live one is a restriction the caller fences.
        dropped: Vec<(AccountId, AuthorisationKey)>,
    },
}

/// One organisation this host is enrolled in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolment {
    root: PolicyAuthorityLink,
    /// The links this host authenticated and keeps, oldest first. The last is the anchor. An
    /// older one stays only while a lease it signed can still be live.
    links: Vec<PolicyAuthorityLink>,
    accepted_head: PolicyKeyRevision,
    enrolment_revision: AuthorityRevision,
    /// The devices bound to member accounts, each by the first verified lease it presented.
    members: BTreeMap<DeviceId, Binding>,
    /// The leases installed now, one per member account and device key. Private: only
    /// [`install`] adds one.
    installed: BTreeMap<(AccountId, AuthorisationKey), InstalledLease>,
}

impl Enrolment {
    /// A new enrolment from a verified chain, at the host authority revision in force.
    pub(crate) fn new(verified: VerifiedEnrolment, enrolment_revision: AuthorityRevision) -> Self {
        Self {
            accepted_head: verified.anchor.payload.key_revision,
            links: vec![verified.anchor],
            root: verified.root,
            enrolment_revision,
            members: BTreeMap::new(),
            installed: BTreeMap::new(),
        }
    }

    /// The enrolment as it was written down, with no lease installed.
    pub(crate) fn restore(stored: &StoredEnrolment) -> Self {
        Self {
            root: stored.root.clone(),
            links: stored.links.clone(),
            accepted_head: stored.accepted_head,
            enrolment_revision: stored.enrolment_revision,
            members: stored
                .members
                .iter()
                .map(|binding| {
                    (
                        binding.device_id,
                        Binding {
                            account_id: binding.account_id.clone(),
                            device_key: binding.device_key,
                            bound_at_ms: binding.bound_at_ms.get(),
                            lease_digest: binding.lease_digest,
                        },
                    )
                })
                .collect(),
            installed: BTreeMap::new(),
        }
    }

    /// The enrolment as it is written down. Installed leases are not: a restarted host holds none.
    pub(crate) fn stored(&self, organisation_id: OrganisationId) -> StoredEnrolment {
        StoredEnrolment {
            organisation_id,
            root: self.root.clone(),
            links: self.links.clone(),
            accepted_head: self.accepted_head,
            enrolment_revision: self.enrolment_revision,
            members: self
                .members
                .iter()
                .map(|(device_id, binding)| StoredBinding {
                    device_id: *device_id,
                    account_id: binding.account_id.clone(),
                    device_key: binding.device_key,
                    bound_at_ms: kr_protocol::scalars::TimestampMs::new(binding.bound_at_ms),
                    lease_digest: binding.lease_digest,
                })
                .collect(),
        }
    }

    /// The member account and key `device_id` is bound to in this organisation.
    #[must_use]
    pub fn binding(&self, device_id: DeviceId) -> Option<&Binding> {
        self.members.get(&device_id)
    }

    /// The lease in force for the member `device_id` is bound to, at both readings.
    ///
    /// # Errors
    ///
    /// Why there is none: the device is bound to nobody here, it holds no lease, or its lease has
    /// ended on either clock.
    pub fn lease_for_device(
        &self,
        device_id: DeviceId,
        now: ContinuousInstant,
        utc_ms: u64,
    ) -> Result<&InstalledLease, MemberLease> {
        let binding = self.members.get(&device_id).ok_or(MemberLease::Unbound)?;
        let installed = self
            .installed(&binding.account_id, &binding.device_key)
            .ok_or(MemberLease::NoLease)?;
        if installed.in_force(now, utc_ms) {
            Ok(installed)
        } else {
            Err(MemberLease::Expired)
        }
    }

    /// Removes `device_id`'s binding: the device was revoked. Returns whether it was bound.
    pub(crate) fn unbind(&mut self, device_id: DeviceId) -> bool {
        self.members.remove(&device_id).is_some()
    }

    /// The first revision's link: the organisation's identity.
    #[must_use]
    pub const fn root(&self) -> &PolicyAuthorityLink {
        &self.root
    }

    /// The link rotation is followed from.
    #[must_use]
    pub fn anchor(&self) -> &PolicyAuthorityLink {
        self.links.last().unwrap_or(&self.root)
    }

    /// The links this host authenticated and keeps, oldest first.
    #[must_use]
    pub fn links(&self) -> &[PolicyAuthorityLink] {
        &self.links
    }

    /// The highest head revision this host has accepted.
    #[must_use]
    pub const fn accepted_head(&self) -> PolicyKeyRevision {
        self.accepted_head
    }

    /// The host authority revision in force when this host enrolled. An organisation grant's
    /// requirement names it.
    #[must_use]
    pub const fn enrolment_revision(&self) -> AuthorityRevision {
        self.enrolment_revision
    }

    /// The lease installed for one member's device, whether or not it is still in force.
    #[must_use]
    pub fn installed(
        &self,
        account_id: &AccountId,
        device_key: &AuthorisationKey,
    ) -> Option<&InstalledLease> {
        self.installed.get(&(account_id.clone(), *device_key))
    }

    /// Every lease installed for one member account, on any device.
    pub fn installed_for<'a>(
        &'a self,
        account_id: &'a AccountId,
    ) -> impl Iterator<Item = &'a InstalledLease> + 'a {
        self.installed
            .iter()
            .filter(move |((account, _), _)| account == account_id)
            .map(|(_, installed)| installed)
    }

    /// Follows a published chain forward from this enrolment's anchor, at `settled_ms`.
    ///
    /// A head above the accepted one is accepted only when the chain carries the anchor byte for
    /// byte, every link after it verifies under its predecessor's key, and the head verifies under
    /// the last link's key and is current. Then the new links are appended, the anchor moves to
    /// the last, and every installed lease is judged again: one whose revision's successor took
    /// over at or before its issue time is dropped. Links a live lease can no longer need are let
    /// go. A head equal to the accepted one does no signature work; a lower one is stale.
    ///
    /// # Errors
    ///
    /// Returns the rule a newer head's chain breaks. Nothing changes then.
    pub(crate) fn accept(
        &mut self,
        authority: &PolicyAuthority,
        settled_ms: u64,
    ) -> Result<ChainOutcome, ChainRefused> {
        let head = authority.head.payload.key_revision;
        match head.get().cmp(&self.accepted_head.get()) {
            core::cmp::Ordering::Equal => return Ok(ChainOutcome::Unchanged),
            core::cmp::Ordering::Less => {
                return Ok(ChainOutcome::Stale {
                    held: self.accepted_head,
                });
            }
            core::cmp::Ordering::Greater => {}
        }
        authority
            .check_structure()
            .map_err(ChainRefused::Structure)?;
        let anchor = self.anchor().clone();
        let from = authority
            .authenticated_from(anchor.payload.key_revision)
            .ok_or(ChainRefused::AnchorMissing)?;
        if from.first() != Some(&anchor) {
            return Err(ChainRefused::AnchorMissing);
        }
        let last = follow(from)?;
        head_holds(&authority.head, last, settled_ms)?;

        self.links.extend(from.iter().skip(1).cloned());
        self.accepted_head = head;
        let dropped = self.drop_leases_signed_after_succession();
        self.let_go_of_spent_links(settled_ms);
        Ok(ChainOutcome::Advanced { to: head, dropped })
    }

    /// Drops every installed lease whose signing revision's successor took over at or before the
    /// lease's issue time: only a key that outlived its rotation could have signed it.
    fn drop_leases_signed_after_succession(&mut self) -> Vec<(AccountId, AuthorisationKey)> {
        let links = &self.links;
        let signed_after = |installed: &InstalledLease| {
            let payload = &installed.lease.payload;
            links
                .iter()
                .position(|link| link.payload.key_revision == payload.key_revision)
                .and_then(|position| links.get(position + 1))
                .is_some_and(|successor| {
                    successor.payload.not_before_ms.get() <= payload.issued_at_ms.get()
                })
        };
        let dropped: Vec<_> = self
            .installed
            .iter()
            .filter(|(_, installed)| signed_after(installed))
            .map(|(holder, _)| holder.clone())
            .collect();
        for holder in &dropped {
            self.installed.remove(holder);
        }
        dropped
    }

    /// Lets go of links older than the anchor once their successor has been signing for longer
    /// than any lease they signed can last, with the clock margin: nothing live can need them.
    fn let_go_of_spent_links(&mut self, settled_ms: u64) {
        let spent = MEMBERSHIP_LEASE_MAX_LIFETIME_MS + LEASE_CLOCK_MARGIN_MS;
        while self.links.len() > 1
            && self.links[1]
                .payload
                .not_before_ms
                .get()
                .saturating_add(spent)
                <= settled_ms
        {
            self.links.remove(0);
        }
    }

    /// Checks a lease against this enrolment's links and the presenting connection's key: the
    /// named revision is authenticated, the signature is its key's, the lease is for this device,
    /// and the revision was signing when the lease was issued.
    fn authenticate(
        &self,
        lease: &MembershipLease,
        signing_input: Vec<u8>,
        proven_key: &AuthorisationKey,
    ) -> Result<(), LeaseRefused> {
        let payload = &lease.payload;
        let position = self
            .links
            .iter()
            .position(|link| link.payload.key_revision == payload.key_revision)
            .ok_or(LeaseRefused::UnauthenticatedRevision)?;
        let link = &self.links[position];
        if !verifies(
            MEMBERSHIP_LEASE_DOMAIN,
            signing_input,
            &link.payload.public_key,
            &lease.signature,
        ) {
            return Err(LeaseRefused::BadSignature);
        }
        if payload.device_key != *proven_key {
            return Err(LeaseRefused::DeviceMismatch);
        }
        if link.payload.not_before_ms.get() > payload.issued_at_ms.get() {
            return Err(LeaseRefused::IssuedBeforeActivation);
        }
        if self.links.get(position + 1).is_some_and(|successor| {
            successor.payload.not_before_ms.get() <= payload.issued_at_ms.get()
        }) {
            return Err(LeaseRefused::SignedAfterSuccessor);
        }
        Ok(())
    }
}

/// A lease presented to this host, with what the presenting connection and this host's clocks
/// say at that moment.
#[derive(Clone, Copy, Debug)]
pub struct LeasePresentation<'a> {
    /// The lease, typed as it arrived.
    pub lease: &'a MembershipLease,
    /// The device presenting it: the paired device of the connection, or this host's own device
    /// for its local owner.
    pub device_id: DeviceId,
    /// The authorisation key the presenting connection proved.
    pub proven_key: &'a AuthorisationKey,
    /// This host's reading of UTC, which exists only while its clock is trusted.
    pub reading: Option<ObservedUtc>,
    /// The continuous clock now.
    pub now: ContinuousInstant,
    /// The controller generation deciding it.
    pub generation: ControllerGeneration,
}

/// A lease this host installed, or answered from its installation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseInstalled {
    /// The organisation.
    pub organisation_id: OrganisationId,
    /// The member account.
    pub account_id: AccountId,
    /// The revision that signed it.
    pub key_revision: PolicyKeyRevision,
    /// When it expires, in UTC milliseconds.
    pub expires_at_ms: u64,
    /// When it ends on the continuous clock.
    pub continuous_deadline: ContinuousInstant,
    /// What the presentation changed.
    pub change: LeaseChange,
    /// Whether it bound the presenting device to the lease's account and key, which the caller
    /// writes down with a retained event.
    pub bound: bool,
}

/// What presenting a lease changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseChange {
    /// The lease already installed in this run, presented again: its deadline does not move, and
    /// nothing is written unless it binds the presenting device.
    Repeat,
    /// A lease newer than any this host installed for that member and device. Its record is new
    /// and is written before the lease is installed.
    Installed {
        /// Whether it replaced a live lease whose signed statement was wider: fewer rights, or an
        /// earlier signed expiry. That is a restriction, which the caller fences.
        narrowed: bool,
    },
}

/// This host's reading of UTC for one lease, as its clock trust and its floor decide it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeaseTime {
    /// The clock went backwards and has not been established again.
    Untrusted,
    /// The clock floor a decision would stand on is owed its record.
    Unrecorded,
    /// The reading through the floor, and whether the lease's signed expiry has passed at it.
    At {
        /// The later of the clock and the floor, in UTC milliseconds.
        settled_ms: u64,
        /// Whether the signed expiry is at or before it.
        expired: bool,
    },
}

/// Decides a presented lease against `enrolment` and the lease records, at `time`, and installs
/// it when it is new.
///
/// The signature, device, activation, rule and time checks come first, in the order the module
/// states; then the record (a lease digest is installed at most once) and the deadline.
///
/// # Errors
///
/// Returns the first rule the lease breaks. Nothing is installed or recorded then.
pub(crate) fn install(
    enrolment: &mut Enrolment,
    records: &mut BTreeMap<LeaseHolder, LeaseRecord>,
    presentation: LeasePresentation<'_>,
    time: LeaseTime,
) -> Result<LeaseInstalled, LeaseRefused> {
    let lease = presentation.lease;
    let payload = &lease.payload;
    let signing_input = payload
        .signing_input()
        .map_err(|_| LeaseRefused::BadSignature)?;
    let digest = Digest256::from_bytes(kr_cbor::sha256(&signing_input));
    enrolment.authenticate(lease, signing_input, presentation.proven_key)?;
    if !payload.lifetime_within_maximum() {
        return Err(LeaseRefused::TooLong);
    }
    if !payload.grants_within_role() {
        return Err(LeaseRefused::AboveRoleCeiling);
    }
    let (settled_ms, expired) = match time {
        LeaseTime::Untrusted => return Err(LeaseRefused::ClockUntrusted),
        LeaseTime::Unrecorded => return Err(LeaseRefused::FloorUnrecorded),
        LeaseTime::At {
            settled_ms,
            expired,
        } => (settled_ms, expired),
    };
    if payload.issued_at_ms.get() > settled_ms.saturating_add(LEASE_CLOCK_MARGIN_MS) {
        return Err(LeaseRefused::NotYetValid);
    }
    if expired {
        return Err(LeaseRefused::Expired);
    }
    // The binding: a device bound in this organisation presents only for the account and key it
    // is bound to; one bound to nobody binds on this lease, once the lease is installed.
    let binds = match enrolment.members.get(&presentation.device_id) {
        Some(binding) if binding.account_id != payload.account_id => {
            return Err(LeaseRefused::AccountMismatch);
        }
        Some(binding) if binding.device_key != payload.device_key => {
            return Err(LeaseRefused::DeviceMismatch);
        }
        Some(_) => false,
        None => true,
    };

    let holder: LeaseHolder = (
        payload.organisation_id,
        payload.account_id.clone(),
        payload.device_key,
    );
    let issued_at_ms = payload.issued_at_ms.get();
    let installed_key = (payload.account_id.clone(), payload.device_key);
    if let Some(record) = records.get(&holder) {
        match issued_at_ms.cmp(&record.issued_at_ms) {
            core::cmp::Ordering::Less => return Err(LeaseRefused::Superseded),
            core::cmp::Ordering::Equal if digest != record.digest => {
                return Err(LeaseRefused::AmbiguousIssue);
            }
            core::cmp::Ordering::Equal => {
                // The record's own lease. In the run that installed it, it is answered from that
                // installation while it lasts; once it has ended, or in any later run, it is
                // never installed again, whatever either clock says.
                if record.installed_in != presentation.generation {
                    return Err(LeaseRefused::InstalledEarlier);
                }
                return match enrolment.installed.get(&installed_key) {
                    Some(installed)
                        if installed.digest == digest
                            && installed.in_force(presentation.now, settled_ms) =>
                    {
                        let continuous_deadline = installed.continuous_deadline;
                        if binds {
                            bind(enrolment, &presentation, settled_ms, digest);
                        }
                        Ok(LeaseInstalled {
                            organisation_id: payload.organisation_id,
                            account_id: payload.account_id.clone(),
                            key_revision: payload.key_revision,
                            expires_at_ms: payload.expires_at_ms.get(),
                            continuous_deadline,
                            change: LeaseChange::Repeat,
                            bound: binds,
                        })
                    }
                    _ => Err(LeaseRefused::Expired),
                };
            }
            core::cmp::Ordering::Greater => {}
        }
    }

    // What is left of the lease on the continuous clock, measured from the later of now and its
    // issue time, never more than the maximum, less the margin.
    let left_ms = payload
        .expires_at_ms
        .get()
        .saturating_sub(settled_ms.max(issued_at_ms))
        .min(MEMBERSHIP_LEASE_MAX_LIFETIME_MS)
        .saturating_sub(LEASE_CLOCK_MARGIN_MS);
    if left_ms == 0 {
        return Err(LeaseRefused::Expired);
    }
    let own_deadline = presentation
        .now
        .checked_add(Duration::from_millis(left_ms))
        .ok_or(LeaseRefused::Expired)?;
    // A renewal of a live lease keeps the later deadline unless its signed statement narrows: the
    // derived deadlines are never compared, only what the organisation signed.
    let live = enrolment
        .installed
        .get(&installed_key)
        .filter(|installed| installed.in_force(presentation.now, settled_ms));
    let narrowed = live.is_some_and(|installed| {
        let before = &installed.lease.payload;
        !before.maximum_grants.is_subset(&payload.maximum_grants)
            || payload.expires_at_ms.get() < before.expires_at_ms.get()
    });
    let continuous_deadline = match live {
        Some(installed) if !narrowed => own_deadline.max(installed.continuous_deadline),
        _ => own_deadline,
    };

    records.insert(
        holder,
        LeaseRecord {
            issued_at_ms,
            expires_at_ms: payload.expires_at_ms.get(),
            digest,
            installed_in: presentation.generation,
        },
    );
    enrolment.installed.insert(
        installed_key,
        InstalledLease {
            lease: lease.clone(),
            digest,
            continuous_deadline,
        },
    );
    if binds {
        bind(enrolment, &presentation, settled_ms, digest);
    }
    Ok(LeaseInstalled {
        organisation_id: payload.organisation_id,
        account_id: payload.account_id.clone(),
        key_revision: payload.key_revision,
        expires_at_ms: payload.expires_at_ms.get(),
        continuous_deadline,
        change: LeaseChange::Installed { narrowed },
        bound: binds,
    })
}

/// Binds the presenting device to the account and key its verified lease names.
fn bind(
    enrolment: &mut Enrolment,
    presentation: &LeasePresentation<'_>,
    bound_at_ms: u64,
    lease_digest: Digest256,
) {
    let payload = &presentation.lease.payload;
    enrolment.members.insert(
        presentation.device_id,
        Binding {
            account_id: payload.account_id.clone(),
            device_key: payload.device_key,
            bound_at_ms,
            lease_digest,
        },
    );
}

/// The lease records as they are written down, keeping only those a lease could still need: a
/// record is let go of only in the write that also records a UTC floor past its issue time plus
/// the longest lease, by which time every lease ever installed for it has expired.
pub(crate) fn stored_records(
    records: &BTreeMap<LeaseHolder, LeaseRecord>,
    floor_ms: u64,
) -> Vec<StoredLeaseRecord> {
    records
        .iter()
        .filter(|(_, record)| {
            record
                .issued_at_ms
                .saturating_add(MEMBERSHIP_LEASE_MAX_LIFETIME_MS)
                >= floor_ms
        })
        .map(
            |((organisation_id, account_id, device_key), record)| StoredLeaseRecord {
                organisation_id: *organisation_id,
                account_id: account_id.clone(),
                device_key: *device_key,
                issued_at_ms: kr_protocol::scalars::TimestampMs::new(record.issued_at_ms),
                expires_at_ms: kr_protocol::scalars::TimestampMs::new(record.expires_at_ms),
                digest: record.digest,
                installed_in: record.installed_in,
            },
        )
        .collect()
}

/// The lease records as they were written down.
pub(crate) fn restored_records(stored: &[StoredLeaseRecord]) -> BTreeMap<LeaseHolder, LeaseRecord> {
    stored
        .iter()
        .map(|record| {
            (
                (
                    record.organisation_id,
                    record.account_id.clone(),
                    record.device_key,
                ),
                LeaseRecord {
                    issued_at_ms: record.issued_at_ms.get(),
                    expires_at_ms: record.expires_at_ms.get(),
                    digest: record.digest,
                    installed_in: record.installed_in,
                },
            )
        })
        .collect()
}

/// An organisation's policy-signing authority with one revision, for this crate's own tests.
#[cfg(test)]
pub(crate) mod testing {
    use kr_crypto::keys::AuthorisationKeyPair;
    use kr_crypto::sign::SigningTranscript;
    use kr_protocol::account::{
        MEMBERSHIP_LEASE_DOMAIN, MEMBERSHIP_LEASE_MAX_LIFETIME_MS, MembershipLease,
        MembershipLeasePayload, POLICY_AUTHORITY_DOMAIN, POLICY_AUTHORITY_HEAD_DOMAIN,
        POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS, PolicyAuthority, PolicyAuthorityHead,
        PolicyAuthorityHeadPayload, PolicyAuthorityLink, PolicyAuthorityLinkPayload, TeamRole,
    };
    use kr_protocol::ids::{AccountId, OrganisationId, PolicyKeyRevision};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{AuthorisationKey, Nullable, Signature64, TimestampMs, Uuid};

    /// An organisation whose one revision takes over at the moment it is made for.
    pub(crate) struct TestOrganisation {
        /// The organisation.
        pub(crate) organisation_id: OrganisationId,
        key: AuthorisationKeyPair,
        link: PolicyAuthorityLink,
    }

    impl TestOrganisation {
        /// An organisation named by `byte`, whose revision takes over at `not_before_ms`.
        pub(crate) fn new(byte: u8, not_before_ms: u64) -> Self {
            let organisation_id = OrganisationId::new(Uuid::from_bytes([byte; 16]));
            let key = AuthorisationKeyPair::generate().expect("a policy-signing key");
            let payload = PolicyAuthorityLinkPayload {
                organisation_id,
                key_revision: PolicyKeyRevision::new(1),
                previous_key_revision: Nullable::null(),
                public_key: *key.public(),
                not_before_ms: TimestampMs::new(not_before_ms),
            };
            let link = PolicyAuthorityLink {
                signature: sign(&key, POLICY_AUTHORITY_DOMAIN, payload.signing_input()),
                payload,
            };
            Self {
                organisation_id,
                key,
                link,
            }
        }

        /// The published authority, with a head issued at `issued_ms`.
        pub(crate) fn authority(&self, issued_ms: u64) -> PolicyAuthority {
            let payload = PolicyAuthorityHeadPayload {
                organisation_id: self.organisation_id,
                key_revision: PolicyKeyRevision::new(1),
                issued_at_ms: TimestampMs::new(issued_ms),
                expires_at_ms: TimestampMs::new(issued_ms + POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS),
            };
            PolicyAuthority {
                organisation_id: self.organisation_id,
                chain: vec![self.link.clone()],
                head: PolicyAuthorityHead {
                    signature: sign(
                        &self.key,
                        POLICY_AUTHORITY_HEAD_DOMAIN,
                        payload.signing_input(),
                    ),
                    payload,
                },
            }
        }

        /// A fifteen-minute lease for `account` on the device holding `device_key`, issued at
        /// `issued_ms` under the owner role.
        pub(crate) fn lease(
            &self,
            account: &AccountId,
            device_key: AuthorisationKey,
            issued_ms: u64,
            rights: &[ActionRight],
        ) -> MembershipLease {
            let payload = MembershipLeasePayload {
                organisation_id: self.organisation_id,
                account_id: account.clone(),
                device_key,
                role: TeamRole::Owner,
                maximum_grants: rights.iter().copied().collect(),
                issued_at_ms: TimestampMs::new(issued_ms),
                expires_at_ms: TimestampMs::new(issued_ms + MEMBERSHIP_LEASE_MAX_LIFETIME_MS),
                key_revision: PolicyKeyRevision::new(1),
            };
            MembershipLease {
                signature: sign(&self.key, MEMBERSHIP_LEASE_DOMAIN, payload.signing_input()),
                payload,
            }
        }
    }

    fn sign(
        key: &AuthorisationKeyPair,
        domain: &str,
        signing_input: Result<Vec<u8>, kr_cbor::CborError>,
    ) -> Signature64 {
        let transcript = SigningTranscript::from_canonical_bytes(
            domain,
            signing_input.expect("a signing input"),
        )
        .expect("a transcript");
        kr_crypto::sign::sign(key, &transcript).expect("a signature")
    }
}
