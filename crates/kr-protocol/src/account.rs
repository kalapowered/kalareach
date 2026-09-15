//! Organisation membership and the policy-signing authority that states it (sections 17, 19, 25).
//!
//! A managed account identifies a person. It never creates host authority, and a host never
//! decrypts anything because somebody signed in. What crosses the boundary is a [`MembershipLease`]:
//! a short-lived signed statement that one account held one role in one organisation, naming the
//! most that role may ever carry. A host intersects that ceiling with its own policy and with the
//! grants the issuer actually holds, so widening a role in the service can never widen a session
//! that is already running.
//!
//! The signature is made by the organisation's policy-signing key, which is separate from billing
//! and rotates on its own schedule. A host pins one revision of that key once, and follows
//! [`PolicyAuthorityLink`]s forward from it: each revision is signed by the revision it names as
//! its predecessor, so the chain proves succession without the service being trusted to assert it.
//! Any prefix of a chain verifies on its own, so [`PolicyAuthorityHead`] is what says the chain is
//! complete: it names the revision signing right now, is signed by that revision, and expires.
//!
//! What the chain proves, and what it does not: a host that has already accepted a later revision
//! refuses a head naming an earlier one, and a head's expiry bounds how long a captured head stays
//! usable. Neither proves that the private key of a retired revision is gone. A host that has never
//! seen the rotation cannot tell a fresh revision-1 head signed by a retained revision-1 key from a
//! legitimate one, so rotation destroys the private half of the revision it retires, and a host
//! that must detect a compromised predecessor needs evidence from somewhere other than this chain.
//!
//! # Lifetimes
//!
//! A lease lasts at most [`MEMBERSHIP_LEASE_MAX_LIFETIME_MS`] and is refreshed every
//! [`MEMBERSHIP_LEASE_REFRESH_INTERVAL_MS`]. Expired membership blocks further
//! organisation-mediated reads and mutations even while the transport stays connected, which is
//! what makes removing somebody from a directory take effect without a host being reachable.
//!
//! # What is signed
//!
//! Three domains, each covering `CBOR([domain, payload])` where the payload is the record without
//! its signature:
//!
//! | Domain | Payload |
//! | --- | --- |
//! | [`MEMBERSHIP_LEASE_DOMAIN`] | [`MembershipLeasePayload`] |
//! | [`POLICY_AUTHORITY_DOMAIN`] | [`PolicyAuthorityLinkPayload`] |
//! | [`POLICY_AUTHORITY_HEAD_DOMAIN`] | [`PolicyAuthorityHeadPayload`] |
//!
//! Every payload is a closed schema and every map is in KR-CBOR-1 key order, so an issuer and a
//! verifier that both build the payload from these types cover identical bytes. `fixtures/accounts`
//! publishes those bytes for both languages.

use kr_cbor::{CborError, signing_value};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{AccountId, OrganisationId, PolicyKeyRevision};
use crate::rights::ActionRight;
use crate::scalars::{AuthorisationKey, CanonicalSet, Nullable, Signature64, TimestampMs};

/// The domain a membership lease signature covers.
pub const MEMBERSHIP_LEASE_DOMAIN: &str = "kr-membership-lease/1";

/// The domain one policy-signing authority link covers.
pub const POLICY_AUTHORITY_DOMAIN: &str = "kr-policy-authority/1";

/// The domain the statement of the current revision covers.
pub const POLICY_AUTHORITY_HEAD_DOMAIN: &str = "kr-policy-authority-head/1";

/// The longest a membership lease may last, in milliseconds (section 17).
pub const MEMBERSHIP_LEASE_MAX_LIFETIME_MS: u64 = 15 * 60 * 1000;

/// How often a holder asks for the next lease, in milliseconds (section 17).
pub const MEMBERSHIP_LEASE_REFRESH_INTERVAL_MS: u64 = 5 * 60 * 1000;

/// The longest a head statement may last, in milliseconds.
///
/// It matches the lease maximum: a host that can still use a lease can still check that the key
/// which signed it is the key signing now.
pub const POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS: u64 = MEMBERSHIP_LEASE_MAX_LIFETIME_MS;

/// An organisation role, from the least to the most authority.
///
/// A role is a label for a grant ceiling. A host authorises from the grants a lease names, never
/// from the label: [`TeamRole::maximum_grants`] is the most a role may ever carry, and a lease may
/// name less.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum TeamRole {
    /// Watch a shared session.
    Viewer,
    /// Watch a shared session and read the diffs and files it selects.
    Reviewer,
    /// Take part in a session: input and answers as well as reading.
    Controller,
    /// Everything a controller may do, plus sharing and closing a session.
    Owner,
}

impl TeamRole {
    /// Every role, from the least to the most authority.
    pub const ALL: &'static [Self] = &[Self::Viewer, Self::Reviewer, Self::Controller, Self::Owner];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Reviewer => "reviewer",
            Self::Controller => "controller",
            Self::Owner => "owner",
        }
    }

    /// The most this role may ever carry.
    ///
    /// Answering a question is inside a viewer's and a reviewer's ceiling because an organisation
    /// may invite one to answer; it is not something either role carries without being asked. The
    /// ceiling is what a grant may reach, not what a role starts with.
    #[must_use]
    pub fn maximum_grants(self) -> CanonicalSet<ActionRight> {
        let rights: &[ActionRight] = match self {
            Self::Viewer => &[ActionRight::SessionView, ActionRight::QuestionRespond],
            Self::Reviewer => &[
                ActionRight::SessionView,
                ActionRight::FilesRead,
                ActionRight::QuestionRespond,
            ],
            Self::Controller => &[
                ActionRight::SessionView,
                ActionRight::FilesRead,
                ActionRight::TerminalInput,
                ActionRight::QuestionRespond,
            ],
            Self::Owner => &[
                ActionRight::SessionView,
                ActionRight::FilesRead,
                ActionRight::TerminalInput,
                ActionRight::QuestionRespond,
                ActionRight::SessionShare,
                ActionRight::SessionClose,
            ],
        };
        rights.iter().copied().collect()
    }
}

impl core::fmt::Display for TeamRole {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// What a membership lease states, and exactly what its signature covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MembershipLeasePayload {
    /// The organisation the lease speaks for.
    pub organisation_id: OrganisationId,
    /// The account it names as a member.
    pub account_id: AccountId,
    /// The role that account held when the lease was signed.
    pub role: TeamRole,
    /// The most the role may carry. A host intersects this with its own policy.
    pub maximum_grants: CanonicalSet<ActionRight>,
    /// When the authority signed it, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// When it stops being usable, at most [`MEMBERSHIP_LEASE_MAX_LIFETIME_MS`] later.
    pub expires_at_ms: TimestampMs,
    /// The policy-key revision that signed it.
    pub key_revision: PolicyKeyRevision,
}

impl MembershipLeasePayload {
    /// Builds the canonical bytes a lease signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            MEMBERSHIP_LEASE_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Returns true when the lease is still usable at `now_ms`.
    #[must_use]
    pub const fn is_valid_at(&self, now_ms: u64) -> bool {
        now_ms >= self.issued_at_ms.get() && now_ms < self.expires_at_ms.get()
    }

    /// Returns true when the lease lasts no longer than section 17 permits.
    #[must_use]
    pub const fn lifetime_within_maximum(&self) -> bool {
        let issued = self.issued_at_ms.get();
        let expires = self.expires_at_ms.get();
        expires > issued && expires - issued <= MEMBERSHIP_LEASE_MAX_LIFETIME_MS
    }

    /// Returns true when the stated ceiling is inside the role's ceiling.
    ///
    /// A lease may name less than the role allows. It may never name more: the label is not what
    /// grants authority, so a lease claiming a right the role does not have is refused rather than
    /// narrowed to the part that fits.
    #[must_use]
    pub fn grants_within_role(&self) -> bool {
        self.maximum_grants.is_subset(&self.role.maximum_grants())
    }
}

/// A signed statement that one account held one role in one organisation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MembershipLease {
    /// What the organisation states.
    pub payload: MembershipLeasePayload,
    /// The policy-signing key's signature over [`MembershipLeasePayload::signing_input`].
    pub signature: Signature64,
}

/// One revision of an organisation's policy-signing key, and exactly what its signature covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityLinkPayload {
    /// The organisation whose chain this link belongs to.
    pub organisation_id: OrganisationId,
    /// The revision this link establishes.
    pub key_revision: PolicyKeyRevision,
    /// The revision whose key signed it, or null at the first revision, which signs itself.
    pub previous_key_revision: Nullable<PolicyKeyRevision>,
    /// The Ed25519 public key of this revision.
    pub public_key: AuthorisationKey,
    /// When this revision took over signing, in UTC milliseconds.
    pub not_before_ms: TimestampMs,
}

impl PolicyAuthorityLinkPayload {
    /// Builds the canonical bytes a link signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            POLICY_AUTHORITY_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// One step in an organisation's policy-signing authority chain.
///
/// The first revision signs itself and names no predecessor, which is what a host pins. Every
/// later revision is signed by the revision it names, so a host that pinned the first can follow
/// the chain to the key signing now, and a link cannot be re-parented under a revision it was not
/// issued against.
///
/// A link carries no expiry, because when a revision stops signing is not known when it is issued.
/// Its successor's `not_before_ms` is when it stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityLink {
    /// What this revision states.
    pub payload: PolicyAuthorityLinkPayload,
    /// The predecessor's signature over [`PolicyAuthorityLinkPayload::signing_input`], or this
    /// revision's own at the first revision.
    pub signature: Signature64,
}

/// Which revision signs right now, and exactly what its signature covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityHeadPayload {
    /// The organisation this statement belongs to.
    pub organisation_id: OrganisationId,
    /// The last revision of the chain, which signs leases now.
    pub key_revision: PolicyKeyRevision,
    /// When the authority made the statement, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// When it stops, at most [`POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS`] later.
    pub expires_at_ms: TimestampMs,
}

impl PolicyAuthorityHeadPayload {
    /// Builds the canonical bytes a head signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            POLICY_AUTHORITY_HEAD_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Returns true when the statement is still current at `now_ms`.
    #[must_use]
    pub const fn is_valid_at(&self, now_ms: u64) -> bool {
        now_ms >= self.issued_at_ms.get() && now_ms < self.expires_at_ms.get()
    }

    /// Returns true when the statement lasts no longer than the maximum.
    #[must_use]
    pub const fn lifetime_within_maximum(&self) -> bool {
        let issued = self.issued_at_ms.get();
        let expires = self.expires_at_ms.get();
        expires > issued && expires - issued <= POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS
    }
}

/// The signed statement of which revision is signing right now.
///
/// It expires, so a captured statement stops being usable, and a host that has accepted a later
/// revision refuses one naming an earlier revision. A retained private key of a retired revision
/// can still sign statements naming that revision, which is why rotation destroys it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthorityHead {
    /// What the authority states.
    pub payload: PolicyAuthorityHeadPayload,
    /// The signature of the revision the statement names, over
    /// [`PolicyAuthorityHeadPayload::signing_input`].
    pub signature: Signature64,
}

/// An organisation's policy-signing authority as it is published.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyAuthority {
    /// The organisation the chain belongs to.
    pub organisation_id: OrganisationId,
    /// Every revision in order, starting at the first.
    pub chain: Vec<PolicyAuthorityLink>,
    /// Which revision signs now, signed by that revision.
    pub head: PolicyAuthorityHead,
}

/// Why a published authority chain is not a chain.
///
/// These are the checks a verifier can make before it touches a signature. A chain that fails one
/// of them is refused: an out-of-order or re-parented chain is never repaired into a plausible one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// The chain carries no revision at all.
    Empty,
    /// A link belongs to a different organisation than the chain.
    ForeignOrganisation {
        /// Which position carries it.
        index: usize,
    },
    /// The first link names a predecessor. The first revision signs itself.
    FirstLinkHasPredecessor,
    /// A later link names no predecessor, or names one that is not the link before it.
    BrokenSuccession {
        /// Which position breaks it.
        index: usize,
    },
    /// Revisions do not ascend by one from the first.
    UnorderedRevisions {
        /// Which position breaks the order.
        index: usize,
    },
    /// A revision takes over before the revision it follows did.
    UnorderedActivation {
        /// Which position breaks the order.
        index: usize,
    },
    /// The head names a revision the chain does not end with.
    HeadRevisionMismatch,
    /// The head was issued before the revision it names took over signing.
    HeadBeforeActivation,
    /// The head belongs to a different organisation than the chain.
    HeadForeignOrganisation,
    /// The head lasts longer than [`POLICY_AUTHORITY_HEAD_MAX_LIFETIME_MS`].
    HeadLifetime,
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("the authority chain is empty"),
            Self::ForeignOrganisation { index } => {
                write!(formatter, "link {index} names another organisation")
            }
            Self::FirstLinkHasPredecessor => {
                formatter.write_str("the first revision names a predecessor")
            }
            Self::BrokenSuccession { index } => {
                write!(formatter, "link {index} does not follow the link before it")
            }
            Self::UnorderedRevisions { index } => {
                write!(formatter, "link {index} is not the next revision")
            }
            Self::UnorderedActivation { index } => {
                write!(formatter, "link {index} takes over before its predecessor")
            }
            Self::HeadRevisionMismatch => {
                formatter.write_str("the head names a revision the chain does not end with")
            }
            Self::HeadBeforeActivation => {
                formatter.write_str("the head was issued before its revision took over")
            }
            Self::HeadForeignOrganisation => {
                formatter.write_str("the head names another organisation")
            }
            Self::HeadLifetime => formatter.write_str("the head lasts longer than the maximum"),
        }
    }
}

impl std::error::Error for ChainError {}

impl PolicyAuthority {
    /// Checks everything about a published chain that needs neither a signature nor the clock.
    ///
    /// It is the first step of accepting a chain, not the whole of it. In order, a verifier:
    ///
    /// 1. runs this check, which is what a complete published chain must satisfy: it starts at the
    ///    revision that signs itself and runs to the revision the head names;
    /// 2. verifies the link of the revision it pinned against the public key it pinned, then each
    ///    later link under the key of the revision it names as its predecessor;
    /// 3. verifies the head under the key of the revision the head names;
    /// 4. requires [`PolicyAuthorityHeadPayload::is_valid_at`] for the current time, because a
    ///    correctly signed head that has expired says nothing about now;
    /// 5. refuses a head below the highest revision it has already accepted, and only then records
    ///    the new highest revision.
    ///
    /// A lease is checked separately, against the key of the revision the lease names: its own
    /// window, its lifetime, and that its ceiling stays inside its role.
    ///
    /// # Errors
    ///
    /// Returns the first structural rule the chain breaks.
    pub fn check_structure(&self) -> Result<(), ChainError> {
        let Some(first) = self.chain.first() else {
            return Err(ChainError::Empty);
        };

        if first.payload.previous_key_revision.is_present() {
            return Err(ChainError::FirstLinkHasPredecessor);
        }

        let base = first.payload.key_revision.get();

        for (index, link) in self.chain.iter().enumerate() {
            if link.payload.organisation_id != self.organisation_id {
                return Err(ChainError::ForeignOrganisation { index });
            }

            let Ok(offset) = u64::try_from(index) else {
                return Err(ChainError::UnorderedRevisions { index });
            };

            let Some(expected) = base.checked_add(offset) else {
                return Err(ChainError::UnorderedRevisions { index });
            };

            if link.payload.key_revision.get() != expected {
                return Err(ChainError::UnorderedRevisions { index });
            }

            if index == 0 {
                continue;
            }

            let previous = &self.chain[index - 1];

            if link
                .payload
                .previous_key_revision
                .as_ref()
                .map(|revision| revision.get())
                != Some(previous.payload.key_revision.get())
            {
                return Err(ChainError::BrokenSuccession { index });
            }

            if link.payload.not_before_ms.get() < previous.payload.not_before_ms.get() {
                return Err(ChainError::UnorderedActivation { index });
            }
        }

        if self.head.payload.organisation_id != self.organisation_id {
            return Err(ChainError::HeadForeignOrganisation);
        }

        let last = self.chain.last().expect("the chain has a first link");

        if self.head.payload.key_revision != last.payload.key_revision {
            return Err(ChainError::HeadRevisionMismatch);
        }

        if self.head.payload.issued_at_ms.get() < last.payload.not_before_ms.get() {
            return Err(ChainError::HeadBeforeActivation);
        }

        if !self.head.payload.lifetime_within_maximum() {
            return Err(ChainError::HeadLifetime);
        }

        Ok(())
    }

    /// Returns the revision that signs leases now.
    #[must_use]
    pub fn current_revision(&self) -> PolicyKeyRevision {
        self.head.payload.key_revision
    }

    /// Returns the link that establishes `revision`.
    #[must_use]
    pub fn link(&self, revision: PolicyKeyRevision) -> Option<&PolicyAuthorityLink> {
        self.chain
            .iter()
            .find(|link| link.payload.key_revision == revision)
    }
}
