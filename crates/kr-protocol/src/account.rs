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

use crate::ids::{
    AccountId, OrganisationId, OrganisationPolicyRevision, PluginId, PolicyKeyRevision,
};
use crate::rights::ActionRight;
use crate::scalars::{
    AuthorisationKey, CanonicalSet, DurationMs, KeyId, Nullable, Signature64, StoredEnvelopeKey,
    TimestampMs, U64,
};

/// The domain a membership lease signature covers.
pub const MEMBERSHIP_LEASE_DOMAIN: &str = "kr-membership-lease/1";

/// The domain one policy-signing authority link covers.
pub const POLICY_AUTHORITY_DOMAIN: &str = "kr-policy-authority/1";

/// The domain the statement of the current revision covers.
pub const POLICY_AUTHORITY_HEAD_DOMAIN: &str = "kr-policy-authority-head/1";

/// The domain one organisation's signed policy covers.
pub const ORGANISATION_POLICY_DOMAIN: &str = "kr-organisation-policy/1";

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

// --- Host policy ------------------------------------------------------------

/// The longest a client version string may be, in bytes.
pub const MAX_CLIENT_VERSION_LEN: usize = 64;

/// The most adapters an allowlist may name.
pub const MAX_ADAPTER_ALLOWLIST: usize = 64;

/// The shortest audit retention an organisation may set, in days.
pub const MIN_AUDIT_RETENTION_DAYS: u64 = 30;

/// The longest audit retention an organisation may set, in days.
pub const MAX_AUDIT_RETENTION_DAYS: u64 = 3_650;

/// The longest grant lifetime an organisation policy may permit, in milliseconds.
///
/// A policy shortens what a host would otherwise allow; it never lengthens it. The bound is here so
/// a policy cannot state a lifetime no host would honour and leave a person believing it applies.
pub const MAX_POLICY_GRANT_LIFETIME_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// A client version, as a policy names the least it accepts.
///
/// Text rather than a triple, because what counts as a version is the release's own name and a
/// policy compares it with what a client reports. It is bounded and restricted to the characters a
/// release name uses, so it cannot carry a control character, a line break or an unbounded string
/// through a signed record.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ClientVersion(String);

/// Text that is not a client version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientVersionError(&'static str);

impl core::fmt::Display for ClientVersionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ClientVersionError {}

impl ClientVersion {
    /// Validates and wraps a version.
    ///
    /// # Errors
    ///
    /// Returns [`ClientVersionError`] naming the rule the text breaks.
    pub fn new(value: impl Into<String>) -> Result<Self, ClientVersionError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ClientVersionError("a client version must not be empty"));
        }
        if value.len() > MAX_CLIENT_VERSION_LEN {
            return Err(ClientVersionError("a client version is at most 64 bytes"));
        }
        if !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+')
        }) {
            return Err(ClientVersionError(
                "a client version is alphanumeric with dots, hyphens and plus signs",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the version text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for ClientVersion {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl core::str::FromStr for ClientVersion {
    type Err = ClientVersionError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl<'de> Deserialize<'de> for ClientVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ClientVersion {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ClientVersion".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::ClientVersion".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_CLIENT_VERSION_LEN,
            "description": "The least client version a policy accepts: alphanumeric with dots, hyphens and plus signs."
        })
    }
}

/// What an organisation permits its members' clients to reach outside KalaReach.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExternalProviderPolicy {
    /// No external provider. Managed and self-hosted paths only.
    Forbidden,
    /// Only the providers the organisation itself configures.
    OrganisationOnly,
    /// Any provider a member configures, including their own credential.
    Any,
}

impl ExternalProviderPolicy {
    /// Every value, from the most restrictive to the least.
    pub const ALL: [Self; 3] = [Self::Forbidden, Self::OrganisationOnly, Self::Any];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Forbidden => "forbidden",
            Self::OrganisationOnly => "organisation_only",
            Self::Any => "any",
        }
    }
}

/// The recipient an organisation's archives are also wrapped for.
///
/// Organisation recovery is optional and never implicit. A policy that carries this names the
/// public key the recipient is, and a host records its own visible enrolment before any archive is
/// wrapped for it: administering billing or membership gives nobody a content key, and an
/// organisation with no named recipient and no enrolment cannot decrypt a personal archive at all.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationRecoveryRecipient {
    /// The recipient's stored-envelope key identifier.
    pub recipient_key_id: KeyId,
    /// The recipient's X25519 public key. Only its public half ever exists in the service.
    pub recipient_key: StoredEnvelopeKey,
    /// A display name for the recipient, so an enrolment can be shown for what it is.
    pub name: String,
    /// When the organisation named it, in UTC milliseconds.
    pub named_at_ms: TimestampMs,
}

/// What an organisation requires of its members' backups.
///
/// The two fields are independent, as section 17 has them. An organisation may require that its
/// members keep managed backups without being able to read one: requiring a backup is a rule about
/// whether an archive exists, and organisation recovery is a recipient an archive is also wrapped
/// for. Recovery applies exactly when a recipient is named, and never by implication.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupPolicy {
    /// Whether a member's host must keep managed backups.
    pub required: bool,
    /// The recipient every archive is also wrapped for, when the organisation names one.
    pub recovery_recipient: Nullable<OrganisationRecoveryRecipient>,
}

/// One revision of an organisation's host policy, and exactly what its signature covers.
///
/// Administrators set what section 17 lets them set: which adapters may run, the least client
/// version they accept, how long a grant may last, what reaches an external provider, what they
/// require of backups, and how long the audit is kept. None of it is a content key, and none of it
/// widens what a host allows: a host intersects a policy with its own rules, so a policy can only
/// narrow them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationPolicyPayload {
    /// The organisation the policy belongs to.
    pub organisation_id: OrganisationId,
    /// The revision this record establishes. A host refuses one below the revision it holds.
    pub policy_revision: OrganisationPolicyRevision,
    /// The adapters members may run, or null for every adapter the host qualifies.
    pub adapter_allowlist: Nullable<CanonicalSet<PluginId>>,
    /// The least client version the organisation accepts, or null for any.
    pub minimum_client_version: Nullable<ClientVersion>,
    /// The longest a grant issued under this organisation may last, or null for the host's own
    /// rule.
    pub maximum_grant_lifetime_ms: Nullable<DurationMs>,
    /// What members' clients may reach outside KalaReach.
    pub external_providers: ExternalProviderPolicy,
    /// What the organisation requires of backups.
    pub backup: BackupPolicy,
    /// How long the organisation keeps its audit events, in days.
    pub audit_retention_days: U64,
    /// When the authority signed it, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// The policy-key revision that signed it.
    pub key_revision: PolicyKeyRevision,
}

/// Why a policy is not one this contract admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// The retention is outside the range an organisation may set.
    #[error("audit retention is between {minimum} and {maximum} days; this policy says {days}")]
    AuditRetention {
        /// The retention the policy stated.
        days: u64,
        /// The shortest permitted.
        minimum: u64,
        /// The longest permitted.
        maximum: u64,
    },
    /// The grant lifetime is zero or longer than a policy may state.
    #[error("a policy grant lifetime is between 1 and {limit} ms; this policy says {lifetime}")]
    GrantLifetime {
        /// The lifetime the policy stated.
        lifetime: u64,
        /// The longest permitted.
        limit: u64,
    },
    /// The allowlist is present and names nothing, which admits no adapter at all.
    #[error("an adapter allowlist names at least one adapter; null permits every adapter")]
    EmptyAllowlist,
    /// The allowlist names more adapters than one may.
    #[error("an adapter allowlist names at most {limit} adapters; this policy names {count}")]
    AllowlistTooLong {
        /// How many the policy named.
        count: usize,
        /// The limit.
        limit: usize,
    },
}

impl OrganisationPolicyPayload {
    /// Builds the canonical bytes a policy signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            ORGANISATION_POLICY_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Every check a policy passes before it is signed or accepted.
    ///
    /// These need neither a signature nor the clock, so both the service that signs a policy and
    /// the host that accepts one make them, and a policy that fails one is refused rather than
    /// narrowed to the part that reads.
    ///
    /// # Errors
    ///
    /// Returns the first rule the policy breaks.
    pub fn check_structure(&self) -> Result<(), PolicyError> {
        let days = self.audit_retention_days.get();
        if !(MIN_AUDIT_RETENTION_DAYS..=MAX_AUDIT_RETENTION_DAYS).contains(&days) {
            return Err(PolicyError::AuditRetention {
                days,
                minimum: MIN_AUDIT_RETENTION_DAYS,
                maximum: MAX_AUDIT_RETENTION_DAYS,
            });
        }

        if let Some(lifetime) = self.maximum_grant_lifetime_ms.as_ref() {
            let value = lifetime.get();
            if value == 0 || value > MAX_POLICY_GRANT_LIFETIME_MS {
                return Err(PolicyError::GrantLifetime {
                    lifetime: value,
                    limit: MAX_POLICY_GRANT_LIFETIME_MS,
                });
            }
        }

        if let Some(adapters) = self.adapter_allowlist.as_ref() {
            if adapters.is_empty() {
                return Err(PolicyError::EmptyAllowlist);
            }
            if adapters.len() > MAX_ADAPTER_ALLOWLIST {
                return Err(PolicyError::AllowlistTooLong {
                    count: adapters.len(),
                    limit: MAX_ADAPTER_ALLOWLIST,
                });
            }
        }

        // Nothing here couples the two backup fields. An organisation that requires backups and
        // names no recipient requires an archive it cannot read, which is the ordinary case;
        // recovery is what naming a recipient establishes, and a host enrols visibly for it.
        Ok(())
    }

    /// Returns true when this revision follows the one a host already holds.
    ///
    /// A host refuses a revision at or below the one it has accepted, so a captured earlier policy
    /// cannot restore permissions the organisation has since withdrawn.
    #[must_use]
    pub const fn follows(&self, accepted: OrganisationPolicyRevision) -> bool {
        self.policy_revision.get() > accepted.get()
    }
}

/// One organisation's host policy, signed by its policy-signing key.
///
/// A host that pinned the organisation's policy-signing authority follows the chain to the revision
/// signing now and checks this signature against it, so what a host applies is the organisation's
/// own statement rather than the service's word about it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrganisationPolicy {
    /// What the organisation states.
    pub payload: OrganisationPolicyPayload,
    /// The policy-signing key's signature over [`OrganisationPolicyPayload::signing_input`].
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
    /// 2. matches the link of the revision it pinned against the pin itself — the same
    ///    organisation, the same revision and the same public key — rather than verifying that
    ///    link's signature, which is the predecessor's at every revision after the first;
    /// 3. verifies each later link under the public key of the revision it names as its
    ///    predecessor, from the pinned revision forward;
    /// 4. verifies the head under the public key of the revision the head names;
    /// 5. requires [`PolicyAuthorityHeadPayload::is_valid_at`] for the current time, because a
    ///    correctly signed head that has expired says nothing about now;
    /// 6. refuses a head below the highest revision it has already accepted, and only then records
    ///    the new highest revision.
    ///
    /// A lease is checked separately, and only against a revision this host has authenticated:
    /// the revision it pinned, or one it reached from the pin by the succession above.
    /// [`PolicyAuthority::authenticated_from`] returns exactly those. A revision *before* the pin
    /// is not one of them — the chain authenticates forward, not backward — so a lease naming one
    /// is refused however well formed the chain around it looks. Then, under that revision's
    /// public key: the lease's signature, its own window, its lifetime, that its ceiling stays
    /// inside its role, and that the revision which signed it was the signing revision when the
    /// lease was issued — its `not_before_ms` is at or before the lease's `issued_at_ms`, and its
    /// successor's, where the chain has one, is after.
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

    /// The links a host may verify anything against, given the revision it pinned.
    ///
    /// A chain authenticates forward: the pinned revision is trusted because the host pinned it,
    /// and every later revision because the one before it signed the link that establishes it.
    /// Nothing authenticates a revision *before* the pin, so a lease or a head naming one is
    /// refused rather than checked against a key the host has no reason to trust.
    ///
    /// Returns `None` when the chain does not carry the pinned revision at all, which is a chain
    /// about some other pin.
    #[must_use]
    pub fn authenticated_from(&self, pinned: PolicyKeyRevision) -> Option<&[PolicyAuthorityLink]> {
        let position = self
            .chain
            .iter()
            .position(|link| link.payload.key_revision == pinned)?;

        Some(&self.chain[position..])
    }

    /// Returns the link that establishes `revision`.
    #[must_use]
    pub fn link(&self, revision: PolicyKeyRevision) -> Option<&PolicyAuthorityLink> {
        self.chain
            .iter()
            .find(|link| link.payload.key_revision == revision)
    }
}
