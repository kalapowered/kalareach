//! Grants, revocation records and the rules that keep both narrow.
//!
//! Section 10 fixes three things this module states as code:
//!
//! * **Delegation narrows.** A child grant can never extend its parent's lifetime, resources or
//!   actions. `Grant::narrows` in `kr-protocol` is that rule; [`issue_grant`] refuses to issue a
//!   grant that fails it.
//! * **A session invitation defaults to view-only for one hour.** The issuer may choose a shorter
//!   duration or extend it to at most 30 days. A personal owner grant is the other case: it
//!   remains valid until revoked, so independent operation does not depend on a cloud lease.
//! * **Only the host issues authority revisions.** A remote owner publishes a signed revocation
//!   *request*, and it carries no revision: a device cannot assign a higher host revision to its
//!   own request. The host validates the request against current owner authority and issues the
//!   ordered record itself.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{self, SigningTranscript};
use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AuthorityRevision, DeviceId, GrantId, RevocationRequestId};
use kr_protocol::pairing::{
    AuthorityRevisionRecord, ProposedGrant, RevocationRequest, RevocationTarget,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, CanonicalSet, Nullable, TimestampMs};

use crate::error::{PairingError, Result};

/// How long a session invitation lasts when the issuer chooses nothing, in milliseconds.
pub const DEFAULT_SESSION_INVITATION_MS: u64 = 60 * 60 * 1000;

/// The longest a session invitation may last, in milliseconds.
pub const MAX_SESSION_INVITATION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// What kind of grant an invitation proposes.
///
/// The two kinds have different rules, and nothing decides between them implicitly: a caller says
/// which it is issuing, and the rules for that kind are checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantKind {
    /// A personal owner grant. It never expires, because independent operation must not depend on
    /// a cloud lease. A host owner may still choose a bounded offline-validity policy separately.
    PersonalOwner,
    /// A session invitation. View-only for an hour unless the issuer says otherwise.
    SessionInvitation,
}

/// Builds the grant a session invitation proposes by default: `session.view` for one hour.
///
/// `duration_ms` shortens or extends it, up to [`MAX_SESSION_INVITATION_MS`].
///
/// # Errors
///
/// Returns [`PairingError::GrantNotPermitted`] when the duration is zero or over the limit.
pub fn session_invitation_grant(
    now_ms: u64,
    duration_ms: u64,
    history: HistoryScope,
) -> Result<ProposedGrant> {
    if duration_ms == 0 {
        return Err(PairingError::GrantNotPermitted {
            reason: "a session invitation lasts at least an instant",
        });
    }
    if duration_ms > MAX_SESSION_INVITATION_MS {
        return Err(PairingError::GrantNotPermitted {
            reason: "a session invitation lasts at most 30 days",
        });
    }
    Ok(ProposedGrant {
        parent_grant_id: Nullable::null(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [ActionRight::SessionView].into_iter().collect(),
        history,
        expiry: GrantExpiry::At {
            expires_at_ms: TimestampMs::new(now_ms.saturating_add(duration_ms)),
        },
        organisation: Nullable::null(),
    })
}

/// Checks a proposal against the rules for its kind.
///
/// # Errors
///
/// Returns [`PairingError::GrantNotPermitted`] naming the rule it broke.
pub fn validate_proposal(proposal: &ProposedGrant, kind: GrantKind, now_ms: u64) -> Result<()> {
    match (kind, proposal.expiry) {
        (GrantKind::PersonalOwner, GrantExpiry::Never) => Ok(()),
        (GrantKind::PersonalOwner, GrantExpiry::At { .. }) => {
            Err(PairingError::GrantNotPermitted {
                reason: "a personal owner grant remains valid until it is revoked",
            })
        }
        (GrantKind::SessionInvitation, GrantExpiry::Never) => {
            Err(PairingError::GrantNotPermitted {
                reason: "a session invitation expires; persistent access needs owner pairing",
            })
        }
        (GrantKind::SessionInvitation, GrantExpiry::At { expires_at_ms }) => {
            let expires = expires_at_ms.get();
            if expires <= now_ms {
                return Err(PairingError::GrantNotPermitted {
                    reason: "a session invitation expires in the future",
                });
            }
            if expires.saturating_sub(now_ms) > MAX_SESSION_INVITATION_MS {
                return Err(PairingError::GrantNotPermitted {
                    reason: "a session invitation lasts at most 30 days",
                });
            }
            Ok(())
        }
    }
}

/// Issues the grant a proposal describes, enforcing the delegation rule.
///
/// `parent` is the grant the issuer is delegating from, when it is delegating. A child that asks
/// for more rights, more resources, more history or a longer life than its parent is refused: the
/// candidate cannot enlarge the grant through its bundle, and neither can the issuer through a
/// delegation.
///
/// # Errors
///
/// Returns [`PairingError::GrantNotPermitted`] when the proposal breaks its kind's rules, names a
/// parent it was not given, or does not narrow the parent it names.
pub fn issue_grant(
    proposal: ProposedGrant,
    kind: GrantKind,
    now_ms: u64,
    identities: &GrantIdentities,
    parent: Option<&Grant>,
) -> Result<Grant> {
    validate_proposal(&proposal, kind, now_ms)?;
    let declared_parent = proposal.parent_grant_id;
    let grant = proposal.into_grant(
        identities.grant_id,
        identities.issuer_device_id,
        identities.recipient_device_id,
        identities.authority_revision,
    );
    match (parent, declared_parent.0) {
        (None, None) => Ok(grant),
        (None, Some(_)) => Err(PairingError::GrantNotPermitted {
            reason: "the proposal names a parent grant the issuer did not supply",
        }),
        (Some(_), None) => Err(PairingError::GrantNotPermitted {
            reason: "a delegated grant names its parent",
        }),
        (Some(parent), Some(named)) => {
            if parent.grant_id != named {
                return Err(PairingError::GrantNotPermitted {
                    reason: "the proposal names a different parent grant",
                });
            }
            if !grant.narrows(parent) {
                return Err(PairingError::GrantNotPermitted {
                    reason: "a delegated grant narrows its parent; it never extends one",
                });
            }
            Ok(grant)
        }
    }
}

/// The identities only the host can assign to a grant.
///
/// They travel together because they are assigned together, in the transition that commits the
/// device record and the grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantIdentities {
    /// The grant's own identity.
    pub grant_id: GrantId,
    /// The device that issued it.
    pub issuer_device_id: DeviceId,
    /// The device it is issued to.
    pub recipient_device_id: DeviceId,
    /// The host authority revision it is issued under.
    pub authority_revision: AuthorityRevision,
}

/// Signs a revocation request a remote owner publishes.
///
/// The request carries no host revision. Only the target host issues ordered revisions, and a
/// device that could name one would be assigning itself a place in the host's order.
///
/// # Errors
///
/// Returns an encoding error, or a library error when libsodium fails.
pub fn sign_revocation_request(
    key: &AuthorisationKeyPair,
    request_id: RevocationRequestId,
    issuer_device_id: DeviceId,
    host_device_id: DeviceId,
    target: RevocationTarget,
    issued_at_ms: TimestampMs,
) -> Result<RevocationRequest> {
    let mut request = RevocationRequest {
        request_id,
        issuer_device_id,
        host_device_id,
        target,
        issued_at_ms,
        issuer_key_id: key.key_id(),
        signature: kr_protocol::scalars::Signature64::from_bytes([0; 64]),
    };
    request.signature = sign::sign(
        key,
        &SigningTranscript::from_canonical_bytes(
            kr_protocol::pairing::REVOCATION_DOMAIN,
            request.signing_input()?,
        )?,
    )?;
    Ok(request)
}

/// Verifies a revocation request against the owner key the host has on record.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`] when the request is addressed to another host or
/// names another key, and [`PairingError::AuthenticationFailed`] when the signature fails.
pub fn verify_revocation_request(
    request: &RevocationRequest,
    host_device_id: DeviceId,
    issuer_key: &AuthorisationKey,
) -> Result<()> {
    if request.host_device_id != host_device_id {
        return Err(PairingError::ContextMismatch {
            what: "the host a revocation request is addressed to",
        });
    }
    if request.issuer_key_id
        != kr_crypto::keys::key_id(
            kr_protocol::pairing::KeyPurpose::Authorisation,
            issuer_key.as_bytes(),
        )
    {
        return Err(PairingError::ContextMismatch {
            what: "the issuer key a revocation request names",
        });
    }
    sign::verify(
        issuer_key,
        &SigningTranscript::from_canonical_bytes(
            kr_protocol::pairing::REVOCATION_DOMAIN,
            request.signing_input()?,
        )?,
        &request.signature,
    )
    .map_err(|_| PairingError::AuthenticationFailed)
}

/// Issues the host's ordered authority revision for a set of applied requests.
///
/// The revision follows the host's latest accepted one. Nothing else can advance it.
///
/// # Errors
///
/// Returns an encoding error, or a library error when libsodium fails.
pub fn issue_authority_revision(
    key: &AuthorisationKeyPair,
    host_device_id: DeviceId,
    previous_revision: AuthorityRevision,
    applied_requests: CanonicalSet<RevocationRequestId>,
    issued_at_ms: TimestampMs,
) -> Result<AuthorityRevisionRecord> {
    let mut record = AuthorityRevisionRecord {
        host_device_id,
        authority_revision: AuthorityRevision::new(previous_revision.get().saturating_add(1)),
        previous_revision,
        applied_requests,
        issued_at_ms,
        host_key_id: key.key_id(),
        signature: kr_protocol::scalars::Signature64::from_bytes([0; 64]),
    };
    record.signature = sign::sign(
        key,
        &SigningTranscript::from_canonical_bytes(
            kr_protocol::pairing::AUTHORITY_REVISION_DOMAIN,
            record.signing_input()?,
        )?,
    )?;
    Ok(record)
}

/// Accepts an authority revision record that follows the revision a host last accepted.
///
/// Each host persists its latest accepted revision and rejects an older one. A record that does
/// not follow it is out of order, whatever its signature says.
///
/// # Errors
///
/// Returns [`PairingError::ContextMismatch`] for a record from another host or out of order, and
/// [`PairingError::AuthenticationFailed`] when the signature fails.
pub fn accept_authority_revision(
    record: &AuthorityRevisionRecord,
    host_device_id: DeviceId,
    host_key: &AuthorisationKey,
    latest_accepted: AuthorityRevision,
) -> Result<AuthorityRevision> {
    if record.host_device_id != host_device_id {
        return Err(PairingError::ContextMismatch {
            what: "the host an authority revision names",
        });
    }
    if record.previous_revision != latest_accepted
        || record.authority_revision.get() != latest_accepted.get().saturating_add(1)
    {
        return Err(PairingError::ContextMismatch {
            what: "the order of an authority revision",
        });
    }
    sign::verify(
        host_key,
        &SigningTranscript::from_canonical_bytes(
            kr_protocol::pairing::AUTHORITY_REVISION_DOMAIN,
            record.signing_input()?,
        )?,
        &record.signature,
    )
    .map_err(|_| PairingError::AuthenticationFailed)?;
    Ok(record.authority_revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_crypto::keys::DeviceKeys;
    use kr_protocol::scalars::Uuid;

    fn history() -> HistoryScope {
        HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        }
    }

    fn device(seed: u8) -> DeviceId {
        DeviceId::new(Uuid::from_bytes([seed; 16]))
    }

    #[test]
    fn a_session_invitation_defaults_to_view_only_for_one_hour() {
        let proposal = session_invitation_grant(1_000, DEFAULT_SESSION_INVITATION_MS, history())
            .expect("a proposal");
        assert_eq!(
            proposal.actions.iter().collect::<Vec<_>>(),
            vec![&ActionRight::SessionView]
        );
        assert_eq!(
            proposal.expiry,
            GrantExpiry::At {
                expires_at_ms: TimestampMs::new(1_000 + DEFAULT_SESSION_INVITATION_MS)
            }
        );
    }

    #[test]
    fn an_invitation_may_be_shortened_but_not_extended_past_thirty_days() {
        assert!(session_invitation_grant(0, 60_000, history()).is_ok());
        assert!(session_invitation_grant(0, MAX_SESSION_INVITATION_MS, history()).is_ok());
        assert!(matches!(
            session_invitation_grant(0, MAX_SESSION_INVITATION_MS + 1, history()),
            Err(PairingError::GrantNotPermitted { .. })
        ));
        assert!(session_invitation_grant(0, 0, history()).is_err());
    }

    #[test]
    fn a_personal_owner_grant_never_expires_and_an_invitation_always_does() {
        let mut personal = session_invitation_grant(0, DEFAULT_SESSION_INVITATION_MS, history())
            .expect("a proposal");
        assert!(matches!(
            validate_proposal(&personal, GrantKind::PersonalOwner, 0),
            Err(PairingError::GrantNotPermitted { .. })
        ));
        personal.expiry = GrantExpiry::Never;
        assert!(validate_proposal(&personal, GrantKind::PersonalOwner, 0).is_ok());
        assert!(matches!(
            validate_proposal(&personal, GrantKind::SessionInvitation, 0),
            Err(PairingError::GrantNotPermitted { .. })
        ));
    }

    #[test]
    fn an_invitation_that_has_already_expired_is_refused() {
        let proposal = session_invitation_grant(0, 1_000, history()).expect("a proposal");
        assert!(validate_proposal(&proposal, GrantKind::SessionInvitation, 999).is_ok());
        assert!(matches!(
            validate_proposal(&proposal, GrantKind::SessionInvitation, 1_000),
            Err(PairingError::GrantNotPermitted { .. })
        ));
    }

    fn identities(grant: u8, issuer: u8, recipient: u8) -> GrantIdentities {
        GrantIdentities {
            grant_id: GrantId::new(Uuid::from_bytes([grant; 16])),
            issuer_device_id: device(issuer),
            recipient_device_id: device(recipient),
            authority_revision: AuthorityRevision::new(3),
        }
    }

    fn issue(proposal: ProposedGrant, parent: Option<&Grant>) -> Result<Grant> {
        issue_grant(
            proposal,
            GrantKind::SessionInvitation,
            0,
            &identities(7, 1, 2),
            parent,
        )
    }

    #[test]
    fn a_delegated_grant_narrows_its_parent() {
        let parent_proposal = session_invitation_grant(0, DEFAULT_SESSION_INVITATION_MS, history())
            .expect("a proposal");
        let parent = issue(parent_proposal, None).expect("a grant");

        let mut child = session_invitation_grant(0, 60_000, history()).expect("a proposal");
        child.parent_grant_id = Nullable::some(parent.grant_id);
        let issued = issue_grant(
            child.clone(),
            GrantKind::SessionInvitation,
            0,
            &identities(8, 2, 3),
            Some(&parent),
        )
        .expect("a narrower grant");
        assert!(issued.narrows(&parent));

        // Asking for longer than the parent is refused.
        let mut longer = child;
        longer.expiry = GrantExpiry::Never;
        assert!(matches!(
            issue_grant(
                longer,
                GrantKind::PersonalOwner,
                0,
                &identities(9, 2, 3),
                Some(&parent),
            ),
            Err(PairingError::GrantNotPermitted { .. })
        ));
    }

    #[test]
    fn a_proposal_that_names_a_parent_without_one_is_refused_and_the_reverse_too() {
        let parent = issue(
            session_invitation_grant(0, DEFAULT_SESSION_INVITATION_MS, history())
                .expect("a proposal"),
            None,
        )
        .expect("a grant");

        let mut orphan = session_invitation_grant(0, 60_000, history()).expect("a proposal");
        orphan.parent_grant_id = Nullable::some(parent.grant_id);
        assert!(matches!(
            issue(orphan, None),
            Err(PairingError::GrantNotPermitted { .. })
        ));

        let rootless = session_invitation_grant(0, 60_000, history()).expect("a proposal");
        assert!(matches!(
            issue(rootless, Some(&parent)),
            Err(PairingError::GrantNotPermitted { .. })
        ));
    }

    #[test]
    fn a_revocation_request_carries_no_host_revision_and_verifies_for_its_host_only() {
        let owner = DeviceKeys::generate().expect("keys");
        let request = sign_revocation_request(
            &owner.authorisation,
            RevocationRequestId::new(Uuid::from_bytes([1; 16])),
            device(1),
            device(2),
            RevocationTarget::Devices {
                device_ids: [device(3)].into_iter().collect(),
            },
            TimestampMs::new(5_000),
        )
        .expect("a request");

        assert!(
            verify_revocation_request(&request, device(2), owner.authorisation.public()).is_ok()
        );
        assert!(matches!(
            verify_revocation_request(&request, device(9), owner.authorisation.public()),
            Err(PairingError::ContextMismatch { .. })
        ));

        let impostor = DeviceKeys::generate().expect("keys");
        assert!(matches!(
            verify_revocation_request(&request, device(2), impostor.authorisation.public()),
            Err(PairingError::ContextMismatch { .. })
        ));

        let mut tampered = request;
        tampered.issued_at_ms = TimestampMs::new(6_000);
        assert!(matches!(
            verify_revocation_request(&tampered, device(2), owner.authorisation.public()),
            Err(PairingError::AuthenticationFailed)
        ));
    }

    #[test]
    fn only_the_host_advances_its_revision_and_only_in_order() {
        let host = DeviceKeys::generate().expect("keys");
        let record = issue_authority_revision(
            &host.authorisation,
            device(2),
            AuthorityRevision::new(4),
            [RevocationRequestId::new(Uuid::from_bytes([1; 16]))]
                .into_iter()
                .collect(),
            TimestampMs::new(6_000),
        )
        .expect("a record");
        assert_eq!(record.authority_revision.get(), 5);

        assert_eq!(
            accept_authority_revision(
                &record,
                device(2),
                host.authorisation.public(),
                AuthorityRevision::new(4),
            )
            .expect("the new revision")
            .get(),
            5
        );

        // A host that has already accepted 5 rejects it as out of order rather than replaying it.
        assert!(matches!(
            accept_authority_revision(
                &record,
                device(2),
                host.authorisation.public(),
                AuthorityRevision::new(5),
            ),
            Err(PairingError::ContextMismatch {
                what: "the order of an authority revision"
            })
        ));

        // A record from another host is refused whatever its order.
        assert!(matches!(
            accept_authority_revision(
                &record,
                device(9),
                host.authorisation.public(),
                AuthorityRevision::new(4),
            ),
            Err(PairingError::ContextMismatch { .. })
        ));

        // A device cannot forge one: the signature is checked against the host's key.
        let device_keys = DeviceKeys::generate().expect("keys");
        assert!(matches!(
            accept_authority_revision(
                &record,
                device(2),
                device_keys.authorisation.public(),
                AuthorityRevision::new(4),
            ),
            Err(PairingError::AuthenticationFailed)
        ));
    }
}
