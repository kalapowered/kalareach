//! Grants: the authority every request is decided against.
//!
//! Section 10 puts four separate things in this module, and keeping them separate is what makes
//! each one checkable:
//!
//! * **The record.** A grant names its issuer, its recipient, the authority revision it was issued
//!   under, the environments and sessions it covers, the actions it permits, how far back it may
//!   see, when it stops and which organisation membership it requires.
//!   [`kr_protocol::grant::Grant`] is that record; [`store`] is where the host keeps it, with the
//!   parent link that makes revocation cascade.
//! * **The intersection.** "The host intersects the grant with current policy on every request."
//!   [`decide`] is that intersection, and it is one function rather than a rule repeated at each
//!   call site. It reads the method registry's own required-rights column, so a method added to
//!   section 23 is decided by the table rather than by a `match` somebody forgot to extend.
//! * **The policy.** [`policy`] holds what is true of the host rather than of one grant: the
//!   revision in force, the organisation leases this host holds, the pinned policy revisions, and
//!   the optional bounded offline-validity policy an owner may choose for personal remote access.
//! * **The vocabulary.** [`vocabulary`] is the method-to-right mapping of section 23, read out of
//!   [`kr_protocol::method::REGISTRY`] rather than restated here, so there is one table.
//! * **The feed.** [`feed`] is this host's half of the remote authority feed: the ordered
//!   revisions only this host issues, the revocation records it retains until every enrolled host
//!   has acknowledged them, and the synchronisation it owes before it serves remote work again.
//!
//! # What this module will not do
//!
//! * It will not authorise from a role. A role compiles to actions when a grant is written
//!   ([`crate::sharing`]); nothing here can see a role, because the record does not carry one.
//! * It will not treat a capability as authority. A capability says a binding could do something.
//!   Whether it may is this module's question and nothing else's.
//! * It will not silently downgrade. An expired or revoked grant refuses the request. It does not
//!   quietly serve a read instead, because "continued reads still require valid authority" and a
//!   narrower grant is something the person has to choose.

pub mod feed;
pub mod policy;
pub mod store;
pub mod vocabulary;

use kr_protocol::authority::{AuthorityDecision, RequiredAuthority, RightCondition};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::Grant;
use kr_protocol::ids::{AuthorityRevision, EnvironmentId, GrantId, SessionId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::CanonicalSet;
use kr_protocol::sharing::MembershipRefusal;

pub use feed::{AuthorityFeed, FeedRefusal, RetainedRevocation};
pub use policy::{HostPolicy, PolicyIntersection};
pub use store::{GrantDirectory, GrantRecord, GrantRevocation};
pub use vocabulary::{rights_for, unconditional_rights_for};

/// One request, as the intersection sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessRequest {
    /// The method being called.
    pub method: Method,
    /// The ingress class the caller reached this host through.
    pub ingress: kr_protocol::actor::ActorIngress,
    /// The environment the request names.
    pub environment_id: EnvironmentId,
    /// The session it names, when it names one.
    pub session_id: Option<SessionId>,
    /// Whether the request claims or adds a geometry claim.
    pub claims_geometry: bool,
    /// Whether the subject belongs to the verified actor itself, when the host has resolved it.
    ///
    /// `None` means the host has not resolved the subject here, which is the ordinary case at the
    /// daemon's boundary: the conditional requirements keyed to it are then left to the subject,
    /// which answers them inside its own dispatch barrier where the subject cannot move.
    pub own_subject: Option<bool>,
    /// The host's current time, in UTC milliseconds.
    pub now_ms: u64,
}

/// Why a request was refused.
///
/// Each variant names one rule, so a refusal says which rule refused it rather than only that
/// something did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The method is not in the registry, or not reachable from this ingress class.
    MethodNotReachable {
        /// The method that was named.
        method: &'static str,
    },
    /// The grant has been revoked.
    Revoked {
        /// The grant.
        grant_id: GrantId,
    },
    /// An ancestor of this grant has been revoked, which revokes this one.
    ParentRevoked {
        /// The ancestor.
        parent_grant_id: GrantId,
    },
    /// The grant's expiry has passed.
    ///
    /// Section 10: expiry never silently downgrades access to view-only. The request is refused,
    /// and a narrower grant is a separate thing the person chooses.
    Expired {
        /// When it expired, in UTC milliseconds.
        expired_at_ms: u64,
    },
    /// The grant was issued under an authority revision this host has replaced.
    StaleAuthority {
        /// What the grant carries.
        grant_revision: AuthorityRevision,
        /// What the host holds now.
        current_revision: AuthorityRevision,
    },
    /// The grant does not cover this environment.
    EnvironmentOutsideGrant,
    /// The grant does not cover this session.
    SessionOutsideGrant,
    /// The grant does not carry a right the method requires.
    MissingRight {
        /// The right.
        right: ActionRight,
    },
    /// The organisation membership the grant requires is not usable.
    MembershipUnusable {
        /// Why.
        refusal: MembershipRefusal,
    },
    /// The host's bounded offline-validity policy has lapsed, so personal remote access stops
    /// until the authority feed is reachable again.
    OfflineValidityLapsed {
        /// The last successful synchronisation, when there was one.
        last_synchronised_at_ms: Option<u64>,
    },
}

impl Refusal {
    /// The sentence a caller is told.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::MethodNotReachable { method } => {
                format!("{method} is not reachable from this caller")
            }
            Self::Revoked { .. } => "this grant has been revoked".to_owned(),
            Self::ParentRevoked { .. } => {
                "the grant this one was delegated from has been revoked".to_owned()
            }
            Self::Expired { .. } => "this grant has expired".to_owned(),
            Self::StaleAuthority { .. } => {
                "this grant was issued under an authority revision this host has replaced"
                    .to_owned()
            }
            Self::EnvironmentOutsideGrant => {
                "this grant does not cover this environment".to_owned()
            }
            Self::SessionOutsideGrant => "this grant does not cover that session".to_owned(),
            Self::MissingRight { right } => {
                format!("this grant does not carry {}", right.as_str())
            }
            Self::MembershipUnusable { refusal } => match refusal {
                MembershipRefusal::NoLease => {
                    "this host holds no membership lease for that organisation".to_owned()
                }
                MembershipRefusal::LeaseExpired => {
                    "this host's membership lease has expired; a connected transport does not \
                     extend it"
                        .to_owned()
                }
                MembershipRefusal::WrongAuthority => {
                    "this host's membership lease is not the one its pinned policy authority \
                     signed"
                        .to_owned()
                }
            },
            Self::OfflineValidityLapsed { .. } => {
                "this host's bounded offline-validity policy has lapsed; the authority feed has \
                 not been reached inside it"
                    .to_owned()
            }
        }
    }

    /// The protocol error a refusal becomes.
    ///
    /// Every one of them is `PERMISSION_DENIED`. A caller learns that its authority does not reach
    /// the request; which of this host's grants exist, and which revisions it has seen, is not a
    /// question a refused caller gets answered.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        ProtocolError::new(ErrorCode::PermissionDenied, self.detail())
    }
}

/// What a permitted request carries away from the intersection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permitted {
    /// The rights the grant and the host policy both allow, which is the intersection itself.
    ///
    /// Never the grant's own action set: an organisation lease that narrows a role narrows what
    /// this actor may do, and the request is decided against the result.
    pub rights: CanonicalSet<ActionRight>,
    /// The revision the decision was taken under.
    pub authority_revision: AuthorityRevision,
}

/// Intersects one grant with the host's current policy for one request.
///
/// The order matters and is deliberate:
///
/// 1. The method has to be in the registry and reachable from this ingress class. An unlisted
///    method is denied whatever the caller holds.
/// 2. The grant has to be live: not revoked, no revoked ancestor, not expired, and issued under a
///    revision this host has not replaced.
/// 3. The host's own policy has to permit the grant to be used at all: the organisation lease it
///    requires, and the bounded offline-validity policy when the owner chose one.
/// 4. The selectors have to admit the environment and the session the request names.
/// 5. The intersected rights have to carry every right the method requires under the conditions
///    this request meets.
///
/// # Errors
///
/// Returns the first rule that refused, as a [`Refusal`].
pub fn decide(
    grant: &Grant,
    record: &GrantRecord,
    policy: &HostPolicy,
    request: AccessRequest,
) -> std::result::Result<Permitted, Refusal> {
    let AuthorityDecision::Listed(entry) =
        kr_protocol::method::decide(request.method.as_str(), MethodVersion::V1, request.ingress)
    else {
        return Err(Refusal::MethodNotReachable {
            method: request.method.as_str(),
        });
    };

    if let Some(revoked_at_ms) = record.revoked_at_ms {
        let _ = revoked_at_ms;
        return Err(match record.revoked_by_parent {
            Some(parent_grant_id) => Refusal::ParentRevoked { parent_grant_id },
            None => Refusal::Revoked {
                grant_id: grant.grant_id,
            },
        });
    }
    if !grant.expiry.is_valid_at(request.now_ms) {
        let expired_at_ms = match grant.expiry {
            kr_protocol::grant::GrantExpiry::Never => request.now_ms,
            kr_protocol::grant::GrantExpiry::At { expires_at_ms } => expires_at_ms.get(),
        };
        return Err(Refusal::Expired { expired_at_ms });
    }
    if grant.authority_revision.get() < policy.authority_revision().get() {
        return Err(Refusal::StaleAuthority {
            grant_revision: grant.authority_revision,
            current_revision: policy.authority_revision(),
        });
    }

    let intersection = policy.intersect(grant, request.now_ms)?;

    if !grant.environment_selector.admits(request.environment_id) {
        return Err(Refusal::EnvironmentOutsideGrant);
    }
    if let Some(session_id) = request.session_id
        && !grant.session_selector.admits(session_id)
    {
        return Err(Refusal::SessionOutsideGrant);
    }

    for required in entry.required_rights {
        if !condition_holds(required.when, request) {
            continue;
        }
        match required.authority {
            RequiredAuthority::Right { right } => {
                if !intersection.rights.contains(&right) {
                    return Err(Refusal::MissingRight { right });
                }
            }
            // Current read authority over the subject the host resolves. For a session subject
            // that is `session.view` at the session's current scope, which is what a grant can
            // answer. The rest belongs to the subject.
            RequiredAuthority::PresentViewAuthority
                if !intersection.rights.contains(&ActionRight::SessionView) =>
            {
                return Err(Refusal::MissingRight {
                    right: ActionRight::SessionView,
                });
            }
            // A basis a grant does not express: a pairing transcript, a service credential, a
            // local caller's token, ownership of a named resource. The subject resolves each of
            // them where the subject cannot move underneath the answer.
            _ => {}
        }
    }

    Ok(Permitted {
        rights: intersection.rights,
        authority_revision: policy.authority_revision(),
    })
}

/// Whether a conditional requirement applies to this request.
///
/// A condition this host cannot evaluate is treated as holding, so the requirement is checked
/// rather than skipped. The exceptions are the pair `own_subject`/`other_actor`, which are
/// alternatives: treating both as holding would demand the authority for somebody else's subject
/// from a caller acting on its own. When the host has resolved the subject the pair is answered
/// here; when it has not, they are left to the subject, which is the only place that knows.
const fn condition_holds(when: RightCondition, request: AccessRequest) -> bool {
    match when {
        RightCondition::Always => true,
        RightCondition::GeometryClaim => request.claims_geometry,
        RightCondition::OwnSubject => match request.own_subject {
            Some(own) => own,
            None => false,
        },
        RightCondition::OtherActor => match request.own_subject {
            Some(own) => !own,
            None => false,
        },
        // Whether the caller is the pairing candidate or the issuing owner is the pairing
        // surface's own question, answered from the transcript rather than from a grant.
        RightCondition::CandidateEndpoint | RightCondition::IssuingOwner => false,
    }
}
