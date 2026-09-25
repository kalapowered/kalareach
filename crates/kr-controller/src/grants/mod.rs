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
//!   revision in force, the organisations this host is enrolled in and the leases it holds, and
//!   the optional bounded offline-validity policy an owner may choose for personal remote access.
//!   [`organisation`] is how an enrolment and a lease are verified before either is stored.
//! * **The vocabulary.** [`vocabulary`] is the method-to-right mapping of section 23, read out of
//!   [`kr_protocol::method::REGISTRY`] rather than restated here, so there is one table.
//! * **The feed.** [`feed`] is this host's half of the remote authority feed: the ordered
//!   revisions only this host issues, the revocation records it retains until every enrolled host
//!   has acknowledged them, and the synchronisation it owes before it serves remote work again.
//! * **What survives a restart.** [`durable`] is the shape of the policy and the feed on disk, and
//!   the limit that persistence does not remove.
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

pub mod durable;
pub mod feed;
pub mod organisation;
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

pub use durable::{StoredFeed, StoredPolicy};
pub use feed::{AuthorityFeed, FeedRefusal, RetainedRevocation};
pub use organisation::LeaseRefused;
pub use policy::{HostPolicy, PolicyIntersection};
pub use store::{
    ActionClaim, ActionRecord, ClaimHold, GrantDirectory, GrantRecord, GrantRevocation,
};
pub use vocabulary::{rights_for, unconditional_rights_for};

/// One request, as the intersection sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    ///
    /// Never used directly: [`decide`] takes the later of this and the highest reading this host
    /// has already observed, so winding the clock back does not revive an expiry this host has
    /// already decided against.
    pub now_ms: u64,
    /// The host's continuous clock when the request is decided, which a membership lease's
    /// continuous deadline is compared with.
    pub continuous_now: kr_transport::clock::ContinuousInstant,
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
    /// The invitation that carries this grant has not been redeemed, so it authorises nothing.
    NotRedeemed {
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
    /// The grant claims an authority revision this host has not issued.
    ///
    /// An *older* revision is not a refusal. Section 10 makes the issuing revision provenance: a
    /// grant records the revision it was issued under, and what stops it being used is revocation
    /// or expiry, not somebody else's revocation advancing the number. A revision the host has
    /// never reached is different: nothing could have issued it here.
    UnissuedAuthority {
        /// What the grant claims.
        grant_revision: AuthorityRevision,
        /// The highest revision this host has issued.
        current_revision: AuthorityRevision,
    },
    /// The grant requires an organisation membership and its recipient device is bound to no
    /// member of that organisation on this host, so no lease answers for it.
    MembershipUnattributed,
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
    /// The decision reads this host's clock, and the clock floor it would stand on is owed its
    /// record, so it is not taken until the floor is written down
    /// ([`policy::UtcFloor::bound`]).
    FloorUnrecorded,
    /// The grant's expiry has passed at a reading this host has not written down yet.
    ///
    /// It is answered as [`Self::FloorUnrecorded`] is: a clock wound back before the next start
    /// would decide the other way, so the answer states no expiry until the floor is on disk. It
    /// is its own variant because a paired device's connection stops its frames for it all the
    /// same, as it does for an expiry, which records nothing.
    ExpiryUnrecorded {
        /// When it expired, in UTC milliseconds.
        expired_at_ms: u64,
    },
}

impl Refusal {
    /// Whether the clock decided this refusal: a grant's expiry, a lapsed offline bound or a lapsed
    /// membership lease.
    ///
    /// Such a refusal is answered only once the clock floor it stood on is on disk: before that, a
    /// clock wound back before the next start would decide the other way.
    #[must_use]
    pub const fn is_clock_decided(&self) -> bool {
        matches!(
            self,
            Self::Expired { .. }
                | Self::OfflineValidityLapsed { .. }
                | Self::MembershipUnusable {
                    refusal: MembershipRefusal::LeaseExpired
                }
        )
    }

    /// The sentence a caller is told.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::MethodNotReachable { method } => {
                format!("{method} is not reachable from this caller")
            }
            Self::Revoked { .. } => "this grant has been revoked".to_owned(),
            Self::NotRedeemed { .. } => {
                "the invitation that carries this grant has not been redeemed".to_owned()
            }
            Self::ParentRevoked { .. } => {
                "the grant this one was delegated from has been revoked".to_owned()
            }
            Self::Expired { .. } => "this grant has expired".to_owned(),
            Self::UnissuedAuthority { .. } => {
                "this grant claims an authority revision this host has not issued".to_owned()
            }
            Self::MembershipUnattributed => {
                "this host cannot tell which member's lease would answer for this grant".to_owned()
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
            Self::FloorUnrecorded | Self::ExpiryUnrecorded { .. } => FLOOR_UNRECORDED.to_owned(),
        }
    }

    /// The protocol error a refusal becomes.
    ///
    /// Every one but [`Self::FloorUnrecorded`] and [`Self::ExpiryUnrecorded`] is
    /// `PERMISSION_DENIED`. A caller learns that its authority does not reach the request; which
    /// of this host's grants exist, and which revisions it has seen, is not a question a refused
    /// caller gets answered. The exceptions say nothing about the caller's authority: they are this
    /// host's store, and they pass when the store takes the write.
    #[must_use]
    pub fn to_protocol_error(&self) -> ProtocolError {
        let code = match self {
            Self::FloorUnrecorded | Self::ExpiryUnrecorded { .. } => ErrorCode::StorageUnavailable,
            _ => ErrorCode::PermissionDenied,
        };
        ProtocolError::new(code, self.detail())
    }
}

/// What a caller is told when a decision that reads this host's clock is not taken because the
/// clock floor it would stand on is owed its record.
pub const FLOOR_UNRECORDED: &str = "this host could not write down the clock reading this \
                                    decision stands on, so it does not decide it until it can";

/// What a permitted request carries away from the intersection.
///
/// "Permitted" here means *this host's authority store has no objection*. It is not the whole
/// answer for a method whose requirements include a basis a grant cannot express, and
/// [`Self::unresolved`] says so out loud rather than leaving a caller to assume otherwise: a
/// caller that ignores it and acts is acting on a check nobody made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permitted {
    /// The rights the grant and the host policy both allow, which is the intersection itself.
    ///
    /// Never the grant's own action set: an organisation lease that narrows a role narrows what
    /// this actor may do, and the request is decided against the result.
    pub rights: CanonicalSet<ActionRight>,
    /// The revision the decision was taken under.
    pub authority_revision: AuthorityRevision,
    /// The deadlines of the membership lease the decision was taken under, when one answered for
    /// it: the decision holds only while both are ahead.
    pub lease: Option<organisation::LeaseBound>,
    /// The requirements this decision could not answer, for the subject to answer.
    ///
    /// Resource ownership, a pairing transcript, a service credential, a local caller's token and
    /// the issuer's delegation authority over a named grant are each resolved where the subject
    /// cannot move underneath the answer. A request whose only requirement is one of these leaves
    /// here permitted and unanswered.
    pub unresolved: Vec<RequiredAuthority>,
}

impl Permitted {
    /// Returns true when every requirement of the method was answered here.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.unresolved.is_empty()
    }
}

/// Intersects one grant with the host's current policy for one request.
///
/// The order matters and is deliberate:
///
/// 1. The method has to be in the registry and reachable from this ingress class. An unlisted
///    method is denied whatever the caller holds.
/// 2. The grant has to be live: not revoked, no revoked ancestor, redeemed, not expired, and
///    claiming no revision this host has not issued.
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
    policy: &mut HostPolicy,
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
    // The later of the clock and the highest reading this host has already observed. A rollback
    // must not revive an expiry this host has already decided against, and section 24 asks for
    // expiry to be revalidated after a wake rather than re-derived from whatever the clock now
    // says.
    // Raised here rather than by the caller. A floor a caller has to remember to advance is a
    // floor that is not there the one time it matters.
    let bound = policy.utc_floor().bound(grant.expiry, request.now_ms);
    let now_ms = policy.settled_now(request.now_ms);
    if !record.is_active() {
        return Err(Refusal::NotRedeemed {
            grant_id: grant.grant_id,
        });
    }
    // Nothing that reads the clock is decided while the floor it would stand on is owed its
    // record: a daemon that stopped before that record landed would start again on an older floor
    // and could decide the other way. What reads the clock is the grant's expiry and this host's
    // own time bounds on its use, so the debt is asked about whatever the grant's own expiry is. A
    // lapse found here is owed its record by the caller, which writes the floor it stood on.
    if policy.utc_floor().is_owed() && policy.stands_on_the_clock(grant, request.ingress) {
        return Err(Refusal::FloorUnrecorded);
    }
    if bound.passed {
        let expired_at_ms = match grant.expiry {
            kr_protocol::grant::GrantExpiry::Never => now_ms,
            kr_protocol::grant::GrantExpiry::At { expires_at_ms } => expires_at_ms.get(),
        };
        return Err(Refusal::Expired { expired_at_ms });
    }
    if grant.authority_revision.get() > policy.authority_revision().get() {
        return Err(Refusal::UnissuedAuthority {
            grant_revision: grant.authority_revision,
            current_revision: policy.authority_revision(),
        });
    }

    let intersection = policy.intersect(grant, &request, now_ms)?;

    if !grant.environment_selector.admits(request.environment_id) {
        return Err(Refusal::EnvironmentOutsideGrant);
    }
    if let Some(session_id) = request.session_id
        && !grant.session_selector.admits(session_id)
    {
        return Err(Refusal::SessionOutsideGrant);
    }

    let mut unresolved: Vec<RequiredAuthority> = Vec::new();
    for required in entry.required_rights {
        if !condition_holds(required.when, &request) {
            // A conditional requirement the host cannot decide is not skipped quietly: the
            // subject decides it, and the answer says so. The pair `own_subject`/`other_actor` is
            // unresolved only while the host has not resolved the subject; the pairing pair is
            // always the pairing surface's to answer, from the transcript rather than a grant.
            let undecided = match required.when {
                RightCondition::OwnSubject | RightCondition::OtherActor => {
                    request.own_subject.is_none()
                }
                RightCondition::CandidateEndpoint | RightCondition::IssuingOwner => true,
                RightCondition::Always | RightCondition::GeometryClaim => false,
            };
            if undecided && !unresolved.contains(&required.authority) {
                unresolved.push(required.authority);
            }
            continue;
        }
        match required.authority {
            RequiredAuthority::Right { right } => {
                if !intersection.rights.contains(&right) {
                    return Err(Refusal::MissingRight { right });
                }
            }
            // Current read authority over the subject the host resolves. For a **session** subject
            // that is `session.view` at the session's current scope, which is what a grant can
            // answer. A host or environment subject resolves against the actor's read scope over
            // that environment, which the selectors above have already decided, so demanding
            // `session.view` for it would refuse a receipt for a host effect to the owner who
            // caused it.
            RequiredAuthority::PresentViewAuthority => {
                if request.session_id.is_some()
                    && !intersection.rights.contains(&ActionRight::SessionView)
                {
                    return Err(Refusal::MissingRight {
                        right: ActionRight::SessionView,
                    });
                }
                if !unresolved.contains(&required.authority) {
                    unresolved.push(required.authority);
                }
            }
            // A basis a grant does not express: a pairing transcript, a service credential, a
            // local caller's token, ownership of a named resource, delegation authority over a
            // named grant. The subject resolves each of them where the subject cannot move
            // underneath the answer, and each is named here so a caller knows the answer is
            // still owed.
            other => {
                if !unresolved.contains(&other) {
                    unresolved.push(other);
                }
            }
        }
    }

    Ok(Permitted {
        rights: intersection.rights,
        authority_revision: policy.authority_revision(),
        lease: intersection.lease,
        unresolved,
    })
}

/// Intersects one grant with this host's current policy at the moment the host acts on it itself.
///
/// A workflow node is this host's own action, taken under the grant a definition names rather
/// than under a request a caller sent, so nothing here is decided against the method registry or
/// against a request's selectors: the node's own rights and resources are the automation engine's
/// to check against what this returns. What is decided here is whether the grant stands under this
/// host's policy at this moment, and which of its rights the policy leaves. The rules are the ones
/// [`decide`] applies before it reaches the method table, in the same order: revocation and a
/// revoked ancestor, the clock floor, redemption, expiry, an unissued revision, and the policy
/// intersection with its membership leases and bounded offline validity.
///
/// The clock floor rises here as it does in [`decide`]: a workflow runs unattended, and a floor
/// that only requests advanced would let a clock wound back between two dispatches revive an
/// expiry this host had already refused. The caller writes the policy down afterwards, as every
/// other raise of the floor is written down.
///
/// A grant that requires an organisation membership is answered by the lease of the member its
/// recipient device is bound to, on both clocks, as a request's is; nothing here presents a
/// connection or names an account. What comes back carries that lease's deadlines with the rights.
///
/// # Errors
///
/// Returns the first rule that refused, as a [`Refusal`].
pub fn standing_at_dispatch(
    record: &GrantRecord,
    policy: &mut HostPolicy,
    environment_id: EnvironmentId,
    ingress: kr_protocol::actor::ActorIngress,
    now_ms: u64,
    continuous_now: kr_transport::clock::ContinuousInstant,
) -> std::result::Result<PolicyIntersection, Refusal> {
    let grant = &record.grant;
    if record.revoked_at_ms.is_some() {
        return Err(match record.revoked_by_parent {
            Some(parent_grant_id) => Refusal::ParentRevoked { parent_grant_id },
            None => Refusal::Revoked {
                grant_id: grant.grant_id,
            },
        });
    }
    let bound = policy.utc_floor().bound(grant.expiry, now_ms);
    let now_ms = policy.settled_now(now_ms);
    if !record.is_active() {
        return Err(Refusal::NotRedeemed {
            grant_id: grant.grant_id,
        });
    }
    // As [`decide`]: nothing that reads the clock is decided while its floor is owed its record.
    if policy.utc_floor().is_owed() && policy.stands_on_the_clock(grant, ingress) {
        return Err(Refusal::FloorUnrecorded);
    }
    if bound.passed {
        let expired_at_ms = match grant.expiry {
            kr_protocol::grant::GrantExpiry::Never => now_ms,
            kr_protocol::grant::GrantExpiry::At { expires_at_ms } => expires_at_ms.get(),
        };
        return Err(Refusal::Expired { expired_at_ms });
    }
    if grant.authority_revision.get() > policy.authority_revision().get() {
        return Err(Refusal::UnissuedAuthority {
            grant_revision: grant.authority_revision,
            current_revision: policy.authority_revision(),
        });
    }
    let request = AccessRequest {
        method: Method::WorkflowRun,
        ingress,
        environment_id,
        session_id: None,
        claims_geometry: false,
        own_subject: None,
        now_ms,
        continuous_now,
    };
    policy.intersect(grant, &request, now_ms)
}

/// Whether a conditional requirement applies to this request.
///
/// A condition this host cannot evaluate is treated as holding, so the requirement is checked
/// rather than skipped. The exceptions are the pair `own_subject`/`other_actor`, which are
/// alternatives: treating both as holding would demand the authority for somebody else's subject
/// from a caller acting on its own. When the host has resolved the subject the pair is answered
/// here; when it has not, they are left to the subject, which is the only place that knows.
fn condition_holds(when: RightCondition, request: &AccessRequest) -> bool {
    match when {
        RightCondition::Always => true,
        RightCondition::GeometryClaim => request.claims_geometry,
        RightCondition::OwnSubject => request.own_subject.unwrap_or(false),
        RightCondition::OtherActor => request.own_subject.is_some_and(|own| !own),
        // Whether the caller is the pairing candidate or the issuing owner is the pairing
        // surface's own question, answered from the transcript rather than from a grant.
        RightCondition::CandidateEndpoint | RightCondition::IssuingOwner => false,
    }
}
