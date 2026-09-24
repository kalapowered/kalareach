//! Ceilings, and the one place they are intersected.
//!
//! Section 26's second paragraph is the whole of this file: "Authority, organisation restrictions,
//! grant ceilings and hard resource limits are **intersections**, not lower-priority defaults that
//! a CLI flag can override. More permissive values are rejected."
//!
//! So a configured ceiling never appears on the precedence ladder. It arrives here, is intersected
//! with what is already in force, and comes out as a [`Ceiling`] that says what was asked for,
//! what is in force, what narrowed it and whether the request was more permissive and therefore
//! refused. There is one intersection function per kind and no second implementation of any of
//! them: the rights intersection is [`crate::grants::decide`]'s, called rather than copied, and
//! this file only narrows what that returned.

use kr_protocol::grant::Grant;
use kr_protocol::hostinfo::CeilingValue;
use kr_protocol::hostinfo::configuration::{ConfigurationCeilings, EnrolmentBudgets};
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::limits::DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Nullable};

use crate::grants::{AccessRequest, GrantRecord, HostPolicy, Permitted, Refusal, decide};

/// One ceiling after it has been intersected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ceiling<T> {
    /// What this host's configuration asked for, when it asked for anything.
    pub configured: Option<T>,
    /// What is in force.
    pub value: T,
    /// What narrowed the configured value, when something did.
    pub narrowed_by: Option<Sentence>,
    /// True when the configured value was more permissive than what is in force, and was therefore
    /// refused rather than applied.
    pub refused: bool,
}

/// The hard resource limits a configured ceiling is intersected with.
///
/// Facts about this machine rather than preferences, which is why they are passed in rather than
/// read from the document: a document that could raise them would be a document that raised a
/// limit by asking.
///
/// Section 2 makes 128 live or creating sessions the *default* admission, "configurable by the
/// local owner and constrained by available PTY/process/storage resources". So 128 is the product
/// default at the bottom of the ladder, and the hard limit is what those resources actually allow.
/// This host does not measure that headroom, so it says so rather than inventing a number: with
/// nothing established, an owner's configured number is what applies, and `kr doctor` reports that
/// no resource limit narrowed it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HardLimits {
    /// The most sessions this machine's own resources allow, where this host has established it.
    pub sessions_per_environment: Option<u64>,
}

/// Intersects the configured session number with the hard resource limit.
///
/// The configured number applies when this host has established no resource limit, and is narrowed
/// and reported as refused when it exceeds one that has been established. Asking for more never
/// raises anything.
#[must_use]
pub fn session_limit(ceilings: &ConfigurationCeilings, limits: HardLimits) -> Ceiling<u64> {
    let configured = ceilings.session_limit.0;
    let asked = configured.unwrap_or(DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT as u64);
    match limits.sessions_per_environment {
        Some(hard) if asked > hard => Ceiling {
            configured,
            value: hard,
            narrowed_by: Some(
                Sentence::new()
                    .stated("this machine's resources allow ")
                    .number(hard)
                    .stated(" live or creating sessions"),
            ),
            refused: true,
        },
        _ => Ceiling {
            configured,
            value: asked,
            narrowed_by: None,
            refused: false,
        },
    }
}

/// Intersects the configured enrolment budgets with what section 11 permits without an explicit
/// setting.
///
/// The payload budget is the one a document can ask to raise, and section 11 answers that a larger
/// full mirror "requires an explicit setting". Without that setting the default stands and the
/// request is refused.
#[must_use]
pub fn enrolment(ceilings: &ConfigurationCeilings) -> Ceiling<EnrolmentBudgets> {
    let default = EnrolmentBudgets::default();
    let Some(written) = ceilings.enrolment.0 else {
        return Ceiling {
            configured: None,
            value: default,
            narrowed_by: None,
            refused: false,
        };
    };
    // The budgets the document names, with the schema's own numbers for the rest. Which of them
    // the document named is kept separately, because that is what the report's source field is
    // about and a resolved set of ten numbers can no longer say it.
    let configured = written.resolve();
    if configured.cached_payload_bytes > default.cached_payload_bytes
        && !configured.full_offline_mirror
    {
        return Ceiling {
            configured: Some(configured),
            value: default,
            narrowed_by: Some(Sentence::new().stated(
                "a payload budget above the default is a full mirror and needs \
                 full_offline_mirror set explicitly",
            )),
            refused: true,
        };
    }
    Ceiling {
        configured: Some(configured),
        value: configured,
        narrowed_by: None,
        refused: false,
    }
}

/// Replaces what a ceiling *would be* with the number admission is enforcing.
///
/// The intersection above answers what this document asks for once this machine's limits have
/// narrowed it. That is the right number on an ordinary host and the wrong one where the document
/// never reached admission: an unusable file, or a registry write that failed. Then the number in
/// force is the one this host was already enforcing, and the report says so rather than printing
/// what the document would have asked for.
#[must_use]
pub fn enforced(intersected: Ceiling<u64>, sessions: crate::config::Enforced) -> Ceiling<u64> {
    if sessions.from_document {
        return intersected;
    }
    Ceiling {
        configured: intersected.configured,
        value: sessions.value,
        // Only where there is something to explain. A host that enforces the product default
        // because nothing ever restricted it is the ordinary first run, not a retained number.
        narrowed_by: (sessions.value != DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT as u64).then(|| {
            Sentence::new().stated(
                "this host is still enforcing the number it last accepted, because this document \
                 did not decide it",
            )
        }),
        refused: false,
    }
}

/// Returns the configured grant-rights ceiling, when the document sets one.
///
/// A right this build does not know is dropped rather than refused. Validation has already
/// rejected the document that names one, so reaching this with an unknown right means the document
/// was written by a build that knows more rights than this one, and a ceiling that silently
/// widened because a name was unfamiliar would be the opposite of a ceiling.
#[must_use]
pub fn configured_rights(ceilings: &ConfigurationCeilings) -> Option<CanonicalSet<ActionRight>> {
    ceilings.grant_rights.as_ref().map(|rights| {
        rights
            .iter()
            .filter_map(|right| ActionRight::from_wire(right))
            .collect()
    })
}

/// Decides one request against a grant, this host's policy and the rights ceiling in force.
///
/// The grant and the policy are intersected by [`crate::grants::decide`], which is the one
/// implementation of that arithmetic. What this adds is the third intersection section 26 asks
/// for: the rights this host's own configuration allows, `ceiling`, which is `None` where the
/// configuration sets no ceiling. It only ever removes rights. A ceiling that named a right the
/// grant and the policy did not already allow adds nothing, and [`Decided::refused_rights`] names
/// each one.
///
/// This is the decision a paired device's every request is taken through, so there is no second
/// copy of the arithmetic anywhere a request passes.
///
/// # Errors
///
/// Returns [`CeilingRefusal::RemovedByConfiguration`] naming the right when the method needs a
/// right the grant and the policy allow and the ceiling removed, and
/// [`CeilingRefusal::Refused`] with whatever [`crate::grants::decide`] refused with otherwise. A
/// ceiling narrows a request; it never turns a refusal into a permission.
pub fn decide_with_ceiling(
    ceiling: Option<&CanonicalSet<ActionRight>>,
    grant: &Grant,
    record: &GrantRecord,
    policy: &mut HostPolicy,
    request: AccessRequest,
) -> Result<Decided, CeilingRefusal> {
    let Some(ceiling) = ceiling else {
        return Ok(Decided {
            permitted: decide(grant, record, policy, request).map_err(CeilingRefusal::Refused)?,
            removed: CanonicalSet::new(),
            refused_rights: CanonicalSet::new(),
        });
    };
    // The ceiling is applied to the grant *before* the decision, never to its result. A method
    // whose required right this host's configuration has removed has to be refused, and a decision
    // taken against the unnarrowed grant would already have permitted it: emptying the answer
    // afterwards would leave a caller holding a permission that was granted and then quietly
    // hollowed out.
    let narrowed = Grant {
        actions: grant
            .actions
            .iter()
            .copied()
            .filter(|right| ceiling.contains(right))
            .collect(),
        ..grant.clone()
    };
    // The decision first, so every rule it applies refuses in its own order and the ceiling only
    // decides what the rules left to it.
    let decided = decide(&narrowed, record, policy, request.clone());
    // What the grant and the policy allow without the ceiling, which is what the ceiling is
    // measured against: an organisation lease that narrows a role has narrowed it already.
    let now_ms = policy.settled_now(request.now_ms);
    let policy_rights = policy
        .intersect(grant, &request, now_ms)
        .map_or_else(|_| CanonicalSet::new(), |intersection| intersection.rights);
    let permitted = match decided {
        Ok(permitted) => permitted,
        Err(Refusal::MissingRight { right })
            if policy_rights.contains(&right) && !ceiling.contains(&right) =>
        {
            return Err(CeilingRefusal::RemovedByConfiguration { right });
        }
        Err(refusal) => return Err(CeilingRefusal::Refused(refusal)),
    };
    let removed: CanonicalSet<ActionRight> = policy_rights
        .iter()
        .copied()
        .filter(|right| !ceiling.contains(right))
        .collect();
    // What the ceiling named and the grant does not carry under policy. Reported, never granted:
    // a ceiling is a maximum, and naming a right the grant and policy never had adds nothing.
    let refused_rights: CanonicalSet<ActionRight> = ceiling
        .iter()
        .copied()
        .filter(|right| !policy_rights.contains(right))
        .collect();
    Ok(Decided {
        permitted,
        removed,
        refused_rights,
    })
}

/// Why a request was refused once every intersection had been applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CeilingRefusal {
    /// The grant and this host's policy refused it, whatever the configuration says.
    Refused(Refusal),
    /// The grant and the policy allow `right`, the method needs it, and this host's configuration
    /// removed it.
    RemovedByConfiguration {
        /// The right the configuration removed.
        right: ActionRight,
    },
}

impl CeilingRefusal {
    /// The sentence a caller is told.
    ///
    /// A right the configuration removed is named, with the reason, rather than reported as one
    /// the grant does not carry: the grant does carry it, and a device holder told otherwise
    /// would go looking for the wrong fix.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Refused(refusal) => refusal.detail(),
            Self::RemovedByConfiguration { right } => format!(
                "this host's configuration removes {} from every grant on this host, although \
                 this grant carries it",
                right.as_str()
            ),
        }
    }

    /// The protocol error a refusal becomes, which is `PERMISSION_DENIED` whichever rule refused.
    #[must_use]
    pub fn to_protocol_error(&self) -> kr_protocol::error::ProtocolError {
        kr_protocol::error::ProtocolError::new(
            kr_protocol::error::ErrorCode::PermissionDenied,
            self.detail(),
        )
    }
}

/// The rights a ceiling in force removes from every grant on this host, in the vocabulary's order.
#[must_use]
pub fn removed_by(ceiling: &CanonicalSet<ActionRight>) -> Vec<ActionRight> {
    ActionRight::ALL
        .iter()
        .copied()
        .filter(|right| !ceiling.contains(right))
        .collect()
}

/// What one request came out as once every intersection had been applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decided {
    /// The decision, with the configured ceiling already applied to its rights.
    pub permitted: Permitted,
    /// The rights the grant and the policy allowed and this host's configuration removed.
    pub removed: CanonicalSet<ActionRight>,
    /// The rights the configuration's ceiling named that the grant and the policy did not carry.
    pub refused_rights: CanonicalSet<ActionRight>,
}

/// Renders one ceiling for the effective-value report.
pub fn report<T>(
    key: &str,
    ceiling: &Ceiling<T>,
    source: kr_protocol::hostinfo::configuration::ValueSource,
    origin: Option<String>,
    effect: kr_protocol::hostinfo::configuration::ValueEffect,
    render: impl Fn(&T) -> Sentence,
) -> CeilingValue {
    CeilingValue {
        key: key.to_owned(),
        configured: Nullable(ceiling.configured.as_ref().map(&render)),
        value: render(&ceiling.value),
        source,
        origin: Nullable(origin),
        effect,
        narrowed_by: Nullable(ceiling.narrowed_by.clone()),
        refused: ceiling.refused,
    }
}
