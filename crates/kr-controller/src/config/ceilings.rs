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
    pub narrowed_by: Option<String>,
    /// True when the configured value was more permissive than what is in force, and was therefore
    /// refused rather than applied.
    pub refused: bool,
}

/// The hard resource limits a configured ceiling is intersected with.
///
/// They are facts about this build and this environment rather than preferences, which is why they
/// are passed in rather than read from the document: a document that could raise them would be a
/// document that could raise a limit by asking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HardLimits {
    /// The most sessions one environment admits, whatever a configuration asks for.
    pub sessions_per_environment: u64,
}

impl Default for HardLimits {
    fn default() -> Self {
        Self {
            sessions_per_environment: DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT as u64,
        }
    }
}

/// Intersects the configured session ceiling with the hard resource limit.
///
/// A configured ceiling below the limit is this owner's own restriction and applies. A configured
/// ceiling above it is more permissive than the product allows, so it is refused and the limit
/// stands; nothing about asking for more raises anything.
#[must_use]
pub fn session_limit(ceilings: &ConfigurationCeilings, limits: HardLimits) -> Ceiling<u64> {
    let hard = limits.sessions_per_environment;
    let configured = ceilings.session_limit.0;
    match configured {
        Some(asked) if asked > hard => Ceiling {
            configured,
            value: hard,
            narrowed_by: Some(format!(
                "the hard resource limit of {hard} sessions per environment"
            )),
            refused: true,
        },
        Some(asked) => Ceiling {
            configured,
            value: asked,
            narrowed_by: None,
            refused: false,
        },
        None => Ceiling {
            configured: None,
            value: hard,
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
    let configured = ceilings.enrolment;
    let default = EnrolmentBudgets::default();
    if configured.cached_payload_bytes > default.cached_payload_bytes
        && !configured.full_offline_mirror
    {
        return Ceiling {
            configured: Some(configured),
            value: default,
            narrowed_by: Some(
                "a payload budget above the default is a full mirror and needs \
                 full_offline_mirror set explicitly"
                    .to_owned(),
            ),
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

/// Decides one request against a grant, this host's policy and this host's configured ceiling.
///
/// The grant and the policy are intersected by [`crate::grants::decide`], which is the one
/// implementation of that arithmetic. What this adds is the third intersection section 26 asks
/// for: the rights this host's own configuration allows. It only ever removes rights. A ceiling
/// that named a right the grant and the policy did not already allow adds nothing, and
/// [`Decided::refused_rights`] names each one so the effective-value report can say the
/// configuration asked for something it did not get.
///
/// # Errors
///
/// Returns whatever [`crate::grants::decide`] refused with. A ceiling narrows a permitted request;
/// it never turns a refusal into something else.
pub fn decide_with_ceiling(
    ceilings: &ConfigurationCeilings,
    grant: &Grant,
    record: &GrantRecord,
    policy: &mut HostPolicy,
    request: AccessRequest,
) -> Result<Decided, Refusal> {
    let permitted = decide(grant, record, policy, request)?;
    let Some(ceiling) = configured_rights(ceilings) else {
        return Ok(Decided {
            permitted,
            removed: CanonicalSet::new(),
            refused_rights: CanonicalSet::new(),
        });
    };
    let removed: CanonicalSet<ActionRight> = permitted
        .rights
        .iter()
        .copied()
        .filter(|right| !ceiling.contains(right))
        .collect();
    // What the configuration asked to allow and the intersection above it did not. Reported, never
    // granted: a ceiling is a maximum, and asking for a right the grant does not carry is asking
    // for nothing.
    let refused_rights: CanonicalSet<ActionRight> = ceiling
        .iter()
        .copied()
        .filter(|right| !permitted.rights.contains(right))
        .collect();
    let rights = permitted
        .rights
        .iter()
        .copied()
        .filter(|right| ceiling.contains(right))
        .collect();
    Ok(Decided {
        permitted: Permitted {
            rights,
            ..permitted
        },
        removed,
        refused_rights,
    })
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
pub fn report<T>(key: &str, ceiling: &Ceiling<T>, render: impl Fn(&T) -> String) -> CeilingValue {
    CeilingValue {
        key: key.to_owned(),
        configured: Nullable(ceiling.configured.as_ref().map(&render)),
        value: render(&ceiling.value),
        narrowed_by: Nullable(ceiling.narrowed_by.clone()),
        refused: ceiling.refused,
    }
}
