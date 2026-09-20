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
            narrowed_by: Some(format!(
                "this machine's resources allow {hard} live or creating sessions"
            )),
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
    let Some(configured) = ceilings.enrolment.0 else {
        return Ceiling {
            configured: None,
            value: default,
            narrowed_by: None,
            refused: false,
        };
    };
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

/// Names the enrolment budgets in `budgets` that differ from the schema default.
///
/// An enrolment section may name one budget and leave the rest out, and `serde` fills the rest
/// with the default before this crate ever sees them, so the section alone does not say which
/// numbers a person chose. What differs from the default does, and it is the same answer for the
/// purpose a report has: a budget that matches the default is in force because it is the default,
/// whether the document spelled it out or said nothing about it.
#[must_use]
pub fn supplied_budgets(budgets: &EnrolmentBudgets) -> Vec<&'static str> {
    let default = EnrolmentBudgets::default();
    let mut named = Vec::new();
    for (name, chosen, fallback) in [
        (
            "metadata_bytes",
            budgets.metadata_bytes,
            default.metadata_bytes,
        ),
        (
            "metadata_entries",
            budgets.metadata_entries,
            default.metadata_entries,
        ),
        (
            "retained_generations",
            budgets.retained_generations,
            default.retained_generations,
        ),
        (
            "cached_payload_bytes",
            budgets.cached_payload_bytes,
            default.cached_payload_bytes,
        ),
        (
            "package_bytes",
            budgets.package_bytes,
            default.package_bytes,
        ),
        ("object_count", budgets.object_count, default.object_count),
        (
            "expanded_pack_bytes",
            budgets.expanded_pack_bytes,
            default.expanded_pack_bytes,
        ),
        (
            "transfer_bytes",
            budgets.transfer_bytes,
            default.transfer_bytes,
        ),
        (
            "compilation_ms",
            budgets.compilation_ms,
            default.compilation_ms,
        ),
    ] {
        if chosen != fallback {
            named.push(name);
        }
    }
    if budgets.full_offline_mirror != default.full_offline_mirror {
        named.push("full_offline_mirror");
    }
    named
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
    let Some(ceiling) = configured_rights(ceilings) else {
        return Ok(Decided {
            permitted: decide(grant, record, policy, request)?,
            removed: CanonicalSet::new(),
            refused_rights: CanonicalSet::new(),
        });
    };
    // Intersect the grant with current policy first, so diagnostics reflect the combination
    // of policy and ceiling restrictions rather than comparing against unconstrained grant actions.
    let now_ms = policy.settled_now(request.now_ms);
    let policy_intersection = policy.intersect(grant, &request, now_ms)?;
    let policy_rights = policy_intersection.rights;

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
        permitted: decide(&narrowed, record, policy, request)?,
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
pub fn report<T>(
    key: &str,
    ceiling: &Ceiling<T>,
    source: kr_protocol::hostinfo::configuration::ValueSource,
    origin: Option<String>,
    effect: kr_protocol::hostinfo::configuration::ValueEffect,
    render: impl Fn(&T) -> String,
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
