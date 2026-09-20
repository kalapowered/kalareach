//! This host's own configuration: its ceilings, its validated edits and what it reports.
//!
//! The schema and the precedence rule are [`kr_protocol::hostinfo::configuration`]'s; reading a
//! document from a state directory is [`kr_worker::config`]'s, and this daemon uses that reader
//! rather than a second one. What is here is what only the host can do.
//!
//! * **Ceilings** ([`ceilings`]). Authority, organisation restrictions, grant ceilings and hard
//!   resource limits intersect. A configured value more permissive than what is already in force
//!   is refused, and the rights intersection calls [`crate::grants::decide`] rather than repeating
//!   its arithmetic.
//! * **Validated edits** ([`apply`]). An edit is validated before a revision is applied, the
//!   revision it was based on is checked again immediately before the write, and a change that
//!   affects authority fences dispatch before the caller is told it took effect.
//! * **The report** ([`effective`]). Each value, its source and whether it applies immediately or
//!   only to new sessions, which is what `kr doctor` prints and what a support bundle carries.
//! * **The catalogue seam** ([`catalogue`]). The enrolment budgets and the shared capability
//!   evidence, defined here so a catalogue client fills them rather than inventing its own.

pub mod catalogue;
pub mod ceilings;

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::desktop::{CapabilityInvalidation, SleepInhibitionSetting};
use kr_protocol::hostinfo::configuration::{self, Change, EditRefused, Edited, ValueEffect};
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus, EffectiveConfiguration, EffectiveValue};
use kr_protocol::identity::WorkerProfile;
use kr_protocol::scalars::U64;
use kr_protocol::session::ShellMode;
use kr_worker::config::{Resolver, effective_value};

use crate::error::{ControllerError, Result};

pub use ceilings::HardLimits;

/// Reads this environment's configuration.
#[must_use]
pub fn open(paths: &EnvironmentPaths) -> Resolver {
    Resolver::open(paths)
}

/// What one applied edit did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Applied {
    /// The revision now in force.
    pub revision: u64,
    /// Whether it applies immediately or only to sessions created afterwards.
    pub effect: ValueEffect,
    /// The capability evidence this change invalidated.
    ///
    /// Invalidated, never migrated: a running worker keeps the profile it was created in, and the
    /// new value applies to sessions created afterwards.
    pub invalidated: Vec<CapabilityInvalidation>,
    /// True when this change affects authority, so dispatch is fenced before it is acknowledged.
    pub fences_dispatch: bool,
}

/// Applies one validated edit to this environment's configuration document.
///
/// The order matters and is the whole of section 26's "validate edits before applying a versioned
/// revision".
///
/// 1. Read the document. One this build cannot use is not edited at all.
/// 2. Apply the change and validate the result. A result that does not validate is refused here,
///    with nothing written.
/// 3. Read the revision again, immediately before the write, and refuse when it has moved. Two
///    writers would otherwise each apply their own edit to the revision they read and the second
///    would erase the first.
/// 4. Write, atomically and owner-only.
///
/// Fencing dispatch and invalidating capability evidence are the caller's, because both need the
/// running daemon. [`Applied`] says which of them this change owes.
///
/// # Errors
///
/// Returns [`ControllerError::Configuration`] when the document may not be edited, when the result
/// does not validate, or when another writer moved the revision first.
pub fn apply(paths: &EnvironmentPaths, change: &Change) -> Result<Applied> {
    let loaded = kr_worker::config::load(paths);
    let edited = configuration::edit(&loaded, change).map_err(refused)?;
    write(paths, &edited)?;
    Ok(Applied {
        revision: edited.revision,
        effect: edited.effect,
        invalidated: change.invalidates(),
        fences_dispatch: change.affects_authority(),
    })
}

/// Writes an edit whose base revision is still the one on disk.
fn write(paths: &EnvironmentPaths, edited: &Edited) -> Result<()> {
    // Read again, here, rather than trusting the read the edit was built from. Between the two a
    // second writer may have applied its own edit, and writing over it would lose a choice
    // somebody made rather than change one.
    configuration::still_current(edited, &kr_worker::config::load(paths)).map_err(refused)?;
    kr_ipc::paths::write_owner_only_file(
        &kr_worker::config::document_path(paths),
        edited.contents.as_bytes(),
    )
    .map_err(ControllerError::Ipc)
}

/// Turns a refusal into this crate's error.
fn refused(refused: EditRefused) -> ControllerError {
    ControllerError::Configuration(format!("{refused}"))
}

/// Builds the effective-value report for one environment.
///
/// Every ordinary preference with its source and its effect, every ceiling with what narrowed it,
/// the precedence ladder in order, the documented overrides, the secure-store references by name,
/// and any document beside this one that this build no longer reads.
#[must_use]
pub fn effective(
    resolver: &Resolver,
    limits: HardLimits,
    platform_profile: WorkerProfile,
    platform_shell_mode: ShellMode,
) -> EffectiveConfiguration {
    let ceilings = resolver.ceilings();
    let power = resolver.sleep_inhibition(None);
    let profile = resolver.worker_profile(None, platform_profile);
    let mode = resolver.shell_mode(None, platform_shell_mode);
    let runtime = resolver.runtime_directory();
    let state = resolver.state_directory();
    let values: Vec<EffectiveValue> = vec![
        effective_value(&power, power.value.as_str().to_owned()),
        effective_value(&profile, profile.value.as_str().to_owned()),
        effective_value(&mode, mode.value.as_str().to_owned()),
        effective_value(&runtime, runtime.value.clone()),
        effective_value(&state, state.value.clone()),
    ];
    let sessions = ceilings::session_limit(&ceilings, limits);
    let enrolment = ceilings::enrolment(&ceilings);
    let rights = ceilings::configured_rights(&ceilings);
    EffectiveConfiguration {
        schema_version: U64::new(configuration::VERSION),
        revision: U64::new(resolver.revision()),
        document: resolver.document().display().to_string(),
        status: resolver.status().clone(),
        runtime_directory: runtime.value,
        state_directory: state.value,
        precedence: configuration::PRECEDENCE
            .iter()
            .map(|source| source.describe().to_owned())
            .collect(),
        overrides: resolver.overrides(),
        values,
        ceilings: vec![
            ceilings::report("session_limit", &sessions, u64::to_string),
            ceilings::report("enrolment", &enrolment, |budgets| {
                format!(
                    "{} metadata bytes, {} entries, {} cached payload bytes{}",
                    budgets.metadata_bytes,
                    budgets.metadata_entries,
                    budgets.cached_payload_bytes,
                    if budgets.full_offline_mirror {
                        ", full offline mirror"
                    } else {
                        ""
                    }
                )
            }),
            kr_protocol::hostinfo::CeilingValue {
                key: "grant_rights".to_owned(),
                configured: kr_protocol::scalars::Nullable(rights.as_ref().map(|rights| {
                    rights
                        .iter()
                        .map(|right| right.as_str().to_owned())
                        .collect::<Vec<_>>()
                        .join(", ")
                })),
                value: rights.as_ref().map_or_else(
                    || "every right the grant and the host policy allow".to_owned(),
                    |rights| {
                        rights
                            .iter()
                            .map(|right| right.as_str().to_owned())
                            .collect::<Vec<_>>()
                            .join(", ")
                    },
                ),
                narrowed_by: kr_protocol::scalars::Nullable(rights.as_ref().map(|_| {
                    "the grant and the host policy are intersected first; this ceiling only \
                     removes rights"
                        .to_owned()
                })),
                refused: false,
            },
        ],
        secrets: resolver
            .loaded()
            .document
            .as_ref()
            .map(|document| document.secrets.clone())
            .unwrap_or_default(),
        stale_documents: resolver
            .stale_documents()
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
    }
}

/// The diagnostics this host's configuration contributes.
///
/// Four checks, each with the evidence `kr doctor --verbose` prints: where the document is and
/// what it turned out to be, the precedence order and the locations, the documented overrides and
/// which of them are set, and the ceilings with what narrowed them. A stale document beside the
/// configuration is one line inside the first of them.
#[must_use]
pub fn checks(effective: &EffectiveConfiguration) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let status = &effective.status;
    let mut detail = format!("{}: {}", effective.document, status.detail);
    for stale in &effective.stale_documents {
        detail.push_str(&format!(
            "; {stale} is a document this build no longer reads and is ignored"
        ));
    }
    checks.push(DoctorCheck::new(
        "configuration-document",
        "This host's configuration document",
        if status.state.is_a_problem() {
            DoctorStatus::Warning
        } else {
            DoctorStatus::Ok
        },
        detail,
        status.state.is_a_problem().then(|| {
            "Every value is the product default while this document cannot be used. It is left \
             exactly as it is: nothing here rewrites it."
                .to_owned()
        }),
    ));
    checks.push(DoctorCheck::new(
        "configuration-precedence",
        "Where each effective value comes from",
        DoctorStatus::Ok,
        format!(
            "{}; runtime directory {}, state directory {}",
            effective.precedence.join(", then "),
            effective.runtime_directory,
            effective.state_directory
        ),
        None,
    ));
    let set: Vec<&str> = effective
        .overrides
        .iter()
        .filter(|entry| entry.set)
        .map(|entry| entry.variable.as_str())
        .collect();
    checks.push(DoctorCheck::new(
        "configuration-overrides",
        "Which environment variables participate",
        DoctorStatus::Ok,
        format!(
            "{}; set here: {}. Any other inherited variable changes nothing.",
            effective
                .overrides
                .iter()
                .map(|entry| format!(
                    "{} supplies {} as {}",
                    entry.variable,
                    entry.preference,
                    entry.position.describe()
                ))
                .collect::<Vec<_>>()
                .join("; "),
            if set.is_empty() {
                "none".to_owned()
            } else {
                set.join(", ")
            }
        ),
        None,
    ));
    let refused: Vec<&str> = effective
        .ceilings
        .iter()
        .filter(|ceiling| ceiling.refused)
        .map(|ceiling| ceiling.key.as_str())
        .collect();
    checks.push(DoctorCheck::new(
        "configuration-ceilings",
        "Ceilings intersect; they are not defaults a flag can raise",
        if refused.is_empty() {
            DoctorStatus::Ok
        } else {
            DoctorStatus::Warning
        },
        effective
            .ceilings
            .iter()
            .map(|ceiling| {
                let narrowed = ceiling
                    .narrowed_by
                    .as_ref()
                    .map(|why| format!(" ({why})"))
                    .unwrap_or_default();
                format!("{} is {}{narrowed}", ceiling.key, ceiling.value)
            })
            .collect::<Vec<_>>()
            .join("; "),
        (!refused.is_empty()).then(|| {
            format!(
                "The configured value for {} was more permissive than what is in force and was \
                 refused. Lower it, or ask for the explicit setting the limit names.",
                refused.join(", ")
            )
        }),
    ));
    checks
}

/// The secure-store references this configuration names, as one line for a diagnostic.
///
/// Names only: the store and the item, never a value. There is no field in the schema a value
/// would fit in, so this cannot print one however it is called.
#[must_use]
pub fn secret_line(effective: &EffectiveConfiguration) -> String {
    if effective.secrets.is_empty() {
        return "no secure-store references are configured".to_owned();
    }
    effective
        .secrets
        .iter()
        .map(|reference| {
            format!(
                "{} is {} in {}",
                reference.name, reference.item, reference.store
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Returns this host's sleep policy as the configuration resolves it.
///
/// The one reader the power module and the diagnostics both use, so the setting and the report
/// about it can never disagree.
#[must_use]
pub fn sleep_inhibition(paths: &EnvironmentPaths) -> SleepInhibitionSetting {
    Resolver::open(paths).sleep_inhibition(None).value
}

#[cfg(test)]
mod tests;
