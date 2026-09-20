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
use kr_worker::config::{Resolver, effective_value};

use crate::error::{ControllerError, Result};

pub use ceilings::HardLimits;

/// Reads this environment's configuration.
#[must_use]
pub fn open(paths: &EnvironmentPaths) -> Resolver {
    Resolver::open(paths)
}

/// One applied edit, with the lock still held.
///
/// The lock outlives the write on purpose: a change that also has to be put somewhere else, such
/// as the session number the registry admits against, has to do that before another writer can
/// prepare an edit of its own. Dropping this value releases the lock.
#[derive(Debug)]
pub struct AppliedEdit {
    /// What the edit did.
    pub applied: Applied,
    /// The lock, held until this value is dropped.
    pub lock: configuration::EditLock,
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
    /// The revision the fence was raised at, when one was.
    pub authority_revision: Option<kr_protocol::ids::AuthorityRevision>,
    /// True when every affected worker's barrier held before this returned.
    ///
    /// A revision that advanced is not a completed revocation. A worker that has not acknowledged
    /// its fence still holds work admitted under the old authority, and a caller told the change
    /// is in force would be told something that is not yet true of that worker.
    pub barrier_holds: bool,
    /// How many workers had not acknowledged the fence when this returned.
    pub pending_workers: u64,
}

/// Applies one validated edit to this environment's configuration document.
///
/// The order matters and is the whole of section 26's "validate edits before applying a versioned
/// revision".
///
/// 1. Take this environment's edit lock, and hold it to the end.
/// 2. Read the document. One this build cannot use is not edited at all.
/// 3. Apply the change and validate the result. A result that does not validate is refused here,
///    with nothing written.
/// 4. Read the document again, immediately before the write, and refuse when its revision or its
///    condition has moved.
/// 5. Write, atomically and owner-only.
///
/// The lock is what makes steps 2 to 5 one edit; the second read is what catches a writer that
/// ran without the lock, which is what a document restored from a backup underneath a running
/// host looks like.
///
/// Fencing dispatch and invalidating capability evidence are the caller's, because both need the
/// running daemon. [`Applied`] says which of them this change owes.
///
/// # Errors
///
/// Returns [`ControllerError::Configuration`] when the document may not be edited, when the result
/// does not validate, or when another writer moved the revision first.
pub fn apply(paths: &EnvironmentPaths, change: &Change, limits: HardLimits) -> Result<AppliedEdit> {
    // Held across the read, the edit and the replacement, and handed back to the caller so the
    // effects of the edit land before another writer can prepare one.
    let lock = kr_worker::config::lock(paths).map_err(ControllerError::Configuration)?;
    let loaded = kr_worker::config::load(paths);
    let edited = configuration::edit(&loaded, change).map_err(refused)?;
    // A ceiling the intersection would refuse is refused here, before it is written. Section 26
    // rejects a more permissive value; a document that recorded one and was then quietly read back
    // narrower would be a rejection nobody was told about, and an owner who lowered a number and
    // then raised it past the limit would find the low number gone.
    if let Some(problem) = refused_ceiling(&edited.document.ceilings, limits) {
        return Err(ControllerError::Configuration(problem));
    }
    write(paths, &edited)?;
    Ok(AppliedEdit {
        applied: Applied {
            revision: edited.revision,
            effect: edited.effect,
            invalidated: change.invalidates(),
            fences_dispatch: change.affects_authority(),
            authority_revision: None,
            // Nothing was fenced here, so nothing is outstanding. A change that does fence sets
            // both of these from the barrier the fence returned.
            barrier_holds: true,
            pending_workers: 0,
        },
        lock,
    })
}

/// Returns why a document's ceilings would not be applied as written, when one would not.
fn refused_ceiling(
    ceilings: &kr_protocol::hostinfo::configuration::ConfigurationCeilings,
    limits: HardLimits,
) -> Option<String> {
    let sessions = ceilings::session_limit(ceilings, limits);
    if sessions.refused {
        return Some(format!(
            "a session number of {} is more permissive than what is in force: {}",
            sessions
                .configured
                .map_or_else(|| "none".to_owned(), |asked| asked.to_string()),
            sessions
                .narrowed_by
                .unwrap_or_else(|| "this host's own limit".to_owned())
        ));
    }
    let enrolment = ceilings::enrolment(ceilings);
    if enrolment.refused {
        return Some(enrolment.narrowed_by.unwrap_or_else(|| {
            "this enrolment budget is more permissive than section 11 allows".to_owned()
        }));
    }
    None
}

/// Writes an edit whose base revision is still the one on disk.
fn write(paths: &EnvironmentPaths, edited: &Edited) -> Result<()> {
    // Read again, here, rather than trusting the read the edit was built from. Between the two a
    // second writer may have applied its own edit, and writing over it would lose a choice
    // somebody made rather than change one.
    configuration::still_current(edited, &kr_worker::config::load(paths)).map_err(refused)?;
    let path = kr_worker::config::document_path(paths);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    kr_ipc::paths::write_owner_only_file(&path, edited.contents.as_bytes())
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
) -> EffectiveConfiguration {
    let ceilings = resolver.ceilings();
    let power = resolver.sleep_inhibition(None);
    let profile = resolver.worker_profile(None, platform_profile);
    let runtime = resolver.runtime_directory();
    let state = resolver.state_directory();
    let values: Vec<EffectiveValue> = vec![
        effective_value(&power, power.value.as_str().to_owned()),
        effective_value(&profile, profile.value.as_str().to_owned()),
        effective_value(&runtime, runtime.value.clone()),
        effective_value(&state, state.value.clone()),
    ];
    let sessions = ceilings::session_limit(&ceilings, limits);
    let enrolment = ceilings::enrolment(&ceilings);
    let rights = ceilings::configured_rights(&ceilings);

    let doc_path = resolver.document().display().to_string();
    let session_source = if ceilings.session_limit.is_present() {
        configuration::ValueSource::HostConfiguration
    } else {
        configuration::ValueSource::Default
    };
    let session_origin = if ceilings.session_limit.is_present() {
        Some(doc_path.clone())
    } else {
        None
    };

    let enrolment_source = if ceilings.enrolment.is_present() {
        configuration::ValueSource::HostConfiguration
    } else {
        configuration::ValueSource::Default
    };
    let enrolment_origin = if ceilings.enrolment.is_present() {
        Some(doc_path.clone())
    } else {
        None
    };

    let rights_source = if ceilings.grant_rights.is_present() {
        configuration::ValueSource::HostConfiguration
    } else {
        configuration::ValueSource::Default
    };
    let rights_origin = if ceilings.grant_rights.is_present() {
        Some(doc_path)
    } else {
        None
    };
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
            ceilings::report(
                "session_limit",
                &sessions,
                session_source,
                session_origin,
                configuration::ValueEffect::Immediately,
                u64::to_string,
            ),
            ceilings::report(
                "enrolment",
                &enrolment,
                enrolment_source,
                enrolment_origin,
                configuration::ValueEffect::Immediately,
                |budgets| {
                    format!(
                        "{} metadata bytes, {} entries, {} generations retained, {} cached payload \
                         bytes, {} per package, {} objects, {} expanded, {} per transfer, {} ms to \
                         compile{}",
                        budgets.metadata_bytes,
                        budgets.metadata_entries,
                        budgets.retained_generations,
                        budgets.cached_payload_bytes,
                        budgets.package_bytes,
                        budgets.object_count,
                        budgets.expanded_pack_bytes,
                        budgets.transfer_bytes,
                        budgets.compilation_ms,
                        if budgets.full_offline_mirror {
                            ", full offline mirror"
                        } else {
                            ""
                        }
                    )
                },
            ),
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
                source: rights_source,
                origin: kr_protocol::scalars::Nullable(rights_origin),
                effect: configuration::ValueEffect::Immediately,
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
    let wrong = status.state.is_a_problem() || !effective.stale_documents.is_empty();
    checks.push(DoctorCheck::new(
        "configuration-document",
        "This host's configuration document",
        // A warning rather than a pass, so the default output prints the line. A stale document
        // the owner still believes is doing something is exactly what a person needs told, and
        // evidence only a `--verbose` run shows is evidence nobody reads.
        if wrong {
            DoctorStatus::Warning
        } else {
            DoctorStatus::Ok
        },
        detail,
        wrong.then(|| {
            if status.state.is_a_problem() {
                "Every value is the product default while this document cannot be used. It is \
                 left exactly as it is: nothing here rewrites it."
                    .to_owned()
            } else {
                "That document has no effect. Remove it once you have moved anything you still \
                 want into the configuration above."
                    .to_owned()
            }
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
    let ungoverned = configuration::ungoverned_here();
    let authority_reaching: Vec<&str> = ungoverned
        .iter()
        .filter(|entry| entry.reaches_authority)
        .map(|entry| entry.variable)
        .collect();
    checks.push(DoctorCheck::new(
        "configuration-overrides",
        "Which environment variables participate",
        // A variable that selects a provider origin or the owner signer is a warning wherever it
        // is set, because section 26 says an inherited variable may not reach either. Saying so is
        // what a diagnostic is for; saying nothing would make the line above it untrue.
        if authority_reaching.is_empty() {
            DoctorStatus::Ok
        } else {
            DoctorStatus::Warning
        },
        format!(
            "{}; set here: {}. No other inherited variable takes part in the precedence. This \
             build also reads {} outside it: {}",
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
            },
            configuration::UNGOVERNED.len(),
            if ungoverned.is_empty() {
                "none of them is set here".to_owned()
            } else {
                ungoverned
                    .iter()
                    .map(|entry| format!("{} selects {}", entry.variable, entry.selects))
                    .collect::<Vec<_>>()
                    .join("; ")
            }
        ),
        (!authority_reaching.is_empty()).then(|| {
            format!(
                "{} selects a provider origin or the owner signing key from this process's \
                 environment. Start this host without it and choose the same thing through its \
                 own configuration or its pairing record.",
                authority_reaching.join(", ")
            )
        }),
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

/// Returns the session number this host admits against, when the configuration names one.
///
/// `None` means the document says nothing about it, and nothing here changes what the environment
/// already admits against. A document this host cannot use says nothing either: a restriction an
/// owner accepted must not be lifted because a later build could not read the file it was in.
#[must_use]
pub fn configured_session_limit(resolver: &Resolver, limits: HardLimits) -> Option<u64> {
    if resolver.status().state.is_a_problem() {
        return None;
    }
    let ceilings = resolver.ceilings();
    ceilings
        .session_limit
        .is_present()
        .then(|| ceilings::session_limit(&ceilings, limits).value)
}

#[cfg(test)]
mod tests;
