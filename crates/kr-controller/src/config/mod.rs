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
//! * **The report** ([`effective`]). Each value, its source and whether it applies immediately,
//!   only to new sessions or at the next start, which is what `kr doctor` prints and what a support
//!   bundle carries.
//! * **What the daemon started with** ([`Started`], [`network_check`]). The network section and the
//!   voice broker's origin are read once, when the daemon starts, from this document and from
//!   nothing a process inherited; the check says what is in force and whether an edit waits for the
//!   next start.
//! * **The catalogue seam** ([`catalogue`]). The enrolment budgets and the shared capability
//!   evidence, defined here so a catalogue client fills them rather than inventing its own.

pub mod catalogue;
pub mod ceilings;

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::desktop::{CapabilityInvalidation, SleepInhibitionSetting};
use kr_protocol::hostinfo::configuration::{self, Change, EditRefused, Edited, ValueEffect};
use kr_protocol::hostinfo::export::{Declared, Sentence};
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

/// Returns one configuration document as this host records it.
///
/// The canonical contents of the parsed document rather than the bytes in the file, so a document
/// saved again with different spacing is the same document and a document whose meaning was changed
/// in place is a different one.
///
/// A document this build cannot use is recorded as none. It decides nothing, so there is nothing
/// for this host to have accepted.
#[must_use]
pub fn recorded(document: Option<&configuration::ConfigurationDocument>) -> Option<String> {
    document.map(configuration::contents)
}

/// Returns the document this environment last accepted, as its effects were derived from.
///
/// A record this build can no longer parse is read as no accepted document, which makes the next
/// acceptance derive everything the document on disk owes rather than nothing.
#[must_use]
pub fn from_record(recorded: Option<&str>) -> Option<configuration::ConfigurationDocument> {
    configuration::load(recorded.map(str::as_bytes)).document
}

/// One written edit, with the lock still held.
///
/// The lock outlives the write on purpose: the effects of the new document have to land before
/// another writer can prepare an edit of its own. Dropping this value releases the lock.
///
/// What the edit *did* is not here, because writing a document is not putting it into force. The
/// caller passes the written document through the one acceptance path, and what comes back from
/// that is [`Applied`].
#[derive(Debug)]
pub struct WrittenEdit {
    /// The revision now on disk.
    pub revision: u64,
    /// Whether it applies immediately or only to sessions created afterwards.
    pub effect: ValueEffect,
    /// The lock, held until this value is dropped.
    pub lock: configuration::EditLock,
}

/// What this host has accepted, and what its effects did.
///
/// One value carries both, which is the whole point of it: a report is built from this rather
/// than from a second reading of the document, so the number a person is shown and the number
/// admission enforces cannot be two different readings of the same file.
#[derive(Debug)]
pub struct Accepted {
    /// The configuration the effects below came from.
    pub resolver: Resolver,
    /// The session number admission enforces.
    pub sessions: Enforced,
    /// What this document owed beyond the registry write.
    pub owed: configuration::Owed,
    /// The fence this acceptance raised, when the document's authority ceiling moved.
    pub barrier: Option<kr_protocol::action::RevocationBarrier>,
    /// The revision whose fence this environment durably owes, read back from that record.
    ///
    /// Not derived from [`Self::barrier`]: a fence raised by a daemon that has since stopped is
    /// owed although nothing in this process raised it, and a fence raised here is owed although
    /// an effect after it failed. `None` means the durable record says every worker answered.
    pub fence_owed: Option<kr_protocol::ids::AuthorityRevision>,
    /// Whether every effect this document owed was applied.
    ///
    /// Apart from [`Self::not_in_force`], which also covers a host that applied the document and
    /// could not record that it had. That one leaves the values in force and costs one more
    /// acceptance at the next start; a failed *effect* leaves the document not acted on, and a
    /// fence it owed not raised.
    pub effects_applied: bool,
    /// Why the document is not in force, when something stopped it.
    ///
    /// A failure cannot be dropped on the floor here: it is part of the value every caller
    /// already has to hold, so the report says it and the edit path returns it.
    pub not_in_force: Option<Sentence>,
}

impl Accepted {
    /// Returns what this host's workers still owe the fence a ceiling here raised.
    ///
    /// `None` once every one of them has acknowledged it, which is what a completed revocation
    /// is. A revision that advanced is not one: a worker that has not answered still holds work
    /// admitted under the ceiling that was withdrawn.
    ///
    /// The answer is [`Self::fence_owed`], which is a reading of this environment's durable
    /// authority record. The barrier only supplies the names: an announcement this acceptance made
    /// knows which workers did not answer, and one made by a daemon that has since stopped does
    /// not, and a debt is owed either way.
    #[must_use]
    pub fn fence_outstanding(&self) -> Option<Sentence> {
        let revision = self.fence_owed?;
        let pending: Vec<kr_protocol::ids::SessionId> = self
            .barrier
            .as_ref()
            .filter(|barrier| !barrier.holds())
            .map(|barrier| barrier.pending().to_vec())
            .unwrap_or_default();
        let line = Sentence::new()
            .stated("authority revision ")
            .number(revision.get())
            .stated(" is in force for everything admitted from now on, and ");
        if pending.is_empty() {
            return Some(
                line.stated("this host's record of it has not been answered by every worker yet"),
            );
        }
        let mut line = line
            .number(pending.len() as u64)
            .stated(" of this host's workers have not acknowledged the fence yet (");
        for (index, session_id) in pending.iter().enumerate() {
            if index > 0 {
                line = line.stated(", ");
            }
            line = line.identifier(session_id);
        }
        Some(line.stated(")"))
    }

    /// The state of a host acting on exactly what this document says.
    ///
    /// What the daemon's acceptance comes to when every effect landed, and what a report built
    /// without one describes: one reading, nothing outstanding, and this document's own numbers
    /// in force.
    #[must_use]
    pub fn in_force(resolver: Resolver, limits: HardLimits) -> Self {
        let sessions = session_limit_in_force(&resolver, limits).map_or(
            Enforced {
                value: kr_protocol::limits::DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT as u64,
                from_document: false,
            },
            |value| Enforced {
                value,
                from_document: true,
            },
        );
        Self {
            resolver,
            sessions,
            owed: configuration::Owed::default(),
            barrier: None,
            fence_owed: None,
            effects_applied: true,
            not_in_force: None,
        }
    }
}

/// The session number admission enforces, and where it came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Enforced {
    /// The number admission enforces right now.
    pub value: u64,
    /// True when the document this report describes is what decided it.
    ///
    /// A document that is absent, one this build cannot read and one whose effects failed all
    /// leave the restriction the owner accepted exactly where it was, and then this is false and
    /// the number is the retained one. Reporting the product default in that case would print a
    /// number nothing is enforcing.
    pub from_document: bool,
}

/// What this daemon last accepted, so the next acceptance can tell what moved.
#[derive(Clone, Debug, Default)]
pub struct AcceptedState {
    /// The revision whose effects are in force.
    pub revision: u64,
    /// The document those effects came from, when this host could use one.
    pub document: Option<configuration::ConfigurationDocument>,
    /// The session number admission enforces because of it.
    ///
    /// Written as soon as the registry takes it, before the effects after it are attempted, so a
    /// later failure cannot leave this describing a number admission has stopped enforcing.
    pub sessions: u64,
}

/// The ordinary preferences in force, for the effects that act on them.
///
/// A preference takes effect by being read, and the things that read one - the sleep inhibitor,
/// the desktop reading a session is created in - run outside the acceptance that decided it. This
/// is the value they read, written from the document that was accepted, so an effect acts on the
/// reading the report describes rather than on a second reading taken a moment later.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InForce {
    /// Whether this host keeps itself awake for work it has admitted, and on which power source.
    pub sleep_inhibition: SleepInhibitionSetting,
    /// The execution context a session is created in, where the configuration chooses one.
    ///
    /// The product default is the platform's own answer, which is established when the desktop is
    /// read rather than here, so this is the choice above it rather than the resolved value.
    pub worker_profile: Option<WorkerProfile>,
}

impl InForce {
    /// Reads both preferences from one configuration.
    #[must_use]
    pub fn of(resolver: &Resolver) -> Self {
        Self {
            sleep_inhibition: resolver.sleep_inhibition(None).value,
            worker_profile: resolver.chosen_worker_profile(),
        }
    }
}

/// The selections this daemon read when it started, which are what it acts on until it next starts.
///
/// The network endpoint and the voice service are built once, at startup, from the document on disk
/// then. A later edit applies at the next start, and `kr doctor` compares the two so an owner who
/// changed one can see that it is not in force yet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Started {
    /// The network section this daemon joined, or did not join, the network under.
    pub network: configuration::NetworkSelection,
    /// The voice broker this daemon names to its paired devices.
    pub voice: configuration::VoiceSelection,
}

impl Started {
    /// Reads both selections from one document, or the defaults of selecting nothing when this
    /// host cannot use the document it found.
    #[must_use]
    pub fn of(document: Option<&configuration::ConfigurationDocument>) -> Self {
        document.map_or_else(Self::default, |document| Self {
            network: document.network.clone(),
            voice: document.voice.clone(),
        })
    }
}

/// What one applied edit did.
///
/// Every field but the first two is what the acceptance path observed, not what the request
/// intended: a change that names the value the document already held fences nothing and
/// invalidates nothing, and this says so.
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
    /// True when this change moved the authority ceiling, so dispatch was fenced before it was
    /// acknowledged.
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
/// Putting the written document into force is the caller's, because every effect needs the running
/// daemon, and it happens through the one acceptance path an externally edited document also takes
/// rather than through a second one built from the request.
///
/// # Errors
///
/// Returns [`ControllerError::Configuration`] when the document may not be edited, when the result
/// does not validate, or when another writer moved the revision first.
pub fn apply(paths: &EnvironmentPaths, change: &Change, limits: HardLimits) -> Result<WrittenEdit> {
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
        return Err(ControllerError::Configuration(problem.render()));
    }
    write(paths, &edited)?;
    Ok(WrittenEdit {
        revision: edited.revision,
        effect: edited.effect,
        lock,
    })
}

/// Returns why a document's ceilings would not be applied as written, when one would not.
fn refused_ceiling(
    ceilings: &kr_protocol::hostinfo::configuration::ConfigurationCeilings,
    limits: HardLimits,
) -> Option<Sentence> {
    let sessions = ceilings::session_limit(ceilings, limits);
    if sessions.refused {
        let mut line = Sentence::new().stated("a session number of ");
        line = match sessions.configured {
            Some(asked) => line.number(asked),
            None => line.stated("none"),
        };
        let line = line.stated(" is more permissive than what is in force: ");
        return Some(match sessions.narrowed_by {
            Some(why) => line.sentence(&why),
            None => line.stated("this host's own limit"),
        });
    }
    let enrolment = ceilings::enrolment(ceilings);
    if enrolment.refused {
        return Some(enrolment.narrowed_by.unwrap_or_else(|| {
            Sentence::new()
                .stated("this enrolment budget is more permissive than section 11 allows")
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

/// Returns one reported location: the rule this platform follows, or the variable that replaced it.
/// An environment whose state directory was named by `KR_STATE_DIR` keeps its document inside that
/// directory on every platform, so `chosen_by_variable` is what decides whether the documented rule
/// still describes where a file is.
fn location(
    what: &'static str,
    chosen_by_variable: bool,
    documented: &'static str,
) -> kr_protocol::hostinfo::ReportedLocation {
    kr_protocol::hostinfo::ReportedLocation {
        what: what.to_owned(),
        documented: kr_protocol::hostinfo::export::Stated::new(if chosen_by_variable {
            configuration::DOCUMENTED_BY_VARIABLE
        } else {
            documented
        }),
    }
}

/// Builds the effective-value report for one environment.
///
/// Every ordinary preference with its source and its effect, every ceiling with what narrowed it,
/// the precedence ladder in order, the documented overrides, the secure-store references by name,
/// and any document beside this one that this build no longer reads.
#[must_use]
pub fn effective(
    accepted: &Accepted,
    limits: HardLimits,
    platform_profile: WorkerProfile,
) -> EffectiveConfiguration {
    let resolver = &accepted.resolver;
    let ceilings = resolver.ceilings();
    let power = resolver.sleep_inhibition(None);
    let profile = resolver.worker_profile(None, platform_profile);
    let runtime = resolver.runtime_directory();
    let state = resolver.state_directory();
    // Each row carries what its value is made of. The two settings resolve to one of this build's
    // own words; the two directories resolve to a path this host composed from a home directory,
    // an environment variable or an owner's own choice, and a path is not this build's to publish
    // to anybody but the owner.
    let mut values: Vec<EffectiveValue> = vec![
        effective_value(&power, &Declared::term(power.value.as_str())),
        effective_value(&profile, &Declared::term(profile.value.as_str())),
        effective_value(
            &runtime,
            &Declared::path(std::path::Path::new(&runtime.value)),
        ),
        effective_value(&state, &Declared::path(std::path::Path::new(&state.value))),
    ];
    // The network and the voice broker: what the document selects, where it said so, and that it
    // applies at the next start. A location and a path are each declared as what they are, so the
    // owner reading their own report sees the address and an export carries its class and length.
    values.extend(configuration::selection_rows(
        resolver.loaded().document.as_ref(),
        &resolver.document().display().to_string(),
    ));
    // What the document asks for, narrowed by what this machine allows, and then replaced by the
    // number admission is actually enforcing. The two are the same on an ordinary host; where they
    // differ - an unusable document, or effects that failed - the report prints the one in force
    // and says why it is not the one written down.
    let sessions = ceilings::enforced(
        ceilings::session_limit(&ceilings, limits),
        accepted.sessions,
    );
    let enrolment = ceilings::enrolment(&ceilings);
    let rights = ceilings::configured_rights(&ceilings);

    let doc_path = resolver.document().display().to_string();
    let (session_source, session_origin) = if !accepted.sessions.from_document {
        // The document in front of this report did not decide the number. Saying it came from the
        // host configuration would name the wrong document; saying it is the product default
        // would be a number nothing is enforcing.
        (
            if sessions.value == kr_protocol::limits::DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT as u64 {
                configuration::ValueSource::Default
            } else {
                configuration::ValueSource::HostConfiguration
            },
            None,
        )
    } else if ceilings.session_limit.is_present() {
        (
            configuration::ValueSource::HostConfiguration,
            Some(doc_path.clone()),
        )
    } else {
        (configuration::ValueSource::Default, None)
    };

    // An enrolment section may name one budget and leave the other nine out, so "the document
    // supplied this" is per budget rather than per section, and it is presence that answers it: a
    // budget written with the number the schema already uses was still chosen by whoever wrote it.
    let supplied_budgets = ceilings
        .enrolment
        .as_ref()
        .map(configuration::ConfiguredEnrolmentBudgets::supplied)
        .unwrap_or_default();
    let enrolment_source = if supplied_budgets.is_empty() {
        configuration::ValueSource::Default
    } else {
        configuration::ValueSource::HostConfiguration
    };
    let enrolment_origin = (!supplied_budgets.is_empty()).then(|| doc_path.clone());

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
        runtime_directory: runtime.value.clone(),
        state_directory: state.value.clone(),
        // The rule this platform follows, not one account's answer to it. A location an
        // allowlisted variable chose says so instead, because there is no rule left to quote.
        locations: vec![
            location(
                "document",
                state.variable.is_some(),
                configuration::DOCUMENTED_DOCUMENT,
            ),
            location(
                "runtime_directory",
                runtime.variable.is_some(),
                configuration::DOCUMENTED_RUNTIME_ROOT,
            ),
            location(
                "state_directory",
                state.variable.is_some(),
                configuration::DOCUMENTED_STATE_ROOT,
            ),
        ],
        precedence: configuration::PRECEDENCE
            .iter()
            .map(|source| kr_protocol::hostinfo::export::Stated::new(source.describe()))
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
                |limit| Sentence::new().number(*limit),
            ),
            ceilings::report(
                "enrolment",
                &enrolment,
                enrolment_source,
                enrolment_origin,
                configuration::ValueEffect::Immediately,
                |budgets| {
                    let mut line = Sentence::new()
                        .number(budgets.metadata_bytes)
                        .stated(" metadata bytes, ")
                        .number(budgets.metadata_entries)
                        .stated(" entries, ")
                        .number(budgets.retained_generations)
                        .stated(" generations retained, ")
                        .number(budgets.cached_payload_bytes)
                        .stated(" cached payload bytes, ")
                        .number(budgets.package_bytes)
                        .stated(" per package, ")
                        .number(budgets.object_count)
                        .stated(" objects, ")
                        .number(budgets.expanded_pack_bytes)
                        .stated(" expanded, ")
                        .number(budgets.transfer_bytes)
                        .stated(" per transfer, ")
                        .number(budgets.compilation_ms)
                        .stated(" ms to compile");
                    if budgets.full_offline_mirror {
                        line = line.stated(", full offline mirror");
                    }
                    // Which of the ten this host's configuration chose, so one budget raised in a
                    // document cannot read as ten budgets the owner set.
                    if supplied_budgets.is_empty() {
                        line.stated("; every budget is the default")
                    } else {
                        line.stated("; configured here: ")
                            .terms(supplied_budgets.iter().copied(), ", ")
                    }
                },
            ),
            kr_protocol::hostinfo::CeilingValue {
                key: "grant_rights".to_owned(),
                configured: kr_protocol::scalars::Nullable(rights.as_ref().map(|rights| {
                    Sentence::new().terms(rights.iter().map(|right| right.as_str()), ", ")
                })),
                value: rights.as_ref().map_or_else(
                    || Sentence::new().stated("every right the grant and the host policy allow"),
                    |rights| Sentence::new().terms(rights.iter().map(|right| right.as_str()), ", "),
                ),
                source: rights_source,
                origin: kr_protocol::scalars::Nullable(rights_origin),
                effect: configuration::ValueEffect::Immediately,
                narrowed_by: kr_protocol::scalars::Nullable(rights.as_ref().map(|_| {
                    Sentence::new().stated(
                        "the grant and the host policy are intersected first; this ceiling only \
                         removes rights",
                    )
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
        not_in_force: kr_protocol::scalars::Nullable(accepted.not_in_force.clone()),
        fence_outstanding: kr_protocol::scalars::Nullable(accepted.fence_outstanding()),
    }
}

/// The diagnostics this host's configuration contributes.
///
/// Five checks, each with the evidence `kr doctor --verbose` prints: where the document is and
/// what it turned out to be, whether this host put it into force, the precedence order and the
/// locations, the documented overrides and which of them are set, and the ceilings with what
/// narrowed them. A stale document beside the configuration is one line inside the first of them.
#[must_use]
pub fn checks(effective: &EffectiveConfiguration) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let status = &effective.status;
    let mut detail = Sentence::new()
        .field("EffectiveConfiguration", "document", &effective.document)
        .stated(": ")
        .stated_value(&status.detail);
    for stale in &effective.stale_documents {
        detail = detail
            .stated("; ")
            .field("EffectiveConfiguration", "stale_documents", stale)
            .stated(" is a document this build no longer reads and is ignored");
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
        wrong.then_some(if status.state.is_a_problem() {
            "Every ordinary preference is the product default while this document cannot be used, \
             and every restriction this host already enforces stays in force. The file is left \
             exactly as it is: nothing here rewrites it."
        } else {
            "That document has no effect. Remove it once you have moved anything you still want \
             into the configuration above."
        }),
    ));
    // Whether the values below are what this host is acting on. A report that described a
    // document nothing is enforcing would be worse than no report, so this says which it is.
    checks.push(DoctorCheck::new(
        "configuration-in-force",
        "This host is acting on the configuration it reports",
        // Three answers, because there are three states. The values do not describe what is
        // enforced: a failure. They do, and a worker has not yet acknowledged the fence one of
        // them raised: worth knowing, and not a failure, because everything admitted from now on
        // is under the new ceiling. Neither: a pass.
        if effective.not_in_force.is_present() {
            DoctorStatus::Failed
        } else if effective.fence_outstanding.is_present() {
            DoctorStatus::Warning
        } else {
            DoctorStatus::Ok
        },
        match effective
            .not_in_force
            .as_ref()
            .map(|problem| ("not_in_force", problem))
            .or_else(|| {
                effective
                    .fence_outstanding
                    .as_ref()
                    .map(|pending| ("fence_outstanding", pending))
            }) {
            Some((_, line)) => Sentence::new().stated_value(line),
            None => Sentence::new()
                .stated("revision ")
                .number(effective.revision.get())
                .stated(" is in force; every value below is the one this host acts on"),
        },
        if effective.not_in_force.is_present() {
            Some(
                "The values below are what this host is enforcing, not what the document asks \
                 for. Fix what the line above names and run this again.",
            )
        } else if effective.fence_outstanding.is_present() {
            Some(
                "A revocation is complete for a worker once it acknowledges the revision or is \
                 confirmed ended. Nothing here has to be repeated: this host asks again each time \
                 it reads its configuration.",
            )
        } else {
            None
        },
    ));
    let mut precedence = Sentence::new();
    for (index, rung) in effective.precedence.iter().enumerate() {
        if index > 0 {
            precedence = precedence.stated(", then ");
        }
        precedence = precedence.stated_value(rung);
    }
    for location in &effective.locations {
        precedence = precedence
            .stated("; ")
            .field("ReportedLocation", "what", &location.what)
            .stated(" ")
            .stated_value(&location.documented);
    }
    checks.push(DoctorCheck::new(
        "configuration-precedence",
        "Where each effective value comes from",
        DoctorStatus::Ok,
        precedence,
        None,
    ));
    let set: Vec<&str> = effective
        .overrides
        .iter()
        .filter(|entry| entry.set)
        .map(|entry| entry.variable.as_str())
        .collect();
    let ungoverned = configuration::ungoverned_here();
    let mut overrides = Sentence::new();
    for (index, entry) in effective.overrides.iter().enumerate() {
        if index > 0 {
            overrides = overrides.stated("; ");
        }
        overrides = overrides
            .field("OverrideReport", "variable", &entry.variable)
            .stated(" supplies ")
            .field("OverrideReport", "preference", &entry.preference)
            .stated(" as ")
            .stated(entry.position.describe());
    }
    overrides = overrides.stated("; set here: ");
    overrides = if set.is_empty() {
        overrides.stated("none")
    } else {
        overrides.terms(set.iter().copied(), ", ")
    };
    overrides = overrides
        .stated(
            ". No other inherited variable takes part in the precedence. This build also \
                 reads ",
        )
        .number(configuration::UNGOVERNED.len() as u64)
        .stated(" outside it: ");
    overrides = if ungoverned.is_empty() {
        overrides.stated("none of them is set here")
    } else {
        let mut line = overrides;
        for (index, entry) in ungoverned.iter().enumerate() {
            if index > 0 {
                line = line.stated("; ");
            }
            line = line
                .term(entry.variable)
                .stated(" selects ")
                .stated(entry.selects);
        }
        line
    };
    checks.push(DoctorCheck::new(
        "configuration-overrides",
        "Which environment variables participate",
        // What is read outside the precedence is the platform's naming of its locations and its
        // login. Every provider origin this host uses is its configuration document's, and its
        // owner is recorded by pairing, so no inherited variable here reaches authority.
        DoctorStatus::Ok,
        overrides,
        None,
    ));
    let refused: Vec<&str> = effective
        .ceilings
        .iter()
        .filter(|ceiling| ceiling.refused)
        .map(|ceiling| ceiling.key.as_str())
        .collect();
    let mut ceilings = Sentence::new();
    for (index, ceiling) in effective.ceilings.iter().enumerate() {
        if index > 0 {
            ceilings = ceilings.stated("; ");
        }
        ceilings = ceilings
            .field("CeilingValue", "key", &ceiling.key)
            .stated(" is ")
            .stated_value(&ceiling.value);
        if let Some(why) = ceiling.narrowed_by.as_ref() {
            ceilings = ceilings.stated(" (").stated_value(why).stated(")");
        }
    }
    checks.push(DoctorCheck::new(
        "configuration-ceilings",
        "Ceilings intersect; they are not defaults a flag can raise",
        if refused.is_empty() {
            DoctorStatus::Ok
        } else {
            DoctorStatus::Warning
        },
        ceilings,
        (!refused.is_empty()).then_some(
            "A configured ceiling was more permissive than what is in force and was refused. \
             Lower it, or ask for the explicit setting the limit names.",
        ),
    ));
    checks
}

/// Whether this host is acting on the network and voice broker its configuration selects.
///
/// Both are read once, when the daemon starts, so what is in force is what it started with, and
/// this check says what that was: whether it joined the network, how many sockets its endpoint
/// holds and how many services it selected, and whether it names a managed voice broker to its
/// devices. When the document now selects something else, the check warns that the edit applies
/// at the next start, rather than leaving an owner to wonder why nothing changed.
///
/// `document` is the document the rest of the report was read from, and `bound_sockets` how many
/// sockets the endpoint holds, which is zero on a host that is not on the network.
#[must_use]
pub fn network_check(
    started: &Started,
    document: Option<&configuration::ConfigurationDocument>,
    bound_sockets: usize,
) -> DoctorCheck {
    let network = &started.network;
    let mut detail = if network.joins() {
        let discovery = [
            network.pkarr_publisher_url().is_some(),
            network.pkarr_resolver_url().is_some(),
            network.dns_origin().is_some(),
            network.local_discovery(),
            network.mainline_dht(),
        ]
        .into_iter()
        .filter(|selected| *selected)
        .count();
        Sentence::new()
            .stated("this host joined the network when it started: its endpoint holds ")
            .number(bound_sockets as u64)
            .stated(" sockets, with ")
            .number(network.relay_urls().len() as u64)
            .stated(" relays and ")
            .number(discovery as u64)
            .stated(" discovery services selected")
    } else {
        Sentence::new().stated(
            "this host selected no network when it started, and serves its local endpoint alone",
        )
    };
    detail = detail.stated(if started.voice.broker_origin().is_some() {
        "; it names a managed voice broker to its paired devices"
    } else {
        "; it names no managed voice broker"
    });
    // Compared with what the document says now. A document this host cannot use selects nothing,
    // which is also what an owner who wrote no network section is told.
    let moved = Started::of(document) != *started;
    if moved {
        detail = detail.stated(
            "; the configuration document now selects a different network or voice broker, which \
             applies at the next start",
        );
    }
    DoctorCheck::new(
        "configuration-network",
        "This host started with the network and voice broker its configuration selects",
        if moved {
            DoctorStatus::Warning
        } else {
            DoctorStatus::Ok
        },
        detail,
        moved.then_some(
            "Restart this host to put the network and voice broker the document now selects into \
             force.",
        ),
    )
}

/// The secure-store references this configuration names, as one line for a diagnostic.
///
/// Names only: the store and the item, never a value. There is no field in the schema a value
/// would fit in, so this cannot print one however it is called.
#[must_use]
pub fn secret_line(effective: &EffectiveConfiguration) -> Sentence {
    if effective.secrets.is_empty() {
        return Sentence::new().stated("no secure-store references are configured");
    }
    // A reference is three names a person wrote, and a name is where an owner who did not read
    // section 26 put the secret itself. What the line says is how many there are and how long each
    // one is; the store holds the names it was given and nothing here changes them.
    let mut line = Sentence::new()
        .number(effective.secrets.len() as u64)
        .stated(" secure-store references are configured: ");
    for (index, reference) in effective.secrets.iter().enumerate() {
        if index > 0 {
            line = line.stated("; ");
        }
        line = line
            .field("SecretReference", "name", &reference.name)
            .stated(" is ")
            .field("SecretReference", "item", &reference.item)
            .stated(" in ")
            .field("SecretReference", "store", &reference.store);
    }
    line
}

/// Returns this host's sleep policy as the configuration resolves it.
///
/// The one reader the power module and the diagnostics both use, so the setting and the report
/// about it can never disagree.
#[must_use]
pub fn sleep_inhibition(paths: &EnvironmentPaths) -> SleepInhibitionSetting {
    Resolver::open(paths).sleep_inhibition(None).value
}

/// Returns the session number a document puts in force, when it decides one.
///
/// A document this host can use decides it whether it names a number or leaves it to the product
/// default: both are things the document says, and an owner who removes a ceiling has removed it.
///
/// `None` is a document that decides nothing at all - one that is absent, and one this build
/// cannot read. Then the number the environment already admits against stays exactly as it is: a
/// restriction an owner accepted must not be lifted because a later build could not read the file
/// it was in.
///
/// One rule, used by the daemon's startup and by every acceptance after it, so a restart can
/// never put a different number in force from the one a running daemon would.
#[must_use]
pub fn session_limit_in_force(resolver: &Resolver, limits: HardLimits) -> Option<u64> {
    if resolver.status().state != configuration::DocumentState::Loaded {
        return None;
    }
    Some(ceilings::session_limit(&resolver.ceilings(), limits).value)
}

#[cfg(test)]
mod tests;
