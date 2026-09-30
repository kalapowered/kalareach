//! The catalogue's side of this host's configuration and its capability evidence.
//!
//! Two things section 11 names belong to configuration rather than to the catalogue client, and
//! both are defined here so the catalogue fills them rather than inventing a second copy.
//!
//! * **The enrolment budgets.** "Repository enrolment sets explicit metadata, generation,
//!   package/asset, object-count, expanded-pack, retained-generation, transfer and compilation
//!   budgets before fetching." They are a section of the configuration document, they are
//!   intersected like every other ceiling, and [`budgets`] is what a catalogue client reads to get
//!   the numbers in force on this host.
//! * **The shared capability evidence.** "`kr doctor`, launch buttons and disabled-action UI read
//!   this shared evidence." The doctor's side of that is [`check`], which answers from the evidence
//!   the catalogue gives when the doctor asks (`crate::catalogue::evidence`).
//!
//! With no repository enrolled [`check`] says "no catalogue is synchronised on this host" and
//! claims no evidence. A check that reported a healthy catalogue because there was nothing to
//! disagree with would be worse than no check.

use kr_protocol::desktop::CapabilityRecord;
use kr_protocol::hostinfo::configuration::EnrolmentBudgets;
use kr_protocol::hostinfo::export::{ContentClass, Sentence};
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};

/// The stable identifier of the catalogue check.
pub const CHECK_ID: &str = "catalogue";

/// What this host says while nothing has synchronised a catalogue.
pub const NOT_SYNCHRONISED: &str = "no catalogue is synchronised on this host";

/// One enrolled repository, as the diagnostics and the support bundle report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepositoryEvidence {
    /// What this host calls the repository.
    pub name: String,
    /// The metadata generation currently activated.
    pub generation: u64,
    /// How much of the metadata budget the activated generation uses, in bytes.
    pub metadata_bytes: u64,
    /// How many index entries it has.
    pub metadata_entries: u64,
    /// How much of the payload budget its cached payloads use, in bytes.
    pub cached_payload_bytes: u64,
    /// The capability records this repository's packages contribute, in the shared section 11
    /// shape.
    pub capabilities: Vec<CapabilityRecord>,
    /// What a person is told about this repository's current state.
    pub detail: String,
    /// True when something about this repository needs attention.
    pub degraded: bool,
}

/// What a synchronised catalogue tells this host about itself.
///
/// This is the seam. A catalogue client implements it, the controller holds one, and `kr doctor`
/// and the support bundle read the shared evidence through it rather than through a second
/// vocabulary of their own. Implementations report what they have; they never decide what the
/// check says about it.
pub trait CatalogueEvidence: Send + Sync + std::fmt::Debug {
    /// The repositories this host has enrolled, in the order the catalogue lists them.
    fn repositories(&self) -> Vec<RepositoryEvidence>;

    /// What a person should know beyond the repositories: each package a worker said it would not
    /// read or bind, with its session and reason, and each set of admissions this host could not
    /// hand over. The words come from the workers and the catalogue, not from this build.
    fn warnings(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Returns the enrolment budgets in force on this host.
///
/// A catalogue client calls this instead of carrying its own defaults, so one document answers
/// what a repository may cost here and `kr doctor` reports the same numbers the fetch enforces.
#[must_use]
pub fn budgets(
    ceilings: &kr_protocol::hostinfo::configuration::ConfigurationCeilings,
) -> EnrolmentBudgets {
    super::ceilings::enrolment(ceilings).value
}

/// Returns the enrolment budgets a reading of this host's configuration puts in force, or `None`
/// when it decides nothing.
///
/// The rule the session number follows (`super::session_limit_in_force`): a document this host
/// loaded decides the budgets, whether it names them or leaves them to the defaults; one that is
/// absent, unreadable, of a version this build does not know or invalid decides nothing, and the
/// budgets already in force stay as they are. So no budget from a document the daemon did not
/// accept is ever in force. One rule for the daemon's startup and every acceptance after it.
#[must_use]
pub fn budgets_in_force(resolver: &kr_worker::config::Resolver) -> Option<EnrolmentBudgets> {
    if resolver.status().state != kr_protocol::hostinfo::configuration::DocumentState::Loaded {
        return None;
    }
    Some(budgets(&resolver.ceilings()))
}

/// Returns the disable policy a reading of this host's configuration puts in force, or `None`
/// when it decides nothing.
///
/// The rule the enrolment budgets follow: a document this host loaded decides the policy, whether
/// it names one or leaves it to the default, which is warning only; one that is absent,
/// unreadable, of a version this build does not know or invalid decides nothing, and the policy
/// already in force stays as it is. One rule for the daemon's startup and every acceptance after
/// it.
#[must_use]
pub fn disable_policy_in_force(
    resolver: &kr_worker::config::Resolver,
) -> Option<kr_protocol::admission::RevocationPolicy> {
    if resolver.status().state != kr_protocol::hostinfo::configuration::DocumentState::Loaded {
        return None;
    }
    Some(super::ceilings::disable_policy(&resolver.ceilings()).value)
}

/// Builds the catalogue diagnostic from whatever evidence is registered.
///
/// With no source it is `NotApplicable` with the reason stated, because a host that has never
/// synchronised a catalogue has nothing to be healthy or unhealthy about. With a source it reports
/// each repository, its generation and what its metadata and payloads cost against the budgets in
/// force.
#[must_use]
pub fn check(source: Option<&dyn CatalogueEvidence>, budgets: EnrolmentBudgets) -> DoctorCheck {
    let Some(source) = source else {
        return DoctorCheck::new(
            CHECK_ID,
            "Catalogue metadata and its capability evidence",
            DoctorStatus::NotApplicable,
            Sentence::new().stated(NOT_SYNCHRONISED),
            None,
        );
    };
    let repositories = source.repositories();
    let warnings = source.warnings();
    if repositories.is_empty() && warnings.is_empty() {
        return DoctorCheck::new(
            CHECK_ID,
            "Catalogue metadata and its capability evidence",
            DoctorStatus::NotApplicable,
            Sentence::new().stated(NOT_SYNCHRONISED),
            None,
        );
    }
    let degraded =
        !warnings.is_empty() || repositories.iter().any(|repository| repository.degraded);
    // A repository's name and the sentence its synchronisation produced both come from the
    // catalogue rather than from this build, so each one contributes its class and its length. The
    // numbers are this host's own measurements and the budgets are its own configuration.
    let mut detail = Sentence::new();
    for (index, repository) in repositories.iter().enumerate() {
        if index > 0 {
            detail = detail.stated("; ");
        }
        detail = detail
            .withheld(ContentClass::Name, &repository.name)
            .stated(" generation ")
            .number(repository.generation)
            .stated(": ")
            .number(repository.metadata_bytes)
            .stated(" of ")
            .number(budgets.metadata_bytes)
            .stated(" metadata bytes, ")
            .number(repository.metadata_entries)
            .stated(" of ")
            .number(budgets.metadata_entries)
            .stated(" entries, ")
            .number(repository.cached_payload_bytes)
            .stated(" of ")
            .number(budgets.cached_payload_bytes)
            .stated(" cached payload bytes; ")
            .withheld(ContentClass::Message, &repository.detail);
    }
    for (index, warning) in warnings.iter().enumerate() {
        if index > 0 || !repositories.is_empty() {
            detail = detail.stated("; ");
        }
        detail = detail.withheld(ContentClass::Message, warning);
    }
    DoctorCheck::new(
        CHECK_ID,
        "Catalogue metadata and its capability evidence",
        if degraded {
            DoctorStatus::Warning
        } else {
            DoctorStatus::Ok
        },
        detail,
        degraded.then_some(
            "A repository that cannot reach its budget keeps its last good generation, an \
             installation this host cannot admit is used by no new binding, and a package a \
             worker refused is not used in that session. Synchronise again, raise the budget or \
             the package limit in this host's configuration, or install the package again.",
        ),
    )
}

/// The capability records a registered catalogue contributes to the shared evidence.
///
/// Empty while nothing is registered, which is what `kr doctor` and a support bundle then report.
/// Nothing here invents a record: evidence this host has not been given is evidence it does not
/// have.
#[must_use]
pub fn capabilities(source: Option<&dyn CatalogueEvidence>) -> Vec<CapabilityRecord> {
    source
        .map(|source| {
            source
                .repositories()
                .into_iter()
                .flat_map(|repository| repository.capabilities)
                .collect()
        })
        .unwrap_or_default()
}
