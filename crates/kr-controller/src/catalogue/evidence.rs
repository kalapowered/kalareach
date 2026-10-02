//! The catalogue's half of the shared capability evidence `kr doctor` and a support bundle read
//! (section 11): one record per enrolled repository, read from the catalogue when the doctor asks,
//! and what the workers said they would not read or bind.
//!
//! The records carry this host's own measurements (the generation activated, the metadata and the
//! cached payloads it costs) and no capability record: the plugin catalogue publishes none in the
//! shared section 11 shape, and evidence this host has not been given is evidence it does not have.

use kr_plugin_catalogue::{Catalogue, CatalogueResult};

use crate::config::catalogue::{CatalogueEvidence, RepositoryEvidence};

/// What one reading of the catalogue and of the workers' reports gives the doctor.
#[derive(Clone, Debug, Default)]
pub struct Evidence {
    /// One record per enrolled repository, in the order the catalogue lists them.
    pub repositories: Vec<RepositoryEvidence>,
    /// Each package a worker refused and each set of admissions not handed over, as a person
    /// reads it.
    pub warnings: Vec<String>,
}

impl CatalogueEvidence for Evidence {
    fn repositories(&self) -> Vec<RepositoryEvidence> {
        self.repositories.clone()
    }

    fn warnings(&self) -> Vec<String> {
        self.warnings.clone()
    }
}

/// Reads one record per enrolled repository.
///
/// # Errors
///
/// Returns what the catalogue returned when its records cannot be read. A store whose cached
/// payloads cannot be measured is a degraded record, not an error.
pub fn repositories(catalogue: &Catalogue) -> CatalogueResult<Vec<RepositoryEvidence>> {
    let mut records = Vec::new();
    for view in catalogue.repository_views()? {
        let name = view.enrolment.id.to_string();
        let cached = catalogue
            .store(&view.enrolment.id)
            .and_then(|store| store.cached_payloads())
            .map(|payloads| payloads.values().copied().fold(0u64, u64::saturating_add));
        let (detail, degraded) = match (view.active, &cached) {
            (_, Err(error)) => (
                format!("its cached payloads cannot be measured: {error}"),
                true,
            ),
            (None, Ok(_)) => ("no generation is activated yet".to_owned(), true),
            (Some(active), Ok(_)) => (
                match view.enrolment.pinned_generation {
                    Some(pinned) => format!(
                        "generation {} activated, pinned to {pinned}",
                        active.generation
                    ),
                    None => format!("generation {} activated", active.generation),
                },
                false,
            ),
        };
        // Where a repository the host seeded came from is part of what it reports, so a person
        // reading the doctor can tell the generation the host shipped with from one it fetched.
        let detail = match catalogue.seed_provenance(&view.enrolment.id)? {
            Some(provenance) => format!(
                "{detail}, seeded from the bundled generation {} of {} at commit {}",
                provenance["generation"],
                provenance["repository"]
                    .as_str()
                    .unwrap_or("its repository"),
                provenance["commit"]
                    .as_str()
                    .map_or("", |commit| commit.get(..12).unwrap_or(commit)),
            ),
            None => detail,
        };
        // The seed moves a repository it made only under a root this build trusts. One that was
        // seeded by another kind of build (a development build's, read by a release) is left as it
        // is, from the enrolment on, and the doctor says so.
        let detail = if catalogue.was_seeded(&view.enrolment.id)?
            && kr_plugin_catalogue::SeedTrust::compiled()
                .permit(&view.enrolment.root)
                .is_err()
        {
            format!(
                "{detail}; its root is not one this build trusts, so the seed leaves it as it is"
            )
        } else {
            detail
        };
        records.push(RepositoryEvidence {
            name,
            generation: view.active.map_or(0, |active| active.generation),
            metadata_bytes: view.active.map_or(0, |active| active.index_bytes),
            metadata_entries: view.active.map_or(0, |active| active.entries),
            cached_payload_bytes: cached.unwrap_or(0),
            capabilities: Vec::new(),
            detail,
            degraded,
        });
    }
    Ok(records)
}
