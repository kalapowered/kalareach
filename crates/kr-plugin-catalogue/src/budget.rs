//! The budgets an enrolment sets before the first fetch.
//!
//! Section 11 puts the numbers in the SDK ([`kr_plugin_sdk::limits::RepositoryBudgets`]) and the
//! accounting here. Two rules shape this module.
//!
//! * **A declared size is checked before the download and the actual size during processing.** A
//!   manifest is untrusted input, so the declared figure decides whether a fetch starts at all,
//!   and the bytes that arrive decide whether it finishes. Neither check stands in for the other:
//!   a repository that declares one megabyte and sends a gigabyte fails the second, and a
//!   repository that declares a gigabyte never reaches it.
//! * **Exceeding a budget names the exact resource.** "Out of space" sends a person to the wrong
//!   setting. [`ResourceLimit`] carries which allowance ran out, what it is and what was asked
//!   for, so the message says which number to raise.
//!
//! Nothing here evicts anything. Reclaiming space is [`crate::store`]'s, and it never
//! removes a payload a live binding or a pinned generation still needs.

use kr_plugin_sdk::limits::RepositoryBudgets;

/// One allowance an enrolment sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Resource {
    /// Bytes of catalogue metadata held for one repository.
    MetadataBytes,
    /// Entries in one repository's index.
    MetadataEntries,
    /// Accepted generations one repository keeps.
    RetainedGenerations,
    /// Bytes of metadata one repository keeps: its trust checkpoint and its kept indexes.
    RetainedMetadataBytes,
    /// Bytes of cached payloads held for one repository, with the packages extracted from them
    /// and a package being staged.
    PayloadCacheBytes,
    /// Bytes in one package.
    PackageBytes,
    /// Files in one package.
    PackageFiles,
}

impl Resource {
    /// Returns the stable name the refusal is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MetadataBytes => "metadata_bytes",
            Self::MetadataEntries => "metadata_entries",
            Self::RetainedGenerations => "retained_generations",
            Self::RetainedMetadataBytes => "retained_metadata_bytes",
            Self::PayloadCacheBytes => "payload_cache_bytes",
            Self::PackageBytes => "package_bytes",
            Self::PackageFiles => "package_files",
        }
    }

    /// Returns the setting a person changes to raise this allowance.
    #[must_use]
    pub const fn setting(self) -> &'static str {
        match self {
            Self::MetadataBytes | Self::MetadataEntries => "the repository's metadata budget",
            Self::RetainedGenerations | Self::RetainedMetadataBytes => {
                "the repository's retention budget"
            }
            Self::PayloadCacheBytes => "the repository's cached payload budget",
            Self::PackageBytes | Self::PackageFiles => "the package size limit in the SDK",
        }
    }
}

impl core::fmt::Display for Resource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// When the allowance was found to be exhausted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Before anything was fetched, against what the metadata declares.
    Declared,
    /// While the bytes were being processed, against what actually arrived.
    Actual,
}

impl Stage {
    /// Returns the stable name the refusal is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Actual => "actual",
        }
    }
}

/// An allowance that would be exceeded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "{resource} would reach {requested} against a limit of {limit}, checked against the {stage} \
     size of {subject}; the last generation stays usable, and raising it means changing {setting}",
    stage = self.stage.as_str(),
    setting = self.resource.setting()
)]
pub struct ResourceLimit {
    /// Which allowance ran out.
    pub resource: Resource,
    /// What the allowance is.
    pub limit: u64,
    /// What the operation would have taken it to.
    pub requested: u64,
    /// Whether the figure came from a declaration or from the bytes themselves.
    pub stage: Stage,
    /// What was being fetched or processed.
    pub subject: String,
}

/// One accepted generation a repository keeps, with the bytes its index document holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retained {
    /// The generation number.
    pub generation: u64,
    /// The bytes of its index document.
    pub index_bytes: u64,
}

/// What one repository currently holds against its budgets.
///
/// The ledger is arithmetic over the enrolment's own numbers. It holds no files and removes none:
/// a caller asks whether an addition fits, and the store decides what to do when it does not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetLedger {
    budgets: RepositoryBudgets,
    metadata_bytes: u64,
    metadata_entries: u64,
    payload_bytes: u64,
}

impl BudgetLedger {
    /// Starts an empty ledger against one enrolment's budgets.
    #[must_use]
    pub const fn new(budgets: RepositoryBudgets) -> Self {
        Self {
            budgets,
            metadata_bytes: 0,
            metadata_entries: 0,
            payload_bytes: 0,
        }
    }

    /// Returns the budgets this ledger measures against.
    #[must_use]
    pub const fn budgets(&self) -> RepositoryBudgets {
        self.budgets
    }

    /// Returns the cached payload bytes accounted for.
    #[must_use]
    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    /// Returns the metadata bytes accounted for.
    #[must_use]
    pub const fn metadata_bytes(&self) -> u64 {
        self.metadata_bytes
    }

    /// Returns the index entries accounted for.
    #[must_use]
    pub const fn metadata_entries(&self) -> u64 {
        self.metadata_entries
    }

    /// Checks a metadata document against the metadata byte budget.
    ///
    /// A generation replaces the previous one rather than adding to it, so the whole snapshot is
    /// measured against the whole allowance.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] when the snapshot is larger than the budget.
    pub fn check_metadata_bytes(
        &self,
        bytes: u64,
        stage: Stage,
        subject: &str,
    ) -> Result<(), ResourceLimit> {
        let limit = self.budgets.metadata_bytes.get();
        if bytes > limit {
            return Err(ResourceLimit {
                resource: Resource::MetadataBytes,
                limit,
                requested: bytes,
                stage,
                subject: subject.to_owned(),
            });
        }
        Ok(())
    }

    /// Checks an entry count against the entry budget.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] when the index carries more entries than the budget permits.
    pub fn check_metadata_entries(
        &self,
        entries: u64,
        stage: Stage,
        subject: &str,
    ) -> Result<(), ResourceLimit> {
        let limit = self.budgets.metadata_entries.get();
        if entries > limit {
            return Err(ResourceLimit {
                resource: Resource::MetadataEntries,
                limit,
                requested: entries,
                stage,
                subject: subject.to_owned(),
            });
        }
        Ok(())
    }

    /// Records the snapshot this repository now holds.
    pub const fn accept_metadata(&mut self, bytes: u64, entries: u64) {
        self.metadata_bytes = bytes;
        self.metadata_entries = entries;
    }

    /// Decides which accepted generations a repository stops keeping once `active` is the one it is
    /// on.
    ///
    /// `kept` is every generation it keeps now, `active` among them or not, and `checkpoint` is
    /// what its trust checkpoint holds. The oldest generations it is no longer on go first: until
    /// the count fits the retained-generation budget, and then until the checkpoint and every index
    /// kept fit the retained metadata budget. The generation it is on is never one of them, so a
    /// repository that cannot keep that one and its checkpoint is refused rather than left with
    /// neither.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] naming the retained metadata when the checkpoint and the active
    /// generation's index alone are past that budget, and naming the retained generations when
    /// that budget is too small to keep even the generation in use.
    pub fn plan_retention(
        &self,
        checkpoint: u64,
        kept: &[Retained],
        active: Retained,
    ) -> Result<Vec<u64>, ResourceLimit> {
        let generations = self.budgets.retained_generations.get();
        if generations == 0 {
            return Err(ResourceLimit {
                resource: Resource::RetainedGenerations,
                limit: 0,
                requested: 1,
                stage: Stage::Actual,
                subject: format!("generation {}", active.generation),
            });
        }
        let limit = self.budgets.retained_metadata_bytes.get();
        let mut others: Vec<Retained> = kept
            .iter()
            .filter(|kept| kept.generation != active.generation)
            .copied()
            .collect();
        others.sort_by_key(|kept| kept.generation);
        let held = |others: &[Retained]| {
            others.iter().fold(
                checkpoint.saturating_add(active.index_bytes),
                |total, kept| total.saturating_add(kept.index_bytes),
            )
        };
        let mut forgotten = Vec::new();
        while !others.is_empty() && (others.len() as u64 >= generations || held(&others) > limit) {
            forgotten.push(others.remove(0).generation);
        }
        let requested = held(&others);
        if requested > limit {
            return Err(ResourceLimit {
                resource: Resource::RetainedMetadataBytes,
                limit,
                requested,
                stage: Stage::Actual,
                subject: format!(
                    "the trust checkpoint and generation {}'s index",
                    active.generation
                ),
            });
        }
        Ok(forgotten)
    }

    /// Checks whether `bytes` more of cached payload fits.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] when the cache would pass its budget.
    pub fn check_payload_bytes(
        &self,
        bytes: u64,
        stage: Stage,
        subject: &str,
    ) -> Result<(), ResourceLimit> {
        let limit = self.budgets.payload_cache_bytes.get();
        let requested = self.payload_bytes.saturating_add(bytes);
        if requested > limit {
            return Err(ResourceLimit {
                resource: Resource::PayloadCacheBytes,
                limit,
                requested,
                stage,
                subject: subject.to_owned(),
            });
        }
        Ok(())
    }

    /// Records `bytes` of payload now held.
    pub const fn add_payload_bytes(&mut self, bytes: u64) {
        self.payload_bytes = self.payload_bytes.saturating_add(bytes);
    }

    /// Records `bytes` of payload no longer held.
    pub const fn remove_payload_bytes(&mut self, bytes: u64) {
        self.payload_bytes = self.payload_bytes.saturating_sub(bytes);
    }

    /// Checks one package against the per-package limits the SDK states.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] when the package declares more bytes or more files than one
    /// package may carry.
    pub fn check_package(
        &self,
        bytes: u64,
        files: u64,
        stage: Stage,
        subject: &str,
    ) -> Result<(), ResourceLimit> {
        if bytes > kr_plugin_sdk::package::MAX_PACKAGE_BYTES {
            return Err(ResourceLimit {
                resource: Resource::PackageBytes,
                limit: kr_plugin_sdk::package::MAX_PACKAGE_BYTES,
                requested: bytes,
                stage,
                subject: subject.to_owned(),
            });
        }
        let file_limit = kr_plugin_sdk::package::MAX_PACKAGE_FILES as u64;
        if files > file_limit {
            return Err(ResourceLimit {
                resource: Resource::PackageFiles,
                limit: file_limit,
                requested: files,
                stage,
                subject: subject.to_owned(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ledger() -> BudgetLedger {
        BudgetLedger::new(RepositoryBudgets::defaults())
    }

    #[test]
    fn the_defaults_are_the_section_eleven_numbers() {
        let ledger = ledger();
        assert_eq!(ledger.budgets().metadata_bytes.get(), 64 * 1024 * 1024);
        assert_eq!(ledger.budgets().metadata_entries.get(), 100_000);
        assert_eq!(
            ledger.budgets().payload_cache_bytes.get(),
            1024 * 1024 * 1024
        );
        assert!(!ledger.budgets().full_offline_mirror);
    }

    #[test]
    fn a_refusal_names_the_resource_the_stage_and_the_setting() {
        let ledger = ledger();
        let refusal = ledger
            .check_metadata_entries(100_001, Stage::Declared, "vendor index")
            .expect_err("over the entry budget");
        assert_eq!(refusal.resource, Resource::MetadataEntries);
        assert_eq!(refusal.limit, 100_000);
        assert_eq!(refusal.requested, 100_001);
        let message = refusal.to_string();
        assert!(message.contains("metadata_entries"), "{message}");
        assert!(message.contains("declared"), "{message}");
        assert!(message.contains("metadata budget"), "{message}");
        assert!(
            message.contains("last generation stays usable"),
            "{message}"
        );
    }

    #[test]
    fn the_payload_cache_measures_what_is_already_held() {
        let mut ledger = ledger();
        ledger.add_payload_bytes(1024 * 1024 * 1024 - 16);
        assert!(
            ledger
                .check_payload_bytes(16, Stage::Declared, "component.wasm")
                .is_ok()
        );
        let refusal = ledger
            .check_payload_bytes(17, Stage::Actual, "component.wasm")
            .expect_err("over the cache budget");
        assert_eq!(refusal.resource, Resource::PayloadCacheBytes);
        assert_eq!(refusal.stage, Stage::Actual);
        ledger.remove_payload_bytes(1024);
        assert!(
            ledger
                .check_payload_bytes(1024, Stage::Actual, "component.wasm")
                .is_ok()
        );
    }

    fn retained(generation: u64, index_bytes: u64) -> Retained {
        Retained {
            generation,
            index_bytes,
        }
    }

    fn retaining(generations: u64, metadata: u64) -> BudgetLedger {
        let mut budgets = RepositoryBudgets::defaults();
        budgets.retained_generations = kr_plugin_sdk::scalars::U64::new(generations);
        budgets.retained_metadata_bytes = kr_plugin_sdk::scalars::U64::new(metadata);
        BudgetLedger::new(budgets)
    }

    #[test]
    fn the_oldest_generations_go_first_until_the_count_fits() {
        let kept = [retained(1, 10), retained(2, 10), retained(3, 10)];
        // At the limit: three kept and the fourth accepted leaves three when three are allowed
        // once the oldest goes, and nothing goes when four are allowed.
        assert_eq!(
            retaining(4, 1_000).plan_retention(0, &kept, retained(4, 10)),
            Ok(Vec::new())
        );
        assert_eq!(
            retaining(3, 1_000).plan_retention(0, &kept, retained(4, 10)),
            Ok(vec![1])
        );
        assert_eq!(
            retaining(1, 1_000).plan_retention(0, &kept, retained(4, 10)),
            Ok(vec![1, 2, 3])
        );
        // The generation in use is never one that goes, even when it is the oldest one named.
        assert_eq!(
            retaining(1, 1_000).plan_retention(0, &kept, retained(2, 10)),
            Ok(vec![1, 3])
        );
    }

    #[test]
    fn the_retained_metadata_counts_the_checkpoint_and_every_index_kept() {
        let kept = [retained(1, 30), retained(2, 30)];
        // Checkpoint 40, the new index 30 and both kept ones: 130 fits exactly.
        assert_eq!(
            retaining(3, 130).plan_retention(40, &kept, retained(3, 30)),
            Ok(Vec::new())
        );
        // One byte less, and the oldest goes to make room.
        assert_eq!(
            retaining(3, 129).plan_retention(40, &kept, retained(3, 30)),
            Ok(vec![1])
        );
        // The checkpoint and the new index alone fit exactly once every older one goes.
        assert_eq!(
            retaining(3, 70).plan_retention(40, &kept, retained(3, 30)),
            Ok(vec![1, 2])
        );
        let refusal = retaining(3, 69)
            .plan_retention(40, &kept, retained(3, 30))
            .expect_err("the checkpoint and the new index alone are past the budget");
        assert_eq!(refusal.resource, Resource::RetainedMetadataBytes);
        assert_eq!(refusal.limit, 69);
        assert_eq!(refusal.requested, 70);
        assert!(
            refusal.to_string().contains("retention budget"),
            "{refusal}"
        );
    }

    #[test]
    fn a_repository_keeps_at_least_the_generation_it_is_on() {
        let refusal = retaining(0, 1_000)
            .plan_retention(0, &[], retained(1, 10))
            .expect_err("no generation may be kept");
        assert_eq!(refusal.resource, Resource::RetainedGenerations);
    }

    #[test]
    fn a_saturating_total_cannot_wrap_past_a_budget() {
        let mut ledger = ledger();
        ledger.add_payload_bytes(u64::MAX);
        assert!(
            ledger
                .check_payload_bytes(u64::MAX, Stage::Declared, "a lying manifest")
                .is_err()
        );
    }
}
