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
    /// Bytes one package takes once extracted.
    ExpandedPackBytes,
    /// Bytes one synchronisation transfers: the metadata, the index and a full mirror's payloads
    /// together.
    TransferBytes,
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
            Self::PackageFiles => "object_count",
            Self::ExpandedPackBytes => "expanded_pack_bytes",
            Self::TransferBytes => "transfer_bytes",
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
            Self::PackageBytes | Self::PackageFiles | Self::ExpandedPackBytes => {
                "this host's package limits, which the package format's own maxima cap"
            }
            Self::TransferBytes => "this host's transfer limit",
        }
    }
}

impl core::fmt::Display for Resource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The limits this host holds one package to: the configuration's values, each no larger than
/// the package format's own maximum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageLimits {
    /// The bytes one package may declare.
    pub package_bytes: u64,
    /// The files one package may hold.
    pub object_count: u64,
    /// The bytes one package may take once extracted.
    pub expanded_pack_bytes: u64,
}

impl PackageLimits {
    /// The package format's own maxima.
    #[must_use]
    pub const fn format() -> Self {
        Self {
            package_bytes: kr_plugin_sdk::package::MAX_PACKAGE_BYTES,
            object_count: kr_plugin_sdk::package::MAX_PACKAGE_FILES as u64,
            expanded_pack_bytes: kr_plugin_sdk::package::MAX_PACKAGE_BYTES,
        }
    }

    /// The configured limits, each no larger than the format's maximum.
    #[must_use]
    pub fn configured(package_bytes: u64, object_count: u64, expanded_pack_bytes: u64) -> Self {
        let format = Self::format();
        Self {
            package_bytes: package_bytes.min(format.package_bytes),
            object_count: object_count.min(format.object_count),
            expanded_pack_bytes: expanded_pack_bytes.min(format.expanded_pack_bytes),
        }
    }

    /// Checks one package against these limits.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] when the package declares or takes more bytes, or holds more
    /// files, than one package may.
    pub fn check(
        &self,
        bytes: u64,
        files: u64,
        stage: Stage,
        subject: &str,
    ) -> Result<(), ResourceLimit> {
        // What a package declares is held to `package_bytes`, and what it takes once extracted to
        // `expanded_pack_bytes`; its files to `object_count` at both. This format stores every file
        // as it is, so the declared total is also the extracted size, and a declaration is held to
        // both byte limits before anything is fetched.
        let limits: &[(Resource, u64)] = match stage {
            Stage::Declared => &[
                (Resource::PackageBytes, self.package_bytes),
                (Resource::ExpandedPackBytes, self.expanded_pack_bytes),
            ],
            Stage::Actual => &[(Resource::ExpandedPackBytes, self.expanded_pack_bytes)],
        };
        for &(resource, limit) in limits {
            if bytes > limit {
                return Err(ResourceLimit {
                    resource,
                    limit,
                    requested: bytes,
                    stage,
                    subject: subject.to_owned(),
                });
            }
        }
        if files > self.object_count {
            return Err(ResourceLimit {
                resource: Resource::PackageFiles,
                limit: self.object_count,
                requested: files,
                stage,
                subject: subject.to_owned(),
            });
        }
        Ok(())
    }
}

/// The limits this host holds its catalogue to: every package's, and what one synchronisation may
/// transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The limits every package is held to.
    pub package: PackageLimits,
    /// The bytes one synchronisation may transfer: its metadata, its index and a full mirror's
    /// payloads together.
    pub transfer_bytes: u64,
}

impl Default for Limits {
    /// The package format's own maxima, and no transfer limit of the host's own: what a catalogue
    /// whose host has put none in force is held to.
    fn default() -> Self {
        Self {
            package: PackageLimits::format(),
            transfer_bytes: u64::MAX,
        }
    }
}

/// The limits in force, shared by the catalogue and whoever puts them in force, and read at every
/// use: a change reaches the next check without the catalogue being told, and no check holds a
/// copy of its own.
#[derive(Clone, Debug, Default)]
pub struct LimitsInForce(std::sync::Arc<std::sync::Mutex<Limits>>);

impl LimitsInForce {
    /// Puts `limits` in force for every check from now on.
    pub fn put(&self, limits: Limits) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = limits;
    }

    /// Returns the limits in force now.
    #[must_use]
    pub fn get(&self) -> Limits {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
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
    package: PackageLimits,
    metadata_bytes: u64,
    metadata_entries: u64,
    payload_bytes: u64,
}

impl BudgetLedger {
    /// Holds each package this ledger checks to `limits` rather than the format's own maxima.
    #[must_use]
    pub const fn with_package_limits(mut self, limits: PackageLimits) -> Self {
        self.package = limits;
        self
    }

    /// Starts an empty ledger against one enrolment's budgets.
    #[must_use]
    pub const fn new(budgets: RepositoryBudgets) -> Self {
        Self {
            package: PackageLimits::format(),
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
    /// on, or while it keeps no generation in use where `active` is none.
    ///
    /// `kept` is every generation it keeps now, `active` among them or not, and `checkpoint` is
    /// what its trust checkpoint counts. The oldest generations it is not on go first: until the
    /// count fits the retained-generation budget, and then until the checkpoint and every index
    /// kept fit the retained metadata budget. The generation it is on is never one of them, so a
    /// repository that cannot keep that one beside its checkpoint is refused rather than left with
    /// neither.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceLimit`] naming the retained metadata when the checkpoint and the active
    /// generation's index alone are past that budget, and naming the retained generations when
    /// that budget keeps no generation at all.
    pub fn plan_retention(
        &self,
        checkpoint: u64,
        kept: &[Retained],
        active: Option<Retained>,
    ) -> Result<Vec<u64>, ResourceLimit> {
        let generations = self.budgets.retained_generations.get();
        if generations == 0 {
            return Err(ResourceLimit {
                resource: Resource::RetainedGenerations,
                limit: 0,
                requested: 1,
                stage: Stage::Actual,
                subject: "the generation a repository is on".to_owned(),
            });
        }
        let limit = self.budgets.retained_metadata_bytes.get();
        let in_use = active.map(|active| active.generation);
        let mut others: Vec<Retained> = kept
            .iter()
            .filter(|kept| Some(kept.generation) != in_use)
            .copied()
            .collect();
        others.sort_by_key(|kept| kept.generation);
        let base = checkpoint.saturating_add(active.map_or(0, |active| active.index_bytes));
        let held = |others: &[Retained]| {
            others
                .iter()
                .fold(base, |total, kept| total.saturating_add(kept.index_bytes))
        };
        let count = |others: &[Retained]| others.len() as u64 + u64::from(active.is_some());
        let mut forgotten = Vec::new();
        while !others.is_empty() && (count(&others) > generations || held(&others) > limit) {
            forgotten.push(others.remove(0).generation);
        }
        let requested = held(&others);
        if requested > limit {
            return Err(ResourceLimit {
                resource: Resource::RetainedMetadataBytes,
                limit,
                requested,
                stage: Stage::Actual,
                subject: active.map_or_else(
                    || "the trust checkpoint".to_owned(),
                    |active| {
                        format!(
                            "the trust checkpoint and generation {}'s index",
                            active.generation
                        )
                    },
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

    /// Checks one package against the package limits this ledger holds.
    ///
    /// # Errors
    ///
    /// Returns what [`PackageLimits::check`] returns.
    pub fn check_package(
        &self,
        bytes: u64,
        files: u64,
        stage: Stage,
        subject: &str,
    ) -> Result<(), ResourceLimit> {
        self.package.check(bytes, files, stage, subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A configured package limit is never above the format's own maximum.
    #[test]
    fn a_configured_package_limit_is_capped_at_the_format() {
        assert_eq!(
            PackageLimits::configured(u64::MAX, u64::MAX, u64::MAX),
            PackageLimits::format()
        );
        let lower = PackageLimits::configured(10, 2, 20);
        assert_eq!(
            (
                lower.package_bytes,
                lower.object_count,
                lower.expanded_pack_bytes
            ),
            (10, 2, 20)
        );
    }

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
            retaining(4, 1_000).plan_retention(0, &kept, Some(retained(4, 10))),
            Ok(Vec::new())
        );
        assert_eq!(
            retaining(3, 1_000).plan_retention(0, &kept, Some(retained(4, 10))),
            Ok(vec![1])
        );
        assert_eq!(
            retaining(1, 1_000).plan_retention(0, &kept, Some(retained(4, 10))),
            Ok(vec![1, 2, 3])
        );
        // The generation in use is never one that goes, even when it is the oldest one named.
        assert_eq!(
            retaining(1, 1_000).plan_retention(0, &kept, Some(retained(2, 10))),
            Ok(vec![1, 3])
        );
    }

    #[test]
    fn the_retained_metadata_counts_the_checkpoint_and_every_index_kept() {
        let kept = [retained(1, 30), retained(2, 30)];
        // Checkpoint 40, the new index 30 and both kept ones: 130 fits exactly.
        assert_eq!(
            retaining(3, 130).plan_retention(40, &kept, Some(retained(3, 30))),
            Ok(Vec::new())
        );
        // One byte less, and the oldest goes to make room.
        assert_eq!(
            retaining(3, 129).plan_retention(40, &kept, Some(retained(3, 30))),
            Ok(vec![1])
        );
        // The checkpoint and the new index alone fit exactly once every older one goes.
        assert_eq!(
            retaining(3, 70).plan_retention(40, &kept, Some(retained(3, 30))),
            Ok(vec![1, 2])
        );
        let refusal = retaining(3, 69)
            .plan_retention(40, &kept, Some(retained(3, 30)))
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
    fn with_no_generation_in_use_every_kept_one_may_go_and_the_checkpoint_counts_alone() {
        let kept = [retained(1, 30), retained(2, 30)];
        assert_eq!(
            retaining(2, 100).plan_retention(40, &kept, None),
            Ok(Vec::new())
        );
        assert_eq!(
            retaining(1, 100).plan_retention(40, &kept, None),
            Ok(vec![1])
        );
        assert_eq!(
            retaining(2, 40).plan_retention(40, &kept, None),
            Ok(vec![1, 2])
        );
        let refusal = retaining(2, 39)
            .plan_retention(40, &kept, None)
            .expect_err("the checkpoint alone is past the budget");
        assert_eq!(refusal.resource, Resource::RetainedMetadataBytes);
        assert_eq!(refusal.requested, 40);
    }

    #[test]
    fn a_repository_keeps_at_least_the_generation_it_is_on() {
        let refusal = retaining(0, 1_000)
            .plan_retention(0, &[], Some(retained(1, 10)))
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
