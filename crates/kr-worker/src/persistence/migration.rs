//! Forward-only transactional migrations, and the importer for what this build cannot migrate.
//!
//! Section 24: *database upgrades are transactional, forward-only migrations keyed by a schema
//! version. Code reads one current schema after migration; do not maintain permanent dual
//! readers. Restoring an unsupported archive uses an explicit versioned importer or a supported
//! older exporter, never an unannounced partial restore.*
//!
//! Three rules follow, and this module is where each is decidable rather than assumed.
//!
//! * **Forward only.** A database written by a newer build is refused, not read. Reading it would
//!   mean guessing what a column this build does not know about means.
//! * **One current schema.** Every migration ends at [`CURRENT`], and the code that runs
//!   afterwards reads that version alone. There is no branch anywhere that reads version 2 and
//!   version 3 differently; there is a migration that makes a version 2 database a version 3 one.
//! * **An unsupported archive is imported explicitly.** A database below the oldest version this
//!   ladder starts from is not partly restored. It is named, with the importer that would take
//!   it, which is what stops a partial restore being mistaken for a complete one.

/// The schema version this build reads after migration.
pub const CURRENT: i64 = 5;

/// The oldest schema version this build's ladder can bring forward.
pub const OLDEST_MIGRATABLE: i64 = 1;

/// One step of the ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Migration {
    /// The version this step reads.
    pub from: i64,
    /// The version this step produces.
    pub to: i64,
    /// What it changes, for a person reading the history rather than the code.
    pub summary: &'static str,
}

/// Every step, in order. Each one is one transaction.
pub static LADDER: &[Migration] = &[
    Migration {
        from: 1,
        to: 2,
        summary: "the session summary and the host events an attachment never saw",
    },
    Migration {
        from: 2,
        to: 3,
        summary: "observations, the host time state, fence evidence and its delivery records",
    },
    Migration {
        from: 3,
        to: 4,
        summary: "the outbox, its consumer cursors, and the intervals durable writing was lost",
    },
    Migration {
        from: 4,
        to: 5,
        summary: "the privacy generation and whether privacy mode is on",
    },
];

/// Why a database cannot be brought to the current schema.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MigrationError {
    /// The database was written by a build newer than this one.
    #[error(
        "this store is at schema version {found}, and this build reads version {current}; a \
         newer store is not read by an older build"
    )]
    FromTheFuture {
        /// The version the store records.
        found: i64,
        /// The version this build reads.
        current: i64,
    },
    /// The database is older than the ladder starts from.
    #[error(
        "this store is at schema version {found}, which is older than the oldest version this \
         build migrates ({oldest}); it needs {importer} rather than being restored in part"
    )]
    Unsupported {
        /// The version the store records.
        found: i64,
        /// The oldest version the ladder starts from.
        oldest: i64,
        /// The importer that takes it.
        importer: &'static str,
    },
    /// The ladder has no step from a version inside its own range.
    #[error("no migration step reads schema version {found}")]
    NoStep {
        /// The version the store records.
        found: i64,
    },
}

/// What an unsupported store is named against.
///
/// Section 24 asks for an explicit versioned importer or a supported older exporter, and neither
/// exists in this build: what exists is the refusal that stops a store older than the ladder
/// being restored in part. The refusal names the route rather than a command, because naming a
/// command this build does not ship would send a person somewhere there is nothing to run.
pub const IMPORTER: &str = "an explicit versioned import of a store this build cannot migrate";

/// Returns the tables a store recording `version` must hold.
///
/// A recorded version is not a schema. Migration creates what is absent, so a journal that has
/// lost a table would come back as a journal with an empty one and the loss would never be
/// reported. This is what a store of each version really had, so a store that records a version
/// and is missing one of these has lost it rather than never having had it.
///
/// For an older version this is what the *first* build recording it created, because a version
/// covered several builds and a later one added tables the earlier stores never had: requiring
/// those would report a loss where there was none. For the current version it is the whole
/// schema, because one build writes it.
#[must_use]
pub fn tables_at(version: i64) -> &'static [&'static str] {
    match version {
        // `927ecc84`, the first build of this schema: the receipt table and nothing else.
        1 => &["schema_version", "receipts"],
        // `87e61430`, the first build recording 2.
        2 => &[
            "schema_version",
            "receipts",
            "results",
            "receipt_events",
            "closure",
        ],
        // `469ee5d8`, the first build recording 3.
        3 => &[
            "schema_version",
            "receipts",
            "results",
            "receipt_events",
            "closure",
            "session",
            "host_events",
            "observations",
            "host_time",
            "fence_evidence",
            "fence_state",
            "fence_delivery",
            "fence_forgotten",
        ],
        4 => &[
            "schema_version",
            "receipts",
            "results",
            "receipt_events",
            "closure",
            "session",
            "host_events",
            "observations",
            "host_time",
            "fence_evidence",
            "fence_state",
            "fence_delivery",
            "fence_forgotten",
            "outbox",
            "outbox_cursors",
            "journal_gaps",
        ],
        _ => &[
            "schema_version",
            "receipts",
            "results",
            "receipt_events",
            "closure",
            "session",
            "host_events",
            "observations",
            "host_time",
            "fence_evidence",
            "fence_state",
            "fence_delivery",
            "fence_forgotten",
            "outbox",
            "outbox_cursors",
            "journal_gaps",
            "privacy",
        ],
    }
}

/// Returns the steps that bring a store at `found` to [`CURRENT`].
///
/// # Errors
///
/// Returns [`MigrationError::FromTheFuture`] for a store a newer build wrote,
/// [`MigrationError::Unsupported`] for one older than the ladder, and
/// [`MigrationError::NoStep`] when no step reads the version recorded.
pub fn plan(found: i64) -> Result<Vec<&'static Migration>, MigrationError> {
    if found > CURRENT {
        return Err(MigrationError::FromTheFuture {
            found,
            current: CURRENT,
        });
    }
    if found < OLDEST_MIGRATABLE {
        return Err(MigrationError::Unsupported {
            found,
            oldest: OLDEST_MIGRATABLE,
            importer: IMPORTER,
        });
    }
    let mut steps = Vec::new();
    let mut at = found;
    while at < CURRENT {
        let Some(step) = LADDER.iter().find(|step| step.from == at) else {
            return Err(MigrationError::NoStep { found: at });
        };
        steps.push(step);
        at = step.to;
    }
    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_is_contiguous_and_ends_at_the_current_schema() {
        assert_eq!(
            LADDER.first().expect("a first step").from,
            OLDEST_MIGRATABLE
        );
        assert_eq!(LADDER.last().expect("a last step").to, CURRENT);
        for pair in LADDER.windows(2) {
            assert_eq!(pair[0].to, pair[1].from);
        }
        for step in LADDER {
            assert_eq!(step.to, step.from + 1, "every step moves one version");
        }
    }

    #[test]
    fn a_store_an_earlier_build_wrote_is_planned_all_the_way_forward() {
        let steps = plan(1).expect("version 1 is migratable");
        assert_eq!(steps.len(), (CURRENT - OLDEST_MIGRATABLE) as usize);
        assert_eq!(steps[0].from, OLDEST_MIGRATABLE);
        assert_eq!(steps.last().expect("a last step").to, CURRENT);
        assert!(
            plan(CURRENT)
                .expect("the current version needs nothing")
                .is_empty()
        );
    }

    #[test]
    fn a_store_a_newer_build_wrote_is_refused_rather_than_read() {
        assert_eq!(
            plan(CURRENT + 1),
            Err(MigrationError::FromTheFuture {
                found: CURRENT + 1,
                current: CURRENT,
            })
        );
    }

    #[test]
    fn each_version_names_the_tables_a_store_of_it_really_had() {
        // Every version's set contains the one before it, because no step of this ladder has ever
        // dropped a table. A version this build does not list answers with the current set, which
        // is the strictest of them.
        for step in LADDER {
            let before = tables_at(step.from);
            let after = tables_at(step.to);
            assert!(
                before.iter().all(|table| after.contains(table)),
                "version {} lost a table version {} had",
                step.to,
                step.from
            );
            assert!(after.len() > before.len(), "every step adds a table");
        }
        assert_eq!(tables_at(1), ["schema_version", "receipts"]);
        assert!(tables_at(CURRENT).contains(&"privacy"));
    }

    #[test]
    fn a_store_older_than_the_ladder_names_the_importer_rather_than_being_partly_restored() {
        let error = plan(0).expect_err("version 0 is not migratable");
        assert_eq!(
            error,
            MigrationError::Unsupported {
                found: 0,
                oldest: OLDEST_MIGRATABLE,
                importer: IMPORTER,
            }
        );
        assert!(error.to_string().contains(IMPORTER));
    }
}
