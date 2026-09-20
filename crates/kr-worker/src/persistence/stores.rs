//! Every store this host keeps, declared as data.
//!
//! Section 24 asks each store's schema to record its durability, its retention, its content
//! class, who is responsible for cleaning it up and how it is reconciled after a restart. Writing
//! that in prose puts it where nothing can check it. Writing it here puts it where a test can:
//! what survives what, what may be evicted under a byte cap and what may not, and which of them
//! the archive serves after the worker is gone.
//!
//! The rule that does the most work is the last column. **Authority, dispatch and causal-budget
//! data cannot be evicted under a history byte cap.** A host under output pressure that dropped a
//! dispatch marker to make room would forget that an action was already sent, and the next retry
//! would send it again.

use std::time::Duration;

/// How much of a crash a store survives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Durability {
    /// Committed with full synchronisation before the caller is answered.
    CrashDurable,
    /// Written to disk without a flush of its own.
    BestEffortFile,
    /// Held in memory for the life of the process.
    ProcessMemory,
}

/// What a store keeps, and for how long.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retention {
    /// Kept for the life of the session, then handed to the archive.
    SessionLifetime,
    /// Kept for a fixed period.
    Period(Duration),
    /// Kept for a fixed period *and* under a byte cap, whichever applies first.
    ///
    /// Section 20's retained output is this: seven days, a host cap and a session cap, all upper
    /// bounds at once. A store declared only `ByteCapped` would be one nothing ever expired from.
    PeriodOrByteCap(Duration),
    /// Kept until every consumer that has registered a cursor has taken it, and then past a
    /// period of its own.
    ///
    /// The outbox is this: an event goes when it is older than the period and below every
    /// registered consumer's cursor, so collection can never take work a consumer still owes.
    UntilDeliveredThenPeriod(Duration),
    /// Kept until the thing it belongs to is gone.
    UntilSubjectGone,
}

/// What class of content a store holds.
///
/// Section 24 keeps raw keystrokes, terminal bodies and provider keys out of a universal control
/// log. The classes are what makes that checkable: a store declared [`ContentClass::Metadata`]
/// that held a keystroke would be a store whose declaration is wrong, and the journal's own test
/// greps for exactly that. A store that holds more than one class declares the widest it holds,
/// because what acts on the declaration - privacy cleanup, an export, an archive - has to be
/// right about the worst case rather than about the usual one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContentClass {
    /// Operation metadata: identifiers, revisions, states, digests and counts.
    Metadata,
    /// Terminal output bytes, as the application produced them.
    TerminalContent,
    /// Text a person wrote or an agent asked for.
    AuthoredContent,
    /// An untrusted notice an application asked the terminal to deliver.
    ///
    /// Section 25 keeps these: an OSC 9, 99 or 777 notification with nothing holding the input
    /// lease becomes a durable host event rather than something shown to whoever is watching. It
    /// is kept apart from the terminal's own body, which section 24 forbids copying here.
    ApplicationNotice,
    /// Key material.
    Secret,
}

impl ContentClass {
    /// Every class, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Metadata,
        Self::TerminalContent,
        Self::AuthoredContent,
        Self::ApplicationNotice,
        Self::Secret,
    ];

    /// Returns the stable stored name of this content class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::TerminalContent => "terminal",
            Self::AuthoredContent => "authored",
            Self::ApplicationNotice => "notice",
            Self::Secret => "secret",
        }
    }

    /// Parses a stored name back into a content class.
    #[must_use]
    pub fn from_stored(name: &str) -> Option<Self> {
        match name {
            "metadata" => Some(Self::Metadata),
            "terminal" => Some(Self::TerminalContent),
            "authored" => Some(Self::AuthoredContent),
            "notice" => Some(Self::ApplicationNotice),
            "secret" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// Who removes what a store no longer needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Cleanup {
    /// The worker's own maintenance tick.
    WorkerMaintenance,
    /// The controller's archive service, after closure or crash.
    ArchiveService,
    /// The controller's transfer sweep.
    TransferSweep,
    /// Nothing: it goes when the process does.
    ProcessExit,
}

/// What protects a store where it lies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protection {
    /// An owner-only directory under the environment's state root.
    ///
    /// Section 24 makes local state directories owner-only and the keys OS-protected. It does not
    /// ask for local encryption at rest, and claiming it would be claiming something this build
    /// does not do.
    OwnerOnlyDirectory,
    /// Held in this process's memory and never written.
    ProcessMemory,
    /// Encrypted before it leaves this host.
    EncryptedBeforeUpload,
}

/// How a store is brought back into agreement after a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reconciliation {
    /// A dispatch marker without an outcome becomes `unknown`, and is never dispatched again.
    UnfinishedDispatchesResolved,
    /// Read back as it stands; nothing needs deciding.
    ReadBack,
    /// Rebuilt from what is still retained, with an explicit gap for what is not.
    RebuiltWithGaps,
    /// Gone with the process that held it.
    NotRestored,
}

/// One store, with everything section 24 asks its schema to record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreDescriptor {
    /// The store's stable name, which is its table or directory name.
    pub name: &'static str,
    /// What the store holds, in one line.
    pub holds: &'static str,
    /// How much of a crash it survives.
    pub durability: Durability,
    /// What it keeps, and for how long.
    pub retention: Retention,
    /// What class of content it holds.
    pub content: ContentClass,
    /// What protects it where it lies.
    pub protection: Protection,
    /// Who removes what it no longer needs.
    pub cleanup: Cleanup,
    /// How it is brought back into agreement after a restart.
    pub reconciliation: Reconciliation,
    /// Whether a history byte cap may evict it.
    ///
    /// False for authority, dispatch and causal-budget data, which section 24 exempts.
    pub evictable_under_history_cap: bool,
    /// Whether the archive service serves it after the session is gone.
    pub served_by_archive: bool,
}

/// The receipt journal's tables and the session's spool, in the order they matter.
pub static STORES: &[StoreDescriptor] = &[
    StoreDescriptor {
        name: "receipts",
        holds: "one row per admitted action: its state, revision, digests, deadline and the intent envelope it was admitted with",
        durability: Durability::CrashDurable,
        retention: Retention::Period(RECEIPT_RETENTION),
        // The intent envelope is what the caller asked for, exactly as it arrived, so a method
        // that carries text a person wrote carries it here. It is never the terminal's own body
        // and never a provider key, which is what section 24 forbids.
        content: ContentClass::AuthoredContent,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::UnfinishedDispatchesResolved,
        evictable_under_history_cap: false,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "results",
        holds: "the encoded result of an action that completed",
        durability: Durability::CrashDurable,
        retention: Retention::Period(RECEIPT_RETENTION),
        // A result can restate what its request carried, so it is declared as widely as the
        // request that produced it.
        content: ContentClass::AuthoredContent,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "receipt_events",
        holds: "the ordered event record each receipt transition commits with",
        durability: Durability::CrashDurable,
        retention: Retention::Period(RECEIPT_RETENTION),
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "outbox",
        holds: "the event each state transition committed with, waiting for its consumers",
        durability: Durability::CrashDurable,
        retention: Retention::UntilDeliveredThenPeriod(RECEIPT_RETENTION),
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "outbox_cursors",
        holds: "how far each consumer has taken the outbox, and what it has already seen",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "observations",
        holds: "evidence about what an uncertain action did",
        durability: Durability::CrashDurable,
        retention: Retention::Period(RECEIPT_RETENTION),
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "fence_evidence",
        holds: "the actions one revocation's fence could not take back, by name",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "fence_state",
        holds: "how far the previous fence got in this journal's own event order",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::ArchiveService,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "host_time",
        holds: "the clock trust, the proven reading and the tombstones a restart must not lose",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::ArchiveService,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "session",
        holds: "the session's own summary, so the archive can serve it with no worker",
        durability: Durability::CrashDurable,
        retention: Retention::SessionLifetime,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::ArchiveService,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "closure",
        holds: "the final closure record, with terminated identities and the coverage flag",
        durability: Durability::CrashDurable,
        retention: Retention::SessionLifetime,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::ArchiveService,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "privacy",
        holds: "the privacy generation in force, and whether privacy mode is on",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::ArchiveService,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "journal_gaps",
        holds: "the intervals durable writing was unavailable, so no reader reads continuity",
        durability: Durability::CrashDurable,
        retention: Retention::SessionLifetime,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::ArchiveService,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "fence_delivery",
        holds: "how many of a revocation's names the controller generation asking now has taken",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "fence_forgotten",
        holds: "the revision below which this journal can no longer count a revocation's names",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "host_events",
        holds: "an application notice that had no attachment to go to, and where in the stream it happened",
        durability: Durability::CrashDurable,
        retention: Retention::SessionLifetime,
        content: ContentClass::ApplicationNotice,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::ArchiveService,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: true,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "output spool",
        holds: "retained terminal output, in fixed segments named by the cursor they start at",
        durability: Durability::BestEffortFile,
        retention: Retention::PeriodOrByteCap(crate::persistence::retention::OUTPUT_RETENTION),
        content: ContentClass::TerminalContent,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::RebuiltWithGaps,
        evictable_under_history_cap: true,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "resident history",
        holds: "the most recent output, in memory, ahead of the spool",
        durability: Durability::ProcessMemory,
        retention: Retention::PeriodOrByteCap(crate::persistence::retention::OUTPUT_RETENTION),
        content: ContentClass::TerminalContent,
        protection: Protection::ProcessMemory,
        cleanup: Cleanup::ProcessExit,
        reconciliation: Reconciliation::NotRestored,
        evictable_under_history_cap: true,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "transfer attachments",
        holds: "files submitted to this session, under the environment's transfer service",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::AuthoredContent,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::TransferSweep,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: true,
    },
    StoreDescriptor {
        name: "broker_schema",
        holds: "the broker ledger's schema version",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "broker_bindings",
        holds: "the broker's binding revisions for active applications",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "broker_decoder_entries",
        holds: "verified decoder proposals, their source bytes and interpreted projections",
        durability: Durability::CrashDurable,
        retention: Retention::Period(RECEIPT_RETENTION),
        content: ContentClass::AuthoredContent,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "broker_consumed_sources",
        holds: "consumed source frame digests to prevent replay",
        durability: Durability::CrashDurable,
        retention: Retention::Period(RECEIPT_RETENTION),
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "broker_pending",
        holds: "pending broker resources waiting for resolution or answer",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::UnfinishedDispatchesResolved,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "broker_profiles",
        holds: "launch profiles and associated capability evidence",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "broker_gaps",
        holds: "recorded broker evidence gaps",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "broker_checkpoints",
        holds: "stream cursor checkpoints for observer replay",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "broker_client_requests",
        holds: "forwarded native client requests awaiting upstream response",
        durability: Durability::CrashDurable,
        retention: Retention::UntilSubjectGone,
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::UnfinishedDispatchesResolved,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
    StoreDescriptor {
        name: "broker_events",
        holds: "ordered broker transition events for attached views and outbox replay",
        durability: Durability::CrashDurable,
        retention: Retention::Period(RECEIPT_RETENTION),
        content: ContentClass::Metadata,
        protection: Protection::OwnerOnlyDirectory,
        cleanup: Cleanup::WorkerMaintenance,
        reconciliation: Reconciliation::ReadBack,
        evictable_under_history_cap: false,
        served_by_archive: false,
    },
];

/// How long receipts are budgeted for, separately from output history.
///
/// Section 20: receipts remain for 30 days and have a separately budgeted store, so history
/// pressure cannot silently delete a live dispatch barrier or de-duplication record.
pub const RECEIPT_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Returns the descriptor of one store, by name.
#[must_use]
pub fn store(name: &str) -> Option<&'static StoreDescriptor> {
    STORES.iter().find(|store| store.name == name)
}

/// Returns every store a history byte cap may evict.
pub fn evictable_under_history_cap() -> impl Iterator<Item = &'static StoreDescriptor> {
    STORES
        .iter()
        .filter(|store| store.evictable_under_history_cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_class_round_trips_through_stored_name() {
        for class in ContentClass::ALL {
            let stored = class.as_str();
            let parsed = ContentClass::from_stored(stored);
            assert_eq!(parsed, Some(*class));
        }
        assert_eq!(ContentClass::from_stored("unknown"), None);
    }

    #[test]
    fn authority_and_dispatch_data_is_exempt_from_the_history_byte_cap() {
        for name in [
            "receipts",
            "results",
            "receipt_events",
            "outbox",
            "outbox_cursors",
            "observations",
            "fence_evidence",
            "fence_state",
            "fence_delivery",
            "fence_forgotten",
            "host_time",
            "privacy",
            "closure",
            "journal_gaps",
            "broker_schema",
            "broker_bindings",
            "broker_decoder_entries",
            "broker_consumed_sources",
            "broker_pending",
            "broker_profiles",
            "broker_gaps",
            "broker_checkpoints",
            "broker_client_requests",
            "broker_events",
        ] {
            let store = store(name).expect("every named store is declared");
            assert!(
                !store.evictable_under_history_cap,
                "{name} must not be evictable under a history cap"
            );
        }
    }

    #[test]
    fn only_terminal_content_and_host_events_are_evictable_under_the_cap() {
        let evictable: Vec<&str> = evictable_under_history_cap()
            .map(|store| store.name)
            .collect();
        assert_eq!(
            evictable,
            vec!["host_events", "output spool", "resident history"]
        );
    }

    #[test]
    fn no_store_holds_key_material_and_only_the_output_layers_hold_the_terminals_body() {
        let terminal: Vec<&str> = STORES
            .iter()
            .filter(|store| store.content == ContentClass::TerminalContent)
            .map(|store| store.name)
            .collect();
        assert_eq!(
            terminal,
            vec!["output spool", "resident history"],
            "the terminal's own body belongs to the retained output and nowhere else"
        );
        for store in STORES {
            assert_ne!(
                store.content,
                ContentClass::Secret,
                "{} must not hold key material",
                store.name
            );
        }
    }

    #[test]
    fn every_store_that_reaches_a_disk_says_what_protects_it() {
        for store in STORES {
            let expected = if store.durability == Durability::ProcessMemory {
                Protection::ProcessMemory
            } else {
                Protection::OwnerOnlyDirectory
            };
            assert_eq!(store.protection, expected, "{}", store.name);
        }
    }

    #[test]
    fn every_receipt_store_is_budgeted_for_thirty_days_rather_than_by_bytes() {
        for name in ["receipts", "results", "receipt_events", "observations"] {
            let store = store(name).expect("every named store is declared");
            assert_eq!(store.retention, Retention::Period(RECEIPT_RETENTION));
        }
        assert_eq!(
            RECEIPT_RETENTION.as_millis() as u64,
            crate::journal::RETENTION_MS
        );
    }

    #[test]
    fn every_store_has_a_distinct_name() {
        let mut names: Vec<&str> = STORES.iter().map(|store| store.name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    #[test]
    fn only_a_crash_durable_store_is_one_an_acknowledgement_waits_on() {
        for name in ["receipts", "outbox", "closure", "journal_gaps"] {
            let store = store(name).expect("every named store is declared");
            assert_eq!(store.durability, Durability::CrashDurable);
        }
        // Output never waits for a flush: section 24 forbids a per-output-byte fsync.
        assert_eq!(
            store("output spool")
                .expect("the spool is declared")
                .durability,
            Durability::BestEffortFile
        );
        assert_eq!(
            store("host_events")
                .expect("host events are declared")
                .durability,
            Durability::CrashDurable
        );
    }
}
