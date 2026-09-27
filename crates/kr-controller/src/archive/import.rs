//! The explicit import of an environment's journals that are older than the migration ladder.
//!
//! [`kr_worker::persistence::import`] reads one journal. This decides which journals it may read,
//! for a whole environment, and runs from `kr host import-journals`, which holds the environment's
//! singleton lock: no daemon is running while it does. A worker can outlive its daemon, so a
//! session's journal is opened only when nothing this host can read says its worker may still be
//! there - the registry's worker row, a closure in the registry that never confirmed its worker's
//! end, and the published descriptor - and a source this host cannot read counts as saying so.
//! What is left of a worker whose end is confirmed, its descriptor and its endpoint, is fenced
//! before the journal is opened, as recovery ownership fences it.

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::SessionId;
use kr_protocol::session::DisplayNumber;
use kr_worker::journal::Journal;
use kr_worker::persistence::import::{Imported, import_journal};
use kr_worker::persistence::migration::OLDEST_MIGRATABLE;

use crate::archive::ArchiveService;
use crate::error::{ControllerError, Result};
use crate::registry::Registry;

/// The kind a closure gives a worker whose end this host never confirmed.
pub const UNACCOUNTED_WORKER: &str = "unaccounted_worker";

/// What the import did with one session's journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalImport {
    /// The session the journal belongs to.
    pub session_id: SessionId,
    /// What became of it.
    pub outcome: ImportOutcome,
}

/// What became of one journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportOutcome {
    /// It was brought from `from` to `to`, and kept its receipts.
    Imported {
        /// The version it recorded.
        from: i64,
        /// The version it records now.
        to: i64,
        /// How many receipts it holds.
        receipts: u64,
    },
    /// It records a version the ladder reads, or a newer one, so the import left it alone.
    Untouched {
        /// The version it records.
        version: i64,
    },
    /// It was not imported.
    Refused {
        /// Which kind of thing stopped it, in words fixed by this build.
        cause: RefusalCause,
        /// What stopped it, naming it.
        reason: String,
    },
}

/// Which kind of thing stopped a journal's import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalCause {
    /// Something this host can read says the session's worker may still be there, or a source
    /// that would say so cannot be read.
    WorkerMayRemain,
    /// What is left of a worker whose end is confirmed could not be fenced.
    NotFenced,
    /// The journal's recorded version could not be read.
    VersionUnreadable,
    /// The importer could not read the journal, and named what it could not read.
    Unreadable,
}

impl RefusalCause {
    /// Returns the stable name this cause is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkerMayRemain => "worker_may_remain",
            Self::NotFenced => "not_fenced",
            Self::VersionUnreadable => "version_unreadable",
            Self::Unreadable => "unreadable",
        }
    }

    /// Returns a sentence for a person about why the journal was not imported.
    #[must_use]
    pub const fn describe(self) -> &'static str {
        match self {
            Self::WorkerMayRemain => {
                "a worker may still own it, or what would say whether one does cannot be read"
            }
            Self::NotFenced => "what is left of its ended worker could not be fenced",
            Self::VersionUnreadable => "its schema version could not be read",
            Self::Unreadable => "it holds something the importer does not read",
        }
    }
}

/// Why a session's worker may still be there, or `None` when nothing says so, with what is left
/// to fence of one whose end is confirmed.
struct Evidence {
    remains: Option<String>,
    ended: Option<(DisplayNumber, ProcessStartIdentity)>,
}

impl ArchiveService {
    /// Imports every journal older than the migration ladder, once, and says what it did with each.
    ///
    /// The caller holds the environment's singleton lock, which is what makes this the only
    /// process touching these files: `kr host import-journals` takes it before it calls this. The
    /// registry is opened only when it is there, under that lock, as a daemon starting would open
    /// it; an environment with no registry has no worker rows or closures to ask.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal directory or an existing registry cannot be read: without
    /// them this host cannot say which journals a worker may still hold, and it imports none.
    pub fn import_journals(&self) -> Result<Vec<JournalImport>> {
        let path = self.paths().registry_database();
        let registry = match path.try_exists() {
            Ok(true) => Some(Registry::open(&path, self.paths().environment_id())?),
            Ok(false) => None,
            Err(error) => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} could not be looked for, so this host cannot say which journals a worker \
                     may still hold: {error}",
                    path.display()
                )));
            }
        };
        let mut done = Vec::new();
        for session_id in self.journals_on_disk()? {
            let outcome = self.import_one(registry.as_ref(), session_id);
            done.push(JournalImport {
                session_id,
                outcome,
            });
        }
        Ok(done)
    }

    /// Imports one session's journal, when it is older than the ladder and nothing says its
    /// worker may still be there.
    fn import_one(&self, registry: Option<&Registry>, session_id: SessionId) -> ImportOutcome {
        let path = self.paths().journal_database(session_id);
        let version = match Journal::recorded_schema_version(&path) {
            Ok(version) => version,
            Err(error) => {
                return ImportOutcome::Refused {
                    cause: RefusalCause::VersionUnreadable,
                    reason: format!("its schema version could not be read: {error}"),
                };
            }
        };
        if version >= OLDEST_MIGRATABLE {
            return ImportOutcome::Untouched { version };
        }
        let evidence = self.evidence_of_a_worker(registry, session_id);
        if let Some(reason) = evidence.remains {
            return ImportOutcome::Refused {
                cause: RefusalCause::WorkerMayRemain,
                reason,
            };
        }
        if let Some((display_number, identity)) = evidence.ended
            && let Err(error) = self.take_ownership(session_id, display_number, &identity)
        {
            return ImportOutcome::Refused {
                cause: RefusalCause::NotFenced,
                reason: error.to_string(),
            };
        }
        match import_journal(&path) {
            Ok(Imported::Imported { from, to, receipts }) => {
                ImportOutcome::Imported { from, to, receipts }
            }
            Ok(Imported::NothingToImport { version }) => ImportOutcome::Untouched { version },
            Err(refusal) => ImportOutcome::Refused {
                cause: RefusalCause::Unreadable,
                reason: refusal.to_string(),
            },
        }
    }

    /// Asks everything this host can read whether the session's worker may still be there.
    fn evidence_of_a_worker(&self, registry: Option<&Registry>, session_id: SessionId) -> Evidence {
        let mut ended = None;
        if let Some(registry) = registry {
            match registry.workers() {
                Ok(rows) => {
                    if let Some(row) = rows.iter().find(|row| row.session_id == session_id) {
                        if !confirmed_ended(&row.process_identity) {
                            return Evidence {
                                remains: Some(
                                    "the registry names its worker, and the kernel has not said \
                                     that process ended"
                                        .to_owned(),
                                ),
                                ended: None,
                            };
                        }
                        ended = Some((row.display_number, row.process_identity.clone()));
                    }
                }
                Err(error) => {
                    return Evidence {
                        remains: Some(format!("the registry's workers could not be read: {error}")),
                        ended: None,
                    };
                }
            }
            match registry.closure(session_id) {
                Ok(Some(closure))
                    if closure
                        .surviving
                        .iter()
                        .any(|resource| resource.kind == UNACCOUNTED_WORKER) =>
                {
                    return Evidence {
                        remains: Some(
                            "its closure lists a worker whose end was never confirmed".to_owned(),
                        ),
                        ended: None,
                    };
                }
                Ok(_) => {}
                Err(error) => {
                    return Evidence {
                        remains: Some(format!("its closure could not be read: {error}")),
                        ended: None,
                    };
                }
            }
        }
        match kr_ipc::descriptor::read(self.paths(), session_id) {
            Ok(None) => {}
            Ok(Some(descriptor)) => {
                if !confirmed_ended(&descriptor.process_start_identity) {
                    return Evidence {
                        remains: Some(
                            "its published descriptor names a process the kernel has not said \
                             ended"
                                .to_owned(),
                        ),
                        ended: None,
                    };
                }
                ended = Some((descriptor.display_number, descriptor.process_start_identity));
            }
            Err(error) => {
                return Evidence {
                    remains: Some(format!(
                        "its published descriptor could not be read: {error}"
                    )),
                    ended: None,
                };
            }
        }
        Evidence {
            remains: None,
            ended,
        }
    }

    /// Returns every session this host holds a journal file for.
    fn journals_on_disk(&self) -> Result<Vec<SessionId>> {
        let directory = self.paths().journals_dir();
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(ControllerError::InvalidArgument(format!(
                    "{} could not be read: {error}",
                    directory.display()
                )));
            }
        };
        let mut found = std::collections::BTreeSet::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                ControllerError::InvalidArgument(format!(
                    "{} could not be read to the end: {error}",
                    directory.display()
                ))
            })?;
            let name = entry.file_name();
            let Some(identifier) = name
                .to_str()
                .and_then(|name| name.strip_prefix("session-"))
                .and_then(|rest| rest.strip_suffix(".sqlite"))
            else {
                continue;
            };
            if let Ok(uuid) = identifier.parse::<kr_protocol::scalars::Uuid>() {
                found.insert(SessionId::new(uuid));
            }
        }
        Ok(found.into_iter().collect())
    }
}

/// Whether the kernel confirms the process with this identity has ended.
fn confirmed_ended(identity: &ProcessStartIdentity) -> bool {
    matches!(
        kr_ipc::identity::process_state(identity),
        kr_ipc::identity::ProcessState::Ended
    )
}
