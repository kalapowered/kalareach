//! The environment registry.
//!
//! Everything the control daemon must still know after it restarts lives here, and the order the
//! rows are written in is the whole point.
//!
//! * A **reservation** is recorded before anything is spawned: the actor, the create token, the
//!   payload digest, the allocated session identifier and display number, and the launch phase.
//!   A daemon that crashes between the reservation and the spawn finds the reservation and can
//!   decide what to do; one that spawned first would have a running worker nothing knows about.
//! * **Display numbers** are allocated in increasing order and never reused, so a number that once
//!   named a closed session never names a different one later.
//! * A **worker** row holds the public key the rendezvous established, which is what every later
//!   verification is checked against.
//! * A **tombstone** is the record of a closed session, so a reader is answered rather than being
//!   sent to an endpoint that might start something.
//!
//! # Process identities in whole seconds
//!
//! The previous build recorded a Windows process's start in whole seconds, and a worker it started
//! keeps running across an upgrade and keeps stating its identity that way, signed. So a record in
//! whole seconds is still read, and every time this registry is opened each such record the kernel
//! can settle is settled: a process still running is recorded at the resolution this build reads,
//! and one that has gone is marked ended. A record the kernel will not describe is left as it is
//! for the next opening. A worker row also keeps the source the worker itself states, which is how
//! a host can tell whether any running worker still states whole seconds. All of it goes with the
//! whole-seconds source, in the first release after one in which every running worker states the
//! creation time.

use kr_ipc::identity::CurrentProcess;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource, WorkerProfile};
use kr_protocol::ids::{
    ActorId, AuthorityRevision, ControllerGeneration, EnvironmentId, SessionId,
};
use kr_protocol::scalars::{AuthorisationKey, Digest256, TimestampMs, Uuid};
use kr_protocol::session::{ClosureRecord, DisplayNumber, SessionState};
use kr_protocol::worker::ReservationId;
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::{ControllerError, Result};

/// The schema version this build reads.
pub const SCHEMA_VERSION: i64 = 4;

/// How far a reservation has progressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchPhase {
    /// Recorded, nothing spawned.
    Reserved,
    /// The service manager was asked to start a worker. Execution may have begun.
    Spawned,
    /// A worker claimed this reservation. The claim is consumed; no second one is admitted.
    Claimed,
    /// The worker reported its root shell and the session is live.
    Live,
    /// The reservation was fenced and must never be resumed. Its execution is unresolved, so it
    /// still occupies a slot: something may be running that this host did not admit.
    Fenced,
    /// The launch is confirmed not to have produced a running worker. It occupies nothing.
    Failed,
    /// The session closed.
    Closed,
}

impl LaunchPhase {
    /// Returns the stable stored string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Spawned => "spawned",
            Self::Claimed => "claimed",
            Self::Live => "live",
            Self::Fenced => "fenced",
            Self::Failed => "failed",
            Self::Closed => "closed",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "reserved" => Some(Self::Reserved),
            "spawned" => Some(Self::Spawned),
            "claimed" => Some(Self::Claimed),
            "live" => Some(Self::Live),
            "fenced" => Some(Self::Fenced),
            "failed" => Some(Self::Failed),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

/// The configuration document an environment has applied the effects of.
///
/// The document itself, not a note that one was accepted. What a change owes is derived by
/// comparing the document that arrives with the document that was accepted, and a daemon that came
/// back holding only a revision number could not make that comparison: removing a ceiling, putting
/// an older document back and editing one in place without moving its revision all look like
/// nothing from a number alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcceptedConfiguration {
    /// The revision whose effects are applied. Zero where this environment has accepted none.
    pub revision: u64,
    /// The document those effects came from, as this host writes one, when there was a usable one.
    pub document: Option<String>,
}

/// One recorded create reservation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    /// The reservation identity.
    pub reservation_id: ReservationId,
    /// The actor that asked for the session.
    pub actor_id: ActorId,
    /// The idempotent create token, which is the action identifier of the request.
    pub create_token: Uuid,
    /// The digest of the immutable create payload.
    pub payload_digest: Digest256,
    /// The create request itself, canonically encoded.
    ///
    /// It is written before anything is spawned. A daemon that restarts mid-create can then say
    /// what the session was going to be instead of holding an identifier with no request behind it.
    /// It is absent only for a reservation an earlier schema recorded without one.
    pub create_intent: Option<Vec<u8>>,
    /// The session identifier allocated for it.
    pub session_id: SessionId,
    /// The display number allocated for it.
    pub display_number: DisplayNumber,
    /// How far it has progressed.
    pub phase: LaunchPhase,
    /// The process identity the launcher reported, once one exists.
    pub launcher_identity: Option<ProcessStartIdentity>,
    /// The public key the claiming worker presented, recorded when the claim was consumed.
    ///
    /// This reaches storage before the worker is told anything, so a worker that starts a shell and
    /// then loses its ready report is still a worker this host can authenticate.
    pub claimed_key: Option<AuthorisationKey>,
    /// When it was recorded.
    pub created_at_ms: TimestampMs,
}

/// One worker the registry knows about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerRecord {
    /// The session the worker owns.
    pub session_id: SessionId,
    /// The display number.
    pub display_number: DisplayNumber,
    /// The public key established at rendezvous.
    pub public_key: AuthorisationKey,
    /// The worker's process identity.
    pub process_identity: ProcessStartIdentity,
    /// The worker's private endpoint.
    pub endpoint: String,
    /// How long the execution context lasts.
    pub profile: WorkerProfile,
    /// The lifecycle state as the registry knows it.
    pub state: SessionState,
    /// The authority revision this worker has acknowledged.
    pub acknowledged_revision: AuthorityRevision,
}

/// The environment registry.
#[derive(Debug)]
pub struct Registry {
    connection: Connection,
    environment_id: EnvironmentId,
    /// Asks the kernel about a recorded process and names it as this build reads it.
    ///
    /// It settles the records the previous build made in whole seconds; a test states what the
    /// kernel says instead.
    current_process: fn(&ProcessStartIdentity) -> CurrentProcess,
}

impl Registry {
    /// Opens the registry for an environment, creating it on first use.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the database cannot be opened or
    /// migrated.
    pub fn open(path: impl AsRef<std::path::Path>, environment_id: EnvironmentId) -> Result<Self> {
        let connection = Connection::open(path.as_ref()).map_err(ControllerError::registry)?;
        Self::prepare(connection, environment_id)
    }

    /// Opens a registry that exists only for the life of this process.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the database cannot be created.
    pub fn in_memory(environment_id: EnvironmentId) -> Result<Self> {
        Self::prepare(
            Connection::open_in_memory().map_err(ControllerError::registry)?,
            environment_id,
        )
    }

    fn prepare(connection: Connection, environment_id: EnvironmentId) -> Result<Self> {
        Self::prepare_reading(
            connection,
            environment_id,
            kr_ipc::identity::current_process,
        )
    }

    /// Opens the registry as [`Self::prepare`] does, asking `current_process` about recorded
    /// processes.
    fn prepare_reading(
        connection: Connection,
        environment_id: EnvironmentId,
        current_process: fn(&ProcessStartIdentity) -> CurrentProcess,
    ) -> Result<Self> {
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ControllerError::registry)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ControllerError::registry)?;
        let registry = Self {
            connection,
            environment_id,
            current_process,
        };
        registry.migrate()?;
        registry.settle_whole_seconds()?;
        Ok(registry)
    }

    fn migrate(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS environment (
                     environment_id      BLOB PRIMARY KEY,
                     generation          INTEGER NOT NULL,
                     next_display        INTEGER NOT NULL,
                     session_limit       INTEGER NOT NULL,
                     authority_revision  INTEGER NOT NULL DEFAULT 0,
                     fence_owed_revision INTEGER NOT NULL DEFAULT 0,
                     accepted_revision   INTEGER NOT NULL DEFAULT 0,
                     accepted_document   TEXT
                 );
                 CREATE TABLE IF NOT EXISTS reservations (
                     reservation_id    BLOB PRIMARY KEY,
                     actor_id          TEXT NOT NULL,
                     create_token      BLOB NOT NULL,
                     payload_digest    BLOB NOT NULL,
                     create_intent     BLOB,
                     session_id        BLOB NOT NULL UNIQUE,
                     display_number    INTEGER NOT NULL UNIQUE,
                     phase             TEXT NOT NULL,
                     launcher_pid      INTEGER,
                     launcher_source   TEXT,
                     launcher_start    INTEGER,
                     claimed_key       BLOB,
                     created_at_ms     INTEGER NOT NULL,
                     UNIQUE (actor_id, create_token)
                 );
                 CREATE TABLE IF NOT EXISTS workers (
                     session_id       BLOB PRIMARY KEY,
                     display_number   INTEGER NOT NULL,
                     public_key       BLOB NOT NULL,
                     process_pid      INTEGER NOT NULL,
                     process_source   TEXT NOT NULL,
                     process_start    INTEGER NOT NULL,
                     endpoint         TEXT NOT NULL,
                     profile          TEXT NOT NULL,
                     state            TEXT NOT NULL,
                     acknowledged_revision INTEGER NOT NULL DEFAULT 0,
                     stated_source    TEXT NOT NULL DEFAULT ''
                 );
                 CREATE TABLE IF NOT EXISTS tombstones (
                     session_id BLOB PRIMARY KEY,
                     record     BLOB NOT NULL,
                     closed_at_ms INTEGER NOT NULL
                 );",
            )
            .map_err(ControllerError::registry)?;
        let recorded: Option<i64> = self
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .optional()
            .map_err(ControllerError::registry)?;
        match recorded {
            None => {
                self.connection
                    .execute(
                        "INSERT INTO schema_version (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(ControllerError::registry)?;
            }
            Some(version) if version == SCHEMA_VERSION => {}
            Some(1) => {
                self.migrate_1_to_2()?;
                self.migrate_2_to_3()?;
                self.migrate_3_to_4()?;
            }
            Some(2) => {
                self.migrate_2_to_3()?;
                self.migrate_3_to_4()?;
            }
            Some(3) => self.migrate_3_to_4()?,
            Some(version) => {
                return Err(ControllerError::RegistryUnavailable {
                    detail: format!(
                        "this registry is at schema version {version}; this build reads {SCHEMA_VERSION}"
                    ),
                });
            }
        }
        self.connection
            .execute(
                "INSERT OR IGNORE INTO environment
                     (environment_id, generation, next_display, session_limit)
                 VALUES (?1, 0, 1, ?2)",
                params![
                    self.environment_id.get().as_bytes().as_slice(),
                    i64::try_from(kr_protocol::limits::DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT)
                        .unwrap_or(128)
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Brings a version 1 registry forward.
    ///
    /// Version 1 recorded a create request's digest but not the request, and recorded the worker's
    /// key only once the session went live. Both columns are added empty: a reservation written by
    /// version 1 genuinely has no recorded request, and recovery treats a missing one as a launch
    /// it cannot resume rather than inventing a session to start.
    ///
    /// Version 1 had no `claimed` phase, so its `spawned` rows cover both "the worker never
    /// reached the rendezvous" and "it did, and may have started a shell". They become `claimed`,
    /// which is the one this host can resolve without assuming the more convenient of the two.
    ///
    /// Version 1 also issued no authority revisions, so the environment and every worker come
    /// forward at revision zero: that is not an assumption about what a worker answered, it is what
    /// a registry with no revisions in it means. The columns are added here rather than left for
    /// the next migration, because every migration after this one reads them.
    ///
    /// This migration goes when there can no longer be a version 1 registry to read, which is the
    /// first release: nothing before it is installed anywhere it has to be read from again.
    fn migrate_1_to_2(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 ALTER TABLE reservations ADD COLUMN create_intent BLOB;
                 ALTER TABLE reservations ADD COLUMN claimed_key BLOB;
                 ALTER TABLE environment ADD COLUMN authority_revision INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE workers ADD COLUMN acknowledged_revision INTEGER NOT NULL DEFAULT 0;
                 UPDATE reservations SET phase = 'claimed' WHERE phase = 'spawned';
                 UPDATE schema_version SET version = 2;
                 COMMIT;",
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Brings a version 2 registry forward.
    ///
    /// Version 2 recorded the authority revision but not whether the fence that revision raised had
    /// been answered, so a daemon that stopped with a worker still holding withdrawn authority came
    /// back believing the revocation complete. Every environment that has issued a revision comes
    /// forward owing its current one: a version 2 registry cannot say which of its revisions a
    /// worker answered, and the safe answer to a question with no recorded answer is that the debt
    /// stands. One announcement settles it where every worker has in fact answered, and that
    /// announcement happens at the first start after the upgrade.
    ///
    /// Version 2 also recorded nothing about which configuration document this environment had
    /// accepted, so it comes forward having accepted none: the columns stay at their defaults and
    /// the first start after the upgrade puts whatever document it finds through acceptance. That
    /// costs one acceptance of a document that may well already be in force, and the alternative is
    /// a host that treats a document written by a daemon that never finished applying it as
    /// already applied.
    ///
    /// This migration goes when there can no longer be a version 2 registry to read, which is the
    /// first release: nothing before it is installed anywhere it has to be read from again.
    fn migrate_2_to_3(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 ALTER TABLE environment ADD COLUMN fence_owed_revision INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE environment ADD COLUMN accepted_revision INTEGER NOT NULL DEFAULT 0;
                 ALTER TABLE environment ADD COLUMN accepted_document TEXT;
                 UPDATE environment SET fence_owed_revision = authority_revision
                  WHERE authority_revision > 0;
                 UPDATE schema_version SET version = 3;
                 COMMIT;",
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Brings a version 3 registry forward.
    ///
    /// Version 3 recorded the process identity each worker stated and nothing beside it, so what
    /// a worker states was what the row said. Version 4 keeps the two apart, because a worker of
    /// the previous build states its start in whole seconds while its row is settled at the
    /// resolution this build reads: each row comes forward stating the source it recorded.
    ///
    /// This migration goes with the whole-seconds source, in the first release after one in which
    /// every running worker states the creation time: until then a registry the previous build
    /// wrote may still be opened by this one.
    fn migrate_3_to_4(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 ALTER TABLE workers ADD COLUMN stated_source TEXT NOT NULL DEFAULT '';
                 UPDATE workers SET stated_source = process_source;
                 UPDATE schema_version SET version = 4;
                 COMMIT;",
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Settles every record of a process in whole seconds that the kernel can settle.
    ///
    /// The previous build recorded a Windows process's start in whole seconds: a worker's launcher
    /// in its reservation and the worker in its row. Each such record is put to the kernel the way
    /// that build read it - the process holding the identifier now, if it was created in that
    /// second - and a process that is still running is recorded at the resolution this build reads,
    /// while one that has gone is marked ended, not rewritten. A record the kernel will not
    /// describe is left in whole seconds, and is read the previous build's way until an opening
    /// settles it. What a worker row says the worker states is left as it was.
    ///
    /// It goes with the whole-seconds source, in the first release after one in which every
    /// running worker states the creation time.
    fn settle_whole_seconds(&self) -> Result<()> {
        let seconds = source_name(ProcessStartSource::WindowsProcessStartSeconds);
        let workers: Vec<(Vec<u8>, i64, i64)> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT session_id, process_pid, process_start FROM workers
                     WHERE process_source = ?1",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map(params![seconds], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(ControllerError::registry)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(ControllerError::registry)?
        };
        for (session, pid, start) in workers {
            if let Some(settled) = self.settled(&in_whole_seconds(pid, start)) {
                self.connection
                    .execute(
                        "UPDATE workers SET process_source = ?2, process_start = ?3
                         WHERE session_id = ?1 AND process_source = ?4",
                        params![
                            session,
                            source_name(settled.source),
                            start_column(settled.start_value.get()),
                            seconds
                        ],
                    )
                    .map_err(ControllerError::registry)?;
            }
        }
        let launches: Vec<(Vec<u8>, i64, i64)> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT reservation_id, launcher_pid, launcher_start FROM reservations
                     WHERE launcher_source = ?1
                       AND launcher_pid IS NOT NULL AND launcher_start IS NOT NULL",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map(params![seconds], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .map_err(ControllerError::registry)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(ControllerError::registry)?
        };
        for (reservation, pid, start) in launches {
            if let Some(settled) = self.settled(&in_whole_seconds(pid, start)) {
                self.connection
                    .execute(
                        "UPDATE reservations SET launcher_source = ?2, launcher_start = ?3
                         WHERE reservation_id = ?1 AND launcher_source = ?4",
                        params![
                            reservation,
                            source_name(settled.source),
                            start_column(settled.start_value.get()),
                            seconds
                        ],
                    )
                    .map_err(ControllerError::registry)?;
            }
        }
        Ok(())
    }

    /// What a record of a process in whole seconds becomes, when the kernel says what it is: the
    /// process at the resolution this build reads when it is still running, the ended marker when
    /// it has gone, and nothing when the kernel will not say.
    fn settled(&self, recorded: &ProcessStartIdentity) -> Option<ProcessStartIdentity> {
        match (self.current_process)(recorded) {
            CurrentProcess::Running(current) => Some(current),
            CurrentProcess::Ended => u32::try_from(recorded.pid.get())
                .ok()
                .map(kr_ipc::identity::ended_process_identity),
            CurrentProcess::Unknown { .. } => None,
        }
    }

    /// Returns the identity this registry records for the process a worker states, in the row of
    /// `session_id`.
    ///
    /// The identity itself, unless it is in whole seconds, which a worker of the previous build
    /// states. Then the finer identity this registry already established for that worker's
    /// process is kept: it was proved when it was recorded, and asking the kernel again could only
    /// answer less, or name a later process created in the same second under the identifier. Only
    /// a row with no finer identity for that process is settled now, as the opening settles one.
    fn to_record(
        &self,
        session_id: SessionId,
        stated: &ProcessStartIdentity,
    ) -> Result<ProcessStartIdentity> {
        if stated.source != ProcessStartSource::WindowsProcessStartSeconds {
            return Ok(stated.clone());
        }
        if let Some(established) = self.recorded_process(session_id)?
            && established.source == ProcessStartSource::WindowsProcessCreationTime
            && established.pid == stated.pid
            && established.start_value.get() != kr_ipc::identity::START_VALUE_UNREAD
            && established.start_value.get() / CREATION_TIME_UNITS_PER_SECOND
                == stated.start_value.get()
        {
            return Ok(established);
        }
        Ok(self.settled(stated).unwrap_or_else(|| stated.clone()))
    }

    /// Returns the process identity one worker row records, when there is a row.
    fn recorded_process(&self, session_id: SessionId) -> Result<Option<ProcessStartIdentity>> {
        let row: Option<(i64, String, i64)> = self
            .connection
            .query_row(
                "SELECT process_pid, process_source, process_start FROM workers
                 WHERE session_id = ?1",
                params![session_id.get().as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        row.map(|(pid, source, start)| {
            Ok(ProcessStartIdentity {
                pid: kr_protocol::scalars::U64::new(u64::try_from(pid).unwrap_or_default()),
                source: source_from(&source)?,
                start_value: kr_protocol::scalars::U64::new(start_from_column(start)),
            })
        })
        .transpose()
    }

    /// Returns the environment this registry belongs to.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Advances and returns the persistent controller generation.
    ///
    /// A new holder of the singleton lock advances the generation **before** it reconnects to any
    /// worker. That is what makes the previous holder unable to present the current generation:
    /// the number it holds is already behind.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn advance_generation(&mut self) -> Result<ControllerGeneration> {
        self.connection
            .execute(
                "UPDATE environment SET generation = generation + 1 WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
            )
            .map_err(ControllerError::registry)?;
        self.generation()
    }

    /// Returns the current generation.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn generation(&self) -> Result<ControllerGeneration> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT generation FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        Ok(ControllerGeneration::new(
            u64::try_from(value).unwrap_or_default(),
        ))
    }

    /// Returns the environment's current authority revision.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn authority_revision(&self) -> Result<AuthorityRevision> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT authority_revision FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        Ok(AuthorityRevision::new(
            u64::try_from(value).unwrap_or_default(),
        ))
    }

    /// Advances the environment's authority revision and records the fence it owes.
    ///
    /// Only the host issues revisions, and they only ever increase. A revocation advances this and
    /// is then pending at every worker until each has acknowledged the new number or is confirmed
    /// ended.
    ///
    /// The debt is written by the same statement as the revision, so the two cannot come apart. A
    /// revision that advanced is not a completed revocation, and the daemon that advanced it can
    /// stop between the write and the announcement; recording the debt afterwards, or only once the
    /// effects behind it had landed, is how a host comes back believing a fence held that no worker
    /// ever answered. It is settled by [`Self::settle_fence`] and by nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn advance_authority_revision(&mut self) -> Result<AuthorityRevision> {
        self.connection
            .execute(
                "UPDATE environment
                    SET authority_revision  = authority_revision + 1,
                        fence_owed_revision = authority_revision + 1
                  WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
            )
            .map_err(ControllerError::registry)?;
        self.authority_revision()
    }

    /// Returns the revision whose fence this environment still owes, when it owes one.
    ///
    /// The durable answer to "has every worker acknowledged the authority this host withdrew". It
    /// survives a restart, an effect that failed after the fence went up, and a configuration
    /// document that later becomes unusable, because none of those is a worker answering.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn fence_owed(&self) -> Result<Option<AuthorityRevision>> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT fence_owed_revision FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        let revision = u64::try_from(value).unwrap_or_default();
        Ok((revision > 0).then(|| AuthorityRevision::new(revision)))
    }

    /// Returns the configuration document this environment has accepted.
    ///
    /// The durable half of acceptance. A document is written before its effects are applied, so the
    /// file on disk says nothing about whether this host ever acted on it: only this record does.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn accepted_configuration(&self) -> Result<AcceptedConfiguration> {
        let (revision, document): (i64, Option<String>) = self
            .connection
            .query_row(
                "SELECT accepted_revision, accepted_document FROM environment
                  WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(ControllerError::registry)?;
        Ok(AcceptedConfiguration {
            revision: u64::try_from(revision).unwrap_or_default(),
            document,
        })
    }

    /// Records the configuration document whose effects this environment has applied.
    ///
    /// Written after the effects have landed and never before: a record written first would tell
    /// the next start that a document had been acted on when the daemon stopped in the middle of
    /// acting on it. The fence a ceiling here raised is recorded the other way round, ahead of its
    /// announcement, because the two answer opposite questions - what this host still owes, and
    /// what it has already done.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_accepted_configuration(
        &mut self,
        accepted: &AcceptedConfiguration,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE environment
                    SET accepted_revision = ?2, accepted_document = ?3
                  WHERE environment_id = ?1",
                params![
                    self.environment_id.get().as_bytes().as_slice(),
                    i64::try_from(accepted.revision).unwrap_or(i64::MAX),
                    accepted.document.as_deref()
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Settles the fence debt up to and including `revision`.
    ///
    /// Called only where every worker has acknowledged that revision or is confirmed ended, which
    /// is what a barrier holding means. A debt raised at a *later* revision is left alone: it
    /// belongs to a revocation this barrier says nothing about.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn settle_fence(&mut self, revision: AuthorityRevision) -> Result<()> {
        self.connection
            .execute(
                "UPDATE environment SET fence_owed_revision = 0
                  WHERE environment_id = ?1 AND fence_owed_revision <= ?2",
                params![
                    self.environment_id.get().as_bytes().as_slice(),
                    i64::try_from(revision.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Records the authority revision one worker has acknowledged.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_acknowledged_revision(
        &mut self,
        session_id: SessionId,
        revision: AuthorityRevision,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE workers SET acknowledged_revision = ?2
                 WHERE session_id = ?1 AND acknowledged_revision < ?2",
                params![
                    session_id.get().as_bytes().as_slice(),
                    i64::try_from(revision.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns the configured admission limit.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn session_limit(&self) -> Result<u64> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT session_limit FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        Ok(u64::try_from(value).unwrap_or_default())
    }

    /// Sets the admission limit.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn set_session_limit(&mut self, limit: u64) -> Result<()> {
        self.connection
            .execute(
                "UPDATE environment SET session_limit = ?2 WHERE environment_id = ?1",
                params![
                    self.environment_id.get().as_bytes().as_slice(),
                    i64::try_from(limit).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns how many sessions occupy the environment.
    ///
    /// A fenced reservation counts. Fencing means the host stopped trusting a claim, not that the
    /// execution behind it ended; until that is resolved something may be running, and admitting a
    /// new session in its place would put the environment over its limit.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn occupancy(&self) -> Result<u64> {
        let value: i64 = self
            .connection
            .query_row(
                "SELECT COUNT(*) FROM reservations
                 WHERE phase IN ('reserved', 'spawned', 'claimed', 'live', 'fenced')",
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        Ok(u64::try_from(value).unwrap_or_default())
    }

    /// Returns every reservation in one phase.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn reservations_in(&self, phase: LaunchPhase) -> Result<Vec<Reservation>> {
        let ids: Vec<Vec<u8>> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT reservation_id FROM reservations WHERE phase = ?1
                     ORDER BY display_number",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map(params![phase.as_str()], |row| row.get::<_, Vec<u8>>(0))
                .map_err(ControllerError::registry)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(ControllerError::registry)?
        };
        let mut reservations = Vec::new();
        for id in ids {
            let reservation_id = ReservationId::new(uuid_from(&id)?);
            if let Some(reservation) = self.reservation(reservation_id)? {
                reservations.push(reservation);
            }
        }
        Ok(reservations)
    }

    /// Records a reservation, or returns the one this create token already made.
    ///
    /// The whole record is committed in one transaction before anything is spawned. A repeated
    /// token with the same payload returns the original reservation; the same token with a
    /// different payload is a conflict rather than a second session.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::SessionLimit`] when the environment is full,
    /// [`ControllerError::InvalidArgument`] when a token is reused with a different payload, and a
    /// registry failure when the write fails.
    pub fn reserve(
        &mut self,
        actor_id: &ActorId,
        create_token: Uuid,
        payload_digest: Digest256,
        create_intent: &[u8],
        now_ms: TimestampMs,
    ) -> Result<Admission> {
        if let Some(existing) = self.reservation_for_token(actor_id, create_token)? {
            if existing.payload_digest != payload_digest {
                return Err(ControllerError::IdConflict {
                    token: create_token.to_string(),
                });
            }
            return Ok(Admission {
                reservation: existing,
                deduplicated: true,
            });
        }
        let limit = self.session_limit()?;
        let live = self.occupancy()?;
        if live >= limit {
            // Rejected before anything is spawned. Nothing is ever evicted to make room.
            return Err(ControllerError::SessionLimit {
                environment: self.environment_id.to_string(),
                live,
                limit,
            });
        }
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        let next_display: i64 = transaction
            .query_row(
                "SELECT next_display FROM environment WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE environment SET next_display = next_display + 1 WHERE environment_id = ?1",
                params![self.environment_id.get().as_bytes().as_slice()],
            )
            .map_err(ControllerError::registry)?;
        let reservation = Reservation {
            reservation_id: ReservationId::new(kr_ipc::new_uuid()),
            actor_id: actor_id.clone(),
            create_token,
            payload_digest,
            create_intent: Some(create_intent.to_vec()),
            session_id: SessionId::new(kr_ipc::new_uuid()),
            display_number: DisplayNumber::new(u64::try_from(next_display).unwrap_or_default()),
            phase: LaunchPhase::Reserved,
            launcher_identity: None,
            claimed_key: None,
            created_at_ms: now_ms,
        };
        transaction
            .execute(
                "INSERT INTO reservations (reservation_id, actor_id, create_token, payload_digest,
                     create_intent, session_id, display_number, phase, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    reservation.reservation_id.get().as_bytes().as_slice(),
                    reservation.actor_id.as_str(),
                    reservation.create_token.as_bytes().as_slice(),
                    reservation.payload_digest.as_bytes().as_slice(),
                    create_intent,
                    reservation.session_id.get().as_bytes().as_slice(),
                    i64::try_from(reservation.display_number.get()).unwrap_or(i64::MAX),
                    reservation.phase.as_str(),
                    i64::try_from(now_ms.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(Admission {
            reservation,
            deduplicated: false,
        })
    }

    /// Records the identity the launcher reported for a spawned reservation.
    ///
    /// The phase is not touched. It moved to `spawned` before the service manager was called, and
    /// a reservation that has since been claimed or fenced must not be moved back by a launcher
    /// report that arrives afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_launch(
        &mut self,
        reservation_id: ReservationId,
        identity: &ProcessStartIdentity,
    ) -> Result<()> {
        self.connection
            .execute(
                "UPDATE reservations SET launcher_pid = ?2, launcher_source = ?3,
                        launcher_start = ?4
                 WHERE reservation_id = ?1",
                params![
                    reservation_id.get().as_bytes().as_slice(),
                    i64::try_from(identity.pid.get()).unwrap_or(i64::MAX),
                    source_name(identity.source),
                    start_column(identity.start_value.get()),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Consumes a reservation's single rendezvous admission.
    ///
    /// One launched process, one claim. The phase moves out of `spawned` in the same transaction
    /// that reads it, so two claims arriving together cannot both find it spawned; the second one
    /// finds `claimed` and is fenced. The worker's public key is written here, before the worker is
    /// told anything, so a claim that is admitted is a claim this host can authenticate afterwards
    /// whatever happens next.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RendezvousRefused`] when the reservation is not waiting for a
    /// claim, and a registry failure when the write fails.
    pub fn claim_rendezvous(
        &mut self,
        reservation_id: ReservationId,
        worker_public_key: AuthorisationKey,
    ) -> Result<Reservation> {
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        let phase: Option<String> = transaction
            .query_row(
                "SELECT phase FROM reservations WHERE reservation_id = ?1",
                params![reservation_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let phase = phase
            .as_deref()
            .and_then(LaunchPhase::parse)
            .ok_or_else(|| ControllerError::rendezvous("no reservation matches this claim"))?;
        if phase != LaunchPhase::Spawned {
            // A second claim on one reservation means the host cannot tell which process owns the
            // session. Fencing it is the only answer that does not hand the session to a guess.
            if matches!(phase, LaunchPhase::Claimed | LaunchPhase::Live) {
                transaction
                    .execute(
                        "UPDATE reservations SET phase = ?2 WHERE reservation_id = ?1",
                        params![
                            reservation_id.get().as_bytes().as_slice(),
                            LaunchPhase::Fenced.as_str()
                        ],
                    )
                    .map_err(ControllerError::registry)?;
                transaction.commit().map_err(ControllerError::registry)?;
            }
            return Err(ControllerError::rendezvous(format!(
                "this reservation is {} and accepts no further claim",
                phase.as_str()
            )));
        }
        transaction
            .execute(
                "UPDATE reservations SET phase = ?2, claimed_key = ?3 WHERE reservation_id = ?1",
                params![
                    reservation_id.get().as_bytes().as_slice(),
                    LaunchPhase::Claimed.as_str(),
                    worker_public_key.as_bytes().as_slice(),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        self.reservation(reservation_id)?
            .ok_or_else(|| ControllerError::rendezvous("the reservation vanished"))
    }

    /// Moves a reservation out of `claimed` into a resolved phase.
    ///
    /// Only a claim is resolved this way. A reservation that has been fenced since the claim was
    /// consumed stays fenced: whatever answer arrives afterwards does not tell the host which of
    /// two claimants owns the session.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn resolve_claim(
        &mut self,
        reservation_id: ReservationId,
        phase: LaunchPhase,
    ) -> Result<bool> {
        let changed = self
            .connection
            .execute(
                "UPDATE reservations SET phase = ?2 WHERE reservation_id = ?1 AND phase = ?3",
                params![
                    reservation_id.get().as_bytes().as_slice(),
                    phase.as_str(),
                    LaunchPhase::Claimed.as_str()
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(changed > 0)
    }

    /// Fences a reservation, whatever phase it is in.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn fence(&mut self, reservation_id: ReservationId) -> Result<()> {
        self.set_phase(reservation_id, LaunchPhase::Fenced)
    }

    /// Moves a reservation to a new phase.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn set_phase(&mut self, reservation_id: ReservationId, phase: LaunchPhase) -> Result<()> {
        self.connection
            .execute(
                "UPDATE reservations SET phase = ?2 WHERE reservation_id = ?1",
                params![reservation_id.get().as_bytes().as_slice(), phase.as_str()],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Reads one reservation.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn reservation(&self, reservation_id: ReservationId) -> Result<Option<Reservation>> {
        self.read_reservation(
            "SELECT reservation_id, actor_id, create_token, payload_digest, session_id,
                    display_number, phase, launcher_pid, launcher_source, launcher_start,
                    created_at_ms, create_intent, claimed_key
             FROM reservations WHERE reservation_id = ?1",
            params![reservation_id.get().as_bytes().as_slice()],
        )
    }

    /// Reads the reservation that allocated a session.
    ///
    /// The reservation row survives closure, so a closed session still has a display number to be
    /// listed under.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn reservation_for_session(&self, session_id: SessionId) -> Result<Option<Reservation>> {
        self.read_reservation(
            "SELECT reservation_id, actor_id, create_token, payload_digest, session_id,
                    display_number, phase, launcher_pid, launcher_source, launcher_start,
                    created_at_ms, create_intent, claimed_key
             FROM reservations WHERE session_id = ?1",
            params![session_id.get().as_bytes().as_slice()],
        )
    }

    /// Returns the reservation one actor's create token already named, if any.
    ///
    /// # Errors
    ///
    /// Returns an error when the registry cannot be read.
    pub fn reservation_for_token(
        &self,
        actor_id: &ActorId,
        create_token: Uuid,
    ) -> Result<Option<Reservation>> {
        self.read_reservation(
            "SELECT reservation_id, actor_id, create_token, payload_digest, session_id,
                    display_number, phase, launcher_pid, launcher_source, launcher_start,
                    created_at_ms, create_intent, claimed_key
             FROM reservations WHERE actor_id = ?1 AND create_token = ?2",
            params![actor_id.as_str(), create_token.as_bytes().as_slice()],
        )
    }

    fn read_reservation(
        &self,
        query: &str,
        parameters: impl rusqlite::Params,
    ) -> Result<Option<Reservation>> {
        self.connection
            .query_row(query, parameters, |row| {
                Ok(RawReservation {
                    reservation: row.get(0)?,
                    actor: row.get(1)?,
                    token: row.get(2)?,
                    digest: row.get(3)?,
                    session: row.get(4)?,
                    display: row.get(5)?,
                    phase: row.get(6)?,
                    pid: row.get(7)?,
                    source: row.get(8)?,
                    start: row.get(9)?,
                    created: row.get(10)?,
                    create_intent: row.get(11)?,
                    claimed_key: row.get(12)?,
                })
            })
            .optional()
            .map_err(ControllerError::registry)?
            .map(RawReservation::into_reservation)
            .transpose()
    }

    /// Returns every reservation whose session has closed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn closed_reservations(&self) -> Result<Vec<Reservation>> {
        let sessions: Vec<Vec<u8>> = {
            let mut statement = self
                .connection
                .prepare(
                    "SELECT session_id FROM reservations WHERE phase = ?1 ORDER BY display_number",
                )
                .map_err(ControllerError::registry)?;
            let rows = statement
                .query_map(params![LaunchPhase::Closed.as_str()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })
                .map_err(ControllerError::registry)?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(ControllerError::registry)?
        };
        let mut reservations = Vec::new();
        for session in sessions {
            let session_id = SessionId::new(uuid_from(&session)?);
            if let Some(reservation) = self.reservation_for_session(session_id)? {
                reservations.push(reservation);
            }
        }
        Ok(reservations)
    }

    /// Records a worker inside the reservation-to-live transition.
    ///
    /// The public key, the process identity and the live phase are committed together, so a
    /// registry that knows a session is live always knows which key answers for it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_worker(
        &mut self,
        reservation_id: ReservationId,
        worker: &WorkerRecord,
    ) -> Result<()> {
        let recorded = self.to_record(worker.session_id, &worker.process_identity)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "INSERT INTO workers (session_id, display_number, public_key, process_pid,
                     process_source, process_start, endpoint, profile, state, stated_source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT (session_id) DO UPDATE SET
                     public_key = excluded.public_key,
                     process_pid = excluded.process_pid,
                     process_source = excluded.process_source,
                     process_start = excluded.process_start,
                     endpoint = excluded.endpoint,
                     state = excluded.state,
                     stated_source = excluded.stated_source",
                params![
                    worker.session_id.get().as_bytes().as_slice(),
                    i64::try_from(worker.display_number.get()).unwrap_or(i64::MAX),
                    worker.public_key.as_bytes().as_slice(),
                    i64::try_from(recorded.pid.get()).unwrap_or(i64::MAX),
                    source_name(recorded.source),
                    start_column(recorded.start_value.get()),
                    worker.endpoint,
                    worker.profile.as_str(),
                    worker.state.as_str(),
                    source_name(worker.process_identity.source),
                ],
            )
            .map_err(ControllerError::registry)?;
        // Only a consumed claim becomes live. A reservation that was fenced while its worker was
        // reporting stays fenced: the ready report does not answer the question fencing asked.
        let promoted = transaction
            .execute(
                "UPDATE reservations SET phase = ?2 WHERE reservation_id = ?1 AND phase = ?3",
                params![
                    reservation_id.get().as_bytes().as_slice(),
                    LaunchPhase::Live.as_str(),
                    LaunchPhase::Claimed.as_str(),
                ],
            )
            .map_err(ControllerError::registry)?;
        if promoted == 0 {
            transaction.rollback().map_err(ControllerError::registry)?;
            return Err(ControllerError::rendezvous(
                "this reservation is no longer waiting for a ready report",
            ));
        }
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Records a worker row without touching any reservation phase.
    ///
    /// Recovery uses this: the worker already exists and already proved itself, so what is missing
    /// is the daemon's own record of it, not a transition.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn adopt_worker(&mut self, worker: &WorkerRecord) -> Result<()> {
        let recorded = self.to_record(worker.session_id, &worker.process_identity)?;
        self.connection
            .execute(
                "INSERT INTO workers (session_id, display_number, public_key, process_pid,
                     process_source, process_start, endpoint, profile, state, stated_source)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT (session_id) DO UPDATE SET
                     public_key = excluded.public_key,
                     process_pid = excluded.process_pid,
                     process_source = excluded.process_source,
                     process_start = excluded.process_start,
                     endpoint = excluded.endpoint,
                     state = excluded.state,
                     stated_source = excluded.stated_source",
                params![
                    worker.session_id.get().as_bytes().as_slice(),
                    i64::try_from(worker.display_number.get()).unwrap_or(i64::MAX),
                    worker.public_key.as_bytes().as_slice(),
                    i64::try_from(recorded.pid.get()).unwrap_or(i64::MAX),
                    source_name(recorded.source),
                    start_column(recorded.start_value.get()),
                    worker.endpoint,
                    worker.profile.as_str(),
                    worker.state.as_str(),
                    source_name(worker.process_identity.source),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns every worker the registry knows about.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn workers(&self) -> Result<Vec<WorkerRecord>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT session_id, display_number, public_key, process_pid, process_source,
                        process_start, endpoint, profile, state, acknowledged_revision
                 FROM workers ORDER BY display_number",
            )
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            })
            .map_err(ControllerError::registry)?;
        let mut workers = Vec::new();
        for row in rows {
            let (session, display, key, pid, source, start, endpoint, profile, state, revision) =
                row.map_err(ControllerError::registry)?;
            workers.push(WorkerRecord {
                session_id: SessionId::new(uuid_from(&session)?),
                display_number: DisplayNumber::new(u64::try_from(display).unwrap_or_default()),
                public_key: key_from(&key)?,
                process_identity: ProcessStartIdentity {
                    pid: kr_protocol::scalars::U64::new(u64::try_from(pid).unwrap_or_default()),
                    source: source_from(&source)?,
                    start_value: kr_protocol::scalars::U64::new(start_from_column(start)),
                },
                endpoint,
                profile: profile_from(&profile)?,
                state: state_from(&state)?,
                acknowledged_revision: AuthorityRevision::new(
                    u64::try_from(revision).unwrap_or_default(),
                ),
            });
        }
        Ok(workers)
    }

    /// Records a closed session and removes its worker row.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the write fails.
    pub fn record_closure(&mut self, record: &ClosureRecord) -> Result<()> {
        let encoded = kr_cbor::to_canonical_vec(record).map_err(ControllerError::registry)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "INSERT INTO tombstones (session_id, record, closed_at_ms) VALUES (?1, ?2, ?3)
                 ON CONFLICT (session_id) DO UPDATE SET record = excluded.record",
                params![
                    record.session_id.get().as_bytes().as_slice(),
                    encoded,
                    i64::try_from(record.closed_at_ms.get()).unwrap_or(i64::MAX)
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "DELETE FROM workers WHERE session_id = ?1",
                params![record.session_id.get().as_bytes().as_slice()],
            )
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE reservations SET phase = ?2 WHERE session_id = ?1",
                params![
                    record.session_id.get().as_bytes().as_slice(),
                    LaunchPhase::Closed.as_str()
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Reads the closure record of a session that has closed.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the read fails.
    pub fn closure(&self, session_id: SessionId) -> Result<Option<ClosureRecord>> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT record FROM tombstones WHERE session_id = ?1",
                params![session_id.get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        encoded
            .map(|bytes| {
                kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
                    .map_err(ControllerError::registry)
            })
            .transpose()
    }
}

struct RawReservation {
    reservation: Vec<u8>,
    actor: String,
    token: Vec<u8>,
    digest: Vec<u8>,
    session: Vec<u8>,
    display: i64,
    phase: String,
    pid: Option<i64>,
    source: Option<String>,
    start: Option<i64>,
    created: i64,
    create_intent: Option<Vec<u8>>,
    claimed_key: Option<Vec<u8>>,
}

impl RawReservation {
    fn into_reservation(self) -> Result<Reservation> {
        Ok(Reservation {
            reservation_id: ReservationId::new(uuid_from(&self.reservation)?),
            actor_id: ActorId::new(self.actor)
                .map_err(|_| ControllerError::registry("a stored actor is not valid"))?,
            create_token: uuid_from(&self.token)?,
            payload_digest: digest_from(&self.digest)?,
            create_intent: self.create_intent,
            session_id: SessionId::new(uuid_from(&self.session)?),
            display_number: DisplayNumber::new(u64::try_from(self.display).unwrap_or_default()),
            phase: LaunchPhase::parse(&self.phase)
                .ok_or_else(|| ControllerError::registry("a stored launch phase is not known"))?,
            launcher_identity: match (self.pid, self.source, self.start) {
                (Some(pid), Some(source), Some(start)) => Some(ProcessStartIdentity {
                    pid: kr_protocol::scalars::U64::new(u64::try_from(pid).unwrap_or_default()),
                    source: source_from(&source)?,
                    start_value: kr_protocol::scalars::U64::new(start_from_column(start)),
                }),
                _ => None,
            },
            claimed_key: self.claimed_key.as_deref().map(key_from).transpose()?,
            created_at_ms: TimestampMs::new(u64::try_from(self.created).unwrap_or_default()),
        })
    }
}

/// What admitting a create request produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    /// The reservation, new or retained.
    pub reservation: Reservation,
    /// True when an existing reservation was returned rather than a new one recorded.
    pub deduplicated: bool,
}

/// Returns the stored form of where a process start value came from.
const fn source_name(source: ProcessStartSource) -> &'static str {
    match source {
        ProcessStartSource::LinuxProcStat => "linux_proc_stat",
        ProcessStartSource::MacosProcBsdInfo => "macos_proc_bsd_info",
        ProcessStartSource::WindowsProcessCreationTime => "windows_process_creation_time",
        // What a worker of the previous build states, and what this registry recorded for one.
        // It goes with the source itself: in the first release after one in which every running
        // worker states the creation time.
        ProcessStartSource::WindowsProcessStartSeconds => "windows_process_start_seconds",
    }
}

/// Reads back what [`source_name`] wrote, and refuses anything else.
fn source_from(text: &str) -> Result<ProcessStartSource> {
    match text {
        "linux_proc_stat" => Ok(ProcessStartSource::LinuxProcStat),
        "macos_proc_bsd_info" => Ok(ProcessStartSource::MacosProcBsdInfo),
        "windows_process_creation_time" => Ok(ProcessStartSource::WindowsProcessCreationTime),
        "windows_process_start_seconds" => Ok(ProcessStartSource::WindowsProcessStartSeconds),
        _ => Err(ControllerError::registry(
            "a stored process identity source is not known",
        )),
    }
}

/// Returns a start value as a column stores it.
///
/// A column holds a signed integer, and no platform's start value comes near the top of that range:
/// the one value above it is the marker of a process that had ended before anything read it, which
/// is stored as the largest value the column holds and read back by [`start_from_column`] as the
/// marker.
fn start_column(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Reads back what [`start_column`] wrote.
fn start_from_column(value: i64) -> u64 {
    if value == i64::MAX {
        kr_ipc::identity::START_VALUE_UNREAD
    } else {
        u64::try_from(value).unwrap_or_default()
    }
}

/// Hundreds of nanoseconds in one second: a Windows creation time's unit.
const CREATION_TIME_UNITS_PER_SECOND: u64 = 10_000_000;

/// A record the previous build made of a Windows process: its creation time in whole seconds.
fn in_whole_seconds(pid: i64, start: i64) -> ProcessStartIdentity {
    ProcessStartIdentity::new(
        u64::try_from(pid).unwrap_or_default(),
        ProcessStartSource::WindowsProcessStartSeconds,
        start_from_column(start),
    )
}

fn profile_from(text: &str) -> Result<WorkerProfile> {
    match text {
        "desktop_bound" => Ok(WorkerProfile::DesktopBound),
        "headless_user" => Ok(WorkerProfile::HeadlessUser),
        _ => Err(ControllerError::registry(
            "a stored worker profile is not known",
        )),
    }
}

fn state_from(text: &str) -> Result<SessionState> {
    SessionState::ALL
        .iter()
        .copied()
        .find(|state| state.as_str() == text)
        .ok_or_else(|| ControllerError::registry("a stored session state is not known"))
}

fn uuid_from(bytes: &[u8]) -> Result<Uuid> {
    <[u8; 16]>::try_from(bytes)
        .map(Uuid::from_bytes)
        .map_err(|_| ControllerError::registry("a stored identifier is not 16 bytes"))
}

fn digest_from(bytes: &[u8]) -> Result<Digest256> {
    <[u8; 32]>::try_from(bytes)
        .map(Digest256::from_bytes)
        .map_err(|_| ControllerError::registry("a stored digest is not 32 bytes"))
}

fn key_from(bytes: &[u8]) -> Result<AuthorisationKey> {
    <[u8; 32]>::try_from(bytes)
        .map(AuthorisationKey::from_bytes)
        .map_err(|_| ControllerError::registry("a stored public key is not 32 bytes"))
}

#[cfg(test)]
mod tests {
    use kr_ipc::identity::START_VALUE_UNREAD;
    use kr_protocol::scalars::U64;

    use super::*;

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([7; 16]))
    }

    /// Hundreds of nanoseconds in one second.
    const PER_SECOND: u64 = 10_000_000;

    /// A second of September 2025, as the previous build recorded a Windows start.
    const SECOND: u64 = 1_758_700_000;

    /// What the kernel says about each process these tests recorded in whole seconds.
    ///
    /// 1001 and 1005 are running, created a moment into that second; 1002 has gone; the kernel will
    /// not describe 1003. Any other process is not one a test recorded in whole seconds, and asking
    /// about it fails the test.
    fn kernel(recorded: &ProcessStartIdentity) -> CurrentProcess {
        assert_eq!(
            recorded.source,
            ProcessStartSource::WindowsProcessStartSeconds,
            "only a record in whole seconds is put to the kernel"
        );
        match recorded.pid.get() {
            pid @ (1001 | 1005) => CurrentProcess::Running(finer(pid)),
            1002 => CurrentProcess::Ended,
            1003 => CurrentProcess::Unknown {
                detail: "Access is denied.".to_owned(),
            },
            other => panic!("process {other} was never recorded in whole seconds"),
        }
    }

    /// The same kernel once process 1003 can be described, and is running.
    fn kernel_later(recorded: &ProcessStartIdentity) -> CurrentProcess {
        match recorded.pid.get() {
            1003 => CurrentProcess::Running(finer(1003)),
            _ => kernel(recorded),
        }
    }

    /// A process created a moment into [`SECOND`], at the resolution this build reads.
    fn finer(pid: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(
            pid,
            ProcessStartSource::WindowsProcessCreationTime,
            SECOND * PER_SECOND + 1_234_567,
        )
    }

    fn in_seconds(pid: u64) -> ProcessStartIdentity {
        ProcessStartIdentity::new(pid, ProcessStartSource::WindowsProcessStartSeconds, SECOND)
    }

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    /// Writes a registry the way the previous build left it: schema version 3, with a worker and
    /// its reservation for each of `workers`, and a spawned reservation with no worker yet for
    /// each of `launches`, every process recorded as given.
    fn previous_build_registry(
        path: &std::path::Path,
        workers: &[(u8, ProcessStartIdentity)],
        launches: &[(u8, ProcessStartIdentity)],
    ) {
        let connection = Connection::open(path).expect("opens");
        connection
            .execute_batch(
                "CREATE TABLE schema_version (version INTEGER NOT NULL);
                 INSERT INTO schema_version (version) VALUES (3);
                 CREATE TABLE environment (
                     environment_id      BLOB PRIMARY KEY,
                     generation          INTEGER NOT NULL,
                     next_display        INTEGER NOT NULL,
                     session_limit       INTEGER NOT NULL,
                     authority_revision  INTEGER NOT NULL DEFAULT 0,
                     fence_owed_revision INTEGER NOT NULL DEFAULT 0,
                     accepted_revision   INTEGER NOT NULL DEFAULT 0,
                     accepted_document   TEXT
                 );
                 CREATE TABLE reservations (
                     reservation_id    BLOB PRIMARY KEY,
                     actor_id          TEXT NOT NULL,
                     create_token      BLOB NOT NULL,
                     payload_digest    BLOB NOT NULL,
                     create_intent     BLOB,
                     session_id        BLOB NOT NULL UNIQUE,
                     display_number    INTEGER NOT NULL UNIQUE,
                     phase             TEXT NOT NULL,
                     launcher_pid      INTEGER,
                     launcher_source   TEXT,
                     launcher_start    INTEGER,
                     claimed_key       BLOB,
                     created_at_ms     INTEGER NOT NULL,
                     UNIQUE (actor_id, create_token)
                 );
                 CREATE TABLE workers (
                     session_id       BLOB PRIMARY KEY,
                     display_number   INTEGER NOT NULL,
                     public_key       BLOB NOT NULL,
                     process_pid      INTEGER NOT NULL,
                     process_source   TEXT NOT NULL,
                     process_start    INTEGER NOT NULL,
                     endpoint         TEXT NOT NULL,
                     profile          TEXT NOT NULL,
                     state            TEXT NOT NULL,
                     acknowledged_revision INTEGER NOT NULL DEFAULT 0
                 );
                 CREATE TABLE tombstones (
                     session_id BLOB PRIMARY KEY,
                     record     BLOB NOT NULL,
                     closed_at_ms INTEGER NOT NULL
                 );",
            )
            .expect("creates the previous schema");
        let reserve = |byte: u8, phase: &str, process: &ProcessStartIdentity| {
            connection
                .execute(
                    "INSERT INTO reservations (reservation_id, actor_id, create_token,
                         payload_digest, session_id, display_number, phase, launcher_pid,
                         launcher_source, launcher_start, created_at_ms)
                     VALUES (?1, 'local:501', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 100)",
                    params![
                        vec![byte; 16],
                        vec![byte.wrapping_add(100); 16],
                        vec![3_u8; 32],
                        session(byte).get().as_bytes().as_slice(),
                        i64::from(byte),
                        phase,
                        i64::try_from(process.pid.get()).expect("a small identifier"),
                        source_name(process.source),
                        i64::try_from(process.start_value.get()).expect("a small start value"),
                    ],
                )
                .expect("records a reservation the previous build made");
        };
        for (byte, process) in workers {
            reserve(*byte, "live", process);
            connection
                .execute(
                    "INSERT INTO workers (session_id, display_number, public_key, process_pid,
                         process_source, process_start, endpoint, profile, state)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'worker', 'headless_user', 'live')",
                    params![
                        session(*byte).get().as_bytes().as_slice(),
                        i64::from(*byte),
                        vec![*byte; 32],
                        i64::try_from(process.pid.get()).expect("a small identifier"),
                        source_name(process.source),
                        i64::try_from(process.start_value.get()).expect("a small start value"),
                    ],
                )
                .expect("records a worker the previous build started");
        }
        for (byte, process) in launches {
            reserve(*byte, "spawned", process);
        }
    }

    fn opened(
        path: &std::path::Path,
        kernel: fn(&ProcessStartIdentity) -> CurrentProcess,
    ) -> Registry {
        Registry::prepare_reading(
            Connection::open(path).expect("opens"),
            environment(),
            kernel,
        )
        .expect("brings the registry forward")
    }

    fn worker(registry: &Registry, byte: u8) -> ProcessStartIdentity {
        registry
            .workers()
            .expect("reads the workers")
            .into_iter()
            .find(|worker| worker.session_id == session(byte))
            .expect("the worker is recorded")
            .process_identity
    }

    fn stated(registry: &Registry, byte: u8) -> String {
        registry
            .connection
            .query_row(
                "SELECT stated_source FROM workers WHERE session_id = ?1",
                params![session(byte).get().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .expect("reads what the worker states")
    }

    fn launcher(registry: &Registry, byte: u8) -> ProcessStartIdentity {
        registry
            .reservation_for_session(session(byte))
            .expect("reads the reservation")
            .expect("the reservation is recorded")
            .launcher_identity
            .expect("the launcher is recorded")
    }

    #[test]
    fn records_the_previous_build_made_in_whole_seconds_are_settled_where_the_kernel_can_say() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        let elsewhere = ProcessStartIdentity::new(1004, ProcessStartSource::MacosProcBsdInfo, 9);
        previous_build_registry(
            &path,
            &[
                (1, in_seconds(1001)),
                (2, in_seconds(1002)),
                (3, in_seconds(1003)),
                (4, elsewhere.clone()),
            ],
            &[(5, in_seconds(1005))],
        );

        let registry = opened(&path, kernel);
        let version: i64 = registry
            .connection
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .expect("reads the version");
        assert_eq!(version, SCHEMA_VERSION);
        // Running: recorded at the resolution this build reads, the worker and its launcher alike.
        assert_eq!(worker(&registry, 1), finer(1001));
        assert_eq!(launcher(&registry, 1), finer(1001));
        assert_eq!(launcher(&registry, 5), finer(1005));
        // Gone: marked ended, not rewritten, and read as ended without asking the kernel about
        // whatever holds the identifier now.
        for ended in [worker(&registry, 2), launcher(&registry, 2)] {
            assert_eq!(ended.pid.get(), 1002);
            assert_eq!(ended.start_value.get(), START_VALUE_UNREAD);
            assert_eq!(
                kr_ipc::identity::process_state(&ended),
                kr_ipc::identity::ProcessState::Ended
            );
        }
        // Not described: left as the previous build recorded it, for the next opening.
        assert_eq!(worker(&registry, 3), in_seconds(1003));
        assert_eq!(launcher(&registry, 3), in_seconds(1003));
        // Never in whole seconds: never put to the kernel, and left alone.
        assert_eq!(worker(&registry, 4), elsewhere);
        // What each worker states is what the previous build recorded for it.
        for byte in 1..=3 {
            assert_eq!(stated(&registry, byte), "windows_process_start_seconds");
        }
        assert_eq!(stated(&registry, 4), "macos_proc_bsd_info");
        drop(registry);

        // The next opening asks again about the one record the kernel would not describe, and
        // about nothing else.
        let registry = opened(&path, kernel_later);
        assert_eq!(worker(&registry, 3), finer(1003));
        assert_eq!(launcher(&registry, 3), finer(1003));
        assert_eq!(worker(&registry, 1), finer(1001));
        assert_eq!(stated(&registry, 3), "windows_process_start_seconds");
    }

    /// A kernel that will not describe any process.
    fn kernel_silent(_recorded: &ProcessStartIdentity) -> CurrentProcess {
        CurrentProcess::Unknown {
            detail: "Access is denied.".to_owned(),
        }
    }

    /// A kernel in which the identifier asked about is held by a later process created in the
    /// same second as the one recorded.
    fn kernel_replaced(recorded: &ProcessStartIdentity) -> CurrentProcess {
        let mut later = finer(recorded.pid.get());
        later.start_value = U64::new(later.start_value.get() + 1);
        CurrentProcess::Running(later)
    }

    #[test]
    fn a_worker_that_states_whole_seconds_again_keeps_the_finer_record_and_what_it_states() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        previous_build_registry(&path, &[(1, in_seconds(1001))], &[]);
        let mut registry = opened(&path, kernel);
        assert_eq!(worker(&registry, 1), finer(1001));
        let record = WorkerRecord {
            session_id: session(1),
            display_number: DisplayNumber::new(1),
            public_key: AuthorisationKey::from_bytes([1; 32]),
            process_identity: in_seconds(1001),
            endpoint: "worker".to_owned(),
            profile: WorkerProfile::HeadlessUser,
            state: SessionState::Live,
            acknowledged_revision: AuthorityRevision::new(0),
        };
        // A controller adopts the worker again from its own signed answer, which states whole
        // seconds. The finer identity the opening established is kept whatever the kernel would
        // say now: that it will not describe the process, or that a later process created in the
        // same second holds the identifier.
        for now in [
            kernel_silent as fn(&ProcessStartIdentity) -> CurrentProcess,
            kernel_replaced,
        ] {
            registry.current_process = now;
            registry.adopt_worker(&record).expect("adopts");
            assert_eq!(worker(&registry, 1), finer(1001));
            assert_eq!(stated(&registry, 1), "windows_process_start_seconds");
        }
        // A worker with no row yet that states whole seconds is settled as the opening settles
        // one.
        registry.current_process = kernel;
        let arriving = WorkerRecord {
            session_id: session(5),
            display_number: DisplayNumber::new(5),
            process_identity: in_seconds(1005),
            ..record.clone()
        };
        registry.adopt_worker(&arriving).expect("adopts");
        assert_eq!(worker(&registry, 5), finer(1005));
        assert_eq!(stated(&registry, 5), "windows_process_start_seconds");
        // One this build started states the creation time, which is recorded as it is.
        let current = WorkerRecord {
            session_id: session(9),
            display_number: DisplayNumber::new(9),
            process_identity: finer(1009),
            ..record
        };
        registry.adopt_worker(&current).expect("adopts");
        assert_eq!(worker(&registry, 9), finer(1009));
        assert_eq!(stated(&registry, 9), "windows_process_creation_time");
    }

    #[test]
    fn a_launcher_that_ended_unread_is_read_back_as_ended() {
        let mut registry = Registry::in_memory(environment()).expect("a registry");
        let reservation = registry
            .reserve(
                &ActorId::new("local:501").expect("a principal"),
                Uuid::from_bytes([2; 16]),
                Digest256::from_bytes([3; 32]),
                b"intent",
                TimestampMs::new(1),
            )
            .expect("reserves")
            .reservation;
        let ended = kr_ipc::identity::ended_process_identity(4242);
        registry
            .record_launch(reservation.reservation_id, &ended)
            .expect("records the launcher");
        let read = registry
            .reservation(reservation.reservation_id)
            .expect("reads")
            .expect("the reservation")
            .launcher_identity
            .expect("the launcher");
        assert_eq!(read, ended, "the ended marker survives the column");
        assert_eq!(read.start_value, U64::new(START_VALUE_UNREAD));
    }

    /// A worker of the previous build still running after an upgrade: this process stands in for
    /// it, recorded in whole seconds as that build recorded it, beside a record of the same
    /// identifier created in another second.
    #[cfg(windows)]
    #[test]
    fn this_process_recorded_in_whole_seconds_is_settled_at_its_creation_time() {
        let directory = tempfile::tempdir().expect("a directory");
        let path = directory.path().join("registry.sqlite3");
        let current =
            kr_ipc::identity::current_process_start_identity().expect("this process's identity");
        let seconds = ProcessStartIdentity::new(
            current.pid.get(),
            ProcessStartSource::WindowsProcessStartSeconds,
            current.start_value.get() / PER_SECOND,
        );
        let mut another_second = seconds.clone();
        another_second.start_value = U64::new(seconds.start_value.get() - 1);
        previous_build_registry(&path, &[(1, seconds), (2, another_second)], &[]);

        let registry = Registry::open(&path, environment()).expect("brings the registry forward");
        assert_eq!(worker(&registry, 1), current);
        assert_eq!(launcher(&registry, 1), current);
        assert_eq!(stated(&registry, 1), "windows_process_start_seconds");
        let ended = worker(&registry, 2);
        assert_eq!(ended.start_value.get(), START_VALUE_UNREAD);
        assert_eq!(
            kr_ipc::identity::process_state(&ended),
            kr_ipc::identity::ProcessState::Ended
        );
    }
}
