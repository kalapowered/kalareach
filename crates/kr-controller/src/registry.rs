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

use kr_protocol::identity::{ProcessStartIdentity, WorkerProfile};
use kr_protocol::ids::{ActorId, ControllerGeneration, EnvironmentId, SessionId};
use kr_protocol::scalars::{AuthorisationKey, Digest256, TimestampMs, Uuid};
use kr_protocol::session::{ClosureRecord, DisplayNumber, SessionState};
use kr_protocol::worker::ReservationId;
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::error::{ControllerError, Result};

/// The schema version this build reads.
pub const SCHEMA_VERSION: i64 = 2;

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
}

/// The environment registry.
#[derive(Debug)]
pub struct Registry {
    connection: Connection,
    environment_id: EnvironmentId,
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
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(ControllerError::registry)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(ControllerError::registry)?;
        let registry = Self {
            connection,
            environment_id,
        };
        registry.migrate()?;
        Ok(registry)
    }

    fn migrate(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS environment (
                     environment_id BLOB PRIMARY KEY,
                     generation     INTEGER NOT NULL,
                     next_display   INTEGER NOT NULL,
                     session_limit  INTEGER NOT NULL
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
                     state            TEXT NOT NULL
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
            Some(1) => self.migrate_1_to_2()?,
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
    /// This migration goes when there can no longer be a version 1 registry to read, which is the
    /// first release: nothing before it is installed anywhere it has to be read from again.
    fn migrate_1_to_2(&self) -> Result<()> {
        self.connection
            .execute_batch(
                "BEGIN;
                 ALTER TABLE reservations ADD COLUMN create_intent BLOB;
                 ALTER TABLE reservations ADD COLUMN claimed_key BLOB;
                 UPDATE schema_version SET version = 2;
                 COMMIT;",
            )
            .map_err(ControllerError::registry)?;
        Ok(())
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
                    i64::try_from(identity.start_value.get()).unwrap_or(i64::MAX),
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

    fn reservation_for_token(
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
        let transaction = self
            .connection
            .transaction()
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "INSERT INTO workers (session_id, display_number, public_key, process_pid,
                     process_source, process_start, endpoint, profile, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (session_id) DO UPDATE SET
                     public_key = excluded.public_key,
                     process_pid = excluded.process_pid,
                     process_source = excluded.process_source,
                     process_start = excluded.process_start,
                     endpoint = excluded.endpoint,
                     state = excluded.state",
                params![
                    worker.session_id.get().as_bytes().as_slice(),
                    i64::try_from(worker.display_number.get()).unwrap_or(i64::MAX),
                    worker.public_key.as_bytes().as_slice(),
                    i64::try_from(worker.process_identity.pid.get()).unwrap_or(i64::MAX),
                    source_name(worker.process_identity.source),
                    i64::try_from(worker.process_identity.start_value.get()).unwrap_or(i64::MAX),
                    worker.endpoint,
                    worker.profile.as_str(),
                    worker.state.as_str(),
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
        self.connection
            .execute(
                "INSERT INTO workers (session_id, display_number, public_key, process_pid,
                     process_source, process_start, endpoint, profile, state)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT (session_id) DO UPDATE SET
                     public_key = excluded.public_key,
                     process_pid = excluded.process_pid,
                     process_source = excluded.process_source,
                     process_start = excluded.process_start,
                     endpoint = excluded.endpoint,
                     state = excluded.state",
                params![
                    worker.session_id.get().as_bytes().as_slice(),
                    i64::try_from(worker.display_number.get()).unwrap_or(i64::MAX),
                    worker.public_key.as_bytes().as_slice(),
                    i64::try_from(worker.process_identity.pid.get()).unwrap_or(i64::MAX),
                    source_name(worker.process_identity.source),
                    i64::try_from(worker.process_identity.start_value.get()).unwrap_or(i64::MAX),
                    worker.endpoint,
                    worker.profile.as_str(),
                    worker.state.as_str(),
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
                        process_start, endpoint, profile, state
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
                ))
            })
            .map_err(ControllerError::registry)?;
        let mut workers = Vec::new();
        for row in rows {
            let (session, display, key, pid, source, start, endpoint, profile, state) =
                row.map_err(ControllerError::registry)?;
            workers.push(WorkerRecord {
                session_id: SessionId::new(uuid_from(&session)?),
                display_number: DisplayNumber::new(u64::try_from(display).unwrap_or_default()),
                public_key: key_from(&key)?,
                process_identity: ProcessStartIdentity {
                    pid: kr_protocol::scalars::U64::new(u64::try_from(pid).unwrap_or_default()),
                    source: source_from(&source)?,
                    start_value: kr_protocol::scalars::U64::new(
                        u64::try_from(start).unwrap_or_default(),
                    ),
                },
                endpoint,
                profile: profile_from(&profile)?,
                state: state_from(&state)?,
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
                    start_value: kr_protocol::scalars::U64::new(
                        u64::try_from(start).unwrap_or_default(),
                    ),
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

const fn source_name(source: kr_protocol::identity::ProcessStartSource) -> &'static str {
    match source {
        kr_protocol::identity::ProcessStartSource::LinuxProcStat => "linux_proc_stat",
        kr_protocol::identity::ProcessStartSource::MacosProcBsdInfo => "macos_proc_bsd_info",
        kr_protocol::identity::ProcessStartSource::WindowsProcessStartSeconds => {
            "windows_process_start_seconds"
        }
    }
}

fn source_from(text: &str) -> Result<kr_protocol::identity::ProcessStartSource> {
    match text {
        "linux_proc_stat" => Ok(kr_protocol::identity::ProcessStartSource::LinuxProcStat),
        "macos_proc_bsd_info" => Ok(kr_protocol::identity::ProcessStartSource::MacosProcBsdInfo),
        "windows_process_start_seconds" => {
            Ok(kr_protocol::identity::ProcessStartSource::WindowsProcessStartSeconds)
        }
        _ => Err(ControllerError::registry(
            "a stored process identity source is not known",
        )),
    }
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
