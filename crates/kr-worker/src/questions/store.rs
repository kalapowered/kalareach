//! The durable question ledger.
//!
//! It lives in the worker's private journal, which section 24 makes the owner of question
//! transitions, in write-ahead-logging mode with full synchronisation. The rules it enforces are
//! the ones section 11 states, and each is a property of the SQL rather than of the caller:
//!
//! * **`pending -> answered | cancelled | expired`, and the first answer wins.** Every resolution
//!   is one conditional `UPDATE ... WHERE state = 'pending' AND revision = ?`. Exactly one of two
//!   simultaneous answers changes a row; the other changes none, reads what happened and is told
//!   `QUESTION_RESOLVED`.
//! * **Creation de-duplicates by the verified source and its request identifier.** The unique
//!   index is `(source_key, request_id)`, and the stored payload digest decides between an exact
//!   duplicate, which returns the existing question and its token, and a changed payload, which is
//!   `ID_CONFLICT`.
//! * **The caller token never leaves in the clear and never leaves at all except to its source.**
//!   What is stored is a keyed verification tag and a sealed copy. The key is generated when the
//!   ledger opens and lives in this process's memory only, so the sealed copies stop being
//!   readable the moment the worker exits, which is when a question's source access ends.
//!
//! Expiry is applied before every read and every resolution, so an expired question is never
//! answered and never reported as pending. A question expires at its deadline on either clock, or
//! when the application that asked has gone: section 11 gives it the shorter of a day and the
//! originating binding's own life.

use kr_crypto::secret::SymmetricKey;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{
    ActorId, ApplicationInstanceId, DeviceId, QuestionId, QuestionRevision, SessionEpoch, SessionId,
};
use kr_protocol::question::{
    Alert, AlertCreateParams, AnswerRecord, CallerToken, Question, QuestionAnswer, QuestionChoice,
    QuestionCreateParams, QuestionEvent, QuestionEventKind, QuestionKind, QuestionSource,
    QuestionState,
};
use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};
use rusqlite::{Connection, OptionalExtension as _, params};

use crate::questions::binding::VerifiedSource;
use crate::questions::error::{QuestionError, Result, unknown};
use crate::questions::token;

/// The ledger's own schema version, kept separately from the receipt journal's.
const SCHEMA_VERSION: i64 = 1;

/// How long a write waits for another connection to this journal before it gives up.
const BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The two clocks a deadline is measured on.
///
/// The wall clock is what a person reads and what survives a restart; the machine's own continuous
/// clock is what cannot be stepped. A question expires when either deadline passes, so a forward
/// wall-clock step expires conservatively and a rollback extends nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    /// UTC milliseconds.
    pub utc_ms: TimestampMs,
    /// Milliseconds since this boot, on the machine's shared continuous clock.
    pub boot_ms: u64,
}

/// What a resolution did to a question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolved {
    /// The question after the transition.
    pub question: Question,
    /// When it first became pending, which is when its idle timer started.
    pub pending_since_ms: TimestampMs,
}

/// One question creation's outcome.
#[derive(Clone, Debug)]
pub struct Created {
    /// The question.
    pub question: Question,
    /// The token the source polls and cancels with.
    pub caller_token: CallerToken,
    /// True when an exact duplicate returned the existing question.
    pub deduplicated: bool,
}

/// The durable question ledger.
#[derive(Debug)]
pub struct Store {
    connection: Connection,
    key: SymmetricKey,
    session_id: SessionId,
    session_epoch: SessionEpoch,
}

impl Store {
    /// Opens the ledger inside the worker's private journal.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the database cannot be opened, when its schema
    /// cannot be created, or when the operating system will not produce a key.
    pub fn open(
        path: Option<&std::path::Path>,
        session_id: SessionId,
        session_epoch: SessionEpoch,
    ) -> Result<Self> {
        let connection = match path {
            Some(path) => Connection::open(path),
            None => Connection::open_in_memory(),
        }
        .map_err(QuestionError::unavailable)?;
        let key = SymmetricKey::random()
            .map_err(|error| QuestionError::unavailable(format!("no key material: {error}")))?;
        let store = Self {
            connection,
            key,
            session_id,
            session_epoch,
        };
        store.prepare()?;
        Ok(store)
    }

    fn prepare(&self) -> Result<()> {
        // The receipt journal opened this file first and owns its own schema version. This ledger
        // adds its tables beside them and keeps its own version row, so neither migration reads
        // the other's.
        self.connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(QuestionError::unavailable)?;
        self.connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(QuestionError::unavailable)?;
        self.connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(QuestionError::unavailable)?;
        self.connection
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS question_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS question_sources (
                     source_key              TEXT PRIMARY KEY,
                     application_instance_id BLOB NOT NULL,
                     first_seen_ms           INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS questions (
                     question_id        BLOB PRIMARY KEY,
                     revision           INTEGER NOT NULL,
                     state              TEXT    NOT NULL,
                     kind               TEXT    NOT NULL,
                     context            TEXT    NOT NULL,
                     question           TEXT    NOT NULL,
                     choices            BLOB    NOT NULL,
                     source             BLOB    NOT NULL,
                     source_key         TEXT    NOT NULL,
                     source_process     BLOB    NOT NULL,
                     request_id         TEXT    NOT NULL,
                     payload_digest     BLOB    NOT NULL,
                     token_tag          BLOB    NOT NULL,
                     token_nonce        BLOB    NOT NULL,
                     token_sealed       BLOB    NOT NULL,
                     created_at_ms      INTEGER NOT NULL,
                     pending_since_ms   INTEGER NOT NULL,
                     expires_at_ms      INTEGER NOT NULL,
                     expires_at_boot_ms INTEGER NOT NULL,
                     answer             BLOB,
                     resolved_at_ms     INTEGER
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS questions_by_request
                     ON questions (source_key, request_id);
                 CREATE INDEX IF NOT EXISTS questions_by_state ON questions (state);
                 CREATE TABLE IF NOT EXISTS question_events (
                     sequence       INTEGER PRIMARY KEY AUTOINCREMENT,
                     kind           TEXT    NOT NULL,
                     question_id    BLOB    NOT NULL,
                     record         BLOB    NOT NULL,
                     recorded_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS alerts (
                     source_key     TEXT    NOT NULL,
                     dedup_id       TEXT    NOT NULL,
                     payload_digest BLOB    NOT NULL,
                     record         BLOB    NOT NULL,
                     created_at_ms  INTEGER NOT NULL,
                     PRIMARY KEY (source_key, dedup_id)
                 );",
            )
            .map_err(QuestionError::unavailable)?;
        let recorded: Option<i64> = self
            .connection
            .query_row("SELECT version FROM question_schema", [], |row| row.get(0))
            .optional()
            .map_err(QuestionError::unavailable)?;
        match recorded {
            None => {
                self.connection
                    .execute(
                        "INSERT INTO question_schema (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(QuestionError::unavailable)?;
            }
            Some(version) if version == SCHEMA_VERSION => {}
            Some(version) => {
                return Err(QuestionError::unavailable(format!(
                    "this ledger is at schema version {version}; this build reads {SCHEMA_VERSION}"
                )));
            }
        }
        Ok(())
    }

    /// Returns the application instance this verified source acts as, minting one on first sight.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the record cannot be read or written.
    pub fn application_instance(
        &self,
        source: &VerifiedSource,
        now: Now,
    ) -> Result<ApplicationInstanceId> {
        let key = source.key();
        if let Some(existing) = self
            .connection
            .query_row(
                "SELECT application_instance_id FROM question_sources WHERE source_key = ?1",
                params![key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()
            .map_err(QuestionError::unavailable)?
        {
            return Ok(ApplicationInstanceId::new(uuid_from(&existing)?));
        }
        let minted = kr_ipc::new_uuid();
        self.connection
            .execute(
                "INSERT INTO question_sources (source_key, application_instance_id, first_seen_ms)
                 VALUES (?1, ?2, ?3)",
                params![key, minted.as_bytes().as_slice(), millis(now.utc_ms.get())],
            )
            .map_err(QuestionError::unavailable)?;
        Ok(ApplicationInstanceId::new(minted))
    }

    /// Builds the identity header for one verified source.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the application instance cannot be resolved.
    pub fn source_header(
        &self,
        source: &VerifiedSource,
        agent_label: Option<String>,
        now: Now,
    ) -> Result<QuestionSource> {
        Ok(QuestionSource {
            application_instance_id: self.application_instance(source, now)?,
            process: source.process.clone(),
            executable: Nullable(source.executable.clone()),
            agent_label: Nullable(agent_label),
            connection_id: source.connection_id,
            launch_channel: source.launch_channel,
            session_member: source.session_member,
            ancestry: source.ancestry,
            // A thread or binding revision is recorded only when a qualified bridge supplies one.
            // No bridge does in this build, so it stays null rather than being invented: section 11
            // makes a null here mean "application-scoped, with no thread-switch detection claimed".
            agent_binding_revision: Nullable::null(),
        })
    }

    /// Creates a question, or returns the one an exact duplicate already created.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::IdConflict`] when the request identifier was used with a different
    /// payload, and [`QuestionError::Unavailable`] when the write fails.
    pub fn create(
        &mut self,
        source: &VerifiedSource,
        header: &QuestionSource,
        params: &QuestionCreateParams,
        choices: &[QuestionChoice],
        expiry_ms: u64,
        now: Now,
    ) -> Result<Created> {
        let key = source.key();
        let digest = payload_digest(params, choices);
        if let Some(existing) = self.by_request(&key, &params.request_id)? {
            if existing.digest != digest {
                return Err(QuestionError::IdConflict {
                    request_id: params.request_id.clone(),
                });
            }
            // An exact retry returns the question as it stands and the token it was issued with.
            // The sealed copy is what makes that possible without ever storing the token itself.
            let caller_token = token::unseal(
                &self.key,
                existing.question.question_id,
                &existing.token_nonce,
                &existing.token_sealed,
            )?;
            return Ok(Created {
                question: existing.question,
                caller_token,
                deduplicated: true,
            });
        }
        let question_id = QuestionId::new(kr_ipc::new_uuid());
        let caller_token = token::issue()?;
        let tag = token::tag(&self.key, question_id, &caller_token);
        let (nonce, sealed) = token::seal(&self.key, question_id, &caller_token)?;
        let expires_at_ms = TimestampMs::new(now.utc_ms.get().saturating_add(expiry_ms));
        let expires_at_boot_ms = now.boot_ms.saturating_add(expiry_ms);
        let question = Question {
            question_id,
            revision: QuestionRevision::new(1),
            state: QuestionState::Pending,
            session_id: self.session_id,
            session_epoch: self.session_epoch,
            kind: params.kind,
            context: params.context.clone(),
            question: params.question.clone(),
            choices: choices.to_vec(),
            source: header.clone(),
            created_at_ms: now.utc_ms,
            expires_at_ms,
            answer: Nullable::null(),
            resolved_at_ms: Nullable::null(),
        };
        let transaction = self
            .connection
            .transaction()
            .map_err(QuestionError::unavailable)?;
        transaction
            .execute(
                "INSERT INTO questions (
                     question_id, revision, state, kind, context, question, choices, source,
                     source_key, source_process, request_id, payload_digest, token_tag,
                     token_nonce, token_sealed, created_at_ms, pending_since_ms, expires_at_ms,
                     expires_at_boot_ms, answer, resolved_at_ms
                 ) VALUES (
                     ?1, 1, 'pending', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                     ?14, ?15, ?16, NULL, NULL
                 )",
                params![
                    question_id.get().as_bytes().as_slice(),
                    question.kind.as_str(),
                    question.context,
                    question.question,
                    encode(&question.choices)?,
                    encode(header)?,
                    key,
                    encode(&source.process)?,
                    params.request_id,
                    digest.as_slice(),
                    tag.as_slice(),
                    nonce.as_slice(),
                    sealed.as_slice(),
                    millis(now.utc_ms.get()),
                    millis(expires_at_ms.get()),
                    millis(expires_at_boot_ms),
                ],
            )
            .map_err(QuestionError::unavailable)?;
        write_event(
            &transaction,
            &QuestionEvent {
                kind: QuestionEventKind::Created,
                question: question.clone(),
                pending_since_ms: question.created_at_ms,
                recorded_at_ms: now.utc_ms,
            },
        )?;
        transaction.commit().map_err(QuestionError::unavailable)?;
        Ok(Created {
            question,
            caller_token,
            deduplicated: false,
        })
    }

    /// Refuses a creation whose request identifier already carries a different payload.
    ///
    /// This is the same comparison [`Self::create`] makes, offered separately so a worker can make
    /// it before it commits a dispatch marker: a conflict is a refusal, and a refusal recorded
    /// after the marker would claim the effect might have happened.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::IdConflict`] when the identifier was used with a different
    /// payload.
    pub fn check_request(
        &self,
        source_key: &str,
        params: &QuestionCreateParams,
        choices: &[QuestionChoice],
    ) -> Result<()> {
        let Some(existing) = self.by_request(source_key, &params.request_id)? else {
            return Ok(());
        };
        if existing.digest == payload_digest(params, choices) {
            return Ok(());
        }
        Err(QuestionError::IdConflict {
            request_id: params.request_id.clone(),
        })
    }

    /// Reads one question, whatever its state.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unknown`] when this session has no such question.
    pub fn read(&self, question_id: QuestionId) -> Result<Question> {
        self.row(question_id)?
            .map(|row| row.question)
            .ok_or_else(|| unknown(question_id))
    }

    /// Reads one question and the token material recorded with it.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unknown`] when this session has no such question.
    pub fn read_row(&self, question_id: QuestionId) -> Result<Row> {
        self.row(question_id)?.ok_or_else(|| unknown(question_id))
    }

    /// Lists this session's questions, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the read fails.
    pub fn list(&self, include_resolved: bool) -> Result<Vec<Question>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT question_id, revision, state, kind, context, question, choices, source,
                        created_at_ms, pending_since_ms, expires_at_ms, answer, resolved_at_ms,
                        token_nonce, token_sealed, payload_digest, source_key, token_tag
                 FROM questions ORDER BY created_at_ms, rowid",
            )
            .map_err(QuestionError::unavailable)?;
        let rows = statement
            .query_map([], |row| Ok(self.hydrate(row)))
            .map_err(QuestionError::unavailable)?;
        let mut questions = Vec::new();
        for row in rows {
            let row = row.map_err(QuestionError::unavailable)??;
            if include_resolved || row.question.state == QuestionState::Pending {
                questions.push(row.question);
            }
        }
        Ok(questions)
    }

    /// Answers a question, if it is still pending at the revision the caller was shown.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Resolved`] when somebody else got there first,
    /// [`QuestionError::Expired`] when its deadline has passed, and
    /// [`QuestionError::StaleRevision`] when the caller answered an older revision.
    pub fn answer(
        &mut self,
        question_id: QuestionId,
        expected: QuestionRevision,
        answer: &QuestionAnswer,
        actor_id: &ActorId,
        device_id: Option<DeviceId>,
        now: Now,
    ) -> Result<Resolved> {
        let record = AnswerRecord {
            answer: answer.clone(),
            actor_id: actor_id.clone(),
            device_id: Nullable(device_id),
            question_revision: expected,
            answered_at_ms: now.utc_ms,
        };
        self.resolve(
            question_id,
            expected,
            QuestionState::Answered,
            QuestionEventKind::Answered,
            Some(&record),
            now,
        )
    }

    /// Cancels a question, if it is still pending at the revision the caller was shown.
    ///
    /// # Errors
    ///
    /// As [`Self::answer`].
    pub fn cancel(
        &mut self,
        question_id: QuestionId,
        expected: QuestionRevision,
        now: Now,
    ) -> Result<Resolved> {
        self.resolve(
            question_id,
            expected,
            QuestionState::Cancelled,
            QuestionEventKind::Cancelled,
            None,
            now,
        )
    }

    /// Moves every question whose time is up, or whose source has gone, to `expired`.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the read or the write fails.
    pub fn expire_due(&mut self, now: Now) -> Result<Vec<Resolved>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT question_id, expires_at_ms, expires_at_boot_ms, source_process
                 FROM questions WHERE state = 'pending'",
            )
            .map_err(QuestionError::unavailable)?;
        let candidates = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    u64::try_from(row.get::<_, i64>(1)?).unwrap_or(u64::MAX),
                    u64::try_from(row.get::<_, i64>(2)?).unwrap_or(u64::MAX),
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(QuestionError::unavailable)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(QuestionError::unavailable)?;
        drop(statement);
        let mut expired = Vec::new();
        for (identifier, utc_deadline, boot_deadline, encoded_process) in candidates {
            let question_id = QuestionId::new(uuid_from(&identifier)?);
            let due = now.utc_ms.get() >= utc_deadline || now.boot_ms >= boot_deadline;
            // Section 11 ends a question at the shorter of its deadline and the life of the
            // application that asked, so a helper that exited takes its unanswered questions with
            // it rather than leaving a decision nobody will collect.
            let source_gone = match decode::<ProcessStartIdentity>(&encoded_process) {
                Ok(process) => matches!(
                    kr_ipc::identity::process_state(&process),
                    kr_ipc::identity::ProcessState::Ended
                ),
                Err(_) => false,
            };
            if !due && !source_gone {
                continue;
            }
            let current = self.read_revision(question_id)?;
            if let Ok(resolved) = self.resolve(
                question_id,
                current,
                QuestionState::Expired,
                QuestionEventKind::Expired,
                None,
                now,
            ) {
                expired.push(resolved);
            }
        }
        Ok(expired)
    }

    /// Raises an alert, or returns the one an exact duplicate already raised.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::IdConflict`] when the de-duplication identifier was used with
    /// different text, and [`QuestionError::Unavailable`] when the write fails.
    pub fn alert(
        &mut self,
        source: &VerifiedSource,
        header: &QuestionSource,
        params: &AlertCreateParams,
        now: Now,
    ) -> Result<(Alert, bool)> {
        let key = source.key();
        let digest = alert_digest(params);
        let existing: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT payload_digest, record FROM alerts WHERE source_key = ?1 AND dedup_id = ?2",
                params![key, params.dedup_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(QuestionError::unavailable)?;
        if let Some((stored_digest, record)) = existing {
            if stored_digest != digest {
                return Err(QuestionError::IdConflict {
                    request_id: params.dedup_id.clone(),
                });
            }
            return Ok((decode::<Alert>(&record)?, true));
        }
        let alert = Alert {
            dedup_id: params.dedup_id.clone(),
            session_id: self.session_id,
            source: header.clone(),
            text: params.text.clone(),
            severity: params.severity,
            safe_session_link: params.safe_session_link.clone(),
            created_at_ms: now.utc_ms,
        };
        self.connection
            .execute(
                "INSERT INTO alerts (source_key, dedup_id, payload_digest, record, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    key,
                    params.dedup_id,
                    digest.as_slice(),
                    encode(&alert)?,
                    millis(now.utc_ms.get())
                ],
            )
            .map_err(QuestionError::unavailable)?;
        Ok((alert, false))
    }

    /// Checks that this token belongs to this question and to this caller.
    ///
    /// Both halves are required. The tag proves the token; the source key proves the application,
    /// so a token that leaked to another process under the same account still reaches nothing.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::TokenRejected`] when either half fails.
    pub fn check_token(
        &self,
        row: &Row,
        source: &VerifiedSource,
        presented: &CallerToken,
    ) -> Result<()> {
        if row.source_key != source.key() {
            return Err(QuestionError::TokenRejected {
                detail: "this question belongs to a different application".to_owned(),
            });
        }
        token::verify(
            &self.key,
            row.question.question_id,
            presented,
            &row.token_tag,
        )
    }

    /// Returns the transitions recorded after this cursor, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the read fails.
    pub fn events_since(&self, cursor: u64, limit: usize) -> Result<Vec<(u64, QuestionEvent)>> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT sequence, record FROM question_events
                  WHERE sequence > ?1 ORDER BY sequence LIMIT ?2",
            )
            .map_err(QuestionError::unavailable)?;
        let rows = statement
            .query_map(params![count(cursor), count(limit as u64)], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(QuestionError::unavailable)?;
        let mut events = Vec::new();
        for row in rows {
            let (sequence, record) = row.map_err(QuestionError::unavailable)?;
            events.push((
                u64::try_from(sequence).unwrap_or_default(),
                decode::<QuestionEvent>(&record)?,
            ));
        }
        Ok(events)
    }

    /// Returns the alerts this session has raised, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionError::Unavailable`] when the read fails.
    pub fn alerts(&self) -> Result<Vec<Alert>> {
        let mut statement = self
            .connection
            .prepare("SELECT record FROM alerts ORDER BY created_at_ms, rowid")
            .map_err(QuestionError::unavailable)?;
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(QuestionError::unavailable)?;
        let mut alerts = Vec::new();
        for record in rows {
            alerts.push(decode::<Alert>(
                &record.map_err(QuestionError::unavailable)?,
            )?);
        }
        Ok(alerts)
    }

    fn resolve(
        &mut self,
        question_id: QuestionId,
        expected: QuestionRevision,
        state: QuestionState,
        kind: QuestionEventKind,
        answer: Option<&AnswerRecord>,
        now: Now,
    ) -> Result<Resolved> {
        let encoded_answer = match answer {
            Some(record) => Some(encode(record)?),
            None => None,
        };
        // The transition and the event it produces are one transaction. A crash between them
        // would leave a question that had moved and a feed that never heard, and the attention
        // engine reads that feed rather than polling every question.
        let transaction = self
            .connection
            .transaction()
            .map_err(QuestionError::unavailable)?;
        // One conditional update is the whole of the atomicity. Two answers race here, and the
        // loser changes no row at all rather than overwriting the winner's.
        let changed = transaction
            .execute(
                "UPDATE questions
                    SET state = ?1, revision = revision + 1, answer = ?2, resolved_at_ms = ?3
                  WHERE question_id = ?4 AND state = 'pending' AND revision = ?5",
                params![
                    state.as_str(),
                    encoded_answer,
                    millis(now.utc_ms.get()),
                    question_id.get().as_bytes().as_slice(),
                    count(expected.get()),
                ],
            )
            .map_err(QuestionError::unavailable)?;
        let row = read_row_in(
            &transaction,
            self.session_id,
            self.session_epoch,
            question_id,
        )?
        .ok_or_else(|| unknown(question_id))?;
        if changed == 0 {
            return Err(match row.question.state {
                QuestionState::Expired => QuestionError::Expired {
                    at_ms: row
                        .question
                        .resolved_at_ms
                        .as_ref()
                        .map_or_else(|| row.question.expires_at_ms.get(), |at| at.get()),
                },
                QuestionState::Answered | QuestionState::Cancelled => QuestionError::Resolved {
                    state: row.question.state,
                },
                QuestionState::Pending => QuestionError::StaleRevision {
                    named: expected.get(),
                    current: row.question.revision.get(),
                },
            });
        }
        let resolved = Resolved {
            question: row.question,
            pending_since_ms: row.pending_since_ms,
        };
        write_event(&transaction, &event_of(kind, &resolved, now))?;
        transaction.commit().map_err(QuestionError::unavailable)?;
        Ok(resolved)
    }

    fn read_revision(&self, question_id: QuestionId) -> Result<QuestionRevision> {
        self.connection
            .query_row(
                "SELECT revision FROM questions WHERE question_id = ?1",
                params![question_id.get().as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(QuestionError::unavailable)?
            .map(|revision| QuestionRevision::new(u64::try_from(revision).unwrap_or_default()))
            .ok_or_else(|| unknown(question_id))
    }

    fn by_request(&self, source_key: &str, request_id: &str) -> Result<Option<Row>> {
        self.connection
            .query_row(
                "SELECT question_id, revision, state, kind, context, question, choices, source,
                        created_at_ms, pending_since_ms, expires_at_ms, answer, resolved_at_ms,
                        token_nonce, token_sealed, payload_digest, source_key, token_tag
                 FROM questions WHERE source_key = ?1 AND request_id = ?2",
                params![source_key, request_id],
                |row| Ok(self.hydrate(row)),
            )
            .optional()
            .map_err(QuestionError::unavailable)?
            .transpose()
    }

    fn row(&self, question_id: QuestionId) -> Result<Option<Row>> {
        self.connection
            .query_row(
                "SELECT question_id, revision, state, kind, context, question, choices, source,
                        created_at_ms, pending_since_ms, expires_at_ms, answer, resolved_at_ms,
                        token_nonce, token_sealed, payload_digest, source_key, token_tag
                 FROM questions WHERE question_id = ?1",
                params![question_id.get().as_bytes().as_slice()],
                |row| Ok(self.hydrate(row)),
            )
            .optional()
            .map_err(QuestionError::unavailable)?
            .transpose()
    }

    fn hydrate(&self, row: &rusqlite::Row<'_>) -> Result<Row> {
        hydrate_row(self.session_id, self.session_epoch, row)
    }
}

/// The columns every question read selects, in the order [`hydrate_row`] expects them.
const ROW_COLUMNS: &str = "question_id, revision, state, kind, context, question, choices, source,
         created_at_ms, pending_since_ms, expires_at_ms, answer, resolved_at_ms,
         token_nonce, token_sealed, payload_digest, source_key, token_tag";

/// Reads one question inside a transaction.
fn read_row_in(
    transaction: &rusqlite::Transaction<'_>,
    session_id: SessionId,
    session_epoch: SessionEpoch,
    question_id: QuestionId,
) -> Result<Option<Row>> {
    transaction
        .query_row(
            &format!("SELECT {ROW_COLUMNS} FROM questions WHERE question_id = ?1"),
            params![question_id.get().as_bytes().as_slice()],
            |row| Ok(hydrate_row(session_id, session_epoch, row)),
        )
        .optional()
        .map_err(QuestionError::unavailable)?
        .transpose()
}

/// Builds one question from a row of [`ROW_COLUMNS`].
fn hydrate_row(
    session_id: SessionId,
    session_epoch: SessionEpoch,
    row: &rusqlite::Row<'_>,
) -> Result<Row> {
    let read = |index: usize| -> Result<Vec<u8>> {
        row.get::<_, Vec<u8>>(index)
            .map_err(QuestionError::unavailable)
    };
    let text = |index: usize| -> Result<String> {
        row.get::<_, String>(index)
            .map_err(QuestionError::unavailable)
    };
    let number = |index: usize| -> Result<u64> {
        row.get::<_, i64>(index)
            .map(|value| u64::try_from(value).unwrap_or_default())
            .map_err(QuestionError::unavailable)
    };
    let state = QuestionState::from_wire(&text(2)?)
        .ok_or_else(|| QuestionError::unavailable("a question state this build cannot read"))?;
    let kind = match text(3)?.as_str() {
        "input" => QuestionKind::Input,
        "select" => QuestionKind::Select,
        "confirm" => QuestionKind::Confirm,
        other => {
            return Err(QuestionError::unavailable(format!(
                "a question kind this build cannot read: {other}"
            )));
        }
    };
    let answer = row
        .get::<_, Option<Vec<u8>>>(11)
        .map_err(QuestionError::unavailable)?
        .map(|bytes| decode::<AnswerRecord>(&bytes))
        .transpose()?;
    let resolved = row
        .get::<_, Option<i64>>(12)
        .map_err(QuestionError::unavailable)?
        .map(|value| TimestampMs::new(u64::try_from(value).unwrap_or_default()));
    Ok(Row {
        question: Question {
            question_id: QuestionId::new(uuid_from(&read(0)?)?),
            revision: QuestionRevision::new(number(1)?),
            state,
            session_id,
            session_epoch,
            kind,
            context: text(4)?,
            question: text(5)?,
            choices: decode::<Vec<QuestionChoice>>(&read(6)?)?,
            source: decode::<QuestionSource>(&read(7)?)?,
            created_at_ms: TimestampMs::new(number(8)?),
            expires_at_ms: TimestampMs::new(number(10)?),
            answer: Nullable(answer),
            resolved_at_ms: Nullable(resolved),
        },
        pending_since_ms: TimestampMs::new(number(9)?),
        token_nonce: read(13)?,
        token_sealed: read(14)?,
        token_tag: read(17)?,
        digest: read(15)?,
        source_key: text(16)?,
    })
}

/// One stored question, with the material a token check needs.
#[derive(Clone, Debug)]
pub struct Row {
    /// The question.
    pub question: Question,
    /// When it first became pending.
    pub pending_since_ms: TimestampMs,
    /// The nonce the sealed token copy was made with.
    pub token_nonce: Vec<u8>,
    /// The sealed copy of the token.
    pub token_sealed: Vec<u8>,
    /// The keyed verification tag of the token this question was issued with.
    pub token_tag: Vec<u8>,
    /// The digest of the payload the question was created from.
    pub digest: Vec<u8>,
    /// The verified source that created it.
    pub source_key: String,
}

/// Writes one transition to the durable feed, inside the caller's transaction.
///
/// The feed is written in the same transaction as the transition it describes, so a crash cannot
/// leave a question that moved beside a feed that never heard. Each event carries the moment the
/// question became pending, which is what section 25's five-minute idle reminder measures from.
fn write_event(transaction: &rusqlite::Transaction<'_>, event: &QuestionEvent) -> Result<()> {
    transaction
        .execute(
            "INSERT INTO question_events (kind, question_id, record, recorded_at_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                event.kind.event_type(),
                event.question.question_id.get().as_bytes().as_slice(),
                encode(event)?,
                millis(event.recorded_at_ms.get())
            ],
        )
        .map_err(QuestionError::unavailable)?;
    Ok(())
}

/// Renders one resolution as the event the feed carries.
fn event_of(kind: QuestionEventKind, resolved: &Resolved, now: Now) -> QuestionEvent {
    QuestionEvent {
        kind,
        question: resolved.question.clone(),
        pending_since_ms: resolved.pending_since_ms,
        recorded_at_ms: now.utc_ms,
    }
}

fn millis(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn count(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn uuid_from(bytes: &[u8]) -> Result<Uuid> {
    <[u8; 16]>::try_from(bytes)
        .map(Uuid::from_bytes)
        .map_err(|_| QuestionError::unavailable("a stored identifier is not sixteen bytes"))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    kr_cbor::to_canonical_vec(value).map_err(QuestionError::unavailable)
}

fn decode<T: serde::de::DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> Result<T> {
    kr_cbor::from_canonical_slice(bytes, &kr_cbor::Limits::DEFAULT).map_err(|error| {
        QuestionError::unavailable(format!("a stored record could not be read: {error}"))
    })
}

/// The digest that decides between an exact duplicate and a reused identifier.
///
/// It covers everything the question is made of, including the choices the host built, so a caller
/// that changed one label under the same request identifier is a conflict rather than a retry.
fn payload_digest(params: &QuestionCreateParams, choices: &[QuestionChoice]) -> Vec<u8> {
    let elements = kr_cbor::CanonicalValue::Array(vec![
        kr_cbor::CanonicalValue::text("kr-question/create/1"),
        kr_cbor::CanonicalValue::text(&params.request_id),
        kr_cbor::CanonicalValue::text(params.kind.as_str()),
        kr_cbor::CanonicalValue::text(&params.context),
        kr_cbor::CanonicalValue::text(&params.question),
        kr_cbor::CanonicalValue::Array(
            choices
                .iter()
                .map(|choice| {
                    kr_cbor::CanonicalValue::Array(vec![
                        kr_cbor::CanonicalValue::text(&choice.choice_id),
                        kr_cbor::CanonicalValue::text(&choice.label),
                    ])
                })
                .collect(),
        ),
        // Everything the question is made of, including what a person reads and how long it lives.
        // A caller that changed the label it shows or the time it allows has asked a different
        // question, and returning the first one under that identifier would answer a question
        // nobody asked.
        kr_cbor::CanonicalValue::text(params.agent_name.as_ref().map_or("", String::as_str)),
        kr_cbor::CanonicalValue::text(
            params
                .requested_expiry_ms
                .as_ref()
                .map_or_else(String::new, |asked| asked.get().to_string()),
        ),
    ]);
    kr_cbor::sha256_of_canonical(&elements).to_vec()
}

fn alert_digest(params: &AlertCreateParams) -> Vec<u8> {
    let elements = kr_cbor::CanonicalValue::Array(vec![
        kr_cbor::CanonicalValue::text("kr-alert/create/1"),
        kr_cbor::CanonicalValue::text(&params.dedup_id),
        kr_cbor::CanonicalValue::text(&params.text),
        kr_cbor::CanonicalValue::text(params.severity.as_str()),
        kr_cbor::CanonicalValue::text(params.agent_name.as_ref().map_or("", String::as_str)),
        kr_cbor::CanonicalValue::text(params.safe_session_link.as_ref().map_or("", String::as_str)),
    ]);
    kr_cbor::sha256_of_canonical(&elements).to_vec()
}

#[cfg(test)]
mod tests {
    use kr_protocol::ids::ConnectionId;
    use kr_protocol::question::{AlertSeverity, QuestionAnswer, build_choices};

    use super::*;

    /// A source that is this test process, so its questions outlive their creation.
    fn source() -> VerifiedSource {
        VerifiedSource {
            process: kr_ipc::identity::process_start_identity(std::process::id())
                .expect("this process's start identity"),
            executable: Some("/usr/bin/agent".to_owned()),
            session_member: true,
            ancestry: true,
            launch_channel: false,
            connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
        }
    }

    fn now(utc: u64) -> Now {
        Now {
            utc_ms: TimestampMs::new(utc),
            boot_ms: utc,
        }
    }

    fn store() -> Store {
        Store::open(
            None,
            SessionId::new(Uuid::from_bytes([3; 16])),
            SessionEpoch::V1,
        )
        .expect("a ledger")
    }

    fn creation(request_id: &str, question: &str) -> QuestionCreateParams {
        QuestionCreateParams {
            session_id: SessionId::new(Uuid::from_bytes([3; 16])),
            request_id: request_id.to_owned(),
            agent_name: Nullable::some("an agent".to_owned()),
            context: "context".to_owned(),
            question: question.to_owned(),
            kind: QuestionKind::Confirm,
            choices: Vec::new(),
            requested_expiry_ms: Nullable::null(),
            wait_ms: Nullable::null(),
        }
    }

    fn create(store: &mut Store, params: &QuestionCreateParams, at: u64) -> Created {
        let source = source();
        let header = store
            .source_header(&source, Some("an agent".to_owned()), now(at))
            .expect("a header");
        let choices = build_choices(params.kind, &params.choices).expect("choices");
        store
            .create(&source, &header, params, &choices, 60_000, now(at))
            .expect("creates")
    }

    #[test]
    fn an_exact_duplicate_returns_the_same_question_and_the_same_token() {
        let mut store = store();
        let params = creation("r-1", "shall I?");
        let first = create(&mut store, &params, 1_000);
        let second = create(&mut store, &params, 2_000);
        assert!(!first.deduplicated);
        assert!(second.deduplicated);
        assert_eq!(first.question.question_id, second.question.question_id);
        assert_eq!(
            first.caller_token.as_slice(),
            second.caller_token.as_slice()
        );
    }

    #[test]
    fn a_changed_payload_under_the_same_request_is_a_conflict() {
        let mut store = store();
        create(&mut store, &creation("r-1", "shall I?"), 1_000);
        let source = source();
        let params = creation("r-1", "shall I really?");
        let header = store
            .source_header(&source, None, now(2_000))
            .expect("a header");
        let choices = build_choices(params.kind, &params.choices).expect("choices");
        let error = store
            .create(&source, &header, &params, &choices, 60_000, now(2_000))
            .expect_err("conflict");
        assert_eq!(error.code(), kr_protocol::error::ErrorCode::IdConflict);
    }

    #[test]
    fn exactly_one_of_two_answers_wins() {
        let mut store = store();
        let created = create(&mut store, &creation("r-1", "shall I?"), 1_000);
        let revision = created.question.revision;
        let actor = ActorId::new("local:501").expect("a principal");
        let first = store
            .answer(
                created.question.question_id,
                revision,
                &QuestionAnswer::Decision { decided: true },
                &actor,
                None,
                now(2_000),
            )
            .expect("wins");
        assert_eq!(first.question.state, QuestionState::Answered);
        let error = store
            .answer(
                created.question.question_id,
                revision,
                &QuestionAnswer::Decision { decided: false },
                &actor,
                None,
                now(2_001),
            )
            .expect_err("loses");
        assert_eq!(
            error.code(),
            kr_protocol::error::ErrorCode::QuestionResolved
        );
    }

    #[test]
    fn a_free_text_answer_stays_free_text() {
        let mut store = store();
        let created = create(&mut store, &creation("r-1", "which one?"), 1_000);
        let resolved = store
            .answer(
                created.question.question_id,
                created.question.revision,
                &QuestionAnswer::Other {
                    text: "neither".to_owned(),
                },
                &ActorId::new("local:501").expect("a principal"),
                None,
                now(2_000),
            )
            .expect("answered");
        let stored = store
            .read(resolved.question.question_id)
            .expect("still there");
        assert_eq!(
            stored.answer.as_ref().map(|record| record.answer.clone()),
            Some(QuestionAnswer::Other {
                text: "neither".to_owned()
            })
        );
    }

    #[test]
    fn a_question_ends_with_the_application_that_asked_it() {
        let mut store = store();
        let source = VerifiedSource {
            process: ProcessStartIdentity::new(
                7,
                kr_protocol::identity::ProcessStartSource::LinuxProcStat,
                11,
            ),
            executable: None,
            session_member: true,
            ancestry: false,
            launch_channel: false,
            connection_id: ConnectionId::new(Uuid::from_bytes([2; 16])),
        };
        let params = creation("r-1", "shall I?");
        let header = store
            .source_header(&source, None, now(1_000))
            .expect("a header");
        let choices = build_choices(params.kind, &params.choices).expect("choices");
        store
            .create(&source, &header, &params, &choices, 60_000, now(1_000))
            .expect("creates");
        // The deadline is an hour away and the process never existed, so what expires the question
        // is the end of the binding rather than the clock.
        let expired = store.expire_due(now(1_001)).expect("sweeps");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].question.state, QuestionState::Expired);
    }

    #[test]
    fn a_deadline_that_has_passed_expires_the_question() {
        let mut store = store();
        let created = create(&mut store, &creation("r-1", "shall I?"), 1_000);
        let expired = store.expire_due(now(1_000 + 60_001)).expect("sweeps");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].question.state, QuestionState::Expired);
        let error = store
            .answer(
                created.question.question_id,
                created.question.revision,
                &QuestionAnswer::Decision { decided: true },
                &ActorId::new("local:501").expect("a principal"),
                None,
                now(1_000 + 60_002),
            )
            .expect_err("too late");
        assert_eq!(error.code(), kr_protocol::error::ErrorCode::QuestionExpired);
    }

    #[test]
    fn a_cancellation_is_not_an_expiry() {
        let mut store = store();
        let created = create(&mut store, &creation("r-1", "shall I?"), 1_000);
        let resolved = store
            .cancel(
                created.question.question_id,
                created.question.revision,
                now(2_000),
            )
            .expect("cancels");
        assert_eq!(resolved.question.state, QuestionState::Cancelled);
        assert!(store.expire_due(now(3_000)).expect("sweeps").is_empty());
    }

    #[test]
    fn a_token_from_another_application_is_refused() {
        let mut store = store();
        let created = create(&mut store, &creation("r-1", "shall I?"), 1_000);
        let row = store
            .read_row(created.question.question_id)
            .expect("the row");
        let mut other = source();
        other.process = ProcessStartIdentity::new(
            9,
            kr_protocol::identity::ProcessStartSource::LinuxProcStat,
            13,
        );
        let error = store
            .check_token(&row, &other, &created.caller_token)
            .expect_err("refused");
        assert_eq!(
            error.code(),
            kr_protocol::error::ErrorCode::PermissionDenied
        );
        assert!(
            store
                .check_token(&row, &source(), &created.caller_token)
                .is_ok()
        );
    }

    #[test]
    fn an_alert_de_duplicates_on_its_own_identifier() {
        let mut store = store();
        let source = source();
        let header = store
            .source_header(&source, None, now(1_000))
            .expect("a header");
        let params = AlertCreateParams {
            session_id: SessionId::new(Uuid::from_bytes([3; 16])),
            dedup_id: "build-failed".to_owned(),
            agent_name: Nullable::null(),
            text: "the build failed".to_owned(),
            severity: AlertSeverity::Warning,
            safe_session_link: Nullable::null(),
        };
        let (first, deduplicated) = store
            .alert(&source, &header, &params, now(1_000))
            .expect("ok");
        assert!(!deduplicated);
        let (second, deduplicated) = store
            .alert(&source, &header, &params, now(2_000))
            .expect("ok");
        assert!(deduplicated);
        assert_eq!(first.created_at_ms, second.created_at_ms);
        assert_eq!(store.alerts().expect("listed").len(), 1);
    }
}
