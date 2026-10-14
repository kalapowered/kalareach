//! What the store holds about the host's own backups: the setup its owner made, the number of the
//! last generation made, what each generation was made from, and the finished ciphertext that is
//! still on the disk.

use kr_protocol::scalars::StoredEnvelopeKey;

use super::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupStore, ControllerError, Digest256, KeyId,
    MadeFrom, OptionalExtension, PathBuf, Reads, Result, TimestampMs, Writing, cancel_production,
    cancel_queued_attempts, key_id, millis, params, sql, try_finish_generation, uuid,
};

/// What the owner's setup recorded.
///
/// None of it is secret: the recovery recipient is a public key, the account is a digest, and the
/// kit is named by a fingerprint of that key and by nothing of the seed.
#[derive(Clone, PartialEq, Eq)]
pub struct SetupRecord {
    /// The archive this host's backups are of.
    pub archive_id: ArchiveId,
    /// The storage service origin, as the host holds it.
    pub origin: String,
    /// The mark of the account the backups belong to: a digest of its issuer, its subject and the
    /// origin, which is all a request is checked against.
    pub account_mark: [u8; 32],
    /// The recovery recipient every generation wraps its manifest key for.
    pub recovery_public_key: StoredEnvelopeKey,
    /// The fingerprint a person matches a kit to this host by.
    pub kit_fingerprint: String,
    /// The writer that signs the manifests and publications.
    pub writer_key_id: KeyId,
    /// The key every wrap is sent from.
    pub producer_key_id: KeyId,
    /// When the owner set backups up. One time, chosen once, repeated in every repeat of a setup.
    pub enabled_at_ms: TimestampMs,
}

impl std::fmt::Debug for SetupRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SetupRecord")
            .field("archive_id", &self.archive_id)
            .field("kit_fingerprint", &self.kit_fingerprint)
            .finish_non_exhaustive()
    }
}

/// The setup, with the number of the last generation made under it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Setup {
    /// What the owner recorded.
    pub record: SetupRecord,
    /// The number of the last generation made for the archive, written in the transaction that
    /// admitted it and never lowered.
    pub generation_counter: u64,
}

/// What writing a setup did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupCommit {
    /// There was no setup, and this is it.
    Written,
    /// The same setup was already there. A repeat of a call whose answer was lost.
    Unchanged,
    /// Another archive's setup was there. Its writer is retired and what it had not finished is
    /// cancelled; what it published stays at the service and is never touched again.
    Replaced {
        /// The archive that was set aside.
        earlier: ArchiveId,
        /// How many of its unfinished generations were cancelled.
        cancelled: u64,
    },
}

/// One staged object whose ciphertext this host no longer needs on its disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Releasable {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// The object.
    pub object_id: BackupObjectId,
    /// Where its ciphertext is staged.
    pub staged_path: PathBuf,
}

impl BackupStore {
    /// Returns the privacy generation in force.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn privacy_generation(&self) -> Result<u64> {
        Ok(u64::try_from(super::current_generation(&self.connection)?).unwrap_or(0))
    }

    /// Returns the setup the owner made, if there is one.
    ///
    /// The absence of a setup is this store's own fact. A host that has none owes no account
    /// anything.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn setup(&self) -> Result<Option<Setup>> {
        read_setup(&self.connection)
    }

    /// Writes the setup, and enrols its writer, in one transaction.
    ///
    /// With `replace` over a setup of another archive, the same transaction retires the earlier
    /// archive's writers and cancels every generation of it that is still producing: retiring the
    /// writer alone stops nothing that was already admitted. What the earlier archive published
    /// stays where it is and is never reclaimed, because retention needs the writer enrolled.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when a setup is there for another archive and
    /// `replace` was not asked for, or for the same archive with something else recorded, and
    /// [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn commit_setup(
        &mut self,
        record: &SetupRecord,
        replace: bool,
        now_ms: TimestampMs,
    ) -> Result<SetupCommit> {
        let transaction = self
            .connection
            .writing()
            .map_err(ControllerError::registry)?;
        let earlier = read_setup(&transaction)?;
        let archive = record.archive_id.get().as_bytes().to_vec();
        let commit = match earlier {
            None => {
                transaction
                    .run(
                        sql!(
                            "INSERT INTO host_backup
                             (id, archive_id, origin, account_mark, recovery_public_key,
                              kit_fingerprint, writer_key_id, producer_key_id, enabled_at_ms,
                              generation_counter)
                         VALUES (0, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)"
                        ),
                        params![
                            archive,
                            record.origin,
                            record.account_mark.as_slice(),
                            record.recovery_public_key.as_bytes().as_slice(),
                            record.kit_fingerprint,
                            record.writer_key_id.as_bytes().as_slice(),
                            record.producer_key_id.as_bytes().as_slice(),
                            millis(record.enabled_at_ms),
                        ],
                    )
                    .map_err(ControllerError::registry)?;
                SetupCommit::Written
            }
            Some(earlier) if earlier.record.archive_id == record.archive_id => {
                if earlier.record != *record {
                    return Err(ControllerError::InvalidArgument(
                        "this host's backups were set up for that archive with something else \
                         recorded"
                            .to_owned(),
                    ));
                }
                return Ok(SetupCommit::Unchanged);
            }
            Some(earlier) => {
                if !replace {
                    return Err(ControllerError::InvalidArgument(
                        "this host's backups are set up for another archive, and setting them up \
                         again for this one replaces it"
                            .to_owned(),
                    ));
                }
                // An archive this host already has generations of is not the next one: a late
                // repeat of a setup for an archive that was replaced would otherwise start its
                // count again under generations the host still records.
                let used: i64 = transaction
                    .read_one(
                        sql!("SELECT COUNT(*) FROM generations WHERE archive_id = ?1"),
                        params![archive],
                        |row| row.get(0),
                    )
                    .map_err(ControllerError::registry)?;
                if used > 0 {
                    return Err(ControllerError::InvalidArgument(
                        "this host already records generations of that archive, so it cannot be \
                         set up for it again"
                            .to_owned(),
                    ));
                }
                let set_aside = earlier.record.archive_id;
                transaction
                    .run(
                        sql!(
                            "UPDATE writers SET retired_at_ms = ?2
                          WHERE archive_id = ?1 AND retired_at_ms IS NULL"
                        ),
                        params![set_aside.get().as_bytes().as_slice(), millis(now_ms)],
                    )
                    .map_err(ControllerError::registry)?;
                let mut cancelled = 0u64;
                for backup_generation in producing_generations(&transaction, set_aside)? {
                    cancel_queued_attempts(&transaction, set_aside, backup_generation, now_ms)?;
                    cancel_production(
                        &transaction,
                        set_aside,
                        backup_generation,
                        "this host's backups were set up again, for another archive",
                        now_ms,
                    )?;
                    try_finish_generation(&transaction, set_aside, backup_generation)?;
                    cancelled += 1;
                }
                transaction
                    .run(
                        sql!(
                            "UPDATE host_backup
                            SET archive_id = ?1, origin = ?2, account_mark = ?3,
                                recovery_public_key = ?4, kit_fingerprint = ?5,
                                writer_key_id = ?6, producer_key_id = ?7, enabled_at_ms = ?8,
                                generation_counter = 0
                          WHERE id = 0"
                        ),
                        params![
                            archive,
                            record.origin,
                            record.account_mark.as_slice(),
                            record.recovery_public_key.as_bytes().as_slice(),
                            record.kit_fingerprint,
                            record.writer_key_id.as_bytes().as_slice(),
                            record.producer_key_id.as_bytes().as_slice(),
                            millis(record.enabled_at_ms),
                        ],
                    )
                    .map_err(ControllerError::registry)?;
                SetupCommit::Replaced {
                    earlier: set_aside,
                    cancelled,
                }
            }
        };
        transaction
            .run(
                sql!(
                    "INSERT INTO writers (writer_key_id, archive_id, enrolled_at_ms, retired_at_ms)
                 VALUES (?1, ?2, ?3, NULL)
                 ON CONFLICT (archive_id, writer_key_id) DO UPDATE
                     SET enrolled_at_ms = ?3, retired_at_ms = NULL"
                ),
                params![
                    record.writer_key_id.as_bytes().as_slice(),
                    archive,
                    millis(record.enabled_at_ms),
                ],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(commit)
    }

    /// Raises the number of the last generation made for the setup's archive to `generation`, and
    /// never lowers it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn raise_generation_counter(
        &mut self,
        archive_id: ArchiveId,
        generation: BackupGeneration,
    ) -> Result<()> {
        self.connection
            .run(
                sql!(
                    "UPDATE host_backup SET generation_counter = ?2
                  WHERE id = 0 AND archive_id = ?1 AND generation_counter < ?2"
                ),
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(generation.get()).unwrap_or(i64::MAX),
                ],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Returns what one generation was made from, if it was made from the host's state.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn made_from(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Option<MadeFrom>> {
        let found: Option<(Vec<u8>, Vec<u8>)> = self
            .connection
            .read_one(
                sql!(
                    "SELECT fingerprint, unreadable FROM generation_sources
                  WHERE archive_id = ?1 AND backup_generation = ?2"
                ),
                params![
                    archive_id.get().as_bytes().as_slice(),
                    i64::try_from(backup_generation.get()).unwrap_or(i64::MAX),
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let stored = |bytes: &[u8]| {
            <[u8; 32]>::try_from(bytes)
                .map(Digest256::from_bytes)
                .map_err(|_| ControllerError::registry("a stored digest is not 32 bytes"))
        };
        found
            .map(|(fingerprint, unreadable)| {
                Ok(MadeFrom {
                    fingerprint: stored(&fingerprint)?,
                    unreadable: unreadable
                        .chunks(32)
                        .map(stored)
                        .collect::<Result<Vec<_>>>()?,
                })
            })
            .transpose()
    }

    /// Whether any object of a generation whose production is over still has its ciphertext on this
    /// host's disk, whether or not it can be given back yet.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn holds_finished_ciphertext(&self) -> Result<bool> {
        let held: i64 = self
            .connection
            .read_one(
                sql!(
                    "SELECT COUNT(*) FROM objects
                       JOIN generations
                         ON generations.archive_id = objects.archive_id
                        AND generations.backup_generation = objects.backup_generation
                      WHERE objects.local_state = 'present'
                        AND generations.production IN ('cancelled', 'complete')"
                ),
                [],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        Ok(held > 0)
    }

    /// Returns every object whose ciphertext is on this host's disk and no longer needed there.
    ///
    /// Production of its generation is over, complete or cancelled, and no attempt or upload of it
    /// is open. A service holds what it will hold, or this host will send nothing more of it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn releasable_ciphertext(&self) -> Result<Vec<Releasable>> {
        let mut statement = self
            .connection
            .prepared(sql!(
                "SELECT objects.archive_id, objects.backup_generation, objects.object_id,
                        objects.staged_path
                   FROM objects
                   JOIN generations
                     ON generations.archive_id = objects.archive_id
                    AND generations.backup_generation = objects.backup_generation
                  WHERE objects.local_state = 'present'
                    AND generations.production IN ('cancelled', 'complete')
                    AND NOT EXISTS (SELECT 1 FROM outbox
                                     WHERE outbox.archive_id = objects.archive_id
                                       AND outbox.backup_generation = objects.backup_generation
                                       AND outbox.status <> 'terminal')
                    AND NOT EXISTS (SELECT 1 FROM uploads
                                     WHERE uploads.archive_id = objects.archive_id
                                       AND uploads.backup_generation = objects.backup_generation)
                  ORDER BY objects.archive_id, objects.backup_generation, objects.object_id"
            ))
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], |row| {
                let archive: Vec<u8> = row.get(0)?;
                let generation: i64 = row.get(1)?;
                let object: Vec<u8> = row.get(2)?;
                let path: String = row.get(3)?;
                Ok((|| -> Result<Releasable> {
                    Ok(Releasable {
                        archive_id: ArchiveId::new(uuid(&archive, "an archive identifier")?),
                        backup_generation: BackupGeneration::new(
                            u64::try_from(generation).unwrap_or(0),
                        ),
                        object_id: BackupObjectId::new(uuid(&object, "an object identifier")?),
                        staged_path: PathBuf::from(path),
                    })
                })())
            })
            .map_err(ControllerError::registry)?;
        let mut found = Vec::new();
        for row in rows {
            found.push(row.map_err(ControllerError::registry)??);
        }
        Ok(found)
    }

    /// Records that one object's ciphertext is gone from the disk, once the checks that made it
    /// releasable still hold in this transaction.
    ///
    /// The caller unlinks the file and flushes its directory first, so a row that says the file is
    /// absent is never written ahead of the removal. Returns whether the row was changed; an object
    /// that was already absent, or whose generation took up work again, is left as it was.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn note_ciphertext_released(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
    ) -> Result<bool> {
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .writing()
            .map_err(ControllerError::registry)?;
        let changed = transaction
            .run(
                sql!(
                    "UPDATE objects SET local_state = 'absent'
                  WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3
                    AND local_state = 'present'
                    AND EXISTS (SELECT 1 FROM generations
                                 WHERE archive_id = ?1 AND backup_generation = ?2
                                   AND production IN ('cancelled', 'complete'))
                    AND NOT EXISTS (SELECT 1 FROM outbox
                                     WHERE archive_id = ?1 AND backup_generation = ?2
                                       AND status <> 'terminal')
                    AND NOT EXISTS (SELECT 1 FROM uploads
                                     WHERE archive_id = ?1 AND backup_generation = ?2)"
                ),
                params![archive, generation, object_id.get().as_bytes().as_slice()],
            )
            .map_err(ControllerError::registry)?;
        try_finish_generation(&transaction, archive_id, backup_generation)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(changed > 0)
    }
}

/// Reads the setup row inside whatever holds the connection.
fn read_setup(reader: &impl Reads) -> Result<Option<Setup>> {
    let found = reader
        .read_one(
            sql!(
                "SELECT archive_id, origin, account_mark, recovery_public_key, kit_fingerprint,
                        writer_key_id, producer_key_id, enabled_at_ms, generation_counter
                   FROM host_backup WHERE id = 0"
            ),
            [],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()
        .map_err(ControllerError::registry)?;
    let Some((archive, origin, mark, recovery, fingerprint, writer, producer, enabled, counter)) =
        found
    else {
        return Ok(None);
    };
    let fixed = |bytes: &[u8], what: &'static str| {
        <[u8; 32]>::try_from(bytes)
            .map_err(|_| ControllerError::registry(format!("a stored {what} is not 32 bytes")))
    };
    Ok(Some(Setup {
        record: SetupRecord {
            archive_id: ArchiveId::new(uuid(&archive, "an archive identifier")?),
            origin,
            account_mark: fixed(&mark, "account mark")?,
            recovery_public_key: StoredEnvelopeKey::from_bytes(fixed(
                &recovery,
                "recovery public key",
            )?),
            kit_fingerprint: fingerprint,
            writer_key_id: key_id(&writer)?,
            producer_key_id: key_id(&producer)?,
            enabled_at_ms: TimestampMs::new(u64::try_from(enabled).unwrap_or(0)),
        },
        generation_counter: u64::try_from(counter).unwrap_or(0),
    }))
}

/// Returns the generations of one archive whose production is not over.
fn producing_generations(
    transaction: &Writing<'_>,
    archive_id: ArchiveId,
) -> Result<Vec<BackupGeneration>> {
    let mut statement = transaction
        .prepared(sql!(
            "SELECT backup_generation FROM generations
              WHERE archive_id = ?1 AND production = 'producing'
              ORDER BY backup_generation"
        ))
        .map_err(ControllerError::registry)?;
    let rows = statement
        .query_map(params![archive_id.get().as_bytes().as_slice()], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(ControllerError::registry)?;
    let mut found = Vec::new();
    for row in rows {
        found.push(BackupGeneration::new(
            u64::try_from(row.map_err(ControllerError::registry)?).unwrap_or(0),
        ));
    }
    Ok(found)
}
