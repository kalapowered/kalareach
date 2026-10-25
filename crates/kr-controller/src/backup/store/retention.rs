//! Which published generations' objects this host may ask the service to delete, and the standing
//! a deletion needs.
//!
//! The service prunes nothing: it records how many daily snapshots the account keeps and leaves the
//! producer to decide which to delete. The host keeps the newest K published generations of its
//! archive and deletes the objects of older ones, one object at a time. The store decides each
//! deletion in the one transaction that writes it down, from its own rows and nothing a caller
//! read before, and decides it again for a deletion already written down and asked for again.

use kr_protocol::error::ErrorCode;

use super::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupStore, ControllerError, OptionalExtension,
    Reads, Result, TimestampMs, current_generation, inhibited_at, millis, params, sql,
};

/// The test, for a row of `generations`, that the host is deleting the whole generation: it
/// records objects for it, and a deletion of each is written down. Such a generation is no backup
/// the host has, whoever asked, so it counts for nothing in what the host keeps.
macro_rules! being_deleted {
    () => {
        "(EXISTS (SELECT 1 FROM objects
                   WHERE objects.archive_id = generations.archive_id
                     AND objects.backup_generation = generations.backup_generation)
          AND NOT EXISTS (SELECT 1 FROM objects
                           WHERE objects.archive_id = generations.archive_id
                             AND objects.backup_generation = generations.backup_generation
                             AND NOT EXISTS (SELECT 1 FROM releases
                                              WHERE releases.archive_id = objects.archive_id
                                                AND releases.backup_generation = objects.backup_generation
                                                AND releases.object_id = objects.object_id)))"
    };
}

/// The fewest generations of an archive the host keeps published: the newest, and the one a
/// restore may be reading when the next is published.
pub const LEAST_KEPT: u64 = 2;

/// Why a deletion for `archive` is not asked now, or nothing when its standing holds.
///
/// When the host has a setup, only the setup's archive is the host's to delete from: an answer of
/// "not found" under another account says nothing of the object, and the earlier archive of a
/// replaced setup is never touched again. With `generation` named and `writer` asked for, the
/// writer that signed the generation must still be enrolled for the archive, so a collection
/// deleted at the account console is not asked about.
pub(super) fn standing_refusal(
    reader: &impl Reads,
    archive: &[u8],
    generation: i64,
    writer: bool,
) -> Result<Option<String>> {
    let setup: Option<Vec<u8>> = reader
        .read_one(
            sql!("SELECT archive_id FROM host_backup WHERE id = 0"),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(ControllerError::registry)?;
    if let Some(setup) = &setup
        && setup.as_slice() != archive
    {
        return Ok(Some(
            "that archive is not the one this host's backups are of".to_owned(),
        ));
    }
    if writer {
        let enrolled: i64 = reader
            .read_one(
                sql!(
                    "SELECT COUNT(*) FROM writers
                  WHERE archive_id = ?1 AND retired_at_ms IS NULL
                    AND writer_key_id = (SELECT writer_key_id FROM generations
                                          WHERE archive_id = ?1 AND backup_generation = ?2)"
                ),
                params![archive, generation],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if enrolled == 0 {
            return Ok(Some(
                "this host holds no enrolment of the writer of that generation for that archive"
                    .to_owned(),
            ));
        }
    }
    Ok(None)
}

/// Why the person may not ask the service to delete the objects of `generation` of `archive`, or
/// nothing when they may.
///
/// Privacy mode is not a reason: the copies it lists as having left this host are exactly what the
/// person's own action is for. The rest is the store's: the host has a setup and the archive is its
/// own, the writer is still enrolled, the generation is in a state the `releases` rule admits, no
/// attempt or upload of it is open, and an outcome this host could not establish is deleted only
/// once a newer generation is published, since a late publication of it would otherwise name
/// objects that are gone.
pub(super) fn person_refusal(
    reader: &impl Reads,
    archive: &[u8],
    generation: i64,
) -> Result<Option<String>> {
    let setup: i64 = reader
        .read_one(sql!("SELECT COUNT(*) FROM host_backup"), [], |row| {
            row.get(0)
        })
        .map_err(ControllerError::registry)?;
    if setup == 0 {
        return Ok(Some(
            "this host has no setup, and deletes nothing at a service without one".to_owned(),
        ));
    }
    if let Some(refusal) = standing_refusal(reader, archive, generation, true)? {
        return Ok(Some(refusal));
    }
    let row: Option<(String, String)> = reader
        .read_one(
            sql!(
                "SELECT production, remote FROM generations
                  WHERE archive_id = ?1 AND backup_generation = ?2"
            ),
            params![archive, generation],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(ControllerError::registry)?;
    let Some((production, remote)) = row else {
        return Ok(Some(
            "that backup generation is not one this host admitted".to_owned(),
        ));
    };
    let over = matches!(production.as_str(), "complete" | "cancelled");
    let admitted = match remote.as_str() {
        "published" if over => true,
        "unknown" if production == "cancelled" => {
            let newer: i64 = reader
                .read_one(
                    sql!(
                        "SELECT COUNT(*) FROM generations
                          WHERE archive_id = ?1 AND backup_generation > ?2
                            AND remote = 'published'"
                    ),
                    params![archive, generation],
                    |row| row.get(0),
                )
                .map_err(ControllerError::registry)?;
            if newer == 0 {
                return Ok(Some(
                    "no newer generation of that archive is published, so a publication of this \
                     one may still land"
                        .to_owned(),
                ));
            }
            true
        }
        "objects" => {
            return Ok(Some(
                "a service holds ciphertext of that generation and no descriptor was published, \
                 which this host's store has no record of asking the deletion of"
                    .to_owned(),
            ));
        }
        _ => false,
    };
    if !admitted {
        return Ok(Some(
            "only an object of a published generation whose production is over, or of one that \
             ended with its outcome unknown, is deleted"
                .to_owned(),
        ));
    }
    let open: i64 = reader
        .read_one(
            sql!(
                "SELECT (SELECT COUNT(*) FROM outbox
                          WHERE archive_id = ?1 AND backup_generation = ?2
                            AND status <> 'terminal')
                      + (SELECT COUNT(*) FROM uploads
                          WHERE archive_id = ?1 AND backup_generation = ?2)"
            ),
            params![archive, generation],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)?;
    if open > 0 {
        return Ok(Some(
            "an attempt or an upload of that generation is still open".to_owned(),
        ));
    }
    let shared: i64 = reader
        .read_one(
            sql!(
                "SELECT COUNT(*) FROM objects AS held
                  WHERE held.archive_id = ?1 AND held.backup_generation = ?2
                    AND EXISTS (SELECT 1 FROM objects AS other
                                 WHERE other.archive_id = held.archive_id
                                   AND other.object_id = held.object_id
                                   AND other.backup_generation <> held.backup_generation)"
            ),
            params![archive, generation],
            |row| row.get(0),
        )
        .map_err(ControllerError::registry)?;
    if shared > 0 {
        return Ok(Some(
            "another backup generation this host records names an object of that one".to_owned(),
        ));
    }
    Ok(None)
}

impl BackupStore {
    /// Writes down that this host will ask the service to delete one object of a published
    /// generation that is older than the newest `keep` published generations of its archive.
    ///
    /// The store decides here, in the transaction that writes it down: the host has a setup and
    /// the archive is its own; the writer is still enrolled; privacy mode holds no fence and the
    /// generation is of the privacy generation in force, since a line privacy mode drew under a
    /// generation leaves its objects to the person's own action; its production is over and no
    /// attempt or upload of it is open; at least `keep` newer generations of the archive are
    /// published on this host, so the newest is never deleted; and no other generation this host
    /// records names the object. The same checks run again for a deletion already written down,
    /// which is asked for again after an unanswered request.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when `keep` is below the least a host keeps,
    /// the generation is not one that was published, or fewer than `keep` newer generations are;
    /// [`ControllerError::Refused`] when privacy mode, the setup, the writer, an open attempt or
    /// another generation stands in the way; and [`ControllerError::RegistryUnavailable`] when the
    /// store refuses the write.
    pub fn note_retained_deletion_asked(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
        keep: u64,
        now_ms: TimestampMs,
    ) -> Result<()> {
        if keep < LEAST_KEPT {
            return Err(ControllerError::InvalidArgument(format!(
                "a host keeps at least {LEAST_KEPT} published generations of an archive"
            )));
        }
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
        let object = object_id.get().as_bytes().to_vec();
        let refuse = |detail: String| ControllerError::Refused {
            code: ErrorCode::PermissionDenied,
            detail,
        };
        let transaction = self
            .connection
            .writing()
            .map_err(ControllerError::registry)?;
        if let Some(fenced) = inhibited_at(&transaction)? {
            return Err(refuse(format!(
                "no backup object is deleted while privacy mode holds, fenced at privacy \
                 generation {fenced}"
            )));
        }
        let row: Option<(String, String, i64)> = transaction
            .read_one(
                sql!(
                    "SELECT production, remote, privacy_generation FROM generations
                  WHERE archive_id = ?1 AND backup_generation = ?2"
                ),
                params![archive, generation],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(ControllerError::registry)?;
        let Some((production, remote, admitted_under)) = row else {
            return Err(ControllerError::InvalidArgument(
                "that backup generation is not one this host admitted".to_owned(),
            ));
        };
        if admitted_under != current_generation(&transaction)? {
            return Err(refuse(
                "that generation belongs to work privacy mode drew its line under, whose objects \
                 go only by the person's own action"
                    .to_owned(),
            ));
        }
        let setup: i64 = transaction
            .read_one(sql!("SELECT COUNT(*) FROM host_backup"), [], |row| {
                row.get(0)
            })
            .map_err(ControllerError::registry)?;
        if setup == 0 {
            return Err(refuse(
                "this host has no setup, and retention deletes nothing without one".to_owned(),
            ));
        }
        if let Some(refusal) = standing_refusal(&transaction, &archive, generation, true)? {
            return Err(refuse(refusal));
        }
        if remote != "published" || !matches!(production.as_str(), "complete" | "cancelled") {
            return Err(ControllerError::InvalidArgument(
                "only an object of a published backup generation whose production is over is \
                 deleted by retention"
                    .to_owned(),
            ));
        }
        let open: i64 = transaction
            .read_one(
                sql!(
                    "SELECT (SELECT COUNT(*) FROM outbox
                              WHERE archive_id = ?1 AND backup_generation = ?2
                                AND status <> 'terminal')
                          + (SELECT COUNT(*) FROM uploads
                              WHERE archive_id = ?1 AND backup_generation = ?2)"
                ),
                params![archive, generation],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if open > 0 {
            return Err(refuse(
                "an attempt or an upload of that generation is still open".to_owned(),
            ));
        }
        // A newer generation whose every object is being deleted is not one the host keeps, so it
        // does not stand between this one and the floor.
        let newer: i64 = transaction
            .read_one(
                sql!(concat!(
                    "SELECT COUNT(*) FROM generations
                  WHERE archive_id = ?1 AND backup_generation > ?2 AND remote = 'published'
                    AND NOT ",
                    being_deleted!()
                )),
                params![archive, generation],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if u64::try_from(newer).unwrap_or(0) < keep {
            return Err(ControllerError::InvalidArgument(format!(
                "fewer than {keep} newer generations of that archive are published, so this one \
                 is kept"
            )));
        }
        let named: i64 = transaction
            .read_one(
                sql!(
                    "SELECT COUNT(*) FROM objects
                  WHERE archive_id = ?1 AND object_id = ?2 AND backup_generation <> ?3"
                ),
                params![archive, object, generation],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if named > 0 {
            return Err(refuse(
                "another backup generation this host records names that object".to_owned(),
            ));
        }
        let asked: i64 = transaction
            .read_one(
                sql!(
                    "SELECT COUNT(*) FROM releases
                  WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3"
                ),
                params![archive, generation, object],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if asked > 0 {
            return Ok(());
        }
        transaction
            .run(
                sql!(
                    "INSERT INTO releases
                     (archive_id, backup_generation, object_id, asked_at_ms, released_at_ms)
                 VALUES (?1, ?2, ?3, ?4, NULL)"
                ),
                params![archive, generation, object, millis(now_ms)],
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Why the person may not ask the service to delete a generation's objects, or nothing when they
    /// may. Privacy mode is not a reason; the store's own rules for a person's deletion are.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the store cannot be read.
    pub fn deletion_refusal(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
    ) -> Result<Option<String>> {
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
        person_refusal(&self.connection, &archive, generation)
    }

    /// Writes down, in one transaction, that this host will ask the service to delete every object
    /// of a generation, because the person asked for exactly that, before any request leaves. It
    /// returns how many of its objects the service has not yet confirmed deleted.
    ///
    /// It is the person's own action, so it applies none of retention's rules and neither of
    /// privacy mode's: not the fence, and not the line privacy mode drew under a generation, whose
    /// copies are what the action is for. It applies the store's own rules for a person's deletion,
    /// so a generation is refused whole, and every object is written down or none is. An object
    /// already written down is left as it is: asking again after an unanswered request writes
    /// nothing new and still finds the standing intact.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when the setup, the writer, an open attempt, the
    /// generation's state or another generation stands in the way, and
    /// [`ControllerError::RegistryUnavailable`] when the store refuses the write.
    pub fn ask_generation_deletion(
        &mut self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        now_ms: TimestampMs,
    ) -> Result<u64> {
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
        let transaction = self
            .connection
            .writing()
            .map_err(ControllerError::registry)?;
        if let Some(refusal) = person_refusal(&transaction, &archive, generation)? {
            return Err(ControllerError::Refused {
                code: ErrorCode::PermissionDenied,
                detail: refusal,
            });
        }
        transaction
            .run(
                sql!(
                    "INSERT INTO releases
                     (archive_id, backup_generation, object_id, asked_at_ms, released_at_ms)
                 SELECT archive_id, backup_generation, object_id, ?3, NULL FROM objects
                  WHERE archive_id = ?1 AND backup_generation = ?2
                    AND object_id NOT IN (SELECT object_id FROM releases
                                           WHERE archive_id = ?1 AND backup_generation = ?2)"
                ),
                params![archive, generation, millis(now_ms)],
            )
            .map_err(ControllerError::registry)?;
        let unconfirmed: i64 = transaction
            .read_one(
                sql!(
                    "SELECT COUNT(*) FROM releases
                  WHERE archive_id = ?1 AND backup_generation = ?2 AND released_at_ms IS NULL"
                ),
                params![archive, generation],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        transaction.commit().map_err(ControllerError::registry)?;
        Ok(u64::try_from(unconfirmed).unwrap_or(0))
    }

    /// Decides again, before its request leaves, a deletion that is written down: the standing it
    /// was asked under must still hold, as for a retention deletion asked for again.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`] when the standing no longer holds, and
    /// [`ControllerError::InvalidArgument`] when no deletion of that object is written down.
    pub fn confirm_asked_deletion(
        &self,
        archive_id: ArchiveId,
        backup_generation: BackupGeneration,
        object_id: BackupObjectId,
    ) -> Result<()> {
        let archive = archive_id.get().as_bytes().to_vec();
        let generation = i64::try_from(backup_generation.get()).unwrap_or(i64::MAX);
        let object = object_id.get().as_bytes().to_vec();
        if let Some(refusal) = person_refusal(&self.connection, &archive, generation)? {
            return Err(ControllerError::Refused {
                code: ErrorCode::PermissionDenied,
                detail: refusal,
            });
        }
        let asked: i64 = self
            .connection
            .read_one(
                sql!(
                    "SELECT COUNT(*) FROM releases
                  WHERE archive_id = ?1 AND backup_generation = ?2 AND object_id = ?3"
                ),
                params![archive, generation, object],
                |row| row.get(0),
            )
            .map_err(ControllerError::registry)?;
        if asked == 0 {
            return Err(ControllerError::InvalidArgument(
                "no deletion of that object is written down".to_owned(),
            ));
        }
        Ok(())
    }
}
