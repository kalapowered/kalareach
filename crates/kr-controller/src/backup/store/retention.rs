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
        let newer: i64 = transaction
            .read_one(
                sql!(
                    "SELECT COUNT(*) FROM generations
                  WHERE archive_id = ?1 AND backup_generation > ?2 AND remote = 'published'"
                ),
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
}
