//! Recording what a restore verified, so the next restore can tell a service that replays an
//! older archive.
//!
//! A signed manifest stops forgery and not a service that hands back an older archive the owner
//! really wrote. What catches that is a checkpoint the owner trusts: the newest generation it
//! verified, in the recovery bundle. The host that makes a bundle holds no seed, so it can write
//! none: the setup runs before any generation exists. A restore holds the kit, and has just
//! verified a generation, so it is where the checkpoint is recorded.
//!
//! [`advance_checkpoint`] is the whole rule, in one place and with nothing to send:
//!
//! * a checkpoint never goes down, so a restore of an older generation that the person accepted
//!   leaves the bundle as it was;
//! * the same generation recorded with another manifest is a disagreement and is refused, because
//!   one of the two is not the archive the owner verified;
//! * everything else the bundle holds (collections, writers, producers, the other archives'
//!   checkpoints) is carried through as it is read, so a write based on a fresh read cannot take a
//!   change that another device made with it.
//!
//! The revision is not moved here. A bundle store commits revision plus one, which is the single
//! place the revision advances.

use kr_protocol::archive::{ArchiveCheckpoint, RecoveryBundle};

use crate::recovery::{RecoveryError, Result};

/// The strongest the restore has read of the bundle, authenticated: its newest revision, and for
/// every archive its highest checkpoint.
///
/// Every read is held to it, and a read that is held raises it to what that read holds, so what one
/// read showed holds every read after it, whether or not a write was made on that read. A service
/// that answers a later read with an older authentic bundle, or one that records a lower checkpoint
/// of any archive than a read before it did, is not recorded into, because writing on it would put
/// back what a newer bundle replaced: a lowered checkpoint, or a writer another device had added.
#[derive(Clone)]
pub(crate) struct Strongest {
    revision: u64,
    checkpoints: Vec<ArchiveCheckpoint>,
}

impl Strongest {
    /// What a restore's first read of the bundle showed: its revision and its checkpoints.
    pub(crate) fn first_read(revision: u64, checkpoints: &[ArchiveCheckpoint]) -> Self {
        Self {
            revision,
            checkpoints: highest_of_each_archive(checkpoints),
        }
    }

    /// Holds `bundle`, a later read, to the strongest read so far, and raises it to `bundle`: it is
    /// not an older revision, and every checkpoint read before is still there, at that generation
    /// or a newer one.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::BundleWentBackToAnOlderRevision`] when `bundle` is an older revision
    /// than one read before, [`RecoveryError::CheckpointWentBack`] when it records an older
    /// generation than one read before for an archive, or none, and
    /// [`RecoveryError::CheckpointDisagrees`] when it records the same generation of an archive
    /// with another encrypted manifest. Nothing is raised then.
    pub(crate) fn hold(&mut self, bundle: &RecoveryBundle) -> Result<()> {
        if bundle.revision.get() < self.revision {
            return Err(RecoveryError::BundleWentBackToAnOlderRevision {
                first: self.revision,
            });
        }
        for known in &self.checkpoints {
            let held = bundle
                .checkpoints
                .iter()
                .filter(|held| held.archive_id == known.archive_id)
                .max_by_key(|held| held.backup_generation);
            match held {
                Some(held) if held.backup_generation > known.backup_generation => {}
                Some(held) if held.backup_generation == known.backup_generation => {
                    if held.encrypted_manifest_hash != known.encrypted_manifest_hash {
                        return Err(RecoveryError::CheckpointDisagrees {
                            generation: known.backup_generation.get(),
                        });
                    }
                }
                _ => {
                    return Err(RecoveryError::CheckpointWentBack {
                        known: known.backup_generation.get(),
                    });
                }
            }
        }
        // Every checkpoint read before is in `bundle` at that generation or a newer one, so what
        // `bundle` holds is at least as strong, and replaces it.
        self.revision = bundle.revision.get();
        self.checkpoints = highest_of_each_archive(bundle.checkpoints.iter());
        Ok(())
    }
}

/// The checkpoint held for each archive that has one, at its highest generation.
fn highest_of_each_archive<'a>(
    held: impl IntoIterator<Item = &'a ArchiveCheckpoint>,
) -> Vec<ArchiveCheckpoint> {
    let mut highest: Vec<ArchiveCheckpoint> = Vec::new();
    for held in held {
        match highest
            .iter_mut()
            .find(|known| known.archive_id == held.archive_id)
        {
            Some(known) if known.backup_generation < held.backup_generation => {
                *known = held.clone();
            }
            Some(_) => {}
            None => highest.push(held.clone()),
        }
    }
    highest
}

/// The bundle that records `verified`, or nothing when the bundle already records it or a newer
/// generation of the same archive.
///
/// # Errors
///
/// Returns [`RecoveryError::CheckpointDisagrees`] when the bundle records the very generation
/// `verified` names with another encrypted manifest.
pub fn advance_checkpoint(
    bundle: &RecoveryBundle,
    verified: &ArchiveCheckpoint,
) -> Result<Option<RecoveryBundle>> {
    let held = bundle
        .checkpoints
        .iter()
        .filter(|held| held.archive_id == verified.archive_id)
        .max_by_key(|held| held.backup_generation);
    if let Some(held) = held {
        if held.backup_generation == verified.backup_generation {
            return if held.encrypted_manifest_hash == verified.encrypted_manifest_hash {
                Ok(None)
            } else {
                Err(RecoveryError::CheckpointDisagrees {
                    generation: verified.backup_generation.get(),
                })
            };
        }
        if held.backup_generation > verified.backup_generation {
            return Ok(None);
        }
    }
    let mut advanced = bundle.clone();
    advanced.checkpoints = bundle
        .checkpoints
        .iter()
        .filter(|held| held.archive_id != verified.archive_id)
        .cloned()
        .chain(std::iter::once(verified.clone()))
        .collect();
    Ok(Some(advanced))
}
