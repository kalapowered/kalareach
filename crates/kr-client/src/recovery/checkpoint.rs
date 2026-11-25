//! Recording what a restore verified, so the next restore can tell a service that replays an
//! older archive.
//!
//! A signed manifest stops forgery and not a service that hands back an older archive the owner
//! really wrote. What catches that is a checkpoint the owner trusts: the newest generation it
//! verified, in the recovery bundle. The host that makes a bundle holds no seed, so it can write
//! none: the setup runs before any generation exists. A restore holds the kit, and has just
//! verified a generation, so it is where the checkpoint is recorded.
//!
//! [`advance_checkpoint`] is the whole rule, in one place and with nothing to send, and [`Standing`]
//! is the comparison it makes:
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
use kr_protocol::ids::BackupGeneration;
use kr_protocol::scalars::Digest256;

use crate::recovery::{RecoveryError, Result};

/// How a verified checkpoint stands against the highest one held for the same archive.
///
/// This is the one comparison every holder of checkpoints makes, so that none of them reads a
/// generation or a manifest its own way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Standing {
    /// Nothing is held for the archive, or the verified generation is newer than the one held.
    Raises,
    /// The verified generation is the one held, with the same manifest.
    Same,
    /// The verified generation is older than the one held.
    Lower,
    /// The verified generation is the one held, with another manifest.
    Disagrees,
}

impl Standing {
    /// How `verified` stands against `held`, the generation and manifest hash of the highest
    /// checkpoint held for the archive, if one is held.
    pub(crate) fn of(
        held: Option<(BackupGeneration, &Digest256)>,
        verified: (BackupGeneration, &Digest256),
    ) -> Self {
        let Some((held_generation, held_hash)) = held else {
            return Self::Raises;
        };
        let (generation, hash) = verified;
        if generation > held_generation {
            Self::Raises
        } else if generation < held_generation {
            Self::Lower
        } else if hash == held_hash {
            Self::Same
        } else {
            Self::Disagrees
        }
    }
}

/// The strongest the restore has read of the bundle, authenticated: its newest revision, and for
/// every archive its highest checkpoint.
///
/// Every read is held to it, and a read that is held raises it to what that read holds, so what one
/// read showed holds every read after it, whether or not a write was made on that read. A service
/// that answers a later read with an older authentic bundle, or one that records a lower checkpoint
/// of any archive than a read before it did, is not recorded into, because writing on it would lower
/// a checkpoint that a newer bundle raised, or drop a writer that another device added.
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
            checkpoints: checkpoints.to_vec(),
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
                newest: self.revision,
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
        // For every checkpoint read before, `bundle` holds its archive at that generation or a
        // newer one, so `bundle` is at least as strong and replaces the floor. It keeps every entry
        // `bundle` holds, not one per archive, so that two manifests recorded for one generation
        // both stay known, and a later read that agrees with only one of them is refused.
        self.revision = bundle.revision.get();
        self.checkpoints = bundle.checkpoints.iter().cloned().collect();
        Ok(())
    }
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
    match Standing::of(
        held.map(|held| (held.backup_generation, &held.encrypted_manifest_hash)),
        (
            verified.backup_generation,
            &verified.encrypted_manifest_hash,
        ),
    ) {
        Standing::Same | Standing::Lower => return Ok(None),
        Standing::Disagrees => {
            return Err(RecoveryError::CheckpointDisagrees {
                generation: verified.backup_generation.get(),
            });
        }
        Standing::Raises => {}
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A verified checkpoint stands as raising, the same, lower or disagreeing, whichever way the
    /// held one is set against it.
    #[test]
    fn a_verified_checkpoint_stands_by_its_generation_and_its_manifest() {
        let generation = BackupGeneration::new;
        let one = Digest256::from_bytes([1; 32]);
        let other = Digest256::from_bytes([2; 32]);

        assert_eq!(
            Standing::of(None, (generation(1), &one)),
            Standing::Raises,
            "nothing is held"
        );
        assert_eq!(
            Standing::of(Some((generation(4), &one)), (generation(5), &other)),
            Standing::Raises,
            "a newer generation raises, whatever its manifest"
        );
        assert_eq!(
            Standing::of(Some((generation(5), &one)), (generation(5), &one)),
            Standing::Same,
            "the same generation with the same manifest"
        );
        assert_eq!(
            Standing::of(Some((generation(5), &one)), (generation(5), &other)),
            Standing::Disagrees,
            "the same generation with another manifest"
        );
        assert_eq!(
            Standing::of(Some((generation(6), &one)), (generation(5), &other)),
            Standing::Lower,
            "an older generation is lower, whatever its manifest"
        );
    }
}
