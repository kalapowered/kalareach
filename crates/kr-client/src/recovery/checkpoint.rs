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

/// Holds a bundle read later to the bundle this restore read first: it is not an older revision, and
/// every checkpoint the first read found is still there, at that generation or a newer one. A
/// service that answers a later read with an older authentic bundle is not recorded into, because
/// writing on it would lower a checkpoint it replaced, whichever archive's it was.
///
/// # Errors
///
/// Returns [`RecoveryError::CheckpointWentBack`] when `bundle` is an older revision than
/// `first_revision`, or records an older generation than one of `known` for an archive, or none;
/// and [`RecoveryError::CheckpointDisagrees`] when it records the same generation of an archive
/// with another encrypted manifest.
pub(crate) fn hold_to_the_first_read(
    bundle: &RecoveryBundle,
    first_revision: u64,
    known: &[ArchiveCheckpoint],
) -> Result<()> {
    if bundle.revision.get() < first_revision {
        return Err(RecoveryError::BundleWentBackToAnOlderRevision {
            first: first_revision,
        });
    }
    for known in known {
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
    Ok(())
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
