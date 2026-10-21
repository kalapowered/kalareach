//! The trusted latest-generation checkpoint, and what a restore can honestly say about it.
//!
//! A signed manifest stops forgery. It does not stop a service handing back an older archive the
//! owner really did write, because that archive's signature is genuine. What catches that is a
//! checkpoint the owner trusts: the latest generation it verified, and the hash of that
//! generation's encrypted manifest.
//!
//! The checkpoint a restore compares against is the one the owner's recovery bundle holds. It does
//! not prove that no newer archive exists, and [`RestoreGeneration::describe`] says so rather than
//! leaving a person to assume otherwise.

use kr_protocol::archive::{ArchiveCheckpoint, ArchiveDescriptor};
use kr_protocol::ids::{ArchiveId, BackupGeneration};

/// What a restore compares the generation it is offered against.
///
/// Two different questions, and they have different answers, so they are two cases rather than an
/// optional checkpoint and a flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationExpectation<'a> {
    /// Nothing to compare against. The recovery-only case: the restore goes ahead and proves
    /// nothing about what else might exist.
    Unverified,
    /// The latest generation the owner verified. A generation at or after it is admitted; one
    /// before it is a replay, and one that claims it with another manifest is a substitution.
    Checkpoint(&'a ArchiveCheckpoint),
}

/// Where one archive stands against the checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationStanding {
    /// It is the generation the checkpoint names, and its encrypted manifest is the one the
    /// checkpoint hashed.
    AtCheckpoint,
    /// It is newer than the checkpoint: the owner has written generations since it was taken.
    Ahead {
        /// The generation the checkpoint names.
        checkpoint: BackupGeneration,
    },
    /// It is older than the checkpoint, which is a service replaying an older valid backup.
    Replayed {
        /// The generation the checkpoint names.
        checkpoint: BackupGeneration,
    },
    /// It claims the checkpoint's generation with a different encrypted manifest.
    Substituted {
        /// The generation the checkpoint names.
        checkpoint: BackupGeneration,
    },
    /// The checkpoint is for another archive, so it says nothing about this one.
    OtherArchive {
        /// The archive the checkpoint is for.
        checkpoint_archive: ArchiveId,
    },
    /// There is no checkpoint for this archive at all.
    NoCheckpoint,
}

/// What a restore displays about the generation it is restoring.
///
/// It is built for every restore, admissible or not, because section 20 requires the generation to
/// be displayed either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RestoreGeneration {
    /// The archive being restored.
    pub archive_id: ArchiveId,
    /// The generation the descriptor names.
    pub backup_generation: BackupGeneration,
    /// Where it stands against the checkpoint.
    pub standing: GenerationStanding,
}

impl RestoreGeneration {
    /// Compares one descriptor against the checkpoint the owner trusts, if there is one.
    #[must_use]
    pub fn against(descriptor: &ArchiveDescriptor, expectation: GenerationExpectation<'_>) -> Self {
        let standing = match expectation {
            GenerationExpectation::Unverified => GenerationStanding::NoCheckpoint,
            GenerationExpectation::Checkpoint(checkpoint)
                if checkpoint.archive_id != descriptor.archive_id =>
            {
                GenerationStanding::OtherArchive {
                    checkpoint_archive: checkpoint.archive_id,
                }
            }
            GenerationExpectation::Checkpoint(checkpoint) => {
                let trusted = checkpoint.backup_generation.get();
                let offered = descriptor.backup_generation.get();
                if offered < trusted {
                    GenerationStanding::Replayed {
                        checkpoint: checkpoint.backup_generation,
                    }
                } else if offered > trusted {
                    GenerationStanding::Ahead {
                        checkpoint: checkpoint.backup_generation,
                    }
                } else if checkpoint.encrypted_manifest_hash
                    == descriptor.encrypted_manifest.encrypted_object_hash
                {
                    GenerationStanding::AtCheckpoint
                } else {
                    GenerationStanding::Substituted {
                        checkpoint: checkpoint.backup_generation,
                    }
                }
            }
        };
        Self {
            archive_id: descriptor.archive_id,
            backup_generation: descriptor.backup_generation,
            standing,
        }
    }

    /// Whether this restore may go ahead.
    ///
    /// Three refusals. A generation behind the checkpoint is a service replaying an older archive.
    /// One that claims the checkpoint's generation with another manifest is a substitution. And a
    /// checkpoint that is for another archive means the caller held an expectation and was handed
    /// a different collection: *no* checkpoint is the recovery-only case and goes ahead, but the
    /// wrong one is a mismatch rather than an absence.
    #[must_use]
    pub const fn is_admissible(&self) -> bool {
        !matches!(
            self.standing,
            GenerationStanding::Replayed { .. }
                | GenerationStanding::Substituted { .. }
                | GenerationStanding::OtherArchive { .. }
        )
    }

    /// Whether a checkpoint for this archive was available to compare against.
    #[must_use]
    pub const fn checkpoint_available(&self) -> bool {
        !matches!(
            self.standing,
            GenerationStanding::NoCheckpoint | GenerationStanding::OtherArchive { .. }
        )
    }

    /// Always false, whatever the checkpoint says.
    ///
    /// A checkpoint records the newest generation the owner has *seen*. A service holding a newer
    /// archive back looks exactly like an owner who has not written one, so no restore can claim
    /// that no newer valid archive exists. Section 20 requires that limitation to be carried
    /// rather than quietly dropped, so it is a method rather than a comment.
    #[must_use]
    pub const fn proves_no_newer_archive(&self) -> bool {
        false
    }

    /// The sentence a restore displays. It always names the generation.
    #[must_use]
    pub fn describe(&self) -> String {
        let generation = self.backup_generation.get();
        let standing = match self.standing {
            GenerationStanding::AtCheckpoint => {
                "It is the generation the recovery bundle last verified.".to_owned()
            }
            GenerationStanding::Ahead { checkpoint } => format!(
                "It is newer than generation {} that the recovery bundle last verified.",
                checkpoint.get()
            ),
            GenerationStanding::Replayed { checkpoint } => format!(
                "It is older than generation {} that the recovery bundle verified, so it is not \
                 being restored.",
                checkpoint.get()
            ),
            GenerationStanding::Substituted { checkpoint } => format!(
                "It claims generation {} but is not the archive the recovery bundle verified, so \
                 it is not being restored.",
                checkpoint.get()
            ),
            GenerationStanding::OtherArchive { .. } => {
                "The verified generation supplied is for a different archive, so this is not the \
                 backup that was asked for and it is not being restored."
                    .to_owned()
            }
            GenerationStanding::NoCheckpoint => {
                "There is no verified generation to compare it with.".to_owned()
            }
        };
        // A generation that is refused is not being restored, so it is not introduced as if it were.
        let lead = if self.is_admissible() {
            "Restoring backup generation"
        } else {
            "The service offered backup generation"
        };
        format!(
            "{lead} {generation}. {standing} No restore can show that the service is not holding \
             a newer backup back."
        )
    }
}
