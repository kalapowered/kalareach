//! The trusted latest-generation checkpoint, and what a restore can honestly say about it.
//!
//! A signed manifest stops forgery. It does not stop a service handing back an older archive the
//! owner really did write, because that archive's signature is genuine. What catches that is a
//! checkpoint the owner trusts: the latest generation it verified, and the hash of that
//! generation's encrypted manifest.
//!
//! Where the checkpoint comes from is part of the answer, so it travels with it. Another of the
//! owner's devices transfers one when the two pair; a restore that has only the recovery kit reads
//! one out of the authenticated bundle. Neither proves that no newer archive exists, and
//! [`RestoreGeneration::describe`] says so rather than leaving a person to assume otherwise.

use kr_protocol::archive::{ArchiveCheckpoint, ArchiveDescriptor};
use kr_protocol::ids::{ArchiveId, BackupGeneration};

/// Where the checkpoint a restore compares against came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CheckpointSource {
    /// Another of the owner's devices, transferred when the two paired.
    Pairing,
    /// The owner's recovery bundle, authenticated with the recovery kit.
    RecoveryBundle,
}

impl CheckpointSource {
    /// Returns the stable name a report uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pairing => "a paired device",
            Self::RecoveryBundle => "the recovery bundle",
        }
    }
}

/// What a restore compares the generation it is offered against.
///
/// Three different questions, and they have different answers, so they are three cases rather than
/// an optional checkpoint and a flag. A restore that was authorised for one exact generation is
/// not asking whether the archive is recent; it is asking whether this is the archive whose
/// authority was established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationExpectation<'a> {
    /// Nothing to compare against. The recovery-only case: the restore goes ahead and proves
    /// nothing about what else might exist.
    Unverified,
    /// The latest generation the owner verified. A generation at or after it is admitted; one
    /// before it is a replay, and one that claims it with another manifest is a substitution.
    Checkpoint(CheckpointSource, &'a ArchiveCheckpoint),
    /// Exactly this generation, with exactly this encrypted manifest. Anything else is refused,
    /// however genuine: a caller that pins has already established the authority of one archive,
    /// and a second one is not it.
    Exactly(&'a ArchiveCheckpoint),
}

/// Where one archive stands against the checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenerationStanding {
    /// It is the generation the checkpoint names, and its encrypted manifest is the one the
    /// checkpoint hashed.
    AtCheckpoint {
        /// Where the checkpoint came from.
        source: CheckpointSource,
    },
    /// It is newer than the checkpoint: the owner has written generations since it was taken.
    Ahead {
        /// Where the checkpoint came from.
        source: CheckpointSource,
        /// The generation the checkpoint names.
        checkpoint: BackupGeneration,
    },
    /// It is older than the checkpoint, which is a service replaying an older valid backup.
    Replayed {
        /// Where the checkpoint came from.
        source: CheckpointSource,
        /// The generation the checkpoint names.
        checkpoint: BackupGeneration,
    },
    /// It claims the checkpoint's generation with a different encrypted manifest.
    Substituted {
        /// Where the checkpoint came from.
        source: CheckpointSource,
        /// The generation the checkpoint names.
        checkpoint: BackupGeneration,
    },
    /// The checkpoint is for another archive, so it says nothing about this one.
    OtherArchive {
        /// The archive the checkpoint is for.
        checkpoint_archive: ArchiveId,
    },
    /// It is not the exact generation this restore was authorised for.
    NotThePinnedGeneration {
        /// The generation the restore was authorised for.
        pinned: BackupGeneration,
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
            GenerationExpectation::Exactly(pinned) => {
                if pinned.archive_id != descriptor.archive_id {
                    GenerationStanding::OtherArchive {
                        checkpoint_archive: pinned.archive_id,
                    }
                } else if pinned.backup_generation == descriptor.backup_generation
                    && pinned.encrypted_manifest_hash
                        == descriptor.encrypted_manifest.encrypted_object_hash
                {
                    GenerationStanding::AtCheckpoint {
                        source: CheckpointSource::Pairing,
                    }
                } else {
                    GenerationStanding::NotThePinnedGeneration {
                        pinned: pinned.backup_generation,
                    }
                }
            }
            GenerationExpectation::Checkpoint(_, checkpoint)
                if checkpoint.archive_id != descriptor.archive_id =>
            {
                GenerationStanding::OtherArchive {
                    checkpoint_archive: checkpoint.archive_id,
                }
            }
            GenerationExpectation::Checkpoint(source, checkpoint) => {
                let trusted = checkpoint.backup_generation.get();
                let offered = descriptor.backup_generation.get();
                if offered < trusted {
                    GenerationStanding::Replayed {
                        source,
                        checkpoint: checkpoint.backup_generation,
                    }
                } else if offered > trusted {
                    GenerationStanding::Ahead {
                        source,
                        checkpoint: checkpoint.backup_generation,
                    }
                } else if checkpoint.encrypted_manifest_hash
                    == descriptor.encrypted_manifest.encrypted_object_hash
                {
                    GenerationStanding::AtCheckpoint { source }
                } else {
                    GenerationStanding::Substituted {
                        source,
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
                | GenerationStanding::NotThePinnedGeneration { .. }
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
            GenerationStanding::AtCheckpoint { source } => {
                format!("It is the generation {} last verified.", source.as_str())
            }
            GenerationStanding::Ahead { source, checkpoint } => format!(
                "It is newer than generation {} that {} last verified.",
                checkpoint.get(),
                source.as_str()
            ),
            GenerationStanding::Replayed { source, checkpoint } => format!(
                "It is older than generation {} that {} verified, so it is not being restored.",
                checkpoint.get(),
                source.as_str()
            ),
            GenerationStanding::Substituted { source, checkpoint } => format!(
                "It claims generation {} but is not the archive {} verified, so it is not being \
                 restored.",
                checkpoint.get(),
                source.as_str()
            ),
            GenerationStanding::OtherArchive { .. } => {
                "The verified generation supplied is for a different archive, so this is not the \
                 backup that was asked for and it is not being restored."
                    .to_owned()
            }
            GenerationStanding::NotThePinnedGeneration { pinned } => format!(
                "This restore was authorised for generation {}, and this is not it, so it is not \
                 being restored.",
                pinned.get()
            ),
            GenerationStanding::NoCheckpoint => {
                "There is no verified generation to compare it with.".to_owned()
            }
        };
        format!(
            "Restoring backup generation {generation}. {standing} No restore can show that the \
             service is not holding a newer backup back."
        )
    }
}
