//! `backup.read`: reading what the managed storage service holds, for a restore.
//!
//! A restore runs in the `kr` process: it holds the recovery kit, opens the archive and writes the
//! files. The control daemon holds the account this host is signed in with, so it is the one that
//! reaches the service, and it does so as a relay of ciphertext and public records. It never sees
//! the seed, a plaintext, a file name or the directory a restore writes to. What it does see is
//! what the service holds already: the archive and object identifiers a read names, the bundle's
//! locator, and the checkpoint a generation read is held to.
//!
//! The method is served on the local socket alone and asks for host management. It answers one
//! read at a time, and each read is idempotent, so one whose answer was lost is asked again:
//!
//! * `service` says which service this host is configured for and whether it holds an account
//!   token a read may carry, and why not when it does not.
//! * `bundle` reads the recovery bundle at a locator, as the service answered it.
//! * `generation` reads the newest generation published for an archive, held to a checkpoint.
//! * `object` reads one range of a stored object.
//!
//! While privacy mode is on the daemon answers none of the last three, and an answer read under a
//! privacy state that has changed by the time it is given is not given.
//!
//! When the service asks to be left alone, the daemon answers [`BackupReadResult::Wait`] with what
//! is left of the delay, and sends nothing until it has passed. The same record holds the
//! carrier of the host's own backups, so a restore and an upload cannot both press on a service
//! that asked for quiet.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::archive::{ArchiveCheckpoint, BackupGenerationPublication};
use crate::ids::{ArchiveId, BackupObjectId};
use crate::scalars::{Bytes, Nullable, U64, Uuid};

/// The most ciphertext one `object` read asks for: it and its framing fit one control frame.
pub const BACKUP_READ_MAX_RANGE_BYTES: u64 = 512 * 1024;

/// The most ciphertext a `bundle` answer carries. A bundle larger than a control frame is refused
/// by name rather than cut.
pub const BACKUP_READ_MAX_BUNDLE_BYTES: usize = 896 * 1024;

/// Parameters of `backup.read`: exactly one read.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "read", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupReadParams {
    /// Which service this host is configured for, and whether a read may be sent.
    Service {},
    /// The recovery bundle at a locator.
    Bundle {
        /// The locator the recovery kit prints.
        locator: Uuid,
    },
    /// The newest generation published for an archive.
    Generation {
        /// The archive.
        archive_id: ArchiveId,
        /// The checkpoint the caller holds for it, from the authenticated bundle. A service that
        /// holds nothing as new answers that rather than an older generation.
        checkpoint: Nullable<ArchiveCheckpoint>,
    },
    /// One range of a stored object.
    Object {
        /// The archive the object belongs to.
        archive_id: ArchiveId,
        /// The object.
        object_id: BackupObjectId,
        /// Where the range starts.
        offset: U64,
        /// How long it is, at most [`BACKUP_READ_MAX_RANGE_BYTES`].
        length: U64,
    },
}

impl fmt::Debug for BackupReadParams {
    /// Which read it is, and the identifiers it names. Never the locator, which is what reaches
    /// the bundle.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service {} => formatter.write_str("Service"),
            Self::Bundle { .. } => formatter.write_str("Bundle { .. }"),
            Self::Generation { archive_id, .. } => formatter
                .debug_struct("Generation")
                .field("archive_id", archive_id)
                .finish_non_exhaustive(),
            Self::Object {
                archive_id,
                object_id,
                offset,
                length,
            } => formatter
                .debug_struct("Object")
                .field("archive_id", archive_id)
                .field("object_id", object_id)
                .field("offset", offset)
                .field("length", length)
                .finish(),
        }
    }
}

/// Why this host holds no account token a read may carry, or that it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackupSignIn {
    /// A token is usable now.
    Usable,
    /// No account is signed in on this host.
    SignedOut,
    /// A sign-in on this host is waiting for the person's browser.
    Waiting,
    /// The service ended the sign-in on this host.
    Ended,
    /// The account is signed in and its grant lacks the scope backup storage needs.
    WithoutScope,
    /// The sign-in looks whole and no token could be had from it just now.
    NotRenewed,
}

/// The recovery bundle at a locator, as the service answered it.
///
/// The two answers are kept apart because they mean different things to a restore: a bundle that is
/// held is ciphertext to authenticate, and one that is not is a locator nobody wrote, written
/// wrongly, or read by an account that does not own it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupBundle {
    /// The service holds a bundle at the locator.
    Held {
        /// This write's place in the collection's order. The first is one.
        write_sequence: U64,
        /// The name the service gave this write, or null where the write was a removal.
        revision: Nullable<Uuid>,
        /// The history the place is in: the recovery the answer named, or null for a service never
        /// put back.
        recovery: Nullable<Uuid>,
        /// The sealed bundle, which only the recovery seed opens.
        ciphertext: Bytes,
    },
    /// The service holds none there.
    Absent {
        /// The history that holds none.
        recovery: Nullable<Uuid>,
    },
}

impl fmt::Debug for BackupBundle {
    /// Where the bundle stands, and never what it holds.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Held { write_sequence, .. } => formatter
                .debug_struct("Held")
                .field("write_sequence", write_sequence)
                .finish_non_exhaustive(),
            Self::Absent { .. } => formatter.debug_struct("Absent").finish_non_exhaustive(),
        }
    }
}

/// What `backup.read` answers: the read asked for, or a wait.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "read", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupReadResult {
    /// The answer to `service`.
    Service {
        /// The storage origin this host is configured for.
        origin: String,
        /// Whether a read may be sent.
        sign_in: BackupSignIn,
    },
    /// The answer to `bundle`.
    Bundle {
        /// The bundle, or its absence.
        bundle: BackupBundle,
    },
    /// The answer to `generation`.
    Generation {
        /// The newest generation the service holds as new as the checkpoint asked for, or null when
        /// it holds none. Null is an answer, kept apart from a failure.
        publication: Nullable<BackupGenerationPublication>,
    },
    /// The answer to `object`.
    Object {
        /// The ciphertext of the range asked for, shorter than asked only at the end of the
        /// object.
        bytes: Bytes,
    },
    /// The service asked to be left alone, and nothing was sent: ask again after this long.
    ///
    /// The delay is what is left of one the service named, and no longer than an hour.
    Wait {
        /// Seconds until the service may be asked again.
        retry_after_seconds: U64,
    },
}

impl fmt::Debug for BackupReadResult {
    /// Which read answered, and nothing the service held.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service { sign_in, .. } => formatter
                .debug_struct("Service")
                .field("sign_in", sign_in)
                .finish_non_exhaustive(),
            Self::Bundle { bundle } => formatter
                .debug_struct("Bundle")
                .field("bundle", bundle)
                .finish(),
            Self::Generation { .. } => formatter.write_str("Generation { .. }"),
            Self::Object { bytes } => formatter
                .debug_struct("Object")
                .field("length", &bytes.len())
                .finish(),
            Self::Wait {
                retry_after_seconds,
            } => formatter
                .debug_struct("Wait")
                .field("retry_after_seconds", retry_after_seconds)
                .finish(),
        }
    }
}
