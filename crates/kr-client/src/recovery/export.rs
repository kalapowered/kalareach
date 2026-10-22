//! The offline export: a copy of the recovery bundle and of one archive, kept where the service is
//! not, and read back with the kit alone.
//!
//! Everything in an export is already encrypted. The bundle is the sealed bundle exactly as the
//! service holds it; the archive is the newest publication the service holds, the encrypted
//! manifest it names and every object that manifest names, each checked against the hash the signed
//! manifest gives. Nothing decrypted is written, and no key or kit text is in the file, so the
//! export adds no protection of its own and claims none: it exists so an owner can keep a copy
//! somewhere the service is not.
//!
//! The reader is [`ExportSource`], a [`RestoreSource`] over the file. A restore from it is the
//! restore from a service with every check unchanged: the kit's checksum, the bundle's
//! authentication under the key the kit and the origin derive, the writers and the producer the
//! bundle names, the publication's signature and the manifest's. A file that does not authenticate
//! under the kit restores nothing.

use kr_protocol::archive::{ArchiveCheckpoint, BackupGenerationPublication};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ArchiveId, BackupObjectId};
use kr_protocol::scalars::{Bytes, Nullable, Uuid};
use serde::{Deserialize, Serialize};

use crate::error::ClientError;
use crate::recovery::{RecoveryError, Result};
use crate::recovery::{RestoreSource, SourceService, SourceSignIn};
use crate::services::{ServiceFuture, SyncFetched, SyncPosition, SyncRevision};
use crate::shown::Shown;

/// The format line of an offline export. A reader refuses any other.
pub const OFFLINE_EXPORT_FORMAT: &str = "kalareach-offline-export/1";

/// The most ciphertext one export of an archive holds, in bytes. An archive over it is restored
/// from the service, not from a file: an export is read whole into memory.
pub const MAX_EXPORT_BYTES: u64 = 256 * 1024 * 1024;

/// One object of an exported archive, as the service stores it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportedObject {
    /// The object's identifier.
    pub object_id: BackupObjectId,
    /// The object's encrypted bytes.
    pub bytes: Bytes,
}

/// One archive in an export: the publication a restore starts from, and the ciphertext it names.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportedArchive {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The newest publication the service held, as the writer signed it.
    pub publication: BackupGenerationPublication,
    /// The encrypted manifest the publication names.
    pub encrypted_manifest: Bytes,
    /// Every member object the manifest names.
    pub objects: Vec<ExportedObject>,
}

/// One offline export: the sealed recovery bundle, and at most one archive's ciphertext.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineExport {
    /// [`OFFLINE_EXPORT_FORMAT`].
    pub format: String,
    /// The service the bundle was read at, as the kit spells it.
    pub service_origin: String,
    /// The sealed recovery bundle, as the service holds it.
    pub encrypted_bundle: Bytes,
    /// The archive, or null for an export of the bundle alone.
    pub archive: Nullable<ExportedArchive>,
}

crate::debug_as_name!(OfflineExport);

impl OfflineExport {
    /// An export of `encrypted_bundle` read at `service_origin`, with `archive` beside it.
    #[must_use]
    pub fn new(
        service_origin: String,
        encrypted_bundle: Vec<u8>,
        archive: Option<ExportedArchive>,
    ) -> Self {
        Self {
            format: OFFLINE_EXPORT_FORMAT.to_owned(),
            service_origin,
            encrypted_bundle: Bytes::new(encrypted_bundle),
            archive: Nullable(archive),
        }
    }

    /// Encodes this export into its canonical KR-CBOR-1 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Cbor`] when the export cannot be encoded.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let limits = kr_cbor::Limits {
            max_message_len: usize::try_from(MAX_EXPORT_BYTES.saturating_mul(2))
                .unwrap_or(usize::MAX),
            max_bytes_len: usize::try_from(MAX_EXPORT_BYTES).unwrap_or(usize::MAX),
            max_collection_len: 65_536,
            max_items: 1_000_000,
            ..kr_cbor::Limits::DEFAULT
        };
        Ok(kr_cbor::to_canonical_vec_within(self, &limits)?)
    }

    /// Decodes an export from its canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Cbor`] when the bytes are not an export, and
    /// [`RecoveryError::UnsupportedExport`] when they are one in another format than this release
    /// reads.
    pub fn from_canonical_slice(bytes: &[u8]) -> Result<Self> {
        let limits = kr_cbor::Limits {
            max_message_len: bytes.len().max(kr_cbor::Limits::DEFAULT.max_message_len),
            max_bytes_len: bytes.len().max(kr_cbor::Limits::DEFAULT.max_bytes_len),
            max_collection_len: 65_536,
            max_items: 1_000_000,
            ..kr_cbor::Limits::DEFAULT
        };
        let export: Self = kr_cbor::from_canonical_slice(bytes, &limits)?;
        if export.format != OFFLINE_EXPORT_FORMAT {
            return Err(RecoveryError::UnsupportedExport);
        }
        Ok(export)
    }
}

/// A restore source that reads from an export and from nothing else: no service, no sign-in.
#[derive(Debug)]
pub struct ExportSource {
    export: OfflineExport,
}

impl ExportSource {
    /// A source over `export`.
    #[must_use]
    pub const fn new(export: OfflineExport) -> Self {
        Self { export }
    }
}

fn not_in_the_export() -> ClientError {
    ClientError::refusal(
        ErrorCode::InvalidArgument,
        Shown::said("that is not in the export file"),
    )
}

impl RestoreSource for ExportSource {
    fn service(&self) -> ServiceFuture<'_, SourceService> {
        Box::pin(async move {
            Ok(SourceService {
                origin: self.export.service_origin.clone(),
                sign_in: SourceSignIn::Usable,
            })
        })
    }

    fn bundle<'a>(&'a self, _locator: &'a str) -> ServiceFuture<'a, SyncFetched> {
        // The bundle opens under the key the kit, the origin and the locator derive, so a locator
        // that is not the one it was sealed for gives bytes that do not authenticate.
        Box::pin(async move {
            Ok(SyncFetched::Held {
                position: SyncPosition::at(1, SyncRevision::new(Uuid::from_bytes([0; 16])), None),
                ciphertext: self.export.encrypted_bundle.as_slice().to_vec(),
            })
        })
    }

    fn generation<'a>(
        &'a self,
        archive_id: ArchiveId,
        checkpoint: Option<&'a ArchiveCheckpoint>,
    ) -> ServiceFuture<'a, Option<BackupGenerationPublication>> {
        Box::pin(async move {
            let Some(archive) = self.export.archive.0.as_ref() else {
                return Ok(None);
            };
            if archive.archive_id != archive_id {
                return Ok(None);
            }
            // A file holds one generation. Held to a checkpoint as new as nothing in it, it answers
            // nothing, as a service does, and the restore then asks what it holds.
            let older = checkpoint.is_some_and(|checkpoint| {
                archive.publication.payload.descriptor.backup_generation
                    < checkpoint.backup_generation
            });
            Ok((!older).then(|| archive.publication.clone()))
        })
    }

    fn object(
        &self,
        archive_id: ArchiveId,
        object: BackupObjectId,
        offset: u64,
        length: u64,
    ) -> ServiceFuture<'_, Vec<u8>> {
        Box::pin(async move {
            let archive = self
                .export
                .archive
                .0
                .as_ref()
                .filter(|archive| archive.archive_id == archive_id)
                .ok_or_else(not_in_the_export)?;
            let stored = if object
                == archive
                    .publication
                    .payload
                    .descriptor
                    .encrypted_manifest
                    .object_id
            {
                archive.encrypted_manifest.as_slice()
            } else {
                archive
                    .objects
                    .iter()
                    .find(|held| held.object_id == object)
                    .ok_or_else(not_in_the_export)?
                    .bytes
                    .as_slice()
            };
            let start = usize::try_from(offset)
                .unwrap_or(usize::MAX)
                .min(stored.len());
            let end = usize::try_from(offset.saturating_add(length))
                .unwrap_or(usize::MAX)
                .min(stored.len());
            Ok(stored[start..end].to_vec())
        })
    }
}
