//! The backup manifest's client: a collection's writer enrolment, one generation's publication and
//! a fetch of one, over the signed call.
//!
//! Section 20: an archive's objects and its encrypted manifest are content, and this service holds
//! neither. What it holds is the public half of each generation, the descriptor with the manifest
//! key wrapped once per recipient, under the signature of a writer the collection's owner enrolled.
//! [`ManagedBackupManifestService`] is how a device or a host reaches it: the
//! [`BackupManifestService`] this crate carries, over [`SignedService`].
//!
//! # Who signs what
//!
//! Each record here is checked against the key that carried the request. An owner enrols a writer
//! by signing the writer's key into the collection, and signs the request that carries the
//! enrolment with the same key. A writer publishes a generation by signing its descriptor, and
//! signs the request that carries the publication with the same key, because a signature the
//! caller does not hold is not authority. So a client that enrols is built with the owner's key and
//! a client that publishes with the writer's, and the service refuses either record in another's
//! hands.
//!
//! # Whose storage a publication spends
//!
//! A publication reserves the account's backup storage for its descriptor, so it carries the
//! account token for `backup.write` beside its signature, as every storage request does, and a
//! client given no account sends none. An enrolment and a fetch spend nothing and carry no token.
//!
//! # The same publication again
//!
//! The service keeps each generation's publication and answers the same publication sent again as
//! a duplicate, while different content for a generation it holds is refused. A publisher that
//! makes a publication the same way every time, the same writer's signature over the same
//! descriptor at the same instant, can therefore send it again after an answer was lost and learn
//! what the service holds without publishing anything twice.
//!
//! # What is never rendered
//!
//! A publication carries the manifest key wrapped for every recipient, and the writer's signature.
//! A fetched generation holds one, so it writes its own [`std::fmt::Debug`]: the archive and the
//! generation, and never the publication.

use std::fmt;
use std::sync::Arc;

use kr_protocol::archive::{BackupGenerationPublication, BackupWriterRecord};
use kr_protocol::ids::{ArchiveId, BackupGeneration};
use kr_protocol::method::Method;
use kr_protocol::pairing::GenerationCheckpoint;
use kr_protocol::scalars::{Digest256, KeyId, Nullable, U64};
use kr_protocol::service::GatewayOrigin;
use serde::{Deserialize, Serialize};

use super::account::{AccountTokenSource, BACKUP_WRITE_SCOPE};
use super::relay::{ServiceHttp, ServiceSigner};
use super::signed::{AccountAuthorisation, Answer, SignedService, unreadable_answer};
use super::storage::ArchiveAnswer;
use super::{BackupManifestService, ServiceFuture};
use crate::error::{ClientError, Result};
use kr_protocol::error::{ErrorCode, ProtocolError};

/// Where every backup-manifest request is served.
pub const BACKUP_MANIFEST_PATH: &str = "/api/backup/manifest";

/// The most bytes one signed backup-manifest request may be.
///
/// A descriptor is at most 64 KiB in its canonical encoding, and it travels as JSON with its bytes
/// as base64url, so this is that bound with the expansion and the rest of the request allowed for.
pub const MAX_BACKUP_REQUEST_BYTES: usize = 256 * 1024;

/* -------------------------------------------------------------------------- */
/* What the service answers                                                    */
/* -------------------------------------------------------------------------- */

/// The writer a collection holds, as the service summarises it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WriterSummary {
    /// The writer's signing key identifier.
    pub writer_key_id: KeyId,
    /// The revision of the enrolment that holds it.
    pub writer_revision: u64,
    /// When the service took the enrolment, as it wrote it.
    pub enrolled_at: String,
}

/// What one collection holds now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionSummary {
    /// The archive.
    pub archive_id: ArchiveId,
    /// The highest generation the collection has ever held, which only rises.
    pub checkpoint_generation: u64,
    /// The generations it still holds, newest first.
    pub generations: Vec<u64>,
    /// The bytes its kept descriptors occupy.
    pub bytes: u64,
    /// The storage allowance the principal holds, as the ledger states it, when it could be read.
    pub allowance_bytes: Option<u64>,
}

/// One kept generation, as the service summarises it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationSummary {
    /// The generation.
    pub backup_generation: BackupGeneration,
    /// The hash of its encrypted manifest.
    pub encrypted_manifest_hash: Digest256,
    /// The bytes of its descriptor.
    pub descriptor_bytes: u64,
    /// How many recipients its manifest key is wrapped for.
    pub recipients: u32,
    /// When the service stored it, as it wrote it.
    pub published_at: String,
}

/// What an enrolment answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enrolled {
    /// Whether this enrolment changed the collection's writer, or was the one it already held.
    pub changed: bool,
    /// The writer the collection holds now.
    pub writer: WriterSummary,
    /// What the collection holds.
    pub collection: CollectionSummary,
}

/// What a publication answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Published {
    /// Whether this publication was stored now, or the service already held it.
    pub duplicate: bool,
    /// The generation it published.
    pub generation: GenerationSummary,
    /// What the collection holds now.
    pub collection: CollectionSummary,
    /// The generations this publication pushed out of the kept history.
    pub dropped: Vec<u64>,
}

/// One generation a fetch found.
#[derive(Clone, PartialEq, Eq)]
pub struct FetchedGeneration {
    /// The writer's publication, exactly as it was published. A restore verifies it against a
    /// writer from the recovery bundle and never against what the service says.
    pub publication: BackupGenerationPublication,
    /// When the service stored it, as it wrote it.
    pub published_at: String,
    /// What the collection holds.
    pub collection: CollectionSummary,
    /// The writer the collection holds now, which need not be the one that signed this generation.
    pub current_writer: WriterSummary,
}

impl fmt::Debug for FetchedGeneration {
    /// The archive and the generation. Never the publication.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let descriptor = &self.publication.payload.descriptor;
        formatter
            .debug_struct("FetchedGeneration")
            .field("archive_id", &descriptor.archive_id)
            .field("backup_generation", &descriptor.backup_generation)
            .finish_non_exhaustive()
    }
}

/* -------------------------------------------------------------------------- */
/* On the wire                                                                 */
/* -------------------------------------------------------------------------- */

/// One backup-manifest request: exactly one member.
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ManifestRequest<'a> {
    Enrol {
        record: &'a BackupWriterRecord,
    },
    Publish {
        publication: &'a BackupGenerationPublication,
    },
    Fetch {
        archive_id: ArchiveId,
        #[serde(skip_serializing_if = "Option::is_none")]
        backup_generation: Option<BackupGeneration>,
        #[serde(skip_serializing_if = "Option::is_none")]
        checkpoint: Option<&'a GenerationCheckpoint>,
    },
}

/// A writer, as the service writes one.
#[derive(Deserialize)]
struct WriterAnswer {
    writer_key_id: KeyId,
    writer_revision: U64,
    enrolled_at: String,
}

impl WriterAnswer {
    fn summary(self) -> WriterSummary {
        WriterSummary {
            writer_key_id: self.writer_key_id,
            writer_revision: self.writer_revision.get(),
            enrolled_at: self.enrolled_at,
        }
    }
}

/// A collection, as the service writes one.
#[derive(Deserialize)]
struct CollectionAnswer {
    archive_id: ArchiveId,
    checkpoint_generation: U64,
    generations: Vec<U64>,
    bytes: U64,
    allowance_bytes: Nullable<U64>,
}

impl CollectionAnswer {
    fn summary(self) -> CollectionSummary {
        CollectionSummary {
            archive_id: self.archive_id,
            checkpoint_generation: self.checkpoint_generation.get(),
            generations: self.generations.into_iter().map(U64::get).collect(),
            bytes: self.bytes.get(),
            allowance_bytes: self.allowance_bytes.0.map(U64::get),
        }
    }
}

/// A generation, as the service writes one.
#[derive(Deserialize)]
struct GenerationAnswer {
    backup_generation: BackupGeneration,
    encrypted_manifest_hash: Digest256,
    descriptor_bytes: U64,
    recipients: u32,
    published_at: String,
}

/// Whether an enrolment changed anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EnrolState {
    Enrolled,
    Unchanged,
}

/// What an enrolment answers.
#[derive(Deserialize)]
struct EnrolAnswer {
    state: EnrolState,
    writer: WriterAnswer,
    collection: CollectionAnswer,
}

/// Whether a publication was stored now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PublishState {
    Published,
    Duplicate,
}

/// What a publication answers.
#[derive(Deserialize)]
struct PublishAnswer {
    state: PublishState,
    generation: GenerationAnswer,
    collection: CollectionAnswer,
    dropped: Vec<U64>,
}

/// What a fetch answers.
#[derive(Deserialize)]
struct FetchAnswer {
    publication: BackupGenerationPublication,
    published_at: String,
    collection: CollectionAnswer,
    current_writer: WriterAnswer,
}

/* -------------------------------------------------------------------------- */
/* The client                                                                  */
/* -------------------------------------------------------------------------- */

/// The backup manifest's client, over the signed call.
#[derive(Clone, Debug)]
pub struct ManagedBackupManifestService {
    call: SignedService,
    /// The account token a publication carries beside its signature, when this client was given an
    /// account.
    account: Option<AccountAuthorisation>,
}

impl ManagedBackupManifestService {
    /// Builds a client against one gateway, signing as the key `signer` holds: an owner's to enrol
    /// a writer, and the writer's own to publish.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        signer: Arc<dyn ServiceSigner>,
    ) -> Self {
        Self {
            call: SignedService::new(origin, http, signer),
            account: None,
        }
    }

    /// The same client, presenting the account token `tokens` holds for `backup.write` beside the
    /// signature of every publication.
    #[must_use]
    pub fn presenting(mut self, tokens: Arc<dyn AccountTokenSource>) -> Self {
        self.account = Some(AccountAuthorisation::new(tokens, BACKUP_WRITE_SCOPE));
        self
    }

    /// The gateway this client addresses.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        self.call.origin()
    }

    /// Sends one request, with the account token beside it where one is given.
    async fn ask(
        &self,
        request: &ManifestRequest<'_>,
        account: Option<&AccountAuthorisation>,
    ) -> Result<Answer> {
        Ok(self
            .call
            .dispatch(
                BACKUP_MANIFEST_PATH,
                Method::BackupManifest,
                request,
                MAX_BACKUP_REQUEST_BYTES,
                None,
                account,
            )
            .await?)
    }

    async fn enrol(&self, record: &BackupWriterRecord) -> Result<Enrolled> {
        let answer: EnrolAnswer = read(
            self.ask(&ManifestRequest::Enrol { record }, None)
                .await?
                .data()?,
            "what an enrolment answered",
        )?;
        if answer.collection.archive_id != record.payload.archive_id
            || answer.writer.writer_key_id != record.payload.writer.writer_key_id
        {
            return Err(contrary(
                "an enrolment of another collection or another writer",
            ));
        }
        Ok(Enrolled {
            changed: answer.state == EnrolState::Enrolled,
            writer: answer.writer.summary(),
            collection: answer.collection.summary(),
        })
    }

    async fn publish(
        &self,
        publication: &BackupGenerationPublication,
    ) -> Result<ArchiveAnswer<Published>> {
        let Some(account) = &self.account else {
            return Err(ClientError::Host(ProtocolError::new(
                ErrorCode::HostNotConfigured,
                "a publication spends an account's backup storage, and this client presents no \
                 account"
                    .to_owned(),
            )));
        };
        let data = match self
            .ask(&ManifestRequest::Publish { publication }, Some(account))
            .await?
        {
            Answer::Data(data) => data,
            Answer::Refused(refusal) if refusal.code() == "COLLECTION_DELETED" => {
                return Ok(ArchiveAnswer::CollectionDeleted);
            }
            Answer::Refused(refusal) => return Err(refusal.into_error()),
        };
        let answer: PublishAnswer = read(data, "what a publication answered")?;
        let descriptor = &publication.payload.descriptor;
        if answer.collection.archive_id != descriptor.archive_id
            || answer.generation.backup_generation != descriptor.backup_generation
            || answer.generation.encrypted_manifest_hash
                != descriptor.encrypted_manifest.encrypted_object_hash
        {
            return Err(contrary("a publication of another archive or generation"));
        }
        Ok(ArchiveAnswer::Done(Published {
            duplicate: answer.state == PublishState::Duplicate,
            generation: GenerationSummary {
                backup_generation: answer.generation.backup_generation,
                encrypted_manifest_hash: answer.generation.encrypted_manifest_hash,
                descriptor_bytes: answer.generation.descriptor_bytes.get(),
                recipients: answer.generation.recipients,
                published_at: answer.generation.published_at,
            },
            collection: answer.collection.summary(),
            dropped: answer.dropped.into_iter().map(U64::get).collect(),
        }))
    }

    async fn fetch(
        &self,
        archive_id: ArchiveId,
        generation: Option<BackupGeneration>,
        checkpoint: Option<&GenerationCheckpoint>,
    ) -> Result<Option<FetchedGeneration>> {
        let request = ManifestRequest::Fetch {
            archive_id,
            backup_generation: generation,
            checkpoint,
        };
        let data = match self.ask(&request, None).await? {
            Answer::Data(data) => data,
            // No collection, no such generation, or none the service holds as new as the
            // checkpoint: the service holds nothing this fetch may be answered with.
            Answer::Refused(refusal) if refusal.code() == "NOT_FOUND" => return Ok(None),
            Answer::Refused(refusal) => return Err(refusal.into_error()),
        };
        let answer: FetchAnswer = read(data, "what a fetch answered")?;
        let descriptor = &answer.publication.payload.descriptor;
        if descriptor.archive_id != archive_id
            || answer.collection.archive_id != archive_id
            || generation.is_some_and(|asked| asked != descriptor.backup_generation)
        {
            return Err(contrary(
                "a generation of another archive than was asked for",
            ));
        }
        Ok(Some(FetchedGeneration {
            publication: answer.publication,
            published_at: answer.published_at,
            collection: answer.collection.summary(),
            current_writer: answer.current_writer.summary(),
        }))
    }
}

impl BackupManifestService for ManagedBackupManifestService {
    fn enrol<'a>(&'a self, record: &'a BackupWriterRecord) -> ServiceFuture<'a, Enrolled> {
        Box::pin(self.enrol(record))
    }

    fn publish<'a>(
        &'a self,
        publication: &'a BackupGenerationPublication,
    ) -> ServiceFuture<'a, ArchiveAnswer<Published>> {
        Box::pin(self.publish(publication))
    }

    fn fetch<'a>(
        &'a self,
        archive_id: ArchiveId,
        generation: Option<BackupGeneration>,
        checkpoint: Option<&'a GenerationCheckpoint>,
    ) -> ServiceFuture<'a, Option<FetchedGeneration>> {
        Box::pin(self.fetch(archive_id, generation, checkpoint))
    }
}

/// Reads one answer as the shape the contract gives it.
fn read<T: for<'de> Deserialize<'de>>(data: serde_json::Value, what: &'static str) -> Result<T> {
    serde_json::from_value(data).map_err(|error| unreadable_answer(what, &error))
}

/// An answer that was read and says something the service's contract does not allow.
fn contrary(what: &str) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        format!("the service answered {what}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::rendering::{NEVER_RENDERED, renders_only};
    use kr_protocol::archive::{
        ArchiveDescriptor, BackupGenerationPublicationPayload, EncryptedObjectRef,
    };
    use kr_protocol::ids::BackupObjectId;
    use kr_protocol::scalars::{Signature64, TimestampMs, Uuid};

    #[test]
    fn a_rendering_of_a_fetched_generation_carries_neither_its_publication_nor_its_signature() {
        let archive_id = ArchiveId::new(Uuid::from_bytes([0x11; 16]));
        let fetched = FetchedGeneration {
            publication: BackupGenerationPublication {
                payload: BackupGenerationPublicationPayload {
                    descriptor: ArchiveDescriptor {
                        version: U64::new(1),
                        archive_id,
                        backup_generation: BackupGeneration::new(3),
                        encrypted_manifest: EncryptedObjectRef {
                            object_id: BackupObjectId::new(Uuid::from_bytes([0xf0; 16])),
                            encrypted_object_hash: Digest256::from_bytes([0x5a; 32]),
                            encrypted_len: U64::new(64),
                        },
                        manifest_key_wraps: Vec::new(),
                    },
                    writer_key_id: KeyId::from_bytes([0x22; 32]),
                    published_at_ms: TimestampMs::new(2_000),
                },
                signature: Signature64::from_bytes([0x33; 64]),
            },
            published_at: NEVER_RENDERED.to_owned(),
            collection: CollectionSummary {
                archive_id,
                checkpoint_generation: 3,
                generations: vec![3],
                bytes: 64,
                allowance_bytes: None,
            },
            current_writer: WriterSummary {
                writer_key_id: KeyId::from_bytes([0x22; 32]),
                writer_revision: 1,
                enrolled_at: NEVER_RENDERED.to_owned(),
            },
        };
        renders_only(
            &fetched,
            &format!(
                "FetchedGeneration{{archive_id:{archive_id:?},backup_generation:{:?},..}}",
                BackupGeneration::new(3)
            ),
        );
    }
}
