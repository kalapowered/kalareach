//! A restore to files: a recovery kit and the ciphertext a service holds, opened into readable
//! copies the person keeps.
//!
//! This is the order the guarantees live in, and a caller cannot change it:
//!
//! 1. **The kit, then the service.** The kit's checksum is checked before anything is derived. The
//!    host's configured service must be one the kit names, and the kit's own spelling of that
//!    origin is what the bundle key is derived from. A service the kit names and the host is not
//!    configured for is refused by name: this restore reaches the managed account service only.
//! 2. **The bundle, authenticated by the seed.** Every writer, producer and checkpoint a restore
//!    trusts comes out of a bundle that opens only under the key the seed, the origin and the
//!    locator derive. Nothing is taken from an archive.
//! 3. **One archive, one generation.** Exactly one authenticated collection entry names the archive
//!    and the configured origin. The newest generation is fetched held to the bundle's checkpoint
//!    for it, and a service that holds nothing as new as the checkpoint stops the restore: it does
//!    not fall back to an older genuine generation.
//! 4. **The publication before any object.** The descriptor is validated, its writer is a writer
//!    the bundle names and the identifier of that writer's key, its signature verifies under that
//!    key, the archive is the one chosen, the declared manifest length is within the bound and the
//!    generation is admissible against the checkpoint. Only then is one byte of an object read.
//! 5. **The manifest, then the plan.** The manifest opens under the recovery recipient with only
//!    the bundle's writers and one producer. Every member is classified by its name (default deny),
//!    sized from its stored length, and bounded. The plan says what will be written and what is
//!    refused with the table's reason, and nothing is read for it beyond the manifest.
//! 6. **A member at a time.** Each admitted member's ciphertext is read in ranges, opened and
//!    handed over whole. Nothing is written here and nothing is imported anywhere: the caller
//!    puts the bytes in a place the person chose.
//!
//! The seed and the plaintext never leave this module's callers' process; [`RestoreSource`] is the
//! only thing that reaches a service, and it carries ciphertext and public records.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_crypto::backup::{
    ArchiveExpectation, ArchiveReader, CheckpointSource, GenerationExpectation, Material,
    OpenArchive, RestoreGeneration, admit_for_restore, member_cap, member_material, open_archive,
};
use kr_crypto::kdf::{RecoveryRecipient, RecoverySeed};
use kr_crypto::secret::SecretVec;
use kr_crypto::sign::SigningTranscript;
use kr_crypto::stream;
use kr_protocol::archive::{
    ArchiveCheckpoint, BACKUP_PUBLICATION_DOMAIN, BackupGenerationPublication, CollectionLocator,
    MAX_MANIFEST_OBJECTS, MAX_MANIFEST_PAYLOAD_LEN, RecoveryKit, TrustedWriter,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId};
use kr_protocol::scalars::{Digest256, KeyId, StoredEnvelopeKey, TimestampMs, Uuid};
use kr_protocol::service::GatewayOrigin;
use serde::Serialize;

use crate::error::ClientError;
use crate::recovery::{
    FreshRestore, RecoveryError, RetrievalPolicy, ServiceAccess, TrustedMaterial,
};
use crate::services::{
    ServiceFuture, SyncBackupService, SyncDispatch, SyncExchanged, SyncFetched, SyncPosition,
    SyncRequestFence, SyncRequestStatus,
};
use crate::shown::Shown;

pub use kr_crypto::backup::{
    MAX_CONFIGURATION_MEMBER_BYTES, MAX_RESTORED_BYTES, MAX_SESSION_MEMBER_BYTES,
};

/// The most ciphertext one object read asks for, which a daemon's reply carries inside one control
/// frame.
pub const MAX_RANGE_BYTES: u64 = kr_protocol::backup_read::BACKUP_READ_MAX_RANGE_BYTES;

/// The domain a plan's digest is made under.
const PLAN_DOMAIN: &[u8] = b"kr-backup-restore-plan/1\0";

/// The format line of the record a restore leaves beside the files.
pub const RESTORE_RECORD_FORMAT: &str = "kalareach-restore/1";

/* -------------------------------------------------------------------------- */
/* Where the ciphertext comes from                                             */
/* -------------------------------------------------------------------------- */

/// Why the host holds no account token a bundle read may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignInCause {
    /// No account is signed in on this host.
    SignedOut,
    /// A sign-in is waiting for the person's browser.
    Waiting,
    /// The service ended the sign-in.
    Ended,
    /// The account is signed in and its grant lacks the scope backup storage needs.
    WithoutScope,
    /// The sign-in looks whole and no token could be had from it just now.
    NotRenewed,
}

impl SignInCause {
    /// Why no token is usable, in this program's words.
    #[must_use]
    pub const fn why(self) -> &'static str {
        match self {
            Self::SignedOut => "no account is signed in on this host",
            Self::Waiting => "a sign-in on this host is waiting to finish",
            Self::Ended => "the service ended the sign-in on this host",
            Self::WithoutScope => "the account signed in on this host lacks the backup.write scope",
            Self::NotRenewed => {
                "this host could not renew the token of the account signed in on this host"
            }
        }
    }

    /// What a person does about it.
    #[must_use]
    pub const fn remedy(self) -> &'static str {
        match self {
            Self::SignedOut | Self::Ended => "Sign this host in with `kr account sign-in`.",
            Self::Waiting => "Finish the sign-in at the address `kr account sign-in` printed.",
            Self::WithoutScope => {
                "Sign this host in again with `kr account sign-in`, which asks for backup \
                 storage because storage.origin is set."
            }
            Self::NotRenewed => {
                "This host asks again by itself. Check that the account service is reachable, or \
                 sign this host in again with `kr account sign-in`."
            }
        }
    }
}

/// Whether the host holds an account token a bundle read may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceSignIn {
    /// A token is usable now.
    Usable,
    /// None is, for this reason.
    Unusable(SignInCause),
}

/// The service a source reaches, as the host is configured for it.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceService {
    /// The configured storage origin.
    pub origin: String,
    /// Whether a bundle read may be sent.
    pub sign_in: SourceSignIn,
}

crate::debug_as_name!(SourceService);

/// Where a restore reads ciphertext and public records from.
///
/// A source carries what a service holds: it has no seed, no kit and no plaintext. The `kr`
/// command's is the daemon's relay; a test's is a script that serves hostile data. An answer a
/// source gives is the service's, and a restore trusts none of it until it has checked it.
pub trait RestoreSource: Send + Sync + fmt::Debug {
    /// The service this host reaches, and whether it may be asked.
    fn service(&self) -> ServiceFuture<'_, SourceService>;

    /// The sealed bundle at a locator, as the service answered it.
    fn bundle<'a>(&'a self, locator: &'a str) -> ServiceFuture<'a, SyncFetched>;

    /// The newest generation published for an archive, held to `checkpoint` when there is one.
    ///
    /// Nothing is an answer: the service holds no such generation, or none as new as the
    /// checkpoint. It is kept apart from a failure.
    fn generation<'a>(
        &'a self,
        archive: ArchiveId,
        checkpoint: Option<&'a ArchiveCheckpoint>,
    ) -> ServiceFuture<'a, Option<BackupGenerationPublication>>;

    /// One range of a stored object, at most [`MAX_RANGE_BYTES`] long.
    fn object(
        &self,
        archive: ArchiveId,
        object: BackupObjectId,
        offset: u64,
        length: u64,
    ) -> ServiceFuture<'_, Vec<u8>>;
}

/// The bundle as the settings-sync client reads it, over a source, and refusing every write.
struct BundleReader {
    source: Arc<dyn RestoreSource>,
    /// Whether the source answered that no bundle is held, so the caller can say that apart from a
    /// bundle that failed to authenticate.
    answered_absent: AtomicBool,
}

impl fmt::Debug for BundleReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundleReader")
            .finish_non_exhaustive()
    }
}

fn read_only() -> ClientError {
    ClientError::refusal(
        ErrorCode::PermissionDenied,
        Shown::said("a restore reads the recovery bundle and never writes it"),
    )
}

impl SyncBackupService for BundleReader {
    fn compare_exchange<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
        _signed_at_ms: u64,
        _expected: Option<SyncPosition>,
        _ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async { Err(read_only()) })
    }

    fn compare_exchange_dispatched<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
        _signed_at_ms: u64,
        _expected: Option<SyncPosition>,
        _ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncDispatch> {
        Box::pin(async { Err(read_only()) })
    }

    fn request_status<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async { Err(read_only()) })
    }

    fn fence_request<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
        _first_signed_at_ms: u64,
        _last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async { Err(read_only()) })
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(async move {
            // The collection is `recovery_bundle/<locator>`; the source is asked for the locator.
            let locator = collection
                .strip_prefix(&format!(
                    "{}/",
                    kr_protocol::sync::SyncObjectKind::RecoveryBundle
                ))
                .unwrap_or(collection);
            let fetched = self.source.bundle(locator).await?;
            if matches!(fetched, SyncFetched::Absent { .. }) {
                self.answered_absent.store(true, Ordering::Relaxed);
            }
            Ok(fetched)
        })
    }

    fn resolve<'a>(
        &'a self,
        _collection: &'a str,
        _retained: kr_protocol::ids::SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        Box::pin(async { Err(read_only()) })
    }
}

/* -------------------------------------------------------------------------- */
/* What can stop a restore                                                     */
/* -------------------------------------------------------------------------- */

/// Why the publication of a generation is not one a restore opens.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PublicationRefusal {
    /// The descriptor breaks a rule the protocol states for one.
    #[error("the published descriptor is not one this build reads")]
    Structure(kr_protocol::archive::DescriptorError),
    /// The archive it describes is not the one chosen.
    #[error("the publication is for another archive than the one being restored")]
    OtherArchive,
    /// Its writer is not a writer the authenticated bundle names.
    #[error("the publication was signed by a writer the recovery bundle does not name")]
    WriterNotInBundle,
    /// The bundle's entry for that writer names a key that is not the writer's.
    #[error("the recovery bundle's writer entry does not carry that writer's own key")]
    WriterKeyMismatch,
    /// The signature does not verify under the bundle's key for the writer.
    #[error("the publication's signature does not verify under the bundle's writer key")]
    BadSignature,
    /// The checkpoint refuses the generation; the standing says how.
    #[error("the recovery bundle's checkpoint refuses that generation. {1}")]
    Generation(RestoreGeneration, Shown),
}

crate::debug_as_display!(PublicationRefusal);

/// Why a restore stopped, before it wrote anything.
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum RestoreError {
    /// The host holds no account token a bundle read may carry.
    #[error("{why}")]
    NotSignedIn {
        /// Why no token is usable, and so what mends it.
        cause: SignInCause,
        /// The same, in words.
        why: Shown,
    },
    /// The kit names no service this host is configured for.
    ///
    /// The host reaches the managed account service it is configured for and no other, so a kit
    /// that names only a self-hosted service cannot be restored here.
    #[error("the recovery kit names no service this host is configured for")]
    OriginNotConfigured,
    /// The kit, the bundle or the service refused at the recovery layer.
    #[error("{0}")]
    Recovery(Box<RecoveryError>),
    /// The service holds no bundle at the kit's locator for this host's account.
    #[error("the service holds no recovery bundle for this account at that locator")]
    BundleAbsent,
    /// The bundle names no archive at the configured service.
    #[error("the recovery bundle names no archive at this service")]
    NoArchive,
    /// The archive asked for is not one the bundle names at the configured service.
    #[error("the recovery bundle names no such archive at this service")]
    ArchiveNotListed,
    /// The bundle names more than one archive at the configured service and none was chosen.
    #[error("the recovery bundle names {count} archives at this service; choose one")]
    SeveralArchives {
        /// How many it names.
        count: usize,
        /// Each, with the newest generation the service holds of it.
        candidates: Vec<Candidate>,
    },
    /// The service holds nothing as new as the generation the bundle's checkpoint records.
    #[error(
        "the service holds no generation as new as the bundle's checkpoint, generation {checkpoint}"
    )]
    NothingAsNewAsTheCheckpoint {
        /// The generation the bundle's checkpoint records.
        checkpoint: u64,
    },
    /// The service holds no generation of the archive at all.
    #[error("the service holds no generation of that archive")]
    NoGeneration,
    /// The publication is not one a restore opens.
    #[error("{0}")]
    Publication(PublicationRefusal),
    /// The manifest is longer than any manifest is.
    #[error("the manifest object declares {declared} bytes, over the {limit}-byte limit")]
    ManifestTooLarge {
        /// The length the descriptor declares.
        declared: u64,
        /// The most a manifest object is.
        limit: u64,
    },
    /// The descriptor carries no manifest key wrapped for the recovery recipient.
    #[error("the archive's manifest key is not wrapped for the recovery kit's recipient")]
    NoWrap,
    /// The producer that wrapped the manifest key is not one the bundle names.
    #[error("the recovery bundle names no producer for this archive's manifest key")]
    NoProducer,
    /// The archive did not open.
    #[error("the archive did not open: {0}")]
    Archive(Shown),
    /// The manifest was signed by another writer than the publication.
    #[error("the manifest was signed by another writer than the publication")]
    ManifestWriter,
    /// The manifest names more members than any archive has.
    #[error("the manifest names {count} members, over the {limit} an archive has")]
    TooManyMembers {
        /// How many it names.
        count: usize,
        /// The most an archive has.
        limit: usize,
    },
    /// A service answered a read with a range other than the one asked for.
    #[error("the service answered with a range other than the one asked for")]
    Range,
    /// A read failed.
    #[error("{0}")]
    Read(ClientError),
    /// A member did not open.
    #[error("a member did not open: {0}")]
    Member(Shown),
    /// The recovery recipient could not be derived from the seed.
    #[error("the recovery recipient could not be derived: {0}")]
    Seed(Shown),
    /// A member was asked for that the plan does not restore.
    #[error("that member is not one this restore's plan writes")]
    NotInPlan,
}

crate::debug_as_display!(RestoreError);

impl From<ClientError> for RestoreError {
    fn from(error: ClientError) -> Self {
        Self::Read(error)
    }
}

/// One archive a bundle names, with the newest generation the service holds of it.
#[derive(Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The archive.
    pub archive_id: ArchiveId,
    /// What the service holds of it.
    pub newest: CandidateState,
}

crate::debug_as_name!(Candidate);

/// What the service held of a candidate archive.
#[derive(Clone, PartialEq, Eq)]
pub enum CandidateState {
    /// Nothing, or nothing as new as the bundle's checkpoint.
    Nothing,
    /// A publication that a restore would refuse, and why.
    Refused(PublicationRefusal),
    /// The newest generation, after its publication was verified as a restore does.
    Newest(CandidateGeneration),
}

crate::debug_as_name!(CandidateState);

/// The newest generation of a candidate, after its publication was verified as a restore does.
#[derive(Clone, PartialEq, Eq)]
pub struct CandidateGeneration {
    /// The generation.
    pub generation: BackupGeneration,
    /// When the writer signed the publication, in UTC milliseconds.
    pub published_at_ms: TimestampMs,
    /// The identifier of the writer's key.
    pub writer: KeyId,
}

crate::debug_as_name!(CandidateGeneration);

/* -------------------------------------------------------------------------- */
/* The plan                                                                    */
/* -------------------------------------------------------------------------- */

/// What a member is once it is restored.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    /// One session export.
    Session,
    /// The host's configuration document.
    Configuration,
}

/// Why a member is not restored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberRefusal {
    /// It is material no restore puts back, for the reason the table gives.
    Kind {
        /// The material.
        material: Material,
        /// The table's reason.
        because: &'static str,
    },
    /// Its name is not one this convention knows.
    UnknownKind,
    /// Another member has its name.
    Duplicate,
    /// It is larger than a member of its kind may be.
    OverMemberCap {
        /// The size it declares, in plaintext bytes.
        size: u64,
        /// The most a member of its kind is.
        cap: u64,
    },
    /// The members before it already take all a restore accepts.
    OverTotal {
        /// The most one restore accepts.
        cap: u64,
    },
    /// Its stored length is not that of any object.
    BadStoredLength,
}

impl MemberRefusal {
    /// A short stable word for the record and for tests.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Kind { .. } => "material_never_restored",
            Self::UnknownKind => "unknown_kind",
            Self::Duplicate => "duplicate_name",
            Self::OverMemberCap { .. } => "over_member_size",
            Self::OverTotal { .. } => "over_total_size",
            Self::BadStoredLength => "bad_stored_length",
        }
    }
}

impl MemberRefusal {
    /// Why the member is not restored, in this program's words and the numbers that broke a bound.
    #[must_use]
    pub fn said(self) -> Shown {
        match self {
            Self::Kind { because, .. } => Shown::said(because),
            Self::UnknownKind => Shown::said("its name is not one a host archive carries"),
            Self::Duplicate => Shown::said("another member has the same name"),
            Self::OverMemberCap { size, cap } => crate::shown!(
                "it holds {} bytes and a member of its kind holds at most {}",
                size,
                cap
            ),
            Self::OverTotal { cap } => crate::shown!(
                "the members before it already take the {} bytes a restore accepts",
                cap
            ),
            Self::BadStoredLength => Shown::said("its stored length is not that of any object"),
        }
    }
}

/// What a restore does with one member.
#[derive(Clone, PartialEq, Eq)]
pub enum MemberVerdict {
    /// It is written, to this file name, which the member's role and number make and the archive
    /// never supplies.
    Restore {
        /// What it is.
        role: MemberRole,
        /// The file name.
        file: String,
    },
    /// It is not written.
    Refused(MemberRefusal),
}

/// One member of the manifest, as the plan treats it.
#[derive(Clone, PartialEq, Eq)]
pub struct PlannedMember {
    /// The object.
    pub object_id: BackupObjectId,
    /// Its stored length, in bytes.
    pub stored_len: u64,
    /// Its plaintext length, when the stored length is one an object has.
    pub plaintext_len: Option<u64>,
    /// What is done with it.
    pub verdict: MemberVerdict,
}

/// What a restore would do, and what it was shown for the person to confirm.
#[derive(Clone, PartialEq, Eq)]
pub struct RestorePlan {
    /// The configured service origin.
    pub origin: String,
    /// The archive.
    pub archive_id: ArchiveId,
    /// The generation.
    pub generation: BackupGeneration,
    /// The hash of the generation's encrypted manifest.
    pub manifest_hash: Digest256,
    /// The identifier of the writer's key.
    pub writer: KeyId,
    /// Where the generation stands against the bundle's checkpoint.
    pub standing: RestoreGeneration,
    /// The bundle's revision.
    pub bundle_revision: u64,
    /// When the writer signed the publication, in UTC milliseconds.
    pub published_at_ms: TimestampMs,
    /// Every member, in manifest order.
    pub members: Vec<PlannedMember>,
}

crate::debug_as_name!(MemberVerdict, PlannedMember, RestorePlan);

/// What a plan's digest covers.
#[derive(Serialize)]
struct DigestInput<'a> {
    environment: &'a str,
    /// The destination as the operating system spells it, in lowercase hexadecimal, so two names
    /// that differ in bytes no text can show are two destinations.
    destination: String,
    origin: &'a str,
    archive: ArchiveId,
    generation: u64,
    manifest_hash: Digest256,
    published_at_ms: u64,
    writer: KeyId,
    standing: String,
    bundle_revision: u64,
    members: Vec<DigestMember>,
}

#[derive(Serialize)]
struct DigestMember {
    object: BackupObjectId,
    file: Option<String>,
    size: Option<u64>,
    decision: &'static str,
}

impl RestorePlan {
    /// The members this plan writes.
    pub fn restored(&self) -> impl Iterator<Item = (&PlannedMember, &str, MemberRole)> {
        self.members
            .iter()
            .filter_map(|member| match &member.verdict {
                MemberVerdict::Restore { role, file } => Some((member, file.as_str(), *role)),
                MemberVerdict::Refused(_) => None,
            })
    }

    /// The members this plan refuses.
    pub fn refused(&self) -> impl Iterator<Item = (&PlannedMember, MemberRefusal)> {
        self.members
            .iter()
            .filter_map(|member| match member.verdict {
                MemberVerdict::Refused(refusal) => Some((member, refusal)),
                MemberVerdict::Restore { .. } => None,
            })
    }

    /// The plaintext this plan writes, in bytes.
    #[must_use]
    pub fn restored_bytes(&self) -> u64 {
        self.restored()
            .map(|(member, _, _)| member.plaintext_len.unwrap_or(0))
            .sum()
    }

    /// The digest the person confirms: a domain, the environment, the absolute destination (as the
    /// bytes the operating system names it by) and everything the plan says, as lowercase
    /// hexadecimal.
    ///
    /// A generation published between the preview and the confirmation changes it, so the
    /// confirmation is for the archive that was shown.
    ///
    /// Returns nothing when the plan cannot be encoded, which no plan this module makes is.
    #[must_use]
    pub fn digest(&self, environment: &str, destination: &[u8]) -> Option<String> {
        let input = DigestInput {
            environment,
            destination: destination
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            origin: &self.origin,
            archive: self.archive_id,
            generation: self.generation.get(),
            manifest_hash: self.manifest_hash,
            published_at_ms: self.published_at_ms.get(),
            writer: self.writer,
            standing: self.standing.describe(),
            bundle_revision: self.bundle_revision,
            members: self
                .members
                .iter()
                .map(|member| match &member.verdict {
                    MemberVerdict::Restore { file, .. } => DigestMember {
                        object: member.object_id,
                        file: Some(file.clone()),
                        size: member.plaintext_len,
                        decision: "restore",
                    },
                    MemberVerdict::Refused(refusal) => DigestMember {
                        object: member.object_id,
                        file: None,
                        size: member.plaintext_len,
                        decision: refusal.word(),
                    },
                })
                .collect(),
        };
        let encoded = kr_cbor::to_canonical_vec(&input).ok()?;
        let mut bytes = Vec::with_capacity(PLAN_DOMAIN.len() + encoded.len());
        bytes.extend_from_slice(PLAN_DOMAIN);
        bytes.extend_from_slice(&encoded);
        Some(
            kr_cbor::sha256(&bytes)
                .iter()
                .fold(String::with_capacity(64), |mut text, byte| {
                    use fmt::Write as _;
                    let _ = write!(text, "{byte:02x}");
                    text
                }),
        )
    }

    /// The record left beside the files once every member is written.
    ///
    /// It holds the plan as confirmed, what was written and what was refused and why, and no value
    /// of the kit. The sentence says what this restore gives: readable copies, nothing imported.
    #[must_use]
    pub fn record(&self, plan_digest: &str, written: &[BackupObjectId]) -> serde_json::Value {
        serde_json::json!({
            "format": RESTORE_RECORD_FORMAT,
            "what_this_is": "Readable copies of the data in a backup. Nothing was imported into this host, no key or authority came back, and the host's configuration is a file to read, not applied.",
            "service": self.origin,
            "archive": self.archive_id.to_string(),
            "backup_generation": self.generation.get(),
            "published_at_ms": self.published_at_ms.get(),
            "writer_key": self.writer,
            "bundle_revision": self.bundle_revision,
            "generation_standing": self.standing.describe(),
            "plan_digest": plan_digest,
            "members": self.members.iter().map(|member| match &member.verdict {
                MemberVerdict::Restore { file, role } => serde_json::json!({
                    "object": member.object_id.to_string(),
                    "role": role,
                    "file": file,
                    "size": member.plaintext_len,
                    "written": written.contains(&member.object_id),
                }),
                MemberVerdict::Refused(refusal) => serde_json::json!({
                    "object": member.object_id.to_string(),
                    "size": member.plaintext_len,
                    "written": false,
                    "refused": refusal.word(),
                    "because": refusal.said().into_string(),
                }),
            }).collect::<Vec<_>>(),
        })
    }
}

/// Classifies and bounds every member of a verified manifest.
///
/// A name decides the kind, `admit_for_restore` decides what the kind may do, and a name that is
/// not in the convention is refused: nothing a producer adds later is restored by accident. The
/// archive's own text reaches no file name; the number and the role do.
fn plan_members(manifest_members: &[(BackupObjectId, String, u64)]) -> Vec<PlannedMember> {
    let kinds: Vec<Option<Material>> = manifest_members
        .iter()
        .map(|(_, name, _)| member_material(name))
        .collect();
    let known: Vec<Material> = kinds.iter().flatten().copied().collect();
    let admissions = admit_for_restore(&known);
    let duplicated = |at: usize| {
        manifest_members
            .iter()
            .enumerate()
            .any(|(other, (_, name, _))| other != at && *name == manifest_members[at].1)
    };
    let mut sessions = 0_u32;
    let mut total = 0_u64;
    // Once one member would pass the total, it and every member after it are refused, so what a
    // restore writes is always a prefix of what the manifest lists that fits.
    let mut full = false;
    let mut planned = Vec::with_capacity(manifest_members.len());
    for (at, (object_id, _, stored_len)) in manifest_members.iter().enumerate() {
        let plaintext_len = stream::plaintext_len(*stored_len);
        let verdict = (|| {
            let Some(material) = kinds[at] else {
                return MemberVerdict::Refused(MemberRefusal::UnknownKind);
            };
            if duplicated(at) {
                return MemberVerdict::Refused(MemberRefusal::Duplicate);
            }
            if admissions.refused_kind(material) {
                let because = admissions
                    .refused
                    .iter()
                    .find(|(kind, _)| *kind == material)
                    .map_or("a restore does not put this back", |(_, because)| *because);
                return MemberVerdict::Refused(MemberRefusal::Kind { material, because });
            }
            // The two kinds a host archive carries; any other material the table allowed is still
            // not one this convention writes.
            let role = match material {
                Material::SessionData => MemberRole::Session,
                Material::DeviceConfiguration => MemberRole::Configuration,
                _ => return MemberVerdict::Refused(MemberRefusal::UnknownKind),
            };
            let (Some(cap), Some(size)) = (member_cap(material), plaintext_len) else {
                return MemberVerdict::Refused(MemberRefusal::BadStoredLength);
            };
            if size > cap {
                return MemberVerdict::Refused(MemberRefusal::OverMemberCap { size, cap });
            }
            if full || total.saturating_add(size) > MAX_RESTORED_BYTES {
                full = true;
                return MemberVerdict::Refused(MemberRefusal::OverTotal {
                    cap: MAX_RESTORED_BYTES,
                });
            }
            total += size;
            match role {
                MemberRole::Session => {
                    sessions += 1;
                    MemberVerdict::Restore {
                        role,
                        file: format!("session-{sessions:04}.json"),
                    }
                }
                MemberRole::Configuration => MemberVerdict::Restore {
                    role,
                    file: "configuration.json".to_owned(),
                },
            }
        })();
        planned.push(PlannedMember {
            object_id: *object_id,
            stored_len: *stored_len,
            plaintext_len,
            verdict,
        });
    }
    planned
}

/* -------------------------------------------------------------------------- */
/* The restore                                                                 */
/* -------------------------------------------------------------------------- */

/// A restore whose archive is open and whose plan is made.
///
/// Holding one is the evidence that the kit, the bundle, the publication and the manifest all
/// checked; [`Self::member`] is reachable only through it.
pub struct PreparedRestore {
    plan: RestorePlan,
    open: OpenArchive,
    recipient: RecoveryRecipient,
    sender: StoredEnvelopeKey,
    source: Arc<dyn RestoreSource>,
}

impl fmt::Debug for PreparedRestore {
    /// What the plan says and nothing else: no key, no ciphertext, no plaintext.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedRestore")
            .field("archive_id", &self.plan.archive_id)
            .field("generation", &self.plan.generation)
            .field("members", &self.plan.members.len())
            .finish_non_exhaustive()
    }
}

impl PreparedRestore {
    /// What this restore would do.
    #[must_use]
    pub const fn plan(&self) -> &RestorePlan {
        &self.plan
    }

    /// Reads one admitted member's ciphertext, opens it and hands over its plaintext.
    ///
    /// The member is looked up in this restore's own plan, and its verdict and stored length are
    /// the plan's. The ciphertext is checked against the manifest's length and hash before it is
    /// decrypted, and its final authenticated record is required, so a cut or altered object is an
    /// error and never a shorter file. Only the plaintext is handed over: the name the manifest
    /// recorded is archive text, and the plan names the file.
    ///
    /// # Errors
    ///
    /// Returns [`RestoreError::NotInPlan`] for an object the plan does not write,
    /// [`RestoreError::Read`] or [`RestoreError::Range`] when the service fails, and
    /// [`RestoreError::Member`] when the object does not open.
    pub async fn member(&self, object: BackupObjectId) -> Result<SecretVec, RestoreError> {
        let planned = self
            .plan
            .members
            .iter()
            .find(|member| member.object_id == object)
            .filter(|member| matches!(member.verdict, MemberVerdict::Restore { .. }))
            .ok_or(RestoreError::NotInPlan)?;
        let bytes = read_whole(
            self.source.as_ref(),
            self.plan.archive_id,
            planned.object_id,
            planned.stored_len,
        )
        .await?;
        self.open
            .restore_object(
                &ArchiveReader::Recovery(&self.recipient),
                &self.sender,
                planned.object_id,
                &bytes,
            )
            .map(|restored| restored.plaintext)
            .map_err(|error| RestoreError::Member(Shown::crypto(&error)))
    }
}

/// Reads one whole object in ranges, and no more than its declared length.
async fn read_whole(
    source: &dyn RestoreSource,
    archive: ArchiveId,
    object: BackupObjectId,
    length: u64,
) -> Result<Vec<u8>, RestoreError> {
    let mut bytes = Vec::with_capacity(usize::try_from(length).map_err(|_| RestoreError::Range)?);
    while (bytes.len() as u64) < length {
        let offset = bytes.len() as u64;
        let want = (length - offset).min(MAX_RANGE_BYTES);
        let range = source.object(archive, object, offset, want).await?;
        if range.is_empty() || range.len() as u64 > want {
            return Err(RestoreError::Range);
        }
        bytes.extend_from_slice(&range);
    }
    Ok(bytes)
}

/// A restore is prepared from a kit and a source.
pub struct FilesRestore;

impl FilesRestore {
    /// Opens the bundle, chooses the archive, verifies its newest publication and its manifest, and
    /// makes the plan. Nothing is written and nothing but the manifest object is read.
    ///
    /// # Errors
    ///
    /// Returns the first reason the restore cannot go on; see [`RestoreError`].
    pub async fn prepare(
        kit: RecoveryKit,
        source: Arc<dyn RestoreSource>,
        archive: Option<ArchiveId>,
    ) -> Result<PreparedRestore, RestoreError> {
        // 1. The kit's checksum, before anything is derived or asked.
        let seed = RecoverySeed::from_kit(&kit)
            .map_err(|_| RestoreError::Recovery(Box::new(RecoveryError::MistypedKit)))?;
        let service = source.service().await?;
        if let SourceSignIn::Unusable(cause) = service.sign_in {
            return Err(RestoreError::NotSignedIn {
                cause,
                why: Shown::said(cause.why()),
            });
        }
        let origin =
            kit_origin_for(&kit, &service.origin).ok_or(RestoreError::OriginNotConfigured)?;
        // The locator is an identifier in its canonical spelling, and the service refuses
        // anything else, so a kit that carries another is wrong before it is used.
        if !is_an_identifier(&kit.bundle_locator) {
            return Err(RestoreError::Recovery(Box::new(
                RecoveryError::MalformedKit {
                    what: "a bundle locator that is not an identifier",
                },
            )));
        }

        // 2. The bundle, through a reader that cannot write.
        let reader = Arc::new(BundleReader {
            source: Arc::clone(&source),
            answered_absent: AtomicBool::new(false),
        });
        let mut fresh = FreshRestore::new(kit, RetrievalPolicy::Account);
        fresh
            .obtained_access(ServiceAccess::new(
                RetrievalPolicy::Account,
                origin.clone(),
                Arc::clone(&reader) as Arc<dyn SyncBackupService>,
            ))
            .map_err(|error| RestoreError::Recovery(Box::new(error)))?;
        let material = match fresh.open_bundle(&origin).await {
            Ok(material) => material,
            Err(RecoveryError::Service(error)) => {
                return Err(if reader.answered_absent.load(Ordering::Relaxed) {
                    RestoreError::BundleAbsent
                } else {
                    RestoreError::Read(error)
                });
            }
            Err(other) => return Err(RestoreError::Recovery(Box::new(other))),
        };

        // 3. One archive.
        let archive_id = choose_archive(&material, &origin, archive, source.as_ref()).await?;
        let checkpoint = material.checkpoint(archive_id).cloned();
        let publication = source
            .generation(archive_id, checkpoint.as_ref())
            .await?
            .ok_or_else(|| match &checkpoint {
                Some(checkpoint) => RestoreError::NothingAsNewAsTheCheckpoint {
                    checkpoint: checkpoint.backup_generation.get(),
                },
                None => RestoreError::NoGeneration,
            })?;

        // 4. The publication, before an object is read.
        let expectation = match &checkpoint {
            Some(checkpoint) => {
                GenerationExpectation::Checkpoint(CheckpointSource::RecoveryBundle, checkpoint)
            }
            None => GenerationExpectation::Unverified,
        };
        let verified = verify_publication(
            &publication,
            archive_id,
            &material.trusted_writers,
            expectation,
        )
        .map_err(RestoreError::Publication)?;
        let descriptor = &publication.payload.descriptor;
        let manifest_limit = stream::encrypted_len(MAX_MANIFEST_PAYLOAD_LEN) as u64;
        let declared = descriptor.encrypted_manifest.encrypted_len.get();
        if declared > manifest_limit {
            return Err(RestoreError::ManifestTooLarge {
                declared,
                limit: manifest_limit,
            });
        }

        // 5. The manifest, then the plan.
        let recipient = seed
            .recipient()
            .map_err(|error| RestoreError::Seed(Shown::crypto(&error)))?;
        drop(seed);
        let reader_key_id = ArchiveReader::Recovery(&recipient).key_id();
        let wrap = kr_crypto::archive::manifest_wrap_for(descriptor, &reader_key_id)
            .ok_or(RestoreError::NoWrap)?;
        let sender = material
            .producer(wrap.context.sender_key_id)
            .ok_or(RestoreError::NoProducer)?
            .stored_envelope_key;
        let encrypted_manifest = read_whole(
            source.as_ref(),
            archive_id,
            descriptor.encrypted_manifest.object_id,
            declared,
        )
        .await?;
        let descriptor_bytes =
            kr_cbor::to_canonical_vec(descriptor).map_err(|_| RestoreError::Range)?;
        let open = open_archive(
            &ArchiveReader::Recovery(&recipient),
            &sender,
            &material.trusted_writers,
            &ArchiveExpectation {
                archive_id,
                generation: expectation,
            },
            &descriptor_bytes,
            &encrypted_manifest,
        )
        .map_err(|error| RestoreError::Archive(Shown::crypto(&error)))?;
        if open.manifest().writer_key_id != publication.payload.writer_key_id {
            return Err(RestoreError::ManifestWriter);
        }
        let objects = open.objects();
        if objects.len() > MAX_MANIFEST_OBJECTS {
            return Err(RestoreError::TooManyMembers {
                count: objects.len(),
                limit: MAX_MANIFEST_OBJECTS,
            });
        }
        let members = plan_members(
            &objects
                .iter()
                .map(|entry| {
                    (
                        entry.object.object_id,
                        entry.filename.clone(),
                        entry.object.encrypted_len.get(),
                    )
                })
                .collect::<Vec<_>>(),
        );
        let plan = RestorePlan {
            origin: service.origin,
            archive_id,
            generation: descriptor.backup_generation,
            manifest_hash: descriptor.encrypted_manifest.encrypted_object_hash,
            writer: publication.payload.writer_key_id,
            standing: verified,
            bundle_revision: material.bundle_revision,
            published_at_ms: publication.payload.published_at_ms,
            members,
        };
        Ok(PreparedRestore {
            plan,
            open,
            recipient,
            sender,
            source,
        })
    }
}

/// Whether `text` is an identifier in its canonical lowercase spelling.
fn is_an_identifier(text: &str) -> bool {
    text.len() == 36
        && text.char_indices().all(|(at, character)| match at {
            8 | 13 | 18 | 23 => character == '-',
            _ => character.is_ascii_digit() || ('a'..='f').contains(&character),
        })
}

/// The kit's own text for the configured origin.
///
/// A gateway origin has one canonical spelling, so the configured origin and the kit's entry for it
/// are the same text. The bundle key is derived from that text byte for byte, so a kit that spells
/// the origin another way names a service this host is not configured for.
fn kit_origin_for(kit: &RecoveryKit, configured: &str) -> Option<String> {
    GatewayOrigin::new(configured).ok()?;
    kit.service_origins
        .iter()
        .find(|named| named.as_str() == configured)
        .cloned()
}

/// The archive to restore, from the entries of the authenticated bundle that name the configured
/// origin.
async fn choose_archive(
    material: &TrustedMaterial,
    origin: &str,
    asked: Option<ArchiveId>,
    source: &dyn RestoreSource,
) -> Result<ArchiveId, RestoreError> {
    let mut archives: Vec<ArchiveId> = Vec::new();
    for CollectionLocator {
        service_origin,
        archive_id,
        ..
    } in &material.collections
    {
        if service_origin == origin && !archives.contains(archive_id) {
            archives.push(*archive_id);
        }
    }
    if let Some(asked) = asked {
        return if archives.contains(&asked) {
            Ok(asked)
        } else {
            Err(RestoreError::ArchiveNotListed)
        };
    }
    match archives.as_slice() {
        [] => Err(RestoreError::NoArchive),
        [only] => Ok(*only),
        several => {
            let mut candidates = Vec::with_capacity(several.len());
            for archive_id in several {
                let checkpoint = material.checkpoint(*archive_id);
                let newest = match source.generation(*archive_id, checkpoint).await? {
                    None => CandidateState::Nothing,
                    Some(publication) => {
                        let expectation =
                            checkpoint.map_or(GenerationExpectation::Unverified, |checkpoint| {
                                GenerationExpectation::Checkpoint(
                                    CheckpointSource::RecoveryBundle,
                                    checkpoint,
                                )
                            });
                        match verify_publication(
                            &publication,
                            *archive_id,
                            &material.trusted_writers,
                            expectation,
                        ) {
                            Ok(_) => CandidateState::Newest(CandidateGeneration {
                                generation: publication.payload.descriptor.backup_generation,
                                published_at_ms: publication.payload.published_at_ms,
                                writer: publication.payload.writer_key_id,
                            }),
                            Err(refusal) => CandidateState::Refused(refusal),
                        }
                    }
                };
                candidates.push(Candidate {
                    archive_id: *archive_id,
                    newest,
                });
            }
            Err(RestoreError::SeveralArchives {
                count: candidates.len(),
                candidates,
            })
        }
    }
}

/// Verifies a publication the way a restore does before it reads an object, and says where the
/// generation stands against the checkpoint.
fn verify_publication(
    publication: &BackupGenerationPublication,
    archive_id: ArchiveId,
    writers: &[TrustedWriter],
    expectation: GenerationExpectation<'_>,
) -> Result<RestoreGeneration, PublicationRefusal> {
    let payload = &publication.payload;
    let descriptor_len =
        kr_cbor::to_canonical_vec(&payload.descriptor).map_or(usize::MAX, |bytes| bytes.len());
    payload
        .descriptor
        .validate(descriptor_len)
        .map_err(PublicationRefusal::Structure)?;
    if payload.descriptor.archive_id != archive_id {
        return Err(PublicationRefusal::OtherArchive);
    }
    let writer = writers
        .iter()
        .find(|writer| writer.writer_key_id == payload.writer_key_id)
        .ok_or(PublicationRefusal::WriterNotInBundle)?;
    let own_id = kr_crypto::keys::key_id(
        kr_protocol::pairing::KeyPurpose::Authorisation,
        writer.signing_key.as_bytes(),
    );
    if own_id != writer.writer_key_id {
        return Err(PublicationRefusal::WriterKeyMismatch);
    }
    let input = payload
        .signing_input()
        .map_err(|_| PublicationRefusal::BadSignature)?;
    let transcript = SigningTranscript::from_canonical_bytes(BACKUP_PUBLICATION_DOMAIN, input)
        .map_err(|_| PublicationRefusal::BadSignature)?;
    kr_crypto::sign::verify(&writer.signing_key, &transcript, &publication.signature)
        .map_err(|_| PublicationRefusal::BadSignature)?;
    let standing = RestoreGeneration::against(&payload.descriptor, expectation);
    if !standing.is_admissible() {
        let told = Shown::restore_standing(&standing);
        return Err(PublicationRefusal::Generation(standing, told));
    }
    Ok(standing)
}
