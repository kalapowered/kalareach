//! `backup.status` and `backup.enable`: the owner setting up this host's backups.
//!
//! The command that sets backups up runs in the `kr` process, which makes the recovery seed, prints
//! the kit and seals the bundle. The control daemon holds the account this host is signed in with
//! and the host's own keys, so it is the one that reaches the service. It never sees the seed: what
//! it is given is the recovery recipient's public key, the bundle's locator and the sealed bundle,
//! and what it keeps of them is the public key and a fingerprint of it.
//!
//! * `backup.status` says what a person needs to decide: which service this host is configured for
//!   and whether it holds an account token, whether backups are set up, in progress or not set up
//!   at all, the host's writer and producer by public key and identifier, and what the account
//!   holds at the service.
//! * `backup.enable` writes the bundle to the service, enrols the host's writer for the archive,
//!   turns managed backup storage on, and records the setup, in that order. It is idempotent on the
//!   archive identifier: a call whose answer was lost is made again with the same bytes and is
//!   answered from what the first left.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::backup_read::BackupSignIn;
use crate::error::ErrorCode;
use crate::ids::ArchiveId;
use crate::scalars::{
    AuthorisationKey, Bytes, KeyId, Nullable, StoredEnvelopeKey, TimestampMs, U64, Uuid,
};

/// Parameters of `backup.status`. The environment is the one the connection reaches.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupStatusParams {}

/// Why a setup that exists cannot make backups, and `kr backup setup --replace` is the remedy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackupUnusable {
    /// The account signed in, or the service selected, is not the one the backups belong to.
    Account,
    /// A key this host holds is not the one the setup names.
    Keys,
    /// The writer is not enrolled for the archive any more.
    WriterRetired,
}

/// Where this host's backups stand.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupSetupState {
    /// Backups are not set up on this host.
    None {},
    /// A call to `backup.enable` has not ended. The fingerprint is the one its kit carries.
    InProgress {
        /// The fingerprint of the kit each call that has not ended carries, oldest first.
        kit_fingerprints: Vec<String>,
    },
    /// Backups are set up.
    Committed {
        /// The archive the backups are of.
        archive_id: ArchiveId,
        /// The fingerprint that matches the kit to this host. It is 40 bits, which is enough to
        /// tell a kit from another by eye and not to prove two recipients are one.
        kit_fingerprint: String,
        /// The recovery recipient's public key the setup was made with, which is what tells a
        /// setup under one recovery from a setup under another.
        recovery_public_key: StoredEnvelopeKey,
        /// When the setup was made, in UTC milliseconds.
        enabled_at_ms: TimestampMs,
        /// Why this host cannot make backups now, or null when it can.
        unusable: Nullable<BackupUnusable>,
    },
}

impl fmt::Debug for BackupSetupState {
    /// Where the setup stands. Fingerprints are public and are shown.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None {} => formatter.write_str("None"),
            Self::InProgress { kit_fingerprints } => formatter
                .debug_struct("InProgress")
                .field("kit_fingerprints", kit_fingerprints)
                .finish(),
            Self::Committed {
                archive_id,
                kit_fingerprint,
                unusable,
                ..
            } => formatter
                .debug_struct("Committed")
                .field("archive_id", archive_id)
                .field("kit_fingerprint", kit_fingerprint)
                .field("unusable", unusable)
                .finish_non_exhaustive(),
        }
    }
}

/// How the last call to `backup.enable` ended, when it did not set backups up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupEnableCause {
    /// The host's configuration selects no storage service.
    NoService {},
    /// No account token could be had, for this reason.
    SignIn {
        /// Why.
        sign_in: BackupSignIn,
    },
    /// The host is signed in as another account than the one the call began under.
    AnotherAccount {},
    /// A key this host holds is not the one the call names.
    KeysChanged {},
    /// The sealed bundle is larger than any sealed bundle may be.
    BundleTooLarge {},
    /// Backups are set up for another archive, and the call did not ask to replace them.
    AlreadySetUp {},
    /// This host already records generations of that archive, so it cannot be set up for it again.
    ArchiveInUse {},
    /// The account has no allowance for backup storage.
    NoAllowance {},
    /// The service did not take the account's token as an account's: it answered as if the bundle
    /// were not there.
    TokenNotAccepted {},
    /// The locator already holds another bundle.
    BundleConflict {},
    /// The service refused the write of the bundle, the enrolment of the writer or the change of
    /// retention.
    ServiceRefused {
        /// The service's error code.
        code: ErrorCode,
    },
}

/// What the account holds at the service, as a live read answered it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "read", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupStorageState {
    /// Nothing was asked of the service, for this reason.
    Unread {
        /// Why.
        why: BackupStorageUnread,
    },
    /// The service answered.
    Read {
        /// Whether managed backup storage is on for the account.
        backup_on: bool,
        /// The daily snapshots the account records.
        daily_snapshots: U64,
        /// The allowance in bytes, when the service could read it.
        allowance_bytes: Nullable<U64>,
        /// The bytes the account holds readable.
        held_bytes: U64,
        /// The bytes deleted and still charged.
        deleted_still_charged_bytes: U64,
    },
}

/// Why `backup.status` did not ask the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BackupStorageUnread {
    /// This host holds no account token a read may carry.
    NoToken,
    /// The service asked to be left alone, and the time has not passed.
    Delayed,
    /// The read failed.
    Failed,
}

/// The host's keys a setup names, by identifier and public key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupHostKeys {
    /// The writer's identifier.
    pub writer_key_id: KeyId,
    /// The writer's public key.
    pub writer_public_key: AuthorisationKey,
    /// The producer's identifier.
    pub producer_key_id: KeyId,
    /// The producer's public key.
    pub producer_public_key: StoredEnvelopeKey,
}

/// The last call to `backup.enable` that did not set backups up, kept until the next one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupLastAttempt {
    /// The fingerprint of the kit the call carried.
    pub kit_fingerprint: String,
    /// How it ended: a cause when the daemon confirmed that nothing was recorded, or null when the
    /// outcome was not known.
    pub cause: Nullable<BackupEnableCause>,
}

/// What `backup.status` answers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupStatusResult {
    /// The storage service this host is configured for, or null when it selects none.
    pub service: Nullable<String>,
    /// Whether this host holds an account token a request may carry, and why not when it does not.
    pub sign_in: BackupSignIn,
    /// Whether privacy mode is on.
    pub privacy_mode: bool,
    /// Where the setup stands.
    pub setup: BackupSetupState,
    /// The host's keys, or null when it selects no service.
    pub keys: Nullable<BackupHostKeys>,
    /// What the account holds at the service.
    pub storage: BackupStorageState,
    /// The last call that did not set backups up, if the daemon still holds it.
    pub last_attempt: Nullable<BackupLastAttempt>,
}

impl fmt::Debug for BackupStatusResult {
    /// The parts that name no key and no secret.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupStatusResult")
            .field("sign_in", &self.sign_in)
            .field("privacy_mode", &self.privacy_mode)
            .field("setup", &self.setup)
            .field("storage", &self.storage)
            .finish_non_exhaustive()
    }
}

/// Parameters of `backup.enable`: everything the daemon needs to set backups up, and nothing of the
/// recovery seed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupEnableParams {
    /// The archive the backups are of, chosen by the command. The call is idempotent on it.
    pub archive_id: ArchiveId,
    /// The recovery recipient's public key, which every generation wraps its keys for.
    pub recovery_public_key: StoredEnvelopeKey,
    /// The fingerprint that matches the kit to this host.
    pub kit_fingerprint: String,
    /// The bundle's locator. It is the one kit value that reaches the daemon.
    pub bundle_locator: Uuid,
    /// The sealed bundle, which only the seed opens.
    pub sealed_bundle: Bytes,
    /// The identity the bundle's write goes out under: the same for every repeat of the call.
    pub request_id: Uuid,
    /// The instant the command chose, which the writer's and the producer's entries in the bundle
    /// and the enrolment carry. Every repeat names the same one.
    pub enabled_at_ms: TimestampMs,
    /// The writer the command read from `backup.status` and put in the bundle.
    pub writer_key_id: KeyId,
    /// The producer the command read from `backup.status` and put in the bundle.
    pub producer_key_id: KeyId,
    /// Whether this replaces backups that are set up for another archive.
    pub replace: bool,
}

impl fmt::Debug for BackupEnableParams {
    /// Which archive and which kit. Never the locator or the bundle.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupEnableParams")
            .field("archive_id", &self.archive_id)
            .field("kit_fingerprint", &self.kit_fingerprint)
            .field("replace", &self.replace)
            .finish_non_exhaustive()
    }
}

/// What `backup.enable` answers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupEnableResult {
    /// Backups are set up, by this call or by an earlier one with the same bytes.
    Enabled {
        /// The archive.
        archive_id: ArchiveId,
        /// The fingerprint of the kit that opens it.
        kit_fingerprint: String,
        /// When the setup was made, in UTC milliseconds.
        enabled_at_ms: TimestampMs,
    },
    /// Nothing was recorded on this host, for this cause. The kit opens nothing unless a later
    /// call finishes the setup.
    Declined {
        /// Why.
        cause: BackupEnableCause,
    },
    /// The daemon cannot say how the call ended. Nothing local has changed that a repeat does not
    /// finish: ask again with the same bytes, after the delay if one is named.
    Unknown {
        /// The seconds the service asked to be left alone for, or null.
        retry_after_seconds: Nullable<U64>,
    },
}

impl fmt::Debug for BackupEnableResult {
    /// How the call ended, and the fingerprint, which is public.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enabled {
                kit_fingerprint, ..
            } => formatter
                .debug_struct("Enabled")
                .field("kit_fingerprint", kit_fingerprint)
                .finish_non_exhaustive(),
            Self::Declined { cause } => formatter
                .debug_struct("Declined")
                .field("cause", cause)
                .finish(),
            Self::Unknown { .. } => formatter.debug_struct("Unknown").finish_non_exhaustive(),
        }
    }
}
