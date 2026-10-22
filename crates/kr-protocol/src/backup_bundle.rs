//! `backup.bundle.write`: moving the recovery bundle on by one compare-and-swap.
//!
//! A restore that has verified a generation records it in the bundle, so that the next restore can
//! tell a service that replays an older archive. The restore holds the recovery kit, so it seals the
//! bundle; the control daemon holds the account the service is written with, so it is the one that
//! reaches the service, as a relay of ciphertext. It never sees the seed or the bundle's content.
//!
//! The method is served on the local socket alone and asks for host management. It only moves a
//! bundle that is there on: the call names the place it was read at, and a service that holds the
//! bundle somewhere else answers that, so a write never replaces a change it did not read. A
//! bundle is made once, by `backup.enable`.
//!
//! The daemon keeps no record of a write. A call whose answer was lost is not settled by the
//! daemon: the caller reads the bundle again and writes from what it finds.
//!
//! The bundle is key material (collection locators, trusted writer keys, generation checkpoints),
//! not content, so the call is not refused while privacy mode is on, as `backup.enable` is not; the
//! restore that makes it has refused to run under privacy mode before it does. The call sends
//! nothing while the service has asked to be left alone.

use core::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::scalars::{Bytes, Nullable, TimestampMs, U64, Uuid};

/// A place in the bundle's order at the service: where a read found it, or where a write left it.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupBundlePlace {
    /// This write's place in the collection's order. The first is one.
    pub write_sequence: U64,
    /// The name the service gave this write.
    pub revision: Nullable<Uuid>,
    /// The history the place is in: the recovery the answer named, or null for a service never put
    /// back.
    pub recovery: Nullable<Uuid>,
}

impl fmt::Debug for BackupBundlePlace {
    /// The place in the order, which is public.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupBundlePlace")
            .field("write_sequence", &self.write_sequence)
            .finish_non_exhaustive()
    }
}

/// Parameters of `backup.bundle.write`: one write of the sealed bundle at its locator.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BackupBundleWriteParams {
    /// The locator the recovery kit prints.
    pub locator: Uuid,
    /// The place the bundle was read at. The write replaces the bundle only if it is still there.
    pub expected: BackupBundlePlace,
    /// The identity the write goes out under. A new write has a new identity.
    pub request_id: Uuid,
    /// The instant the caller signed the write at, in UTC milliseconds, which the service measures
    /// freshness against.
    pub signed_at_ms: TimestampMs,
    /// The sealed bundle, at most as large as any sealed bundle may be.
    pub sealed_bundle: Bytes,
}

impl fmt::Debug for BackupBundleWriteParams {
    /// Which place the write compares against. Never the locator or the bundle.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupBundleWriteParams")
            .field("expected", &self.expected)
            .finish_non_exhaustive()
    }
}

/// What `backup.bundle.write` answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupBundleWriteResult {
    /// The service applied the write, and the bundle is now at this place.
    Written {
        /// Where the write left the bundle.
        place: BackupBundlePlace,
    },
    /// The service compared and the bundle is not at the place the call named; nothing was
    /// written.
    Conflict {
        /// Where the bundle stood when the refusal was answered, when the service said.
        current: Nullable<BackupBundlePlace>,
    },
    /// The service asked to be left alone, and nothing was sent: ask again after this long.
    Wait {
        /// Seconds until the service may be asked again.
        retry_after_seconds: U64,
    },
}
