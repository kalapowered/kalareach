//! Encrypted settings sync: what travels, what a comparison decides, and what privacy mode stops.
//!
//! Section 18 bullet 5 names one feature: *encrypted settings sync, optional history backups and
//! recovery material*. [`StorageFeature`] is that feature, said plainly, so a person is told what
//! each part needs rather than finding out by its absence. This module builds the first part.
//!
//! Section 20 fixes how it works. An object is encrypted before it is stored, it is written by
//! compare and swap against a per-object revision, and a write that loses the comparison is kept
//! for the person to choose from rather than resolved by whichever clock was further ahead.
//!
//! What this module does **not** hold is authority. There is no kind for host grants or revocation
//! state, no body variant that names either, and no handle from here to any authority store. A
//! setting is text, a number or a switch, which narrows the shape and not the bytes: anything can
//! be written into text. What keeps a restore away from authority is that nothing here interprets
//! a setting as authority and nothing here can reach a store that holds any.
//!
//! # What may be synchronised, and what may not
//!
//! [`kr_protocol::sync::SyncObjectKind`] is settings, drafts, a client's own position and the
//! recovery bundle, which [`crate::recovery::BundleStore`] writes and this module never does. The
//! set is closed, and what it leaves out is as load bearing as what it holds: host grants and
//! revocation state have one host authority, so no kind names them and restoring a synchronised
//! object can never reach them. This client makes that as structural as a client can. [`SyncBody`]
//! has a variant for settings and one for a client's position and **no variant for anything else**,
//! nothing here reads a setting as authority, and nothing here holds a handle to any authority
//! store. A setting's value is text, a number or a switch, which narrows the shape and not the
//! bytes.
//!
//! Drafts are synchronised as drafts, by [`crate::drafts::DraftSync`], which is the device's own
//! draft store publishing its own records. A draft that arrived through this module would be a
//! second way to write one, so an object that says it is a draft is refused here and named for
//! where it belongs. Nothing in either path submits: [`crate::drafts::Draft::submission`] answers
//! a question and performs nothing, and there is no call from here to a host at all.
//!
//! What the two halves share is the account. A draft publication keeps its one record in the
//! [`SyncStore`] beside the settings, and is settled by the same rule, so the barrier, the fence
//! and privacy mode's cleanup have one implementation and [`SyncClient::outstanding`] counts a
//! draft that has left without an answer the way it counts a setting.
//!
//! # One object, one collection
//!
//! A collection holds one object, for the reason [`crate::drafts::draft_collection`] gives: the
//! comparison is per object, and two settings changed on two devices are not a conflict unless
//! they are the same setting.
//!
//! # Modules
//!
//! | Module | What it holds |
//! | --- | --- |
//! | [`store`] | This device's own sync state on disk: one record of each publication request, checkpoints, conflict copies, pinned labels and the records of what has left |
//! | [`client`] | The compare-and-swap client, and the privacy operations the host drives it through |
//! | [`keys`] | The key a collection is sealed under, where a device keeps it, and the sealing itself |
//! | [`membership`] | Who holds a shared collection's key, and what this device does when that changes |

pub mod client;
pub mod keys;
pub mod membership;
pub mod store;

use std::collections::{BTreeMap, BTreeSet};

use kr_protocol::ids::{DeviceId, EnvironmentId, SessionId, SyncObjectId, SyncRevisionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};
use kr_protocol::sync::{MAX_SYNC_OBJECT_PLAINTEXT_BYTES, SyncObjectKind};
use serde::{Deserialize, Serialize};

pub use client::{
    Cancelled, Exported, Fenced, KeptExplicitly, Published, Reconciled, Removed, Resolutions,
    Resolved, Restored, Resumed, SyncClient, fresh_object_id, fresh_revision,
};
pub use keys::{CollectionKeys, CollectionSealer, MemoryCollectionKeys, StoredCollectionKeys};
pub use store::{
    Across, Attempt, Basis, Claimed, ConflictCopy, Crossing, Dispatch, End, Fetched, InGeneration,
    Listing, Outcome, PinnedLabel, PrivacyRecord, Publication, RequestRecord, RequestRevision,
    RequestState, Result, Settled, Settlement, Standing, SyncCheckpoint, SyncError, SyncStore,
    WhatLeft,
};

/// What section 18 bullet 5 offers, part by part.
///
/// Naming the parts is the point. A person who is told that settings sync is on, that history
/// backups are a separate choice and that recovery material is what makes a restore possible
/// without another device knows what they have; one who is shown a single switch does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StorageFeature {
    /// Encrypted settings sync: this module.
    SettingsSync,
    /// Optional history backups.
    HistoryBackups,
    /// Recovery material: the seed and bundle a restore without another device needs.
    RecoveryMaterial,
}

impl StorageFeature {
    /// Every part, in the order section 18 states them.
    pub const ALL: [Self; 3] = [
        Self::SettingsSync,
        Self::HistoryBackups,
        Self::RecoveryMaterial,
    ];

    /// Returns the stable name this part is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SettingsSync => "encrypted settings sync",
            Self::HistoryBackups => "history backups",
            Self::RecoveryMaterial => "recovery material",
        }
    }

    /// Returns whether this part is something a person chooses to have.
    ///
    /// History backups and recovery material both are: section 18 says so of backups and section 20
    /// says so of the recovery seed. Settings sync is the feature itself, so there is nothing left
    /// of it to turn off.
    #[must_use]
    pub const fn is_optional(self) -> bool {
        matches!(self, Self::HistoryBackups | Self::RecoveryMaterial)
    }

    /// Returns what a person does without this part.
    #[must_use]
    pub const fn alternative(self) -> &'static str {
        match self {
            Self::SettingsSync => "set each device up the way you want it",
            Self::HistoryBackups => "keep nothing beyond what each device retains",
            Self::RecoveryMaterial => "restore from another device you have paired",
        }
    }
}

/// One synchronised object, as it travels.
///
/// The record names which object it is and what revision it is. A reader checks the identity and
/// the kind against the collection it asked for; the revision is what it compares with its own to
/// see whether the two devices hold the same content, not something it asked the service for.
/// Sealing says the bytes came from a device that holds the key; it does not say they belong where
/// they were found.
///
/// It carries no collection of its own, because [`sync_collection`] derives the collection from the
/// kind and the identity. A second statement of the same fact would be a second thing to check and
/// a second thing to disagree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncObject {
    /// Its own identity, which is stable across every revision of it.
    pub object_id: SyncObjectId,
    /// The revision this content is.
    ///
    /// A fresh 128-bit value for every write, never a counter: an object removed and written again
    /// would pass through revisions it has already had, and a device holding an old revision of the
    /// earlier object would win a comparison it should lose.
    pub revision: SyncRevisionId,
    /// The device that wrote it.
    pub device_id: DeviceId,
    /// When that device wrote it.
    ///
    /// It is shown to a person choosing between conflicting copies. It decides nothing: section 20
    /// keeps both copies rather than taking whichever clock was further ahead.
    pub updated_at_ms: TimestampMs,
    /// What it carries.
    pub body: SyncBody,
}

impl SyncObject {
    /// Returns which kind of object this is.
    #[must_use]
    pub const fn kind(&self) -> SyncObjectKind {
        self.body.kind()
    }
}

/// What one synchronised object carries.
///
/// Two variants for the three kinds section 20 admits, and the missing one is the point: a draft
/// belongs to the device's draft store and travels through [`crate::drafts::DraftSync`], so there
/// is no value of this type that is a draft and no code here that could turn one into anything.
/// Host grants and revocation state are not kinds at all, so no restore can reach them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SyncBody {
    /// Application settings and preferences.
    Settings(SyncSettings),
    /// Which session this client was looking at, and where.
    ClientSelection(ClientSelection),
}

impl SyncBody {
    /// Returns the protocol kind this body is.
    #[must_use]
    pub const fn kind(&self) -> SyncObjectKind {
        match self {
            Self::Settings(_) => SyncObjectKind::Settings,
            Self::ClientSelection(_) => SyncObjectKind::ClientSelection,
        }
    }
}

/// The settings a person's devices keep in step.
///
/// The values are a closed set of scalars: a setting is a preference, and a preference is text, a
/// number or a switch. That is a narrowing rather than a guarantee about the bytes, because text is
/// text and anything can be written into it. What keeps a restored settings object away from
/// authority is that nothing here reads a setting as authority and the client holds no handle to an
/// authority store: section 20 gives host grants and revocation state one host authority, and there
/// is no kind, no body variant and no code path here that reaches it.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncSettings {
    /// The settings, by their stable names.
    pub values: BTreeMap<String, SettingValue>,
    /// The labels the person pinned.
    ///
    /// Section 24 keeps pinned labels locally unless they are explicitly cleared, and excludes them
    /// from subsequent sync while privacy mode is on. [`SyncClient::settings_to_publish`] is where
    /// that exclusion happens, and the device's own copy is untouched by it.
    pub pinned_labels: BTreeSet<String>,
}

impl std::fmt::Debug for SyncSettings {
    /// How many settings and labels there are, never what they say.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SyncSettings")
            .field("values", &self.values.len())
            .field("pinned_labels", &self.pinned_labels.len())
            .finish()
    }
}

/// One setting's value.
///
/// The set is closed. A person's preference is one of these three things, and a shape that admitted
/// anything else would be a shape a restore could smuggle something through.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SettingValue {
    /// Text the person chose or typed.
    Text(String),
    /// A whole number.
    Number(U64),
    /// A switch.
    Flag(bool),
}

impl std::fmt::Debug for SettingValue {
    /// What kind of value it is, never the value: a setting is what a person chose.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text(text) => formatter
                .debug_struct("Text")
                .field("bytes", &text.len())
                .finish(),
            Self::Number(_) => formatter.write_str("Number"),
            Self::Flag(_) => formatter.write_str("Flag"),
        }
    }
}

/// Where a client was looking.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSelection {
    /// The environment it had selected, when it had one.
    pub environment_id: Nullable<EnvironmentId>,
    /// The session it was looking at, when it was looking at one.
    pub session_id: Nullable<SessionId>,
    /// How far back from the newest row the view was, in rows.
    ///
    /// A position rather than an absolute row: the row a device is on means nothing on another
    /// device, whose history reaches back a different distance.
    pub rows_from_newest: U64,
}

impl ClientSelection {
    /// Returns a selection that names nothing, which is where a client starts.
    #[must_use]
    pub const fn nothing_selected() -> Self {
        Self {
            environment_id: Nullable::null(),
            session_id: Nullable::null(),
            rows_from_newest: U64::new(0),
        }
    }
}

/// A buffer of plaintext this library owns, cleared when it goes out of scope.
///
/// A statement that clears a buffer is skipped by an early return and by an unwinding panic. This
/// is not: dropping it clears it, on every path out. It covers the buffers this crate allocates
/// itself; the intermediate value trees the encoder builds belong to the crate that owns the
/// encoder, and the cryptography reference records that.

pub(crate) struct Zeroising(pub Vec<u8>);

impl std::fmt::Debug for Zeroising {
    /// How many bytes it holds. Never the bytes, which are a plaintext.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Zeroising")
            .field("0", &self.0.len())
            .finish()
    }
}

impl Drop for Zeroising {
    fn drop(&mut self) {
        kr_crypto::zeroise(&mut self.0);
    }
}

/// Returns the collection one synchronised object is stored in.
///
/// One object per collection, because the comparison is per object. The kind is in the name so a
/// service can answer a read for one kind, which is the whole of what section 20 lets it know
/// about an object it cannot read.
#[must_use]
pub fn sync_collection(kind: SyncObjectKind, object_id: SyncObjectId) -> String {
    format!("{kind}/{object_id}")
}

/// The most a synchronised object's plaintext may carry, in bytes.
///
/// It is [`kr_protocol::sync::MAX_SYNC_OBJECT_PLAINTEXT_BYTES`], and it applies to the encoded
/// record rather than to any one value inside it.
pub const MAX_OBJECT_BYTES: u64 = MAX_SYNC_OBJECT_PLAINTEXT_BYTES;
