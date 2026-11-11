//! The rows of an invocation's journal: what each says, in a form that reads back the same.
//!
//! A row is written, durable, before the step it protects, so that whatever happened after a crash
//! is told by the rows that reached the file and by none that did not. Each row is JSON, framed by
//! [`super::framing`]. The file belongs to one invocation, so no row repeats its identity but the
//! first.

use serde::{Deserialize, Serialize};

use crate::filekey::FileKey;

/// What kind of object a row names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// A file.
    File,
    /// A directory.
    Directory,
}

/// Which of the two release rules a recorded transition applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    /// The owner rule: the object was made by the invocation, so its owner and list are replaced.
    Owner,
    /// The group rule: only the entries that name the invocation's group are removed.
    Group,
}

/// What the release does with a mandatory label on an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    /// The object's label stays as it is.
    Keep,
    /// The label is removed.
    Remove,
}

/// Why a snapshot of the repository was taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    /// Taken when the invocation held the tree.
    Initial,
    /// Taken by the end check when it found a difference.
    Changed,
}

/// What a leftover blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeftoverClass {
    /// An object of the person's files that the release could not finish: blocks the tree's slot.
    Tree,
    /// Changes in the Git directory that the operation did not make: blocks the tree's slot.
    Repository,
    /// The end of the invocation is not proved: blocks the tree's slot.
    Uncertain,
    /// An object of the private root that the removal could not delete: blocks only that root.
    Root,
}

impl LeftoverClass {
    /// Whether a leftover of this class keeps the tree's slot.
    #[must_use]
    pub fn holds_the_slot(self) -> bool {
        !matches!(self, LeftoverClass::Root)
    }
}

/// A file the end check digests: a hook or the attributes file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestedFile {
    /// The name, relative to the Git directory.
    pub name: String,
    /// The file's identity.
    pub key: FileKey,
    /// Its size in bytes.
    pub size: u64,
    /// The SHA-256 of its content, in hex.
    pub sha256: String,
}

/// Bytes that read in JSON as one string of hex, so that a row stays one readable line.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        hex::decode(&text).map_err(serde::de::Error::custom)
    }
}

/// One row of an invocation's journal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "row")]
pub enum Row {
    /// The invocation began: its identity, the boot it began in and what it holds.
    Begin {
        /// The invocation's identifier, in hex.
        invocation: String,
        /// The boot marker when the invocation began.
        boot_marker: String,
        /// The logon session of the invocation's token.
        session_luid: u64,
        /// The invocation's group.
        group_sid: String,
        /// The client's account.
        client_sid: String,
        /// The client's process and when it started, which together name it.
        client_pid: u32,
        /// The client process's creation time.
        client_creation_time: u64,
        /// The identity of each directory from the volume's root to the tree's root.
        chain: Vec<FileKey>,
        /// The tree's path as the client gave it, for the person's messages.
        tree_path: String,
    },
    /// What the repository's Git directory held at one moment, for the end check to compare with.
    RepositorySnapshot {
        /// The snapshot's number, from one.
        id: u32,
        /// Why it was taken.
        kind: SnapshotKind,
        /// The SHA-256 of the `config` file, in hex.
        config_digest: String,
        /// Every hook.
        hooks: Vec<DigestedFile>,
        /// The `info\attributes` file, when there is one.
        info_attributes: Option<DigestedFile>,
        /// The names that must be absent from the Git directory.
        absent_names: Vec<String>,
    },
    /// The private root is about to be made at this path.
    RootIntent {
        /// The root's path.
        path: String,
    },
    /// The private root was made.
    RootMade {
        /// The root's path.
        path: String,
        /// The root's identity.
        key: FileKey,
    },
    /// An object that existed before the grant, as it was, written before the grant changes it.
    Grant {
        /// The object's identity.
        key: FileKey,
        /// The object's path when it was seen.
        path: String,
        /// What kind of object it is.
        kind: ObjectKind,
        /// Its owner.
        owner: String,
        /// Its whole permission list, as the platform stores it.
        #[serde(with = "hex_bytes")]
        dacl_bytes: Vec<u8>,
        /// The descriptor's control flags.
        control_flags: u16,
        /// Whether its list took nothing from the parent.
        protected: bool,
        /// How many names the object had.
        link_count: u32,
        /// The entry the grant adds.
        added_ace: String,
    },
    /// Every object of the grant has its row, and the grant is complete.
    GrantComplete {
        /// How many objects the grant covered.
        count: u64,
    },
    /// The primary child exists, suspended, and is about to be resumed.
    ProcessStarted {
        /// Its process identifier.
        pid: u32,
        /// Its creation time, which names the process with the identifier.
        creation_time: u64,
    },
    /// The job ended.
    JobEnded,
    /// The end of the invocation is not proved.
    EndUncertain {
        /// Why.
        reason: String,
    },
    /// What the release is about to write on an object, so that a replay applies the recorded
    /// transition instead of working it out again from the object's current owner.
    ReleaseIntent {
        /// The object's identity.
        key: FileKey,
        /// The rule.
        rule: Rule,
        /// The owner the object gets, when the rule is the owner rule.
        new_owner: Option<String>,
        /// The permission list the object gets.
        #[serde(with = "hex_bytes")]
        new_dacl_bytes: Vec<u8>,
        /// What happens to its label.
        label: Label,
        /// Whether the object's list is protected from inheritance after the write.
        protected_target: bool,
    },
    /// The release wrote the object.
    ObjectReleased {
        /// The object's identity.
        key: FileKey,
        /// What happened.
        outcome: String,
    },
    /// The release is verified: every object is as the rows say it should be.
    ReleaseVerified {
        /// How many objects the release covered.
        objects: u64,
        /// How many leftovers there are: none, or this row is not written.
        leftovers: u32,
    },
    /// The private root was removed.
    RootRemoved,
    /// Something could not be finished. It is durable before any row that says the invocation ended.
    Leftover {
        /// The object, as a path or an identity in text.
        object: String,
        /// Why.
        reason: String,
        /// What it blocks.
        class: LeftoverClass,
        /// The snapshot a repository leftover names.
        snapshot: Option<u32>,
    },
    /// The person accepted the repository's changed state: from now on that snapshot is the tree's
    /// baseline.
    AcceptedState {
        /// The snapshot the leftover named.
        snapshot: u32,
        /// The person's account.
        person: String,
        /// When, in the platform's file time.
        time: u64,
    },
    /// A leftover was cleared.
    LeftoverCleared {
        /// The object the leftover named.
        key: String,
    },
    /// The invocation ended and its tree's slot is free.
    End {
        /// How many leftovers of the private root the sweep still carries.
        root_leftovers: u32,
    },
}

impl Row {
    /// The row as the bytes that are framed.
    ///
    /// # Panics
    ///
    /// Never: every field of every row serialises.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a row serialises")
    }

    /// Reads a row back.
    ///
    /// # Errors
    ///
    /// Returns an error when the bytes are not a row.
    pub fn from_bytes(bytes: &[u8]) -> Result<Row, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}
