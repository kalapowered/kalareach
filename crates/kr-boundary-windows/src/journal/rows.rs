//! The rows of an invocation's journal: what each says, in a form that reads back the same.
//!
//! A row is written, durable, before the step it protects, so that whatever happened after a crash
//! is told by the rows that reached the file and by none that did not. Each row is JSON, framed by
//! [`super::framing`]. The file belongs to one invocation, so no row repeats its identity but the
//! first.

use serde::{Deserialize, Serialize};

use crate::filekey::FileKey;

use super::limits;

/// The name of an invocation's private root, one directory directly under the broker's `run`
/// directory: exactly 32 lowercase hexadecimal digits.
///
/// A row records this name and never a path, so a recovery that acts on a row can only open that
/// one name relative to the `run` directory it holds.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RootName(String);

/// Text that is not a private root's name.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[error("a private root's name is 32 lowercase hexadecimal digits")]
pub struct RootNameError;

impl RootName {
    /// How many digits a name has.
    pub const DIGITS: usize = 32;

    /// Checks that the text is exactly 32 lowercase hexadecimal digits.
    ///
    /// # Errors
    ///
    /// Returns [`RootNameError`] for any other text.
    pub fn parse(text: &str) -> Result<RootName, RootNameError> {
        if text.len() == Self::DIGITS
            && text
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            Ok(RootName(text.to_owned()))
        } else {
            Err(RootNameError)
        }
    }

    /// The name that 16 bytes make.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> RootName {
        RootName(hex::encode(bytes))
    }

    /// The name's digits.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for RootName {
    type Error = RootNameError;

    fn try_from(text: String) -> Result<RootName, RootNameError> {
        RootName::parse(&text)
    }
}

impl From<RootName> for String {
    fn from(name: RootName) -> String {
        name.0
    }
}

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
    /// The private root is about to be made under this name in the `run` directory.
    RootIntent {
        /// The root's name.
        name: RootName,
    },
    /// The private root was made.
    RootMade {
        /// The root's name.
        name: RootName,
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
        /// The object, as a path or an identity in text. A `Tree` leftover for an object that a
        /// `Grant` row recorded names it by that row's path or by its key as the key prints.
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

/// A kind of row, without its fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    /// [`Row::Begin`].
    Begin,
    /// [`Row::RepositorySnapshot`].
    RepositorySnapshot,
    /// [`Row::RootIntent`].
    RootIntent,
    /// [`Row::RootMade`].
    RootMade,
    /// [`Row::Grant`].
    Grant,
    /// [`Row::GrantComplete`].
    GrantComplete,
    /// [`Row::ProcessStarted`].
    ProcessStarted,
    /// [`Row::JobEnded`].
    JobEnded,
    /// [`Row::EndUncertain`].
    EndUncertain,
    /// [`Row::ReleaseIntent`].
    ReleaseIntent,
    /// [`Row::ObjectReleased`].
    ObjectReleased,
    /// [`Row::ReleaseVerified`].
    ReleaseVerified,
    /// [`Row::RootRemoved`].
    RootRemoved,
    /// [`Row::Leftover`].
    Leftover,
    /// [`Row::AcceptedState`].
    AcceptedState,
    /// [`Row::LeftoverCleared`].
    LeftoverCleared,
    /// [`Row::End`].
    End,
}

impl RowKind {
    /// The most bytes a row of this kind takes encoded, before it is framed.
    #[must_use]
    pub const fn max_encoded(self) -> usize {
        match self {
            RowKind::Begin => limits::BEGIN_MAX,
            RowKind::RepositorySnapshot => limits::SNAPSHOT_MAX,
            RowKind::RootIntent | RowKind::RootMade | RowKind::RootRemoved => limits::ROOT_MAX,
            RowKind::Grant => limits::GRANT_MAX,
            RowKind::GrantComplete
            | RowKind::ProcessStarted
            | RowKind::JobEnded
            | RowKind::ReleaseVerified
            | RowKind::End => limits::SMALL_MAX,
            RowKind::EndUncertain => limits::UNCERTAIN_MAX,
            RowKind::ReleaseIntent => limits::INTENT_MAX,
            RowKind::ObjectReleased => limits::RELEASED_MAX,
            RowKind::Leftover => limits::LEFTOVER_MAX,
            RowKind::AcceptedState => limits::ACCEPTED_MAX,
            RowKind::LeftoverCleared => limits::CLEARED_MAX,
        }
    }
}

impl Row {
    /// What kind of row this is.
    #[must_use]
    pub fn kind(&self) -> RowKind {
        match self {
            Row::Begin { .. } => RowKind::Begin,
            Row::RepositorySnapshot { .. } => RowKind::RepositorySnapshot,
            Row::RootIntent { .. } => RowKind::RootIntent,
            Row::RootMade { .. } => RowKind::RootMade,
            Row::Grant { .. } => RowKind::Grant,
            Row::GrantComplete { .. } => RowKind::GrantComplete,
            Row::ProcessStarted { .. } => RowKind::ProcessStarted,
            Row::JobEnded => RowKind::JobEnded,
            Row::EndUncertain { .. } => RowKind::EndUncertain,
            Row::ReleaseIntent { .. } => RowKind::ReleaseIntent,
            Row::ObjectReleased { .. } => RowKind::ObjectReleased,
            Row::ReleaseVerified { .. } => RowKind::ReleaseVerified,
            Row::RootRemoved => RowKind::RootRemoved,
            Row::Leftover { .. } => RowKind::Leftover,
            Row::AcceptedState { .. } => RowKind::AcceptedState,
            Row::LeftoverCleared { .. } => RowKind::LeftoverCleared,
            Row::End { .. } => RowKind::End,
        }
    }

    /// Whether every field is within the caps of the journal, with the words for the person when
    /// one is not. A row that fails is never written. The caps limit what may be added: the reader
    /// does not apply them.
    ///
    /// # Errors
    ///
    /// Returns the first field over its cap, or the row over its kind's largest size.
    pub fn check_caps(&self) -> Result<(), String> {
        use limits::{
            ABSENT_NAMES, CHAIN_KEYS, HOOKS, NAME_BYTES, PATH_JSON_BYTES, SID_BYTES, TEXT_BYTES,
            check_list, check_path, check_text,
        };
        let digested =
            |file: &DigestedFile| check_text("a name in a snapshot", &file.name, NAME_BYTES);
        match self {
            Row::Begin {
                invocation,
                boot_marker,
                group_sid,
                client_sid,
                chain,
                tree_path,
                ..
            } => {
                check_text("an invocation's identifier", invocation, TEXT_BYTES)?;
                check_text("the boot marker", boot_marker, TEXT_BYTES)?;
                check_text("a group's identifier", group_sid, SID_BYTES)?;
                check_text("an account's identifier", client_sid, SID_BYTES)?;
                if chain.len() > CHAIN_KEYS {
                    return Err(format!(
                        "the tree is more than {CHAIN_KEYS} directories below the volume's root, which the journal does not record"
                    ));
                }
                check_path(tree_path)?;
            }
            Row::RepositorySnapshot {
                config_digest,
                hooks,
                info_attributes,
                absent_names,
                ..
            } => {
                check_text("a digest", config_digest, 128)?;
                if hooks.len() > HOOKS {
                    return Err(format!(
                        "the repository has more than {HOOKS} hooks, which the journal does not record"
                    ));
                }
                for hook in hooks {
                    digested(hook)?;
                }
                if let Some(file) = info_attributes {
                    digested(file)?;
                }
                if absent_names.len() > ABSENT_NAMES {
                    return Err(format!(
                        "a snapshot names more than {ABSENT_NAMES} absent names, which the journal does not record"
                    ));
                }
                for name in absent_names {
                    check_text("a name in a snapshot", name, NAME_BYTES)?;
                }
            }
            Row::Grant {
                path,
                owner,
                dacl_bytes,
                added_ace,
                ..
            } => {
                check_path(path)?;
                check_text("an owner's identifier", owner, SID_BYTES)?;
                check_list("an object's permission list", dacl_bytes)?;
                check_text("the entry the grant adds", added_ace, TEXT_BYTES)?;
            }
            Row::EndUncertain { reason } => check_text("a reason", reason, TEXT_BYTES)?,
            Row::ReleaseIntent {
                new_owner,
                new_dacl_bytes,
                ..
            } => {
                if let Some(owner) = new_owner {
                    check_text("an owner's identifier", owner, SID_BYTES)?;
                }
                check_list("the permission list a release would write", new_dacl_bytes)?;
            }
            Row::ObjectReleased { outcome, .. } => check_text("an outcome", outcome, TEXT_BYTES)?,
            Row::Leftover { object, reason, .. } => {
                check_text("the name of an object", object, PATH_JSON_BYTES)?;
                check_text("a reason", reason, TEXT_BYTES)?;
            }
            Row::AcceptedState { person, .. } => {
                check_text("a person's identifier", person, SID_BYTES)?;
            }
            Row::LeftoverCleared { key } => {
                check_text("the name of an object", key, PATH_JSON_BYTES)?;
            }
            Row::RootIntent { .. }
            | Row::RootMade { .. }
            | Row::GrantComplete { .. }
            | Row::ProcessStarted { .. }
            | Row::JobEnded
            | Row::ReleaseVerified { .. }
            | Row::RootRemoved
            | Row::End { .. } => {}
        }
        let size = self.to_bytes().len();
        if size > self.kind().max_encoded() {
            return Err(format!(
                "a {:?} row takes {size} bytes, more than the {} bytes the journal allows one",
                self.kind(),
                self.kind().max_encoded()
            ));
        }
        Ok(())
    }

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
