//! The messages a person sent to an agent over a channel that confirms nothing, and the records of
//! sends whose outcome nobody could establish, as this device keeps them.
//!
//! A channel message is never a draft: no draft reader lists it, no composer takes it, and drafts
//! synchronisation never sees it, because it lives in a directory of its own beside the drafts.
//! Only the person removes a message, and only a final receipt, "I checked; send anyway" or a keep
//! removes a record of a send that was under way.
//!
//! * **One layout, version 1.** `channel-messages/` holds `<action_id>.message` (the whole text and
//!   what the page needs to show it), `<hold_id>.held` (a send that is under way: no text), the
//!   lock `store.lock` and the names a write stages under. Both kinds are JSON with exactly the
//!   members they name: a file with another `version`, a member more or fewer, or a name that is not
//!   its identity is counted and left, never read or changed, because a later release may own it.
//! * **A keep is durable before it is believed.** The entry is written beside itself, flushed and
//!   renamed into place, and its directory flushed; only then is the draft that held the text owed
//!   its removal, in the ledger the drafts keep, and that is flushed too. A fault at any step is
//!   returned: nothing authorises a draft's removal until the entry is durable.
//! * **One lock order.** The process-wide gate, then the lock file of this store, then the ledger's
//!   gate and lock file. Nothing takes them the other way round.
//! * **The repair is part of every read of the drafts.** An entry that is durable and whose ledger
//!   line is not (a stop between the two writes, another process's fault) is finished by the next
//!   read of the drafts, under the lock, before the page can put a draft in a composer.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use kr_flush::{NameKind, flush_directory};
use kr_protocol::agent::MAX_INLINE_PROMPT_BYTES;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ActionId, AgentBindingRevision, ApplicationInstanceId, EnvironmentId, SessionId,
};
use kr_protocol::scalars::TimestampMs;
use serde::{Deserialize, Serialize};

use crate::drafts::{DiscardParams, DraftDesk, Ledger, Sources, Stored, publish, remove_durably};
use crate::error::{CommandError, Result};

/// The directory the messages are kept in, under an application data directory.
#[must_use]
pub fn kept_in(data: &Path) -> PathBuf {
    data.join("channel-messages")
}

/// The most entries the store holds. A keep that would pass it is refused and nothing is evicted.
pub const MAX_ENTRIES: usize = 10_000;
/// The most bytes the entries take on disk, as encoded.
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
/// The most records of sends under way, counting the ones that can be read.
pub const MAX_HOLDS: usize = 1_000;

/// The bounds a store holds to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// Entries.
    pub entries: usize,
    /// Encoded bytes of the entries.
    pub bytes: u64,
    /// Readable records of sends under way.
    pub holds: usize,
}

impl Limits {
    /// The bounds of a shipped build.
    pub const SHIPPED: Self = Self {
        entries: MAX_ENTRIES,
        bytes: MAX_BYTES,
        holds: MAX_HOLDS,
    };
}

/// Where a step of a store can be made to stop or wait in a test. Compiled to nothing without the
/// `testing` feature.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    /// A keep has read the bounds and has not written the entry.
    AfterCountRead,
    /// A keep's entry is durable and no ledger line has been written.
    AfterEntry,
    /// The ledger is staged and not yet renamed into place. Keyed by the data directory.
    LedgerBeforeRename,
    /// A repair has named what the entries owe and has written nothing.
    RepairNamed,
    /// A keep is about to remove the record of the send it ends.
    HoldRemoval,
    /// A set-aside holds every lock and has read nothing. Keyed by the data directory.
    SetAsideLocked,
    /// A set-aside has copied the ledger and not replaced it. Keyed by the data directory.
    SetAsideCopied,
}

/// Runs the hook a test put at `point` of the store in `directory`, if there is one.
#[doc(hidden)]
pub fn reach(directory: &Path, point: Point) -> std::io::Result<()> {
    #[cfg(feature = "testing")]
    {
        testing::reached(directory, point)
    }
    #[cfg(not(feature = "testing"))]
    {
        let _ = (directory, point);
        Ok(())
    }
}

/// The bounds the store in `directory` holds to.
fn limits_of(directory: &Path) -> Limits {
    #[cfg(feature = "testing")]
    {
        testing::limits_of(directory)
    }
    #[cfg(not(feature = "testing"))]
    {
        let _ = directory;
        Limits::SHIPPED
    }
}

/// What a test acts through: a stop or a wait at a point of a step, lower bounds, a clock. Each is
/// keyed by the directory of the store it was made for, so tests that run together do not see each
/// other's, and each is removed when its guard is dropped.
#[cfg(feature = "testing")]
pub mod testing {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};

    use super::{Limits, Point};

    type Hook = Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>;

    static NEXT: AtomicU64 = AtomicU64::new(1);
    static HOOKS: Mutex<Vec<(u64, PathBuf, Point, Hook)>> = Mutex::new(Vec::new());
    static LIMITS: Mutex<Vec<(u64, PathBuf, Limits)>> = Mutex::new(Vec::new());
    static CLOCKS: Mutex<Vec<(u64, PathBuf, u64)>> = Mutex::new(Vec::new());

    /// Removes what it stands for when it is dropped.
    #[derive(Debug)]
    #[must_use = "what a test put in place goes when this is dropped"]
    pub struct Registered(u64);

    impl Drop for Registered {
        fn drop(&mut self) {
            let id = self.0;
            HOOKS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retain(|(held, ..)| *held != id);
            LIMITS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retain(|(held, ..)| *held != id);
            CLOCKS
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .retain(|(held, ..)| *held != id);
        }
    }

    /// Runs `hook` each time the store in `directory` reaches `point`. An error it returns is the
    /// step's own failure there, as a stop of the process or a refused write would be.
    pub fn at(
        directory: impl Into<PathBuf>,
        point: Point,
        hook: impl Fn() -> std::io::Result<()> + Send + Sync + 'static,
    ) -> Registered {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        HOOKS.lock().unwrap_or_else(PoisonError::into_inner).push((
            id,
            directory.into(),
            point,
            Arc::new(hook),
        ));
        Registered(id)
    }

    /// Holds the store in `directory` to lower bounds.
    pub fn lower_limits(directory: impl Into<PathBuf>, limits: Limits) -> Registered {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        LIMITS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((id, directory.into(), limits));
        Registered(id)
    }

    /// Makes a set-aside of the ledger under `data` read `milliseconds` as the time.
    pub fn clock(data: impl Into<PathBuf>, milliseconds: u64) -> Registered {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        CLOCKS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((id, data.into(), milliseconds));
        Registered(id)
    }

    pub(super) fn reached(directory: &Path, point: Point) -> std::io::Result<()> {
        let hooks: Vec<Hook> = HOOKS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(_, held, at, _)| held == directory && *at == point)
            .map(|(.., hook)| Arc::clone(hook))
            .collect();
        for hook in hooks {
            hook()?;
        }
        Ok(())
    }

    pub(super) fn limits_of(directory: &Path) -> Limits {
        LIMITS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .rev()
            .find(|(_, held, _)| held == directory)
            .map_or(Limits::SHIPPED, |(.., limits)| *limits)
    }

    pub(crate) fn clock_of(data: &Path) -> Option<u64> {
        CLOCKS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .rev()
            .find(|(_, held, _)| held == data)
            .map(|(.., milliseconds)| *milliseconds)
    }
}

// ---- What the page sends and reads ----

/// What the page asks the store for when it reads.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListParams {
    /// Whether the text of each message is wanted. A refresh and a reconciliation read without it.
    #[serde(default)]
    pub with_text: bool,
}

/// A message kept, as the page reads it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredChannelMessage {
    /// The action the message was sent as.
    pub action_id: ActionId,
    /// The record of the send that ended with this message, when there was one.
    pub hold_id: Option<String>,
    /// The page's own identity for the submission.
    pub local_id: String,
    /// The session it was sent to.
    pub session_id: SessionId,
    /// The application it was sent to, when one was known.
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// The binding it was sent against, when one was known.
    pub agent_binding_revision: Option<AgentBindingRevision>,
    /// The host's environment, when one was known.
    pub environment_id: Option<EnvironmentId>,
    /// What the person called the host when it was sent.
    pub host_name: String,
    /// The whole text, only when the read asked for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// When it was sent.
    pub sent_at_ms: TimestampMs,
}

/// The record of a send that was under way, as the page reads it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredHold {
    /// Its identity, which is also its file's name.
    pub hold_id: String,
    /// The action, once the host's answer named one.
    pub action_id: Option<ActionId>,
    /// The page's own identity for the submission.
    pub local_id: String,
    /// The session it was sent to.
    pub session_id: SessionId,
    /// The application it was sent to, when one was known.
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// The binding it was sent against, when one was known.
    pub agent_binding_revision: Option<AgentBindingRevision>,
    /// The host's environment, when one was known.
    pub environment_id: Option<EnvironmentId>,
    /// What the person called the host when it was sent.
    pub host_name: String,
    /// When the press was made.
    pub sent_at_ms: TimestampMs,
    /// The exact references the press wrote: the stored record that held the text.
    pub drafts: Vec<DiscardParams>,
}

/// How many files of one kind could not be read, by cause.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Unreadable {
    /// Files of another layout: another version, a member more or fewer, a name that is not theirs.
    pub layout: usize,
    /// Files that could not be read now, which are tried again at the next read.
    pub now: usize,
}

/// What the store holds, and what it holds to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Used {
    /// Entries, readable or not.
    pub entries: usize,
    /// Bytes of those entries, as encoded.
    pub bytes: u64,
}

/// What the page reads when it opens the store.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelMessageList {
    /// The messages, oldest first.
    pub messages: Vec<StoredChannelMessage>,
    /// The records of sends under way that could be read.
    pub holds: Vec<StoredHold>,
    /// The names of records of this layout whose bytes do not parse, which the person can remove.
    pub damaged_holds: Vec<String>,
    /// Messages that could not be read.
    pub unreadable_messages: Unreadable,
    /// Records of sends under way that could not be read.
    pub unreadable_holds: Unreadable,
    /// What the entries take.
    pub used: Used,
    /// The bounds.
    pub limits: Limits,
}

/// A message to keep.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KeepParams {
    /// The action the message was sent as.
    pub action_id: ActionId,
    /// The record of the send this ends, which is removed with the keep.
    pub hold_id: Option<String>,
    /// The page's own identity for the submission.
    pub local_id: String,
    /// The session it was sent to.
    pub session_id: SessionId,
    /// The application it was sent to, when one was known.
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// The binding it was sent against, when one was known.
    pub agent_binding_revision: Option<AgentBindingRevision>,
    /// The host's environment, when one was known.
    pub environment_id: Option<EnvironmentId>,
    /// What the person called the host.
    pub host_name: String,
    /// The whole text.
    pub text: String,
    /// When it was sent.
    pub sent_at_ms: TimestampMs,
    /// The stored records that held the text: at most two.
    pub drafts: Vec<DiscardParams>,
}

/// What a keep did.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Kept {
    /// Whether the entry was already there, so that this call finished an earlier one.
    pub resumed: bool,
}

/// What to remove: one message, or every message of a session.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RemoveParams {
    /// One message.
    pub action_id: Option<ActionId>,
    /// Every message of one session.
    pub session_id: Option<SessionId>,
}

/// What a removal did.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Removed {
    /// How many entries were removed.
    pub removed: usize,
}

/// A record of a send to make.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HoldCreateParams {
    /// Its identity: 1 to 64 characters of letters, digits and hyphens.
    pub hold_id: String,
    /// The page's own identity for the submission.
    pub local_id: String,
    /// The session the send goes to.
    pub session_id: SessionId,
    /// The application it goes to, when one is known.
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// The binding it is written against, when one is known.
    pub agent_binding_revision: Option<AgentBindingRevision>,
    /// The host's environment, when one is known.
    pub environment_id: Option<EnvironmentId>,
    /// What the person calls the host.
    pub host_name: String,
    /// When the press was made.
    pub sent_at_ms: TimestampMs,
    /// The exact references the press wrote.
    pub drafts: Vec<DiscardParams>,
}

/// The action a record of a send is now known by.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HoldUpdateParams {
    /// The record.
    pub hold_id: String,
    /// The action the host named.
    pub action_id: ActionId,
}

/// A record of a send to remove.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HoldClearParams {
    /// The record.
    pub hold_id: String,
}

/// What setting the ledger aside did.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetAside {
    /// Whether the damaged list is now a file of its own and the ledger is a rebuilt one.
    pub moved: bool,
    /// Whether the directory is known to hold that on disk.
    pub confirmed: bool,
}

// ---- What is on disk ----

/// Held while the store is changed, so that two windows of one process never change it at once.
static CHANNEL_GATE: Mutex<()> = Mutex::new(());
const LOCK_NAME: &str = "store.lock";
const MESSAGE_SUFFIX: &str = ".message";
const HOLD_SUFFIX: &str = ".held";
/// What a name that a write staged under holds.
const STAGED_MARK: &str = ".staged-";
/// The layout of both kinds of file.
const VERSION: u32 = 1;
const MAX_LABEL_BYTES: usize = 256;
const MAX_DRAFT_REFERENCES: usize = 2;

/// One message, as its file holds it. Exactly these members: a file with another `version` or a
/// member more or fewer is of another layout and is never read.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MessageFile {
    version: u32,
    action_id: ActionId,
    hold_id: Option<String>,
    local_id: String,
    session_id: SessionId,
    application_instance_id: Option<ApplicationInstanceId>,
    agent_binding_revision: Option<AgentBindingRevision>,
    environment_id: Option<EnvironmentId>,
    host_name: String,
    text: String,
    sent_at_ms: TimestampMs,
    drafts: Vec<DiscardParams>,
}

/// The word a record of a send carries in its `kind` member.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum HeldKind {
    #[serde(rename = "held")]
    Held,
}

/// One record of a send under way, as its file holds it. It carries no text.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HoldFile {
    version: u32,
    kind: HeldKind,
    hold_id: String,
    action_id: Option<ActionId>,
    local_id: String,
    session_id: SessionId,
    application_instance_id: Option<ApplicationInstanceId>,
    agent_binding_revision: Option<AgentBindingRevision>,
    environment_id: Option<EnvironmentId>,
    host_name: String,
    sent_at_ms: TimestampMs,
    drafts: Vec<DiscardParams>,
}

/// What a file's bytes are.
enum Parsed<T> {
    /// A file of this layout whose name is its identity.
    Whole(T),
    /// Another layout, or a name that is not the identity: left as it is, for a release that owns it.
    Layout,
    /// Bytes of no layout at all, or version 1 with a member wrong.
    Damaged,
}

fn parse_message(bytes: &[u8], stem: &str) -> Parsed<MessageFile> {
    match serde_json::from_slice::<MessageFile>(bytes) {
        Ok(file) if file.version == VERSION && is_name_of(&file.action_id, stem) => {
            Parsed::Whole(file)
        }
        _ => Parsed::Layout,
    }
}

/// Whether `stem` is the canonical text of `id`, the only name a message file is written under.
fn is_name_of(id: &ActionId, stem: &str) -> bool {
    format!("{id}") == stem
}

fn parse_hold(bytes: &[u8], stem: &str) -> Parsed<HoldFile> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return Parsed::Damaged;
    };
    match value.get("version").and_then(serde_json::Value::as_u64) {
        Some(1) => match serde_json::from_value::<HoldFile>(value) {
            Ok(file) if file.hold_id == stem => Parsed::Whole(file),
            Ok(_) => Parsed::Layout,
            Err(_) => Parsed::Damaged,
        },
        Some(_) => Parsed::Layout,
        None => Parsed::Damaged,
    }
}

/// Whether `id` can be a file's name here: 1 to 64 letters, digits and hyphens.
fn valid_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn storage(what: &str, error: &std::io::Error) -> CommandError {
    CommandError::new(ErrorCode::StorageUnavailable, format!("{what}: {error}"))
}

fn failed(what: &str, error: &std::io::Error) -> CommandError {
    CommandError::local_failure(format!("{what}: {error}"))
}

fn reference_key(reference: &DiscardParams) -> String {
    serde_json::to_string(reference).unwrap_or_default()
}

fn same_references(left: &[DiscardParams], right: &[DiscardParams]) -> bool {
    let sorted = |references: &[DiscardParams]| {
        let mut keys: Vec<String> = references.iter().map(reference_key).collect();
        keys.sort();
        keys
    };
    sorted(left) == sorted(right)
}

fn names_reference(references: &[DiscardParams], line: &DiscardParams) -> bool {
    references
        .iter()
        .any(|held| held.id == line.id && held.expected_revision == line.expected_revision)
}

fn same_message(held: &MessageFile, asked: &MessageFile) -> bool {
    held.text == asked.text
        && held.session_id == asked.session_id
        && held.application_instance_id == asked.application_instance_id
        && held.agent_binding_revision == asked.agent_binding_revision
        && same_references(&held.drafts, &asked.drafts)
}

fn length_of(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

/// Everything in the store's folder, sorted into what the page reads and what it is told of.
#[derive(Default)]
struct Scan {
    messages: Vec<MessageFile>,
    holds: Vec<HoldFile>,
    damaged_holds: Vec<String>,
    unreadable_messages: Unreadable,
    unreadable_holds: Unreadable,
    used: Used,
}

fn scan(directory: &Path) -> std::io::Result<Scan> {
    let mut found = Scan::default();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(STAGED_MARK) {
            continue;
        }
        if let Some(stem) = name.strip_suffix(MESSAGE_SUFFIX) {
            found.used.entries += 1;
            match std::fs::read(entry.path()) {
                Ok(bytes) => {
                    found.used.bytes += length_of(&bytes);
                    match parse_message(&bytes, stem) {
                        Parsed::Whole(file) => found.messages.push(file),
                        Parsed::Layout | Parsed::Damaged => found.unreadable_messages.layout += 1,
                    }
                }
                Err(_) => {
                    found.used.bytes += entry.metadata().map_or(0, |held| held.len());
                    found.unreadable_messages.now += 1;
                }
            }
        } else if let Some(stem) = name.strip_suffix(HOLD_SUFFIX) {
            if !valid_id(stem) {
                found.unreadable_holds.layout += 1;
                continue;
            }
            match std::fs::read(entry.path()) {
                Ok(bytes) => match parse_hold(&bytes, stem) {
                    Parsed::Whole(file) => found.holds.push(file),
                    Parsed::Layout => found.unreadable_holds.layout += 1,
                    Parsed::Damaged => found.damaged_holds.push(stem.to_owned()),
                },
                Err(_) => found.unreadable_holds.now += 1,
            }
        }
    }
    found.messages.sort_by(|left, right| {
        (left.sent_at_ms, left.action_id).cmp(&(right.sent_at_ms, right.action_id))
    });
    found.holds.sort_by(|left, right| {
        (left.sent_at_ms, &left.hold_id).cmp(&(right.sent_at_ms, &right.hold_id))
    });
    found.damaged_holds.sort();
    Ok(found)
}

/// How many records of sends under way can be read: the bound counts these alone, so that an
/// unreadable file adds no work at a start and cannot shut a person out.
fn readable_holds(directory: &Path) -> std::io::Result<usize> {
    let mut readable = 0;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(STAGED_MARK) {
            continue;
        }
        let Some(stem) = name.strip_suffix(HOLD_SUFFIX) else {
            continue;
        };
        if valid_id(stem)
            && std::fs::read(entry.path())
                .is_ok_and(|bytes| matches!(parse_hold(&bytes, stem), Parsed::Whole(_)))
        {
            readable += 1;
        }
    }
    Ok(readable)
}

/// What the entries take, read from the directory's own sizes.
fn usage(directory: &Path) -> std::io::Result<Used> {
    let mut used = Used::default();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains(STAGED_MARK) || !name.ends_with(MESSAGE_SUFFIX) {
            continue;
        }
        used.entries += 1;
        used.bytes += entry.metadata()?.len();
    }
    Ok(used)
}

impl Scan {
    fn into_list(self, with_text: bool, limits: Limits) -> ChannelMessageList {
        ChannelMessageList {
            messages: self
                .messages
                .into_iter()
                .map(|file| StoredChannelMessage {
                    action_id: file.action_id,
                    hold_id: file.hold_id,
                    local_id: file.local_id,
                    session_id: file.session_id,
                    application_instance_id: file.application_instance_id,
                    agent_binding_revision: file.agent_binding_revision,
                    environment_id: file.environment_id,
                    host_name: file.host_name,
                    text: with_text.then_some(file.text),
                    sent_at_ms: file.sent_at_ms,
                })
                .collect(),
            holds: self
                .holds
                .into_iter()
                .map(|file| StoredHold {
                    hold_id: file.hold_id,
                    action_id: file.action_id,
                    local_id: file.local_id,
                    session_id: file.session_id,
                    application_instance_id: file.application_instance_id,
                    agent_binding_revision: file.agent_binding_revision,
                    environment_id: file.environment_id,
                    host_name: file.host_name,
                    sent_at_ms: file.sent_at_ms,
                    drafts: file.drafts,
                })
                .collect(),
            damaged_holds: self.damaged_holds,
            unreadable_messages: self.unreadable_messages,
            unreadable_holds: self.unreadable_holds,
            used: self.used,
            limits,
        }
    }
}

// ---- The store ----

/// The store's lock: the process-wide gate and the lock file of the folder, held until dropped.
struct Held {
    directory: PathBuf,
    /// Whether the folder exists. Without it there is nothing to lock but the gate.
    present: bool,
    _gate: MutexGuard<'static, ()>,
    _lock: Option<std::fs::File>,
}

impl Held {
    /// Removes what a write that did not finish left behind. The lock is held, so no writer of this
    /// folder is between staging a file and putting it in place.
    fn sweep(&self) {
        if !self.present {
            return;
        }
        if let Ok(entries) = std::fs::read_dir(&self.directory) {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().contains(STAGED_MARK) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

fn open_lock(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

fn now_ms(data: &Path) -> u64 {
    #[cfg(feature = "testing")]
    if let Some(moved) = testing::clock_of(data) {
        return moved;
    }
    let _ = data;
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Where this application keeps the messages it sent over channels that confirm nothing.
#[derive(Default)]
pub struct ChannelDesk {
    /// The application data directory, once it is known.
    data: Mutex<Option<PathBuf>>,
}

impl std::fmt::Debug for ChannelDesk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChannelDesk")
            .finish_non_exhaustive()
    }
}

impl ChannelDesk {
    /// Names the application data directory the store lives under.
    pub fn keep_at(&self, data: PathBuf) {
        *self.data.lock().unwrap_or_else(PoisonError::into_inner) = Some(data);
    }

    fn data(&self) -> Result<PathBuf> {
        self.data
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
            .ok_or_else(|| {
                CommandError::unsupported(
                    "messages cannot be kept on this device: it has no place for them",
                )
            })
    }

    /// Takes the store's lock. With `create` the folder is made first, each new name along the path
    /// proved durable and a wider folder narrowed; without it a missing folder is locked by the
    /// gate alone, and a name that is not a folder refuses.
    fn lock(&self, create: bool) -> Result<Held> {
        let directory = kept_in(&self.data()?);
        let gate = CHANNEL_GATE.lock().unwrap_or_else(PoisonError::into_inner);
        if create {
            kr_client::drafts::private_directory(&directory)
                .map_err(|error| failed("the channel messages' folder cannot be made", &error))?;
        } else {
            match std::fs::metadata(&directory) {
                Ok(held) if held.is_dir() => {}
                Ok(_) => {
                    return Err(storage(
                        "the channel messages' folder",
                        &std::io::Error::new(ErrorKind::NotADirectory, "it is not a directory"),
                    ));
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    return Ok(Held {
                        directory,
                        present: false,
                        _gate: gate,
                        _lock: None,
                    });
                }
                Err(error) => return Err(storage("the channel messages' folder", &error)),
            }
        }
        let report = |error: &std::io::Error| {
            let what = "the channel messages' lock cannot be taken";
            if create {
                failed(what, error)
            } else {
                storage(what, error)
            }
        };
        let file = open_lock(&directory.join(LOCK_NAME)).map_err(|error| report(&error))?;
        kr_flush::lock::exclusive(&file).map_err(|error| report(&error))?;
        Ok(Held {
            directory,
            present: true,
            _gate: gate,
            _lock: Some(file),
        })
    }

    /// Proves the folder and its name in the data directory durable, which a read of what they hold
    /// relies on.
    fn make_durable(&self, held: &Held) -> Result<()> {
        let what = "the channel messages' folder cannot be proved durable";
        flush_directory(&held.directory, NameKind::File).map_err(|error| storage(what, &error))?;
        flush_directory(&self.data()?, NameKind::Directory).map_err(|error| storage(what, &error))
    }

    /// Reads the store.
    ///
    /// # Errors
    ///
    /// Returns why the folder cannot be read as one, or cannot be proved durable.
    pub fn list(&self, with_text: bool) -> Result<ChannelMessageList> {
        let held = self.lock(false)?;
        let limits = limits_of(&held.directory);
        if !held.present {
            return Ok(Scan::default().into_list(with_text, limits));
        }
        self.make_durable(&held)?;
        let found = scan(&held.directory)
            .map_err(|error| storage("the channel messages cannot be read", &error))?;
        Ok(found.into_list(with_text, limits))
    }

    /// Reads the drafts, and first finishes what the entries owe: every draft a durable entry holds
    /// the text of is named in the ledger before any draft is returned, and a record of a send that
    /// an entry ends is removed once the ledger is published. This runs at every read, under the
    /// store's lock, so another process's stop or fault is finished too.
    ///
    /// # Errors
    ///
    /// Returns why the drafts cannot be read, or why the folder and the data directory cannot be
    /// proved durable: no draft may be put in a composer while that is unknown.
    pub fn read_drafts(&self, drafts: &DraftDesk) -> Result<Stored> {
        drafts.settle_owed_flush()?;
        let held = self.lock(false)?;
        let mut stored = drafts.read()?;
        if !held.present {
            return Ok(stored);
        }
        self.make_durable(&held)?;
        let found = scan(&held.directory)
            .map_err(|error| storage("the channel messages cannot be read", &error))?;
        let mut owed: Vec<DiscardParams> = Vec::new();
        for message in &found.messages {
            for reference in &message.drafts {
                let held_still = stored.drafts.iter().any(|draft| {
                    draft.id == reference.id && draft.revision == reference.expected_revision
                });
                if held_still && !names_reference(&owed, reference) {
                    owed.push(reference.clone());
                }
            }
        }
        let _ = reach(&held.directory, Point::RepairNamed);
        if matches!(drafts.ledger(), Ledger::Whole(_)) && drafts.mark_removals(&owed).is_ok() {
            for hold in &found.holds {
                let ended = found.messages.iter().any(|message| {
                    message.hold_id.as_deref() == Some(hold.hold_id.as_str())
                        || hold.action_id == Some(message.action_id)
                });
                if ended {
                    let _ = remove_durably(
                        &held
                            .directory
                            .join(format!("{}{HOLD_SUFFIX}", hold.hold_id)),
                    );
                }
            }
        }
        for reference in owed {
            if !names_reference(&stored.pending_removals, &reference) {
                stored.pending_removals.push(reference);
            }
        }
        if found.unreadable_messages.now > 0 {
            stored.sources = Sources::Unknown;
        }
        Ok(stored)
    }

    /// Keeps a message.
    ///
    /// # Errors
    ///
    /// Returns the rule the keep broke, or why it could not be made durable: the entry is durable
    /// before any draft is named for removal, and a fault after the entry's rename leaves the entry.
    pub fn keep(&self, drafts: &DraftDesk, params: KeepParams) -> Result<Kept> {
        check_keep(&params)?;
        let held = self.lock(true)?;
        held.sweep();
        let directory = held.directory.clone();
        let stem = params.action_id.to_string();
        let path = directory.join(format!("{stem}{MESSAGE_SUFFIX}"));
        let entry = MessageFile {
            version: VERSION,
            action_id: params.action_id,
            hold_id: params.hold_id.clone(),
            local_id: params.local_id,
            session_id: params.session_id,
            application_instance_id: params.application_instance_id,
            agent_binding_revision: params.agent_binding_revision,
            environment_id: params.environment_id,
            host_name: params.host_name,
            text: params.text,
            sent_at_ms: params.sent_at_ms,
            drafts: params.drafts,
        };
        let mut wrote = false;
        match std::fs::read(&path) {
            Ok(bytes) => match parse_message(&bytes, &stem) {
                Parsed::Whole(existing) if same_message(&existing, &entry) => {}
                _ => {
                    return Err(CommandError::invalid(
                        "another message is already kept under this action",
                    ));
                }
            },
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let encoded = serde_json::to_vec(&entry)
                    .map_err(|error| CommandError::local_failure(error.to_string()))?;
                let used = usage(&directory)
                    .map_err(|error| storage("the channel messages cannot be counted", &error))?;
                reach(&directory, Point::AfterCountRead)
                    .map_err(|error| failed("the message cannot be kept", &error))?;
                let limits = limits_of(&directory);
                if used.entries >= limits.entries
                    || used.bytes.saturating_add(length_of(&encoded)) > limits.bytes
                {
                    return Err(CommandError::too_large(
                        "Channel messages is full: nothing was kept and nothing was removed",
                    ));
                }
                publish(&path, &encoded, || Ok(()))
                    .map_err(|fault| failed("the message cannot be kept", &fault.error))?;
                wrote = true;
            }
            Err(error) => return Err(storage("the kept message cannot be read", &error)),
        }
        if !wrote {
            flush_directory(&directory, NameKind::File)
                .map_err(|error| failed("the kept message cannot be proved durable", &error))?;
        }
        reach(&directory, Point::AfterEntry)
            .map_err(|error| failed("the message cannot be kept", &error))?;
        if !entry.drafts.is_empty() {
            match drafts.mark_removals(&entry.drafts) {
                Ok(_) => {}
                Err(fault) => {
                    if wrote && !fault.renamed {
                        let named = match drafts.ledger() {
                            Ledger::Whole(lines) => lines
                                .iter()
                                .any(|line| names_reference(&entry.drafts, line)),
                            // A ledger that cannot be read may name them.
                            _ => true,
                        };
                        if !named {
                            let _ = remove_durably(&path);
                        }
                    }
                    return Err(fault.error);
                }
            }
        }
        if let Some(hold_id) = &entry.hold_id
            && reach(&directory, Point::HoldRemoval).is_ok()
        {
            // The repair removes a record that an entry names, so a failure here is not the keep's.
            let _ = remove_durably(&directory.join(format!("{hold_id}{HOLD_SUFFIX}")));
        }
        Ok(Kept { resumed: !wrote })
    }

    /// Removes a message, or every message of a session. A file that cannot be read is never
    /// touched.
    ///
    /// # Errors
    ///
    /// Returns why the removal could not be made durable.
    pub fn remove(&self, params: &RemoveParams) -> Result<Removed> {
        if params.action_id.is_some() == params.session_id.is_some() {
            return Err(CommandError::invalid(
                "name one message or one session to remove",
            ));
        }
        let held = self.lock(false)?;
        if !held.present {
            return Ok(Removed { removed: 0 });
        }
        let found = scan(&held.directory)
            .map_err(|error| storage("the channel messages cannot be read", &error))?;
        let mut removed = 0;
        for message in &found.messages {
            let chosen = params.action_id == Some(message.action_id)
                || params.session_id == Some(message.session_id);
            if !chosen {
                continue;
            }
            match std::fs::remove_file(
                held.directory
                    .join(format!("{}{MESSAGE_SUFFIX}", message.action_id)),
            ) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(failed("the message cannot be removed", &error)),
            }
        }
        flush_directory(&held.directory, NameKind::File)
            .map_err(|error| failed("the removal cannot be proved durable", &error))?;
        Ok(Removed { removed })
    }

    /// Writes the record of a send that is about to be made.
    ///
    /// # Errors
    ///
    /// Returns the rule the record broke, or why it could not be made durable.
    pub fn hold_create(&self, params: HoldCreateParams) -> Result<()> {
        if !valid_id(&params.hold_id) {
            return Err(CommandError::invalid(
                "a record's identity is 1 to 64 letters, digits and hyphens",
            ));
        }
        check_label("the record's local identity", &params.local_id, 1)?;
        check_label("the host's name", &params.host_name, 0)?;
        if params.drafts.len() > MAX_DRAFT_REFERENCES {
            return Err(CommandError::invalid("a record names at most two drafts"));
        }
        let held = self.lock(true)?;
        held.sweep();
        let path = held
            .directory
            .join(format!("{}{HOLD_SUFFIX}", params.hold_id));
        if path.symlink_metadata().is_ok() {
            return Err(CommandError::invalid(
                "a record is already kept under this identity",
            ));
        }
        let readable = readable_holds(&held.directory)
            .map_err(|error| storage("the records of sends cannot be read", &error))?;
        if readable >= limits_of(&held.directory).holds {
            return Err(CommandError::too_large(
                "too many records of messages being sent are kept",
            ));
        }
        let file = HoldFile {
            version: VERSION,
            kind: HeldKind::Held,
            hold_id: params.hold_id,
            action_id: None,
            local_id: params.local_id,
            session_id: params.session_id,
            application_instance_id: params.application_instance_id,
            agent_binding_revision: params.agent_binding_revision,
            environment_id: params.environment_id,
            host_name: params.host_name,
            sent_at_ms: params.sent_at_ms,
            drafts: params.drafts,
        };
        write_hold(&path, &file)
    }

    /// Gives a record of a send the action the host named. A record that is not there, or that
    /// already names another action, is never made or changed. A flush that fails after the rename
    /// leaves the file with the action in it.
    ///
    /// # Errors
    ///
    /// Returns the rule the update broke, or why it could not be made durable.
    pub fn hold_update(&self, params: &HoldUpdateParams) -> Result<()> {
        if !valid_id(&params.hold_id) {
            return Err(CommandError::invalid("this is not a record's identity"));
        }
        let held = self.lock(false)?;
        let path = held
            .directory
            .join(format!("{}{HOLD_SUFFIX}", params.hold_id));
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(CommandError::invalid(
                    "no record is kept under this identity",
                ));
            }
            Err(error) => return Err(storage("the record cannot be read", &error)),
        };
        let Parsed::Whole(mut file) = parse_hold(&bytes, &params.hold_id) else {
            return Err(CommandError::invalid(
                "this record cannot be read by this version of the application",
            ));
        };
        if file
            .action_id
            .is_some_and(|named| named != params.action_id)
        {
            return Err(CommandError::invalid(
                "this record already names another action",
            ));
        }
        file.action_id = Some(params.action_id);
        write_hold(&path, &file)
    }

    /// Removes a record of a send. A record that is not there is already removed, and the folder
    /// is flushed all the same. A record of a later layout is left alone.
    ///
    /// # Errors
    ///
    /// Returns why the removal could not be made durable.
    pub fn hold_clear(&self, params: &HoldClearParams) -> Result<()> {
        if !valid_id(&params.hold_id) {
            return Err(CommandError::invalid("this is not a record's identity"));
        }
        let held = self.lock(false)?;
        if !held.present {
            return Ok(());
        }
        let path = held
            .directory
            .join(format!("{}{HOLD_SUFFIX}", params.hold_id));
        if let Ok(bytes) = std::fs::read(&path)
            && matches!(parse_hold(&bytes, &params.hold_id), Parsed::Layout)
        {
            return Err(CommandError::invalid(
                "this record belongs to another version of the application",
            ));
        }
        remove_durably(&path).map_err(|error| failed("the record cannot be removed", &error))
    }

    /// Sets a damaged ledger aside and starts a rebuilt one: the bytes are copied to a file of
    /// their own, and the ledger is replaced by the removals that the readable entries name, so
    /// that the ledger's name is never absent and every process reads the damaged list or the
    /// rebuilt one. A ledger that can be read, or that cannot be read at all, is never touched.
    ///
    /// # Errors
    ///
    /// Returns why nothing was moved. A flush that fails after the ledger was replaced is not an
    /// error: the answer says the move is not yet confirmed, and the flush stays owed.
    pub fn set_aside(&self, drafts: &DraftDesk) -> Result<SetAside> {
        let held = self.lock(false)?;
        let locked = drafts.lock_ledger()?;
        let data = locked.data().to_path_buf();
        let _ = reach(&data, Point::SetAsideLocked);
        if !matches!(locked.read(), Ledger::Damaged) {
            return Err(CommandError::invalid(
                "the list of removals is not damaged, so it is not set aside",
            ));
        }
        let rebuilt = if held.present {
            let found = scan(&held.directory)
                .map_err(|error| storage("the channel messages cannot be read", &error))?;
            let mut rebuilt: Vec<DiscardParams> = Vec::new();
            for message in &found.messages {
                for reference in &message.drafts {
                    if !names_reference(&rebuilt, reference) {
                        rebuilt.push(reference.clone());
                    }
                }
            }
            rebuilt
        } else {
            Vec::new()
        };
        let bytes = std::fs::read(locked.file())
            .map_err(|error| failed("the list of removals cannot be read", &error))?;
        // Owed before anything moves: a flush that fails from here on is finished by the next read
        // of the drafts or change of the ledger, whichever comes first.
        drafts.owe_flush();
        let copy = data.join(format!("drafts-removals.set-aside-{}", now_ms(&data)));
        kr_client::drafts::write_whole(&copy, &bytes)
            .map_err(|error| failed("the list of removals cannot be copied", &error))?;
        flush_directory(&data, NameKind::File)
            .map_err(|error| failed("the copy cannot be proved durable", &error))?;
        reach(&data, Point::SetAsideCopied)
            .map_err(|error| failed("the list of removals cannot be set aside", &error))?;
        match locked.publish(&rebuilt) {
            Ok(()) => {
                drafts.clear_owed_flush();
                Ok(SetAside {
                    moved: true,
                    confirmed: true,
                })
            }
            Err(fault) if fault.renamed => Ok(SetAside {
                moved: true,
                confirmed: false,
            }),
            Err(fault) => Err(failed(
                "the list of removals cannot be set aside: nothing was moved",
                &fault.error,
            )),
        }
    }
}

fn check_label(what: &str, value: &str, least: usize) -> Result<()> {
    if value.len() < least || value.len() > MAX_LABEL_BYTES {
        return Err(CommandError::invalid(format!(
            "{what} is not of a length that can be kept"
        )));
    }
    Ok(())
}

fn check_keep(params: &KeepParams) -> Result<()> {
    if params.text.is_empty() || params.text.len() > MAX_INLINE_PROMPT_BYTES {
        return Err(CommandError::invalid(
            "a message is 1 byte to 64 KiB of text",
        ));
    }
    if params.drafts.len() > MAX_DRAFT_REFERENCES {
        return Err(CommandError::invalid("a message names at most two drafts"));
    }
    if params.hold_id.as_deref().is_some_and(|id| !valid_id(id)) {
        return Err(CommandError::invalid("this is not a record's identity"));
    }
    check_label("the local identity", &params.local_id, 1)?;
    check_label("the host's name", &params.host_name, 0)
}

fn write_hold(path: &Path, file: &HoldFile) -> Result<()> {
    let encoded =
        serde_json::to_vec(file).map_err(|error| CommandError::local_failure(error.to_string()))?;
    publish(path, &encoded, || Ok(()))
        .map_err(|fault| failed("the record cannot be kept", &fault.error))
}
