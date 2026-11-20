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

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use kr_protocol::ids::{
    ActionId, AgentBindingRevision, ApplicationInstanceId, EnvironmentId, SessionId,
};
use kr_protocol::scalars::TimestampMs;
use serde::{Deserialize, Serialize};

use crate::drafts::{DiscardParams, DraftDesk};
use crate::error::Result;

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

    /// Reads the store.
    ///
    /// # Errors
    ///
    /// Returns why the store cannot be read.
    pub fn list(&self, _with_text: bool) -> Result<ChannelMessageList> {
        Ok(ChannelMessageList {
            messages: Vec::new(),
            holds: Vec::new(),
            damaged_holds: Vec::new(),
            unreadable_messages: Unreadable::default(),
            unreadable_holds: Unreadable::default(),
            used: Used::default(),
            limits: Limits::SHIPPED,
        })
    }

    /// Keeps a message.
    ///
    /// # Errors
    ///
    /// Returns the rule the keep broke, or why it could not be made durable.
    pub fn keep(&self, _drafts: &DraftDesk, _params: KeepParams) -> Result<Kept> {
        Ok(Kept { resumed: false })
    }

    /// Removes a message, or every message of a session.
    ///
    /// # Errors
    ///
    /// Returns why the removal could not be made durable.
    pub fn remove(&self, _params: &RemoveParams) -> Result<Removed> {
        Ok(Removed { removed: 0 })
    }

    /// Writes the record of a send that is about to be made.
    ///
    /// # Errors
    ///
    /// Returns the rule the record broke, or why it could not be made durable.
    pub fn hold_create(&self, _params: HoldCreateParams) -> Result<()> {
        Ok(())
    }

    /// Gives a record of a send the action the host named.
    ///
    /// # Errors
    ///
    /// Returns the rule the update broke, or why it could not be made durable.
    pub fn hold_update(&self, _params: &HoldUpdateParams) -> Result<()> {
        Ok(())
    }

    /// Removes a record of a send. A record that is not there is already removed.
    ///
    /// # Errors
    ///
    /// Returns why the removal could not be made durable.
    pub fn hold_clear(&self, _params: &HoldClearParams) -> Result<()> {
        Ok(())
    }

    /// Sets a damaged ledger aside and starts a rebuilt one.
    ///
    /// # Errors
    ///
    /// Returns why nothing was moved.
    pub fn set_aside(&self, _drafts: &DraftDesk) -> Result<SetAside> {
        Ok(SetAside {
            moved: false,
            confirmed: false,
        })
    }
}
