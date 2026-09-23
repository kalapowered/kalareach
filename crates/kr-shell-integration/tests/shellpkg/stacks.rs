//! The qualification corpus under `tests/shells/`, and the sessions each case drives.
//!
//! Section 7 says the managed packages are qualified against the startup customisations people
//! actually run: zsh-autosuggestions, zsh-syntax-highlighting, Powerlevel10k with its instant
//! prompt, starship, oh-my-zsh, fzf's widgets, atuin and ordinary distribution customisations. The
//! corpus is that list as data: one directory per shell and stack, holding the startup files the
//! case installs and the checks it claims, and one list per shell of the combinations that do not
//! exist, each with its reason.
//!
//! The stacks themselves are pinned in `fixtures/shells/stacks.lock` and fetched once by
//! `scripts/fetch-shell-stacks.sh`. Nothing here reaches the network: a case reads the index that
//! script wrote, and a stack that index calls unreachable is a stack this run did not qualify.
//!
//! Nothing a launched process touches is inside the workspace. The shell's executable is the
//! installed package and the case's home, runtime directory and endpoint are on the internal disk,
//! which is what keeps a rebuilt binary from asking the person at the machine for permission.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use kr_protocol::ids::SessionId;
use kr_protocol::root::{
    FENCE_EXCHANGE_TIMEOUT, FenceCause, RootEditorFenceParams, RootEditorFenceResult,
};
use kr_protocol::scalars::Uuid;
use kr_shell_integration::contract::events::ReaderIdle;
use kr_shell_integration::contract::qualification::{DetachExclusion, ShellKind};
use kr_shell_integration::contract::transport::{
    BOOTSTRAP_SECRET_LEN, BridgeEndpoint, BridgeFrame, HandshakeOutcome, ObservedPeer,
    ProofVerdict, WorkerExpectation, bootstrap_transcript, decide_handshake,
};
use portable_pty::{Child, CommandBuilder, PtySize, native_pty_system};
use serde::Deserialize;

use super::*;

/// The token a case's startup file puts where the package's own marked entry belongs.
///
/// A case that names it says where in its own startup the integration is activated, which is what
/// makes "the normal profile order is preserved" something the corpus states rather than assumes.
pub const ENTRY_TOKEN: &str = "# {kalareach-entry}";

/// What the person's binding writes into the line when the key they bound is pressed.
pub const USER_BINDING_TEXT: &str = "kr-user-binding-ran";

/// The key the person's own binding is on, in every case: `ESC q` on the three Unix readers and
/// `Alt+q` on the editor that reads a chord, which is the same two bytes at the terminal.
pub const USER_BINDING_KEY: &[u8] = &[0x1b, b'q'];

/// A key the editor has a binding for, which moves the cursor one place and changes nothing else.
///
/// A managed package sits in front of the operations the editor binds, so a key like this one is
/// how a reader is given a step to take: it ends at the reader's own boundary, where the reader
/// reads its state and reports it. An ordinary character is the editor's own insertion, which
/// nothing is in front of, so it is no step at all.
pub const STEP_KEY: &[u8] = &[0x06];

/// What [`liveness_command`] prints when a shell still answers.
pub const LIVENESS_MARKER: &str = "kr-answering";

/// A command every shell here runs, for proving a shell still answers.
///
/// It puts [`LIVENESS_MARKER`] together from two pieces as it runs, so the word this waits for is
/// never part of the line that was typed. A terminal echoing that line back cannot produce it.
#[must_use]
pub fn liveness_command(kind: ShellKind) -> &'static str {
    match kind {
        ShellKind::PowerShell => "Write-Output ('kr-' + 'answering')",
        _ => "printf '%s%s\\n' kr- answering",
    }
}

/// How long a session waits, over all its probes, for an editor to say it is reading.
const READINESS: Duration = Duration::from_secs(45);

/// How long a person's own binding is given, over all the offers of its key.
const BINDING: Duration = Duration::from_secs(30);

/// How long a reader is given, over all the fences asked of it, to answer one of its own.
const FENCE: Duration = Duration::from_secs(30);

/// The whole of what one report says about which reader wrote it and what that reader was doing.
///
/// A prompt generation is not a reader. One reader can leave and another take its place at the
/// same prompt, an editor that redraws reports a new revision at the same prompt, and a nested
/// reader of the shell's own runs at a prompt of the primary reader's. So everything that names
/// the reader is kept together and compared together: nothing here reads a subset of it.
///
/// [`ReaderMark::lifetime`] is the one part no reader reports of itself. This session counts the
/// entries and leaves as they arrive, and a report stamped with a different count is a report from
/// the other side of a reader having come or gone, whatever the numbers in it say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReaderMark {
    /// How many readers of this session had entered or left when this report was read.
    pub lifetime: u64,
    /// The prompt the report was at.
    pub prompt_generation: u64,
    /// The revision of the reader that wrote it.
    pub reader_revision: u64,
    /// Which of the shell's readers wrote it.
    pub context: kr_protocol::root::ReaderContext,
    /// The buffer revision it carried.
    pub buffer_revision: u64,
    /// Whether the buffer was empty at that revision.
    pub buffer_empty: bool,
    /// The keymap in force when it was read.
    pub keymap: kr_protocol::root::EditorKeymap,
    /// What the reader was in the middle of.
    pub pending: kr_protocol::root::PendingReaderInput,
}

impl ReaderMark {
    /// The mark one report leaves behind it.
    #[must_use]
    pub fn of(idle: &ReaderIdle, lifetime: u64) -> Self {
        Self {
            lifetime,
            prompt_generation: idle.prompt_generation.get(),
            reader_revision: idle.reader_revision.get(),
            context: idle.reader_context,
            buffer_revision: idle.editor.buffer_revision.get(),
            buffer_empty: idle.editor.buffer_empty,
            keymap: idle.editor.keymap,
            pending: idle.editor.pending,
        }
    }

    /// The mark a fence answer leaves behind it.
    ///
    /// A fence exchange is how a drive asks a reader that is waiting inside an operation what it
    /// is doing: such a reader reaches no key boundary and so writes no report of its own, and its
    /// answer to the exchange carries the same identity and the same state as one that did.
    #[must_use]
    pub fn of_acknowledgement(
        acknowledgement: &kr_protocol::root::FenceAcknowledgement,
        lifetime: u64,
    ) -> Self {
        Self {
            lifetime,
            prompt_generation: acknowledgement.prompt_generation.get(),
            reader_revision: acknowledgement.reader_revision.get(),
            context: acknowledgement.reader_context,
            buffer_revision: acknowledgement.editor.buffer_revision.get(),
            buffer_empty: acknowledgement.editor.buffer_empty,
            keymap: acknowledgement.editor.keymap,
            pending: acknowledgement.editor.pending,
        }
    }

    /// Whether a line typed at this reader becomes text rather than the editor's own motions.
    ///
    /// The command keymap of a vi-style editor reads a typed line as motions and operators, so a
    /// command submitted to a reader in it never runs and the silence that follows says nothing
    /// about the key that was offered. Anything a drive asks of the shell waits for this.
    #[must_use]
    pub fn takes_typed_text(&self) -> bool {
        self.keymap != kr_protocol::root::EditorKeymap::ViCommand
    }

    /// Whether the reader was in the state this exclusion names, as the report has it.
    ///
    /// `None` is an exclusion that is not a state of a reader at all, which one of them is: that
    /// the reader is the managed root editor is a condition on the reader rather than something
    /// it can be doing.
    #[must_use]
    pub fn shows(&self, exclusion: DetachExclusion) -> Option<bool> {
        Some(match exclusion {
            DetachExclusion::BufferNotEmpty => !self.buffer_empty,
            DetachExclusion::QuotedInsertion => self.pending.quoted_insertion,
            DetachExclusion::MacroInput => self.pending.macro_input,
            DetachExclusion::Search => self.pending.search,
            DetachExclusion::NumericArgument => self.pending.numeric_argument,
            DetachExclusion::MultikeySequence => self.pending.multikey_sequence,
            DetachExclusion::ViMotion => self.pending.vi_motion,
            DetachExclusion::Paste => self.pending.paste,
            DetachExclusion::ContinuationInput => {
                self.context == kr_protocol::root::ReaderContext::Continuation
            }
            DetachExclusion::ReadBuiltin => {
                self.context == kr_protocol::root::ReaderContext::ReadBuiltin
            }
            DetachExclusion::NotManagedRootEditor => return None,
        })
    }

    /// What the reader said it was doing, for the record to carry.
    #[must_use]
    pub fn doing(&self) -> String {
        let mut states: Vec<&str> = Vec::new();
        for (held, name) in [
            (self.pending.quoted_insertion, "a quoted insertion"),
            (self.pending.macro_input, "a macro being replayed"),
            (self.pending.search, "a search"),
            (self.pending.numeric_argument, "a numeric argument"),
            (self.pending.multikey_sequence, "a multikey sequence"),
            (self.pending.vi_motion, "a vi motion waiting for its target"),
            (self.pending.paste, "an open paste"),
        ] {
            if held {
                states.push(name);
            }
        }
        let line = if self.buffer_empty {
            "an empty line"
        } else {
            "a line of its own"
        };
        if states.is_empty() {
            format!("{line} and nothing pending")
        } else {
            format!("{line} and {}", states.join(", "))
        }
    }

    /// Whether two reports are about one reader.
    ///
    /// The same reader at the same prompt, with no reader of this session having entered or left
    /// between the two. A drive that offers a key after an observation asks this before it claims
    /// the observation was about the reader the key reached.
    #[must_use]
    pub fn same_reader(&self, other: &Self) -> bool {
        self.lifetime == other.lifetime
            && self.prompt_generation == other.prompt_generation
            && self.reader_revision == other.reader_revision
            && self.context == other.context
    }

    /// The reader, as a record says which one it was.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "the {} reader at prompt {} revision {}, buffer revision {}, keymap {}",
            self.context.as_str(),
            self.prompt_generation,
            self.reader_revision,
            self.buffer_revision,
            self.keymap.as_str()
        )
    }
}

/// One report of a reader's, with the identity of the reader that wrote it.
#[derive(Clone, Debug)]
pub struct ReaderReport {
    /// Which reader wrote it, whole.
    pub mark: ReaderMark,
    /// What it said.
    pub idle: ReaderIdle,
}

/// Whether a fence answer shows the reader replaying input of its own.
///
/// Three things say so, and any one of them is enough: the reader reporting the replay as pending,
/// a macro queue it has not drained, and keys queued behind the one it is reading. A binding that
/// replays nothing answers no to all three, and that answer is honest rather than a miss: the
/// drive that gets it narrows its claim to the two keys it offered instead of counting a binding
/// that did nothing as a replay it never saw.
#[must_use]
pub fn replay_seen(acknowledgement: &kr_protocol::root::FenceAcknowledgement) -> bool {
    acknowledgement.editor.pending.macro_input
        || !acknowledgement.queues.macro_input_drained
        || acknowledgement.snapshot.queued_keys > U64::ZERO
}

/// What one report of the reader's says about the probe a session is waiting out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadinessStep {
    /// The probe's own report, or one from before it. It is about a line that is gone.
    Behind,
    /// After the probe at the probe's own prompt, with the line or a queue still holding
    /// something: this reader is inside the read the probe drew and has not finished with it.
    Busy,
    /// After the probe at the probe's own prompt, at an empty line with nothing queued behind it.
    Ready,
    /// A prompt after the probe's.
    Moved,
}

/// What one exclusion drive saw, in the drive's own words.
///
/// A qualification's summary is made from these rather than written beside them. A drive that
/// claims a state says here what it read out of the reader's own report before it offered the key,
/// and what it saw the shell do afterwards; a claim no line here carries is a claim nothing
/// checked, and it does not belong in the record.
#[derive(Clone, Debug)]
pub struct DriveObservation {
    /// The state the drive put the reader into.
    pub exclusion: DetachExclusion,
    /// What the reader reported about itself before the key was offered.
    pub before: String,
    /// What the shell did with the key.
    pub after: String,
    /// Whether the reader was observed in the state this exclusion names.
    ///
    /// False is a drive that put the reader where it could and found the reader reporting no such
    /// state of its own. What it saw is still recorded, and the exclusion counts as accounted for
    /// rather than as driven: a corpus that called it driven would be claiming the thing the
    /// reader declined to say.
    pub proved: bool,
}

impl DriveObservation {
    /// One line of the record.
    #[must_use]
    pub fn line(&self) -> String {
        format!(
            "{}: before, {}; after, {}",
            self.exclusion.as_str(),
            self.before,
            self.after
        )
    }

    /// A drive whose reader reported the state the exclusion names.
    #[must_use]
    pub fn proved(exclusion: DetachExclusion, before: String, after: String) -> Self {
        Self {
            exclusion,
            before,
            after,
            proved: true,
        }
    }
}

/// Where one probe of a reader ended.
///
/// A probe asks four questions in order, and a qualification that fails here is worth more when it
/// says which of them went unanswered: a shell that drew no prompt, a reader that never took the
/// request in front of the probe, a reader that never reported the line the probe drew, and a
/// reader that never reported the line the clear took away are four different faults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeStop {
    /// The reader said it was inside its read at the prompt it was probed at.
    Reading,
    /// The reader never answered the request that separates this probe from what came before it.
    NoBarrierAnswer,
    /// The reader never reported the line the probe drew.
    NoProbeReport,
    /// The reader moved to a later prompt under the probe, so this one is about a prompt that has
    /// gone and the next probe is drawn where the reader is now.
    Moved,
    /// The reader never reported the line the clear took away.
    NoSettledReport,
}

impl ProbeStop {
    /// What did not happen, as a clause a failure reads with.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reading => "the reader said it was inside its read",
            Self::NoBarrierAnswer => "the reader never answered the request in front of the probe",
            Self::NoProbeReport => "the reader never reported the line the probe drew",
            Self::Moved => "the reader moved to a later prompt under the probe",
            Self::NoSettledReport => "the reader never reported the line the clear took away",
        }
    }
}

/// What a report of the reader's says about the probe that left `since`.
///
/// This is the rule every session here offers a key by. A key goes to an editor only after the
/// reader has said, in a report of its own, that it is inside its read for the prompt the key is
/// meant for. It says so by reporting an empty line with nothing queued, at the prompt the probe
/// was drawn at, later than the probe's own report.
///
/// The report a reader sends as it enters cannot say it. That one goes out before the editor takes
/// the terminal, and it is the first report of its prompt, so it is always behind a probe's report
/// of the same prompt and is dropped here by comparison rather than waited out. A report from a
/// prompt after the probe's says nothing about this wait either, for the same reason: at that
/// prompt the session has not probed yet. The answer there is another probe, not a longer wait.
#[must_use]
pub fn readiness_of(since: &ReaderMark, report: &ReaderReport) -> ReadinessStep {
    // A reader that has entered or left since the probe, a later prompt, and a reader that redrew
    // under a new revision are all the same answer: this report is not about the reader the probe
    // was drawn at, and what settles the wait is another probe where the reader is now. A report
    // from before any of that is about a line that has gone, and is dropped by comparison.
    let mark = &report.mark;
    for (seen, wanted) in [
        (mark.lifetime, since.lifetime),
        (mark.prompt_generation, since.prompt_generation),
        (mark.reader_revision, since.reader_revision),
    ] {
        if seen > wanted {
            return ReadinessStep::Moved;
        }
        if seen < wanted {
            return ReadinessStep::Behind;
        }
    }
    if mark.context != since.context {
        return ReadinessStep::Moved;
    }
    if mark.buffer_revision <= since.buffer_revision {
        return ReadinessStep::Behind;
    }
    if report.mark.buffer_empty
        && report.idle.snapshot.queued_keys == U64::ZERO
        && report.idle.snapshot.pending_bytes == U64::ZERO
        && report.mark.pending == kr_protocol::root::PendingReaderInput::NONE
    {
        ReadinessStep::Ready
    } else {
        ReadinessStep::Busy
    }
}

/// One stack, as `scripts/fetch-shell-stacks.sh` left it.
#[derive(Clone, Debug, Deserialize)]
pub struct InstalledStack {
    pub id: String,
    pub version: String,
    /// `installed`, `unreachable` or `unsupported_platform`.
    pub status: String,
    pub root: Option<String>,
    pub executable: Option<String>,
    pub url: Option<String>,
    pub sha256: Option<String>,
    /// A digest of the installed tree, taken when it was unpacked and checked on every run since.
    pub tree_sha256: Option<String>,
    pub reason: Option<String>,
}

impl InstalledStack {
    #[must_use]
    pub fn installed(&self) -> bool {
        self.status == "installed"
    }
}

/// The index that script writes beside the trees it unpacked.
#[derive(Clone, Debug, Deserialize)]
pub struct StackIndex {
    pub platform: String,
    pub lock_sha256: String,
    pub stacks: Vec<InstalledStack>,
}

impl StackIndex {
    /// Reads the index, or says why there is none.
    ///
    /// # Errors
    ///
    /// Returns the reason a run has no stacks: the fetcher has not run on this host.
    pub fn read() -> Result<Self, String> {
        let path = stack_cache().join("index.json");
        let body = std::fs::read_to_string(&path).map_err(|error| {
            format!(
                "{} is not here ({error}); run scripts/fetch-shell-stacks.sh",
                path.display()
            )
        })?;
        serde_json::from_str(&body)
            .map_err(|error| format!("{} does not decode: {error}", path.display()))
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&InstalledStack> {
        self.stacks.iter().find(|stack| stack.id == id)
    }
}

/// One pinned stack in `fixtures/shells/stacks.lock`.
#[derive(Clone, Debug, Deserialize)]
pub struct LockedStack {
    pub id: String,
    pub name: String,
    pub version: String,
    /// `source` for a tree the startup file reads, `program` for one it runs.
    pub role: String,
    pub program: Option<String>,
    pub shells: Vec<String>,
    pub entry: Option<String>,
    pub sources: Vec<LockedSource>,
}

/// One platform's archive for a pinned stack.
#[derive(Clone, Debug, Deserialize)]
pub struct LockedSource {
    pub platform: String,
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub strip_components: u32,
}

/// The pinned set.
#[derive(Clone, Debug, Deserialize)]
pub struct StackLock {
    pub lock_version: u32,
    pub description: String,
    pub stacks: Vec<LockedStack>,
}

impl StackLock {
    /// Reads the pinned set.
    ///
    /// # Panics
    ///
    /// Panics when the lock is missing or does not decode: it is committed beside the corpus, so
    /// either is a corpus that has been taken apart rather than a run-time condition.
    #[must_use]
    pub fn read() -> Self {
        let path = repository_root().join("fixtures/shells/stacks.lock");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        serde_json::from_str(&body)
            .unwrap_or_else(|error| panic!("{} does not decode: {error}", path.display()))
    }
}

/// One file a case installs under its own home.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeFile {
    /// The file in the case's `home/` directory.
    pub file: String,
    /// Where it goes, relative to the session's home directory.
    pub path: String,
}

/// A native module a case installs that the shell cannot load.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeModuleCase {
    pub name: String,
    /// The word the startup file records when the load was refused.
    pub marker: String,
    /// What this case can and cannot prove, stated in the corpus rather than in a comment.
    pub note: String,
}

/// One combination of a shell and a startup customisation.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCase {
    pub id: String,
    pub shell: ShellKind,
    /// The customisation this case runs, by the identifier the pinned set uses, or `none`,
    /// `distribution` or `native-module` for the three that are not pinned archives.
    pub stack: String,
    pub title: String,
    pub supported: bool,
    #[serde(default)]
    pub reason: Option<String>,
    /// The pinned stacks this case needs installed.
    pub requires: Vec<String>,
    /// The markers the case's startup writes, in the order it writes them.
    pub order: Vec<String>,
    /// The order a second start over the same home writes, where a case has one.
    #[serde(default)]
    pub warm_order: Option<Vec<String>>,
    /// What the person's own binding is called.
    pub binding: String,
    /// What this case claims to prove.
    pub checks: Vec<String>,
    /// The excluded states this customisation takes the key for, so they are not states of the
    /// managed reader in this case.
    #[serde(default)]
    pub skip_exclusions: Vec<String>,
    /// What this case does not drive, and why, where that is not obvious from the checks.
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub plugin: Option<PluginProbe>,
    #[serde(default)]
    pub native_module: Option<NativeModuleCase>,
    pub covers: Vec<String>,
    pub home: Vec<HomeFile>,
    /// Where the case was read from. Not part of the file.
    #[serde(skip)]
    pub directory: PathBuf,
}

/// How a case asks the shell whether its customisation is loaded and working.
///
/// Without this a case proves only that a startup file ran. With it, a customisation that failed
/// to load — a path that moved, a release that changed its own entry point — fails the case that
/// claims it rather than passing as a shell with nothing loaded.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginProbe {
    /// The command the shell is given.
    pub probe: String,
    /// What it prints when the customisation is there.
    pub marker: String,
    /// A second command that makes the customisation do the thing it is for, where one command
    /// cannot both set a state and read it back.
    #[serde(default)]
    pub operation: Option<String>,
    /// What that prints when the customisation did it.
    #[serde(default)]
    pub operation_marker: Option<String>,
}

/// A combination that does not exist, with the reason it does not.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedStack {
    pub stack: String,
    pub reason: String,
}

/// Every combination one shell does not have.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedList {
    pub shell: ShellKind,
    pub unsupported: Vec<UnsupportedStack>,
}

/// The workspace root, from this crate's own manifest.
#[must_use]
pub fn repository_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("..");
    root.push("..");
    root
}

/// Where the corpus lives.
#[must_use]
pub fn corpus_root() -> PathBuf {
    repository_root().join("tests").join("shells")
}

/// Where the built packages are installed, which is what a session resolves one from.
#[must_use]
pub fn package_root() -> PathBuf {
    cache_root()
}

/// Where `scripts/fetch-shell-stacks.sh` installs what it fetched.
#[must_use]
pub fn stack_cache() -> PathBuf {
    if let Some(explicit) = std::env::var_os("KR_SHELL_STACKS") {
        return PathBuf::from(explicit);
    }
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    if cfg!(target_os = "macos") {
        home.join("Library/Caches/kalareach/shell-stacks")
    } else if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("kalareach/shell-stacks")
    } else {
        home.join(".cache/kalareach/shell-stacks")
    }
}

/// Reads every case, in a stable order.
///
/// # Panics
///
/// Panics when a case does not decode, which is a corpus that cannot be read rather than a
/// package that failed.
#[must_use]
pub fn cases() -> Vec<QualificationCase> {
    let mut found = Vec::new();
    for shell in read_directory(&corpus_root()) {
        if !shell.is_dir() {
            continue;
        }
        for entry in read_directory(&shell) {
            let path = entry.join("case.json");
            if !path.is_file() {
                continue;
            }
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            let mut case: QualificationCase = serde_json::from_str(&body)
                .unwrap_or_else(|error| panic!("{} does not decode: {error}", path.display()));
            case.directory = entry;
            found.push(case);
        }
    }
    found.sort_by(|left, right| left.id.cmp(&right.id));
    found
}

/// Reads each shell's list of combinations that do not exist.
///
/// # Panics
///
/// Panics when a list does not decode.
#[must_use]
pub fn unsupported() -> Vec<UnsupportedList> {
    let mut found = Vec::new();
    for shell in read_directory(&corpus_root()) {
        let path = shell.join("unsupported.json");
        if !path.is_file() {
            continue;
        }
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        found.push(
            serde_json::from_str(&body)
                .unwrap_or_else(|error| panic!("{} does not decode: {error}", path.display())),
        );
    }
    found.sort_by_key(|list: &UnsupportedList| list.shell.as_str());
    found
}

fn read_directory(root: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
        .unwrap_or_else(|error| panic!("{}: {error}", root.display()))
        .map(|entry| entry.expect("a directory entry is readable").path())
        .collect();
    entries.sort();
    entries
}

/// The environment variable a case's startup file reads a stack's own directory from.
#[must_use]
pub fn stack_variable(id: &str) -> String {
    format!("KR_STACK_{}", id.to_uppercase().replace('-', "_"))
}

/// Everything one case needs on disk before its shell starts.
///
/// The home outlives the session that reads it, so a case can start a second shell over the same
/// home — which is what a theme that draws from a cache of the last run needs — and so the order
/// the startup wrote can be read after the shell has gone.
pub struct CaseSetup {
    pub home: PathBuf,
    pub runtime: PathBuf,
    /// Where the startup files append the markers that say what ran and in what order.
    pub order: PathBuf,
    pub environment: Vec<(String, String)>,
    directory: tempfile::TempDir,
}

impl CaseSetup {
    /// Writes the case's startup files, with the package's own marked entry where the case put it.
    ///
    /// # Panics
    ///
    /// Panics when a file the case names is missing or its path climbs out of the home, which is a
    /// corpus fault rather than a package one.
    #[must_use]
    pub fn prepare(case: &QualificationCase, package: &Package, stacks: &StackIndex) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("kr-qualification-")
            .tempdir()
            .expect("a case directory on the internal disk");
        let home = directory.path().join("home");
        let runtime = directory.path().join("rt");
        std::fs::create_dir(&home).expect("a home directory");
        std::fs::create_dir(&runtime).expect("a runtime directory");
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
            .expect("an owner-only runtime directory");
        let order = directory.path().join("order");
        std::fs::write(&order, "").expect("the order record");

        let entry = package_entry(package);
        let mut entry_written = false;
        for file in &case.home {
            let source = case.directory.join("home").join(&file.file);
            // Read as bytes: a case may ship a file that is not text, and a module the loader is
            // meant to refuse is one of them.
            let body = std::fs::read(&source)
                .unwrap_or_else(|error| panic!("{}: {error}", source.display()));
            let destination = home_path(&home, &file.path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).expect("a directory under the case home");
            }
            let body = match std::str::from_utf8(&body) {
                Ok(text) if text.contains(ENTRY_TOKEN) => {
                    entry_written = true;
                    text.replace(ENTRY_TOKEN, &entry).into_bytes()
                }
                _ => body,
            };
            std::fs::write(&destination, body).expect("a startup file");
        }
        if !entry_written {
            // This shell activates the integration from a file of its own rather than from inside
            // the person's, which is what its own configuration layout asks for.
            let destination = home_path(&home, default_entry_path(case.shell));
            std::fs::create_dir_all(destination.parent().expect("a parent")).expect("a directory");
            std::fs::write(&destination, entry).expect("the startup entry");
        }

        let mut environment = vec![
            ("HOME".to_owned(), home.display().to_string()),
            ("ZDOTDIR".to_owned(), home.display().to_string()),
            (
                "XDG_CONFIG_HOME".to_owned(),
                home.join(".config").display().to_string(),
            ),
            (
                "XDG_DATA_HOME".to_owned(),
                home.join(".local/share").display().to_string(),
            ),
            (
                "XDG_CACHE_HOME".to_owned(),
                home.join(".cache").display().to_string(),
            ),
            ("KR_TEST_ORDER".to_owned(), order.display().to_string()),
            ("TERM".to_owned(), "xterm-256color".to_owned()),
            ("LANG".to_owned(), "C".to_owned()),
        ];
        for id in &case.requires {
            let stack = stacks
                .get(id)
                .unwrap_or_else(|| panic!("{} needs {id}, which the index does not name", case.id));
            let root = stack
                .root
                .as_ref()
                .unwrap_or_else(|| panic!("{id} is {} and has no directory", stack.status));
            environment.push((stack_variable(id), root.clone()));
        }

        // A process a harness starts is its own identity to the operating system, and one that
        // reaches the removable volume this workspace lives on makes it ask the person at the
        // machine for permission. Every path this shell is given is checked rather than assumed.
        for (name, value) in &environment {
            assert!(
                outside_workspace(Path::new(value)),
                "{} would give the shell {name}={value}, which is on the workspace volume",
                case.id
            );
        }
        assert!(
            outside_workspace(&package.executable),
            "{} would launch {}, which is on the workspace volume",
            case.id,
            package.executable.display()
        );

        Self {
            home,
            runtime,
            order,
            environment,
            directory,
        }
    }

    /// The markers the startup files recorded, in the order they wrote them.
    #[must_use]
    pub fn recorded_order(&self) -> Vec<String> {
        std::fs::read_to_string(&self.order)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Empties the order record, so a second start over the same home records only its own run.
    pub fn forget_order(&self) {
        std::fs::write(&self.order, "").expect("the order record");
    }

    /// Where the case's own files live, for evidence a test writes beside them.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.directory.path()
    }
}

/// Joins a path a case named to the home, refusing one that climbs out of it.
fn home_path(home: &Path, relative: &str) -> PathBuf {
    let path = Path::new(relative);
    assert!(path.is_relative(), "{relative} is not relative to the home");
    for part in path.components() {
        assert!(
            matches!(part, std::path::Component::Normal(_)),
            "{relative} climbs out of the home"
        );
    }
    home.join(path)
}

/// Where a shell that activates the integration from its own file keeps that file.
fn default_entry_path(kind: ShellKind) -> &'static str {
    match kind {
        ShellKind::Zsh => ".zshrc",
        ShellKind::Bash => ".bashrc",
        ShellKind::Fish => ".config/fish/conf.d/kr-kalareach.fish",
        ShellKind::PowerShell => ".config/powershell/Microsoft.PowerShell_profile.ps1",
    }
}

/// What the installed record says the package is, as a worker that launched it would read it.
fn declared_package(
    package: &Package,
) -> kr_shell_integration::contract::transport::PackageDeclaration {
    use kr_shell_integration::contract::transport::{
        ModuleEntry, PackageDeclaration, PatchRevision,
    };

    let shell = &package.record["shell"];
    let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_owned();
    PackageDeclaration {
        kind: package.kind,
        executable: package.executable.display().to_string(),
        upstream_version: text(&shell["upstream_version"]),
        editor_abi: text(&shell["editor_abi"]),
        integration_version: text(&shell["integration_version"]),
        patches: shell["patches"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|patch| PatchRevision {
                        name: text(&patch["name"]),
                        upstream_revision: text(&patch["upstream_revision"]),
                        revision: text(&patch["revision"]),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        modules: shell["modules"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|module| ModuleEntry {
                        name: text(&module["name"]),
                        search_path: text(&module["search_path"]),
                        editor_abi: text(&module["editor_abi"]),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// The marked block the package publishes, exactly as it publishes it.
fn package_entry(package: &Package) -> String {
    std::fs::read_to_string(&package.startup_entry)
        .unwrap_or_else(|error| panic!("{}: {error}", package.startup_entry.display()))
}

impl Session {
    /// Starts the packaged shell over one case's own home and completes the handshake.
    ///
    /// This is beside [`Session::start`] rather than inside it because the two answer different
    /// questions. That one starts a package against the configuration the package tests own; this
    /// one starts it against a person's, which the corpus supplies, and keeps the home after the
    /// shell has gone so what the startup files recorded can be read.
    ///
    /// # Panics
    ///
    /// Panics when the endpoint cannot be created, the shell does not connect, or the worker's own
    /// decision refuses the handshake: each is a failure of the package under test.
    #[must_use]
    pub fn start_for(package: &Package, case: &QualificationCase, setup: &CaseSetup) -> Self {
        let endpoint_path = setup.runtime.join("shell-bridge");
        // A session that starts twice over one home binds a fresh endpoint each time.
        let _ = std::fs::remove_file(&endpoint_path);
        let endpoint = BridgeEndpoint::unix(endpoint_path.to_string_lossy().into_owned());
        endpoint
            .validate()
            .expect("the endpoint path fits a socket address");
        let listener = UnixListener::bind(&endpoint_path).expect("the endpoint binds");
        std::fs::set_permissions(&endpoint_path, std::fs::Permissions::from_mode(0o600))
            .expect("an owner-only endpoint");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");

        let session_id = SessionId::new(Uuid::from_bytes([0x63; 16]));
        let secret: Vec<u8> = (0..BOOTSTRAP_SECRET_LEN)
            .map(|index| (index as u8).wrapping_mul(11))
            .collect();

        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pseudo-terminal");

        let mut command = CommandBuilder::new(package.executable.to_string_lossy().into_owned());
        match package.kind {
            ShellKind::PowerShell => {
                command.arg("-NoLogo");
                let mut module_path = package.module_directory.to_string_lossy().into_owned();
                if let Some(existing) = std::env::var_os("PSModulePath") {
                    module_path.push(':');
                    module_path.push_str(&existing.to_string_lossy());
                }
                command.env("PSModulePath", module_path);
                // The host's own image needs its runtime's location, which the qualification
                // recorded from the launcher that started the host it qualified.
                if let Some(environment) = package.record["launch"]["environment"].as_object() {
                    for (name, value) in environment {
                        if let Some(value) = value.as_str() {
                            command.env(name, value);
                        }
                    }
                }
            }
            _ => {
                command.arg("-i");
            }
        }
        command.cwd(&setup.home);
        for (name, value) in &setup.environment {
            command.env(name, value);
        }
        command.env("KR_SESSION", session_id.to_string());
        command.env("KR_SHELL_BRIDGE", &endpoint.path);
        command.env(
            "KR_SHELL_BRIDGE_SECRET",
            kr_protocol::scalars::to_base64url(&secret),
        );
        if let Some(trace) = std::env::var_os("KR_SHELL_BRIDGE_TRACE") {
            command.env("KR_SHELL_BRIDGE_TRACE", trace);
        }

        let child = pty
            .slave
            .spawn_command(command)
            .unwrap_or_else(|error| panic!("{} does not start: {error}", case.id));
        drop(pty.slave);

        let output = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        // From here to the session being built, anything can fail: the shell may never connect,
        // or its opening frame may not arrive. The guard ends and reaps the shell and stops the
        // thread reading its terminal, because the session that would have done both does not
        // exist yet and the cases after this one share the machine.
        let mut guard = SpawnGuard {
            child: Some(child),
            stopped: Arc::clone(&stopped),
        };
        let mut reader = pty.master.try_clone_reader().expect("a terminal reader");
        let collected = Arc::clone(&output);
        let finished = Arc::clone(&stopped);
        let writer: Arc<Mutex<Box<dyn Write + Send>>> = Arc::new(Mutex::new(
            pty.master.take_writer().expect("a terminal writer"),
        ));
        let answering = Arc::clone(&writer);
        let (finished_reading, stopped_reading) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            // A terminal read ends wherever the kernel had bytes, which can be in the middle of a
            // query an editor is waiting for an answer to. What has not been answered is carried
            // to the next read rather than dropped.
            let mut carried: Vec<u8> = Vec::new();
            while !finished.load(Ordering::Relaxed) {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(taken) => {
                        carried.extend_from_slice(&buffer[..taken]);
                        answer_carried_queries(&mut carried, &answering);
                        collected
                            .lock()
                            .expect("the output lock")
                            .extend_from_slice(&buffer[..taken]);
                    }
                }
            }
            drop(finished_reading);
        });

        let stream = accept_within(&listener, REPLY).unwrap_or_else(|| {
            panic!(
                "{} did not connect to the endpoint it was given; the terminal showed:\n{}",
                case.id,
                String::from_utf8_lossy(&output.lock().expect("the output lock"))
            )
        });
        stream
            .set_nonblocking(true)
            .expect("a non-blocking connection");

        // The session's own scratch directory. The case's home is the setup's and outlives this,
        // so what the startup files recorded can be read after the shell has gone.
        let scratch = tempfile::Builder::new()
            .prefix("kr-qualification-session-")
            .tempdir()
            .expect("a session directory on the internal disk");

        let child = guard.release();
        let mut session = Self {
            package_kind: package.kind,
            session_id,
            hello: placeholder_hello(session_id),
            accepted: placeholder_accept(session_id),
            prompt: "KR> ".to_owned(),
            mark: 0,
            reading: false,
            stepping: true,
            last_entry: None,
            stream,
            shut: false,
            peer_write_gone: false,
            peer_read_gone: false,
            closure_expected: false,
            budget: None,
            reader_lifetime: 0,
            reading_reader: None,
            pending: Vec::new(),
            events: Inbox::default(),
            answers: std::collections::HashMap::new(),
            next_request: 1,
            output,
            stopped,
            stopped_reading,
            writer,
            child,
            _master: pty.master,
            _directory: scratch,
        };

        let hello = match session.read_frame(REPLY) {
            Some(BridgeFrame::Hello(hello)) => hello,
            other => panic!(
                "{} opened with {other:?}; the terminal showed:\n{}",
                case.id,
                session.terminal_output()
            ),
        };
        let transcript = bootstrap_transcript(
            session.session_id,
            &endpoint,
            &hello.shell_process,
            &hello.shell.integration_version,
        )
        .expect("the transcript encodes");
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&secret).expect("any key length");
        mac.update(&transcript);
        let verdict = if mac.verify_slice(hello.proof.as_slice()).is_ok() {
            ProofVerdict::Verified
        } else {
            ProofVerdict::Failed
        };
        let expectation = WorkerExpectation {
            session_id: session.session_id,
            root_process: hello.shell_process.clone(),
            supported_editor_abis: vec![hello.shell.editor_abi.clone()],
            supported_integration_versions: vec![hello.shell.integration_version.clone()],
            // This harness is the worker's side of one session and it launched the package it is
            // driving, so the declaration the shell makes is compared against the record that
            // build wrote beside the binary, which is what a worker does with a package it
            // started.
            launched_package: Some(declared_package(package)),
            already_registered: false,
            gesture: kr_shell_integration::contract::events::EofGesture::default(),
        };
        let peer = ObservedPeer {
            uid: endpoint_owner(&endpoint_path),
            process: Some(hello.shell_process.clone()),
        };
        let accepted = match decide_handshake(&expectation, &peer, &hello, verdict) {
            HandshakeOutcome::Accepted(accepted) => accepted,
            HandshakeOutcome::Refused(refused) => {
                panic!("{} was refused: {:?}", case.id, refused.reason)
            }
        };
        session.write_frame(&BridgeFrame::Handshake(HandshakeOutcome::Accepted(
            accepted.clone(),
        )));
        session.hello = hello;
        session.accepted = accepted;
        session
    }

    /// Waits until this editor is reading the terminal itself, before a key is offered to it.
    ///
    /// An editor that takes the terminal out of its own line mode reads a key as the key it binds.
    /// One typed before it takes the terminal goes through the terminal's own line discipline
    /// instead: an ordinary character waits there and reaches the editor when it takes over, but
    /// the end-of-file character is the line discipline's own and is answered by the terminal
    /// rather than held for anybody. A key of that kind offered a moment early is gone, whichever
    /// of these four readers it was meant for.
    ///
    /// So no session here offers a key until the reader has said, in a report of its own, that it
    /// is inside the read the key is meant for. Nothing infers it from a length of silence or from
    /// a report that could belong to another prompt.
    ///
    /// The three native readers write their idle report from inside the editor's own read loop,
    /// where it is about to wait for a key and the terminal is already in the editor's modes, so
    /// one report of theirs is the proof. The fourth writes its first report of a prompt before it
    /// calls `ReadLine`, so there a probe is drawn and [`readiness_of`] decides the reports that
    /// follow it.
    ///
    /// # Panics
    ///
    /// Panics when the shell draws no prompt at all, and when the reader never says it is inside
    /// the read this waited for.
    pub fn ensure_reading(&mut self) {
        assert!(
            self.reading,
            "no reader of this shell's has reported itself yet, so there is nothing here to \
             probe; the terminal showed:\n{}",
            self.terminal_output()
        );
        let deadline = self.deadline_for(READINESS);
        let mut probes = 0;
        let mut stopped = ProbeStop::NoBarrierAnswer;
        while !deadline.passed() {
            probes += 1;
            stopped = self.probe_for_a_reading_editor(deadline);
            if stopped == ProbeStop::Reading {
                return;
            }
        }
        panic!(
            "{probes} probes in {READINESS:?} and the reader never said it was inside its read at \
             the prompt it was probed at; the last one stopped where {}:\n{}",
            stopped.as_str(),
            self.terminal_output()
        );
    }

    /// Draws one probe and waits the reader out, returning whether it said it was reading.
    ///
    /// One path for every reader, because the thing that has to hold is one thing: the report this
    /// accepts was written after the session asked for it, by the reader the session means, with
    /// the line empty and nothing queued. The barrier below is what makes a report fresh, the
    /// probe's own report is what names the reader, and the clear is what settles it. Nothing here
    /// depends on which keys the editor has bound to what, because the probe does not require the
    /// line to stay as it was: whatever the two keys do to it, the clear takes it away and the
    /// report after that is the one this reads.
    ///
    /// Anything but [`ProbeStop::Reading`] is a probe that ended without its answer: a reader that
    /// has moved is probed again where it is now, and a deadline that has passed ends the wait in
    /// [`Session::ensure_reading`] rather than here. The step it ended at is carried back so a
    /// failure says which question went unanswered rather than only that one did.
    fn probe_for_a_reading_editor(&mut self, deadline: Deadline) -> ProbeStop {
        self.within_budget(deadline, Self::draw_one_probe)
    }

    /// The probe itself, with every wait inside it answering to the budget now in force.
    fn draw_one_probe(&mut self) -> ProbeStop {
        let deadline = self.deadline_for(READINESS);
        // Nothing here reads the terminal for a prompt. A theme draws its prompt with its own
        // colour changes between the characters of it, so the text a case configured never appears
        // in the output as one run of bytes, and a session that waited for it would wait for ever
        // at a prompt that is plainly drawn. What says a reader is there is the reader's own
        // report below; what says a key reached it is the line that report carries. A key typed
        // while the shell is still running a command is held by the terminal and delivered at the
        // next prompt, which is a prompt this probe is equally about.
        self.type_bytes(b"x");
        // Everything the reader said before this moment is about a line that is gone, and some of
        // it looks exactly like what this is about to ask for: a check that typed a character and
        // cleared it leaves a report of a held line and a report of an empty one behind it. A
        // request of this session's own is the barrier. The reader reads its mailbox in order, so
        // an answer to this request is every report the reader wrote before it having arrived too,
        // and what is dropped here is all of it. Whether the reader acknowledges or says it has
        // moved on does not matter: either is the answer this waits for.
        let barrier = self.ask(WorkerRequest::Fence(RootEditorFenceParams {
            session_id: self.session_id,
            fence_id: fence_id(200),
            prompt_generation: self.last_entry.as_ref().map_or_else(
                || kr_protocol::root::PromptGeneration::new(0),
                |entry| entry.prompt_generation,
            ),
            reader_revision: self.last_entry.as_ref().map_or_else(
                || kr_protocol::root::ReaderRevision::new(0),
                |entry| entry.reader_revision,
            ),
            deadline_ms: FENCE_EXCHANGE_TIMEOUT,
            cause: FenceCause::Retry,
        }));
        if self.answer_by(barrier, deadline).is_none() {
            return ProbeStop::NoBarrierAnswer;
        }
        self.forget_events();
        // From here the session types every key itself. Acknowledging an event types one too --
        // this editor reaches its own queue when the reader steps, so an answer carries a step
        // with it -- and a key of that kind in flight is a key in the queue the reports below are
        // read for. They are held off until the two reports have been seen.
        let stepping = self.stepping;
        self.stepping = false;
        let stop = self.watch_the_reader_clear_the_probe(deadline);
        self.stepping = stepping;
        stop
    }

    /// Watches the reader hold the probe and then report the line the clear took away.
    ///
    /// The first report is behind the barrier, so the reader wrote it after this session asked for
    /// it: it is this probe's own answer rather than something said earlier. It also proves the
    /// reader is inside its read, because the buffer it carries holds the probe and none of these
    /// readers reads its buffer anywhere else. The second report is the one [`readiness_of`] calls
    /// [`ReadinessStep::Ready`], at that same reader.
    fn watch_the_reader_clear_the_probe(&mut self, deadline: Deadline) -> ProbeStop {
        // The probe character is the editor's own insertion, which these packages do not sit in
        // front of, so the reader is given one key it does have a binding for and the boundary
        // that key ends at is where the reader reads its own state and reports it. What the key
        // does to the line does not matter: the clear below takes the line away either way.
        self.type_bytes(STEP_KEY);
        let Some(held) = self.next_reader_report(deadline, |report| !report.mark.buffer_empty)
        else {
            return ProbeStop::NoProbeReport;
        };
        let since = held.mark;
        // The clear is typed rather than driven through [`Session::clear_line`], whose settling
        // sleep is a constant this probe's own budget does not own. What follows it is a wait for
        // the reader's report, which is the same thing said as an observation.
        self.type_bytes(CTRL_U);
        loop {
            while let Some(report) = self.take_reader_report() {
                match readiness_of(&since, &report) {
                    ReadinessStep::Ready => {
                        self.reading_reader = Some(report.mark);
                        return ProbeStop::Reading;
                    }
                    ReadinessStep::Moved => return ProbeStop::Moved,
                    ReadinessStep::Behind | ReadinessStep::Busy => {}
                }
            }
            if deadline.passed() {
                return ProbeStop::NoSettledReport;
            }
            self.pump(Duration::from_millis(25));
        }
    }

    /// The reader the last successful probe left this session looking at.
    ///
    /// A key offered after [`Session::ensure_reading`] is offered to this reader, so a drive that
    /// wants to say what the key reached compares what it sees afterwards against this.
    ///
    /// # Panics
    ///
    /// Panics when no probe has succeeded yet, which is a drive claiming a reader it never found.
    #[must_use]
    pub fn reading_reader(&self) -> ReaderMark {
        self.reading_reader
            .clone()
            .expect("a probe has said which reader is reading")
    }

    /// Waits for the next thing the reader says about itself, for a drive that reads its state.
    ///
    /// This is how a drive asserts the state it claims: the keymap, what the reader is in the
    /// middle of and what its queues hold are all read out of a report the reader wrote, rather
    /// than assumed from the keys that were typed. The report says which reader wrote it, so a
    /// drive can ask later whether the key it offered went to that same one.
    pub fn reader_said(&mut self, within: Duration) -> Option<ReaderReport> {
        let deadline = Deadline::after(self.bounded(within));
        self.next_reader_report(deadline, |_| true)
    }

    /// Asks the reader that is running what it is doing, and returns its whole answer.
    ///
    /// A reader waiting inside an operation of the person's reaches no key boundary and so writes
    /// no report of its own. The exchange is how it is asked anyway, and its answer carries the
    /// same identity and the same state a report would.
    ///
    /// # Errors
    ///
    /// Returns why the state could not be read. Nothing answering is one of those reasons and it
    /// is not a fault of the shell's: a startup customisation can put a widget of its own on the
    /// key a drive types, and a widget that holds the terminal reaches no key boundary and answers
    /// no exchange while it does. A drive that can carry on without the state narrows its claim to
    /// what it did see and puts this reason in its record; one whose whole subject is the reader
    /// this names says which reader it could not read.
    pub fn reader_state_now(
        &mut self,
        enter: &RootEditorEnterParams,
        fence: FenceId,
    ) -> Result<ReaderMark, String> {
        // A reader that redrew its prompt between the entry this names and the question answers
        // honestly: this is not the reader you asked about. What a worker does then is ask the one
        // that is there now, and which one that is comes from the reader's own next report rather
        // than from waiting for a fresh prompt: an editor can take a new revision at the prompt it
        // is already at, and no entry is owed for that.
        let deadline = self.deadline_for(FENCE);
        let mut asked = (enter.prompt_generation, enter.reader_revision);
        let mut attempts = 0;
        loop {
            attempts += 1;
            let id = self.ask(WorkerRequest::Fence(RootEditorFenceParams {
                session_id: self.session_id,
                fence_id: fence,
                prompt_generation: asked.0,
                reader_revision: asked.1,
                deadline_ms: FENCE_EXCHANGE_TIMEOUT,
                cause: FenceCause::Retry,
            }));
            match self.answer_by(id, deadline) {
                Some(BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(acknowledgement))) => {
                    return Ok(ReaderMark::of_acknowledgement(
                        &acknowledgement,
                        self.reader_lifetime,
                    ));
                }
                Some(BridgeAnswer::Fence(RootEditorFenceResult::Refused(refusal)))
                    if refusal.reason == kr_protocol::root::FenceRefusalReason::ReaderMoved =>
                {
                    let Some(report) = self.next_reader_report(deadline, |_| true) else {
                        return Err(format!(
                            "the reader moved under every one of {attempts} fences in {FENCE:?} \
                             and reported no reader to ask instead"
                        ));
                    };
                    asked = (report.idle.prompt_generation, report.idle.reader_revision);
                }
                // Nothing answered. Something that is not this reader has the terminal, and what
                // it is holding cannot be read from here.
                None => {
                    return Err(format!(
                        "nothing answered any of {attempts} fences in {FENCE:?}, so this session \
                         read no state of the reader's at all"
                    ));
                }
                other => {
                    return Err(format!(
                        "the reader answered a fence for the reader it is running with {other:?}"
                    ));
                }
            }
        }
    }

    /// Offers `keys` until the reader says a typed line would be text, and returns what it said.
    ///
    /// A teardown that types a key and carries on is a teardown that assumed it worked. This one
    /// reads the keymap out of the reader's own reports, so the command a drive runs next goes to
    /// a reader that will read it as a command. The reports are what it reads rather than a fence
    /// exchange after every offer, which was tried and does not work here: one such loop offered
    /// the insertion key 199 times in 30 seconds and the reader reported the same keymap
    /// throughout. A report is written where the reader has nothing left to read, which is the
    /// moment the question is about. The whole of it is one deadline, and the offers are counted
    /// for the record rather than used to decide.
    ///
    /// # Errors
    ///
    /// Returns the keymap the reader kept where it reported one throughout, and says it reported
    /// nothing where a reader something else is holding never wrote a report at all.
    pub fn reader_takes_typed_text(
        &mut self,
        keys: &[&[u8]],
        within: Duration,
    ) -> Result<ReaderMark, String> {
        let deadline = Deadline::after(self.bounded(within));
        // What the reader has already said about itself, waiting for nothing: the keys that ended
        // the drive's state are reports of their own, and a reader that never left the keymap it
        // types text in has nothing here to do.
        let mut seen = self.report_in_hand().map(|report| report.mark);
        let mut last = seen.clone();
        let mut offers = 0;
        while seen.as_ref().is_none_or(|mark| !mark.takes_typed_text()) {
            if keys.is_empty() || deadline.passed() {
                break;
            }
            for bytes in keys.iter().copied() {
                self.type_bytes(bytes);
                std::thread::sleep(self.bounded(Duration::from_millis(80)));
            }
            offers += 1;
            seen = self
                .next_reader_report(deadline, |_| true)
                .map(|report| report.mark);
            if seen.is_some() {
                last.clone_from(&seen);
            }
        }
        match last {
            Some(mark) if mark.takes_typed_text() => Ok(mark),
            Some(mark) => Err(format!(
                "the reader kept its {} keymap through {offers} offers of the keys that leave it, \
                 so a line typed at it would be motions rather than a command",
                mark.keymap.as_str()
            )),
            None => Err(format!(
                "the reader wrote no report of its own through {offers} offers of the keys that \
                 leave the state this drive put it in"
            )),
        }
    }

    /// The newest report of the reader's this session has already been told, waiting for none.
    fn report_in_hand(&mut self) -> Option<ReaderReport> {
        self.pump(Duration::from_millis(50));
        let mut newest = None;
        while let Some(report) = self.take_reader_report() {
            newest = Some(report);
        }
        newest
    }

    /// Whether the reader says it is replaying input of its own rather than reading the terminal.
    ///
    /// Asked through a fence exchange, because a reader consuming a macro reaches no key boundary
    /// of its own while it does. A reader that has already finished the replay answers no, which
    /// is honest: what this returns is whether the replay was seen, and a drive that did not see
    /// it says so rather than assuming it happened.
    pub fn reader_replaying(&mut self, enter: &RootEditorEnterParams, fence: FenceId) -> bool {
        let id = self.ask(WorkerRequest::Fence(RootEditorFenceParams {
            session_id: self.session_id,
            fence_id: fence,
            prompt_generation: enter.prompt_generation,
            reader_revision: enter.reader_revision,
            deadline_ms: FENCE_EXCHANGE_TIMEOUT,
            cause: FenceCause::Retry,
        }));
        let deadline = self.deadline_for(REPLY);
        match self.answer_by(id, deadline) {
            Some(BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(acknowledgement))) => {
                replay_seen(&acknowledgement)
            }
            // A reader that moved, refused or said nothing is a reader this did not see replaying.
            _ => false,
        }
    }

    /// Whether no more than `allowed` managed decisions arrived since the drive's boundary.
    ///
    /// Not a window, and not the queue. The inbox counts every decision as it arrives, so one
    /// that arrived while the drive was waiting for something else, and one that a later wait took
    /// off the queue with what stood in front of it, are both still counted here. What is read is
    /// everything since the last [`Session::forget_events`], after whatever is already on the
    /// endpoint has been taken in. `allowed` is how many of them the drive asked for itself.
    pub fn no_managed_decision_before(&mut self, allowed: usize) -> bool {
        self.pump(Duration::from_millis(200));
        self.events.managed_decisions() <= allowed
    }

    /// Whether the reader this session is looking at is still the one a report named.
    ///
    /// A reader that has left, or one that has been replaced at the same prompt, makes every
    /// observation of it an observation of something that is gone.
    #[must_use]
    pub fn still_the_same_reader(&self, mark: &ReaderMark) -> bool {
        self.reader_lifetime == mark.lifetime
    }

    /// Waits for the shell itself to end, which is its own answer to an end of file.
    ///
    /// The bridge goes with the shell, so a write that finds it gone is a result here rather than
    /// a fault, and whatever the bridge sent before it went is still read and kept.
    pub fn ended_within(&mut self, within: Duration) -> bool {
        let deadline = Deadline::after(self.bounded(within));
        self.expecting_the_bridge_to_go(|session| {
            loop {
                if !session.alive() {
                    return true;
                }
                if deadline.passed() {
                    return false;
                }
                session.pump(Duration::from_millis(50));
            }
        })
    }

    /// Takes the next report of the reader's off this session's queue, where one has arrived.
    ///
    /// What is in front of it is dropped, as [`Session::expect_event`] drops it: each call asks
    /// for the next thing the reader said about itself. Nothing is dropped unread, though: the
    /// lifecycle events this passes were counted on the endpoint, so a report taken from behind a
    /// reader's leave carries a stamp that says so, and a managed decision it passes was counted
    /// by the inbox as it arrived.
    fn take_reader_report(&mut self) -> Option<ReaderReport> {
        let (idle, lifetime) = self.events.take_reader_report()?;
        let mark = ReaderMark::of(&idle, lifetime);
        Some(ReaderReport { mark, idle })
    }

    /// Waits until `deadline` for the next report of the reader's that `accept` takes.
    pub(super) fn next_reader_report<F>(
        &mut self,
        deadline: Deadline,
        accept: F,
    ) -> Option<ReaderReport>
    where
        F: Fn(&ReaderReport) -> bool,
    {
        loop {
            while let Some(report) = self.take_reader_report() {
                if accept(&report) {
                    return Some(report);
                }
            }
            if deadline.passed() {
                return None;
            }
            self.pump(Duration::from_millis(25));
        }
    }

    /// Presses the key the case's own binding is on and waits for what that binding writes.
    ///
    /// The text comes from the binding rather than from the two bytes that were typed, so seeing
    /// it drawn is the binding having run rather than the terminal having echoed. Only what
    /// arrives after the key counts: a case that had already printed the same word would
    /// otherwise pass without the binding running at all.
    /// # Errors
    ///
    /// Returns which step did not happen: a shell that answers nothing before the key is offered
    /// is a shell that cannot say anything about the key, and saying so is not the same as saying
    /// the binding did not survive.
    pub fn user_binding_ran(&mut self) -> Result<(), String> {
        // A command of this session's own first. The key is about to be judged by what the editor
        // draws, and an editor that is drawing nothing at all would fail that judgement whatever
        // the binding does.
        let liveness = liveness_command(self.package_kind);
        if !self.run(liveness, LIVENESS_MARKER) {
            return Err(format!(
                "the shell answered nothing to {liveness} before the key was offered"
            ));
        }
        let start = self.written();
        let mut settled = true;
        let mut offers = 0;
        // An editor that takes the terminal out of its own line mode can still be between one
        // read and the next, where the two bytes go to the line discipline instead. The key is
        // offered again while there is time for another offer; what the binding writes is the same
        // text either way. What ends this is the clock, not a number of tries: the number is kept
        // for the failure to report, and decides nothing.
        let deadline = self.deadline_for(BINDING);
        loop {
            if offers > 0 {
                // The key that was offered and did nothing may have left the editor holding a
                // prefix, waiting for the rest of a sequence that is never coming. Every editor
                // here abandons what it is part way through on this key, which is what a person
                // does before pressing theirs again.
                self.type_bytes(CTRL_G);
                // Every wait counts, not the last one: one that ran out is what the failure below
                // says, whether or not a later one went quiet.
                settled &= self.quiet_for(Duration::from_millis(150), Duration::from_secs(2));
            }
            // This ends at the reader's own report that it is at an empty line and waiting for a
            // key, so the chord below is offered to a reader that is there to read it.
            self.ensure_reading();
            self.type_bytes(USER_BINDING_KEY);
            offers += 1;
            // An offer is given the rest of the budget or one reader's reply, whichever is less,
            // so a binding that answers late still answers inside the one budget this owns.
            let within = deadline.at_most(REPLY);
            if self
                .drew_after(start, USER_BINDING_TEXT, within)
                .was_drawn()
            {
                return Ok(());
            }
            if deadline.passed() {
                break;
            }
        }
        Err(format!(
            "the key was offered {offers} times in {BINDING:?} and wrote no {USER_BINDING_TEXT}; \
             {} between the offers",
            if settled {
                "the terminal went quiet before every deadline"
            } else {
                "at least one wait for the terminal ran out before it went quiet"
            }
        ))
    }

    /// Waits until the terminal has shown nothing for `quiet`, and no longer than `cap`.
    ///
    /// Returns whether the terminal did go quiet, because the two are not the same answer: a
    /// terminal still drawing when the cap is reached is a terminal this did not wait out, and a
    /// caller that reads the return says so rather than carrying on as though it had.
    ///
    /// What this is for is knowing that a shell has stopped drawing where nothing of the reader's
    /// own says so. Where the reader does say so, its own report decides instead.
    pub fn quiet_for(&mut self, quiet: Duration, cap: Duration) -> bool {
        let deadline = Instant::now() + self.bounded(cap);
        let mut shown = self.written();
        let mut since = Instant::now();
        while Instant::now() < deadline {
            self.pump(Duration::from_millis(25));
            let now = self.written();
            if now == shown {
                if since.elapsed() >= quiet {
                    return true;
                }
            } else {
                shown = now;
                since = Instant::now();
            }
        }
        false
    }

    /// Proves the shell and the bridge are both still working, after a check that ended on an
    /// absence.
    ///
    /// A check whose conclusion is "nothing happened" has to say what the shell was doing while
    /// nothing happened. A process that had gone, an endpoint one side had dropped and a bridge
    /// that had stopped sending would all satisfy such a check by doing nothing at all, and
    /// [`Session::alive`] separates only the first of the three. So this asks for all of it: the
    /// process is running, the endpoint is whole both ways, the shell runs a command of this
    /// session's own, and the bridge reports the reader leaving and coming back while it does.
    ///
    /// # Errors
    ///
    /// Returns what was not true, for a caller that names its own check in the failure.
    pub fn still_serving(&mut self, marker: &str) -> Result<(), String> {
        if !self.alive() {
            return Err("the shell is no longer running".to_owned());
        }
        if !self.endpoint_open() {
            return Err(format!(
                "the endpoint is no longer whole ({})",
                self.endpoint_state()
            ));
        }
        let lifecycle = self.reader_lifetime;
        if !self.answered(marker) {
            return Err(format!(
                "the shell printed no {marker} for a command of this session's own; the terminal \
                 showed:\n{}",
                self.terminal_output()
            ));
        }
        if !self.endpoint_open() {
            return Err(format!(
                "the endpoint stopped being whole while the shell ran a command ({})",
                self.endpoint_state()
            ));
        }
        // The marker reaches the screen from the command, and the reader's own events reach the
        // endpoint from the bridge, so the two do not arrive together. This waits for the second
        // rather than reading it at the moment the first arrives. What it waits for is the reader
        // coming back, not the lifecycle count moving: a reader that left and never returned moves
        // that count once, and a bridge that went with it moves it once too. So the reader has to
        // enter again, and the endpoint has to be whole after it does.
        let deadline = self.deadline_for(REPLY);
        let returned = self.next_prompt_after(lifecycle, deadline).is_some();
        if !returned {
            return Err(format!(
                "the shell ran the command and printed {marker}, but in {REPLY:?} afterwards the \
                 bridge reported no reader entering, so the endpoint is not carrying the reader's \
                 own events (the lifecycle count went from {lifecycle} to {}, and the endpoint is \
                 {})",
                self.reader_lifetime,
                self.endpoint_state()
            ));
        }
        if !self.endpoint_open() {
            return Err(format!(
                "the reader came back and the endpoint then stopped being whole ({})",
                self.endpoint_state()
            ));
        }
        if !self.alive() {
            return Err("the reader came back and the shell then stopped running".to_owned());
        }
        Ok(())
    }

    /// How much the terminal has shown so far, as an offset a later wait counts from.
    #[must_use]
    pub fn written(&self) -> usize {
        self.output.lock().expect("the output lock").len()
    }

    /// Waits for `needle` in what the terminal showed after `start`.
    ///
    /// This and the call below it are the mechanism the checked command API and the display
    /// observations are built on, and they are not offered to a check directly: a check that read
    /// the screen for itself would be deciding on its own what the screen is allowed to prove.
    pub(super) fn wait_for_output_after(
        &mut self,
        start: usize,
        needle: &str,
        within: Duration,
    ) -> bool {
        let deadline = Deadline::after(self.bounded(within));
        self.wait_for_output_after_by(start, needle, deadline)
    }

    /// Waits for it until `deadline`, for a caller that owns a budget of its own.
    pub(super) fn wait_for_output_after_by(
        &mut self,
        start: usize,
        needle: &str,
        deadline: Deadline,
    ) -> bool {
        loop {
            {
                let output = self.output.lock().expect("the output lock");
                let from = start.min(output.len());
                if find(&output[from..], needle.as_bytes()) {
                    return true;
                }
            }
            if deadline.passed() {
                return false;
            }
            self.pump(Duration::from_millis(25));
        }
    }

    /// Takes the reader to a fenced empty prompt that nothing before this has a claim on.
    ///
    /// A check that has just run commands leaves reader entries in this session's own event
    /// queue, and the next one taken from it names a reader that has since moved. Clearing the
    /// queue and running one command of this session's own is what makes the prompt that follows
    /// the one the fence is about.
    ///
    /// # Panics
    ///
    /// Panics when the shell does not answer, which is a shell that has stopped reading.
    pub fn fenced_after_a_command(&mut self, index: u8) -> (RootEditorEnterParams, EditorFence) {
        self.recover();
        self.forget_events();
        assert!(
            self.answered("kr-fence-ready"),
            "the shell did not answer before a fence was asked for:\n{}",
            self.terminal_output()
        );
        let published = self.fenced_latest(index);
        // An editor that reaches its own queue only when the reader steps has not taken the
        // publication frame yet, and a gesture sent before it does is decided against the fence
        // that was there before. A request sent after the publication is the barrier: the reader
        // reads its mailbox in order, so an answer to that request is the publication having been
        // read. Waiting for the answer is what puts the two in a known order, rather than a sleep.
        if dialect(self.package_kind).answers_at_the_next_step {
            let barrier = self.ask(WorkerRequest::Fence(RootEditorFenceParams {
                session_id: self.session_id,
                fence_id: published.1.fence_id,
                prompt_generation: published.0.prompt_generation,
                reader_revision: published.0.reader_revision,
                deadline_ms: FENCE_EXCHANGE_TIMEOUT,
                cause: FenceCause::Retry,
            }));
            let _ = self.answer(barrier);
        }
        published
    }

    /// Waits for the hooks the guarded entry activates and the first primary reader, patiently.
    ///
    /// A startup that loads a framework reads hundreds of files and builds a completion cache
    /// before it draws anything, and on a machine running several of these at once that takes
    /// longer than a reader is normally given to answer. This is the one wait in a case that is
    /// about the person's own startup rather than about the reader, so it is given its own budget.
    ///
    /// # Panics
    ///
    /// Panics when the startup entry never activates or no reader reports itself, which is a
    /// package that did not come up rather than one that was slow.
    pub fn first_prompt_within(&mut self, within: Duration) -> RootEditorEnterParams {
        self.first_within("hooks_activated", within, |event| {
            matches!(event, BridgeEvent::HooksActivated(_))
        });
        let received = self.first_within("the first editor entry", within, |event| {
            matches!(event, BridgeEvent::EditorEnter(_))
        });
        // From here the shell has a reader, so a key typed at it is a step it takes.
        self.reading = true;
        let entry = as_enter(&received.event).clone();
        self.last_entry = Some(entry.clone());
        entry
    }

    /// Waits up to `within` of its own for the first event `accept` takes, dropping what is in
    /// front of it.
    ///
    /// # Panics
    ///
    /// Panics when no such event arrives, naming `what` it was.
    fn first_within(
        &mut self,
        what: &str,
        within: Duration,
        accept: impl Fn(&BridgeEvent) -> bool,
    ) -> Received {
        let deadline = Instant::now() + within;
        loop {
            if let Some(received) = self.events.take_first(|received| accept(&received.event)) {
                return received;
            }
            assert!(
                Instant::now() < deadline,
                "no {what} arrived in {within:?}; the terminal showed:\n{}",
                self.terminal_output()
            );
            self.pump(Duration::from_millis(100));
        }
    }

    /// The primary reader that is running now, rather than the first one still in the queue.
    ///
    /// A reader that leaves and comes back reports both, and an editor that redraws its prompt can
    /// report several in a row. A fence names one reader, so it has to name the one the gesture
    /// after it will be read by: the newest entry this session has been told about.
    ///
    /// # Panics
    ///
    /// Panics when no primary reader reports itself at all.
    pub fn latest_prompt(&mut self) -> RootEditorEnterParams {
        let mut newest = self.next_prompt();
        self.pump(Duration::from_millis(200));
        while let Some(received) = self.events.take_first(|received| {
            matches!(
                &received.event,
                BridgeEvent::EditorEnter(params)
                    if params.reader_context == kr_protocol::root::ReaderContext::Primary
            )
        }) {
            newest = as_enter(&received.event).clone();
        }
        self.last_entry = Some(newest.clone());
        newest
    }

    /// Waits until `deadline` for a primary reader that entered after `lifecycle`, where one does.
    ///
    /// An entry already on the queue is about a prompt from before, so what this takes is one the
    /// endpoint stamped with a later count. Nothing it passes over is lost: a managed decision is
    /// counted where it arrives.
    fn next_prompt_after(
        &mut self,
        lifecycle: u64,
        deadline: Deadline,
    ) -> Option<RootEditorEnterParams> {
        loop {
            let found = self.events.take_first(|received| {
                received.reader_lifetime > lifecycle
                    && matches!(
                        &received.event,
                        BridgeEvent::EditorEnter(params)
                            if params.reader_context == kr_protocol::root::ReaderContext::Primary
                    )
            });
            if let Some(received) = found {
                let entry = as_enter(&received.event).clone();
                self.last_entry = Some(entry.clone());
                return Some(entry);
            }
            if deadline.passed() {
                return None;
            }
            self.pump(Duration::from_millis(50));
        }
    }

    /// Takes the reader that is running now to a fenced empty prompt.
    ///
    /// # Panics
    ///
    /// Panics when that reader reports a queue still holding input at an empty prompt.
    pub fn fenced_latest(&mut self, index: u8) -> (RootEditorEnterParams, EditorFence) {
        // A reader can leave between reporting itself and being asked — a prompt redrawn, a
        // nested read returning — and the reader's answer to that is honest: this is not the
        // reader you asked about. What a worker does then is ask the one that is there now, at
        // its next boundary, which is what this does rather than calling the refusal a failure.
        // What ends the asking is the clock; the count is kept for the failure to report.
        let deadline = self.deadline_for(FENCE);
        let mut attempts = 0;
        loop {
            attempts += 1;
            let enter = self.latest_prompt();
            let fence = fence_for(&enter, fence_id(index), attachment_id(1), epoch(4));
            let asked = self.ask(WorkerRequest::Fence(RootEditorFenceParams {
                session_id: self.session_id,
                fence_id: fence.fence_id,
                prompt_generation: enter.prompt_generation,
                reader_revision: enter.reader_revision,
                deadline_ms: FENCE_EXCHANGE_TIMEOUT,
                cause: FenceCause::EditorEntry,
            }));
            match self.answer(asked) {
                BridgeAnswer::Fence(RootEditorFenceResult::Acknowledged(acknowledgement)) => {
                    assert!(
                        acknowledgement.queues.tty_typeahead_drained
                            && acknowledgement.queues.macro_input_drained
                            && acknowledgement.queues.partial_key_drained,
                        "an idle reader reported a queue still holding input: {:?}",
                        acknowledgement.queues
                    );
                    self.publish(&fence);
                    return (enter, fence);
                }
                BridgeAnswer::Fence(RootEditorFenceResult::Refused(refusal))
                    if refusal.reason == kr_protocol::root::FenceRefusalReason::ReaderMoved =>
                {
                    assert!(
                        !deadline.passed(),
                        "the reader moved under every one of {attempts} fences in {FENCE:?}; the \
                         terminal showed:\n{}",
                        self.terminal_output()
                    );
                    std::thread::sleep(self.bounded(Duration::from_millis(200)));
                }
                other => panic!(
                    "the reader answered a fence for the reader it is running with {other:?}"
                ),
            }
        }
    }

    /// Puts the reader back where a drive left it, before anything is asked of it.
    ///
    /// A check that drove an excluded state can leave the editor inside a listing, a search or a
    /// pending sequence. The keys here are the ones every one of these editors answers with
    /// "stop what you are doing and keep the line", followed by clearing the line itself.
    pub fn recover(&mut self) {
        // An editor whose own queue the reader steps to reach is left out of the interrupt: that
        // key ends its read altogether there, and the reader that comes back is a different one
        // from the one a fence would have been about.
        let keys: &[&[u8]] = if dialect(self.package_kind).answers_at_the_next_step {
            &[CTRL_G, CTRL_U]
        } else {
            &[CTRL_G, CTRL_C, CTRL_U]
        };
        for bytes in keys.iter().copied() {
            self.type_bytes(bytes);
            std::thread::sleep(self.bounded(Duration::from_millis(80)));
        }
        std::thread::sleep(self.bounded(Duration::from_millis(120)));
    }

    /// Asks the shell whether the case's customisation is loaded and working.
    ///
    /// Where the case gives a second command, the first is what the customisation is meant to act
    /// on and the second reads back what it did, which is the customisation doing its job rather
    /// than a variable saying it is there.
    ///
    /// # Errors
    ///
    /// Returns the command that did not answer as the case said it would.
    pub fn plugin_is_active(&mut self, probe: &PluginProbe) -> Result<(), String> {
        if !self.run(&probe.probe, &probe.marker) {
            return Err(format!(
                "{} printed nothing like {}",
                probe.probe, probe.marker
            ));
        }
        if let (Some(command), Some(marker)) = (&probe.operation, &probe.operation_marker) {
            let _ = self.next_prompt();
            std::thread::sleep(self.bounded(Duration::from_millis(300)));
            if !self.run(command, marker) {
                return Err(format!("{command} printed nothing like {marker}"));
            }
        }
        Ok(())
    }
}

/// Holds a shell that has started until the session that owns it exists.
struct SpawnGuard {
    child: Option<Box<dyn Child + Send + Sync>>,
    stopped: Arc<AtomicBool>,
}

impl SpawnGuard {
    /// Hands the shell to the session, after which the session ends it.
    fn release(&mut self) -> Box<dyn Child + Send + Sync> {
        self.child.take().expect("the shell is still held here")
    }
}

impl Drop for SpawnGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        // The terminal keeps being read while the shell goes away: a process whose last bytes
        // have nowhere to go cannot finish leaving.
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        self.stopped.store(true, Ordering::Relaxed);
    }
}

/// The queries a terminal is expected to answer, and what this one answers them with.
const TERMINAL_QUERIES: &[(&[u8], &[u8])] = &[
    (b"\x1b[6n", b"\x1b[1;1R"),
    (b"\x1b[0c", b"\x1b[?6c"),
    (b"\x1b[c", b"\x1b[?6c"),
    (b"\x1b]11;?", b"\x1b]11;rgb:0000/0000/0000\x1b\\"),
];

/// Answers every complete query in `carried` and keeps only what could still become one.
///
/// A read ends wherever the kernel had bytes, so a query can arrive in two pieces. Each answer is
/// sent once: everything up to the last query answered is dropped, and what is kept afterwards is
/// shorter than the longest query, which is as much as an unfinished one can be.
fn answer_carried_queries(carried: &mut Vec<u8>, writer: &Arc<Mutex<Box<dyn Write + Send>>>) {
    let mut reply: Vec<u8> = Vec::new();
    let mut answered = 0;
    let mut index = 0;
    while index < carried.len() {
        let matched = TERMINAL_QUERIES.iter().find_map(|(query, answer)| {
            carried[index..]
                .starts_with(query)
                .then_some((query.len(), *answer))
        });
        match matched {
            Some((length, answer)) => {
                reply.extend_from_slice(answer);
                index += length;
                answered = index;
            }
            None => index += 1,
        }
    }
    let longest = TERMINAL_QUERIES
        .iter()
        .map(|(query, _)| query.len())
        .max()
        .unwrap_or(1);
    let keep_from = answered.max(carried.len().saturating_sub(longest - 1));
    carried.drain(..keep_from);
    if reply.is_empty() {
        return;
    }
    if let Ok(mut writer) = writer.lock() {
        let _ = writer.write_all(&reply);
        let _ = writer.flush();
    }
}

/// What one case's run concluded, for the report the qualification prints.
#[derive(Clone, Debug)]
pub struct CaseOutcome {
    pub id: String,
    pub shell: ShellKind,
    pub stack: String,
    /// `qualified`, or why the case did not run.
    pub verdict: String,
    /// The package identity this case qualified, where it ran.
    pub package_identity: Option<String>,
    /// The stack versions it ran against.
    pub stack_versions: BTreeMap<String, String>,
    pub checks: Vec<String>,
}

impl CaseOutcome {
    #[must_use]
    pub fn skipped(case: &QualificationCase, reason: &str) -> Self {
        Self {
            id: case.id.clone(),
            shell: case.shell,
            stack: case.stack.clone(),
            verdict: reason.to_owned(),
            package_identity: None,
            stack_versions: BTreeMap::new(),
            checks: Vec::new(),
        }
    }
}

/// Flattens a verdict to one line, so the record stays one line per case.
///
/// A failure carries what the terminal showed, which is what makes it readable in the test's own
/// output and unreadable in a table.
fn one_line(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character == '\t' || character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Writes what each case concluded where the run asked for its evidence.
pub fn record_outcomes(name: &str, outcomes: &[CaseOutcome]) {
    let mut report = String::new();
    for outcome in outcomes {
        report.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            outcome.id,
            outcome.shell.as_str(),
            outcome.stack,
            one_line(&outcome.verdict),
            outcome.package_identity.as_deref().unwrap_or("-"),
            outcome
                .stack_versions
                .iter()
                .map(|(id, version)| format!("{id}={version}"))
                .collect::<Vec<_>>()
                .join(","),
        ));
    }
    record(name, &report);
    print!("{report}");
}

/// Waits until the terminal has been quiet for `quiet`, or `within` has passed.
///
/// A prompt some of these stacks draw is several writes long, and a case that typed into the
/// middle of one would be measuring the drawing rather than the reader.
pub fn settle(session: &mut Session, quiet: Duration, within: Duration) {
    let deadline = Instant::now() + within;
    let mut last = session.terminal_output().len();
    let mut since = Instant::now();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
        let now = session.terminal_output().len();
        if now == last {
            if since.elapsed() >= quiet {
                return;
            }
        } else {
            last = now;
            since = Instant::now();
        }
    }
}

/// Which of section 7's exclusions this reader could be put into, and why the rest could not.
///
/// The corpus names ten states that exclude the detach condition. Some of them are not states a
/// particular reader has — an editor with no quoted insertion cannot be waiting inside one — and
/// one of them, the requirement that this is the managed root editor at all, is not a state of a
/// managed reader. Those are recorded with their reason rather than left out, so a reader that
/// stopped reporting a state it does have fails rather than passing quietly.
#[must_use]
pub fn exclusions_accounted_for(kind: ShellKind) -> Vec<(DetachExclusion, String)> {
    DetachExclusion::ALL
        .iter()
        .copied()
        .chain(std::iter::once(DetachExclusion::NotManagedRootEditor))
        .filter_map(|exclusion| {
            not_constructible_here(kind, exclusion).map(|reason| (exclusion, reason.to_owned()))
        })
        .collect()
}

/// The shell's own `read` through the editor, where it has one that reads through it.
#[must_use]
pub fn read_builtin_command(kind: ShellKind) -> Option<&'static str> {
    match kind {
        ShellKind::Bash => Some("read -e -t 5 kr_read_var"),
        ShellKind::Fish => Some("read -l kr_read_var"),
        // Zsh's `vared` ends on the gesture rather than surviving it, and this editor's own
        // `Read-Host` does not read through the editor at all.
        ShellKind::Zsh | ShellKind::PowerShell => None,
    }
}

/// Switching the editor to vi bindings and back, where a motion waits for its target there.
#[must_use]
pub fn vi_keymap_commands(kind: ShellKind) -> Option<(&'static str, &'static str)> {
    match kind {
        ShellKind::Zsh => Some((
            "bindkey -v; printf '%s%s\\n' kr-vi- on",
            "bindkey -e; printf '%s%s\\n' kr-vi- off",
        )),
        ShellKind::Bash => Some((
            "set -o vi; printf '%s%s\\n' kr-vi- on",
            "set -o emacs; printf '%s%s\\n' kr-vi- off",
        )),
        ShellKind::Fish => Some((
            "fish_vi_key_bindings; printf '%s%s\\n' kr-vi- on",
            "fish_default_key_bindings; printf '%s%s\\n' kr-vi- off",
        )),
        // This editor's vi mode is the host's own and its operators take their keys themselves.
        ShellKind::PowerShell => None,
    }
}

/// A binding that feeds the gesture back as the reader's own input.
#[must_use]
pub fn macro_binding(kind: ShellKind) -> Option<&'static str> {
    match kind {
        ShellKind::Zsh => Some("bindkey -s '^T' $'\\x04'; printf '%s%s\\n' kr-macro- bound"),
        ShellKind::Bash => Some("bind '\"\\C-t\": \"\\C-d\"' ; printf '%s%s\\n' kr-macro- bound"),
        // Neither editor replays a macro of its own.
        ShellKind::Fish | ShellKind::PowerShell => None,
    }
}

/// What this qualification cannot put a reader into, beyond what the package suite records.
///
/// [`not_constructible_here`] says what a reader does not have. This says what it has and this
/// corpus cannot reach: a state that exists only where a person bound it, where the corpus binds
/// nothing of the kind.
#[must_use]
pub fn not_driven_by_the_qualification(
    kind: ShellKind,
    exclusion: DetachExclusion,
) -> Option<&'static str> {
    match (kind, exclusion) {
        // This shell ships no numeric-argument binding of its own. Its reader accumulates one
        // where a person has bound `up-line-or-search`-style digits, and none of these cases does.
        (ShellKind::Fish, DetachExclusion::NumericArgument) => Some(
            "this shell binds no numeric argument by default and no case in this corpus binds one",
        ),
        _ => None,
    }
}
