//! What every driver that starts a real agent holds in common, whichever driver it is.
//!
//! The qualification cases and the gateway cases call the same functions here, so a rule about a
//! key, a file of the person's or a turn changes in one place:
//!
//! - the values of the keys the harness's shell holds ([`HeldKeys`]), the rule that no panic message,
//!   record or note carries a piece of one ([`holds_a_key`], [`kept_clear`], [`recorded_text`],
//!   [`gate_panics`]), and the values a search cannot find ([`unsearchable_count`]);
//! - the files the build list says must not exist before the agent starts ([`absent_paths`]);
//! - the search of a run's directory for the keys, its removal and the record of both
//!   ([`RunScan`]), which a driver makes on every outcome;
//! - the guard over the person's own agent files, by metadata alone ([`MetaGuard`]);
//! - the count of the turns the agent's own record holds ([`turns_recorded`]), against the turns
//!   charged to the ledger.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kr_e2e_m1b::run::Run;
use serde_json::{Value, json};

use crate::account::{self, KeyScan, files_holding, files_holding_any, now_ms, record_key_scan};
use crate::build::Account;
use crate::{confine, keys};

/// How a part says it could not show that the agent loads none of the person's own servers. A
/// part that says so stops its agent before it starts.
pub const ISOLATION_UNPROVEN: &str =
    "the agent's isolation from the person's own servers is not established:";

/// The directory of a run that holds the agent's configuration, where the build list gives it one
/// of the run's own.
pub const CONFIG_DIRECTORY: &str = "agent-config";

/// The proxy variables a part without a login sets to a closed port. An agent with a login has
/// none of them: it reaches its vendor.
pub const PROXY_VARIABLES: [&str; 8] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// The run's folder as the agent sees it: its resolved path.
///
/// # Panics
///
/// Panics when the system cannot name the folder.
#[must_use]
pub fn folder_of(run: &Run) -> PathBuf {
    std::fs::canonicalize(run.work())
        .unwrap_or_else(|error| panic!("the run's folder as the system names it: {error}"))
}

/// The keys a driver holds: the login's own, where the build list's login is a variable, and the
/// values of the other keys the harness's shell holds, which no session was given and which a text
/// a driver keeps must not carry.
#[derive(Clone, Debug)]
pub struct HeldKeys {
    /// The login's variable and its value, where the login is a variable.
    pub key: Option<(String, String)>,
    /// The values of the other keys the harness's shell holds.
    pub others: Vec<String>,
}

impl HeldKeys {
    /// Reads the keys from the descriptors the harness gave, makes every panic of the process go
    /// through the held-key rule before it is printed, and refuses a value that a result's own
    /// syntax could hide, because a search cannot find it and a record cannot be held clear of it.
    /// `who` names the driver in the messages, such as `part 3`.
    ///
    /// # Panics
    ///
    /// Panics when the harness gave no value where the entry needs one, or a value cannot be
    /// searched for: nothing has started, and no turn is spent.
    #[must_use]
    pub fn read(who: &str, account: &Account) -> Self {
        let key = account.variable.as_ref().map(|name| {
            let value = account::key_from_descriptor().unwrap_or_else(|why| {
                panic!("{who} carries {name}, and the harness gave no value for it: {why}")
            });
            (name.clone(), value)
        });
        // The other keys the harness's shell holds, whose values the driver's data is searched for;
        // the login's own value is searched for by the key scan.
        let others: Vec<String> = keys::scan_values_from_descriptor()
            .unwrap_or_else(|why| {
                panic!(
                    "{who} searches its data for the keys the person's shell holds, and the \
                     harness gave none: {why}"
                )
            })
            .into_iter()
            .filter(|value| key.as_ref().is_none_or(|(_, own)| own != value))
            .collect();
        let held = Self { key, others };
        // From here every panic's message goes through the held-key rule before it is printed.
        gate_panics(&held.values());
        let unsearchable =
            unsearchable_count(held.key.as_ref().map(|(_, own)| own.as_str()), &held.others);
        assert!(
            unsearchable == 0,
            "{ISOLATION_UNPROVEN} {unsearchable} key value(s), the login's own among them or the \
             person's shell's other keys, have a quote, bracket, backslash or control character, so \
             a result could not be searched for them: have them unset for the run, or use another key"
        );
        held
    }

    /// Every value held: the other keys' and the login's own.
    #[must_use]
    pub fn values(&self) -> Vec<String> {
        self.others
            .iter()
            .cloned()
            .chain(self.key.iter().map(|(_, value)| value.clone()))
            .collect()
    }
}

/// One element of a text read for a key: a character a key is made of, or a run that may be a
/// colour code (`ESC [`, digits and semicolons, `m`) or may be characters of the key itself, which
/// the reading takes either way, whole.
enum Item {
    Char(char),
    Colour(Vec<char>),
}

/// `text` as the characters a key is made of (letters, digits, `-` and `_`) in order, the rest taken
/// out: whitespace, the frame and block characters an agent draws around its rows, the escape
/// character and what else sits between them. A whole colour-looking sequence is one [`Item::Colour`]
/// holding its digits and its `m`, so that a key is found whichever of such sequences are colour and
/// whichever are key characters.
fn items_of(text: &str) -> Vec<Item> {
    let characters: Vec<char> = text.chars().collect();
    let mut items = Vec::new();
    let mut at = 0;
    while at < characters.len() {
        let character = characters[at];
        if character == '\u{1b}' {
            if characters.get(at + 1) == Some(&'[') {
                let mut end = at + 2;
                while end < characters.len()
                    && (characters[end].is_ascii_digit() || characters[end] == ';')
                {
                    end += 1;
                }
                if characters.get(end) == Some(&'m') {
                    let inner: Vec<char> = characters[at + 2..=end]
                        .iter()
                        .copied()
                        .filter(|inner| *inner != ';')
                        .collect();
                    items.push(Item::Colour(inner));
                    at = end + 1;
                    continue;
                }
            }
        } else if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
            items.push(Item::Char(character));
        }
        at += 1;
    }
    items
}

/// Whether `piece` is found in `items`, from some start, taking each [`Item::Colour`] whole or not
/// at all (a start can fall inside one, which then is key characters). The search is a walk over
/// states (item, offset inside a colour-looking run, characters of the piece matched), each taken
/// once, with a stack of its own: its time and memory grow with the length of the text, not with
/// the number of ways its colour codes can be read.
fn piece_in(items: &[Item], piece: &[char]) -> bool {
    let mut seen = std::collections::HashSet::new();
    let mut stack: Vec<(usize, usize, usize)> = Vec::new();
    for (item, element) in items.iter().enumerate() {
        match element {
            Item::Char(_) => stack.push((item, 0, 0)),
            Item::Colour(inner) => stack.extend((0..inner.len()).map(|offset| (item, offset, 0))),
        }
    }
    while let Some(state) = stack.pop() {
        let (item, offset, matched) = state;
        if matched == piece.len() {
            return true;
        }
        if item >= items.len() || !seen.insert(state) {
            continue;
        }
        match &items[item] {
            Item::Char(character) => {
                if *character == piece[matched] {
                    stack.push((item + 1, 0, matched + 1));
                }
            }
            Item::Colour(inner) => {
                let rest = &inner[offset..];
                let take = rest.len().min(piece.len() - matched);
                if rest[..take] == piece[matched..matched + take] {
                    stack.push((item + 1, 0, matched + take));
                }
                if offset == 0 {
                    stack.push((item + 1, 0, matched));
                }
            }
        }
    }
    false
}

/// The length of the pieces of a held key that no note may carry: a note holding eight characters
/// of a random key in a row holds more of it than is safe, whole, wrapped over rows, clipped at a
/// screen edge or between colour codes. (A key's fixed vendor prefix is as long and also stops a
/// note, which costs a diagnostic and nothing else, since a failure is classed before its text is
/// held to this.)
const KEY_PIECE: usize = 8;

thread_local! {
    /// How many times this thread has searched a text for a piece of a key: what a text's recording
    /// costs is counted in searches, which a test holds to a number the text's length cannot raise.
    pub static KEY_SEARCHES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Whether `rows`, read as one run, hold a piece of eight characters of one of `secrets`, whichever
/// of the colour-looking sequences in them are colour and whichever are characters of the key. A
/// value of fewer than eight characters has no piece. An encoding of the key that changes its
/// characters (base64, hex, a `\u` escape of each) is not covered; nor are pieces of fewer than
/// eight characters kept apart by other letters or digits, or an escape sequence that is not a
/// colour code and a terminal would draw nothing for, between pieces of seven.
#[must_use]
pub fn holds_a_key(rows: &[&str], secrets: &[&str]) -> bool {
    KEY_SEARCHES.with(|searches| searches.set(searches.get() + 1));
    let items: Vec<Item> = rows.iter().flat_map(|row| items_of(row)).collect();
    secrets.iter().any(|secret| {
        let secret: Vec<char> = items_of(secret)
            .into_iter()
            .flat_map(|item| match item {
                Item::Char(character) => vec![character],
                Item::Colour(inner) => inner,
            })
            .collect();
        secret
            .windows(KEY_PIECE)
            .any(|piece| piece_in(&items, piece))
    })
}

/// `text` as it is, or a line that says it is not kept where it holds a piece of a held key
/// (`secrets`; see [`holds_a_key`]): the one place a text goes through before the part prints or
/// keeps it.
#[must_use]
pub fn kept_clear(text: &str, secrets: &[&str]) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if holds_a_key(&lines, secrets) {
        "(the text holds a key, so it is not kept)".to_owned()
    } else {
        text.to_owned()
    }
}

/// The values of the keys the part holds, for the panic hook: set when a part with a login is made.
static HELD_FOR_PANICS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Makes every panic of the part's threads go through [`kept_clear`] before it is printed, once for
/// the process: a failure's message, which can hold a screen or an agent's output, never carries a
/// piece of a held key into the part's log. The values are those of the part made last.
pub fn gate_panics(secrets: &[String]) {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    *HELD_FOR_PANICS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = secrets.to_vec();
    INSTALLED.call_once(|| {
        let printed = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let message = panic_text(info.payload());
            let held = HELD_FOR_PANICS
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let held: Vec<&str> = held.iter().map(String::as_str).collect();
            if holds_a_key(&message.lines().collect::<Vec<_>>(), &held) {
                let place = info
                    .location()
                    .map_or_else(String::new, |place| format!(" at {place}"));
                let _ = std::io::Write::write_fmt(
                    &mut std::io::stderr(),
                    format_args!(
                        "\nthread panicked{place}: the message holds a key, so it is not printed\n"
                    ),
                );
            } else {
                printed(info);
            }
        }));
    });
}

/// What a panic said, where it said anything, as it said it: the text a failure is classed by.
#[must_use]
pub fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
        .unwrap_or_else(|| "the part stopped without saying why".to_owned())
}

/// `text` as the part records or prints it: as it is, or, where it holds a piece of a held key
/// (`secrets`), only its first words (up to the first colon or line break, the colon that ends the
/// class a failure begins with), where those hold no piece of a key, and a line that says the rest
/// is not kept.
#[must_use]
pub fn recorded_text(text: &str, secrets: &[&str]) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if !holds_a_key(&lines, secrets) {
        return text.to_owned();
    }
    // A longer head holds every piece a shorter one holds, so the first delimiter after the first
    // character is the only one whose head can be free of a key: one search decides, and a head
    // that holds a piece is discarded whatever follows it.
    let head = text
        .match_indices([':', '\n'])
        .find(|(at, _)| *at > 0)
        .filter(|(at, _)| !holds_a_key(&[&text[..*at]], secrets))
        .map_or("", |(at, _)| &text[..=at.min(text.len() - 1)]);
    let head = head.trim_end_matches('\n');
    format!("{head} (the rest holds a key, so it is not kept)")
}

/// [`recorded_text`] with the values of the keys the part holds, which a part with a login sets at
/// its start.
#[must_use]
pub fn kept_panic_text(text: &str) -> String {
    let held = HELD_FOR_PANICS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let held: Vec<&str> = held.iter().map(String::as_str).collect();
    recorded_text(text, &held)
}

/// How many of the values a part searches for cannot be held out of a result or found in one, the
/// login's own value (`own`) and the other keys the person's shell holds (`others`), each counted
/// once.
#[must_use]
pub fn unsearchable_count(own: Option<&str>, others: &[String]) -> usize {
    let mut values: Vec<&str> = others.iter().map(String::as_str).collect();
    values.extend(own);
    values.sort_unstable();
    values.dedup();
    values
        .into_iter()
        .filter(|value| !confine::searchable(value))
        .count()
}

/// Which of an entry's `absent` paths [`absent_paths`] gives.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Absent {
    /// Every path, each `{ancestors}` entry expanded for every folder above the working folder.
    All,
    /// Only the `{ancestors}` entries, expanded: the files an agent searches for up the tree, which
    /// must be known absent before any program of the agent runs.
    Ancestors,
    /// Every path, with an `{ancestors}` entry as its template, for the record.
    Published,
}

/// The paths of the entry's `absent` list that `which` selects, with each template filled in:
/// `{config}` and `{work}` are the run's configuration and working directories, `{home}` the home
/// the agent runs with, `{person}` the person's own home, `{user}` the account name the system has
/// for the person, as `id -un` says it, and `{ancestors}` the working folder and each folder above
/// it, as given and as the system resolves it.
///
/// # Panics
///
/// Panics when the system cannot say the account name.
#[must_use]
pub fn absent_paths(
    account: &Account,
    run: &Run,
    home: &Path,
    person: &Path,
    which: Absent,
) -> Vec<PathBuf> {
    let home = home.display().to_string();
    let config = run.root().join(CONFIG_DIRECTORY).display().to_string();
    let work = run.work().display().to_string();
    let person = person.display().to_string();
    // The account name as the system has it, as the agent itself reads it, not the environment's.
    let user = std::process::Command::new("/usr/bin/id")
        .arg("-un")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            panic!("{ISOLATION_UNPROVEN} the account name the system has cannot be read")
        });
    let folders: Vec<String> = {
        let mut seen = Vec::new();
        for start in [run.work(), folder_of(run)] {
            for folder in start.ancestors() {
                let text = folder.display().to_string();
                let text = if text == "/" { String::new() } else { text };
                if !seen.contains(&text) {
                    seen.push(text);
                }
            }
        }
        seen
    };
    account
        .absent
        .iter()
        .filter(|path| which != Absent::Ancestors || path.contains("{ancestors}"))
        .flat_map(|path| {
            let expand = |path: &str| {
                PathBuf::from(
                    path.replace("{config}", &config)
                        .replace("{work}", &work)
                        .replace("{home}", &home)
                        .replace("{person}", &person)
                        .replace("{user}", &user),
                )
            };
            if path.contains("{ancestors}") && which == Absent::Published {
                vec![PathBuf::from(path)]
            } else if path.contains("{ancestors}") {
                folders
                    .iter()
                    .map(|folder| expand(&path.replace("{ancestors}", folder)))
                    .collect::<Vec<_>>()
            } else {
                vec![expand(path)]
            }
        })
        .collect()
}

/// What stops a driver, as a class and the words that say it.
pub type Stop = (&'static str, String);

/// The search of a run's directory for the values of the keys a driver held, made while the
/// directory is still there and every process the run started has ended.
#[derive(Debug)]
pub struct RunScan {
    key: Option<(String, KeyScan)>,
    others: Option<KeyScan>,
}

impl RunScan {
    /// Searches `root` for the login's value and, together, for the other keys' values.
    #[must_use]
    pub fn of(root: &Path, held: &HeldKeys) -> Self {
        let key = held
            .key
            .as_ref()
            .map(|(name, value)| (name.clone(), files_holding(root, value.as_bytes())));
        let others = (!held.others.is_empty()).then(|| {
            let values: Vec<&[u8]> = held.others.iter().map(String::as_bytes).collect();
            files_holding_any(root, &values)
        });
        Self { key, others }
    }

    /// Whether a key was searched for at all.
    #[must_use]
    pub const fn searched(&self) -> bool {
        self.key.is_some() || self.others.is_some()
    }

    /// Removes the run's directory, checks it gone, records the search by path and what became of
    /// the directory, and says what stops the driver: a search that could not read everything, a
    /// directory still there, a process that may still have been writing during the search, and
    /// another key's value found in a file. The login's own value found in a file is recorded, as
    /// the qualification cases record it, and stops nothing. Call it once the run is dropped, so the
    /// run's own end does not say it keeps a directory that is about to go.
    #[must_use]
    pub fn finish(self, root: &Path, case: &str, writers_ended: bool) -> (Vec<Stop>, Value) {
        let mut stops: Vec<Stop> = Vec::new();
        let _ = std::fs::remove_dir_all(root);
        let gone = !root.exists();
        let mut evidence = json!({ "run_gone": gone });
        if let Some((name, scan)) = &self.key {
            record_key_scan(case, name, scan, now_ms(), gone);
            evidence["variable"] = json!(name);
            evidence["held_by"] = json!(
                scan.held_by
                    .iter()
                    .map(|holder| &holder.path)
                    .collect::<Vec<_>>()
            );
            evidence["complete"] = json!(scan.complete());
        }
        let unread = self.key.as_ref().map_or(0, |(_, scan)| scan.unread.len())
            + self.others.as_ref().map_or(0, |scan| scan.unread.len());
        if unread > 0 || !gone || (self.searched() && !writers_ended) {
            stops.push((
                "key_scan_incomplete",
                format!(
                    "the run's directory was {}searched whole ({unread} entries unread) {}and is {}gone",
                    if unread == 0 { "" } else { "not " },
                    if writers_ended {
                        ""
                    } else {
                        "while something the run started may still have been writing, "
                    },
                    if gone { "" } else { "not " }
                ),
            ));
        }
        if let Some(found) = self
            .others
            .as_ref()
            .filter(|found| !found.held_by.is_empty())
        {
            stops.push((
                "provider_key_found",
                format!(
                    "the value of a key the person's shell holds is in {} file(s) of the run's \
                     directory, which no session was given it in",
                    found.held_by.len()
                ),
            ));
        }
        (stops, evidence)
    }
}

/// How a file of the person's stood at one moment, as its metadata says and nothing of its content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stat {
    inode: u64,
    bytes: u64,
    modified: (i64, i64),
}

/// A file's [`Stat`] now, or none where there is no such file.
fn stat_of(path: &Path) -> Result<Option<Stat>, String> {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(Stat {
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// The person's own agent files as their metadata stood before a driver started anything, and the
/// check that none of them changed. Only metadata is read, by `stat`: never a file's content, so
/// the person's login and settings stay unread. A file that is there, gone or replaced is a
/// change. A directory is recorded and stops nothing: the person's own programs add and remove
/// entries in it while a driver runs.
#[derive(Clone, Debug)]
pub struct MetaGuard {
    home: PathBuf,
    files: Vec<(String, Option<Stat>)>,
    directories: Vec<(String, Option<Stat>)>,
}

impl MetaGuard {
    /// Takes the metadata of `files` and `directories`, each a path relative to `home`.
    ///
    /// # Panics
    ///
    /// Panics when the system refuses a path's metadata for a reason other than the path not being
    /// there: a file whose state is not known cannot be shown unchanged.
    #[must_use]
    pub fn take(home: &Path, files: &[&str], directories: &[&str]) -> Self {
        let state = |relative: &&str| {
            let stat = stat_of(&home.join(relative))
                .unwrap_or_else(|why| panic!("a file of the person's cannot be looked at: {why}"));
            ((*relative).to_owned(), stat)
        };
        Self {
            home: home.to_path_buf(),
            files: files.iter().map(state).collect(),
            directories: directories.iter().map(state).collect(),
        }
    }

    /// Looks again and says what stops the driver, with what was seen: for each file whether it
    /// was there and whether its size, modification time or identity changed; never a value.
    #[must_use]
    pub fn compare(&self) -> (Vec<Stop>, Value) {
        let mut stops: Vec<Stop> = Vec::new();
        let mut look = |entries: &[(String, Option<Stat>)], stops_on_change: bool| -> Vec<Value> {
            entries
                .iter()
                .map(|(relative, before)| {
                    let after = stat_of(&self.home.join(relative));
                    let (changed, present, detail) = match &after {
                        Ok(after) => (
                            after != before,
                            after.is_some(),
                            json!({
                                "size_changed": before.as_ref().map(|b| b.bytes) != after.as_ref().map(|a| a.bytes),
                                "modified_changed": before.as_ref().map(|b| b.modified) != after.as_ref().map(|a| a.modified),
                                "replaced": before.as_ref().map(|b| b.inode) != after.as_ref().map(|a| a.inode),
                            }),
                        ),
                        Err(why) => {
                            stops.push((
                                "person_file_unreadable",
                                format!("~/{relative} cannot be looked at after the run: {why}"),
                            ));
                            (true, false, json!({ "unreadable": true }))
                        }
                    };
                    if changed && stops_on_change && after.is_ok() {
                        stops.push((
                            "guarded_file_changed",
                            format!("~/{relative} changed while the run ran"),
                        ));
                    }
                    json!({
                        "path": format!("~/{relative}"),
                        "was_there": before.is_some(),
                        "is_there": present,
                        "changed": changed,
                        "detail": detail,
                    })
                })
                .collect()
        };
        let files = look(&self.files, true);
        let directories = look(&self.directories, false);
        (
            stops,
            json!({ "files": files, "directories_recorded_only": directories }),
        )
    }
}

/// The member `turn_id` of a JSON line, at any depth, where it has one.
fn turn_identifier(value: &Value) -> Option<String> {
    match value {
        Value::Object(members) => members
            .get("turn_id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| members.values().find_map(turn_identifier)),
        Value::Array(items) => items.iter().find_map(turn_identifier),
        _ => None,
    }
}

/// How many turns the model ran, as the agent's own record under `root` holds them: the lines the
/// entry's turn line marks, each turn once, whichever of the agent's files, a copy of a
/// conversation among them, holds it. A line is the same turn as another where both name the same
/// turn, and where a line names none, where the two lines are equal.
///
/// # Errors
///
/// Returns why the count is not whole: the entry names no turn line, or an entry of the record
/// could not be read.
pub fn turns_recorded(account: &Account, root: &Path) -> Result<u64, String> {
    let marker = account.turn_line.as_deref().ok_or_else(|| {
        "the entry names no line that marks a turn, so the turns the agent ran cannot be counted"
            .to_owned()
    })?;
    let mut turns: BTreeSet<String> = BTreeSet::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            // No conversation was written: no turn ran.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && path == root => {
                return Ok(0);
            }
            Err(error) => return Err(format!("{}: {error}", path.display())),
        };
        if metadata.is_dir() {
            let entries =
                std::fs::read_dir(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            for entry in entries {
                let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
                pending.push(entry.path());
            }
        } else {
            let bytes =
                std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            for line in String::from_utf8_lossy(&bytes).lines() {
                if line.contains(marker) {
                    let named = serde_json::from_str::<Value>(line)
                        .ok()
                        .as_ref()
                        .and_then(turn_identifier);
                    turns.insert(named.unwrap_or_else(|| line.to_owned()));
                }
            }
        }
    }
    Ok(u64::try_from(turns.len()).unwrap_or(u64::MAX))
}

/// Where the agent's conversations are under its configuration directory: the entry's path before
/// the `{date}` its files are sorted under.
#[must_use]
pub fn conversations_root(account: &Account, configuration: &Path) -> PathBuf {
    let base = account.conversations.split("{date}").next().unwrap_or("");
    configuration.join(base.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of this test's own.
    fn scratch(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!("kr-held-{name}-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&directory).expect("a scratch directory");
        directory
    }

    fn account() -> Account {
        serde_json::from_value(json!({
            "login": "l", "stored": "s", "home": "run", "budget": "b", "turns": 3,
            "conversations": "sessions/{date}", "prompt_line": "\"role\":\"user\"",
            "ready": "r", "composer": "c", "submit": "\r", "clear": "\u{15}",
            "reply_line": "x", "decision_line": "y", "busy": "b",
            "slash": { "input": "/p", "shows": "p" },
            "interrupt": { "input": "\u{1b}", "shows": "i" },
            "approval": { "shows": "a", "allow": "y", "deny": "n" },
            "resume": ["resume", "{conversation}"], "image": "paste",
            "turn_line": "\"type\":\"task_started\""
        }))
        .expect("an account")
    }

    #[test]
    fn a_guarded_file_that_is_written_replaced_or_made_is_a_change_and_a_directory_is_not() {
        let home = scratch("guard");
        let present = home.join("present");
        let absent = "absent";
        std::fs::write(&present, b"one").expect("a file");
        std::fs::create_dir(home.join("dir")).expect("a directory");
        let guard = MetaGuard::take(&home, &["present", absent], &["dir"]);
        let (stops, evidence) = guard.compare();
        assert!(stops.is_empty(), "{stops:?}");
        assert_eq!(evidence["files"][0]["changed"], json!(false));
        // A directory gaining an entry is recorded and stops nothing.
        std::fs::write(home.join("dir").join("x"), b"x").expect("an entry");
        let (stops, evidence) = guard.compare();
        assert!(stops.is_empty(), "{stops:?}");
        assert_eq!(
            evidence["directories_recorded_only"][0]["changed"],
            json!(true)
        );
        // A file written in place changes its size.
        std::fs::write(&present, b"three").expect("a rewrite");
        let (stops, _) = guard.compare();
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(stops[0].0, "guarded_file_changed");
        // A file that was not there and is, and one that was there and is gone.
        std::fs::write(home.join(absent), b"new").expect("a new file");
        std::fs::remove_file(&present).expect("a removal");
        let (stops, _) = guard.compare();
        assert_eq!(stops.len(), 2, "{stops:?}");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_turn_counts_once_however_many_files_hold_it_and_a_line_with_no_name_counts_by_its_text() {
        let root = scratch("turns");
        let line = |id: &str| {
            format!(r#"{{"timestamp":"t","payload":{{"type":"task_started","turn_id":"{id}"}}}}"#)
        };
        std::fs::create_dir_all(root.join("2026/11")).expect("directories");
        std::fs::write(
            root.join("2026/11/a.jsonl"),
            format!("{}\n{{\"role\":\"user\"}}\n{}\n", line("one"), line("two")),
        )
        .expect("a conversation");
        // A copy of the conversation, as a fork writes it, and one more turn of its own.
        std::fs::write(
            root.join("2026/11/b.jsonl"),
            format!("{}\n{}\n{}\n", line("one"), line("two"), line("three")),
        )
        .expect("a copy");
        std::fs::write(
            root.join("c.jsonl"),
            "{\"type\":\"task_started\"}\nnot json \"type\":\"task_started\"\n",
        )
        .expect("lines with no name");
        assert_eq!(turns_recorded(&account(), &root), Ok(5));
        assert_eq!(turns_recorded(&account(), &root.join("none")), Ok(0));
        let mut unnamed = account();
        unnamed.turn_line = None;
        assert!(turns_recorded(&unnamed, &root).is_err());
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn a_run_directory_is_searched_removed_and_recorded_and_a_key_of_another_kind_stops_the_run() {
        let root = scratch("scan");
        let own = "login-value-0123456789";
        let other = "other-key-value-9876543210";
        std::fs::write(root.join("log"), format!("token {own}")).expect("a file");
        std::fs::write(root.join("note"), format!("also {other}")).expect("a file");
        let held = HeldKeys {
            key: Some(("LOGIN".to_owned(), own.to_owned())),
            others: vec![other.to_owned()],
        };
        let scan = RunScan::of(&root, &held);
        assert!(scan.searched());
        let (stops, evidence) = scan.finish(&root, "held-test", true);
        assert!(!root.exists(), "the run's directory is removed");
        assert_eq!(evidence["run_gone"], json!(true));
        assert_eq!(evidence["held_by"], json!(["log"]));
        // The login's own value in a file is recorded; another key's value in a file stops the run.
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(stops[0].0, "provider_key_found");
        assert!(!stops[0].1.contains(other));
        // A search made while something may still have been writing is not a finished one.
        let again = scratch("scan-writers");
        let held = HeldKeys {
            key: Some(("LOGIN".to_owned(), own.to_owned())),
            others: Vec::new(),
        };
        let (stops, _) = RunScan::of(&again, &held).finish(&again, "held-test", false);
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(stops[0].0, "key_scan_incomplete");
    }
}
