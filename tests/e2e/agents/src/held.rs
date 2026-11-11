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

/// How a tree of the person's stood at one moment, by metadata alone: how many entries it holds,
/// and a digest of every entry's name, kind, identity, size and times. Only the digest and the
/// count are kept, in memory; no name, size or time is printed, logged or recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Tree {
    entries: usize,
    digest: [u8; 32],
}

/// Why a tree could not be looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    /// The tree's own path is a symbolic link: the guard refuses it and follows nothing.
    LinkAtRoot,
    /// An entry was gone between the listing that named it and the look at it.
    Vanished,
    /// A directory was another kind of entry when it was opened than when it was looked at.
    Replaced,
    /// The system refused a look or a listing.
    Refused(rustix::io::Errno),
    /// The tree is deeper than the walk goes.
    TooDeep,
}

/// A tree that could not be looked at: the class of the failure and how many entries had been looked
/// at by then. It says no name, so that nothing under the person's own directory is said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Unlooked {
    class: Class,
    seen: usize,
}

impl std::fmt::Display for Unlooked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let seen = self.seen;
        match self.class {
            Class::LinkAtRoot => write!(formatter, "the directory is a symbolic link"),
            Class::Vanished => write!(
                formatter,
                "an entry disappeared while the tree was looked at (after {seen} entries)"
            ),
            Class::Replaced => write!(
                formatter,
                "a directory became another kind of entry while the tree was looked at (after \
                 {seen} entries)"
            ),
            Class::Refused(error) => write!(
                formatter,
                "the system refused a look or a listing: {error} (after {seen} entries)"
            ),
            Class::TooDeep => write!(
                formatter,
                "the tree is deeper than {DEEPEST} levels (after {seen} entries)"
            ),
        }
    }
}

/// The deepest the walk goes: what lies below is not looked at, and that is a failure.
const DEEPEST: usize = 64;

/// The two moments of the walk at which a test changes the tree under it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Moment {
    /// A directory was listed, and the entry named has not been looked at yet.
    Listed,
    /// The entry named was looked at and is a directory, which is not opened yet.
    Looked,
}

/// Opens `name` in `directory` as a directory and follows no link: a name that was made a link, or
/// any other kind of entry, since it was looked at is refused.
fn opened_directory(
    directory: &std::os::fd::OwnedFd,
    name: &std::ffi::CStr,
    looked: &rustix::fs::Stat,
    seen: usize,
) -> Result<std::os::fd::OwnedFd, Unlooked> {
    use rustix::fs::{Mode, OFlags};
    let unlooked = |class| Unlooked { class, seen };
    let handle = rustix::fs::openat(
        directory,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| unlooked(opening_failed(error)))?;
    let opened = rustix::fs::fstat(&handle).map_err(|error| unlooked(Class::Refused(error)))?;
    if (opened.st_dev, opened.st_ino) == (looked.st_dev, looked.st_ino) {
        Ok(handle)
    } else {
        Err(unlooked(Class::Replaced))
    }
}

/// The class of a failed opening of a name that was a directory when it was looked at.
fn opening_failed(error: rustix::io::Errno) -> Class {
    match error {
        rustix::io::Errno::NOENT => Class::Vanished,
        // What `O_NOFOLLOW` and `O_DIRECTORY` say of a name that is now a link or another kind.
        rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => Class::Replaced,
        other => Class::Refused(other),
    }
}

/// One entry's line in the digest: its place in the tree, kind and permissions, identity, size and
/// times.
fn described(relative: &[u8], stat: &rustix::fs::Stat) -> Vec<u8> {
    let mut line = relative.to_vec();
    line.extend_from_slice(
        format!(
            "\0{}\0{}\0{}\0{}.{}\0{}.{}",
            stat.st_mode,
            stat.st_ino,
            stat.st_size,
            stat.st_ctime,
            stat.st_ctime_nsec,
            stat.st_mtime,
            stat.st_mtime_nsec,
        )
        .as_bytes(),
    );
    line
}

/// Looks at every entry of `directory`, and of each directory below it, through handles: an entry
/// is looked at with `fstatat` on its directory's handle and no link followed, and a directory is
/// opened with the same handle and no link followed, then checked to be the one that was looked at.
/// No path is looked up again, so a directory made a link during the walk is refused, not followed.
fn walk_directory(
    directory: &std::os::fd::OwnedFd,
    relative: &[u8],
    depth: usize,
    seen: &mut usize,
    lines: &mut Vec<Vec<u8>>,
    between: &mut dyn FnMut(Moment, &[u8]),
) -> Result<(), Unlooked> {
    use rustix::fs::{AtFlags, FileType};
    if depth > DEEPEST {
        return Err(Unlooked {
            class: Class::TooDeep,
            seen: *seen,
        });
    }
    let names: Vec<std::ffi::CString> = {
        let refused = |error| Unlooked {
            class: Class::Refused(error),
            seen: *seen,
        };
        let listing = rustix::fs::Dir::read_from(directory).map_err(refused)?;
        let mut names = Vec::new();
        for entry in listing {
            let entry = entry.map_err(refused)?;
            let name = entry.file_name();
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                names.push(name.to_owned());
            }
        }
        names
    };
    for name in names {
        between(Moment::Listed, name.to_bytes());
        let looked = rustix::fs::statat(directory, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| Unlooked {
                class: if error == rustix::io::Errno::NOENT {
                    Class::Vanished
                } else {
                    Class::Refused(error)
                },
                seen: *seen,
            })?;
        *seen += 1;
        let mut path = relative.to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(name.to_bytes());
        lines.push(described(&path, &looked));
        if FileType::from_raw_mode(looked.st_mode) == FileType::Directory {
            between(Moment::Looked, name.to_bytes());
            let child = opened_directory(directory, name.as_c_str(), &looked, *seen)?;
            walk_directory(&child, &path, depth + 1, seen, lines, between)?;
        }
    }
    Ok(())
}

/// The tree at `path` as its metadata says it stands now: a file is a tree of one entry, a path that
/// is not there a tree of none, and a symbolic link at `path` itself is refused. A link below it is
/// an entry and is not followed. Nothing is read of any file but its metadata, and no file is
/// written. `between` is told of the two moments at which a test changes what is being walked.
fn walk_tree(path: &Path, between: &mut dyn FnMut(Moment, &[u8])) -> Result<Tree, Unlooked> {
    use rustix::fs::{FileType, Mode, OFlags};
    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut seen = 0_usize;
    match rustix::fs::lstat(path) {
        // A path that is not there is a tree of none.
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => {
            return Err(Unlooked {
                class: Class::Refused(error),
                seen,
            });
        }
        Ok(root) => match FileType::from_raw_mode(root.st_mode) {
            FileType::Symlink => {
                return Err(Unlooked {
                    class: Class::LinkAtRoot,
                    seen,
                });
            }
            FileType::Directory => {
                let handle = rustix::fs::open(
                    path,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| Unlooked {
                    class: opening_failed(error),
                    seen,
                })?;
                let opened = rustix::fs::fstat(&handle).map_err(|error| Unlooked {
                    class: Class::Refused(error),
                    seen,
                })?;
                if (opened.st_dev, opened.st_ino) != (root.st_dev, root.st_ino) {
                    return Err(Unlooked {
                        class: Class::Replaced,
                        seen,
                    });
                }
                seen = 1;
                lines.push(described(b"", &opened));
                walk_directory(&handle, b"", 1, &mut seen, &mut lines, between)?;
            }
            _ => lines.push(described(b"", &root)),
        },
    }
    lines.sort();
    Ok(Tree {
        entries: lines.len(),
        digest: kr_cbor::sha256(&lines.join(&b'\n')),
    })
}

/// [`walk_tree`] with nothing changing under it.
fn tree_of(path: &Path) -> Result<Tree, Unlooked> {
    walk_tree(path, &mut |_, _| {})
}

/// The person's home directory, as the system's account database names it, for a run whose `HOME`
/// is `environment`: the guard over the person's own agent files looks under the home that is
/// theirs, so a driver started with a `HOME` of its own, which would look at a tree that is not
/// theirs and pass, is refused before anything runs.
///
/// # Errors
///
/// Returns why the run is refused: the account database names no home for this user, or `HOME` is
/// another directory than that one. The text names no path.
pub fn person_home(environment: Option<&std::ffi::OsStr>) -> Result<PathBuf, String> {
    let record = kr_ipc::paths::passwd_entry().and_then(|entry| entry.home);
    person_home_of(environment, record.as_deref())
}

/// [`person_home`] for a given answer of the account database.
fn person_home_of(
    environment: Option<&std::ffi::OsStr>,
    record: Option<&str>,
) -> Result<PathBuf, String> {
    let Some(record) = record.filter(|home| !home.is_empty()) else {
        return Err(
            "the system's account database names no home directory for this user, so the person's \
             own files cannot be told from the run's"
                .to_owned(),
        );
    };
    let home = PathBuf::from(record);
    let given = environment.map(PathBuf::from);
    let same = given.as_ref().is_some_and(|given| {
        given == &home
            || matches!(
                (std::fs::canonicalize(given), std::fs::canonicalize(&home)),
                (Ok(given), Ok(home)) if given == home
            )
    });
    if same {
        Ok(home)
    } else {
        Err(
            "HOME is not the home directory the system's account database names for this user: \
             the guard over the person's own files would look at another tree, so the run is \
             refused before it starts anything"
                .to_owned(),
        )
    }
}

/// The person's own agent files as their metadata stood before a driver started anything, and the
/// check that none of them changed. Every entry under each named path is looked at, by `stat` and
/// directory listing alone: never a file's content, so the person's login and settings stay unread,
/// and nothing is written there. An entry that is added, removed, replaced, resized or touched is a
/// change. What is kept is a digest and a count; what is said is `changed` or `unchanged` and the
/// counts, and, where a tree cannot be looked at, the class of the failure and a count: never a
/// name. A symbolic link at a named path is refused, and a directory that becomes a link during the
/// walk is not followed. A stat cannot show that a file was read, so this is a tripwire for writes.
#[derive(Clone, Debug)]
pub struct MetaGuard {
    home: PathBuf,
    trees: Vec<(String, Tree)>,
}

impl MetaGuard {
    /// Takes the trees at `trees`, each a path relative to `home`.
    ///
    /// # Panics
    ///
    /// Panics when a tree cannot be looked at, for any reason other than its not being there: a
    /// tree whose state is not known cannot be shown unchanged. The message gives the class of the
    /// failure and a count, and names no file.
    #[must_use]
    pub fn take(home: &Path, trees: &[&str]) -> Self {
        Self {
            home: home.to_path_buf(),
            trees: trees
                .iter()
                .map(|relative| {
                    let tree = tree_of(&home.join(relative)).unwrap_or_else(|why| {
                        panic!("the person's directory ~/{relative} cannot be looked at: {why}")
                    });
                    ((*relative).to_owned(), tree)
                })
                .collect(),
        }
    }

    /// Looks again and says what stops the driver, with what was seen: for each tree whether it
    /// changed and how many entries it held before and holds now; never a name or a value.
    #[must_use]
    pub fn compare(&self) -> (Vec<Stop>, Value) {
        let mut stops: Vec<Stop> = Vec::new();
        let seen: Vec<Value> = self
            .trees
            .iter()
            .map(|(relative, before)| match tree_of(&self.home.join(relative)) {
                Ok(after) => {
                    let changed = after != *before;
                    if changed {
                        stops.push((
                            "guarded_file_changed",
                            format!(
                                "~/{relative} changed while the run ran ({} entries before, {} after)",
                                before.entries, after.entries
                            ),
                        ));
                    }
                    json!({
                        "path": format!("~/{relative}"),
                        "changed": changed,
                        "entries_before": before.entries,
                        "entries_after": after.entries,
                    })
                }
                Err(why) => {
                    stops.push((
                        "person_file_unreadable",
                        format!("~/{relative} cannot be looked at after the run: {why}"),
                    ));
                    json!({ "path": format!("~/{relative}"), "unreadable": true })
                }
            })
            .collect();
        (stops, json!({ "trees": seen }))
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

/// The turns the agent's own record holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Recorded {
    /// How many turns the model ran, as the record counts them.
    pub turns: u64,
    /// How many of them are counted by occurrence of their line, because the line names no turn.
    pub unnamed: u64,
    /// How many files of the record were read: none where the record's directory is not there.
    pub files: u64,
}

/// How many turns the model ran, as the agent's own record under `root` holds them: the lines the
/// entry's turn line marks. A line that names its turn (`turn_id`) counts once for that name,
/// whichever of the agent's files, a copy of a conversation among them, holds it. A line that names
/// none counts once for each time it occurs, in any file: nothing offline says that two equal lines
/// are one turn, and a copy of a conversation written again would count its turns twice, so the
/// count can be too high and is never too low. [`Recorded::unnamed`] says how many turns stand on
/// an occurrence. No other member of a line identifies a turn offline.
///
/// # Errors
///
/// Returns why the count is not whole: the entry names no turn line, or an entry of the record
/// could not be read.
pub fn turns_recorded(account: &Account, root: &Path) -> Result<Recorded, String> {
    let marker = account.turn_line.as_deref().ok_or_else(|| {
        "the entry names no line that marks a turn, so the turns the agent ran cannot be counted"
            .to_owned()
    })?;
    let mut turns: BTreeSet<String> = BTreeSet::new();
    let mut unnamed = 0_u64;
    let mut files = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            // No conversation was written: no turn ran.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && path == root => {
                return Ok(Recorded {
                    turns: 0,
                    unnamed: 0,
                    files: 0,
                });
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
            files += 1;
            for line in String::from_utf8_lossy(&bytes).lines() {
                if line.contains(marker) {
                    let named = serde_json::from_str::<Value>(line)
                        .ok()
                        .as_ref()
                        .and_then(turn_identifier);
                    match named {
                        Some(named) => {
                            turns.insert(named);
                        }
                        None => unnamed += 1,
                    }
                }
            }
        }
    }
    // A name and an occurrence cannot be the same turn: they are kept apart, and counted together.
    Ok(Recorded {
        turns: u64::try_from(turns.len())
            .unwrap_or(u64::MAX)
            .saturating_add(unnamed),
        unnamed,
        files,
    })
}

/// What the agent's own record says of the turns a case charged, once the case has ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Audit {
    /// The record holds no more turns than were charged, and at least one where the case passed
    /// with a charged turn.
    Agrees,
    /// The record holds this many turns more than the ledger was charged for.
    Surplus(u64),
    /// A case passed with charged turns and the record holds none, in this many files: the count
    /// that backs the ledger saw nothing, so it cannot be relied on for this entry's record.
    Blind {
        /// How many files of the record were read.
        files: u64,
    },
    /// The record could not be counted.
    Uncountable(String),
}

/// Judges the agent's record of the turns against the `charged` turns of a case that `passed` or
/// did not. A case that failed may have charged a turn that never reached the agent, so an empty
/// record says nothing of it; one that passed ran every turn it charged, and a record that holds none
/// cannot be the entry's record.
#[must_use]
pub fn audit_turns(passed: bool, charged: u64, recorded: &Result<Recorded, String>) -> Audit {
    match recorded {
        Err(why) => Audit::Uncountable(why.clone()),
        Ok(found) if found.turns > charged => Audit::Surplus(found.turns - charged),
        Ok(found) if passed && charged > 0 && found.turns == 0 => {
            Audit::Blind { files: found.files }
        }
        Ok(_) => Audit::Agrees,
    }
}

/// Runs `command` in a process group of its own and returns its output. The group is ended whole as
/// soon as its leader has exited or `within` has passed, while the leader is not yet reaped and its
/// number still names the group, so that nothing the command started outlives it with the
/// environment it was given, and no signal can reach a group that took the number since. A command
/// that does not end within `within`, or whose output stays open for five seconds after the group
/// was ended, is the answer.
///
/// # Errors
///
/// Returns why it did not finish.
pub fn grouped_output(
    mut command: std::process::Command,
    within: std::time::Duration,
) -> Result<std::process::Output, String> {
    use std::io::Read as _;
    use std::os::unix::process::CommandExt as _;
    use std::time::{Duration, Instant};
    command
        .process_group(0)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start: {error}"))?;
    let group = i32::try_from(child.id()).map_err(|_| "a process number too large".to_owned())?;
    let pid = rustix::process::Pid::from_raw(group).ok_or("a process number of zero")?;
    let read = |pipe: Option<Box<dyn std::io::Read + Send>>| {
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut bytes);
            }
            let _ = sent.send(bytes);
        });
        received
    };
    let stdout = read(
        child
            .stdout
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
    );
    let stderr = read(
        child
            .stderr
            .take()
            .map(|pipe| Box::new(pipe) as Box<dyn std::io::Read + Send>),
    );
    let started = Instant::now();
    let ended = loop {
        // Whether the leader has ended, read without reaping it, so its number stays its own.
        let exited = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT,
        );
        match exited {
            Ok(Some(_)) => break Ok(()),
            Ok(None) if started.elapsed() < within => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => break Err(format!("it did not finish within {within:?}")),
            Err(error) => break Err(format!("it could not be waited for: {error}")),
        }
    };
    // The group goes whole while its leader is unreaped; only then is the leader reaped.
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    let status = child
        .wait()
        .map_err(|error| format!("it could not be reaped: {error}"))?;
    ended?;
    let handover = Instant::now() + Duration::from_secs(5);
    let collect = |received: std::sync::mpsc::Receiver<Vec<u8>>| {
        received
            .recv_timeout(handover.saturating_duration_since(Instant::now()))
            .map_err(|_| "it ended and its output stayed open past five seconds".to_owned())
    };
    Ok(std::process::Output {
        status,
        stdout: collect(stdout)?,
        stderr: collect(stderr)?,
    })
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
    fn a_tree_of_the_persons_is_unchanged_until_any_entry_in_it_is_added_resized_or_removed() {
        let home = scratch("guard");
        let deep = home.join(".agent/sessions/2026/11");
        std::fs::create_dir_all(&deep).expect("directories");
        std::fs::write(deep.join("a.jsonl"), b"one").expect("a file");
        std::fs::write(home.join(".agent/config"), b"x").expect("a file");
        let guard = MetaGuard::take(&home, &[".agent", ".absent"]);
        let (stops, evidence) = guard.compare();
        assert!(stops.is_empty(), "{stops:?}");
        assert_eq!(evidence["trees"][0]["changed"], json!(false));
        assert_eq!(evidence["trees"][0]["entries_before"], json!(6));
        // A new file in a subdirectory two levels down is a change, which no listing of named files
        // would see.
        std::fs::write(deep.join("b.jsonl"), b"new").expect("a new file");
        let (stops, evidence) = guard.compare();
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(stops[0].0, "guarded_file_changed");
        assert_eq!(evidence["trees"][0]["entries_after"], json!(7));
        // Nothing of a name goes into what is said or recorded.
        let said = format!("{stops:?}{evidence}");
        assert!(
            !said.contains("jsonl") && !said.contains("sessions"),
            "{said}"
        );
        // A file resized in place, and a path made where there was none, each against a look of its
        // own: the times of a directory move with every entry added to it or removed from it.
        let guard = MetaGuard::take(&home, &[".agent", ".absent"]);
        std::fs::write(deep.join("a.jsonl"), b"three").expect("a rewrite");
        assert_eq!(guard.compare().0.len(), 1);
        let guard = MetaGuard::take(&home, &[".agent", ".absent"]);
        std::fs::write(home.join(".absent"), b"now there").expect("a new file");
        let (stops, evidence) = guard.compare();
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(evidence["trees"][1]["entries_before"], json!(0));
        assert_eq!(evidence["trees"][1]["entries_after"], json!(1));
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_tree_that_cannot_be_looked_at_is_a_class_and_a_count_and_names_no_entry() {
        let home = scratch("unlooked");
        let tree = home.join(".agent");
        std::fs::create_dir_all(tree.join("sessions")).expect("directories");
        std::fs::write(tree.join("sessions/rollout-name.jsonl"), b"x").expect("a file");
        std::fs::write(tree.join("login-name.json"), b"x").expect("a file");
        let home_text = home.to_str().expect("a path of text").to_owned();
        let names_nothing = |why: &str| {
            for name in ["rollout-name", "login-name", "sessions", &home_text] {
                assert!(!why.contains(name), "{why}");
            }
        };
        // An entry that is gone between the listing that named it and the look at it.
        let why = walk_tree(&tree, &mut |moment, name| {
            if moment == Moment::Listed && name == b"login-name.json" {
                std::fs::remove_file(tree.join("login-name.json")).expect("removed");
            }
        })
        .expect_err("an entry that disappears during the walk is a failure");
        assert_eq!(why.class, Class::Vanished);
        names_nothing(&why.to_string());
        // A directory that became a link between the look at it and its opening is refused: the
        // walk does not go into what the link names.
        let elsewhere = scratch("elsewhere");
        std::fs::write(elsewhere.join("outside-name"), b"x").expect("a file");
        let why = walk_tree(&tree, &mut |moment, name| {
            if moment == Moment::Looked && name == b"sessions" {
                std::fs::remove_dir_all(tree.join("sessions")).expect("removed");
                std::os::unix::fs::symlink(&elsewhere, tree.join("sessions")).expect("a link");
            }
        })
        .expect_err("a directory that became a link is refused");
        assert_eq!(why.class, Class::Replaced);
        names_nothing(&why.to_string());
        // A link at the tree's own path is refused, when the guard is taken and when it looks again.
        let link = home.join(".linked");
        std::os::unix::fs::symlink(&elsewhere, &link).expect("a link");
        assert_eq!(
            tree_of(&link).expect_err("a link at the root").class,
            Class::LinkAtRoot
        );
        let taken = std::panic::catch_unwind(|| MetaGuard::take(&home, &[".linked"]))
            .expect_err("a guard over a link is refused");
        let said = panic_text(&*taken);
        names_nothing(&said);
        assert!(said.contains("symbolic link"), "{said}");
        let guard = MetaGuard::take(&home, &[".agent"]);
        std::fs::remove_dir_all(&tree).expect("removed");
        std::os::unix::fs::symlink(&elsewhere, &tree).expect("a link");
        let (stops, evidence) = guard.compare();
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(stops[0].0, "person_file_unreadable");
        names_nothing(&format!("{stops:?}{evidence}"));
        // A directory the system will not list. A process with every permission lists it.
        if !rustix::process::geteuid().is_root() {
            let other = scratch("closed");
            let closed = other.join("closed-name");
            std::fs::create_dir_all(&closed).expect("a directory");
            std::fs::set_permissions(&closed, std::os::unix::fs::PermissionsExt::from_mode(0o000))
                .expect("closed");
            let why = tree_of(&other).expect_err("a directory that cannot be listed");
            assert!(matches!(why.class, Class::Refused(_)), "{why}");
            assert!(!why.to_string().contains("closed-name"), "{why}");
            std::fs::set_permissions(&closed, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .expect("opened");
            std::fs::remove_dir_all(&other).expect("clean up");
        }
        std::fs::remove_dir_all(&elsewhere).expect("clean up");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_turn_counts_once_by_its_name_however_many_files_hold_it_and_a_line_with_no_name_counts_each_time()
     {
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
        // Two equal lines that name no turn are two turns, not one, as are a third that is no JSON.
        std::fs::write(
            root.join("c.jsonl"),
            "{\"type\":\"task_started\"}\n{\"type\":\"task_started\"}\nnot json \"type\":\"task_started\"\n",
        )
        .expect("lines with no name");
        assert_eq!(
            turns_recorded(&account(), &root),
            Ok(Recorded {
                turns: 6,
                unnamed: 3,
                files: 3
            })
        );
        assert_eq!(
            turns_recorded(&account(), &root.join("none")),
            Ok(Recorded {
                turns: 0,
                unnamed: 0,
                files: 0
            })
        );
        let mut unnamed = account();
        unnamed.turn_line = None;
        assert!(turns_recorded(&unnamed, &root).is_err());
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn a_case_that_passed_with_a_charged_turn_stops_when_the_record_holds_no_turn() {
        let found = |turns, files| {
            Ok(Recorded {
                turns,
                unnamed: 0,
                files,
            })
        };
        // The record is not there, or holds files with no turn in them: a passed case with a
        // charge is blind, and says how many files were read.
        assert_eq!(
            audit_turns(true, 1, &found(0, 0)),
            Audit::Blind { files: 0 }
        );
        assert_eq!(
            audit_turns(true, 2, &found(0, 4)),
            Audit::Blind { files: 4 }
        );
        // A case that failed may have charged a turn that never reached the agent; one that
        // charged nothing has nothing to find.
        assert_eq!(audit_turns(false, 1, &found(0, 0)), Audit::Agrees);
        assert_eq!(audit_turns(true, 0, &found(0, 0)), Audit::Agrees);
        // Fewer turns than were charged is not a surplus: a charged prompt a host refused is no turn.
        assert_eq!(audit_turns(true, 2, &found(1, 1)), Audit::Agrees);
        assert_eq!(audit_turns(true, 1, &found(3, 1)), Audit::Surplus(2));
        assert_eq!(audit_turns(false, 1, &found(3, 1)), Audit::Surplus(2));
        assert_eq!(
            audit_turns(true, 1, &Err("unread".to_owned())),
            Audit::Uncountable("unread".to_owned())
        );
    }

    #[test]
    fn a_run_whose_home_is_not_the_account_databases_is_refused_before_it_starts() {
        let home = scratch("home");
        let other = scratch("other-home");
        let named = home.to_str().expect("a path of text");
        // The same directory, written two ways.
        assert_eq!(
            person_home_of(Some(home.as_os_str()), Some(named)),
            Ok(home.clone())
        );
        assert_eq!(
            person_home_of(Some(home.join(".").as_os_str()), Some(named)),
            Ok(home.clone())
        );
        // Another directory, no HOME, and an account database that names none.
        for refused in [
            person_home_of(Some(other.as_os_str()), Some(named)),
            person_home_of(None, Some(named)),
            person_home_of(Some(home.as_os_str()), None),
            person_home_of(Some(home.as_os_str()), Some("")),
        ] {
            let why = refused.expect_err("refused");
            assert!(
                !why.contains(named) && !why.contains(other.to_str().expect("text")),
                "the refusal names no directory: {why}"
            );
        }
        std::fs::remove_dir_all(&home).expect("clean up");
        std::fs::remove_dir_all(&other).expect("clean up");
    }

    #[test]
    fn a_probe_ends_whole_before_its_output_is_returned_and_one_that_hangs_is_ended() {
        let mut command = std::process::Command::new("/bin/sh");
        // The leader exits at once and leaves a helper that holds the output open.
        command.arg("-c").arg("/bin/sleep 300 & echo $!");
        let output = grouped_output(command, std::time::Duration::from_secs(60))
            .expect("the group ended whole, so the output closed");
        let helper: i32 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("the helper's number");
        let helper = rustix::process::Pid::from_raw(helper).expect("a number");
        let started = std::time::Instant::now();
        while rustix::process::test_kill_process(helper).is_ok() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "the helper the probe left still runs"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let mut hangs = std::process::Command::new("/bin/sh");
        hangs.arg("-c").arg("/bin/sleep 300");
        let why = grouped_output(hangs, std::time::Duration::from_millis(300))
            .expect_err("a probe that hangs is ended and refused");
        assert!(why.contains("did not finish"), "{why}");
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
