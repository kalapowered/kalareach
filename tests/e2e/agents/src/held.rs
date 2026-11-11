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

use kr_e2e_m1b::run::{Removal, Run, remove_run_directory};
use serde_json::{Value, json};

use crate::account::{
    self, KeyScan, RunRules, now_ms, record_key_scan, run_files_holding, run_files_holding_any,
};
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
/// it, as given and as the system resolved it before the agent started: `resolved_work` is that
/// resolution, made once by the caller ([`folder_of`]) and kept, since the run's tree can change once
/// the agent has run, and a link left at the working directory would send a second resolution
/// outside.
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
    resolved_work: &Path,
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
        for start in [run.work(), resolved_work.to_path_buf()] {
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

/// Whether nothing is at `path`, looked at with no link followed at its last component: "not found"
/// is absent, any entry (a link that leads nowhere included) is present, and any other answer is an
/// error, since an absence the system did not show is not one.
///
/// # Errors
///
/// Returns what the system said when it said anything but "not found".
pub fn is_absent(path: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
    }
}

/// Whether nothing is at `path`, for a path of the run: below the run's directory `root`, which
/// `pin` names, it is looked at by a walk from the pin that follows no link at any component, so a
/// link at `w`, `h` or the configuration directory is a class and nothing is looked at through it;
/// a path outside the run is a fixed place and is looked at as [`is_absent`] does.
///
/// # Errors
///
/// Returns why the absence was not shown.
pub fn absent_below(
    root: &Path,
    pin: &kr_e2e_m1b::run::RootPin,
    path: &Path,
) -> Result<bool, String> {
    match path.strip_prefix(root) {
        Ok(relative) if !relative.as_os_str().is_empty() => {
            kr_e2e_m1b::run::entry_below(root, pin, relative)
                .map(|present| !present)
                .map_err(|refusal| refusal.to_string())
        }
        _ => is_absent(path).map_err(|error| error.to_string()),
    }
}

/// What stops a driver, as a class and the words that say it.
pub type Stop = (&'static str, String);

/// The search of a run's directory for the values of the keys a driver held, made while the
/// directory is still there and every process the run started has ended.
#[derive(Debug)]
pub struct RunScan {
    key: Option<(String, KeyScan)>,
    others: Option<KeyScan>,
    pin: kr_e2e_m1b::run::RootPin,
}

impl RunScan {
    /// Searches `root` for the login's value and, together, for the other keys' values, under
    /// `rules`: the directory the run made, and the links the harness made.
    #[must_use]
    pub fn of(root: &Path, rules: &RunRules, held: &HeldKeys) -> Self {
        let key = held.key.as_ref().map(|(name, value)| {
            (
                name.clone(),
                run_files_holding(root, rules, value.as_bytes()),
            )
        });
        let others = (!held.others.is_empty()).then(|| {
            let values: Vec<&[u8]> = held.others.iter().map(String::as_bytes).collect();
            run_files_holding_any(root, rules, &values)
        });
        Self {
            key,
            others,
            pin: rules.pin().clone(),
        }
    }

    /// Whether a key was searched for at all.
    #[must_use]
    pub const fn searched(&self) -> bool {
        self.key.is_some() || self.others.is_some()
    }

    /// Why the run's directory is to be left where it is, as a class: the search met a volume
    /// mounted below it, or its root was not the directory the run made.
    fn left_in_place(&self, writers_ended: bool) -> Option<&'static str> {
        let scans = || self.key.iter().map(|(_, scan)| scan).chain(&self.others);
        if !writers_ended {
            Some("a process the run started may still be running")
        } else if scans().any(|scan| scan.root_changed) {
            Some("the root was not the directory the run made")
        } else if scans().any(|scan| scan.crossed_a_mount) {
            Some("an entry below it lies on another file system")
        } else {
            None
        }
    }

    /// Removes the run's directory (through handles, inside the run: nothing on another file system
    /// is entered or removed, and a directory the search found a volume below, or whose root was not
    /// the run's, is left where it is), checks it gone, records the search by path and what became
    /// of the directory, and says what stops the driver: a search that could not read everything, a
    /// directory still there, a process that may still have been writing during the search, and
    /// another key's value found in a file. The login's own value found in a file is recorded, as
    /// the qualification cases record it, and stops nothing. Call it once the run is dropped, so the
    /// run's own end does not say it keeps a directory that is about to go.
    ///
    /// The order is the caller's: everything the run started is ended and checked ended before the
    /// search and before this removal. `writers_ended` says whether that check passed, and a run
    /// whose check did not pass is left where it is, whatever else holds.
    #[must_use]
    pub fn finish(self, root: &Path, case: &str, writers_ended: bool) -> (Vec<Stop>, Value) {
        let mut stops: Vec<Stop> = Vec::new();
        let left = match self.left_in_place(writers_ended) {
            Some(why) => Some(why.to_owned()),
            None => match remove_run_directory(root, &self.pin) {
                Removal::Removed => None,
                Removal::Left(why) => Some(why.to_string()),
            },
        };
        // No link's target is looked at, and a look the system did not answer is not "gone".
        let gone = is_absent(root).unwrap_or(false);
        let mut evidence = json!({ "run_gone": gone });
        if let Some(why) = &left {
            evidence["run_left"] = json!(why);
            stops.push((
                "run_left_in_place",
                format!("the run's directory was left where it is: {why}"),
            ));
        }
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
pub(crate) enum Class {
    /// The tree's own path is a symbolic link: the guard refuses it and follows nothing.
    LinkAtRoot,
    /// An entry of the agent's record, or a directory on the way to it, is a symbolic link, or a
    /// file that has more than one name (a hard link, which is the same file under another name,
    /// possibly one of the person's): the reading of the record refuses it and reads nothing
    /// through it.
    Link,
    /// An entry of the agent's record is neither a file nor a directory, or a path that is not a
    /// plain run of names was asked for.
    NotAFile,
    /// An entry was gone between the listing that named it and the look at it.
    Vanished,
    /// A directory was another kind of entry when it was opened than when it was looked at.
    Replaced,
    /// An entry of the agent's record lies on another file system than the run's directory, as a
    /// volume attached below it does: no-follow does not refuse a mount, and a file on it has one
    /// name, so only the device tells it from the run's own. The reading refuses it before anything
    /// on it is opened.
    OtherDevice,
    /// The path the reading was asked to start from is not the directory the run made: another
    /// directory, or a mounted volume, is there.
    RootChanged,
    /// A directory or file the reading holds open is no longer beneath the run's directory: it was
    /// moved out of the run, or into a directory that was.
    Moved,
    /// The system refused a look or a listing.
    Refused(rustix::io::Errno),
    /// The tree is deeper than the walk goes.
    TooDeep,
}

/// A tree that could not be looked at: the class of the failure and how many entries had been looked
/// at by then. It says no name, so that nothing under the person's own directory is said.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Unlooked {
    pub(crate) class: Class,
    pub(crate) seen: usize,
}

impl std::fmt::Display for Unlooked {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let seen = self.seen;
        match self.class {
            Class::LinkAtRoot => write!(formatter, "the directory is a symbolic link"),
            Class::Link => write!(
                formatter,
                "an entry is a symbolic link or a file with more than one name, which is refused \
                 and read through by nothing (after {seen} entries)"
            ),
            Class::NotAFile => write!(
                formatter,
                "an entry is neither a file nor a directory (after {seen} entries)"
            ),
            Class::Vanished => write!(
                formatter,
                "an entry disappeared while the tree was looked at (after {seen} entries)"
            ),
            Class::Replaced => write!(
                formatter,
                "a directory became another kind of entry while the tree was looked at (after \
                 {seen} entries)"
            ),
            Class::RootChanged => write!(
                formatter,
                "the run's directory is not the directory the run made (after {seen} entries)"
            ),
            Class::Moved => write!(
                formatter,
                "an entry is no longer beneath the run's directory, which is refused and read \
                 through by nothing (after {seen} entries)"
            ),
            Class::OtherDevice => write!(
                formatter,
                "an entry lies on another file system than the run's, which is refused and read \
                 through by nothing (after {seen} entries)"
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
pub(crate) const DEEPEST: usize = 64;

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
pub(crate) fn opened_directory(
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
pub(crate) fn opening_failed(error: rustix::io::Errno) -> Class {
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

/// One row of the process listing: the process, its parent, its user, the name its parent gave it
/// (`argv[0]`, which is what `ps` prints as `comm` on macOS) and the path of the file it runs as the
/// system says it, where the system says one.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcessRow {
    pid: u32,
    parent: u32,
    user: u32,
    argv0: String,
    executable: Option<String>,
}

/// Whether `file` is the name of an agent whose executable is called `agent`, case-insensitively:
/// `agent` itself (`codex`; the desktop application's main process is `Codex`), or `agent` followed
/// by a hyphen, an underscore, a point or a space and anything (the release files such as
/// `codex-aarch64-apple-darwin`, a helper such as `codex-code-mode-host` or `Codex Helper`). A
/// longer name that only begins with the same letters (`codexify`) is another program.
fn names_the_agent(file: &str, agent: &str) -> bool {
    let (file, agent) = (file.to_lowercase(), agent.to_lowercase());
    file.strip_prefix(&agent)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(['-', '_', '.', ' ']))
}

impl ProcessRow {
    /// Whether this process is the agent called `agent`: the file name of the path the system gives
    /// for its executable, or the file name of the name its parent gave it, is the agent's
    /// ([`names_the_agent`]). Either is enough, since a parent can give a process any name and a
    /// renamed file runs under its own.
    fn is_the_agent(&self, agent: &str) -> bool {
        let file = |path: &str| {
            Path::new(path)
                .file_name()
                .is_some_and(|name| names_the_agent(&name.to_string_lossy(), agent))
        };
        self.executable.as_deref().is_some_and(file) || file(&self.argv0)
    }
}

/// The process ids of the processes of `user` that are the agent called `agent`
/// ([`ProcessRow::is_the_agent`]) and are not the run's, in ascending order: a process is the run's
/// when it or an ancestor of it is one of `marked`, the processes whose command line names the run's
/// directory. Nothing else of a process is kept: no path, no name, no argument, no directory, no
/// file it has open.
fn outside_the_run(
    rows: &[ProcessRow],
    marked: &BTreeSet<u32>,
    user: u32,
    agent: &str,
) -> Vec<u32> {
    let parents: std::collections::BTreeMap<u32, u32> =
        rows.iter().map(|row| (row.pid, row.parent)).collect();
    let mut found: Vec<u32> = rows
        .iter()
        .filter(|row| row.user == user && row.is_the_agent(agent))
        .filter(|row| {
            let mut pid = row.pid;
            // Far deeper than any lineage; a loop in the table cannot hold the walk.
            for _ in 0..256 {
                if marked.contains(&pid) {
                    return false;
                }
                match parents.get(&pid) {
                    Some(parent) if *parent != pid && *parent != 0 => pid = *parent,
                    _ => break,
                }
            }
            true
        })
        .map(|row| row.pid)
        .collect();
    found.sort_unstable();
    found
}

/// The processes of this user that are the agent called `agent` (`codex`) outside the run whose
/// directory is `run_root`, where there is a run, each as its process id and nothing else: found by
/// a listing of the processes and, for each of this user's, the path of the file it runs as the
/// system says it (`proc_pidpath` on macOS), which reads no file under the person's agent
/// directory. A process counts when the file name of that path or of the name its parent gave it
/// (`argv[0]`) is the agent's ([`names_the_agent`]: `codex`, the release files `codex-<target>`, the
/// desktop application's main process `Codex`, in any case). A process of the run's own, an agent
/// it started among them, is not counted. No path is kept, so none can be said: a path under the
/// person's agent folder would name something there, and no comparison with the folder can tell
/// every spelling of it.
///
/// This is a help and not a proof. It does not find an agent that runs as another program (a
/// Node script, a wrapper under another name that has no `codex` child), a process of another user,
/// or one that starts after the listing; the comparison of the person's agent directory right before
/// the charge, and the operator's own check that no agent runs, are what keep a turn from being
/// wasted.
///
/// # Errors
///
/// Returns why the listing is not known: a listing that cannot be read says nothing of which
/// processes run, so it is never read as none.
pub fn other_agent_processes(agent: &str, run_root: Option<&Path>) -> Result<Vec<u32>, String> {
    let mut ps = std::process::Command::new("/bin/ps");
    ps.args(["-A", "-ww", "-o", "pid=,ppid=,uid=,comm="])
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    let output = grouped_output(ps, std::time::Duration::from_secs(20))
        .map_err(|why| format!("the process listing could not be read: ps {why}"))?;
    if !output.status.success() {
        return Err(format!(
            "the process listing could not be read: ps ended with {}",
            output.status
        ));
    }
    let me = rustix::process::geteuid().as_raw();
    let rows: Vec<ProcessRow> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid: u32 = fields.next()?.parse().ok()?;
            let parent = fields.next()?.parse().ok()?;
            let user: u32 = fields.next()?.parse().ok()?;
            let argv0 = fields.collect::<Vec<_>>().join(" ");
            // The system's own answer, asked for the processes of this user only.
            let executable = (user == me)
                .then(|| kr_e2e_m1b::run::executable_path(pid))
                .flatten()
                .map(|path| path.display().to_string());
            Some(ProcessRow {
                pid,
                parent,
                user,
                argv0,
                executable,
            })
        })
        .collect();
    if rows.is_empty() {
        return Err("the process listing held no process, which is not a listing".to_owned());
    }
    let marked: BTreeSet<u32> = match run_root {
        Some(root) => kr_e2e_m1b::run::processes_under(root)?
            .into_iter()
            .map(|(pid, _)| pid)
            .collect(),
        None => BTreeSet::new(),
    };
    Ok(outside_the_run(&rows, &marked, me, agent))
}

/// What a driver says when processes of the user are the agent outside the run: how many there are,
/// their process ids, and what to do; nothing else of a process, no path and no name. The guard over
/// the person's agent directory compares the whole of it at the end, and cannot tell a write of
/// theirs from one of the run's agent.
#[must_use]
pub fn other_agents_refusal(found: &[u32], when: &str) -> String {
    let mut ids = found.to_vec();
    ids.sort_unstable();
    let ids: Vec<String> = ids.iter().map(u32::to_string).collect();
    format!(
        "{} process(es) of this user are the agent outside the run (process ids {}), {when}: a \
         write of theirs to the person's agent directory would be taken for the run's, so no turn \
         is started or charged while they run; end them, and start again",
        found.len(),
        ids.join(", ")
    )
}

/// Whether the person's own agent files are as they stood when `guard` was taken, looked at again
/// right before a turn is charged: a change since then, by a process the listing missed or any
/// other writer, stops the case here, with no turn charged. What is said is the class and the
/// counts of [`MetaGuard::compare`], never a name.
///
/// # Errors
///
/// Returns what changed.
pub fn unchanged_before_the_charge(guard: &MetaGuard) -> Result<(), String> {
    let (stops, _) = guard.compare();
    if stops.is_empty() {
        return Ok(());
    }
    Err(stops
        .iter()
        .map(|(class, why)| format!("{class}: {why}"))
        .collect::<Vec<_>>()
        .join("; "))
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

/// The member `turn_id` of a JSON line, at any depth, where it has one that names a turn: a text
/// with something in it. An empty or blank one names nothing, and the line is unnamed.
fn turn_identifier(value: &Value) -> Option<String> {
    match value {
        Value::Object(members) => match members.get("turn_id") {
            Some(Value::String(name)) => (!name.trim().is_empty()).then(|| name.clone()),
            _ => members.values().find_map(turn_identifier),
        },
        Value::Array(items) => items.iter().find_map(turn_identifier),
        _ => None,
    }
}

/// What a reading of a run's record stays within: the look at the run's directory, whose file system
/// every entry must lie on, and the directory the run made, beneath which every handle must stay.
struct Bounds<'a> {
    root: rustix::fs::Stat,
    pin: &'a kr_e2e_m1b::run::RootPin,
}

/// Opens the directory `relative` below `within`, one component at a time, each looked at and opened
/// with no link followed and checked to be the directory that was looked at, and returns it with the
/// look at `within`, the file system the record is read on: `None` where a component is not there
/// (nothing was written). A component that is a symbolic link, or is not a directory, or lies on
/// another file system than `within`, is a failure of the look, and nothing is read through it.
/// `within` itself is opened with no link followed at its last component, as the run's directory it
/// is.
fn record_directory<'a>(
    within: &Path,
    pin: &'a kr_e2e_m1b::run::RootPin,
    relative: &Path,
) -> Result<Option<(std::os::fd::OwnedFd, Bounds<'a>)>, Unlooked> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    let unlooked = |class| Unlooked { class, seen: 0 };
    let mut directory = rustix::fs::open(
        within,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| unlooked(opening_failed(error)))?;
    let root = rustix::fs::fstat(&directory).map_err(|error| unlooked(Class::Refused(error)))?;
    // The run's directory is the one the run made: not a mount point, and not another directory
    // renamed to its path.
    if !pin.holds(&directory) {
        return Err(unlooked(Class::RootChanged));
    }
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(unlooked(Class::NotAFile));
        };
        let name = std::ffi::CString::new(name.as_encoded_bytes())
            .map_err(|_| unlooked(Class::NotAFile))?;
        let looked =
            match rustix::fs::statat(&directory, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(looked) => looked,
                Err(rustix::io::Errno::NOENT) => return Ok(None),
                Err(error) => return Err(unlooked(Class::Refused(error))),
            };
        // The check is for mounts only: the system's own volumes share one device number.
        if looked.st_dev != root.st_dev {
            return Err(unlooked(Class::OtherDevice));
        }
        match FileType::from_raw_mode(looked.st_mode) {
            FileType::Directory => {}
            FileType::Symlink => return Err(unlooked(Class::Link)),
            _ => return Err(unlooked(Class::NotAFile)),
        }
        directory = opened_directory(&directory, name.as_c_str(), &looked, 0)?;
        if !pin.contains(&directory) {
            return Err(unlooked(Class::Moved));
        }
    }
    Ok(Some((directory, Bounds { root, pin })))
}

/// Reads every file of the directory `directory` and below through handles, handing each file's
/// place (its names from the record's root, joined by `/`) and content to `visit`: an entry is
/// looked at with `fstatat` and no link followed, a directory is opened with the same handle and no
/// link followed, and a file is opened with no link followed and nonblocking, then checked to be a
/// regular file and the one that was looked at, before a byte of it is read. A link, an entry that
/// is neither a file nor a directory, and an entry that lies on another file system than `root`,
/// the look at the record's root, is a failure and nothing is read through it.
fn read_files(
    directory: &std::os::fd::OwnedFd,
    bounds: &Bounds<'_>,
    relative: &[u8],
    depth: usize,
    seen: &mut usize,
    visit: &mut dyn FnMut(&[u8], &[u8]),
    between: &mut dyn FnMut(Moment, &[u8]),
) -> Result<(), Unlooked> {
    use rustix::fs::{AtFlags, FileType, Mode, OFlags};
    use std::io::Read as _;
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
        let unlooked = |class, seen: &usize| Unlooked { class, seen: *seen };
        let looked = rustix::fs::statat(directory, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| {
                unlooked(
                    if error == rustix::io::Errno::NOENT {
                        Class::Vanished
                    } else {
                        Class::Refused(error)
                    },
                    seen,
                )
            })?;
        *seen += 1;
        // A volume attached below the record is no link and its files have one name: only the
        // device tells it from the run's own (a check for mounts only: the system's own volumes
        // share one device number).
        if looked.st_dev != bounds.root.st_dev {
            return Err(unlooked(Class::OtherDevice, seen));
        }
        let mut path = relative.to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(name.to_bytes());
        match FileType::from_raw_mode(looked.st_mode) {
            FileType::Directory => {
                between(Moment::Looked, name.to_bytes());
                let child = opened_directory(directory, name.as_c_str(), &looked, *seen)?;
                // A directory moved out of the run since it was looked at is not read.
                if !bounds.pin.contains(&child) {
                    return Err(unlooked(Class::Moved, seen));
                }
                read_files(&child, bounds, &path, depth + 1, seen, visit, between)?;
            }
            FileType::RegularFile => {
                // A file with a second name is the same file under another name, whoever made
                // it: refused before it is opened.
                if looked.st_nlink != 1 {
                    return Err(unlooked(Class::Link, seen));
                }
                between(Moment::Looked, name.to_bytes());
                let handle = rustix::fs::openat(
                    directory,
                    name.as_c_str(),
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| unlooked(opening_failed(error), seen))?;
                let opened = rustix::fs::fstat(&handle)
                    .map_err(|error| unlooked(Class::Refused(error), seen))?;
                if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile
                    || (opened.st_dev, opened.st_ino) != (looked.st_dev, looked.st_ino)
                {
                    return Err(unlooked(Class::Replaced, seen));
                }
                // A name added since the look is a second name too: counted again on the handle
                // that will be read, after the identity check and before any read.
                if opened.st_nlink != 1 {
                    return Err(unlooked(Class::Link, seen));
                }
                // A file moved into a directory that was moved out of the run is not the run's.
                if !bounds.pin.contains(&handle) {
                    return Err(unlooked(Class::Moved, seen));
                }
                let mut bytes = Vec::new();
                std::fs::File::from(handle)
                    .read_to_end(&mut bytes)
                    .map_err(|error| {
                        unlooked(
                            Class::Refused(rustix::io::Errno::from_raw_os_error(
                                error.raw_os_error().unwrap_or(0),
                            )),
                            seen,
                        )
                    })?;
                visit(&path, &bytes);
            }
            FileType::Symlink => return Err(unlooked(Class::Link, seen)),
            _ => return Err(unlooked(Class::NotAFile, seen)),
        }
    }
    Ok(())
}

/// Reads the agent's own record: every file below `relative` in `within`, the run's directory,
/// through directory handles with no link followed at any step ([`record_directory`],
/// [`read_files`]), handing each file's place in the record and its content to `visit`, and returns
/// how many files were read. A record that is not there is none (`Ok(0)`); a `within` that is not
/// the directory `pin` names, a link anywhere in it, an entry that is neither a file nor a
/// directory, an entry on another file system than `within` (a volume attached below the record),
/// and a handle no longer beneath the run's directory are refused before a byte is read through
/// them, since the person's own files must never be read, and what is said is a class and a count,
/// never a name.
///
/// # Errors
///
/// Returns why the record could not be read whole.
pub fn read_record(
    within: &Path,
    pin: &kr_e2e_m1b::run::RootPin,
    relative: &Path,
    visit: &mut dyn FnMut(&[u8], &[u8]),
) -> Result<u64, String> {
    read_record_by(within, pin, relative, visit, &mut |_, _| {})
}

/// [`read_record`] with the two moments of the walk at which a test changes what is being read.
fn read_record_by(
    within: &Path,
    pin: &kr_e2e_m1b::run::RootPin,
    relative: &Path,
    visit: &mut dyn FnMut(&[u8], &[u8]),
    between: &mut dyn FnMut(Moment, &[u8]),
) -> Result<u64, String> {
    let said = |why: Unlooked| format!("the agent's record cannot be read whole: {why}");
    let Some((directory, bounds)) = record_directory(within, pin, relative).map_err(said)? else {
        return Ok(0);
    };
    let mut seen = 0_usize;
    let mut files = 0_u64;
    read_files(
        &directory,
        &bounds,
        b"",
        1,
        &mut seen,
        &mut |place, content| {
            files += 1;
            visit(place, content);
        },
        between,
    )
    .map_err(said)?;
    Ok(files)
}

/// The turns the agent's own record holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recorded {
    /// How many turns the model ran, as the record counts them.
    pub turns: u64,
    /// How many of them are counted by occurrence of their line, because the line names no turn.
    pub unnamed: u64,
    /// How many files of the record were read: none where the record's directory is not there.
    pub files: u64,
    /// How many distinct turn names are UUIDs, which count once across the record's files.
    pub by_uuid: u64,
    /// How many turn names, each for its file, are not UUIDs, and count once for each file.
    pub by_other_name: u64,
    /// The forms of the names that are not UUIDs (an ASCII digit as `9`, a lower-case letter as
    /// `a`, an upper-case one as `A`, a hyphen and an underscore as they are, any other character
    /// as `?`; at most forty characters, at most five forms), so that the record says what the
    /// names look like though the run's directory, and with it the agent's record, is removed.
    pub forms: Vec<String>,
}

/// The form of a turn name that is not a UUID: see [`Recorded::forms`]. Every character becomes one
/// of six marks: `9` for an ASCII digit, `a` for an ASCII lower-case letter, `A` for an ASCII
/// upper-case one, `-`, `_`, and `?` for any other character, so that no character of the name,
/// whatever script or symbol it is, survives.
fn form_of(name: &str) -> String {
    name.chars()
        .take(40)
        .map(|character| match character {
            '0'..='9' => '9',
            'a'..='z' => 'a',
            'A'..='Z' => 'A',
            '-' => '-',
            '_' => '_',
            _ => '?',
        })
        .collect()
}

/// Whether `name` is a UUID in its written form: 8, 4, 4, 4 and 12 hexadecimal digits between
/// hyphens. A UUID that is random or time-ordered is unique across threads by construction.
fn is_uuid(name: &str) -> bool {
    name.len() == 36
        && name.char_indices().all(|(index, character)| match index {
            8 | 13 | 18 | 23 => character == '-',
            _ => character.is_ascii_hexdigit(),
        })
}

/// How many turns the model ran, as the agent's own record under `root` holds them: the lines the
/// entry's turn line marks. A line that names its turn (`turn_id`, one with something in it) counts
/// once for its thread and its name: a name that is a UUID is unique across threads, so it counts
/// once whichever of the agent's files, a copy of a conversation among them, holds it; any other
/// name is only known to be unique within its thread, a file of the record, so it counts once for
/// each file that holds it. A line that names none (no name, an empty one) counts once for each
/// time it occurs, in any file. A conversation written again, a fork's copy of the one it forked
/// from where the names are not UUIDs, or unnamed lines in a copy, count their turns twice: the
/// count is then too high. It is too low only where the record lost lines (an agent that was ended
/// before it wrote them, or that marks no turn this way), which no count of the lines can show; the
/// audit stops a case that passed with a charge and finds none. [`Recorded::unnamed`] says how many
/// turns stand on an occurrence.
///
/// The record is read below `relative` in `within`, the run's directory, through directory handles
/// with no link followed at any step ([`read_record`]).
///
/// # Errors
///
/// Returns why the count is not whole: the entry names no turn line, or the record could not be
/// read whole (a link in it is refused, and what is said of it is a class and a count, never a
/// name).
pub fn turns_recorded(
    account: &Account,
    within: &Path,
    pin: &kr_e2e_m1b::run::RootPin,
    relative: &Path,
) -> Result<Recorded, String> {
    let marker = account.turn_line.as_deref().ok_or_else(|| {
        "the entry names no line that marks a turn, so the turns the agent ran cannot be counted"
            .to_owned()
    })?;
    let mut turns: BTreeSet<String> = BTreeSet::new();
    let mut by_uuid: BTreeSet<String> = BTreeSet::new();
    let mut by_other_name: BTreeSet<String> = BTreeSet::new();
    let mut forms: BTreeSet<String> = BTreeSet::new();
    let mut unnamed = 0_u64;
    let files = read_record(within, pin, relative, &mut |place, content| {
        for line in String::from_utf8_lossy(content).lines() {
            if line.contains(marker) {
                let named = serde_json::from_str::<Value>(line)
                    .ok()
                    .as_ref()
                    .and_then(turn_identifier);
                match named {
                    Some(named) if is_uuid(&named) => {
                        by_uuid.insert(named.clone());
                        turns.insert(named);
                    }
                    Some(named) => {
                        let own = format!("{}\0{named}", String::from_utf8_lossy(place));
                        by_other_name.insert(own.clone());
                        turns.insert(own);
                        forms.insert(form_of(&named));
                    }
                    None => unnamed += 1,
                }
            }
        }
    })?;
    // A name and an occurrence cannot be the same turn: they are kept apart, and counted together.
    Ok(Recorded {
        turns: u64::try_from(turns.len())
            .unwrap_or(u64::MAX)
            .saturating_add(unnamed),
        unnamed,
        files,
        by_uuid: u64::try_from(by_uuid.len()).unwrap_or(u64::MAX),
        by_other_name: u64::try_from(by_other_name.len()).unwrap_or(u64::MAX),
        forms: forms.into_iter().take(5).collect(),
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

/// The leader of a command's process group, from the moment the command is spawned: until its
/// leader is reaped, its number still names the group, so ending the group is safe, and dropping
/// this ends it and reaps the leader. A probe therefore never outlives a failure of its own setup,
/// a panic included.
struct Leader {
    child: std::process::Child,
    group: rustix::process::Pid,
    /// Whether the number still names the group: true until the leader is reaped, or found not to
    /// be this process's to wait for.
    holds: bool,
}

impl Leader {
    /// Ends the group whole, if its number is still the leader's.
    fn end_group(&self) {
        if self.holds {
            let _ = rustix::process::kill_process_group(self.group, rustix::process::Signal::KILL);
        }
    }

    /// Reaps the leader, after the group was ended.
    fn reap(&mut self) -> Result<std::process::ExitStatus, String> {
        self.holds = false;
        self.child
            .wait()
            .map_err(|error| format!("it could not be reaped: {error}"))
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        if self.holds {
            self.end_group();
            let _ = self.reap();
        }
    }
}

/// Whether a failed look at the leader still shows it to be an unreaped child of this process, whose
/// number therefore still names the group. `ECHILD` shows the opposite: there is no such child to
/// wait for, so the number may name nothing or another process's group, and no signal goes to it.
fn leader_may_hold_its_number(error: rustix::io::Errno) -> bool {
    error != rustix::io::Errno::CHILD
}

/// How a probe's output is collected: a thread that reads `pipe` to its end and sends what it read.
/// A thread that cannot be made is an error and not a panic.
fn read_in_a_thread(
    _stream: &str,
    pipe: Box<dyn std::io::Read + Send>,
) -> std::io::Result<std::sync::mpsc::Receiver<Vec<u8>>> {
    use std::io::Read as _;
    let (sent, received) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("probe-output".to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            let mut pipe = pipe;
            let _ = pipe.read_to_end(&mut bytes);
            let _ = sent.send(bytes);
        })?;
    Ok(received)
}

/// Runs `command` in a process group of its own and returns its output. The group is guarded from
/// the moment it is spawned ([`Leader`]); it is ended whole as soon as its leader has exited or
/// `within` has passed, while the leader is not yet reaped and its number still names the group, so
/// that nothing the command started outlives it with the environment it was given, and no signal
/// can reach a group that took the number since. A command that does not end within `within`, or
/// whose output stays open for five seconds after the group was ended, is the answer; so is one
/// whose output cannot be collected, with its group ended all the same.
///
/// # Errors
///
/// Returns why it did not finish.
pub fn grouped_output(
    command: std::process::Command,
    within: std::time::Duration,
) -> Result<std::process::Output, String> {
    grouped_output_by(command, within, &mut |stream, pipe| {
        read_in_a_thread(stream, pipe)
    })
}

/// How one of a probe's two output pipes (named) is collected: what the pipe holds, once it has
/// ended, arrives on the channel returned.
type OutputReader<'a> = dyn FnMut(
        &str,
        Box<dyn std::io::Read + Send>,
    ) -> std::io::Result<std::sync::mpsc::Receiver<Vec<u8>>>
    + 'a;

/// [`grouped_output`] with the way each of the two output pipes is collected, which a test
/// replaces to make collecting fail.
fn grouped_output_by(
    mut command: std::process::Command,
    within: std::time::Duration,
    readers: &mut OutputReader<'_>,
) -> Result<std::process::Output, String> {
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
    let pipes = (child.stdout.take(), child.stderr.take());
    let group = i32::try_from(child.id())
        .ok()
        .and_then(rustix::process::Pid::from_raw);
    let Some(group) = group else {
        // A number that cannot name a group is not signalled: the leader is reaped as it is.
        let _ = child.kill();
        let _ = child.wait();
        return Err("a process number that cannot name a group".to_owned());
    };
    // Guarded from here: a failure below ends the group and reaps the leader.
    let mut leader = Leader {
        child,
        group,
        holds: true,
    };
    let (Some(out), Some(error)) = pipes else {
        return Err("its output pipes were not made".to_owned());
    };
    let stdout = readers("stdout", Box::new(out))
        .map_err(|error| format!("a thread for its output could not be made: {error}"))?;
    let stderr = readers("stderr", Box::new(error))
        .map_err(|error| format!("a thread for its output could not be made: {error}"))?;
    let started = Instant::now();
    let ended = loop {
        // Whether the leader has ended, read without reaping it, so its number stays its own.
        let exited = rustix::process::waitid(
            rustix::process::WaitId::Pid(group),
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
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => {
                // A leader that is not this process's child to wait for does not hold its number.
                leader.holds = leader_may_hold_its_number(error);
                break Err(format!("it could not be waited for: {error}"));
            }
        }
    };
    // The group goes whole while its leader is unreaped; only then is the leader reaped.
    leader.end_group();
    let reaped = leader.reap();
    ended?;
    let status = reaped?;
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

/// Where the agent's conversations are, relative to the run's directory: the run's configuration
/// directory and the entry's path before the `{date}` its files are sorted under.
#[must_use]
pub fn conversations_relative(account: &Account) -> PathBuf {
    let base = account.conversations.split("{date}").next().unwrap_or("");
    Path::new(CONFIG_DIRECTORY).join(base.trim_end_matches('/'))
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

    /// The pin of `root`, as the run that made it holds it.
    fn pinned(root: &Path) -> kr_e2e_m1b::run::RootPin {
        kr_e2e_m1b::run::RootPin::of(root).expect("a directory to pin")
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
    fn a_turn_counts_once_for_its_thread_and_name_and_a_line_with_no_name_counts_each_time() {
        let root = scratch("turns");
        let line = |id: &str| {
            format!(r#"{{"timestamp":"t","payload":{{"type":"task_started","turn_id":"{id}"}}}}"#)
        };
        let uuid = |number: u8| format!("019a0000-0000-7000-8000-00000000000{number}");
        std::fs::create_dir_all(root.join("2026/11")).expect("directories");
        std::fs::write(
            root.join("2026/11/a.jsonl"),
            format!(
                "{}\n{{\"role\":\"user\"}}\n{}\n",
                line(&uuid(1)),
                line(&uuid(2))
            ),
        )
        .expect("a conversation");
        // A copy of the conversation, as a fork writes it, and one more turn of its own: the names
        // are UUIDs, which are unique across threads, so the copy adds nothing.
        std::fs::write(
            root.join("2026/11/b.jsonl"),
            format!(
                "{}\n{}\n{}\n",
                line(&uuid(1)),
                line(&uuid(2)),
                line(&uuid(3))
            ),
        )
        .expect("a copy");
        // Names that are not UUIDs are known only within their thread: the same name in two files
        // is two turns.
        std::fs::write(root.join("d.jsonl"), format!("{}\n", line("1"))).expect("a thread");
        std::fs::write(root.join("e.jsonl"), format!("{}\n", line("1"))).expect("a thread");
        // Two equal lines that name no turn are two turns, as is one that is no JSON.
        std::fs::write(
            root.join("c.jsonl"),
            "{\"type\":\"task_started\"}\n{\"type\":\"task_started\"}\nnot json \"type\":\"task_started\"\n",
        )
        .expect("lines with no name");
        // An empty or blank name names nothing: two such lines are two turns, not one.
        std::fs::write(
            root.join("f.jsonl"),
            format!("{}\n{}\n{}\n", line(""), line(""), line("  ")),
        )
        .expect("lines with an empty name");
        assert_eq!(
            turns_recorded(&account(), &root, &pinned(&root), Path::new("")),
            Ok(Recorded {
                turns: 3 + 2 + 3 + 3,
                unnamed: 6,
                files: 6,
                by_uuid: 3,
                by_other_name: 2,
                // The non-UUID name is a digit: its form is one digit, and no value is kept.
                forms: vec!["9".to_owned()],
            })
        );
        assert_eq!(
            turns_recorded(&account(), &root, &pinned(&root), Path::new("none")),
            Ok(Recorded::default())
        );
        let mut unnamed = account();
        unnamed.turn_line = None;
        assert!(turns_recorded(&unnamed, &root, &pinned(&root), Path::new("")).is_err());
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn only_a_process_of_this_user_that_is_the_agent_outside_the_run_is_another_agent() {
        let row = |pid, parent, user, argv0: &str, executable: Option<&str>| ProcessRow {
            pid,
            parent,
            user,
            argv0: argv0.to_owned(),
            executable: executable.map(str::to_owned),
        };
        let rows = [
            row(1, 0, 0, "/sbin/launchd", Some("/sbin/launchd")),
            // The run's worker, a shell below it and the agent the shell started: the agent is the
            // pinned file, outside the run's directory, and is the run's by its lineage.
            row(10, 1, 501, "kr-worker", Some("/tmp/krm-x/b/kr-worker")),
            row(11, 10, 501, "zsh", Some("/bin/zsh")),
            row(12, 11, 501, "codex", Some("/cache/codex/bin/codex")),
            row(
                13,
                12,
                501,
                "codex-code-mode-host",
                Some("/cache/codex/bin/codex-code-mode-host"),
            ),
            // Another Codex of this user, with a helper under it.
            row(
                20,
                1,
                501,
                "codex",
                Some("/opt/homebrew/lib/codex/bin/codex"),
            ),
            row(
                21,
                20,
                501,
                "codex-code-mode-host",
                Some("/opt/homebrew/lib/codex/bin/codex-code-mode-host"),
            ),
            // The desktop application's main process and a helper of it, in any case; a release
            // file under the name its parent gave it, which is not a Codex's.
            row(
                60,
                1,
                501,
                "launcher",
                Some("/Applications/Codex.app/Contents/MacOS/Codex"),
            ),
            row(
                61,
                60,
                501,
                "Codex Helper (Renderer)",
                Some(
                    "/Applications/Codex.app/Contents/Frameworks/Codex Helper.app/Codex Helper (Renderer)",
                ),
            ),
            row(
                62,
                1,
                501,
                "node",
                Some("/usr/local/bin/codex-aarch64-apple-darwin"),
            ),
            // A name only the parent gave: another program under the name `codex`.
            row(63, 1, 501, "codex", Some("/usr/bin/vim")),
            // A process the system names no executable for, under the agent's name.
            row(64, 1, 501, "/somewhere/secret-name/codex", None),
            // Not the agent: another user's, other programs, and names that only begin alike.
            row(30, 1, 0, "codex", Some("/usr/local/bin/codex")),
            row(40, 1, 501, "vim", Some("/usr/bin/vim")),
            row(50, 1, 501, "codexify", Some("/usr/local/bin/codexify")),
            row(51, 1, 501, "notcodex", Some("/usr/local/bin/notcodex")),
            row(52, 1, 501, "node", Some("/usr/local/bin/node")),
        ];
        let marked: BTreeSet<u32> = [10].into_iter().collect();
        assert_eq!(
            outside_the_run(&rows, &marked, 501, "codex"),
            vec![20, 21, 60, 61, 62, 63, 64],
            "the run's agent, another user's, other programs and lookalike names are not counted, \
             and the name a parent gave is not kept"
        );
        // Before a run exists nothing is the run's: the pinned file's process counts too.
        assert_eq!(
            outside_the_run(&rows, &BTreeSet::new(), 501, "codex").len(),
            9
        );
        // The refusal says how many and which processes, and nothing else of them.
        let said = other_agents_refusal(&[12, 7], "now");
        assert!(
            said.starts_with("2 process(es)") && said.contains("process ids 7, 12"),
            "{said}"
        );
        assert!(!said.contains('/'), "{said}");
    }

    #[test]
    fn a_refusal_names_no_path_whatever_the_spelling_of_the_agents_folder() {
        // The same folder under other spellings (a link's target, another case), and a file the
        // system names no path for: no text of the refusal carries a path.
        let row = |pid, executable: Option<&str>| ProcessRow {
            pid,
            parent: 1,
            user: 501,
            argv0: "codex".to_owned(),
            executable: executable.map(str::to_owned),
        };
        let rows = [
            row(70, Some("/private/Users/r/.codex/bin/secret-name/codex")),
            row(71, Some("/USERS/R/.CODEX/bin/secret-name/codex")),
            row(72, Some("/Users/r/.codex/bin/secret-name/codex")),
            row(73, Some("/Users/r/bin/secret-name/codex")),
            row(74, None),
        ];
        let found = outside_the_run(&rows, &BTreeSet::new(), 501, "codex");
        assert_eq!(found, vec![70, 71, 72, 73, 74]);
        let said = other_agents_refusal(&found, "now");
        assert!(
            said.starts_with("5 process(es)") && said.contains("process ids 70, 71, 72, 73, 74"),
            "{said}"
        );
        assert!(
            !said.contains("secret-name") && !said.contains('/'),
            "{said}"
        );
    }

    #[test]
    fn a_process_is_found_by_the_file_it_runs_whatever_name_its_parent_gave_it() {
        use std::os::unix::process::CommandExt as _;
        // A copy of this test program called `codex`, started under another name: it is found by
        // the path the system gives for its executable. A copy under another file name, started
        // under the name `codex`, is found by that name. Neither is found by the other's file name.
        let directory = scratch("argv0");
        let program = std::env::current_exe().expect("this program");
        let start = |file: &str, name: &str| {
            let path = directory.join(file);
            std::fs::copy(&program, &path).expect("a copy");
            std::process::Command::new(&path)
                .arg0(name)
                .args([
                    "--ignored",
                    "--exact",
                    "held::tests::a_process_that_waits_to_be_listed",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("it starts")
        };
        let mut children = [
            start("codex", "unrelated-name"),
            start("other-file", "codex"),
            start("another-file", "another-name"),
        ];
        let ids: Vec<u32> = children.iter().map(std::process::Child::id).collect();
        let started = std::time::Instant::now();
        let seen = loop {
            let seen = other_agent_processes("codex", None).expect("a listing");
            if (seen.contains(&ids[0]) && seen.contains(&ids[1]))
                || started.elapsed() > std::time::Duration::from_secs(20)
            {
                break seen;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        for child in &mut children {
            child.kill().expect("ended by its own handle");
            child.wait().expect("reaped");
        }
        std::fs::remove_dir_all(&directory).expect("clean up");
        // A failure says how many were counted, not which.
        assert!(
            seen.contains(&ids[0]),
            "the copy called `codex` was not found by its executable ({} counted)",
            seen.len()
        );
        assert!(
            seen.contains(&ids[1]),
            "the copy started under the name `codex` was not found by that name ({} counted)",
            seen.len()
        );
        assert!(
            !seen.contains(&ids[2]),
            "the copy under another file and name was counted ({} counted)",
            seen.len()
        );
    }

    /// The process the listing test starts under the name `codex`: a copy of this test program that
    /// runs this one test, and waits in it until it is ended.
    #[test]
    #[ignore = "started by the listing test as a process of its own, which waits"]
    fn a_process_that_waits_to_be_listed() {
        std::thread::sleep(std::time::Duration::from_secs(300));
    }

    #[test]
    fn the_process_listing_finds_a_codex_outside_the_run_and_none_inside_it() {
        // A program called `codex` in a directory of this test's own, run by this user: a copy of
        // this test program, since a copy of a system program is not run on every system.
        let directory = scratch("listing");
        let codex = directory.join("codex");
        std::fs::copy(std::env::current_exe().expect("this program"), &codex)
            .expect("a program called codex");
        let mut running = std::process::Command::new(&codex)
            .args([
                "--ignored",
                "--exact",
                "held::tests::a_process_that_waits_to_be_listed",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("it starts");
        let id = running.id();
        let started = std::time::Instant::now();
        let seen = loop {
            let seen = other_agent_processes("codex", None).expect("a listing");
            if seen.contains(&id) || started.elapsed() > std::time::Duration::from_secs(20) {
                break seen;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        };
        // Inside a run whose directory its command line names, it is the run's.
        let inside = other_agent_processes("codex", Some(&directory)).expect("a listing");
        running.kill().expect("ended by its own handle");
        running.wait().expect("reaped");
        std::fs::remove_dir_all(&directory).expect("clean up");
        // A failure says how many were counted, not which.
        assert!(
            seen.contains(&id),
            "the listing did not count the process ({} counted)",
            seen.len()
        );
        assert!(
            !inside.contains(&id),
            "a process the run's directory names is the run's ({} counted)",
            inside.len()
        );
    }

    #[test]
    fn the_record_is_read_through_no_link_and_a_link_in_it_is_a_class_and_no_name() {
        let run = scratch("record");
        let elsewhere = scratch("record-elsewhere");
        // What lies outside the run: a conversation of the person's, which is never read.
        let line = r#"{"type":"task_started","turn_id":"019a0000-0000-7000-8000-0000000000aa"}"#;
        std::fs::write(elsewhere.join("outside-name.jsonl"), format!("{line}\n")).expect("a file");
        let account = account();
        let sessions = Path::new("agent-config/sessions");
        let make = || {
            let _ = std::fs::remove_dir_all(run.join("agent-config"));
            std::fs::create_dir_all(run.join("agent-config/sessions/2026/11")).expect("a record");
            std::fs::write(
                run.join("agent-config/sessions/2026/11/own-name.jsonl"),
                format!("{}\n", line.replace("aa", "bb")),
            )
            .expect("a conversation of the run's own");
        };
        let refused = |why: String| {
            for name in ["outside-name", "own-name", "agent-config", "sessions"] {
                assert!(!why.contains(name), "{why}");
            }
            assert!(!why.contains(run.to_str().expect("text")), "{why}");
            why
        };
        // The record as the agent writes it.
        make();
        assert_eq!(
            turns_recorded(&account, &run, &pinned(&run), sessions).map(|found| found.turns),
            Ok(1)
        );
        // The sessions directory itself is a link into the person's files.
        make();
        std::fs::remove_dir_all(run.join("agent-config/sessions")).expect("removed");
        std::os::unix::fs::symlink(&elsewhere, run.join("agent-config/sessions")).expect("a link");
        let why = refused(
            turns_recorded(&account, &run, &pinned(&run), sessions)
                .expect_err("a linked directory"),
        );
        assert!(why.contains("symbolic link"), "{why}");
        // A directory above it is.
        make();
        std::fs::remove_dir_all(run.join("agent-config")).expect("removed");
        std::fs::create_dir_all(elsewhere.join("sessions")).expect("a directory");
        std::os::unix::fs::symlink(&elsewhere, run.join("agent-config")).expect("a link");
        refused(
            turns_recorded(&account, &run, &pinned(&run), sessions).expect_err("a linked parent"),
        );
        // An entry of the record is a link, to a file and to a directory, and nothing in either is
        // read.
        for target in [elsewhere.join("outside-name.jsonl"), elsewhere.clone()] {
            make();
            std::os::unix::fs::symlink(&target, run.join("agent-config/sessions/2026/linked"))
                .expect("a link");
            let mut read = Vec::new();
            let why = read_record(&run, &pinned(&run), sessions, &mut |place, content| {
                read.push((place.to_vec(), content.to_vec()));
            })
            .expect_err("a link in the record");
            refused(why);
            assert!(
                read.iter()
                    .all(|(_, content)| !String::from_utf8_lossy(content).contains("0000aa")),
                "nothing was read through the link"
            );
        }
        // A file that was a file when the directory was listed and is a link when it is opened.
        make();
        let mut read = Vec::new();
        let why = read_record_by(
            &run,
            &pinned(&run),
            sessions,
            &mut |_, content| read.push(content.to_vec()),
            &mut |moment, name| {
                if moment == Moment::Looked && name == b"own-name.jsonl" {
                    let path = run.join("agent-config/sessions/2026/11/own-name.jsonl");
                    std::fs::remove_file(&path).expect("removed");
                    std::os::unix::fs::symlink(elsewhere.join("outside-name.jsonl"), &path)
                        .expect("a link");
                }
            },
        )
        .expect_err("a file that became a link");
        refused(why);
        assert!(
            read.iter()
                .all(|content| !String::from_utf8_lossy(content).contains("0000aa")),
            "nothing was read through the link a file became"
        );
        // A hard link: a second name for a file of the person's, which has the device and the
        // inode of the file that is read; and a second name of the run's own file. Neither is read.
        for target in [
            elsewhere.join("outside-name.jsonl"),
            run.join("agent-config/sessions/2026/11/own-name.jsonl"),
        ] {
            make();
            std::fs::hard_link(&target, run.join("agent-config/sessions/2026/hard.jsonl"))
                .expect("a hard link");
            let mut read = Vec::new();
            let why = read_record(&run, &pinned(&run), sessions, &mut |_, content| {
                read.push(content.to_vec())
            })
            .expect_err("a file with a second name");
            refused(why);
            assert!(
                read.iter()
                    .all(|content| !String::from_utf8_lossy(content).contains("0000aa")),
                "nothing was read through the second name"
            );
        }
        // A name added between the look and the open is caught on the handle that would be read.
        make();
        let mut read = Vec::new();
        let why = read_record_by(
            &run,
            &pinned(&run),
            sessions,
            &mut |_, content| read.push(content.to_vec()),
            &mut |moment, name| {
                if moment == Moment::Looked && name == b"own-name.jsonl" {
                    std::fs::hard_link(
                        run.join("agent-config/sessions/2026/11/own-name.jsonl"),
                        run.join("agent-config/sessions/2026/11/second-name.jsonl"),
                    )
                    .expect("a second name");
                }
            },
        )
        .expect_err("a name added after the look");
        refused(why);
        // An entry that is neither a file nor a directory is refused without being opened.
        make();
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(run.join("agent-config/sessions/pipe"))
            .status()
            .expect("mkfifo starts");
        assert!(made.success());
        refused(
            turns_recorded(&account, &run, &pinned(&run), sessions)
                .expect_err("a pipe in the record"),
        );
        // A record that is not there is none.
        let _ = std::fs::remove_dir_all(run.join("agent-config"));
        assert_eq!(
            turns_recorded(&account, &run, &pinned(&run), sessions),
            Ok(Recorded::default())
        );
        std::fs::remove_dir_all(&run).expect("clean up");
        std::fs::remove_dir_all(&elsewhere).expect("clean up");
    }

    /// A volume attached below the record (a disk image, a network view) is another file system:
    /// no-follow does not refuse a mount, and the files on it have one name. It is refused before
    /// anything on it is opened, as a class and a count, and a volume attached between the look at a
    /// directory and its opening is refused by the identity check.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_file_system_mounted_below_the_record_is_refused_and_nothing_on_it_is_read() {
        use kr_ipc::testing::volumes::{Volume, not_attachable};
        let run = scratch("record-mounted");
        let images = scratch("record-mounted-images");
        let line = r#"{"type":"task_started","turn_id":"019a0000-0000-7000-8000-0000000000aa"}"#;
        let sessions = Path::new("agent-config/sessions");
        let mount = run.join("agent-config/sessions/2026/11");
        std::fs::create_dir_all(&mount).expect("a record");
        std::fs::write(
            run.join("agent-config/sessions/own-name.jsonl"),
            format!("{}\n", line.replace("aa", "bb")),
        )
        .expect("a conversation of the run's own");
        let refused = |why: &str| {
            assert!(why.contains("another file system"), "{why}");
            for name in [
                "outside-name",
                "own-name",
                "agent-config",
                "sessions",
                "2026",
            ] {
                assert!(!why.contains(name), "{why}");
            }
        };
        // The record's own directory is the mount point: the look at it, on the way to the record,
        // gives another file system.
        let record = run.join("agent-config/sessions");
        let volume = Volume::attach(&record, &images, "root").unwrap_or_else(|| not_attachable());
        std::fs::write(record.join("outside-name.jsonl"), format!("{line}\n"))
            .expect("a file of the person's, with one name, on the volume");
        let mut read = Vec::new();
        // The directory is refused before it is opened, not only the entries on it after.
        let not_opened = matches!(
            record_directory(&run, &pinned(&run), sessions),
            Err(Unlooked {
                class: Class::OtherDevice,
                ..
            })
        );
        let said = read_record(&run, &pinned(&run), sessions, &mut |place, content| {
            read.push((place.to_vec(), content.to_vec()));
        });
        volume.detach();
        assert!(
            not_opened,
            "a directory on another file system is not opened"
        );
        refused(&said.expect_err("the record is on a mount"));
        assert!(read.is_empty(), "nothing on the volume was read");
        // A directory below the record is the mount point.
        let volume = Volume::attach(&mount, &images, "record").unwrap_or_else(|| not_attachable());
        std::fs::write(mount.join("outside-name.jsonl"), format!("{line}\n"))
            .expect("a file of the person's, with one name, on the volume");
        let mut read = Vec::new();
        let said = read_record(&run, &pinned(&run), sessions, &mut |place, content| {
            read.push((place.to_vec(), content.to_vec()));
        });
        volume.detach();
        refused(&said.expect_err("a mount below the record"));
        assert!(
            read.iter().all(|(place, content)| {
                !place.ends_with(b"outside-name.jsonl")
                    && !String::from_utf8_lossy(content).contains("0000aa")
            }),
            "nothing on the volume was read"
        );
        // A volume attached after the directory was looked at and before it was opened.
        let mut attached = None;
        let mut read = Vec::new();
        let said = read_record_by(
            &run,
            &pinned(&run),
            sessions,
            &mut |_, content| read.push(content.to_vec()),
            &mut |moment, name| {
                if moment == Moment::Looked && name == b"11" {
                    let volume =
                        Volume::attach(&mount, &images, "race").unwrap_or_else(|| not_attachable());
                    std::fs::write(mount.join("outside-name.jsonl"), format!("{line}\n"))
                        .expect("a file on the volume");
                    attached = Some(volume);
                }
            },
        );
        attached
            .expect("the volume was attached at the moment")
            .detach();
        let why = said.expect_err("a mount made after the look");
        assert!(!why.contains("outside-name"), "{why}");
        assert!(
            read.iter()
                .all(|content| !String::from_utf8_lossy(content).contains("0000aa")),
            "nothing on the volume was read"
        );
        std::fs::remove_dir_all(&run).expect("clean up");
        std::fs::remove_dir_all(&images).expect("clean up");
    }

    #[test]
    fn a_turn_name_form_is_made_of_six_fixed_marks_and_no_character_of_the_name_survives() {
        assert_eq!(form_of("Ab-9_x"), "Aa-9_a");
        // A path, an email, other scripts, other digits, punctuation, spaces and controls are all
        // the one mark for any other character.
        assert_eq!(form_of("/\u{79d8}\u{5bc6}/\u{6587}\u{4ef6}"), "??????");
        assert_eq!(form_of("a.b@c.d"), "a?a?a?a");
        assert_eq!(form_of("\u{663}\u{e4}\u{df} \t\u{0}"), "??????");
        assert_eq!(form_of(&"x".repeat(100)).len(), 40);
        // In the record: a name that is a path keeps nothing of it.
        let root = scratch("forms");
        let line = r#"{"type":"task_started","turn_id":"/\u79d8\u5bc6/file-1"}"#;
        std::fs::write(root.join("a.jsonl"), format!("{line}\n")).expect("a record");
        let found =
            turns_recorded(&account(), &root, &pinned(&root), Path::new("")).expect("a count");
        assert_eq!(found.forms, vec!["????aaaa-9".to_owned()]);
        std::fs::remove_dir_all(&root).expect("clean up");
    }

    #[test]
    fn a_change_of_the_persons_files_since_the_start_stops_the_charge_and_names_nothing() {
        let home = scratch("before-charge");
        let tree = home.join(".agent");
        std::fs::create_dir_all(tree.join("sessions")).expect("directories");
        std::fs::write(tree.join("sessions/rollout-name.jsonl"), b"x").expect("a file");
        let guard = MetaGuard::take(&home, &[".agent"]);
        assert_eq!(unchanged_before_the_charge(&guard), Ok(()));
        // A write by some other process during the setup, which no listing of processes saw.
        std::fs::write(tree.join("sessions/another-name.jsonl"), b"y").expect("a new file");
        let why = unchanged_before_the_charge(&guard).expect_err("a change stops the charge");
        assert!(
            why.starts_with("guarded_file_changed:") && why.contains("entries"),
            "{why}"
        );
        for name in ["rollout-name", "another-name", "sessions"] {
            assert!(!why.contains(name), "{why}");
        }
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_case_that_passed_with_a_charged_turn_stops_when_the_record_holds_no_turn() {
        let found = |turns, files| {
            Ok(Recorded {
                turns,
                files,
                ..Recorded::default()
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
    fn a_probe_whose_output_cannot_be_collected_is_ended_with_its_helpers() {
        use std::io::Read as _;
        let mut command = std::process::Command::new("/bin/sh");
        // The leader waits, and a helper it started holds the group too; the helper's number is
        // the first line of the output.
        command
            .arg("-c")
            .arg("/bin/sleep 300 & echo $!; /bin/sleep 300");
        let mut helper = None;
        let why = grouped_output_by(
            command,
            std::time::Duration::from_secs(60),
            &mut |stream, mut pipe| {
                if stream == "stdout" {
                    // Read the helper's number, then fail as a system that cannot make a thread.
                    let mut number = String::new();
                    let mut byte = [0_u8; 1];
                    while pipe.read(&mut byte).expect("a read") == 1 && byte[0] != b'\n' {
                        number.push(char::from(byte[0]));
                    }
                    helper = Some(number.parse::<i32>().expect("the helper's number"));
                }
                Err(std::io::Error::other("no thread"))
            },
        )
        .expect_err("a probe whose output cannot be collected is refused");
        assert!(why.contains("could not be made"), "{why}");
        let helper = rustix::process::Pid::from_raw(helper.expect("the helper was started"))
            .expect("a number");
        let started = std::time::Instant::now();
        while rustix::process::test_kill_process(helper).is_ok() {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(10),
                "the helper of a probe that failed its own setup still runs"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn no_signal_goes_to_a_number_the_process_has_no_child_for() {
        // `ECHILD` shows no unreaped child of this process holds the number, so it may name
        // another process's group; any other failure leaves the leader unreaped.
        assert!(!leader_may_hold_its_number(rustix::io::Errno::CHILD));
        assert!(leader_may_hold_its_number(rustix::io::Errno::INVAL));
        assert!(leader_may_hold_its_number(rustix::io::Errno::PERM));
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
        let scan = RunScan::of(&root, &RunRules::new(&pinned(&root), Vec::new()), &held);
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
        let (stops, evidence) = RunScan::of(
            &again,
            &RunRules::new(&pinned(&again), Vec::new()),
            &held,
        )
        .finish(&again, "held-test", false);
        // A run whose processes were not shown ended is searched and left where it is.
        let classes: Vec<&str> = stops.iter().map(|(class, _)| *class).collect();
        assert_eq!(
            classes,
            ["run_left_in_place", "key_scan_incomplete"],
            "{stops:?}"
        );
        assert!(again.is_dir(), "the run was left");
        assert_eq!(evidence["run_gone"], json!(false));
        std::fs::remove_dir_all(&again).expect("clean up");
    }

    /// A path below the run is looked at by a walk from the pin that follows no link at any
    /// component: a link at the working directory, the home or the configuration directory is a
    /// class and what it names is not looked at; a link at the last name is an entry; a path outside
    /// the run is looked at as before.
    #[test]
    fn a_path_below_the_run_is_looked_at_with_no_link_followed_at_any_component() {
        let base = scratch("absent-below");
        let root = base.join("run");
        for name in ["w", "h", "agent-config"] {
            std::fs::create_dir_all(root.join(name)).expect("a directory of the run");
        }
        let outside = base.join("outside");
        std::fs::create_dir_all(&outside).expect("a directory outside");
        std::fs::write(outside.join("AGENTS.md"), b"the person's").expect("a file outside");
        let pin = pinned(&root);
        assert!(
            absent_below(&root, &pin, &root.join("w/AGENTS.md")).expect("a look"),
            "nothing is there"
        );
        std::fs::write(root.join("h/AGENTS.md"), b"x").expect("a file in the run");
        assert!(!absent_below(&root, &pin, &root.join("h/AGENTS.md")).expect("a look"));
        for name in ["w", "h", "agent-config"] {
            std::fs::remove_dir_all(root.join(name)).expect("the directory goes");
            std::os::unix::fs::symlink(&outside, root.join(name)).expect("a link at the name");
            let said = absent_below(&root, &pin, &root.join(name).join("AGENTS.md"))
                .expect_err("a link on the way is not looked through");
            assert!(said.contains("symbolic link"), "{name}: {said}");
        }
        std::os::unix::fs::symlink(base.join("nowhere"), root.join("last"))
            .expect("a link that leads nowhere");
        assert!(
            !absent_below(&root, &pin, &root.join("last")).expect("a look"),
            "a link at the last name is an entry"
        );
        assert!(absent_below(&root, &pin, &base.join("not-there")).expect("a look"));
        assert!(!absent_below(&root, &pin, &outside.join("AGENTS.md")).expect("a look"));
        std::fs::remove_dir_all(&base).expect("clean up");
    }

    /// A run's path that is a link which leads nowhere is not "gone": the removal left it, and the
    /// answer to whether the run is gone looks at no link's target. The check of an absent name is
    /// the same: a link there is present, a name that is not there is absent, and an answer that is
    /// neither is an error.
    #[test]
    fn a_link_that_leads_nowhere_is_present_and_an_unlooked_at_name_is_no_absence() {
        let base = scratch("absent");
        let link = base.join("run");
        std::os::unix::fs::symlink(base.join("nowhere"), &link).expect("a link that leads nowhere");
        assert!(!is_absent(&link).expect("a look"), "a link is an entry");
        assert!(is_absent(&base.join("not-there")).expect("a look"));
        std::fs::write(base.join("file"), b"x").expect("a file");
        assert!(!is_absent(&base.join("file")).expect("a look"));
        assert!(
            is_absent(&base.join("file/below")).is_err(),
            "a name below a file is not shown absent, it is not looked at"
        );
        // The run's path is such a link: the scan refuses it, the removal leaves it, and the
        // evidence does not call the run gone.
        let (stops, evidence) = RunScan::of(
            &link,
            &RunRules::new(&pinned(&base), Vec::new()),
            &HeldKeys {
                key: Some(("LOGIN".to_owned(), "login-value-0123456789".to_owned())),
                others: Vec::new(),
            },
        )
        .finish(&link, "held-test", true);
        assert_eq!(evidence["run_gone"], json!(false), "{evidence}");
        assert!(
            stops
                .iter()
                .any(|(class, _)| *class == "key_scan_incomplete"),
            "{stops:?}"
        );
        std::fs::remove_dir_all(&base).expect("clean up");
    }

    /// A directory that is not the one the run made, put at the run's path, is not read, scanned or
    /// removed, and the run's own directory is known by its identity, not by its path.
    #[test]
    fn a_directory_that_is_not_the_one_the_run_made_is_not_read_scanned_or_removed() {
        use kr_e2e_m1b::run::{Left, remove_run_directory};
        let run = scratch("pinned");
        let sessions = Path::new("agent-config/sessions");
        let line = r#"{"type":"task_started","turn_id":"019a0000-0000-7000-8000-0000000000aa"}"#;
        std::fs::create_dir_all(run.join(sessions)).expect("a record");
        std::fs::write(run.join(sessions).join("own.jsonl"), format!("{line}\n")).expect("a file");
        let pin = pinned(&run);
        let rules = RunRules::new(&pin, Vec::new());
        // The run's directory is renamed away, and another directory that holds a record of the
        // person's is put at its path.
        let away = run.with_file_name(format!(
            "{}-away",
            run.file_name().expect("a name").to_string_lossy()
        ));
        std::fs::rename(&run, &away).expect("renamed away");
        std::fs::create_dir_all(run.join(sessions)).expect("another record");
        std::fs::write(run.join(sessions).join("theirs.jsonl"), format!("{line}\n"))
            .expect("a file");
        let mut read = Vec::new();
        let why = read_record(&run, &pin, sessions, &mut |_, content| {
            read.push(content.to_vec())
        })
        .expect_err("another directory at the run's path");
        assert!(why.contains("not the directory the run made"), "{why}");
        assert!(
            !why.contains("theirs") && !why.contains("agent-config"),
            "{why}"
        );
        assert!(read.is_empty(), "nothing was read");
        let scan = run_files_holding(&run, &rules, b"019a0000-0000-7000-8000-0000000000aa");
        assert!(
            scan.root_changed && !scan.complete() && scan.held_by.is_empty(),
            "{scan:?}"
        );
        assert_eq!(
            remove_run_directory(&run, &pin),
            Removal::Left(Left::RootChanged)
        );
        assert!(
            run.join(sessions).join("theirs.jsonl").exists(),
            "nothing was removed"
        );
        // The directory the run made, renamed away, is the right directory at another place: it is
        // not emptied either, since what is beneath the run's own place is the run's.
        assert_eq!(
            remove_run_directory(&away, &pin),
            Removal::Left(kr_e2e_m1b::run::Left::MovedOut)
        );
        assert!(away.join(sessions).join("own.jsonl").exists());
        std::fs::remove_dir_all(&away).expect("clean up");
        std::fs::remove_dir_all(&run).expect("clean up");
    }

    /// A directory the walk holds open that is moved out of the run, and a file moved into it, are
    /// not read.
    #[test]
    fn a_directory_moved_out_of_the_run_during_the_walk_and_a_file_moved_into_it_are_not_read() {
        let run = scratch("moved");
        let elsewhere = scratch("moved-elsewhere");
        let sessions = Path::new("agent-config/sessions");
        let line = r#"{"type":"task_started","turn_id":"019a0000-0000-7000-8000-0000000000aa"}"#;
        std::fs::create_dir_all(run.join("agent-config/sessions/2026/11")).expect("a record");
        std::fs::write(run.join("agent-config/sessions/2026/11/own.jsonl"), b"x\n")
            .expect("a file");
        std::fs::write(elsewhere.join("theirs.jsonl"), format!("{line}\n"))
            .expect("a file of the person's");
        let mut read = Vec::new();
        let mut moved = false;
        let why = read_record_by(
            &run,
            &pinned(&run),
            sessions,
            &mut |_, content| read.push(content.to_vec()),
            &mut |moment, name| {
                // The directory `11` is open and its entry `own.jsonl` is listed: the directory is
                // moved out of the run and the person's file is put in the entry's place.
                if moment == Moment::Listed && name == b"own.jsonl" && !moved {
                    moved = true;
                    std::fs::rename(
                        run.join("agent-config/sessions/2026/11"),
                        elsewhere.join("11"),
                    )
                    .expect("moved out");
                    std::fs::rename(
                        elsewhere.join("theirs.jsonl"),
                        elsewhere.join("11/own.jsonl"),
                    )
                    .expect("a file moved in");
                }
            },
        )
        .expect_err("a directory moved out of the run");
        assert!(moved && why.contains("no longer beneath"), "{why}");
        assert!(read.is_empty(), "nothing was read");
        // A directory above the one being opened is moved out of the run: the directories below it
        // are no longer the run's either.
        std::fs::create_dir_all(run.join("agent-config/sessions/2026/11")).expect("a record");
        std::fs::write(run.join("agent-config/sessions/2026/11/own.jsonl"), b"x\n")
            .expect("a file");
        let mut read = Vec::new();
        let mut moved = false;
        let mut listed_inside = false;
        let why = read_record_by(
            &run,
            &pinned(&run),
            sessions,
            &mut |_, content| read.push(content.to_vec()),
            &mut |moment, name| {
                listed_inside |= moment == Moment::Listed && name == b"own.jsonl";
                if moment == Moment::Listed && name == b"11" && !moved {
                    moved = true;
                    std::fs::rename(
                        run.join("agent-config/sessions/2026"),
                        elsewhere.join("2026"),
                    )
                    .expect("moved out");
                }
            },
        )
        .expect_err("a directory moved out of the run");
        assert!(moved && why.contains("no longer beneath"), "{why}");
        assert!(read.is_empty(), "nothing was read");
        assert!(
            !listed_inside,
            "the directory moved out was not even listed"
        );
        std::fs::remove_dir_all(&run).expect("clean up");
        std::fs::remove_dir_all(&elsewhere).expect("clean up");
    }

    /// A volume mounted below the run, or on its root, is not entered or removed by the removal of
    /// the run, which then leaves the whole directory where it is; the search's own end does the
    /// same, and says so.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_removal_of_a_run_enters_no_volume_mounted_in_it_and_leaves_the_run() {
        use kr_e2e_m1b::run::{Left, remove_run_directory};
        use kr_ipc::testing::volumes::{Volume, not_attachable};
        let images = scratch("removal-images");
        let key = "login-value-0123456789";
        let made = || {
            let run = scratch("removal");
            std::fs::create_dir_all(run.join("a/mounted")).expect("a run");
            for number in 0..12 {
                std::fs::write(run.join(format!("a/own-{number}")), b"the run's own file")
                    .expect("a file");
            }
            run
        };
        let own_files =
            |run: &Path| (0..12).all(|number| run.join(format!("a/own-{number}")).exists());
        // Below the run, by the removal itself.
        let run = made();
        let pin = pinned(&run);
        let volume = Volume::attach(&run.join("a/mounted"), &images, "below")
            .unwrap_or_else(|| not_attachable());
        std::fs::write(run.join("a/mounted/theirs"), b"a file of the person's")
            .expect("a file on the volume");
        let before = std::fs::read_dir(run.join("a/mounted"))
            .expect("the volume")
            .count();
        let removal = remove_run_directory(&run, &pin);
        let after = std::fs::read_dir(run.join("a/mounted"))
            .expect("the volume")
            .count();
        let theirs = run.join("a/mounted/theirs").exists();
        let own = own_files(&run);
        volume.detach();
        assert_eq!(removal, Removal::Left(Left::AnotherFileSystem));
        assert!(
            theirs && before == after,
            "every file on the volume is still there"
        );
        assert!(own, "the run was left whole");
        // Below the run, by the end of the search: the search meets the volume, and the run stays.
        let volume = Volume::attach(&run.join("a/mounted"), &images, "finish")
            .unwrap_or_else(|| not_attachable());
        std::fs::write(run.join("a/mounted/theirs"), b"a file of the person's")
            .expect("a file on the volume");
        let held = HeldKeys {
            key: Some(("LOGIN".to_owned(), key.to_owned())),
            others: Vec::new(),
        };
        let scan = RunScan::of(&run, &RunRules::new(&pin, Vec::new()), &held);
        let (stops, evidence) = scan.finish(&run, "held-test", true);
        let theirs = run.join("a/mounted/theirs").exists();
        volume.detach();
        assert!(theirs, "the file on the volume is still there");
        assert_eq!(evidence["run_gone"], json!(false));
        assert!(evidence["run_left"].is_string(), "{evidence}");
        assert!(
            stops.iter().any(|(class, _)| *class == "run_left_in_place"),
            "{stops:?}"
        );
        // With the volume gone, the run goes.
        assert_eq!(remove_run_directory(&run, &pin), Removal::Removed);
        // On the run's root: a volume put at its path is not the directory the run made.
        let run = made();
        let pin = pinned(&run);
        let volume = Volume::attach(&run, &images, "root").unwrap_or_else(|| not_attachable());
        std::fs::write(run.join("theirs"), b"a file of the person's")
            .expect("a file on the volume");
        let removal = remove_run_directory(&run, &pin);
        let theirs = run.join("theirs").exists();
        volume.detach();
        assert_eq!(removal, Removal::Left(Left::RootChanged));
        assert!(theirs, "the file on the volume is still there");
        std::fs::remove_dir_all(&run).expect("clean up");
        std::fs::remove_dir_all(&images).expect("clean up");
    }
}
