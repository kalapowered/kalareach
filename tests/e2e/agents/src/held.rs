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
//! - the guard over the person's own agent files, by metadata alone, as each entry's lists call for
//!   it ([`PersonPlan`]): a whole tree ([`MetaGuard`]) or the entry's named files ([`FileGuard`]);
//! - the count of the turns the agent's own record holds ([`turns_recorded`]), against the turns
//!   charged to the ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use kr_e2e_m1b::run::{Removal, Run, remove_run_directory};
use serde_json::{Value, json};

use crate::account::{
    self, KeyScan, RunRules, ScanBytes, now_ms, record_key_scan, run_files_holding_any_sharing,
    run_files_holding_sharing,
};
use crate::build::{Account, NEVER_ALLOWED_BELOW_CONFIG, pattern_reaches, same_name};
use crate::{confine, keys};

/// How a part says it could not show that the agent loads none of the person's own servers. A
/// part that says so stops its agent before it starts.
pub const ISOLATION_UNPROVEN: &str =
    "the agent's isolation from the person's own servers is not established:";

/// The directory of a run that holds the agent's configuration, where the build list gives it one
/// of the run's own.
pub const CONFIG_DIRECTORY: &str = "agent-config";

/// The run's directory for the configuration of a newer build, which has no provider and no login:
/// the second configuration directory a case that upgrades prepares.
pub const NEWER_CONFIG_DIRECTORY: &str = "agent-config-newer";

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
        Self::searched(who, key)
    }

    /// The keys of a case that runs with no login: the descriptor of the login's value is neither
    /// asked for nor read, so a run given none starts, and the values of the other keys the
    /// harness's shell holds are read and searched for as for any case.
    ///
    /// # Panics
    ///
    /// Panics as [`HeldKeys::read`] does for the other keys.
    #[must_use]
    pub fn read_without_login(who: &str) -> Self {
        Self::searched(who, None)
    }

    /// The keys with the login's own `key`, where there is one: the other keys are read, every
    /// panic of the process goes through the held-key rule from here, and a value that cannot be
    /// searched for is refused.
    fn searched(who: &str, key: Option<(String, String)>) -> Self {
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
/// Panics when the system cannot say the account name, and where [`absent_paths_in`] panics.
#[must_use]
pub fn absent_paths(
    account: &Account,
    run: &Run,
    home: &Path,
    person: &Path,
    resolved_work: &Path,
    which: Absent,
) -> Vec<PathBuf> {
    absent_paths_in(
        account,
        run,
        CONFIG_DIRECTORY,
        home,
        person,
        resolved_work,
        which,
    )
}

/// [`absent_paths`] for the configuration directory `config_directory` of the run, which
/// `{config}` stands for.
///
/// # Panics
///
/// Panics when the system cannot say the account name, and where [`absent_paths_under`] panics.
#[must_use]
pub fn absent_paths_in(
    account: &Account,
    run: &Run,
    config_directory: &str,
    home: &Path,
    person: &Path,
    resolved_work: &Path,
    which: Absent,
) -> Vec<PathBuf> {
    absent_paths_under(
        account,
        &run.root().join(config_directory),
        &run.work(),
        home,
        person,
        resolved_work,
        which,
    )
}

/// [`absent_paths_in`] for the configuration directory `config` and the working directory `work`
/// of a run. Each path is expanded, and the names of the expanded path are compared with the names
/// of `config`, each pair by [`same_name`]. A path that names the directory or a path below it must
/// be spelled `{config}/` and a plain rest (names only, no placeholder), and any other spelling
/// stops the run, whatever the allowed files are. A path spelled so is held to the entry's allowed
/// files too, and the run stops where an allowed file names it or a file below it.
///
/// For an entry that `read_build` accepted, whose names are printable ASCII, no spelling of a path
/// below `config` escapes this on a volume that treats two ASCII names as one only where they
/// differ in letter case (APFS and the usual Linux file systems). That rests on three facts of the
/// harness. Every placeholder that names a place in the run expands from the run's one root path,
/// as its handle gives it (`Run::root`), so the names above `config` are the same in `config` and
/// in the expanded path. The run's tree is on one volume: the run's directory, the absence check
/// and the end compare refuse another file system. The absence check ([`absent_below`]) refuses a
/// link and a `..` part below the root, so the path it looks at is the path the system opens.
///
/// What this does not claim: a volume with short names (such as FAT); a link into the run that
/// another process makes while the run is live; absence through a whole run, since the absence check
/// runs before the first start and after the probes and the end compare does not repeat it. It
/// also refuses two names that a case-sensitive volume holds apart and that differ in letter case
/// only, which costs an entry one spelling. Whether a file is there is not decided here: the
/// absence check asks the file system.
///
/// # Panics
///
/// Panics when the system cannot say the account name; when an allowed file of the entry does not
/// begin with `{config}/`; when a path names the configuration directory, or a path below it, in a
/// spelling other than `{config}/` and a plain rest; and when an allowed file names such a path or
/// a file below it.
#[must_use]
pub fn absent_paths_under(
    account: &Account,
    config: &Path,
    work: &Path,
    home: &Path,
    person: &Path,
    resolved_work: &Path,
    which: Absent,
) -> Vec<PathBuf> {
    // The entry was checked where it was read; this holds the expansion to the same allowed files a
    // second way, so it takes them as they stand and checks no spelling of them again.
    let allowed: Vec<String> = account
        .allowed
        .iter()
        .map(|pattern| {
            pattern
                .strip_prefix("{config}/")
                .unwrap_or_else(|| {
                    panic!("{ISOLATION_UNPROVEN} the allowed file {pattern:?} is not below `{{config}}`")
                })
                .to_owned()
        })
        .collect();
    let home = home.display().to_string();
    let config_text = config.display().to_string();
    let work_text = work.display().to_string();
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
        for start in [work.to_path_buf(), resolved_work.to_path_buf()] {
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
    let mut paths: Vec<PathBuf> = account
        .absent
        .iter()
        .filter(|path| which != Absent::Ancestors || path.contains("{ancestors}"))
        .flat_map(|path| {
            let expand = |text: &str| {
                let expanded = PathBuf::from(
                    text.replace("{config}", &config_text)
                        .replace("{work}", &work_text)
                        .replace("{home}", &home)
                        .replace("{person}", &person)
                        .replace("{user}", &user),
                );
                held_to_the_entry(config, &allowed, path, &expanded);
                expanded
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
        .collect();
    if which == Absent::All {
        // The agent reads command rules from a `rules` directory of its configuration directory
        // (the vendor documents it, and the agent's own help for checking a command against rule
        // files shows the feature): a rule there lets a command run with no prompt, so the
        // directory is known absent whatever the entry lists.
        paths.push(config.join("rules"));
    }
    paths
}

/// The names `path` is made of, as text.
fn names_of(path: &Path) -> Vec<String> {
    path.components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect()
}

/// Stops the run where `expanded`, the absent path `template` with its placeholders filled in,
/// names the configuration directory `config` or a path below it, each name compared with the
/// directory's own by [`same_name`], unless the template is `{config}/` and a plain rest, and where
/// one of the entry's allowed files (`allowed`, as [`Account::allowed_below_config`] gives them)
/// names such a path or a file below it.
fn held_to_the_entry(config: &Path, allowed: &[String], template: &str, expanded: &Path) {
    let directory_names = names_of(config);
    let path_names = names_of(expanded);
    let at_or_below = path_names.len() >= directory_names.len()
        && directory_names
            .iter()
            .zip(&path_names)
            .all(|(own, other)| same_name(own, other));
    if !at_or_below {
        return;
    }
    let plain = template.strip_prefix("{config}/").filter(|rest| {
        rest.split('/')
            .all(|part| !matches!(part, "" | "." | "..") && !part.contains(['{', '}']))
    });
    let Some(rest) = plain else {
        panic!(
            "{ISOLATION_UNPROVEN} the absent path {template:?} names the configuration directory \
             or a path below it, and an entry spells such a path `{{config}}/` and its names"
        );
    };
    let held: Vec<&str> = rest.split('/').collect();
    for pattern in allowed {
        let names: Vec<&str> = pattern.split('/').collect();
        assert!(
            !pattern_reaches(&names, &held),
            "{ISOLATION_UNPROVEN} the absent path {template:?} names {rest:?} below the \
             configuration directory, which the entry's allowed file {:?} names",
            format!("{{config}}/{pattern}")
        );
    }
}

/// Whether nothing is at `path`, looked at with no link followed at its last component: "not found"
/// is absent, any entry (a link that leads nowhere included) is present, and any other answer is an
/// error, since an absence the system did not show is not one.
///
/// # Errors
///
/// Returns what the system said when it said anything but "not found".
fn is_absent(path: &Path) -> std::io::Result<bool> {
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
fn absent_below(root: &Path, pin: &kr_e2e_m1b::run::RootPin, path: &Path) -> Result<bool, String> {
    match path.strip_prefix(root) {
        Ok(relative) if !relative.as_os_str().is_empty() => {
            kr_e2e_m1b::run::entry_below(root, pin, relative)
                .map(|present| !present)
                .map_err(|refusal| refusal.to_string())
        }
        _ => is_absent(path).map_err(|error| error.to_string()),
    }
}

/// Whether nothing is at any path of `absent`, the entry's list as [`absent_paths`] gives it, for
/// the run whose directory is `root` and whose pin is `pin`: each path is looked at by
/// [`absent_below`]. Nothing is excused: an entry at one of the paths, a link included, is refused,
/// whatever the entry's allowed files name.
///
/// # Errors
///
/// Returns the first path that exists, or that could not be shown absent, with what was found.
pub fn shown_absent(
    root: &Path,
    pin: &kr_e2e_m1b::run::RootPin,
    absent: &[PathBuf],
) -> Result<(), String> {
    shown_absent_by(absent, |path| absent_below(root, pin, path))
}

/// [`shown_absent`] with the look of each path given: the free [`absent_below`], or the guard's.
fn shown_absent_by(
    absent: &[PathBuf],
    look: impl Fn(&Path) -> Result<bool, String>,
) -> Result<(), String> {
    for path in absent {
        match look(path) {
            Ok(true) => {}
            Ok(false) => {
                return Err(format!(
                    "{} exists, which would load the person's own settings, hooks or servers into \
                     the agent, or which it would remove",
                    path.display()
                ));
            }
            Err(error) => {
                return Err(format!(
                    "{} cannot be shown absent: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Whether `relative`, the path of a file below the configuration directory, is one the allowed
/// patterns name: each part is a name (one that differs only in letter case is the same name) or a
/// lone `*`, which is any one name, and a last `**` is every file below its directory. The
/// patterns are [`Account::allowed_below_config`]'s.
#[must_use]
pub fn is_allowed(patterns: &[String], relative: &str) -> bool {
    let names: Vec<&str> = relative.split('/').collect();
    patterns.iter().any(|pattern| {
        let parts: Vec<&str> = pattern.split('/').collect();
        let mut taken = 0;
        for (index, part) in parts.iter().enumerate() {
            if *part == "**" && index + 1 == parts.len() {
                return names.len() > taken;
            }
            match names.get(taken) {
                Some(name) if *part == "*" || same_name(part, name) => taken += 1,
                _ => return false,
            }
        }
        taken == names.len()
    })
}

/// Compares what stands below the run's configuration directory `config`, as the run placed it
/// ([`kr_e2e_m1b::run::PlacedDirectory::record`], called before the agent starts, below the run's
/// directory `root`, which `pin` names), at the end of a part with what the harness and the agent
/// may have put there. The directory is reached again through the pin and must be the one that was
/// recorded, by its device and inode, and it is listed through handles, so a directory that was
/// made a link, or that another directory has replaced, is refused and nothing is read through it.
/// Each of the recipe's files (`recipe_files`, each by its path below `config` and the bytes the
/// recipe wrote) and `settings.json` is looked at by its own path, whatever names the directory
/// holds: a regular file with one name that holds those bytes, or, for `settings.json`, exactly the
/// one key the recipe sets (`settings_key`, in `enabledPlugins`, set to `true`); one that is not
/// there is refused. Every other name is looked at as the directory lists it: a link, a regular
/// file with more than one name, and an entry that is neither a regular file, a directory nor a
/// link, are refused at every name, an allowed one included, and a name on another file system
/// than the configuration directory is refused and not entered; the names `settings.json`,
/// `settings.local.json` and `rules`, in any letter case, are looked at before any directory is
/// entered, so a directory with one of these names is refused and its contents are not compared,
/// and `settings.local.json` and `rules` are refused whatever they are; any other file must be one
/// that the entry's allowed files name.
///
/// The compare holds only while no process of the run changes the tree: `settings.json` and the
/// recipe's files are reached again from the pin, not through the handle that lists the directory.
///
/// # Errors
///
/// Returns why the entry's allowed files are not ones the harness reads, or why the directory
/// cannot be compared, or a line for each file that is none of these, in the order of their names.
pub fn end_compare(
    root: &Path,
    pin: &kr_e2e_m1b::run::RootPin,
    config: &kr_e2e_m1b::run::PlacedDirectory,
    recipe_files: &[(&str, &[u8])],
    settings_key: &str,
    account: &Account,
) -> Result<(), String> {
    let allowed = account.allowed_below_config()?;
    let directory = config
        .open(root, pin)
        .map_err(|refusal| format!("the configuration directory cannot be compared: {refusal}"))?;
    let device = rustix::fs::fstat(&directory)
        .map_err(|error| format!("the configuration directory cannot be compared: {error}"))?
        .st_dev;
    let mut compare = EndCompare {
        root,
        pin,
        config: config.relative(),
        recipe_files,
        settings_key,
        allowed: &allowed,
        refused: Vec::new(),
        seen: 0,
        device,
    };
    compare.each_file_of_the_recipe();
    compare.walk(&directory, "", 0);
    compare.refused.sort();
    if compare.refused.is_empty() {
        Ok(())
    } else {
        Err(compare.refused.join("; "))
    }
}

/// The state of one [`end_compare`]: what it compares against, and the lines it has to say.
struct EndCompare<'a> {
    root: &'a Path,
    pin: &'a kr_e2e_m1b::run::RootPin,
    config: &'a Path,
    recipe_files: &'a [(&'a str, &'a [u8])],
    settings_key: &'a str,
    allowed: &'a [String],
    refused: Vec<String>,
    seen: usize,
    /// The file system the configuration directory is on.
    device: rustix::fs::Dev,
}

impl EndCompare<'_> {
    /// Looks at `settings.json` and at each of the recipe's files by its own path.
    fn each_file_of_the_recipe(&mut self) {
        self.settings("settings.json");
        for (path, wrote) in self.recipe_files {
            self.recipe_file(path, wrote);
        }
    }

    /// Looks at each entry of `directory`, which `prefix` names below the configuration directory,
    /// and at each directory below it, through handles. `settings.json` and the recipe's files, as
    /// they are written, are looked at by `each_file_of_the_recipe` and not here.
    fn walk(&mut self, directory: &std::os::fd::OwnedFd, prefix: &str, depth: usize) {
        use rustix::fs::{AtFlags, FileType};
        let place = if prefix.is_empty() {
            "the configuration directory"
        } else {
            prefix
        };
        if depth > DEEPEST {
            self.refused
                .push(format!("{place} is deeper than {DEEPEST} levels"));
            return;
        }
        let names = match names_in(directory) {
            Ok(names) => names,
            Err(error) => {
                self.refused
                    .push(format!("{place} cannot be listed: {error}"));
                return;
            }
        };
        for name in names {
            let text = name.to_string_lossy().into_owned();
            let relative = if prefix.is_empty() {
                text
            } else {
                format!("{prefix}/{text}")
            };
            let looked =
                match rustix::fs::statat(directory, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(looked) => looked,
                    Err(error) => {
                        self.refused
                            .push(format!("{relative} cannot be looked at: {error}"));
                        continue;
                    }
                };
            self.seen += 1;
            if relative == "settings.json"
                || self.recipe_files.iter().any(|(path, _)| *path == relative)
            {
                continue;
            }
            let kind = FileType::from_raw_mode(looked.st_mode);
            if same_name(&relative, "settings.json") {
                self.settings(&relative);
            } else if NEVER_ALLOWED_BELOW_CONFIG
                .iter()
                .any(|reserved| same_name(&relative, reserved))
            {
                self.refused.push(format!(
                    "{relative} is a name the agent reads its settings or rules from, which no \
                     entry may allow"
                ));
            } else if looked.st_dev != self.device {
                self.refused.push(format!(
                    "{relative} is on another file system than the configuration directory, and \
                     nothing there is compared"
                ));
            } else if kind == FileType::Directory {
                match opened_directory(directory, name.as_c_str(), &looked, self.seen) {
                    Ok(child) => self.walk(&child, &relative, depth + 1),
                    Err(unlooked) => self
                        .refused
                        .push(format!("{relative} cannot be listed: {unlooked}")),
                }
            } else if kind == FileType::Symlink {
                self.refused.push(format!(
                    "{relative} is a link, and a link is accepted at no name below the \
                     configuration directory"
                ));
            } else if kind == FileType::RegularFile && looked.st_nlink > 1 {
                self.refused.push(format!(
                    "{relative} is a file with more than one name, and such a file is accepted \
                     at no name below the configuration directory"
                ));
            } else if kind != FileType::RegularFile {
                self.refused.push(format!(
                    "{relative} is neither a regular file, a directory nor a link, and such an \
                     entry is accepted at no name below the configuration directory"
                ));
            } else if !is_allowed(self.allowed, &relative) {
                self.refused.push(format!(
                    "{relative} is not one of the recipe's files, and the entry does not allow it"
                ));
            }
        }
    }

    /// The bytes of the regular file `relative` below the configuration directory, with one name,
    /// read through the pin by [`kr_e2e_m1b::run::open_file_below`]: at most `at_most` of them and
    /// one more where the file is longer.
    fn read(&self, relative: &str, at_most: u64) -> Result<Vec<u8>, String> {
        use std::io::Read as _;
        match kr_e2e_m1b::run::open_file_below(self.root, self.pin, &self.config.join(relative)) {
            Ok(Some(file)) => {
                let mut bytes = Vec::new();
                std::fs::File::from(file)
                    .take(at_most + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                Ok(bytes)
            }
            Ok(None) => Err("it is not there".to_owned()),
            Err(refusal) => Err(refusal.to_string()),
        }
    }

    /// Whether the settings file `relative` (`settings.json` in any letter case) is a regular file
    /// that holds exactly the one key the recipe sets.
    fn settings(&mut self, relative: &str) {
        match self.read(relative, SETTINGS_AT_MOST) {
            Err(why) => self
                .refused
                .push(format!("{relative} is not a file of the run's own: {why}")),
            Ok(bytes) => {
                let held: Option<Value> = serde_json::from_slice(&bytes).ok();
                let key = self.settings_key;
                if held != Some(json!({ "enabledPlugins": { key: true } })) {
                    self.refused.push(format!(
                        "{relative} does not hold exactly the recipe's key {}",
                        self.settings_key
                    ));
                }
            }
        }
    }

    /// Whether the recipe's file `relative` is a regular file that holds the bytes `wrote`.
    fn recipe_file(&mut self, relative: &str, wrote: &[u8]) {
        match self.read(relative, wrote.len() as u64) {
            Err(why) => self
                .refused
                .push(format!("{relative} is not a file of the run's own: {why}")),
            Ok(bytes) if bytes != wrote => self.refused.push(format!(
                "{relative} does not hold the bytes the recipe wrote"
            )),
            Ok(_) => {}
        }
    }
}

/// The most bytes of `settings.json` that the end compare reads.
const SETTINGS_AT_MOST: u64 = 1 << 20;

/// The names in `directory`, as its handle lists them, in order: no entry is looked at.
fn names_in(directory: &std::os::fd::OwnedFd) -> Result<Vec<std::ffi::CString>, rustix::io::Errno> {
    let mut names = Vec::new();
    for entry in rustix::fs::Dir::read_from(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if name.to_bytes() != b"." && name.to_bytes() != b".." {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
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
        Self::of_within(root, rules, held, ScanBytes::default())
    }

    /// [`RunScan::of`] with a budget of bytes that the two scans read from together, so that they
    /// are bound together.
    #[must_use]
    fn of_within(root: &Path, rules: &RunRules, held: &HeldKeys, budget: ScanBytes) -> Self {
        let bytes = std::sync::Arc::new(budget);
        let key = held.key.as_ref().map(|(name, value)| {
            (
                name.clone(),
                run_files_holding_sharing(root, rules, value.as_bytes(), &bytes),
            )
        });
        let others = (!held.others.is_empty()).then(|| {
            let values: Vec<&[u8]> = held.others.iter().map(String::as_bytes).collect();
            run_files_holding_any_sharing(root, rules, &values, &bytes)
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
            evidence["held_by_not_listed"] = json!(scan.held_by.not_listed());
            evidence["unread_not_listed"] = json!(scan.unread.not_listed());
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
    /// A file of the agent's record is larger than the audit reads: none of it was read.
    TooLarge,
    /// The agent's record lists more entries than the audit walks.
    TooMany,
    /// The files of the agent's record are more bytes than the audit reads in all: the file that
    /// would pass the bound was not read.
    TooMuch,
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
            Class::TooLarge => write!(
                formatter,
                "a file is larger than the audit reads: what was read of it is discarded, and none of \
                 it is counted or kept (after {seen} entries)"
            ),
            Class::TooMany => write!(
                formatter,
                "the tree lists more entries than the audit walks (after {seen} entries)"
            ),
            Class::TooMuch => write!(
                formatter,
                "the files are more bytes than the audit reads in all (after {seen} entries)"
            ),
        }
    }
}

/// The deepest the walk goes: what lies below is not looked at, and that is a failure.
pub(crate) const DEEPEST: usize = 64;

/// The most bytes of one file of the agent's record that the audit reads: a file above it, by the
/// size its handle reports or by what is read through it, is left unread.
pub(crate) const RECORD_FILE_AT_MOST: u64 = 64 << 20;

/// The most entries of the agent's record that the audit lists, in all, counted when each is
/// listed: the names of one listing are held until its directory is done, so the count bounds what
/// the walk holds. A real record is a few files.
pub(crate) const RECORD_ENTRIES_AT_MOST: usize = 100_000;

/// The most bytes of the agent's record that the audit reads in all. A file whose size would take
/// the total past it is not read; a real record is a few kilobytes, and many files that each fit
/// the per-file bound (clones cost no disk) must not make the audit read for hours.
pub(crate) const RECORD_BYTES_AT_MOST: u64 = 256 << 20;

/// The most distinct turn names the audit keeps in all. Each is kept in two sets, a non-UUID name
/// with its file's place, so the figure alone does not bound what is held ([`RECORD_NAME_BYTES_AT_MOST`]
/// does); a real record names a handful.
pub(crate) const RECORD_NAMES_AT_MOST: usize = 50_000;

/// The most bytes of turn names the audit keeps in all, a non-UUID name counted with its file's
/// place, which is up to sixteen kilobytes in a deep tree: each name is held in two sets, so the
/// sets hold at most twice this.
pub(crate) const RECORD_NAME_BYTES_AT_MOST: usize = 16 << 20;

/// What the audit's walk of the agent's record reads at most. A walk past either is a failure of
/// its own ([`Class::TooLarge`], [`Class::TooMany`]): nothing of the file is read, and the audit says
/// it is incomplete.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// The most bytes of one file.
    pub(crate) file: u64,
    /// The most entries listed, in all.
    pub(crate) entries: usize,
    /// The most bytes read, in all.
    pub(crate) bytes: u64,
    /// The most distinct turn names kept, in all.
    pub(crate) names: usize,
    /// The most bytes of the names kept, in all.
    pub(crate) name_bytes: usize,
}

impl Limits {
    /// What the agent's record is read within.
    pub(crate) const RECORD: Self = Self {
        file: RECORD_FILE_AT_MOST,
        entries: RECORD_ENTRIES_AT_MOST,
        bytes: RECORD_BYTES_AT_MOST,
        names: RECORD_NAMES_AT_MOST,
        name_bytes: RECORD_NAME_BYTES_AT_MOST,
    };
}

/// The start of what is said of a record that is beyond the audit's bounds, which the audit takes
/// for an incomplete count, not for a record that could not be read.
pub const RECORD_BEYOND_THE_BOUNDS: &str = "the agent's record is beyond what the audit reads";

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
/// (`argv[0]`: what `ps` prints as `comm` on macOS, and the first field of the process's command
/// line on Linux, where `comm` is the name of the file it runs) and the path of the file it runs as
/// the system says it, where the system says one.
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

/// The first field of a command line as `/proc/<pid>/cmdline` holds it, its fields ended by a NUL:
/// the name the process's parent gave it. None for a command line with no first field, which is
/// what the system gives for a process that has ended and for a kernel thread.
#[cfg(any(target_os = "linux", test))]
fn first_argument(command_line: &[u8]) -> Option<String> {
    let first = command_line.split(|byte| *byte == 0).next()?;
    (!first.is_empty()).then(|| String::from_utf8_lossy(first).into_owned())
}

/// The name the parent of the process `pid` gave it: `argv[0]`, which `ps` prints as `comm` on
/// macOS and which Linux keeps in the process's command line, where `comm` is the name of the file
/// it runs. The listing's `comm` stays the answer where the command line cannot be read.
#[cfg(target_os = "linux")]
fn name_given_by_parent(pid: u32, comm: String) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .and_then(|command_line| first_argument(&command_line))
        .unwrap_or(comm)
}

/// The name the parent of the process `pid` gave it: what `ps` prints as `comm`.
#[cfg(not(target_os = "linux"))]
fn name_given_by_parent(_pid: u32, comm: String) -> String {
    comm
}

/// The processes of this user that are the agent called `agent` (`codex`) outside the run whose
/// directory is `run_root`, where there is a run, each as its process id and nothing else: found by
/// a listing of the processes and, for each of this user's, the path of the file it runs as the
/// system says it (`proc_pidpath` on macOS), which reads no file under the person's agent
/// directory. A process counts when the file name of that path or of the name its parent gave it
/// (`argv[0]`) is the agent's (`names_the_agent`: `codex`, the release files `codex-<target>`, the
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
            let comm = fields.collect::<Vec<_>>().join(" ");
            // The system's own answers, asked for the processes of this user only.
            let argv0 = if user == me {
                name_given_by_parent(pid, comm)
            } else {
                comm
            };
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
/// other writer, stops the case here, with no turn charged. What is said is the class and the words
/// of [`PersonGuard::compare`]: a path the entry names, counts, and no other name.
///
/// # Errors
///
/// Returns what changed.
pub fn unchanged_before_the_charge(guard: &PersonGuard) -> Result<(), String> {
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
                        format!("~/{relative} cannot be looked at: {why}"),
                    ));
                    json!({ "path": format!("~/{relative}"), "unreadable": true })
                }
            })
            .collect();
        (stops, json!({ "trees": seen }))
    }
}

/// Whether `path` is a plain path relative to the person's home: it has no empty, `.` or `..` part,
/// and does not start with `/`.
fn plain_relative(path: &str) -> bool {
    path.split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Why the path `template` of an entry's absent list is refused for `application`, where it names
/// one of `files`, the entry's guarded and shared files, in the person's home: it starts with
/// `{person}/` or `{ancestors}/` and goes on with a path that is not plain or with one of the
/// files, or it starts with `/` and its last parts are one of the files', where the empty and `.`
/// parts are dropped and each `..` takes away the part before it.
fn absent_path_refusal(application: &str, template: &str, files: &[&String]) -> Option<String> {
    let listed =
        format!("the entry for {application} lists {template:?} as a file that must not exist");
    let reason = |file: &String| {
        format!(
            "{listed}, and it can name ~/{file}, which the entry also guards or shares, so a look \
             at it could be a look at a guarded name"
        )
    };
    if let Some(rest) = template
        .strip_prefix("{person}/")
        .or_else(|| template.strip_prefix("{ancestors}/"))
    {
        if !plain_relative(rest) {
            return Some(format!(
                "{listed}, and the path after its first folder is not a plain path: it has an \
                 empty, `.` or `..` part, so it could name a guarded or shared file by another \
                 spelling"
            ));
        }
        return files
            .iter()
            .copied()
            .find(|file| file.as_str() == rest)
            .map(reason);
    }
    if template.starts_with('/') {
        let mut parts: Vec<&str> = Vec::new();
        for part in template.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                part => parts.push(part),
            }
        }
        return files
            .iter()
            .copied()
            .find(|file| parts.ends_with(&file.split('/').collect::<Vec<_>>()))
            .map(reason);
    }
    None
}

/// How an entry's run guards the person's own agent files, and so whether another process of the
/// agent refuses the run.
///
/// An agent that keeps a directory of the person's own, which a run is held to leave whole (Codex's
/// `.codex`), is guarded by [`MetaGuard`]: it compares the whole tree and cannot tell a write of
/// another process from the run's, so another process of the agent refuses the run. An entry that
/// names guarded files ([`Account::guarded`]) is guarded by [`FileGuard`]: those files, and the
/// shared files ([`Account::shared`]) read once at the end for the run's name, and no others, so
/// another process of the agent, a session of the person's among them, may run beside the run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PersonPlan {
    /// The trees, each a path relative to the person's home, whose every entry is compared.
    Trees(&'static [&'static str]),
    /// The files no process may change, and the files that must not come to name the run.
    Files {
        /// The files no process may change, as paths relative to the person's home.
        guarded: Vec<String>,
        /// The files the person's own sessions also write, as paths relative to the person's home.
        shared: Vec<String>,
    },
}

impl PersonPlan {
    /// The guard of the build list entry for `application`, from the entry's own lists.
    ///
    /// A path of `absent`, the entry's list of files that must not exist, is refused when it names
    /// a guarded or shared file of the person's home. `{person}` is the person's home, and
    /// `{ancestors}` takes in each folder above the run's working directory, the home among them.
    /// After `{person}/` or `{ancestors}/` the path must be a plain relative path and not one of
    /// those files. A path that starts with `/` is refused when its last parts are the parts of one
    /// of those files, with the empty and `.` parts dropped and each `..` taking away the part
    /// before it, whatever comes before those parts: `/etc/x/.claude.json` is refused as well as a
    /// path in a home.
    ///
    /// The check is lexical, and a path can pass it and still name one of those files: a
    /// placeholder after the first part (`{person}/{ancestors}/.claude.json`), a relative path
    /// (a look takes it from the test's working directory), a change of letter case
    /// (`{person}/.Claude.json`) on a volume that ignores case, and a link on the way to a path
    /// outside the run, which the look follows. Inside the run the look refuses a `..` part and a
    /// link on the way, and keeps the refusal. What protects a guarded name from a path of the
    /// list that reaches it is the write of [`PersonGuard::absent_below`], which keeps every look
    /// that does not show the path absent; this check only comes second.
    ///
    /// # Errors
    ///
    /// Returns why the entry has no guard: it names no person tree and no guarded file, and a run
    /// of it would leave the person's files unwatched; or a path of its lists is not a plain path
    /// relative to the person's home, or a file is in both lists, or a path that must be absent
    /// names a guarded or shared file, or names one by a spelling that is not plain.
    pub fn of(
        application: &str,
        guarded: &[String],
        shared: &[String],
        absent: &[String],
    ) -> Result<Self, String> {
        if application == "codex" {
            return Ok(Self::Trees(&[".codex"]));
        }
        if guarded.is_empty() {
            return Err(format!(
                "the entry for {application} names no person tree and no guarded file, so nothing \
                 would guard the person's own agent files and no real run of it starts"
            ));
        }
        if let Some(path) = guarded
            .iter()
            .chain(shared)
            .find(|path| !plain_relative(path))
        {
            return Err(format!(
                "the entry for {application} names the path {path:?}, which is not a plain path \
                 relative to the person's home: it has an empty, `.` or `..` part, or starts with \
                 `/`"
            ));
        }
        if let Some(path) = shared.iter().find(|path| guarded.contains(path)) {
            return Err(format!(
                "the entry for {application} names ~/{path} as both a guarded and a shared file, \
                 so the end read would read a guarded file"
            ));
        }
        let named: Vec<&String> = guarded.iter().chain(shared).collect();
        if let Some(refusal) = absent
            .iter()
            .find_map(|template| absent_path_refusal(application, template, &named))
        {
            return Err(refusal);
        }
        Ok(Self::Files {
            guarded: guarded.to_vec(),
            shared: shared.to_vec(),
        })
    }

    /// The processes of this user that are the agent called `agent` outside the run whose directory
    /// is `run_root`, where there is a run ([`other_agent_processes`]): none, and no listing made,
    /// for an entry guarded by its files, which a process of the agent beside the run cannot
    /// mislead.
    ///
    /// # Errors
    ///
    /// Returns why the listing is not known.
    pub fn other_agents(&self, agent: &str, run_root: Option<&Path>) -> Result<Vec<u32>, String> {
        match self {
            Self::Trees(_) => other_agent_processes(agent, run_root),
            Self::Files { .. } => Ok(Vec::new()),
        }
    }

    /// Takes the guard: the trees as they stand, or the files as `lstat` shows them.
    ///
    /// # Panics
    ///
    /// Panics when a tree or a file cannot be looked at, for any reason other than its not being
    /// there, when a file the guard names is a symbolic link, or when a shared file is one that
    /// the end read refuses by its kind, names, size or identity.
    #[must_use]
    pub fn take(self, home: &Path) -> PersonGuard {
        let watch = match &self {
            Self::Trees(trees) => Watch::Trees(MetaGuard::take(home, trees)),
            Self::Files { guarded, shared } => Watch::Files(FileGuard::take(home, guarded, shared)),
        };
        PersonGuard { plan: self, watch }
    }
}

/// What a taken guard compares.
#[derive(Debug)]
enum Watch {
    Trees(MetaGuard),
    Files(FileGuard),
}

/// The person's own agent files as an entry's [`PersonPlan`] guards them, and the check that none
/// of them changed.
#[derive(Debug)]
pub struct PersonGuard {
    plan: PersonPlan,
    watch: Watch,
}

impl PersonGuard {
    /// [`PersonPlan::other_agents`] of the plan this guard was taken from.
    ///
    /// # Errors
    ///
    /// Returns why the listing is not known.
    pub fn other_agents(&self, agent: &str, run_root: Option<&Path>) -> Result<Vec<u32>, String> {
        self.plan.other_agents(agent, run_root)
    }

    /// Looks at a path of the entry's absent list. Where the entry has guarded files, every look
    /// that does not show the path absent is kept as a failed look: a path found present, whether
    /// a file, a directory or a link, and a look that failed for any reason other than the name's
    /// not being there (for a path in the run a link on the way is such a failure; for another
    /// path the look follows it). The path may reach a guarded name, and the
    /// look keeps no identity of what it found, so every shared read after it is refused. The
    /// caller still stops the case on a path found present. A path shown absent keeps nothing,
    /// and a look never reads a file. This write is what protects a guarded name from a path of
    /// the list that reaches it; the check of [`PersonPlan::of`] is a second line.
    ///
    /// # Errors
    ///
    /// Returns why the absence was not shown.
    pub fn absent_below(
        &self,
        root: &Path,
        pin: &kr_e2e_m1b::run::RootPin,
        path: &Path,
    ) -> Result<bool, String> {
        let looked = absent_below(root, pin, path);
        let shown_absent = looked == Ok(true);
        if let (false, Watch::Files(files)) = (shown_absent, &self.watch) {
            files.looks.lost();
        }
        looked
    }

    /// [`shown_absent`] through the guard: each path is looked at by [`PersonGuard::absent_below`],
    /// so a look that finds a path present, or does not show the absence, stays on the guard's
    /// record and no shared file is read for the rest of the run.
    ///
    /// # Errors
    ///
    /// Returns the first path that exists, or that could not be shown absent, with what was found.
    pub fn shown_absent(
        &self,
        root: &Path,
        pin: &kr_e2e_m1b::run::RootPin,
        absent: &[PathBuf],
    ) -> Result<(), String> {
        shown_absent_by(absent, |path| self.absent_below(root, pin, path))
    }

    /// Looks again by metadata alone and says what stops the driver, with what was seen; never a
    /// value, and no file is read.
    #[must_use]
    pub fn compare(&self) -> (Vec<Stop>, Value) {
        match &self.watch {
            Watch::Trees(guard) => guard.compare(),
            Watch::Files(guard) => guard.compare(&[]),
        }
    }

    /// [`PersonGuard::compare`] at the end of the run, where an entry's shared files are read once
    /// for `needles`, the run's directory name and mark, and nothing of what is read is kept.
    #[must_use]
    pub fn compare_at_the_end(&self, needles: &[&str]) -> (Vec<Stop>, Value) {
        match &self.watch {
            Watch::Trees(guard) => guard.compare(),
            Watch::Files(guard) => guard.compare(needles),
        }
    }
}

/// What `lstat` says of one file, apart from its owner: its kind and permissions, device, inode,
/// size and times.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    mode: u32,
    device: u64,
    inode: u64,
    size: u64,
    changed: (i64, i64),
    modified: (i64, i64),
}

/// One file as `lstat` showed it: its [`Stamp`], and its owner, which is compared on its own, since
/// the digest of a tree has no owner in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    stamp: Stamp,
    owner: u32,
    /// Whether the name is a symbolic link.
    link: bool,
}

/// How `path` stands by `lstat` alone: none where it is not there. No link is followed at its last
/// name and nothing of the file is read, so a file the user cannot read is looked at all the same.
fn seen_by_lstat(path: &Path) -> std::io::Result<Option<Seen>> {
    use std::os::unix::fs::MetadataExt as _;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(Seen {
            stamp: Stamp {
                mode: metadata.mode(),
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.size(),
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                modified: (metadata.mtime(), metadata.mtime_nsec()),
            },
            owner: metadata.uid(),
            link: metadata.file_type().is_symlink(),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// The size above which a shared file is refused: by its metadata when it is looked at, or by the
/// read, which asks for one byte past it, when the file has grown.
const SHARED_LIMIT: u64 = 16 << 20;

/// The longest the end read of a shared file may take: the run stops on one that takes longer.
const SHARED_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Why a shared file was not read to its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unread {
    Link,
    NotAFile,
    Gone,
    ManyNames,
    GuardedFile,
    Unlooked,
    TooLarge,
    TooSlow,
    Failed,
}

impl Unread {
    /// What is said of the file after its path.
    fn said(self) -> String {
        let reason = match self {
            Self::Link => "is a symbolic link and is not read".to_owned(),
            Self::NotAFile => "is not a regular file and is not read".to_owned(),
            Self::Gone => "has no name left and is not read".to_owned(),
            Self::ManyNames => "has more than one name and is not read".to_owned(),
            Self::GuardedFile => "is the same file as a guarded file and is not read".to_owned(),
            Self::Unlooked => "is not read, because a look of a guarded name has failed, has seen \
                               a link or has not answered in time, or a look of a path that \
                               must not exist has found it or has failed, since the run \
                               started, and this file may be the one it names"
                .to_owned(),
            Self::TooLarge => format!("is larger than {SHARED_LIMIT} bytes and is not read"),
            Self::TooSlow => format!("was not read within {} seconds", SHARED_BOUND.as_secs()),
            Self::Failed => "cannot be read after the run".to_owned(),
        };
        format!("{reason}, so it is not known whether it holds the run's directory name or mark")
    }
}

/// What the looks of the guarded names have shown since the guard was taken.
#[derive(Clone, Debug)]
struct Known {
    /// The device and inode of every file a look saw at a guarded name.
    seen: BTreeSet<(u64, u64)>,
    /// Whether a look of a guarded name failed for any reason other than the name's not being
    /// there, saw a link at the name or gave no answer in time, or a look of a path that must not
    /// exist found the path or failed. It is never cleared.
    unlooked: bool,
}

/// The one [`Known`] of a guard, held by the guard and by every worker it starts. Each look writes
/// to it where the look happens, and each shared read reads it as it stands.
#[derive(Clone, Debug)]
struct Looks(std::sync::Arc<std::sync::Mutex<Known>>);

impl Looks {
    fn of(known: Known) -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(known)))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, Known> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Keeps the identity of a file that a look saw at a guarded name.
    fn saw(&self, identity: (u64, u64)) {
        self.state().seen.insert(identity);
    }

    /// Keeps that a look failed, saw a link or gave no answer in time, or that an absence look did
    /// not show its path absent.
    fn lost(&self) {
        self.state().unlooked = true;
    }
}

/// The worker's `stat` of a guarded name.
type Stat = dyn Fn(&Path) -> std::io::Result<std::fs::Metadata> + Send + Sync;

/// What a shared read calls for the look of a guarded name, how long it waits, and the count of the
/// reads it has begun. The real one is [`Reading::real`]; a case gives its own.
#[derive(Clone)]
struct Reading {
    stat: std::sync::Arc<Stat>,
    bound: std::time::Duration,
    begun: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Reading {
    fn real() -> Self {
        Self {
            stat: std::sync::Arc::new(|path: &Path| std::fs::metadata(path)),
            bound: SHARED_BOUND,
            begun: std::sync::Arc::default(),
        }
    }
}

/// Whether `opened` is the object of one of the `guarded` names, which a stat follows to the file.
/// Each look is written to `looks` before this returns: the identity of a file it saw, whether or
/// not that file is `opened`, and a failure. The error where a name cannot be looked at for any
/// reason other than its not being there.
fn is_a_guarded_file(
    opened: &std::fs::Metadata,
    guarded: &[PathBuf],
    looks: &Looks,
    stat: &Stat,
) -> Result<bool, Unread> {
    use std::os::unix::fs::MetadataExt as _;
    for name in guarded {
        match stat(name) {
            Ok(other) => {
                let identity = (other.dev(), other.ino());
                looks.saw(identity);
                if identity == (opened.dev(), opened.ino()) {
                    return Ok(true);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {
                looks.lost();
                return Err(Unread::Unlooked);
            }
        }
    }
    Ok(false)
}

/// Why `file`, a handle's or a name's metadata, is not one to read for the run's name: it is not a
/// regular file, has no name left or more than one name, has the device and inode of a file in
/// `seen`, or is larger than the byte limit. None where it may be read.
fn refusal_of(file: &std::fs::Metadata, seen: &BTreeSet<(u64, u64)>) -> Option<Unread> {
    use std::os::unix::fs::MetadataExt as _;
    if !file.is_file() {
        Some(Unread::NotAFile)
    } else if file.nlink() == 0 {
        Some(Unread::Gone)
    } else if file.nlink() != 1 {
        Some(Unread::ManyNames)
    } else if seen.contains(&(file.dev(), file.ino())) {
        Some(Unread::GuardedFile)
    } else if file.len() > SHARED_LIMIT {
        Some(Unread::TooLarge)
    } else {
        None
    }
}

/// Opens the shared file at `path` with no link followed and no wait, and checks the handle before
/// a byte is read: a regular file, with one name, that is no guarded file (by the device and inode
/// of any file the guard saw at a guarded name, as `looks` holds them now, or by the guarded names
/// now) and is within the byte limit; and none is read where `looks` says now that a look has
/// failed since the take: a look of a guarded name that failed, a look that saw a link at one, a
/// read that gave no answer in time, or a look of a path that must not exist that found the path or
/// failed. None where the file is not there.
fn open_shared(
    path: &Path,
    guarded: &[PathBuf],
    looks: &Looks,
    stat: &Stat,
) -> Result<Option<std::fs::File>, Unread> {
    use rustix::fs::{Mode, OFlags};
    let handle = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(handle) => handle,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(rustix::io::Errno::LOOP) => return Err(Unread::Link),
        Err(_) => return Err(Unread::Failed),
    };
    let file = std::fs::File::from(handle);
    let opened = file.metadata().map_err(|_| Unread::Failed)?;
    {
        let known = looks.state();
        if let Some(unread) = refusal_of(&opened, &known.seen) {
            return Err(unread);
        }
        if known.unlooked {
            return Err(Unread::Unlooked);
        }
    }
    if is_a_guarded_file(&opened, guarded, looks, stat)? {
        return Err(Unread::GuardedFile);
    }
    Ok(Some(file))
}

/// Whether `source` holds one of `needles`, read a piece at a time. It asks for at most `limit`
/// bytes and one more, and refuses a source that gives the one more; it starts no read after
/// `deadline`. Nothing is kept but the last bytes that a needle split across two pieces needs.
fn scan(
    source: &mut dyn std::io::Read,
    needles: &[&[u8]],
    limit: u64,
    deadline: std::time::Instant,
) -> Result<bool, Unread> {
    const PIECE: usize = 64 * 1024;
    let overlap = needles.iter().map(|needle| needle.len()).max().unwrap_or(1) - 1;
    let mut window: Vec<u8> = Vec::with_capacity(PIECE + overlap);
    let mut piece = vec![0_u8; PIECE];
    let mut taken = 0_u64;
    loop {
        if std::time::Instant::now() > deadline {
            return Err(Unread::TooSlow);
        }
        // Ask for no more than what is left up to one byte past the limit; that is always at least
        // one byte.
        let room =
            usize::try_from(limit.saturating_add(1) - taken).map_or(PIECE, |left| left.min(PIECE));
        match source.read(&mut piece[..room]) {
            Ok(0) => return Ok(false),
            Ok(count) => {
                taken += count as u64;
                if taken > limit {
                    return Err(Unread::TooLarge);
                }
                window.extend_from_slice(&piece[..count]);
                if needles.iter().any(|needle| {
                    window
                        .windows(needle.len())
                        .any(|candidate| candidate == *needle)
                }) {
                    return Ok(true);
                }
                let keep = window.len().min(overlap);
                window.drain(..window.len() - keep);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Unread::Failed),
        }
    }
}

/// What `work` gives within `bound`, run on a thread that `builder` makes: its own answer, or a
/// refusal: too slow where it gave none in time, and failed where the thread could not be made or
/// ended without an answer. A thread still waiting is not cancelled: it keeps its descriptor and
/// its buffers until its calls return.
fn read_within(
    builder: std::thread::Builder,
    bound: std::time::Duration,
    work: impl FnOnce() -> Result<bool, Unread> + Send + 'static,
) -> Result<bool, Unread> {
    let (sender, receiver) = std::sync::mpsc::channel();
    // A thread that cannot be made drops the sender, and the wait below ends as a failure.
    let _ = builder.spawn(move || {
        let _ = sender.send(work());
    });
    match receiver.recv_timeout(bound) {
        Ok(read) => read,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(Unread::TooSlow),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(Unread::Failed),
    }
}

/// Whether the shared file at `path` holds one of `needles`, read once through a handle of its own:
/// opened with no link followed and no wait, then checked by the handle before any byte is read (a
/// regular file, one name, no guarded file by the identities `looks` holds now or by the guarded
/// names now, within the byte limit), and read within the time bound. Nothing of the file is kept,
/// and a file that is not there holds nothing. A read that gives no answer in time leaves the look
/// of its worker unresolved, which may yet fail or see a file: it is kept as a failed look, and
/// every shared read after it is refused.
fn shared_names_the_run(
    path: PathBuf,
    guarded: Vec<PathBuf>,
    looks: Looks,
    reading: &Reading,
    needles: Vec<String>,
) -> Result<bool, Unread> {
    let deadline = std::time::Instant::now() + reading.bound;
    let reading = reading.clone();
    let worker_looks = looks.clone();
    let read = read_within(std::thread::Builder::new(), reading.bound, move || {
        let needles: Vec<&[u8]> = needles
            .iter()
            .filter(|needle| !needle.is_empty())
            .map(String::as_bytes)
            .collect();
        match open_shared(&path, &guarded, &worker_looks, &*reading.stat)? {
            Some(mut file) => {
                reading
                    .begun
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                scan(&mut file, &needles, SHARED_LIMIT, deadline)
            }
            None => Ok(false),
        }
    });
    if read == Err(Unread::TooSlow) {
        looks.lost();
    }
    read
}

/// An entry's named files of the person's home, as `lstat` showed them before a driver started
/// anything, and the check that none of the guarded ones changed. A guarded file is looked at by
/// `lstat` alone, never read: its kind, permissions, device, inode, size and times are compared,
/// and its owner on its own. A guarded name that is a symbolic link is refused when the guard is
/// taken, since a write through it changes the target and not the link, and so is a shared name,
/// which would not be read. A shared file, which the person's own sessions also write, is looked
/// at by metadata when the guard is taken, where one that the end read would refuse by its kind,
/// names, size or identity is refused too, and is not read until the end of the run. It is then
/// opened with no link followed and no wait; its opened handle must be a regular file with one
/// name that is not a guarded file; and it is read once, up to a byte limit and within a time
/// bound, for the run's directory name and mark. Nothing of what is read is kept, and a file that
/// fails these checks is not read and stops the run. A file that is the same file as a guarded
/// file is not read: the guard keeps the device and inode of each guarded file from the take and
/// from every later look, the look that each shared read makes of the guarded names among them,
/// and refuses a handle with one of them, or with the one a guarded name holds at the end, so a
/// guarded file moved or linked over the shared name is refused even when its guarded name is
/// gone or holds another file. A look of a guarded name that fails, for any reason other than the
/// name's not being there, a look that sees a link at the name, and a shared read that gives no
/// answer in time are kept for the rest of the run, wherever they are made, a look of the entry's
/// absent list that finds the path present or fails among them, and every shared read after them is
/// refused; so is a read at which a guarded name cannot be looked at. What no look saw can be read,
/// where no saved or current identity matches it: a file that was at no guarded name at any look,
/// put there and then moved over the shared name between two looks; the target of a link put at a
/// guarded name after the take, when no look of the guard observed the link, since the worker's
/// `stat` follows a link and does not see one at the name itself; and a file on a file system that
/// gives a file another device and inode when it is renamed or linked, which defeats a saved
/// identity where no current guarded name matches it. A write to a file that is not named, a
/// transcript below `~/.claude/projects` among them, is not seen. What is said is the path the
/// entry names and whether it changed, never a value.
#[derive(Debug)]
pub struct FileGuard {
    home: PathBuf,
    guarded: Vec<(String, Option<Seen>)>,
    shared: Vec<String>,
    /// What every look of a guarded name has shown since the take.
    looks: Looks,
}

impl FileGuard {
    /// Takes the guarded files, each a path relative to `home`.
    ///
    /// # Panics
    ///
    /// Panics when a guarded or a shared file cannot be looked at, for any reason other than its
    /// not being there, or is a symbolic link: a file whose state is not known cannot be shown
    /// unchanged, and a link would hide the file it points to. It panics too when a shared file is
    /// one that the end read refuses (not a regular file, with more than one name, the same file as
    /// a guarded file, or too large): the run would otherwise spend its turns and stop only at the
    /// end.
    fn take(home: &Path, guarded: &[String], shared: &[String]) -> Self {
        let look = |relative: &String| {
            seen_by_lstat(&home.join(relative)).unwrap_or_else(|error| {
                panic!("the person's file ~/{relative} cannot be looked at: {error}")
            })
        };
        let guarded: Vec<(String, Option<Seen>)> = guarded
            .iter()
            .map(|relative| {
                let seen = look(relative);
                assert!(
                    !seen.is_some_and(|seen| seen.link),
                    "the person's file ~/{relative} is a symbolic link, which the guard does not \
                     follow, so a write to its target would go unseen: replace the link with a \
                     file before a real run"
                );
                (relative.clone(), seen)
            })
            .collect();
        let seen: BTreeSet<(u64, u64)> = guarded
            .iter()
            .filter_map(|(_, seen)| seen.map(|seen| (seen.stamp.device, seen.stamp.inode)))
            .collect();
        for relative in shared {
            match std::fs::symlink_metadata(home.join(relative)) {
                Ok(metadata) => {
                    assert!(
                        !metadata.file_type().is_symlink(),
                        "the person's file ~/{relative} is a symbolic link, which the guard does \
                         not read, so it could not be searched for the run's name at the end: \
                         replace the link with a file before a real run"
                    );
                    if let Some(unread) = refusal_of(&metadata, &seen) {
                        panic!("the person's file ~/{relative} {}", unread.said());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    panic!("the person's file ~/{relative} cannot be looked at: {error}")
                }
            }
        }
        Self {
            home: home.to_path_buf(),
            guarded,
            shared: shared.to_vec(),
            looks: Looks::of(Known {
                seen,
                unlooked: false,
            }),
        }
    }

    /// Looks at each guarded file again, and, where `needles` names something, reads each shared
    /// file once for it.
    fn compare(&self, needles: &[&str]) -> (Vec<Stop>, Value) {
        self.compare_with(
            &|relative| seen_by_lstat(&self.home.join(relative)),
            &Reading::real(),
            needles,
        )
    }

    /// What the cell holds now.
    #[cfg(test)]
    fn known(&self) -> Known {
        self.looks.state().clone()
    }

    /// [`FileGuard::compare`] with the look of the guarded files that `look` gives, and the
    /// worker's look and bound that `reading` gives.
    fn compare_with(
        &self,
        look: &dyn Fn(&str) -> std::io::Result<Option<Seen>>,
        reading: &Reading,
        needles: &[&str],
    ) -> (Vec<Stop>, Value) {
        let (mut stops, files) = self.compared(look);
        let mut shared: Vec<Value> = Vec::new();
        let names: Vec<String> = needles
            .iter()
            .filter(|needle| !needle.is_empty())
            .map(|needle| (*needle).to_owned())
            .collect();
        if !names.is_empty() {
            let guarded: Vec<PathBuf> = self
                .guarded
                .iter()
                .map(|(relative, _)| self.home.join(relative))
                .collect();
            for relative in &self.shared {
                let read = shared_names_the_run(
                    self.home.join(relative),
                    guarded.clone(),
                    self.looks.clone(),
                    reading,
                    names.clone(),
                );
                if matches!(read, Ok(true)) {
                    stops.push((
                        "guarded_file_changed",
                        format!("~/{relative} now holds the run's directory name or mark"),
                    ));
                }
                if let Err(unread) = read {
                    stops.push((
                        "person_file_unreadable",
                        format!("~/{relative} {}", unread.said()),
                    ));
                }
                shared.push(json!({
                    "path": format!("~/{relative}"),
                    "unreadable": read.is_err(),
                    "holds_the_run": matches!(read, Ok(true)),
                }));
            }
        }
        (stops, json!({ "files": files, "shared": shared }))
    }

    /// The guarded files against what `look` shows of each now.
    fn compared(
        &self,
        look: &dyn Fn(&str) -> std::io::Result<Option<Seen>>,
    ) -> (Vec<Stop>, Vec<Value>) {
        let mut stops: Vec<Stop> = Vec::new();
        let mut files: Vec<Value> = Vec::new();
        for (relative, before) in &self.guarded {
            match look(relative) {
                Ok(after) => {
                    if let Some(now) = after {
                        self.looks.saw((now.stamp.device, now.stamp.inode));
                        // The take refuses a link at a guarded name, so a link seen now is a change,
                        // and the look records the link and not its target: every shared read after
                        // it is refused.
                        if now.link {
                            self.looks.lost();
                        }
                    }
                    let owner_changed = matches!(
                        (before, &after),
                        (Some(first), Some(second)) if first.owner != second.owner
                    );
                    let changed = before.map(|seen| seen.stamp) != after.map(|seen| seen.stamp);
                    if owner_changed {
                        stops.push((
                            "guarded_file_changed",
                            format!("~/{relative} has another owner than when the run started"),
                        ));
                    } else if changed {
                        stops.push((
                            "guarded_file_changed",
                            format!("~/{relative} changed while the run ran"),
                        ));
                    }
                    files.push(json!({
                        "path": format!("~/{relative}"),
                        "changed": changed,
                        "owner_changed": owner_changed,
                    }));
                }
                Err(error) => {
                    self.looks.lost();
                    stops.push((
                        "person_file_unreadable",
                        format!("~/{relative} cannot be looked at: {error}"),
                    ));
                    files.push(json!({ "path": format!("~/{relative}"), "unreadable": true }));
                }
            }
        }
        (stops, files)
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
    limits: Limits,
    /// How many entries have been listed so far, and how many bytes read, in the whole walk.
    listed: std::cell::Cell<usize>,
    read: std::cell::Cell<u64>,
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
    Ok(Some((
        directory,
        Bounds {
            root,
            pin,
            limits: Limits::RECORD,
            listed: std::cell::Cell::new(0),
            read: std::cell::Cell::new(0),
        },
    )))
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
                // An entry is counted when it is listed, across the whole walk, and a listing that
                // takes the count past the bound is not listed further.
                bounds.listed.set(bounds.listed.get() + 1);
                if bounds.listed.get() > bounds.limits.entries {
                    return Err(Unlooked {
                        class: Class::TooMany,
                        seen: *seen,
                    });
                }
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
                // The size comes from the handle that will be read, and no more than the bound is
                // read through it: a file above it, sparse or not, is not read into memory.
                let Some(size) = u64::try_from(opened.st_size)
                    .ok()
                    .filter(|size| *size <= bounds.limits.file)
                else {
                    return Err(unlooked(Class::TooLarge, seen));
                };
                // And no more than the bound in all: a file that would take the bytes read past it
                // is not read, and what was read before is already handed on.
                if bounds.read.get().saturating_add(size) > bounds.limits.bytes {
                    return Err(unlooked(Class::TooMuch, seen));
                }
                bounds.read.set(bounds.read.get() + size);
                let mut bytes = Vec::new();
                std::fs::File::from(handle)
                    .take(bounds.limits.file.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(|error| {
                        unlooked(
                            Class::Refused(rustix::io::Errno::from_raw_os_error(
                                error.raw_os_error().unwrap_or(0),
                            )),
                            seen,
                        )
                    })?;
                // A file that grew past the bound since its size was read is not handed on.
                if u64::try_from(bytes.len()).map_or(true, |read| read > bounds.limits.file) {
                    return Err(unlooked(Class::TooLarge, seen));
                }
                visit(&path, &bytes);
            }
            FileType::Symlink => return Err(unlooked(Class::Link, seen)),
            _ => return Err(unlooked(Class::NotAFile, seen)),
        }
    }
    Ok(())
}

/// Reads the agent's own record: every file below `relative` in `within`, the run's directory,
/// through directory handles with no link followed at any step (`record_directory`,
/// `read_files`), handing each file's place in the record and its content to `visit`, and returns
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
    read_record_within(within, pin, relative, Limits::RECORD, visit, between)
}

/// [`read_record_by`] within `limits`: a file above `limits.file` bytes, or more than
/// `limits.entries` entries, is a failure that says the record is beyond the audit's bounds
/// ([`RECORD_BEYOND_THE_BOUNDS`]) and the entries looked at by then, and no content.
fn read_record_within(
    within: &Path,
    pin: &kr_e2e_m1b::run::RootPin,
    relative: &Path,
    limits: Limits,
    visit: &mut dyn FnMut(&[u8], &[u8]),
    between: &mut dyn FnMut(Moment, &[u8]),
) -> Result<u64, String> {
    let said = |why: Unlooked| {
        if matches!(why.class, Class::TooLarge | Class::TooMany | Class::TooMuch) {
            format!("{RECORD_BEYOND_THE_BOUNDS}: {why}")
        } else {
            format!("the agent's record cannot be read whole: {why}")
        }
    };
    let Some((directory, mut bounds)) = record_directory(within, pin, relative).map_err(said)?
    else {
        return Ok(0);
    };
    bounds.limits = limits;
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

/// The identities of the turns of a record that name theirs: a UUID, or a name with the file that
/// holds it, within the bounds of `Limits`. Debug shows how many there are and never a name.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Identities(BTreeSet<String>);

impl std::fmt::Debug for Identities {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} identities", self.0.len())
    }
}

impl Identities {
    /// How many identities are not among those of `baseline`.
    #[must_use]
    pub fn not_in(&self, baseline: &Self) -> u64 {
        u64::try_from(self.0.difference(&baseline.0).count()).unwrap_or(u64::MAX)
    }

    /// How many identities there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there is none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The turns of `found` that are not turns of `baseline`: a turn that names itself counts where its
/// identity is not among the baseline's, whatever turns the baseline held that `found` lacks; a
/// line that names none has an identity of its place, its bytes and its order among the equal lines
/// of its file. A record that lost one turn and gained another therefore shows the new one, though
/// its total is the same.
#[must_use]
pub fn new_turns(baseline: &Recorded, found: &Recorded) -> u64 {
    found.identities.not_in(&baseline.identities)
}

/// The turns the agent's own record holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Recorded {
    /// How many turns the model ran, as the record counts them.
    pub turns: u64,
    /// How many of them are known by their line alone, because the line names no turn.
    pub unnamed: u64,
    /// How many files of the record were read: none where the record's directory is not there.
    pub files: u64,
    /// How many distinct turn names are UUIDs, which count once across the record's files.
    pub by_uuid: u64,
    /// How many turn names, each for its file, are not UUIDs, and count once for each file.
    pub by_other_name: u64,
    /// The identities of the turns that name themselves: what a later reading of the record is
    /// compared with ([`new_turns`]).
    pub identities: Identities,
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
/// time it occurs, in any file, and is told apart from others by its place, its bytes and its order
/// among the equal lines of its file. A conversation written again, a fork's copy of the one it
/// forked from where the names are not UUIDs, or unnamed lines in a copy, count their turns twice:
/// the count is then too high. It is too low only where the record lost lines (an agent that was
/// ended before it wrote them, or that marks no turn this way), which no count of the lines can
/// show; the audit stops a case that passed with a charge and finds none. [`Recorded::unnamed`]
/// says how many turns stand on their line alone.
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
    turns_recorded_within(account, within, pin, relative, Limits::RECORD)
}

/// [`turns_recorded`] within `limits`: a record beyond the bounds on the bytes read in all, the
/// entries listed in all, or the turn names kept in all is incomplete ([`RECORD_BEYOND_THE_BOUNDS`]),
/// and what is said holds the figure and the files read by then, and no content.
fn turns_recorded_within(
    account: &Account,
    within: &Path,
    pin: &kr_e2e_m1b::run::RootPin,
    relative: &Path,
    limits: Limits,
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
    let mut too_many_names = false;
    let mut kept_bytes = 0_usize;
    let files = read_record_within(
        within,
        pin,
        relative,
        limits,
        &mut |place, content| {
            // How many lines of this file are equal to each line that names no turn, in order: two
            // equal lines of one file are two turns.
            let mut equal: BTreeMap<String, u64> = BTreeMap::new();
            for line in String::from_utf8_lossy(content).lines() {
                if line.contains(marker) {
                    let named = serde_json::from_str::<Value>(line)
                        .ok()
                        .as_ref()
                        .and_then(turn_identifier);
                    let (own, name) = match named {
                        Some(named) => {
                            let uuid = is_uuid(&named);
                            let own = if uuid {
                                named.clone()
                            } else {
                                format!("{}\0{named}", String::from_utf8_lossy(place))
                            };
                            (own, Some((named, uuid)))
                        }
                        // A line that names no turn is a turn by its place, its bytes and its
                        // order among the equal lines of its file.
                        None => {
                            let digest = kr_cbor::sha256(line.as_bytes())
                                .iter()
                                .map(|byte| format!("{byte:02x}"))
                                .collect::<String>();
                            let nth = equal.entry(digest.clone()).or_insert(0);
                            *nth += 1;
                            (
                                format!(
                                    "{}\0unnamed\0{digest}\0{nth}",
                                    String::from_utf8_lossy(place)
                                ),
                                None,
                            )
                        }
                    };
                    // The identities kept in all are bound, in number and in bytes: past either
                    // bound no identity that is new is kept.
                    if !turns.contains(&own) {
                        if turns.len() >= limits.names
                            || kept_bytes.saturating_add(own.len()) > limits.name_bytes
                        {
                            too_many_names = true;
                            return;
                        }
                        kept_bytes += own.len();
                    }
                    match name {
                        Some((_, true)) => {
                            by_uuid.insert(own.clone());
                        }
                        Some((named, false)) => {
                            by_other_name.insert(own.clone());
                            forms.insert(form_of(&named));
                        }
                        None => unnamed += 1,
                    }
                    turns.insert(own);
                }
            }
        },
        &mut |_, _| {},
    )?;
    if too_many_names {
        return Err(format!(
            "{RECORD_BEYOND_THE_BOUNDS}: the record names more turns than the audit keeps ({} \
             names or {} bytes of them), and the turns were not counted ({files} files read by \
             then, no content kept)",
            limits.names, limits.name_bytes
        ));
    }
    Ok(Recorded {
        turns: u64::try_from(turns.len()).unwrap_or(u64::MAX),
        unnamed,
        files,
        by_uuid: u64::try_from(by_uuid.len()).unwrap_or(u64::MAX),
        by_other_name: u64::try_from(by_other_name.len()).unwrap_or(u64::MAX),
        identities: Identities(turns),
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
    /// The record is beyond what the audit reads (a file above its size bound, or more entries
    /// than its walk lists): the turns were not counted, and what is said holds the entries looked
    /// at by then and no content.
    Incomplete(String),
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
        Err(why) if why.starts_with(RECORD_BEYOND_THE_BOUNDS) => Audit::Incomplete(why.clone()),
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
/// the moment it is spawned (`Leader`); it is ended whole as soon as its leader has exited or
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
    conversations_relative_in(account, CONFIG_DIRECTORY)
}

/// [`conversations_relative`] for the configuration directory `config_directory` of the run.
#[must_use]
pub fn conversations_relative_in(account: &Account, config_directory: &str) -> PathBuf {
    let base = account.conversations.split("{date}").next().unwrap_or("");
    Path::new(config_directory).join(base.trim_end_matches('/'))
}

/// Calls `attempt` again, up to `attempts` calls in all with `pause` between them, while the
/// system refuses it because the program it runs is open for writing, and for no other error.
fn retried_while_busy<T>(
    attempts: u32,
    pause: std::time::Duration,
    mut attempt: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let mut tried = 1;
    loop {
        match attempt() {
            Err(error)
                if error.kind() == std::io::ErrorKind::ExecutableFileBusy && tried < attempts =>
            {
                tried += 1;
                std::thread::sleep(pause);
            }
            other => return other,
        }
    }
}

/// Starts `command`, a program that was written a moment ago. Another thread's `fork` can still
/// hold the file open for writing until that child has run its own `exec`, and the system then
/// refuses the start as busy; it is tried again a bounded number of times (a hundred, fifty
/// milliseconds apart), and no other error is tried again.
///
/// # Errors
///
/// Returns the system's refusal where the program is still busy after the last try, or any other.
pub fn spawn_retrying_when_busy(
    command: &mut std::process::Command,
) -> std::io::Result<std::process::Child> {
    retried_while_busy(100, std::time::Duration::from_millis(50), || {
        command.spawn()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::run_files_holding;

    /// A refusal as busy is tried again and nothing else is, and the number of tries is bounded.
    #[test]
    fn a_start_refused_as_busy_is_tried_again_a_bounded_number_of_times_and_no_other_error_is() {
        let pause = std::time::Duration::from_millis(1);
        let mut calls = 0;
        let started = retried_while_busy(5, pause, || {
            calls += 1;
            if calls < 3 {
                Err(std::io::ErrorKind::ExecutableFileBusy.into())
            } else {
                Ok(calls)
            }
        });
        assert_eq!(started.expect("the third call starts it"), 3);
        let mut calls = 0;
        let refused: std::io::Result<()> = retried_while_busy(5, pause, || {
            calls += 1;
            Err(std::io::ErrorKind::ExecutableFileBusy.into())
        });
        assert_eq!(calls, 5, "the tries are bounded");
        assert_eq!(
            refused.expect_err("still busy").kind(),
            std::io::ErrorKind::ExecutableFileBusy
        );
        let mut calls = 0;
        let other: std::io::Result<()> = retried_while_busy(5, pause, || {
            calls += 1;
            Err(std::io::ErrorKind::PermissionDenied.into())
        });
        assert_eq!(calls, 1, "another error is returned at once");
        assert_eq!(
            other.expect_err("denied").kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

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

    /// The recipe's files below a configuration directory, with the bytes it wrote, and the key it
    /// sets.
    const RECIPE: [(&str, &[u8]); 2] = [
        ("skills/p/.mcp.json", br#"{"servers":1}"#),
        ("skills/p/hooks/hooks.json", br#"{"hooks":1}"#),
    ];
    const KEY: &str = "p@skills-dir";

    /// A run's directory whose configuration directory `c` holds the recipe's files with their
    /// bytes and `settings.json` with its key.
    fn configured(name: &str) -> PathBuf {
        let root = scratch(name);
        filled(&root.join("c"));
        root
    }

    /// Puts the recipe's files with their bytes and `settings.json` with its key in `config`.
    fn filled(config: &Path) {
        for (file, bytes) in RECIPE {
            let path = config.join(file);
            std::fs::create_dir_all(path.parent().expect("a directory")).expect("directories");
            std::fs::write(path, bytes).expect("a recipe file");
        }
        std::fs::write(
            config.join("settings.json"),
            format!(r#"{{"enabledPlugins":{{"{KEY}":true}}}}"#),
        )
        .expect("the settings");
    }

    /// The configuration directory `c` of the run's directory `root` as it stands now, recorded as
    /// the run placed it.
    fn placed(root: &Path) -> kr_e2e_m1b::run::PlacedDirectory {
        kr_e2e_m1b::run::PlacedDirectory::record(root, &pinned(root), Path::new("c"))
            .expect("the directory as placed")
    }

    /// The end compare of the run's directory `root`, whose configuration directory is `c` as it
    /// stands now, for an entry that allows `allowed` below it.
    fn compared(root: &Path, allowed: &[&str]) -> Result<(), String> {
        compared_with(root, &placed(root), allowed)
    }

    /// The end compare of the run's directory `root` against the configuration directory `placed`,
    /// for an entry that allows `allowed` below it.
    fn compared_with(
        root: &Path,
        placed: &kr_e2e_m1b::run::PlacedDirectory,
        allowed: &[&str],
    ) -> Result<(), String> {
        let mut account = account();
        account.allowed = allowed
            .iter()
            .map(|pattern| format!("{{config}}/{pattern}"))
            .collect();
        end_compare(root, &pinned(root), placed, &RECIPE, KEY, &account)
    }

    /// With no allowed set, the recipe's files and the settings with the recipe's key are all the
    /// end compare finds.
    #[test]
    fn the_recipes_files_and_its_key_are_all_the_end_compare_finds_below_the_configuration_directory()
     {
        let root = configured("end-recipe");
        assert_eq!(compared(&root, &[]), Ok(()));
    }

    /// A file that is not the recipe's and that no pattern names is named, and one that a pattern
    /// names is not.
    #[test]
    fn a_file_beyond_the_recipe_and_the_allowed_set_is_named_by_the_end_compare() {
        let root = configured("end-beyond");
        let config = root.join("c");
        std::fs::write(config.join(".claude.json"), b"{}").expect("a file");
        std::fs::create_dir_all(config.join("projects/a")).expect("directories");
        std::fs::write(config.join("projects/a/t.jsonl"), b"x").expect("a file");
        assert_eq!(
            compared(&root, &["projects/**"]),
            Err(
                ".claude.json is not one of the recipe's files, and the entry does not allow it"
                    .to_owned()
            )
        );
    }

    /// A `settings.json` that holds another key, or the recipe's key set to false, is named, and an
    /// allowed file that names it is refused before any file is compared.
    #[test]
    fn a_settings_file_that_holds_more_than_the_recipes_key_is_named_by_the_end_compare() {
        let root = configured("end-settings");
        let config = root.join("c");
        for held in [
            format!(r#"{{"enabledPlugins":{{"{KEY}":true,"other@x":true}}}}"#),
            format!(r#"{{"enabledPlugins":{{"{KEY}":false}}}}"#),
            format!(r#"{{"theme":"dark","enabledPlugins":{{"{KEY}":true}}}}"#),
            "not json".to_owned(),
        ] {
            std::fs::write(config.join("settings.json"), &held).expect("the settings");
            assert_eq!(
                compared(&root, &[]),
                Err(format!(
                    "settings.json does not hold exactly the recipe's key {KEY}"
                )),
                "{held}"
            );
        }
        let refused = compared(&root, &["settings.json"]).expect_err("a pattern that names it");
        assert!(refused.contains("no entry may allow"), "{refused}");
    }

    /// The files a signed-in run writes beside the recipe pass when the entry names them.
    #[test]
    fn a_name_in_the_allowed_set_passes_the_end_compare() {
        let root = configured("end-allowed");
        let config = root.join("c");
        for file in [
            ".claude.json",
            "plugins/installed_plugins.json",
            "plugins/data/p/x/y.json",
            "projects/one/s.jsonl",
        ] {
            let path = config.join(file);
            std::fs::create_dir_all(path.parent().expect("a directory")).expect("directories");
            std::fs::write(path, b"{}").expect("a file");
        }
        let allowed = [
            ".claude.json",
            "plugins/installed_plugins.json",
            "plugins/data/p/**",
            "projects/*/s.jsonl",
        ];
        assert_eq!(compared(&root, &allowed), Ok(()));
    }

    /// The account name as the system has it, as the expansion of `{user}` reads it.
    fn user() -> String {
        let output = std::process::Command::new("/usr/bin/id")
            .arg("-un")
            .output()
            .expect("the account name");
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// The absent list of an entry with `absent` and `allowed` as the expansion makes it for a run
    /// whose configuration directory is `config` and whose home is `home`, or what it stops with.
    fn expanded(
        absent: &[&str],
        allowed: &[String],
        config: &Path,
        home: &Path,
    ) -> Result<Vec<PathBuf>, String> {
        let mut account = account();
        account.absent = absent.iter().map(|path| (*path).to_owned()).collect();
        account.allowed = allowed
            .iter()
            .map(|pattern| format!("{{config}}/{pattern}"))
            .collect();
        let root = config.parent().expect("a run's directory").to_path_buf();
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            absent_paths_under(
                &account,
                config,
                &root.join("w"),
                home,
                Path::new("/person"),
                &root.join("w"),
                Absent::All,
            )
        }))
        .map_err(|panic| {
            panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|text| (*text).to_owned()))
                .unwrap_or_default()
        })
    }

    /// An absent path that the expansion puts below the configuration directory is refused unless
    /// it is spelled `{config}/` and its names, whatever the allowed files are: a root slash
    /// before `{config}`, which the expansion turns into two leading slashes that name the same
    /// file.
    #[test]
    fn a_slash_before_the_config_placeholder_does_not_hide_an_absent_path_from_the_allowed_files() {
        let root = scratch("expand-slash");
        let said = expanded(
            &["/{config}/.claude.json"],
            &[".claude.json".to_owned()],
            &root.join("c"),
            &root.join("h"),
        )
        .expect_err("an absent path an allowed file names");
        assert!(
            said.contains("the absent path \"/{config}/.claude.json\" names the configuration directory or a path below it"),
            "{said}"
        );
    }

    /// A placeholder inside a name of the rest, expanded, names a file below the configuration
    /// directory, so the path is refused as one that is not spelled with its names alone.
    #[test]
    fn a_placeholder_in_a_name_below_the_config_placeholder_does_not_hide_an_absent_path() {
        let root = scratch("expand-user");
        let user = user();
        let said = expanded(
            &["{config}/{user}.json"],
            &[format!("{user}.json")],
            &root.join("c"),
            &root.join("h"),
        )
        .expect_err("an absent path an allowed file names");
        assert!(
            said.contains(
                "the absent path \"{config}/{user}.json\" names the configuration directory or a path below it"
            ),
            "{said}"
        );
    }

    /// Where the configuration directory is a directory of the home, the home placeholder names a
    /// path below it, and the path is refused, with an allowed file that names it or with none,
    /// since an entry spells such a path `{config}/`.
    #[test]
    fn the_home_placeholder_naming_a_path_below_the_configuration_directory_is_held_too() {
        let root = scratch("expand-home");
        let home = root.join("h");
        let said = expanded(
            &["{home}/.claude/x", "{home}/.claude/../.claude/y/z"],
            &["x".to_owned()],
            &home.join(".claude"),
            &home,
        )
        .expect_err("an absent path an allowed file names");
        assert!(
            said.contains("the absent path \"{home}/.claude/x\" names the configuration directory or a path below it"),
            "{said}"
        );
        let said = expanded(
            &["{home}/.claude/../.claude/y/z"],
            &["y/*".to_owned()],
            &home.join(".claude"),
            &home,
        )
        .expect_err("a path with a part that is taken back");
        assert!(
            said.contains("the absent path \"{home}/.claude/../.claude/y/z\" names the configuration directory or a path below it"),
            "{said}"
        );
    }

    /// The directory's own names in another letter case still name the directory on a volume that
    /// ignores it, so a path below them is refused though an allowed file names it as `{config}/`
    /// spells it.
    #[test]
    fn the_directorys_own_names_in_another_letter_case_do_not_escape_the_expansion() {
        let root = scratch("expand-case");
        let home = root.join("h");
        let said = expanded(
            &["{home}/.CLAUDE/x"],
            &["x".to_owned()],
            &home.join(".claude"),
            &home,
        )
        .expect_err("a path that names a path below the directory");
        assert!(
            said.contains("the absent path \"{home}/.CLAUDE/x\" names the configuration directory or a path below it"),
            "{said}"
        );
    }

    /// A spelling of a path below the directory other than `{config}/` is refused with no allowed
    /// file at all: the check is of the spelling, not of the allowed files.
    #[test]
    fn a_spelling_other_than_the_config_placeholder_is_refused_with_no_allowed_file() {
        let root = scratch("expand-spelling");
        let home = root.join("h");
        for absent in ["{home}/.claude/x", "{home}/.CLAUDE/x", "{home}/.Claude/a/b"] {
            let said = expanded(&[absent], &[], &home.join(".claude"), &home)
                .expect_err("a path below the directory");
            assert!(
                said.contains(&format!(
                    "the absent path {absent:?} names the configuration directory or a path below it"
                )),
                "{said}"
            );
        }
    }

    /// The directory itself is no absent path of an entry, in any spelling: not as `{config}` alone
    /// and not through another placeholder in another letter case.
    #[test]
    fn the_configuration_directory_itself_is_refused_in_any_spelling() {
        let root = scratch("expand-itself");
        let home = root.join("h");
        for absent in ["{home}/.CLAUDE", "{home}/.claude", "{config}"] {
            let said = expanded(&[absent], &[], &home.join(".claude"), &home)
                .expect_err("the directory itself");
            assert!(
                said.contains(&format!(
                    "the absent path {absent:?} names the configuration directory or a path below it"
                )),
                "{said}"
            );
        }
    }

    /// The working folder and each folder above it can be the directory's parent, so a path below
    /// it that is spelled with `{ancestors}` is refused in any letter case.
    #[test]
    fn an_ancestor_that_is_the_configuration_directorys_parent_does_not_escape_the_expansion() {
        let root = scratch("expand-ancestors");
        let said = expanded(
            &["{ancestors}/AGENT-CONFIG/x"],
            &[],
            &root.join("agent-config"),
            &root.join("h"),
        )
        .expect_err("a path below the directory");
        assert!(
            said.contains("the absent path \"{ancestors}/AGENT-CONFIG/x\" names the configuration directory or a path below it"),
            "{said}"
        );
    }

    /// A path spelled `{config}/` and its names, with no allowed file that names it, is expanded as
    /// before whatever the directory is, and so is each form the live entries use where the
    /// directory is `.claude` of the home.
    #[test]
    fn a_path_spelled_below_the_config_placeholder_and_the_live_forms_are_expanded_as_before() {
        let root = scratch("expand-live");
        let home = root.join("h");
        // The working directory is `w` beside the configuration directory's parent.
        let work = home.join("w");
        let directory = home.join(".claude");
        assert_eq!(
            expanded(&["{config}/x"], &[], &directory, &home),
            Ok(vec![directory.join("x"), directory.join("rules")])
        );
        let mut live = vec![
            work.join(".mcp.json"),
            home.join(".claude.json"),
            PathBuf::from(format!("/Library/Managed Preferences/{}/x.plist", user())),
        ];
        live.extend(work.ancestors().map(|folder| folder.join(".env")));
        live.push(directory.join("rules"));
        assert_eq!(
            expanded(
                &[
                    "{work}/.mcp.json",
                    "{home}/.claude.json",
                    "/Library/Managed Preferences/{user}/x.plist",
                    "{ancestors}/.env"
                ],
                &["projects/**".to_owned()],
                &directory,
                &home
            ),
            Ok(live)
        );
    }

    /// A path spelled `{config}/` and its names is held to the allowed files as well, names that
    /// differ in letter case being one name: the second line behind the entry's own check.
    #[test]
    fn a_path_spelled_below_the_config_placeholder_is_held_to_the_allowed_files() {
        let root = scratch("expand-allowed");
        for (absent, allowed, names) in [
            ("{config}/x", "x", "x"),
            ("{config}/Projects/x", "projects/**", "Projects/x"),
            ("{config}/a/b", "a/*", "a/b"),
        ] {
            let said = expanded(
                &[absent],
                &[allowed.to_owned()],
                &root.join("c"),
                &root.join("h"),
            )
            .expect_err("an absent path an allowed file names");
            assert!(
                said.contains(&format!(
                    "the absent path {absent:?} names {names:?} below the configuration directory, which the entry's allowed file \"{{config}}/{allowed}\" names"
                )),
                "{said}"
            );
        }
    }

    /// A path that is there is not shown absent, whatever an allowed file names: the file system
    /// is asked and nothing else, so a file and a link at names that allowed files name are
    /// present, and a name nothing is at is absent.
    #[cfg(unix)]
    #[test]
    fn a_present_path_is_not_shown_absent_whatever_an_allowed_file_names() {
        let root = configured("shown-present");
        let config = root.join("c");
        let pin = pinned(&root);
        std::fs::write(config.join(".claude.json"), b"{}").expect("a file");
        std::os::unix::fs::symlink(root.join("nowhere"), config.join("link")).expect("a link");
        let allowed = patterns(&[".claude.json", "link", "projects/**"]);
        for name in [".claude.json", "link", "projects/x"] {
            assert!(is_allowed(&allowed, name), "{name} is an allowed name");
        }
        for name in [".claude.json", "link"] {
            let said = shown_absent(&root, &pin, &[config.join(name)])
                .expect_err("a path that is there, whatever an allowed file names");
            assert!(
                said.contains(&format!("{} exists", config.join(name).display())),
                "{said}"
            );
        }
        assert_eq!(
            shown_absent(&root, &pin, &[config.join("projects/x")]),
            Ok(())
        );
    }

    /// An absent path that no allowed file names, whatever directory it lies in, is expanded as it
    /// always was, with the configuration directory's `rules` last; and the list with an
    /// `{ancestors}` template for the record is not held to anything.
    #[test]
    fn an_absent_path_that_no_allowed_file_names_is_expanded_as_before() {
        let root = scratch("expand-plain");
        let (config, home) = (root.join("c"), root.join("h"));
        let allowed = ["projects/**".to_owned()];
        assert_eq!(
            expanded(
                &[
                    "{config}/auth.json",
                    "{work}/b",
                    "{home}/c",
                    "{home}/.claude/x"
                ],
                &allowed,
                &config,
                &home
            ),
            Ok(vec![
                config.join("auth.json"),
                root.join("w/b"),
                home.join("c"),
                home.join(".claude/x"),
                config.join("rules"),
            ])
        );
        let mut account = account();
        account.absent = vec!["{ancestors}/.env".to_owned()];
        account.allowed = vec!["{config}/projects/**".to_owned()];
        let work = root.join("w");
        assert_eq!(
            absent_paths_under(
                &account,
                &config,
                &work,
                &home,
                Path::new("/person"),
                &work,
                Absent::Published,
            ),
            vec![PathBuf::from("{ancestors}/.env")],
            "the list for the record keeps its template"
        );
    }

    fn patterns(list: &[&str]) -> Vec<String> {
        list.iter().map(|pattern| (*pattern).to_owned()).collect()
    }

    /// A `*` is one name and a last `**` is every file below its directory, and neither is the
    /// directory itself, a longer path than a `*` leaves, or a file of another name.
    #[test]
    fn a_star_is_one_name_and_a_last_double_star_is_every_file_below() {
        let allowed = patterns(&["a/*/c", "d/**", "e.json"]);
        for named in ["a/b/c", "a/x/c", "d/f", "d/f/g/h", "e.json"] {
            assert!(is_allowed(&allowed, named), "{named} is allowed");
        }
        for refused in ["a/c", "a/b/c/d", "a/b", "d", "e.json/x", "x/e.json", ""] {
            assert!(!is_allowed(&allowed, refused), "{refused} is not allowed");
        }
    }

    /// Names that differ only in letter case are one name: a pattern names a file whatever the
    /// case of the file's name, since the volume a run lives on may ignore it.
    #[test]
    fn a_pattern_names_a_file_whatever_the_letter_case_of_its_name() {
        let allowed = patterns(&["a/*/c", "d/**", "e.json"]);
        for named in ["A/b/C", "a/X/c", "D/f", "d/F/G/h", "E.JSON"] {
            assert!(is_allowed(&allowed, named), "{named} is allowed");
        }
        for refused in ["a/C/d", "e.jsonl", "D", "x/E.json"] {
            assert!(!is_allowed(&allowed, refused), "{refused} is not allowed");
        }
    }

    /// A link below the configuration directory is refused at every name, an allowed name too: a
    /// name says nothing of where a link leads, and the agent may read what it leads to.
    #[cfg(unix)]
    #[test]
    fn a_link_below_the_configuration_directory_is_refused_at_every_name_an_allowed_one_too() {
        let root = configured("end-link");
        let config = root.join("c");
        let outside = scratch("end-link-outside");
        std::fs::write(outside.join("somewhere"), b"{}").expect("a file outside");
        std::fs::create_dir(outside.join("directory")).expect("a directory outside");
        std::fs::write(outside.join("directory/in"), b"{}").expect("a file in it");
        let said = |name: &str| {
            format!(
                "{name} is a link, and a link is accepted at no name below the configuration directory"
            )
        };
        // A link by a name that no pattern names, and by names that a pattern names exactly.
        for (name, allowed) in [
            ("link", &[][..]),
            ("link", &["link"][..]),
            (".claude.json", &[".claude.json"][..]),
        ] {
            std::os::unix::fs::symlink(outside.join("somewhere"), config.join(name))
                .expect("a link");
            assert_eq!(
                compared(&root, allowed),
                Err(said(name)),
                "{name} with {allowed:?}"
            );
            std::fs::remove_file(config.join(name)).expect("the link goes");
        }
        // A link to a directory, named like an allowed directory, and a link below a directory.
        std::os::unix::fs::symlink(outside.join("directory"), config.join("projects"))
            .expect("a link");
        assert_eq!(compared(&root, &["projects"]), Err(said("projects")));
        assert_eq!(compared(&root, &["projects/**"]), Err(said("projects")));
        std::fs::remove_file(config.join("projects")).expect("the link goes");
        std::fs::create_dir(config.join("projects")).expect("a directory");
        std::os::unix::fs::symlink(outside.join("somewhere"), config.join("projects/x"))
            .expect("a link");
        assert_eq!(compared(&root, &["projects/*"]), Err(said("projects/x")));
        std::fs::remove_dir_all(config.join("projects")).expect("the directory goes");
        // A `settings.json` that is a link is not the recipe's.
        std::fs::remove_file(config.join("settings.json")).expect("the settings go");
        std::os::unix::fs::symlink(outside.join("somewhere"), config.join("settings.json"))
            .expect("a link");
        let refused = compared(&root, &["link"]).expect_err("settings.json as a link");
        assert!(
            refused.starts_with("settings.json is not a file of the run's own: "),
            "{refused}"
        );
    }

    /// An entry that is neither a regular file, a directory nor a link (a socket, a pipe) is refused
    /// at every name below the configuration directory, an allowed name too: the agent may read
    /// from it or write to it, and a name says nothing of what is on the other end.
    #[cfg(unix)]
    #[test]
    fn an_entry_that_is_neither_a_file_a_directory_nor_a_link_is_refused_at_every_name() {
        let root = configured("end-kind");
        let config = root.join("c");
        let said = |name: &str| {
            format!(
                "{name} is neither a regular file, a directory nor a link, and such an entry is \
                 accepted at no name below the configuration directory"
            )
        };
        let _socket =
            std::os::unix::net::UnixListener::bind(config.join("sock")).expect("a socket");
        assert_eq!(compared(&root, &[]), Err(said("sock")));
        assert_eq!(compared(&root, &["sock"]), Err(said("sock")));
        std::fs::remove_file(config.join(".claude.json")).ok();
        let made = std::process::Command::new("/usr/bin/mkfifo")
            .arg(config.join(".claude.json"))
            .status()
            .expect("mkfifo");
        assert!(made.success(), "a pipe at an allowed name");
        let refused = compared(&root, &[".claude.json", "sock"]).expect_err("a pipe");
        assert!(refused.contains(&said(".claude.json")), "{refused}");
    }

    /// A name on another file system than the configuration directory is refused and not entered:
    /// the walk is told that the directory is on a device that it is not on, so every name in it
    /// is on another one.
    #[test]
    fn a_name_on_another_file_system_is_refused_and_not_entered() {
        let root = configured("end-device");
        let pin = pinned(&root);
        let placed = placed(&root);
        let directory = placed.open(&root, &pin).expect("the directory");
        let device = rustix::fs::fstat(&directory)
            .expect("the directory's device")
            .st_dev;
        let mut compare = EndCompare {
            root: &root,
            pin: &pin,
            config: placed.relative(),
            recipe_files: &RECIPE,
            settings_key: KEY,
            allowed: &[],
            refused: Vec::new(),
            seen: 0,
            device: device.wrapping_add(1),
        };
        compare.walk(&directory, "", 0);
        assert_eq!(
            compare.refused,
            [
                "skills is on another file system than the configuration directory, and nothing there is compared"
            ],
            "the directory is refused where it is, and nothing below it is looked at"
        );
    }

    /// A file with more than one name is refused at every name below the configuration directory,
    /// an allowed name too: its other name may be a file the agent reads, in a place of the
    /// person's.
    #[cfg(unix)]
    #[test]
    fn a_file_with_a_second_name_is_refused_below_the_configuration_directory_an_allowed_name_too()
    {
        let root = configured("end-hard-allowed");
        let config = root.join("c");
        std::fs::write(root.join("theirs"), b"{}").expect("a file of theirs");
        std::fs::hard_link(root.join("theirs"), config.join(".claude.json"))
            .expect("a second name");
        let said = ".claude.json is a file with more than one name, and such a file is accepted at no name below the configuration directory";
        assert_eq!(compared(&root, &[".claude.json"]), Err(said.to_owned()));
        assert_eq!(compared(&root, &[]), Err(said.to_owned()));
        std::fs::remove_file(root.join("theirs")).expect("the other name goes");
        assert_eq!(
            compared(&root, &[".claude.json"]),
            Ok(()),
            "with one name, the allowed file passes"
        );
    }

    /// Each of the recipe's files and `settings.json` is looked at by itself, whatever names the
    /// directory holds: a directory that holds none of them is refused with each one named.
    #[test]
    fn an_empty_configuration_directory_is_refused_with_each_file_of_the_recipe_named() {
        let root = scratch("end-empty");
        std::fs::create_dir(root.join("c")).expect("an empty directory");
        let refused = compared(&root, &[]).expect_err("none of the recipe is there");
        for file in ["settings.json", RECIPE[0].0, RECIPE[1].0] {
            assert!(
                refused.contains(&format!(
                    "{file} is not a file of the run's own: it is not there"
                )),
                "{file}: {refused}"
            );
        }
    }

    /// A link named like an allowed directory that leads to files of the recipe's bytes is
    /// refused: each recipe file is looked at by its own path, and a link on the way is a refusal.
    #[cfg(unix)]
    #[test]
    fn a_link_named_like_an_allowed_directory_does_not_stand_for_the_recipes_files() {
        let root = configured("end-recipe-link");
        let config = root.join("c");
        let theirs = scratch("end-recipe-link-theirs");
        std::fs::rename(config.join("skills"), theirs.join("skills"))
            .expect("the recipe's directory moves");
        std::os::unix::fs::symlink(theirs.join("skills"), config.join("skills")).expect("a link");
        let refused = compared(&root, &["skills"]).expect_err("a link named like an allowed one");
        for (file, _) in RECIPE {
            assert!(
                refused.contains(&format!("{file} is not a file of the run's own: ")),
                "{file}: {refused}"
            );
        }
    }

    /// The configuration directory is reached through the run's pinned directory: one that was
    /// made a link to another directory is refused, and nothing in that directory is read or named.
    #[cfg(unix)]
    #[test]
    fn a_configuration_directory_replaced_by_a_link_is_refused_and_nothing_through_it_is_read() {
        let root = configured("end-root-link");
        let theirs = scratch("end-root-link-theirs");
        std::fs::write(
            theirs.join("settings.json"),
            format!(r#"{{"enabledPlugins":{{"{KEY}":true}}}}"#),
        )
        .expect("their settings");
        std::fs::write(theirs.join("their-file"), b"x").expect("their file");
        let kept = placed(&root);
        std::fs::rename(root.join("c"), root.join("c-moved")).expect("moved");
        std::os::unix::fs::symlink(&theirs, root.join("c")).expect("a link");
        let refused =
            compared_with(&root, &kept, &[]).expect_err("a link in place of the directory");
        assert!(
            refused.starts_with("the configuration directory cannot be compared: ")
                && !refused.contains("their-file"),
            "{refused}"
        );
    }

    /// A directory that stands where the configuration directory was, with the recipe's files and
    /// key in it, is not the directory the run placed: it is refused, though every file in it is
    /// as it should be.
    #[test]
    fn another_directory_in_the_place_of_the_configuration_directory_is_refused() {
        let root = configured("end-placed");
        let kept = placed(&root);
        assert_eq!(
            compared_with(&root, &kept, &[]),
            Ok(()),
            "the directory as placed"
        );
        std::fs::rename(root.join("c"), root.join("c-moved")).expect("moved");
        std::fs::create_dir(root.join("c")).expect("another directory");
        filled(&root.join("c"));
        let refused = compared_with(&root, &kept, &[]).expect_err("another directory");
        assert!(
            refused.starts_with("the configuration directory cannot be compared: ")
                && refused.contains("it is another directory"),
            "{refused}"
        );
    }

    /// A `settings.json` with a second name is the same file under another one, and is refused
    /// though it holds the recipe's key.
    #[cfg(unix)]
    #[test]
    fn a_settings_file_with_a_second_name_is_refused_though_it_holds_the_recipes_key() {
        let root = configured("end-hard");
        let config = root.join("c");
        std::fs::hard_link(config.join("settings.json"), root.join("second-name"))
            .expect("a second name");
        let refused = compared(&root, &[]).expect_err("a second name");
        assert!(
            refused.starts_with("settings.json is not a file of the run's own: ")
                && refused.contains("more than one name"),
            "{refused}"
        );
    }

    /// A directory named `settings.json` is refused, empty or not, and its contents are not
    /// compared: the name is the agent's settings file's, and only a file may have it.
    #[test]
    fn a_directory_named_settings_json_is_refused_whatever_it_holds() {
        let root = configured("end-settings-directory");
        let config = root.join("c");
        std::fs::remove_file(config.join("settings.json")).expect("the settings go");
        std::fs::create_dir(config.join("settings.json")).expect("an empty directory");
        let said = "settings.json is not a file of the run's own: an entry is not the kind of entry the path names";
        assert_eq!(compared(&root, &[]), Err(said.to_owned()));
        std::fs::write(config.join("settings.json/inside"), b"x").expect("a file inside");
        assert_eq!(compared(&root, &[]), Err(said.to_owned()));
        let refused =
            compared(&root, &["settings.json/*"]).expect_err("a pattern for its contents");
        assert!(refused.contains("no entry may allow"), "{refused}");
    }

    /// A name that differs from `settings.json` only in letter case is `settings.json`: a file by it
    /// must hold exactly the recipe's key and a directory by it is refused, empty or not. The volume
    /// a run lives on may ignore letter case, so the agent reads the file by that name too.
    #[test]
    fn settings_json_in_another_letter_case_is_held_to_the_settings_rule() {
        let root = configured("end-settings-case");
        let config = root.join("c");
        std::fs::remove_file(config.join("settings.json")).expect("the settings go");
        std::fs::write(config.join("SETTINGS.JSON"), br#"{"theme":"dark"}"#).expect("a file");
        let refused = compared(&root, &[]).expect_err("a file that holds another key");
        assert!(
            refused.contains("SETTINGS.JSON does not hold exactly the recipe's key"),
            "{refused}"
        );
        std::fs::remove_file(config.join("SETTINGS.JSON")).expect("the file goes");
        std::fs::create_dir(config.join("SETTINGS.JSON")).expect("an empty directory");
        let refused = compared(&root, &[]).expect_err("an empty directory");
        assert!(
            refused.contains("SETTINGS.JSON is not a file of the run's own: "),
            "{refused}"
        );
        std::fs::write(config.join("SETTINGS.JSON/inside"), b"x").expect("a file inside");
        let refused = compared(&root, &[]).expect_err("a directory with a file");
        assert!(
            refused.contains("SETTINGS.JSON is not a file of the run's own: ")
                && !refused.contains("inside"),
            "{refused}"
        );
    }

    /// `settings.local.json` and `rules`, in any letter case, as a file or a directory, empty or
    /// not, are refused: the agent reads its settings and its rules from them, and no entry may
    /// allow them.
    #[test]
    fn the_other_names_the_agent_reads_its_settings_and_rules_from_are_refused_in_any_case() {
        for name in [
            "settings.local.json",
            "Settings.Local.Json",
            "rules",
            "RULES",
            "Rules",
        ] {
            for kind in ["a file", "an empty directory"] {
                let root = configured("end-reserved");
                let config = root.join("c");
                if kind == "a file" {
                    std::fs::write(config.join(name), b"{}").expect("a file");
                } else {
                    std::fs::create_dir(config.join(name)).expect("a directory");
                }
                let refused = compared(&root, &[]).expect_err(name);
                assert!(
                    refused.contains(&format!(
                        "{name} is a name the agent reads its settings or rules from, which no \
                         entry may allow"
                    )),
                    "{name} as {kind}: {refused}"
                );
                std::fs::remove_dir_all(&root).expect("clean up");
            }
        }
    }

    /// Each of the recipe's files is held to a regular file with the bytes the recipe wrote: other
    /// bytes, a link, a second name and a directory are each refused, and the file is named.
    #[cfg(unix)]
    #[test]
    fn a_recipe_file_that_is_not_a_regular_file_with_the_recipes_bytes_is_refused() {
        let root = configured("end-recipe-files");
        let config = root.join("c");
        let (file, bytes) = RECIPE[0];
        let place = config.join(file);
        let outside = scratch("end-recipe-files-outside").join("theirs");
        std::fs::write(&outside, bytes).expect("a file with the same bytes");
        // Other bytes.
        std::fs::write(&place, br#"{"servers":2}"#).expect("other bytes");
        assert_eq!(
            compared(&root, &[]),
            Err(format!("{file} does not hold the bytes the recipe wrote"))
        );
        // The same bytes under a link, a second name and a directory.
        for kind in ["link", "second name", "directory"] {
            std::fs::remove_file(&place).ok();
            std::fs::remove_dir_all(&place).ok();
            match kind {
                "link" => std::os::unix::fs::symlink(&outside, &place).expect("a link"),
                "second name" => {
                    std::fs::write(&place, bytes).expect("the bytes");
                    std::fs::hard_link(&place, root.join("second-name")).expect("a second name");
                }
                _ => {
                    std::fs::create_dir(&place).expect("a directory");
                    std::fs::write(place.join("inside"), bytes).expect("a file inside");
                }
            }
            let refused = compared(&root, &[]).expect_err(kind);
            assert!(
                refused.starts_with(&format!("{file} is not a file of the run's own: "))
                    && !refused.contains("inside"),
                "{kind}: {refused}"
            );
            std::fs::remove_file(root.join("second-name")).ok();
        }
        // And the file as it was written passes again.
        std::fs::remove_dir_all(&place).ok();
        std::fs::write(&place, bytes).expect("the bytes");
        assert_eq!(compared(&root, &[]), Ok(()));
    }

    /// An allowed set the harness does not read is refused before any file is compared, so that no
    /// unchecked list reaches the compare.
    #[test]
    fn an_allowed_file_that_could_excuse_a_settings_file_does_not_reach_the_end_compare() {
        let root = configured("end-unchecked");
        for broad in ["**", "*", "rules/**"] {
            let refused = compared(&root, &[broad]).expect_err(broad);
            assert!(refused.contains("the allowed file"), "{broad}: {refused}");
        }
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
        let found =
            turns_recorded(&account(), &root, &pinned(&root), Path::new("")).expect("a count");
        // Every turn has an identity: a name, or the place and the bytes of its line.
        assert_eq!(found.identities.len(), 3 + 2 + 6);
        assert_eq!(
            Recorded {
                identities: Identities::default(),
                ..found
            },
            Recorded {
                turns: 3 + 2 + 3 + 3,
                unnamed: 6,
                files: 6,
                by_uuid: 3,
                by_other_name: 2,
                identities: Identities::default(),
                // The non-UUID name is a digit: its form is one digit, and no value is kept.
                forms: vec!["9".to_owned()],
            }
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
            row(
                70,
                Some("/private/Users/person/.codex/bin/secret-name/codex"),
            ),
            row(71, Some("/USERS/PERSON/.CODEX/bin/secret-name/codex")),
            row(72, Some("/Users/person/.codex/bin/secret-name/codex")),
            row(73, Some("/Users/person/bin/secret-name/codex")),
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

    /// The name a parent gave a process is the first field of the command line the system keeps,
    /// whole, with its spaces; a command line with no first field gives none.
    #[test]
    fn the_name_a_parent_gave_is_the_first_field_of_the_command_line() {
        assert_eq!(
            first_argument(b"codex\0--flag\0value\0").as_deref(),
            Some("codex")
        );
        assert_eq!(
            first_argument(b"/opt/the agent/codex\0a\0").as_deref(),
            Some("/opt/the agent/codex")
        );
        assert_eq!(first_argument(b"codex").as_deref(), Some("codex"));
        assert_eq!(first_argument(b""), None);
        assert_eq!(first_argument(b"\0a\0"), None);
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
            let mut command = std::process::Command::new(&path);
            command
                .arg0(name)
                .args([
                    "--ignored",
                    "--exact",
                    "held::tests::a_process_that_waits_to_be_listed",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            spawn_retrying_when_busy(&mut command).expect("it starts")
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
        let mut command = std::process::Command::new(&codex);
        command
            .args([
                "--ignored",
                "--exact",
                "held::tests::a_process_that_waits_to_be_listed",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let mut running = spawn_retrying_when_busy(&mut command).expect("it starts");
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
        let guard = PersonPlan::Trees(&[".agent"]).take(&home);
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
    fn a_change_of_a_guarded_file_since_the_start_stops_the_charge() {
        let home = claude_home("before-charge-files");
        let guard = claude_plan().take(&home);
        assert_eq!(unchanged_before_the_charge(&guard), Ok(()));
        std::fs::write(home.join(".claude/settings.json"), b"two").expect("a write");
        assert_eq!(
            unchanged_before_the_charge(&guard),
            Err(
                "guarded_file_changed: ~/.claude/settings.json changed while the run ran"
                    .to_owned()
            )
        );
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
    fn a_record_beyond_the_audits_bounds_is_incomplete_and_none_of_it_is_read() {
        let run = scratch("record-bounds");
        let sessions = Path::new("agent-config/sessions");
        let line = r#"{"type":"task_started","turn_id":"019a0000-0000-7000-8000-0000000000aa"}"#;
        std::fs::create_dir_all(run.join("agent-config/sessions/2026")).expect("a record");
        std::fs::write(
            run.join("agent-config/sessions/2026/own.jsonl"),
            format!("{line}\n"),
        )
        .expect("a conversation");
        // A sparse file far over the bound: a file the agent left, of a size that no memory holds.
        let sparse = std::fs::File::create(run.join("agent-config/sessions/2026/large.jsonl"))
            .expect("a file");
        sparse.set_len(256 << 20).expect("a sparse file");
        let within = Limits {
            file: 1 << 10,
            entries: 100,
            ..Limits::RECORD
        };
        let mut read = Vec::new();
        let why = read_record_within(
            &run,
            &pinned(&run),
            sessions,
            within,
            &mut |place, content| read.push((place.to_vec(), content.len())),
            &mut |_, _| {},
        )
        .expect_err("a file above the bound");
        assert!(why.starts_with(RECORD_BEYOND_THE_BOUNDS), "{why}");
        assert!(why.contains("entries"), "{why}");
        assert!(
            !why.contains("large.jsonl") && !why.contains("agent-config"),
            "no name: {why}"
        );
        assert!(
            read.iter()
                .all(|(place, _)| !place.ends_with(b"large.jsonl")),
            "no byte of the large file was handed on"
        );
        // The audit says it is incomplete: a stop of its own, and not a record that was refused.
        assert_eq!(
            audit_turns(true, 1, &Err(why.clone())),
            Audit::Incomplete(why)
        );
        // The same through the audit's own count, at the bound it has: the file is above it.
        let counted = turns_recorded(&account(), &run, &pinned(&run), sessions)
            .expect_err("a file above the audit's bound");
        assert!(counted.starts_with(RECORD_BEYOND_THE_BOUNDS), "{counted}");
        // More entries than the walk lists: the walk stops at the count and reads no more.
        std::fs::remove_file(run.join("agent-config/sessions/2026/large.jsonl")).expect("removed");
        for index in 0..8 {
            std::fs::write(
                run.join(format!("agent-config/sessions/2026/more-{index}.jsonl")),
                format!("{line}\n"),
            )
            .expect("a conversation");
        }
        let few = Limits {
            file: 1 << 10,
            entries: 4,
            ..Limits::RECORD
        };
        let mut handed = 0;
        let why = read_record_within(
            &run,
            &pinned(&run),
            sessions,
            few,
            &mut |_, _| handed += 1,
            &mut |_, _| {},
        )
        .expect_err("more entries than the bound");
        assert!(why.starts_with(RECORD_BEYOND_THE_BOUNDS), "{why}");
        assert!(handed <= few.entries, "{handed} files read");
        // Within the bounds the same record is read whole.
        let wide = Limits {
            file: 1 << 10,
            entries: 100,
            ..Limits::RECORD
        };
        assert_eq!(
            read_record_within(
                &run,
                &pinned(&run),
                sessions,
                wide,
                &mut |_, _| {},
                &mut |_, _| {}
            ),
            Ok(9)
        );
    }

    #[test]
    fn the_two_scans_of_a_run_read_from_one_budget_of_bytes() {
        let run = scratch("scan-budget");
        for index in 0..6 {
            std::fs::write(run.join(format!("f{index}")), "x".repeat(1000)).expect("a file");
        }
        let rules = RunRules::new(&pinned(&run), Vec::new());
        let held = HeldKeys {
            key: Some(("LOGIN".to_owned(), "login-value-0123456789".to_owned())),
            others: vec!["other-key-value-9876543210".to_owned()],
        };
        let scan = RunScan::of_within(&run, &rules, &held, ScanBytes::new(3 << 10));
        let unread = |scan: &KeyScan| scan.unread.len();
        // The first scan reads three files of the six; the second finds the budget spent.
        assert_eq!(scan.key.as_ref().map(|(_, scan)| unread(scan)), Some(3));
        assert_eq!(scan.others.as_ref().map(unread), Some(6));
    }

    #[test]
    fn a_record_of_many_files_that_each_fit_is_incomplete_past_the_totals_in_all() {
        let run = scratch("record-totals");
        let sessions = Path::new("agent-config/sessions");
        let line = |name: &str| format!("{{\"type\":\"task_started\",\"turn_id\":\"{name}\"}}\n");
        std::fs::create_dir_all(run.join("agent-config/sessions/2026")).expect("a record");
        // Six files of a little over a kilobyte that each fit a bound of two, and name one turn.
        for index in 0..6 {
            std::fs::write(
                run.join(format!("agent-config/sessions/2026/f{index}.jsonl")),
                format!("{}{}\n", line("a1"), " ".repeat(1000)),
            )
            .expect("a conversation");
        }
        // The bytes read in all: with a bound of three kilobytes, the third file is not read.
        let bytes = Limits {
            file: 2 << 10,
            bytes: 3 << 10,
            ..Limits::RECORD
        };
        let mut handed = 0;
        let why = read_record_within(
            &run,
            &pinned(&run),
            sessions,
            bytes,
            &mut |_, _| handed += 1,
            &mut |_, _| {},
        )
        .expect_err("more bytes than the bound in all");
        assert!(why.starts_with(RECORD_BEYOND_THE_BOUNDS), "{why}");
        assert!(why.contains("bytes"), "{why}");
        assert!(handed <= 2, "{handed} files were read");
        // The turn names kept in all: the same name in six files is six entries, and past the
        // bound of three the audit stops and says so, with no content.
        let names = Limits {
            file: 2 << 10,
            names: 3,
            ..Limits::RECORD
        };
        let why = turns_recorded_within(&account(), &run, &pinned(&run), sessions, names)
            .expect_err("more names than the bound in all");
        assert!(why.starts_with(RECORD_BEYOND_THE_BOUNDS), "{why}");
        assert!(why.contains("names") && !why.contains("a1"), "{why}");
        assert_eq!(
            audit_turns(true, 1, &Err(why.clone())),
            Audit::Incomplete(why)
        );
        // The bytes of the names kept in all: a name is kept with its file's place, so a few names
        // in deep places are past a bound of a few bytes though they are few.
        let bytes_of_names = Limits {
            file: 2 << 10,
            name_bytes: 40,
            ..Limits::RECORD
        };
        let why = turns_recorded_within(&account(), &run, &pinned(&run), sessions, bytes_of_names)
            .expect_err("more bytes of names than the bound in all");
        assert!(why.starts_with(RECORD_BEYOND_THE_BOUNDS), "{why}");
        assert!(
            why.contains("bytes of them") && !why.contains("a1"),
            "{why}"
        );
        // Within the bounds the same record is counted.
        let whole = Limits {
            file: 2 << 10,
            ..Limits::RECORD
        };
        assert_eq!(
            turns_recorded_within(&account(), &run, &pinned(&run), sessions, whole)
                .map(|found| found.by_other_name),
            Ok(6)
        );
        // Entries in all: four levels that each list five entries are twenty, and the walk stops
        // at its bound of twelve though no level lists more than the bound.
        let deep = scratch("record-deep");
        let mut place = deep.join("agent-config/sessions");
        for _ in 0..4 {
            std::fs::create_dir_all(&place).expect("a level");
            for file in 0..4 {
                std::fs::write(place.join(format!("f{file}.jsonl")), "{}\n").expect("a file");
            }
            place = place.join("next");
        }
        let few = Limits {
            entries: 12,
            ..Limits::RECORD
        };
        let why = read_record_within(
            &deep,
            &pinned(&deep),
            sessions,
            few,
            &mut |_, _| {},
            &mut |_, _| {},
        )
        .expect_err("more entries listed in all than the bound");
        assert!(why.starts_with(RECORD_BEYOND_THE_BOUNDS), "{why}");
        // A directory that lists more entries than the bound is refused when it is listed, before
        // any entry of it is looked at: none of its files is read.
        let wide = scratch("record-wide");
        std::fs::create_dir_all(wide.join("agent-config/sessions")).expect("a directory");
        for file in 0..15 {
            std::fs::write(
                wide.join(format!("agent-config/sessions/f{file}.jsonl")),
                "{}\n",
            )
            .expect("a file");
        }
        let mut handed = 0;
        let why = read_record_within(
            &wide,
            &pinned(&wide),
            sessions,
            few,
            &mut |_, _| handed += 1,
            &mut |_, _| {},
        )
        .expect_err("a directory that lists more entries than the bound");
        assert!(why.starts_with(RECORD_BEYOND_THE_BOUNDS), "{why}");
        assert_eq!(handed, 0, "no file of the directory was read");
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

    /// The files the claude-code entry guards, relative to the person's home.
    const CLAUDE_GUARDED: [&str; 3] = [
        ".claude/.credentials.json",
        ".claude/.device-keys.json",
        ".claude/settings.json",
    ];

    /// The name a run's directory has in the tests below, and the run's mark.
    const RUN_NAME: &str = "krm-3f9a61c2";
    const RUN_MARK: &str = "mark-77d0e5b4";

    /// A home of the test's own that holds the files the claude-code entry names, the one it shares
    /// and a transcript.
    fn claude_home(name: &str) -> PathBuf {
        let home = scratch(name);
        std::fs::create_dir_all(home.join(".claude/projects/-w")).expect("directories");
        for file in CLAUDE_GUARDED {
            std::fs::write(home.join(file), b"one").expect("a file");
        }
        std::fs::write(home.join(".claude/projects/-w/session.jsonl"), b"{}\n")
            .expect("a transcript");
        std::fs::write(home.join(".claude.json"), br#"{"theme":"dark"}"#).expect("a file");
        home
    }

    /// The plan the claude-code entry's lists give.
    fn claude_plan() -> PersonPlan {
        let guarded: Vec<String> = CLAUDE_GUARDED
            .iter()
            .map(|file| (*file).to_owned())
            .collect();
        PersonPlan::of("claude-code", &guarded, &[".claude.json".to_owned()], &[]).expect("a plan")
    }

    /// The stops of a guard taken from `home` and compared at the end for the run's name and mark.
    fn stops_at_the_end(guard: &PersonGuard) -> Vec<Stop> {
        guard.compare_at_the_end(&[RUN_NAME, RUN_MARK]).0
    }

    #[test]
    fn an_entry_is_guarded_by_its_own_person_tree_or_its_own_guarded_files() {
        assert_eq!(
            PersonPlan::of("codex", &[], &[], &[]),
            Ok(PersonPlan::Trees(&[".codex"]))
        );
        assert_eq!(
            claude_plan(),
            PersonPlan::Files {
                guarded: CLAUDE_GUARDED
                    .iter()
                    .map(|file| (*file).to_owned())
                    .collect(),
                shared: vec![".claude.json".to_owned()],
            }
        );
        let refused = PersonPlan::of("qoder-cli", &[], &[], &[]).expect_err("no guard");
        assert!(
            refused.contains("qoder-cli") && refused.contains("no person tree"),
            "{refused}"
        );
    }

    #[test]
    fn a_write_to_a_guarded_file_by_another_process_stops_the_run() {
        let home = claude_home("files-write");
        let guard = claude_plan().take(&home);
        let (stops, evidence) = guard.compare();
        assert!(stops.is_empty(), "{stops:?}");
        assert_eq!(evidence["files"][2]["changed"], json!(false));
        // A process of another program appends to one of the three files.
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", r#"printf more >> "$1""#, "sh"])
            .arg(home.join(".claude/settings.json"))
            .status()
            .expect("a shell");
        assert!(status.success());
        let (stops, evidence) = guard.compare();
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(stops[0].0, "guarded_file_changed");
        assert_eq!(
            stops[0].1,
            "~/.claude/settings.json changed while the run ran"
        );
        assert_eq!(evidence["files"][2]["changed"], json!(true));
        assert_eq!(evidence["files"][0]["changed"], json!(false));
        // The end of the run sees it too.
        assert_eq!(stops_at_the_end(&guard).len(), 1);
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_transcript_written_below_the_projects_directory_does_not_stop_the_run() {
        let home = claude_home("files-transcript");
        let guard = claude_plan().take(&home);
        // A whole-tree guard over the same directory sees every one of these writes.
        let whole = MetaGuard::take(&home, &[".claude"]);
        let projects = home.join(".claude/projects");
        std::fs::create_dir_all(projects.join("-another")).expect("a directory");
        std::fs::write(projects.join("-another/new.jsonl"), b"{}\n").expect("a new transcript");
        std::fs::write(projects.join("-w/session.jsonl"), b"{}\n{}\n").expect("an appended one");
        assert!(!whole.compare().0.is_empty(), "the writes are changes");
        let (stops, evidence) = guard.compare();
        assert!(stops.is_empty(), "{stops:?}");
        assert!(
            evidence["files"]
                .as_array()
                .expect("a list")
                .iter()
                .all(|file| file["changed"] == json!(false)),
            "{evidence}"
        );
        assert!(stops_at_the_end(&guard).is_empty());
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_guarded_file_replaced_removed_or_changed_in_mode_stops_the_run() {
        use std::os::unix::fs::PermissionsExt as _;
        let file = ".claude/settings.json";
        // Replaced by another file of the same size, which has another inode.
        let home = claude_home("files-replaced");
        let guard = claude_plan().take(&home);
        std::fs::write(home.join("other"), b"one").expect("another file");
        std::fs::rename(home.join("other"), home.join(file)).expect("a replacement");
        assert_eq!(guard.compare().0.len(), 1);
        // Removed, and a file that was not there made.
        let guard = claude_plan().take(&home);
        std::fs::remove_file(home.join(file)).expect("removed");
        assert_eq!(guard.compare().0.len(), 1);
        let guard = claude_plan().take(&home);
        std::fs::write(home.join(file), b"back").expect("a new file");
        assert_eq!(guard.compare().0.len(), 1);
        // The permissions of a file changed, which moves neither its size nor its content.
        let guard = claude_plan().take(&home);
        let mode = std::fs::metadata(home.join(file))
            .expect("a look")
            .permissions()
            .mode();
        std::fs::set_permissions(
            home.join(file),
            std::fs::Permissions::from_mode(mode ^ 0o001),
        )
        .expect("a mode");
        assert_eq!(guard.compare().0.len(), 1);
        // Nothing done, nothing seen.
        let guard = claude_plan().take(&home);
        assert!(guard.compare().0.is_empty());
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_change_of_the_shared_file_that_names_the_runs_directory_or_mark_stops_the_run() {
        let home = claude_home("shared-names");
        let guard = claude_plan().take(&home);
        // What the agent writes for a folder it was started in, and a field the test plants to see
        // that nothing of the file is kept.
        let planted = "PLANTED-TEXT-OF-THE-FILE";
        std::fs::write(
            home.join(".claude.json"),
            format!(r#"{{"projects":{{"/private/tmp/{RUN_NAME}/w":{{}}}},"note":"{planted}"}}"#),
        )
        .expect("a write");
        // The metadata look, before a charge, reads no shared file: the one read is at the end.
        assert!(guard.compare().0.is_empty());
        let (stops, evidence) = guard.compare_at_the_end(&[RUN_NAME, RUN_MARK]);
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(stops[0].0, "guarded_file_changed");
        assert_eq!(
            stops[0].1,
            "~/.claude.json now holds the run's directory name or mark"
        );
        assert_eq!(evidence["shared"][0]["holds_the_run"], json!(true));
        let said = format!("{stops:?}{evidence}");
        assert!(!said.contains(planted), "{said}");
        // The mark alone does the same.
        std::fs::write(
            home.join(".claude.json"),
            format!(r#"{{"id":"{RUN_MARK}"}}"#),
        )
        .expect("a write");
        assert_eq!(stops_at_the_end(&guard).len(), 1);
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_change_of_the_shared_file_that_names_neither_does_not_stop_the_run() {
        let home = claude_home("shared-neither");
        let guard = claude_plan().take(&home);
        std::fs::write(
            home.join(".claude.json"),
            br#"{"projects":{"/home/person/work":{}},"numStartups":99}"#,
        )
        .expect("a write");
        let (stops, evidence) = guard.compare_at_the_end(&[RUN_NAME, RUN_MARK]);
        assert!(stops.is_empty(), "{stops:?}");
        assert_eq!(evidence["shared"][0]["holds_the_run"], json!(false));
        assert_eq!(evidence["shared"][0]["unreadable"], json!(false));
        // A person with no such file has nothing to hold the run's name.
        std::fs::remove_file(home.join(".claude.json")).expect("removed");
        assert!(stops_at_the_end(&guard).is_empty());
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn an_owner_change_of_a_guarded_file_stops_the_run() {
        let home = claude_home("files-owner");
        let guard = claude_plan().take(&home);
        let Watch::Files(files) = &guard.watch else {
            panic!("a claude-code plan guards files");
        };
        let look = |relative: &str| seen_by_lstat(&home.join(relative));
        // As things stand, nothing is said.
        assert!(files.compared(&look).0.is_empty());
        // The same file, to the last time and byte, under another owner: only the owner differs.
        let another_owner = |relative: &str| {
            look(relative).map(|seen| {
                seen.map(|mut seen| {
                    if relative == ".claude/.credentials.json" {
                        seen.owner += 1;
                    }
                    seen
                })
            })
        };
        let (stops, evidence) = files.compared(&another_owner);
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(stops[0].0, "guarded_file_changed");
        assert_eq!(
            stops[0].1,
            "~/.claude/.credentials.json has another owner than when the run started"
        );
        assert_eq!(evidence[0]["owner_changed"], json!(true));
        assert_eq!(evidence[0]["changed"], json!(false));
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    /// Runs `work` on a thread of its own and returns what it returned, or none where it did not
    /// finish within `seconds`: a read of a file that has no writer does not.
    fn within<T: Send + 'static>(
        seconds: u64,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<T> {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(work());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(seconds))
            .ok()
    }

    /// A named pipe at `path`: opening it to read waits until another process opens it to write.
    fn make_pipe(path: &Path) {
        let status = std::process::Command::new("/usr/bin/mkfifo")
            .arg(path)
            .status()
            .expect("mkfifo runs");
        assert!(status.success(), "a named pipe");
    }

    #[test]
    fn the_guard_reads_no_content_of_a_guarded_file_and_none_of_the_shared_file_before_the_end() {
        use std::os::unix::fs::PermissionsExt as _;
        // A guarded file that is a named pipe, which a read of would wait on for ever, and one the
        // user cannot read: both are looked at, taken and compared to the end.
        let home = claude_home("no-read");
        let pipe = home.join(".claude/.credentials.json");
        std::fs::remove_file(&pipe).expect("removed");
        make_pipe(&pipe);
        std::fs::set_permissions(
            home.join(".claude/.device-keys.json"),
            std::fs::Permissions::from_mode(0o000),
        )
        .expect("no access");
        let plan = claude_plan();
        let looked = within(20, {
            let (home, plan) = (home.clone(), plan);
            move || {
                let guard = plan.take(&home);
                let mut stops = guard.compare().0;
                stops.extend(guard.compare_at_the_end(&[RUN_NAME, RUN_MARK]).0);
                stops
            }
        });
        assert_eq!(
            looked,
            Some(Vec::new()),
            "the guard did not finish: it read a guarded file, or stopped on one it could not read"
        );
        // The shared file as a named pipe, made after the take: compared before the end, with no
        // read of it.
        let looked = within(20, {
            let (home, plan) = (home.clone(), claude_plan());
            move || {
                let guard = plan.take(&home);
                std::fs::remove_file(home.join(".claude.json")).expect("removed");
                make_pipe(&home.join(".claude.json"));
                guard.compare().0
            }
        });
        assert_eq!(
            looked,
            Some(Vec::new()),
            "the guard did not finish: it read the shared file before the end"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    /// A process of this user that waits, called `name`: a copy of this test program that runs the
    /// one test that waits.
    fn waiting_agent(directory: &Path, name: &str) -> std::process::Child {
        let path = directory.join(name);
        std::fs::copy(std::env::current_exe().expect("this program"), &path)
            .expect("a program called as the agent");
        let mut command = std::process::Command::new(&path);
        command
            .args([
                "--ignored",
                "--exact",
                "held::tests::a_process_that_waits_to_be_listed",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        spawn_retrying_when_busy(&mut command).expect("it starts")
    }

    /// The processes the listing of the agent `agent` shows once it shows `id`, or after twenty
    /// seconds.
    fn listed_with(id: u32, agent: &str) -> Vec<u32> {
        let started = std::time::Instant::now();
        loop {
            let seen = other_agent_processes(agent, None).expect("a listing");
            if seen.contains(&id) || started.elapsed() > std::time::Duration::from_secs(20) {
                return seen;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[test]
    fn another_claude_process_does_not_refuse_a_claude_code_run() {
        let directory = scratch("claude-beside");
        let root = scratch("claude-beside-run");
        let mut running = waiting_agent(&directory, "claude");
        let id = running.id();
        let seen = listed_with(id, "claude");
        let plan = claude_plan();
        let at_the_start = plan.other_agents("claude", None);
        let at_the_charge = plan.other_agents("claude", Some(&root));
        let home = claude_home("claude-beside-home");
        let by_the_guard = plan.take(&home).other_agents("claude", Some(&root));
        running.kill().expect("ended by its own handle");
        running.wait().expect("reaped");
        std::fs::remove_dir_all(&directory).expect("clean up");
        std::fs::remove_dir_all(&root).expect("clean up");
        std::fs::remove_dir_all(&home).expect("clean up");
        // The process is there to be found, and the claude-code entry is not refused for it, at
        // the start (no run's root) or at the charge (the run's root).
        assert!(
            seen.contains(&id),
            "the listing did not count the process ({} counted)",
            seen.len()
        );
        assert_eq!(at_the_start, Ok(Vec::new()));
        assert_eq!(at_the_charge, Ok(Vec::new()));
        assert_eq!(by_the_guard, Ok(Vec::new()));
    }

    #[test]
    fn a_codex_process_still_refuses_a_codex_run_at_the_start_and_at_the_charge() {
        let directory = scratch("codex-beside");
        let root = scratch("codex-beside-run");
        let mut running = waiting_agent(&directory, "codex");
        let id = running.id();
        let seen = listed_with(id, "codex");
        let plan = PersonPlan::of("codex", &[], &[], &[]).expect("a plan");
        let at_the_start = plan.other_agents("codex", None).expect("a listing");
        let at_the_charge = plan.other_agents("codex", Some(&root)).expect("a listing");
        running.kill().expect("ended by its own handle");
        running.wait().expect("reaped");
        std::fs::remove_dir_all(&directory).expect("clean up");
        std::fs::remove_dir_all(&root).expect("clean up");
        // A failure says how many were counted, not which.
        assert!(
            seen.contains(&id),
            "the listing did not count the process ({} counted)",
            seen.len()
        );
        assert!(
            at_the_start.contains(&id),
            "the start did not count the process ({} counted)",
            at_the_start.len()
        );
        assert!(
            at_the_charge.contains(&id),
            "the charge did not count the process ({} counted)",
            at_the_charge.len()
        );
    }

    #[test]
    fn a_link_at_a_guarded_name_is_refused_when_the_guard_is_taken() {
        let home = claude_home("guarded-link");
        let target = home.join("elsewhere.json");
        std::fs::write(&target, b"one").expect("a file");
        let name = home.join(".claude/settings.json");
        std::fs::remove_file(&name).expect("removed");
        std::os::unix::fs::symlink(&target, &name).expect("a link");
        let taken =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| claude_plan().take(&home)));
        let why = panic_text(&*taken.expect_err("the take refuses a link at a guarded name"));
        assert_eq!(
            why,
            "the person's file ~/.claude/settings.json is a symbolic link, which the guard does \
             not follow, so a write to its target would go unseen: replace the link with a file \
             before a real run"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_link_at_a_shared_name_is_refused_when_the_guard_is_taken() {
        let home = claude_home("shared-link-at-the-take");
        let target = home.join("elsewhere.json");
        std::fs::write(&target, b"one").expect("a file");
        std::fs::remove_file(home.join(".claude.json")).expect("removed");
        std::os::unix::fs::symlink(&target, home.join(".claude.json")).expect("a link");
        let taken =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| claude_plan().take(&home)));
        let why = panic_text(&*taken.expect_err("the take refuses a link at a shared name"));
        assert_eq!(
            why,
            "the person's file ~/.claude.json is a symbolic link, which the guard does not read, \
             so it could not be searched for the run's name at the end: replace the link with a \
             file before a real run"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    /// A cell that holds nothing: no identity seen and no look failed.
    fn clean_looks() -> Looks {
        Looks::of(Known {
            seen: BTreeSet::new(),
            unlooked: false,
        })
    }

    /// What the end read says of the shared file `name` it did not read, for `reason`.
    fn not_read_at(name: &str, reason: &str) -> String {
        format!(
            "~/{name} {reason}, so it is not known whether it holds the run's directory name or \
             mark"
        )
    }

    /// What the end read says of the shared file `.claude.json` it did not read, for `reason`.
    fn not_read(reason: &str) -> String {
        not_read_at(".claude.json", reason)
    }

    /// What the end read says after the path of a shared file when a look of a guarded name has
    /// failed, has seen a link or has not answered in time, or a look of a path that must not exist
    /// has found it or has failed.
    const UNLOOKED: &str = "is not read, because a look of a guarded name has failed, has seen a \
                            link or has not answered in time, or a look of a path that must not \
                            exist has found it or has failed, since the run started, and this \
                            file may be the one it names";

    #[test]
    fn the_unlooked_refusal_names_each_look_that_causes_it() {
        assert_eq!(
            format!("~/.claude.json {}", Unread::Unlooked.said()),
            not_read(UNLOOKED)
        );
    }

    /// What the take refuses a shared file with, for `reason`: the end read's text, after the
    /// person's file.
    fn take_not_read(reason: &str) -> String {
        format!("the person's file {}", not_read(reason))
    }

    /// The text of the panic with which the take of the claude-code guard from `home` is refused.
    fn why_the_take_is_refused(home: &Path) -> String {
        let taken =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| claude_plan().take(home)));
        panic_text(&*taken.expect_err("the take refuses a shared file the end read would refuse"))
    }

    #[test]
    fn a_named_pipe_at_the_shared_name_is_refused_when_the_guard_is_taken() {
        let home = claude_home("take-pipe");
        std::fs::remove_file(home.join(".claude.json")).expect("removed");
        make_pipe(&home.join(".claude.json"));
        assert_eq!(
            why_the_take_is_refused(&home),
            take_not_read("is not a regular file and is not read")
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_directory_at_the_shared_name_is_refused_when_the_guard_is_taken() {
        let home = claude_home("take-directory");
        std::fs::remove_file(home.join(".claude.json")).expect("removed");
        std::fs::create_dir(home.join(".claude.json")).expect("a directory");
        assert_eq!(
            why_the_take_is_refused(&home),
            take_not_read("is not a regular file and is not read")
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_second_name_at_the_shared_name_is_refused_when_the_guard_is_taken() {
        let home = claude_home("take-second-name");
        std::fs::remove_file(home.join(".claude.json")).expect("removed");
        std::fs::hard_link(
            home.join(".claude/settings.json"),
            home.join(".claude.json"),
        )
        .expect("a second name");
        assert_eq!(
            why_the_take_is_refused(&home),
            take_not_read("has more than one name and is not read")
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_shared_file_larger_than_the_limit_is_refused_when_the_guard_is_taken() {
        let home = claude_home("take-large");
        let file = std::fs::File::create(home.join(".claude.json")).expect("a file");
        file.set_len(SHARED_LIMIT + 1).expect("a size");
        assert_eq!(
            why_the_take_is_refused(&home),
            take_not_read("is larger than 16777216 bytes and is not read")
        );
        // A file of the limit's size is taken.
        file.set_len(SHARED_LIMIT).expect("a size");
        let taken =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| claude_plan().take(&home)));
        assert!(taken.is_ok(), "a file of the limit's size is refused");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_file_with_no_name_left_is_refused_by_the_shared_checks() {
        let home = scratch("refusal-no-name");
        let path = home.join("file");
        std::fs::write(&path, b"one").expect("a file");
        let file = std::fs::File::open(&path).expect("opened");
        let none = BTreeSet::new();
        assert_eq!(refusal_of(&file.metadata().expect("a look"), &none), None);
        // The only name is removed while the file is open.
        std::fs::remove_file(&path).expect("removed");
        assert_eq!(
            refusal_of(&file.metadata().expect("a look"), &none),
            Some(Unread::Gone)
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_file_with_the_device_and_inode_of_a_guarded_file_is_refused_by_the_shared_checks() {
        use std::os::unix::fs::MetadataExt as _;
        let home = scratch("refusal-identity");
        std::fs::write(home.join("file"), b"one").expect("a file");
        let metadata = std::fs::metadata(home.join("file")).expect("a look");
        let mut seen = BTreeSet::new();
        assert_eq!(refusal_of(&metadata, &seen), None);
        // The device alone, or the inode alone, is another file.
        seen.insert((metadata.dev() + 1, metadata.ino()));
        seen.insert((metadata.dev(), metadata.ino() + 1));
        assert_eq!(refusal_of(&metadata, &seen), None);
        seen.insert((metadata.dev(), metadata.ino()));
        assert_eq!(refusal_of(&metadata, &seen), Some(Unread::GuardedFile));
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    /// The stops of the end compare of a guard taken from `home` after `home` stands as `change`
    /// makes it, on a thread with a bound: none where it did not finish.
    fn end_stops_after(home: &Path, change: impl FnOnce(&Path)) -> Option<Vec<Stop>> {
        let plan = claude_plan();
        let guard = plan.take(home);
        change(home);
        within(20, move || stops_at_the_end(&guard))
    }

    /// A text only a guarded file holds, which no read of one may find.
    const PLANTED_IN_CREDENTIALS: &str = "krm-3f9a61c2-in-the-credentials";

    #[test]
    fn a_named_pipe_made_at_the_shared_name_after_the_take_is_refused_and_not_waited_on() {
        let home = claude_home("shared-pipe");
        let stops = end_stops_after(&home, |home| {
            std::fs::remove_file(home.join(".claude.json")).expect("removed");
            make_pipe(&home.join(".claude.json"));
        });
        assert_eq!(
            stops.map(|stops| stops.into_iter().map(|(_, why)| why).collect::<Vec<_>>()),
            Some(vec![not_read("is not a regular file and is not read")]),
            "the end read waited on a named pipe, or read it"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_directory_made_at_the_shared_name_after_the_take_is_refused() {
        let home = claude_home("shared-directory");
        let stops = end_stops_after(&home, |home| {
            std::fs::remove_file(home.join(".claude.json")).expect("removed");
            std::fs::create_dir(home.join(".claude.json")).expect("a directory");
        });
        assert_eq!(
            stops.map(|stops| stops.into_iter().map(|(_, why)| why).collect::<Vec<_>>()),
            Some(vec![not_read("is not a regular file and is not read")])
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_symbolic_link_at_the_shared_name_is_refused_and_its_target_is_not_read() {
        let home = claude_home("shared-link");
        let stops = end_stops_after(&home, |home| {
            std::fs::write(
                home.join(".claude/.credentials.json"),
                PLANTED_IN_CREDENTIALS,
            )
            .expect("a write");
            std::fs::remove_file(home.join(".claude.json")).expect("removed");
            std::os::unix::fs::symlink(
                home.join(".claude/.credentials.json"),
                home.join(".claude.json"),
            )
            .expect("a link");
        })
        .expect("the end compare finished");
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(
            said.contains(&not_read("is a symbolic link and is not read").as_str()),
            "{said:?}"
        );
        assert!(
            !said.iter().any(|why| why.contains("now holds")),
            "the target of the link was read: {said:?}"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_second_name_of_a_guarded_file_at_the_shared_name_is_refused_and_not_read() {
        let home = claude_home("shared-hard-link");
        std::fs::write(
            home.join(".claude/.credentials.json"),
            PLANTED_IN_CREDENTIALS,
        )
        .expect("a write");
        let stops = end_stops_after(&home, |home| {
            std::fs::remove_file(home.join(".claude.json")).expect("removed");
            std::fs::hard_link(
                home.join(".claude/.credentials.json"),
                home.join(".claude.json"),
            )
            .expect("a second name");
        })
        .expect("the end compare finished");
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(
            said.contains(&not_read("has more than one name and is not read").as_str()),
            "{said:?}"
        );
        assert!(
            !said.iter().any(|why| why.contains("now holds")),
            "the second name of a guarded file was read: {said:?}"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn the_shared_file_made_the_object_of_a_guarded_name_after_the_take_is_not_read() {
        let home = claude_home("shared-guarded-object");
        std::fs::write(
            home.join(".claude.json"),
            format!(r#"{{"id":"{RUN_NAME}"}}"#),
        )
        .expect("a write");
        let stops = end_stops_after(&home, |home| {
            std::fs::remove_file(home.join(".claude/.device-keys.json")).expect("removed");
            std::os::unix::fs::symlink(
                home.join(".claude.json"),
                home.join(".claude/.device-keys.json"),
            )
            .expect("a link");
        })
        .expect("the end compare finished");
        // The end's own look sees the link at the guarded name, so no shared read goes on.
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(said.contains(&not_read(UNLOOKED).as_str()), "{said:?}");
        assert!(
            !said.iter().any(|why| why.contains("now holds")),
            "the shared file was read as a guarded file's object: {said:?}"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    /// Makes the settings file of the claude-code entry hold the run's directory name, which a read
    /// of it would find.
    fn name_the_run_in_the_settings(home: &Path) {
        std::fs::write(
            home.join(".claude/settings.json"),
            format!(r#"{{"id":"{RUN_NAME}"}}"#),
        )
        .expect("a write");
    }

    /// Asserts that the end read refused the shared file as a guarded file and read none of it.
    fn assert_refused_as_a_guarded_file(stops: &[Stop]) {
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(
            said.contains(&not_read("is the same file as a guarded file and is not read").as_str()),
            "{said:?}"
        );
        assert!(
            !said.iter().any(|why| why.contains("now holds")),
            "a guarded file was read at the shared name: {said:?}"
        );
    }

    #[test]
    fn a_guarded_file_moved_over_the_shared_name_after_the_take_is_not_read() {
        let home = claude_home("shared-guarded-moved");
        name_the_run_in_the_settings(&home);
        let stops = end_stops_after(&home, |home| {
            std::fs::rename(
                home.join(".claude/settings.json"),
                home.join(".claude.json"),
            )
            .expect("a move");
        })
        .expect("the end compare finished");
        assert_refused_as_a_guarded_file(&stops);
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_guarded_file_at_the_shared_name_is_not_read_once_its_guarded_name_is_gone() {
        let home = claude_home("shared-second-name-gone");
        name_the_run_in_the_settings(&home);
        let stops = end_stops_after(&home, |home| {
            std::fs::remove_file(home.join(".claude.json")).expect("removed");
            std::fs::hard_link(
                home.join(".claude/settings.json"),
                home.join(".claude.json"),
            )
            .expect("a second name");
            std::fs::remove_file(home.join(".claude/settings.json")).expect("removed");
        })
        .expect("the end compare finished");
        assert_refused_as_a_guarded_file(&stops);
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_file_put_at_the_old_guarded_name_does_not_hide_the_guarded_file_at_the_shared_name() {
        let home = claude_home("shared-guarded-replaced");
        name_the_run_in_the_settings(&home);
        let stops = end_stops_after(&home, |home| {
            std::fs::rename(
                home.join(".claude/settings.json"),
                home.join(".claude.json"),
            )
            .expect("a move");
            std::fs::write(home.join(".claude/settings.json"), b"another file").expect("a write");
        })
        .expect("the end compare finished");
        assert_refused_as_a_guarded_file(&stops);
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_file_seen_at_a_guarded_name_by_a_later_look_is_not_read_at_the_shared_name() {
        let home = claude_home("shared-guarded-seen-later");
        let guard = claude_plan().take(&home);
        // Another file takes the guarded name, and the look before a charge sees it there.
        std::fs::write(
            home.join("replacement"),
            format!(r#"{{"id":"{RUN_NAME}"}}"#),
        )
        .expect("a write");
        std::fs::rename(home.join("replacement"), home.join(".claude/settings.json"))
            .expect("a replacement");
        assert_eq!(guard.compare().0.len(), 1);
        // Then that file is moved over the shared name, and no look sees it at a guarded name again.
        std::fs::rename(
            home.join(".claude/settings.json"),
            home.join(".claude.json"),
        )
        .expect("a move");
        let stops = within(20, move || stops_at_the_end(&guard)).expect("the end compare finished");
        assert_refused_as_a_guarded_file(&stops);
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_guarded_name_that_cannot_be_looked_at_refuses_the_shared_read() {
        let home = claude_home("shared-guarded-unlooked");
        // The guarded files' directory becomes a file, so that a stat of a guarded name fails with
        // another error than "not found".
        let stops = end_stops_after(&home, |home| {
            std::fs::rename(home.join(".claude"), home.join(".claude-moved")).expect("a move");
            std::fs::write(home.join(".claude"), b"a file").expect("a write");
        })
        .expect("the end compare finished");
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(said.contains(&not_read(UNLOOKED).as_str()), "{said:?}");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    /// Makes the credentials file, which the claude-code entry guards and which was not there when
    /// the guard was taken, hold the run's directory name.
    fn make_the_credentials(home: &Path) {
        std::fs::write(
            home.join(".claude/.credentials.json"),
            format!(r#"{{"id":"{RUN_NAME}"}}"#),
        )
        .expect("a write");
    }

    /// The look of the guarded files that fails for the credentials file with a permission error,
    /// and is the guard's own look for the others.
    fn look_failing_for_the_credentials(
        home: &Path,
    ) -> impl Fn(&str) -> std::io::Result<Option<Seen>> + '_ {
        move |relative| {
            if relative == ".claude/.credentials.json" {
                Err(std::io::ErrorKind::PermissionDenied.into())
            } else {
                seen_by_lstat(&home.join(relative))
            }
        }
    }

    /// Asserts that the end read refused the shared file because a guarded name could not be looked
    /// at, and read none of it.
    fn assert_refused_as_unlooked(stops: &[Stop]) {
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(said.contains(&not_read(UNLOOKED).as_str()), "{said:?}");
        assert!(
            !said.iter().any(|why| why.contains("now holds")),
            "the shared file was read after a look of a guarded name failed: {said:?}"
        );
    }

    #[test]
    fn a_guarded_name_that_cannot_be_looked_at_is_an_error_and_one_that_is_not_there_is_no_match() {
        let home = scratch("guarded-stat");
        std::fs::write(home.join("file"), b"one").expect("a file");
        let metadata = std::fs::metadata(home.join("file")).expect("a look");
        // A name below a file fails with another error than "not found"; a name that is not there
        // does not.
        let looks = clean_looks();
        let real = Reading::real();
        assert_eq!(
            is_a_guarded_file(&metadata, &[home.join("file/below")], &looks, &*real.stat),
            Err(Unread::Unlooked)
        );
        assert_eq!(
            is_a_guarded_file(&metadata, &[home.join("not-there")], &looks, &*real.stat),
            Ok(false)
        );
        assert_eq!(
            is_a_guarded_file(&metadata, &[home.join("file")], &looks, &*real.stat),
            Ok(true)
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_failed_look_at_a_charge_refuses_every_later_shared_read_though_the_next_looks_succeed() {
        let home = claude_home("failed-look-charge");
        std::fs::remove_file(home.join(".claude/.credentials.json")).expect("removed");
        let guard = claude_plan().take(&home);
        let Watch::Files(files) = &guard.watch else {
            panic!("a claude-code plan guards files");
        };
        // Another process makes the credentials file, and the look of it before a charge fails.
        make_the_credentials(&home);
        let (stops, _) = files.compare_with(
            &look_failing_for_the_credentials(&home),
            &Reading::real(),
            &[],
        );
        assert_eq!(stops.len(), 1, "{stops:?}");
        // The next looks succeed, and the file is moved over the shared name.
        std::fs::rename(
            home.join(".claude/.credentials.json"),
            home.join(".claude.json"),
        )
        .expect("a move");
        assert_refused_as_unlooked(&stops_at_the_end(&guard));
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_failed_look_at_the_end_refuses_the_shared_read_though_the_guarded_name_then_looks_fine() {
        let home = claude_home("failed-look-end");
        std::fs::remove_file(home.join(".claude/.credentials.json")).expect("removed");
        let guard = claude_plan().take(&home);
        let Watch::Files(files) = &guard.watch else {
            panic!("a claude-code plan guards files");
        };
        // The credentials file is made and moved over the shared name before the end, and the
        // first look of the end fails for its name; the guard's own look of it, with nothing
        // there, finds nothing.
        make_the_credentials(&home);
        std::fs::rename(
            home.join(".claude/.credentials.json"),
            home.join(".claude.json"),
        )
        .expect("a move");
        let (stops, _) = files.compare_with(
            &look_failing_for_the_credentials(&home),
            &Reading::real(),
            &[RUN_NAME, RUN_MARK],
        );
        assert_refused_as_unlooked(&stops);
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    /// The plan of the claude-code entry with a second shared name, `.claude2.json`.
    fn two_shared_plan() -> PersonPlan {
        let guarded: Vec<String> = CLAUDE_GUARDED
            .iter()
            .map(|file| (*file).to_owned())
            .collect();
        PersonPlan::of(
            "claude-code",
            &guarded,
            &[".claude.json".to_owned(), ".claude2.json".to_owned()],
            &[],
        )
        .expect("a plan")
    }

    /// The file guard of `guard`.
    fn files_of(guard: &PersonGuard) -> &FileGuard {
        let Watch::Files(files) = &guard.watch else {
            panic!("a claude-code plan guards files");
        };
        files
    }

    /// The look of the guarded files that the guard itself makes, below `home`.
    fn lstat_in(home: &Path) -> impl Fn(&str) -> std::io::Result<Option<Seen>> + '_ {
        move |relative| seen_by_lstat(&home.join(relative))
    }

    /// A worker's look and bound that `stat` and `bound` give, with no read begun.
    fn reading_with(
        stat: impl Fn(&Path) -> std::io::Result<std::fs::Metadata> + Send + Sync + 'static,
        bound: std::time::Duration,
    ) -> Reading {
        Reading {
            stat: std::sync::Arc::new(stat),
            bound,
            begun: std::sync::Arc::default(),
        }
    }

    /// An error of the system that is not "not found".
    fn input_output_error() -> std::io::Error {
        std::io::Error::from_raw_os_error(5)
    }

    /// The reads that `reading` has begun.
    fn begun(reading: &Reading) -> usize {
        reading.begun.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[test]
    fn a_failed_look_of_the_worker_refuses_the_next_shared_read_though_the_path_recovers() {
        let home = claude_home("worker-failure-two-entries");
        // The credentials file is not there at the take and at the end's first look.
        std::fs::remove_file(home.join(".claude/.credentials.json")).expect("removed");
        std::fs::write(home.join(".claude2.json"), b"{}").expect("a second shared file");
        let guard = two_shared_plan().take(&home);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let moving = home.clone();
        let reading = reading_with(
            move |path| {
                if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    // After the end's looks: another process makes the credentials file, which holds
                    // the run's name and which no look of the guard saw, moves it over the second
                    // shared name, and the first look of the worker fails. Every look after it
                    // succeeds.
                    make_the_credentials(&moving);
                    std::fs::rename(
                        moving.join(".claude/.credentials.json"),
                        moving.join(".claude2.json"),
                    )
                    .expect("a move");
                    return Err(input_output_error());
                }
                std::fs::metadata(path)
            },
            long_bound(),
        );
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(said.contains(&not_read(UNLOOKED).as_str()), "{said:?}");
        assert!(
            said.contains(&not_read_at(".claude2.json", UNLOOKED).as_str()),
            "the second shared read went on after the first look of the worker failed: {said:?}"
        );
        assert_eq!(begun(&reading), 0, "a shared file was read");
        assert!(
            files_of(&guard).known().unlooked,
            "the failed look of the worker was not kept"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_failed_look_of_the_worker_is_kept_in_the_cell() {
        let home = scratch("worker-failure-kept");
        std::fs::write(home.join("shared.json"), b"{}").expect("a file");
        std::fs::write(home.join("file"), b"one").expect("a file");
        let looks = clean_looks();
        let real = Reading::real();
        // A guarded name below a file cannot be looked at, and it is not "not found".
        let opened = open_shared(
            &home.join("shared.json"),
            &[home.join("file/below")],
            &looks,
            &*real.stat,
        );
        assert_eq!(opened.err(), Some(Unread::Unlooked));
        assert!(
            looks.state().unlooked,
            "the failed look of the worker was not kept"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_later_end_compare_after_a_failed_look_of_the_worker_refuses_a_readable_file() {
        let home = claude_home("worker-failure-later-compare");
        let guard = claude_plan().take(&home);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let reading = reading_with(
            move |path| {
                if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    return Err(input_output_error());
                }
                std::fs::metadata(path)
            },
            long_bound(),
        );
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        assert!(
            files_of(&guard).known().unlooked,
            "the failed look of the worker was not kept in the cell"
        );
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(
            said.contains(&not_read(UNLOOKED).as_str()),
            "the first read went on after the failed look of the worker: {said:?}"
        );
        // The path recovers, and a file that names the run is at the shared name.
        std::fs::write(
            home.join(".claude.json"),
            format!(r#"{{"id":"{RUN_NAME}"}}"#),
        )
        .expect("a write");
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        assert!(
            files_of(&guard).known().unlooked,
            "the failed look of the worker was no longer kept at the later end compare"
        );
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(
            said.contains(&not_read(UNLOOKED).as_str()),
            "the later end compare read a file after the failed look of the worker: {said:?}"
        );
        assert!(
            !said.iter().any(|why| why.contains("now holds")),
            "the later end compare found the run's name in a file it read: {said:?}"
        );
        assert_eq!(begun(&reading), 0, "a shared file was read");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_file_that_the_worker_saw_at_a_guarded_name_is_not_read_at_a_later_shared_name() {
        use std::os::unix::fs::MetadataExt as _;
        let home = claude_home("worker-saw-a-file");
        // The credentials file is not there at the take and at the end's first look.
        std::fs::remove_file(home.join(".claude/.credentials.json")).expect("removed");
        std::fs::write(home.join(".claude2.json"), b"{}").expect("a second shared file");
        let guard = two_shared_plan().take(&home);
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let moving = home.clone();
        let reading = reading_with(
            move |path| {
                match calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                    // The credentials file appears at its guarded name before the first look of the
                    // worker, which sees it there.
                    0 => make_the_credentials(&moving),
                    // The first shared read is at its last guarded name: the file moves over the
                    // second shared name.
                    2 => std::fs::rename(
                        moving.join(".claude/.credentials.json"),
                        moving.join(".claude2.json"),
                    )
                    .expect("a move"),
                    _ => {}
                }
                std::fs::metadata(path)
            },
            long_bound(),
        );
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        // The cell holds the identity of the file that the worker saw, now at the second shared
        // name.
        let moved = std::fs::metadata(home.join(".claude2.json")).expect("a look");
        assert!(
            files_of(&guard)
                .known()
                .seen
                .contains(&(moved.dev(), moved.ino())),
            "the file that the worker saw at a guarded name was not kept in the cell"
        );
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert_eq!(
            said,
            [not_read_at(
                ".claude2.json",
                "is the same file as a guarded file and is not read"
            )
            .as_str()]
        );
        assert_eq!(begun(&reading), 1, "the second shared file was read");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_link_seen_at_a_guarded_name_refuses_every_shared_read_after_it_though_the_link_is_gone() {
        let home = claude_home("link-seen-at-a-guarded-name");
        let guard = claude_plan().take(&home);
        // A file that names the run, and a link to it at a guarded name.
        std::fs::write(home.join("target"), format!(r#"{{"id":"{RUN_NAME}"}}"#)).expect("a write");
        std::fs::remove_file(home.join(".claude/.device-keys.json")).expect("removed");
        std::os::unix::fs::symlink(home.join("target"), home.join(".claude/.device-keys.json"))
            .expect("a link");
        // The look before a charge sees the link: the guarded file's own stop is one thing, and
        // the cell is another.
        let (stops, _) = guard.compare();
        assert!(
            stops
                .iter()
                .any(|(_, why)| why.contains("~/.claude/.device-keys.json changed")),
            "{stops:?}"
        );
        assert!(
            files_of(&guard).known().unlooked,
            "a link seen at a guarded name was not kept"
        );
        // The link goes, and its target is moved over the shared name.
        std::fs::remove_file(home.join(".claude/.device-keys.json")).expect("removed");
        std::fs::rename(home.join("target"), home.join(".claude.json")).expect("a move");
        let reading = Reading::real();
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        assert_refused_as_unlooked(&stops);
        assert_eq!(begun(&reading), 0, "a shared file was read");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_guarded_name_that_is_a_link_to_the_shared_path_is_refused_as_a_guarded_file() {
        let home = scratch("guarded-link-to-shared");
        std::fs::write(home.join("shared.json"), b"{}").expect("a file");
        std::os::unix::fs::symlink(home.join("shared.json"), home.join("guarded")).expect("a link");
        let real = Reading::real();
        let opened = open_shared(
            &home.join("shared.json"),
            &[home.join("guarded")],
            &clean_looks(),
            &*real.stat,
        );
        assert_eq!(opened.err(), Some(Unread::GuardedFile));
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_read_with_no_answer_in_time_refuses_every_shared_read_after_it_while_its_worker_waits() {
        let home = claude_home("no-answer-in-time");
        // The credentials file is not there at the take and at the end's first look.
        std::fs::remove_file(home.join(".claude/.credentials.json")).expect("removed");
        std::fs::write(home.join(".claude2.json"), b"{}").expect("a second shared file");
        let guard = two_shared_plan().take(&home);
        let (release, waiting) = std::sync::mpsc::channel::<()>();
        let (ended, worker_ended) = std::sync::mpsc::channel::<()>();
        let (waiting, ended) = (std::sync::Mutex::new(waiting), std::sync::Mutex::new(ended));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let moving = home.clone();
        let reading = reading_with(
            move |path| {
                if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    // After the end's looks: another process makes the credentials file, which holds
                    // the run's name and which no look of the guard saw, and moves it over the second
                    // shared name. The first look of the worker then waits until the case lets it
                    // go, and fails.
                    make_the_credentials(&moving);
                    std::fs::rename(
                        moving.join(".claude/.credentials.json"),
                        moving.join(".claude2.json"),
                    )
                    .expect("a move");
                    let _ = waiting.lock().expect("a lock").recv();
                    let _ = ended.lock().expect("a lock").send(());
                    return Err(input_output_error());
                }
                std::fs::metadata(path)
            },
            std::time::Duration::from_secs(2),
        );
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(
            said.contains(&not_read("was not read within 10 seconds").as_str()),
            "{said:?}"
        );
        assert!(
            said.contains(&not_read_at(".claude2.json", UNLOOKED).as_str()),
            "the second shared read went on while the first worker's look had no answer: {said:?}"
        );
        assert_eq!(begun(&reading), 0, "a shared file was read");
        // The first worker still waits, so its failure is not what the cell keeps.
        assert!(
            files_of(&guard).known().unlooked,
            "a read with no answer in time was not kept"
        );
        release.send(()).expect("the worker waits");
        worker_ended
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("the worker's look ended");
        assert!(files_of(&guard).known().unlooked);
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn an_absence_look_that_fails_is_a_failed_look_of_the_guard() {
        let home = claude_home("absence-look");
        let root = home.join("run");
        std::fs::create_dir_all(root.join("w")).expect("a directory of the run");
        let pin = pinned(&root);
        let guard = claude_plan().take(&home);
        // The agent makes a folder of the run a link to the person's `.claude`: the look of a path
        // through it is refused, and it is a failed look.
        std::os::unix::fs::symlink(home.join(".claude"), root.join("w/.claude")).expect("a link");
        let said = guard
            .absent_below(&root, &pin, &root.join("w/.claude/settings.json"))
            .expect_err("a link on the way is not looked through");
        assert!(said.contains("symbolic link"), "{said}");
        assert!(
            files_of(&guard).known().unlooked,
            "a failed absence look was not kept"
        );
        // A file that no look saw at a guarded name is then moved over the shared name.
        std::fs::write(home.join("moved"), format!(r#"{{"id":"{RUN_NAME}"}}"#)).expect("a write");
        std::fs::rename(home.join("moved"), home.join(".claude.json")).expect("a move");
        let reading = Reading::real();
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        assert_refused_as_unlooked(&stops);
        assert_eq!(begun(&reading), 0, "a shared file was read");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn an_absence_look_that_finds_a_file_is_kept_as_a_failed_look_of_the_guard() {
        let home = claude_home("absence-look-finds-a-file");
        let root = home.join("run");
        std::fs::create_dir_all(root.join("w")).expect("a directory of the run");
        let pin = pinned(&root);
        // The credentials file is not there at the take.
        std::fs::remove_file(home.join(".claude/.credentials.json")).expect("removed");
        let guard = claude_plan().take(&home);
        // Another process makes it, and the absence look of a spelling of its name finds it. The
        // plan here has no absent list, so this case tests the guard's write apart from the
        // plan's check, which refuses this spelling.
        make_the_credentials(&home);
        assert_eq!(
            guard.absent_below(&root, &pin, &home.join(".claude/./.credentials.json")),
            Ok(false)
        );
        assert!(
            files_of(&guard).known().unlooked,
            "a file that an absence look found was not kept as a failed look"
        );
        // The file moves over the shared name, and no look at the end sees it at a guarded name.
        std::fs::rename(
            home.join(".claude/.credentials.json"),
            home.join(".claude.json"),
        )
        .expect("a move");
        let reading = Reading::real();
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(said.contains(&not_read(UNLOOKED).as_str()), "{said:?}");
        assert_eq!(begun(&reading), 0, "a shared file was read");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    /// The list form the gateway calls, through the guard: a path that the look finds present is
    /// refused with what was found, and it is kept as a failed look, so that no shared file is
    /// read at the end.
    #[test]
    fn the_guards_absent_list_keeps_a_look_that_finds_a_file_as_a_failed_look() {
        let home = claude_home("absent-list-finds-a-file");
        let root = home.join("run");
        std::fs::create_dir_all(root.join("w")).expect("a directory of the run");
        let pin = pinned(&root);
        std::fs::remove_file(home.join(".claude/.credentials.json")).expect("removed");
        let guard = claude_plan().take(&home);
        make_the_credentials(&home);
        let refused = guard
            .shown_absent(&root, &pin, &[home.join(".claude/./.credentials.json")])
            .expect_err("a file that exists is not absent");
        assert!(refused.contains("exists"), "{refused}");
        assert!(
            files_of(&guard).known().unlooked,
            "a file that an absent list found was not kept as a failed look"
        );
        std::fs::rename(
            home.join(".claude/.credentials.json"),
            home.join(".claude.json"),
        )
        .expect("a move");
        let reading = Reading::real();
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(said.contains(&not_read(UNLOOKED).as_str()), "{said:?}");
        assert_eq!(begun(&reading), 0, "a shared file was read");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn an_absence_look_that_finds_a_link_is_kept_as_a_failed_look_of_the_guard() {
        let home = claude_home("absence-look-finds-a-link");
        let root = home.join("run");
        std::fs::create_dir_all(root.join("w")).expect("a directory of the run");
        let pin = pinned(&root);
        // The credentials file is not there at the take.
        std::fs::remove_file(home.join(".claude/.credentials.json")).expect("removed");
        let guard = claude_plan().take(&home);
        // A link to a file that names the run is put at the guarded name, and the absence look of
        // a spelling of that name finds it: a link is an entry. The plan has no absent list here
        // either, so this case tests the guard's write apart from the plan's check.
        std::fs::write(home.join("target"), format!(r#"{{"id":"{RUN_NAME}"}}"#)).expect("a write");
        std::os::unix::fs::symlink(home.join("target"), home.join(".claude/.credentials.json"))
            .expect("a link");
        assert_eq!(
            guard.absent_below(&root, &pin, &home.join(".claude/./.credentials.json")),
            Ok(false)
        );
        assert!(
            files_of(&guard).known().unlooked,
            "a link that an absence look found was not kept as a failed look"
        );
        // The link goes, and its target is moved over the shared name.
        std::fs::remove_file(home.join(".claude/.credentials.json")).expect("removed");
        std::fs::rename(home.join("target"), home.join(".claude.json")).expect("a move");
        let reading = Reading::real();
        let (stops, _) =
            files_of(&guard).compare_with(&lstat_in(&home), &reading, &[RUN_NAME, RUN_MARK]);
        let said: Vec<&str> = stops.iter().map(|(_, why)| why.as_str()).collect();
        assert!(said.contains(&not_read(UNLOOKED).as_str()), "{said:?}");
        assert_eq!(begun(&reading), 0, "a shared file was read");
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_shared_file_larger_than_the_limit_is_refused_and_not_read() {
        let home = claude_home("shared-large");
        // A file of holes, so that it costs nothing to make: a read of it would find the run's
        // name nowhere, and a refusal is the only stop.
        let stops = end_stops_after(&home, |home| {
            let file = std::fs::File::create(home.join(".claude.json")).expect("a file");
            file.set_len(SHARED_LIMIT + 1).expect("a size");
        })
        .expect("the end compare finished");
        assert_eq!(
            stops.into_iter().map(|(_, why)| why).collect::<Vec<_>>(),
            vec![not_read("is larger than 16777216 bytes and is not read")]
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn the_handle_of_a_shared_file_larger_than_the_limit_is_refused_before_any_read() {
        let home = scratch("shared-handle-large");
        let path = home.join("shared.json");
        let file = std::fs::File::create(&path).expect("a file");
        file.set_len(SHARED_LIMIT + 1).expect("a size");
        let looks = clean_looks();
        let real = Reading::real();
        assert_eq!(
            open_shared(&path, &[], &looks, &*real.stat).err(),
            Some(Unread::TooLarge)
        );
        file.set_len(SHARED_LIMIT).expect("a size");
        assert!(matches!(
            open_shared(&path, &[], &looks, &*real.stat),
            Ok(Some(_))
        ));
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    /// A time far enough on that no test reaches it.
    fn far_off() -> std::time::Instant {
        std::time::Instant::now() + std::time::Duration::from_secs(3600)
    }

    #[test]
    fn a_read_that_passes_the_byte_limit_is_refused() {
        use std::io::Read as _;
        let needle: &[&[u8]] = &[b"zzz"];
        let mut source = std::io::repeat(b'a').take(1000);
        assert_eq!(
            scan(&mut source, needle, 100, far_off()),
            Err(Unread::TooLarge)
        );
        // Within the limit it reads to the end, and finds what is there.
        let mut source = std::io::repeat(b'a').take(1000);
        assert_eq!(scan(&mut source, needle, 1000, far_off()), Ok(false));
        let mut source = std::io::Cursor::new(b"aaaazzzaaaa".to_vec());
        assert_eq!(scan(&mut source, needle, 1000, far_off()), Ok(true));
    }

    #[test]
    fn a_read_asks_for_one_byte_past_the_limit_and_no_more() {
        /// Gives bytes without end, and counts those it gave.
        struct Endless(u64);
        impl std::io::Read for Endless {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                buffer.fill(b'a');
                self.0 += buffer.len() as u64;
                Ok(buffer.len())
            }
        }
        let needle: &[&[u8]] = &[b"zzz"];
        // A limit of several pieces, and one that is less than a piece.
        for limit in [200_000_u64, 5] {
            let mut source = Endless(0);
            assert_eq!(
                scan(&mut source, needle, limit, far_off()),
                Err(Unread::TooLarge)
            );
            assert_eq!(source.0, limit + 1, "bytes given for a limit of {limit}");
        }
        // A source of exactly the limit's size is read to its end.
        let mut source = std::io::Cursor::new(vec![b'a'; 200_000]);
        assert_eq!(scan(&mut source, needle, 200_000, far_off()), Ok(false));
    }

    #[test]
    fn an_error_during_the_read_is_refused() {
        /// Gives ten bytes, then fails.
        struct Fails(bool);
        impl std::io::Read for Fails {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                if self.0 {
                    return Err(std::io::Error::other("a failing disk"));
                }
                self.0 = true;
                buffer[..10].fill(b'a');
                Ok(10)
            }
        }
        let needle: &[&[u8]] = &[b"zzz"];
        assert_eq!(
            scan(&mut Fails(false), needle, 1000, far_off()),
            Err(Unread::Failed)
        );
    }

    #[test]
    fn a_read_that_outlasts_its_deadline_is_refused() {
        use std::io::Read as _;
        let needle: &[&[u8]] = &[b"zzz"];
        let deadline = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(5));
        // A source of fifty megabytes, which the limit allows: only the deadline stops it.
        let mut source = std::io::repeat(b'a').take(50_000_000);
        assert_eq!(
            scan(&mut source, needle, u64::MAX, deadline),
            Err(Unread::TooSlow)
        );
        let mut source = std::io::repeat(b'a').take(50_000_000);
        assert_eq!(scan(&mut source, needle, u64::MAX, far_off()), Ok(false));
    }

    /// A bound of thirty seconds, which no case here reaches.
    fn long_bound() -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }

    #[test]
    fn a_read_that_waits_past_its_bound_is_too_slow_and_one_in_time_gives_its_answer() {
        let slow = read_within(
            std::thread::Builder::new(),
            std::time::Duration::from_millis(50),
            || {
                std::thread::sleep(std::time::Duration::from_secs(2));
                Ok(true)
            },
        );
        assert_eq!(slow, Err(Unread::TooSlow));
        let builder = std::thread::Builder::new;
        assert_eq!(read_within(builder(), long_bound(), || Ok(true)), Ok(true));
        assert_eq!(
            read_within(builder(), long_bound(), || Err(Unread::TooLarge)),
            Err(Unread::TooLarge)
        );
    }

    #[test]
    fn a_read_whose_thread_ends_without_an_answer_is_a_failure() {
        let ended = read_within(std::thread::Builder::new(), long_bound(), || {
            panic!("the thread of the read ends without an answer")
        });
        assert_eq!(ended, Err(Unread::Failed));
    }

    #[test]
    fn a_read_whose_thread_cannot_be_made_is_a_failure() {
        // A stack that no system has the memory for.
        let builder = std::thread::Builder::new().stack_size(1 << 60);
        assert_eq!(
            read_within(builder, long_bound(), || Ok(true)),
            Err(Unread::Failed)
        );
    }

    #[test]
    fn each_refusal_of_the_shared_read_says_so_in_its_own_words() {
        let end = ", so it is not known whether it holds the run's directory name or mark";
        let said: Vec<String> = [
            (Unread::Link, "is a symbolic link and is not read"),
            (Unread::NotAFile, "is not a regular file and is not read"),
            (Unread::Gone, "has no name left and is not read"),
            (Unread::ManyNames, "has more than one name and is not read"),
            (
                Unread::GuardedFile,
                "is the same file as a guarded file and is not read",
            ),
            (Unread::Unlooked, UNLOOKED),
            (
                Unread::TooLarge,
                "is larger than 16777216 bytes and is not read",
            ),
            (Unread::TooSlow, "was not read within 10 seconds"),
            (Unread::Failed, "cannot be read after the run"),
        ]
        .into_iter()
        .map(|(refusal, words)| {
            assert_eq!(refusal.said(), format!("{words}{end}"));
            refusal.said()
        })
        .collect();
        let distinct: std::collections::BTreeSet<&String> = said.iter().collect();
        assert_eq!(distinct.len(), said.len());
    }

    #[test]
    fn a_change_of_the_device_of_a_guarded_file_stops_the_run() {
        let home = claude_home("files-device");
        let guard = claude_plan().take(&home);
        let Watch::Files(files) = &guard.watch else {
            panic!("a claude-code plan guards files");
        };
        let look = |relative: &str| seen_by_lstat(&home.join(relative));
        // The same file, to the last inode, time and byte, on another device.
        let another_device = |relative: &str| {
            look(relative).map(|seen| {
                seen.map(|mut seen| {
                    if relative == ".claude/settings.json" {
                        seen.stamp.device += 1;
                    }
                    seen
                })
            })
        };
        let (stops, evidence) = files.compared(&another_device);
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert_eq!(
            stops[0].1,
            "~/.claude/settings.json changed while the run ran"
        );
        assert_eq!(evidence[2]["changed"], json!(true));
        assert_eq!(evidence[2]["owner_changed"], json!(false));
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_tree_that_cannot_be_looked_at_at_a_charge_stops_the_run_in_words_that_fit_it() {
        let home = scratch("tree-unlooked-at-a-charge");
        std::fs::create_dir_all(home.join(".codex")).expect("a tree");
        let guard = MetaGuard::take(&home, &[".codex"]);
        // The tree is replaced by a link, which the look refuses.
        std::fs::remove_dir_all(home.join(".codex")).expect("removed");
        std::os::unix::fs::symlink(&home, home.join(".codex")).expect("a link");
        let (stops, _) = guard.compare();
        assert_eq!(stops.len(), 1, "{stops:?}");
        assert!(
            stops[0].1.starts_with("~/.codex cannot be looked at: "),
            "{stops:?}"
        );
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_guarded_file_that_cannot_be_looked_at_after_the_start_stops_the_run() {
        let home = claude_home("files-unlooked");
        let guard = claude_plan().take(&home);
        let Watch::Files(files) = &guard.watch else {
            panic!("a claude-code plan guards files");
        };
        let refused = |relative: &str| -> std::io::Result<Option<Seen>> {
            if relative == ".claude/settings.json" {
                Err(std::io::ErrorKind::PermissionDenied.into())
            } else {
                seen_by_lstat(&home.join(relative))
            }
        };
        let (stops, evidence) = files.compared(&refused);
        assert_eq!(
            stops,
            vec![(
                "person_file_unreadable",
                "~/.claude/settings.json cannot be looked at: permission denied".to_owned()
            )]
        );
        assert_eq!(evidence[2]["unreadable"], json!(true));
        assert_eq!(evidence[0].get("unreadable"), None);
        std::fs::remove_dir_all(&home).expect("clean up");
    }

    #[test]
    fn a_path_of_the_lists_that_is_not_plain_and_relative_is_refused() {
        let plain = vec![".claude/settings.json".to_owned()];
        for path in [
            "/etc/passwd",
            "../outside",
            "a/../b",
            "./a",
            "a//b",
            "a/",
            "",
        ] {
            let odd = vec![path.to_owned()];
            let said = format!(
                "the entry for claude-code names the path {path:?}, which is not a plain path \
                 relative to the person's home: it has an empty, `.` or `..` part, or starts with \
                 `/`"
            );
            assert_eq!(
                PersonPlan::of("claude-code", &odd, &[], &[]),
                Err(said.clone()),
                "{path:?} as a guarded file"
            );
            assert_eq!(
                PersonPlan::of("claude-code", &plain, &odd, &[]),
                Err(said),
                "{path:?} as a shared file"
            );
        }
        assert!(PersonPlan::of("claude-code", &plain, &[".claude.json".to_owned()], &[]).is_ok());
    }

    #[test]
    fn a_plan_whose_absent_list_names_a_guarded_or_shared_file_is_refused() {
        let guarded: Vec<String> = CLAUDE_GUARDED
            .iter()
            .map(|file| (*file).to_owned())
            .collect();
        let shared = [".claude.json".to_owned()];
        for template in [
            "{person}/.claude/settings.json",
            "{person}/.claude.json",
            "{ancestors}/.claude/.device-keys.json",
        ] {
            let refused = PersonPlan::of("claude-code", &guarded, &shared, &[template.to_owned()])
                .expect_err("an absent path that names a guarded or shared file");
            assert!(
                refused.contains(template) && refused.contains("claude-code"),
                "{refused}"
            );
        }
        // The claude-code entry's own paths, none of which is a file of the person's home that the
        // entry guards or shares.
        let own: Vec<String> = [
            "{config}/settings.json",
            "{work}/.claude/settings.json",
            "{work}/.mcp.json",
            "/Library/Application Support/ClaudeCode/managed-settings.json",
            "/Library/Managed Preferences/{user}/com.anthropic.claudecode.plist",
        ]
        .iter()
        .map(|path| (*path).to_owned())
        .collect();
        assert!(PersonPlan::of("claude-code", &guarded, &shared, &own).is_ok());
        // A path of the person's home below a guarded file's directory is not a guarded name.
        let kimi_guarded = [".kimi-code/config.toml".to_owned()];
        assert!(
            PersonPlan::of(
                "kimi-code-cli",
                &kimi_guarded,
                &[],
                &["{person}/.kimi-code/plugins".to_owned()]
            )
            .is_ok()
        );
    }

    #[test]
    fn a_not_plain_absent_path_of_the_person_is_refused() {
        let guarded: Vec<String> = CLAUDE_GUARDED
            .iter()
            .map(|file| (*file).to_owned())
            .collect();
        let shared = [".claude.json".to_owned()];
        for template in [
            "{person}/./.claude.json",
            "{person}/.claude/./.credentials.json",
            "{person}//.claude.json",
            "{ancestors}/.claude/../.claude.json",
        ] {
            let refused = PersonPlan::of("claude-code", &guarded, &shared, &[template.to_owned()])
                .expect_err("an absent path that is not plain");
            assert!(
                refused.contains(template)
                    && refused.contains("claude-code")
                    && refused.contains("is not a plain path"),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_literal_absolute_absent_path_that_names_a_guarded_or_shared_file_is_refused() {
        let guarded: Vec<String> = CLAUDE_GUARDED
            .iter()
            .map(|file| (*file).to_owned())
            .collect();
        let shared = [".claude.json".to_owned()];
        for template in [
            "/Users/x/.claude.json",
            "/Users/{user}/.claude/settings.json",
            "/Users/x/.claude/./.credentials.json",
            "/Users/x/.claude/y/../.device-keys.json",
        ] {
            let refused = PersonPlan::of("claude-code", &guarded, &shared, &[template.to_owned()])
                .expect_err("a literal absent path that ends in a guarded or shared file");
            assert!(
                refused.contains(template) && refused.contains("claude-code"),
                "{refused}"
            );
        }
    }

    #[test]
    fn a_file_in_both_lists_is_refused() {
        let both = vec![".claude/settings.json".to_owned()];
        assert_eq!(
            PersonPlan::of("claude-code", &both, &both, &[]),
            Err(
                "the entry for claude-code names ~/.claude/settings.json as both a guarded and a \
                 shared file, so the end read would read a guarded file"
                    .to_owned()
            )
        );
    }
}
