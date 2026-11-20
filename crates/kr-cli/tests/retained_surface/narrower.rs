//! The entry for a worker's input rule that refuses more than the retained release's rule did.
//!
//! A change to such a rule moves the digest of its root, and the table of [`super::SAME`] says a
//! change leaves what a level accepts as it was. This kind says the opposite for one rule: the
//! worker now refuses what the retained level's worker accepted, and the entry shows what reaches
//! that rule from every peer that can send to a worker of this level. It holds the rule's root and
//! its digests, the helpers the root does not follow, one row of evidence per class of peer, and
//! the sightings that send none of the six methods this is about.
//!
//! The checker works on a [`Reader`], which is a source tree (the checkout, or a release's) or a
//! fixed set of answers, and returns the texts of what it finds. Three stages run in order and a
//! stage that has a text stops the next: the guards, the shape of the entry, and the lookups that
//! compare it with the trees.

use std::collections::BTreeSet;

use serde_json::Value;

use super::Root;
use super::walker::{Depth, Lookup, SightKind, Sighting, Tree};

/// The crates that receive: nothing in them is scanned and no row names them.
pub const RECEIVER_CRATES: &[&str] = &["kr_protocol", "kr_worker"];
/// The crates of the daemon, which reaches only a worker of its own level or a retained one: its
/// items hold this checkout's digests and no earlier ones.
pub const DAEMON_CRATES: &[&str] = &["kr_controller"];
/// The classes of peer that can send to a worker, each exactly once in an entry.
pub const PEER_CLASSES: &[&str] = &[
    "the companion",
    "a device's mutation relayed by the daemon",
    "the daemon's local prompt route",
    "the workflow and voice routes",
    "kr",
    "kr-hook",
    "the plugin host, the plugin runtime and the automation engine",
];

/// What a rule of a worker's input refuses now that the retained release's did not.
#[derive(Clone)]
pub struct Narrower {
    /// The level the entry is made for: this build's.
    pub level: &'static str,
    /// The root's label.
    pub root: &'static str,
    /// The retained record's digest of the root.
    pub recorded: &'static str,
    /// This checkout's digest of the root.
    pub digest: &'static str,
    /// What the rule refuses now; it never says the level accepts what it did.
    pub refuses: &'static str,
    /// What else differs from the retained release, and the command that shows it.
    pub rest: &'static str,
    /// The registry rows no digest holds, and the cases that fail when one changes.
    pub registry: &'static str,
    /// Who may meet the rule and was not read.
    pub unreached: &'static str,
    /// The shell searches that find the senders, as run.
    pub searched: &'static [&'static str],
    pub range: Range,
    /// Items the rule calls that the root, digested alone, does not follow.
    pub helpers: &'static [Helper],
    /// One row per class of peer.
    pub senders: &'static [Sender],
    /// Sightings that send none of the six methods.
    pub accounts: &'static [Account],
}

#[derive(Clone)]
pub struct Helper {
    pub krate: &'static str,
    pub name: &'static str,
    /// The digest in this checkout.
    pub now: &'static str,
    /// The digest in the retained release's tree, or `absent`.
    pub before: &'static str,
    pub what: &'static str,
}

#[derive(Clone)]
pub struct Sender {
    pub class: &'static str,
    pub sends: &'static str,
    pub evidence: Evidence,
}

#[derive(Clone)]
pub enum Evidence {
    /// Items that build or set the instance and the revision of a mutation.
    Builds { items: &'static [Item] },
    /// Items that copy a decoded mutation on and construct none.
    Relays { items: &'static [Item] },
    /// Crates that send none of the six.
    SendsNone { crates: &'static [&'static str] },
}

impl Evidence {
    pub fn items(&self) -> &'static [Item] {
        match self {
            Self::Builds { items } | Self::Relays { items } => items,
            Self::SendsNone { .. } => &[],
        }
    }
}

#[derive(Clone)]
pub struct Item {
    pub krate: &'static str,
    pub name: &'static str,
    /// A digest, or `absent` for an item of a client crate that only earlier releases have.
    pub now: &'static str,
    /// One pair per distinct text over the range: the digest (or `absent`) and what that text does
    /// with the instance and the revision. Empty in a daemon crate.
    pub across: &'static [(&'static str, &'static str)],
}

#[derive(Clone)]
pub struct Account {
    pub krate: &'static str,
    pub name: &'static str,
    pub kinds: &'static [SightKind],
    pub now: &'static str,
    pub why: &'static str,
}

#[derive(Clone)]
pub struct Range {
    pub first_tag: &'static str,
    pub why_first: &'static str,
    pub tags: u32,
}

/// What the checker reads a tree through.
pub trait Reader {
    /// `Found` when the tree defines the crate.
    fn krate(&self, krate: &str) -> Lookup;
    /// The digest of a root as its names and depth follow it.
    fn root(&self, root: &Root) -> Lookup;
    /// One item, alone.
    fn item(&self, krate: &str, name: &str) -> Lookup;
    fn sightings(&self) -> Result<Vec<Sighting>, String>;
}

impl Reader for Tree {
    fn krate(&self, krate: &str) -> Lookup {
        Tree::krate(self, krate)
    }

    fn root(&self, root: &Root) -> Lookup {
        let names: Vec<&str> = root.names.iter().map(String::as_str).collect();
        self.lookup(root.krate, &names, root.depth)
    }

    fn item(&self, krate: &str, name: &str) -> Lookup {
        Tree::item(self, krate, name)
    }

    fn sightings(&self) -> Result<Vec<Sighting>, String> {
        Tree::sightings(self, &|krate| !RECEIVER_CRATES.contains(&krate))
    }
}

/// One retained level's record.
pub struct LevelRecord<'a> {
    pub level: &'a str,
    /// The `roots` object of the level's `sources.json`: a digest and what was followed, by label.
    pub roots: &'a serde_json::Map<String, Value>,
    /// Whether the level's surface defines a type of that name.
    pub surface_defines: &'a dyn Fn(&str) -> bool,
}

pub struct Input<'a> {
    pub entries: &'a [Narrower],
    pub roots: &'a [Root],
    pub worker_input_roots: &'a [&'a str],
    pub receiver_crates: &'a [&'a str],
    pub daemon_crates: &'a [&'a str],
    pub peer_classes: &'a [&'a str],
    pub this_level: &'a str,
    /// Whether the public freeze file exists.
    pub frozen: bool,
    pub same: &'a [super::Same],
    /// One per retained level.
    pub retained: &'a [LevelRecord<'a>],
    pub current: &'a dyn Reader,
    /// The tree of a release, when the check is run against one.
    pub release: Option<&'a dyn Reader>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Receiver,
    Daemon,
    Client,
}

struct Checker<'a> {
    input: &'a Input<'a>,
    entry: &'a Narrower,
    out: Vec<String>,
}

pub const ABSENT: &str = "absent";

/// The problems of every entry of the table. An empty table has none.
pub fn check_narrower(input: &Input) -> Vec<String> {
    let mut out = Vec::new();
    if input.entries.is_empty() {
        return out;
    }
    if input.retained.len() != 1 && !input.frozen {
        out.push(format!(
            "an entry of the narrower table is read against exactly one retained record, and this build retains {}",
            input.retained.len()
        ));
        return out;
    }
    for entry in input.entries {
        let mut checker = Checker {
            input,
            entry,
            out: Vec::new(),
        };
        checker.run();
        out.extend(checker.out);
    }
    out
}

impl Checker<'_> {
    fn say(&mut self, text: String) {
        self.out
            .push(format!("narrower {}: {text}", self.entry.root));
    }

    fn class_of(&self, krate: &str) -> Class {
        if self.input.receiver_crates.contains(&krate) {
            Class::Receiver
        } else if self.input.daemon_crates.contains(&krate) {
            Class::Daemon
        } else {
            Class::Client
        }
    }

    fn run(&mut self) {
        let entry = self.entry;
        if self.input.frozen {
            self.say("from the public freeze this change needs a new public major".to_owned());
            return;
        }
        if entry.level != self.input.this_level {
            self.say(format!(
                "level {} is not this build's level {}",
                entry.level, self.input.this_level
            ));
            return;
        }
        self.shape();
        if !self.out.is_empty() {
            return;
        }
        self.lookups();
    }

    /// Stage B: every rule runs.
    fn shape(&mut self) {
        self.the_root();
        self.the_digests_are_two();
        self.nothing_is_empty();
        self.the_senders();
    }

    fn the_root(&mut self) {
        let (entry, input) = (self.entry, self.input);
        if !input.worker_input_roots.contains(&entry.root) {
            self.say("the root is not a worker input root".to_owned());
        }
        match input.roots.iter().find(|root| root.label == entry.root) {
            None => self.say("no root has this label".to_owned()),
            Some(root) => {
                if root.krate != "kr_worker" {
                    self.say(format!("the root is in {}, not in kr_worker", root.krate));
                }
                if root.depth != Depth::Alone {
                    self.say(format!(
                        "the root is followed at {:?}, not at Alone",
                        root.depth
                    ));
                }
            }
        }
    }

    fn the_digests_are_two(&mut self) {
        let (entry, input) = (self.entry, self.input);
        if input
            .same
            .iter()
            .any(|same| same.root == entry.root && same.digest == entry.digest)
        {
            self.say(format!(
                "a Same entry and this entry both excuse the digest {}",
                entry.digest
            ));
        }
    }

    fn nothing_is_empty(&mut self) {
        let entry = self.entry;
        let empty = |text: &str| text.trim().is_empty();
        for (field, text) in [
            ("refuses", entry.refuses),
            ("rest", entry.rest),
            ("registry", entry.registry),
            ("unreached", entry.unreached),
            ("range.first_tag", entry.range.first_tag),
            ("range.why_first", entry.range.why_first),
        ] {
            if empty(text) {
                self.say(format!("{field} is empty"));
            }
        }
        if entry.searched.is_empty() {
            self.say("searched is empty".to_owned());
        }
        for (at, line) in entry.searched.iter().enumerate() {
            if empty(line) {
                self.say(format!("searched line {} is empty", at + 1));
            }
        }
        if entry.range.tags == 0 {
            self.say("range.tags is zero".to_owned());
        }
        for helper in entry.helpers {
            if empty(helper.what) {
                self.say(format!(
                    "helper {}::{} says nothing in what",
                    helper.krate, helper.name
                ));
            }
        }
        for sender in entry.senders {
            if empty(sender.sends) {
                self.say(format!("sender {} says nothing in sends", sender.class));
            }
            for item in sender.evidence.items() {
                for (digest, sentence) in item.across {
                    if empty(sentence) {
                        self.say(format!(
                            "item {}::{} says nothing of its text {digest}",
                            item.krate, item.name
                        ));
                    }
                }
            }
        }
        for account in entry.accounts {
            if empty(account.why) {
                self.say(format!(
                    "account {}::{} says nothing in why",
                    account.krate, account.name
                ));
            }
            if account.kinds.is_empty() {
                self.say(format!(
                    "account {}::{} covers no kind of sighting",
                    account.krate, account.name
                ));
            }
        }
    }

    fn the_senders(&mut self) {
        let (entry, input) = (self.entry, self.input);
        for class in input.peer_classes {
            match entry.senders.iter().filter(|s| s.class == *class).count() {
                0 => self.say(format!("the peer class {class} has no row")),
                1 => {}
                count => self.say(format!("the peer class {class} has {count} rows")),
            }
        }
        for sender in entry.senders {
            if !input.peer_classes.contains(&sender.class) {
                self.say(format!("{} is no peer class", sender.class));
            }
        }
        let mut none_crates: BTreeSet<&str> = BTreeSet::new();
        for sender in entry.senders {
            match &sender.evidence {
                Evidence::Builds { items } | Evidence::Relays { items } => {
                    if items.is_empty() {
                        self.say(format!("sender {} lists no item", sender.class));
                    }
                }
                Evidence::SendsNone { crates } => {
                    if crates.is_empty() {
                        self.say(format!(
                            "sender {} names no crate that sends none",
                            sender.class
                        ));
                    }
                    for krate in *crates {
                        if input.receiver_crates.contains(krate) {
                            self.say(format!(
                                "sender {} names {krate}, a receiver crate, as sending none",
                                sender.class
                            ));
                        }
                        none_crates.insert(krate);
                    }
                }
            }
        }
        let items: Vec<&Item> = entry
            .senders
            .iter()
            .flat_map(|sender| sender.evidence.items())
            .collect();
        let named: Vec<(&str, &str, &str)> = items
            .iter()
            .map(|item| ("item", item.krate, item.name))
            .chain(
                entry
                    .accounts
                    .iter()
                    .map(|account| ("account", account.krate, account.name)),
            )
            .collect();
        for (what, krate, name) in &named {
            if none_crates.contains(krate) {
                self.say(format!(
                    "the {what} {krate}::{name} is in a crate that a row says sends none"
                ));
            }
            if self.class_of(krate) == Class::Receiver {
                self.say(format!("the {what} {krate}::{name} is in a receiver crate"));
            }
        }
        let mut seen_accounts: BTreeSet<(&str, &str)> = BTreeSet::new();
        let mut twice: BTreeSet<(&str, &str)> = BTreeSet::new();
        for account in entry.accounts {
            if !seen_accounts.insert((account.krate, account.name))
                && twice.insert((account.krate, account.name))
            {
                self.say(format!(
                    "two accounts cover {}::{}",
                    account.krate, account.name
                ));
            }
            if items
                .iter()
                .any(|item| (item.krate, item.name) == (account.krate, account.name))
            {
                self.say(format!(
                    "the account for {}::{} repeats an item",
                    account.krate, account.name
                ));
            }
        }
        let mut seen_items: BTreeSet<(&str, &str)> = BTreeSet::new();
        let mut in_two: BTreeSet<(&str, &str)> = BTreeSet::new();
        for item in &items {
            if !seen_items.insert((item.krate, item.name)) && in_two.insert((item.krate, item.name))
            {
                self.say(format!("{}::{} is in two rows", item.krate, item.name));
            }
        }
        for item in &items {
            match self.class_of(item.krate) {
                Class::Client if item.across.is_empty() => {
                    self.say(format!(
                        "the item {}::{} of a client crate has no texts across the range",
                        item.krate, item.name
                    ));
                }
                Class::Daemon if !item.across.is_empty() => {
                    self.say(format!(
                        "the item {}::{} of a daemon crate has texts across the range",
                        item.krate, item.name
                    ));
                }
                _ => {}
            }
            if item.now == ABSENT && self.class_of(item.krate) != Class::Client {
                self.say(format!(
                    "the item {}::{} is absent now and is not in a client crate",
                    item.krate, item.name
                ));
            }
        }
        for account in entry.accounts {
            if account.now == ABSENT && self.class_of(account.krate) != Class::Client {
                self.say(format!(
                    "the account {}::{} is absent now and is not in a client crate",
                    account.krate, account.name
                ));
            }
        }
        for helper in entry.helpers {
            if helper.now == ABSENT {
                self.say(format!(
                    "the helper {}::{} is absent now",
                    helper.krate, helper.name
                ));
            }
        }
    }

    /// Stage C: every rule runs and none stops another.
    fn lookups(&mut self) {
        self.the_record();
        match self.input.release {
            None => {
                self.this_checkout();
                self.sightings_of_this_checkout();
            }
            Some(release) => self.a_release(release),
        }
    }

    fn the_record(&mut self) {
        let (entry, input) = (self.entry, self.input);
        match input.retained[0].roots.get(entry.root) {
            None => self.say(format!(
                "stale: the record of level {} has no root of this label",
                input.retained[0].level
            )),
            Some(root) => {
                let recorded = root["digest"].as_str().unwrap_or_default();
                if recorded != entry.recorded {
                    self.say(format!(
                        "stale: the record holds {recorded}, the entry names {}",
                        entry.recorded
                    ));
                }
            }
        }
        if entry.digest == entry.recorded {
            self.say("nothing differs, so there is nothing to excuse".to_owned());
        }
    }

    /// An own-tree run: the entry matches this checkout.
    fn this_checkout(&mut self) {
        let (entry, input) = (self.entry, self.input);
        let current = input.current;
        if let Some(root) = input.roots.iter().find(|root| root.label == entry.root) {
            match current.root(root) {
                Lookup::Found(digest) if digest == entry.digest => {}
                Lookup::Found(digest) => self.say(format!(
                    "this checkout's digest of the root is {digest}, the entry names {}",
                    entry.digest
                )),
                Lookup::Absent => self.say("the root is absent in this checkout".to_owned()),
                Lookup::Failed(error) => {
                    self.say(format!("the root cannot be read in this checkout: {error}"));
                }
            }
        }
        for helper in entry.helpers {
            let name = format!("{}::{}", helper.krate, helper.name);
            self.exact(
                "helper",
                &name,
                helper.now,
                current.item(helper.krate, helper.name),
            );
        }
        for sender in entry.senders {
            for item in sender.evidence.items() {
                let name = format!("{}::{}", item.krate, item.name);
                let lookup = current.item(item.krate, item.name);
                match self.class_of(item.krate) {
                    Class::Daemon => self.exact("daemon item", &name, item.now, lookup),
                    _ => self.client("client item", &name, item.now, lookup),
                }
            }
            if let Evidence::SendsNone { crates } = &sender.evidence {
                for krate in *crates {
                    match current.krate(krate) {
                        Lookup::Found(_) => {}
                        Lookup::Absent => {
                            self.say(format!(
                                "the crate {krate}, which sends none, is absent in this checkout"
                            ));
                        }
                        Lookup::Failed(error) => {
                            self.say(format!(
                                "the crate {krate}, which sends none, cannot be read: {error}"
                            ));
                        }
                    }
                }
            }
        }
        for account in entry.accounts {
            let name = format!("{}::{}", account.krate, account.name);
            let lookup = current.item(account.krate, account.name);
            match self.class_of(account.krate) {
                Class::Daemon => self.exact("daemon account", &name, account.now, lookup),
                _ => self.client("client account", &name, account.now, lookup),
            }
        }
    }

    /// An item that must be there, with the digest the entry names.
    fn exact(&mut self, role: &str, name: &str, now: &str, lookup: Lookup) {
        match lookup {
            Lookup::Found(digest) if digest == now => {}
            Lookup::Found(digest) => self.say(format!(
                "the {role} {name} has the digest {digest} in this checkout, the entry names {now}"
            )),
            Lookup::Absent => self.say(format!("the {role} {name} is absent in this checkout")),
            Lookup::Failed(error) => {
                self.say(format!(
                    "the {role} {name} cannot be read in this checkout: {error}"
                ));
            }
        }
    }

    /// An item of a client crate: a digest, or absent where the entry says it is gone.
    fn client(&mut self, role: &str, name: &str, now: &str, lookup: Lookup) {
        match lookup {
            Lookup::Found(digest) if now == ABSENT => self.say(format!(
                "the {role} {name} is defined in this checkout, and the entry says it is gone ({digest})"
            )),
            Lookup::Found(digest) if digest == now => {}
            Lookup::Found(digest) => self.say(format!(
                "the {role} {name} has the digest {digest} in this checkout, the entry names {now}"
            )),
            Lookup::Absent if now == ABSENT => {}
            Lookup::Absent => self.say(format!(
                "the {role} {name} is absent in this checkout, and the entry names the digest {now}"
            )),
            Lookup::Failed(error) => {
                self.say(format!("the {role} {name} cannot be read in this checkout: {error}"));
            }
        }
    }

    fn sightings_of_this_checkout(&mut self) {
        let (entry, input) = (self.entry, self.input);
        let sightings = match input.current.sightings() {
            Ok(sightings) => sightings,
            Err(error) => {
                self.say(format!("the scan of this checkout failed: {error}"));
                return;
            }
        };
        let none_crates: BTreeSet<&str> = entry
            .senders
            .iter()
            .filter_map(|sender| match &sender.evidence {
                Evidence::SendsNone { crates } => Some(crates.iter().copied()),
                _ => None,
            })
            .flatten()
            .collect();
        for sighting in sightings {
            if none_crates.contains(sighting.krate.as_str()) {
                self.say(format!(
                    "{}::{} is a sighting in a crate that a row says sends none",
                    sighting.krate, sighting.name
                ));
                continue;
            }
            if self.class_of(&sighting.krate) == Class::Receiver {
                continue;
            }
            let covered = entry.senders.iter().any(|sender| {
                sender
                    .evidence
                    .items()
                    .iter()
                    .any(|item| item.krate == sighting.krate && item.name == sighting.name)
            });
            if covered {
                continue;
            }
            let account = entry
                .accounts
                .iter()
                .find(|account| account.krate == sighting.krate && account.name == sighting.name);
            match account {
                None => self.say(format!(
                    "the sighting {}::{} ({:?}) is no item of a row and no account covers it",
                    sighting.krate, sighting.name, sighting.kinds
                )),
                Some(account) => {
                    let lacking: Vec<&SightKind> = sighting
                        .kinds
                        .iter()
                        .filter(|kind| !account.kinds.contains(kind))
                        .collect();
                    if !lacking.is_empty() {
                        self.say(format!(
                            "the account for {}::{} lacks the kind {lacking:?} of its sighting ({:?})",
                            sighting.krate, sighting.name, sighting.kinds
                        ));
                    }
                }
            }
        }
    }

    /// A run against a release's tree.
    fn a_release(&mut self, release: &dyn Reader) {
        let entry = self.entry;
        if let Some(root) = self
            .input
            .roots
            .iter()
            .find(|root| root.label == entry.root)
        {
            match release.root(root) {
                Lookup::Found(digest) if digest == entry.recorded => {}
                Lookup::Found(digest) => self.say(format!(
                    "the release's tree has the digest {digest} for the root, the entry records {}",
                    entry.recorded
                )),
                Lookup::Absent => self.say("the root is absent in the release's tree".to_owned()),
                Lookup::Failed(error) => {
                    self.say(format!(
                        "the root cannot be read in the release's tree: {error}"
                    ));
                }
            }
        }
        for helper in entry.helpers {
            let name = format!("{}::{}", helper.krate, helper.name);
            match release.item(helper.krate, helper.name) {
                Lookup::Found(digest) if digest == helper.before => {}
                Lookup::Found(digest) => self.say(format!(
                    "the helper {name} has the digest {digest} in the release's tree, the entry names {}",
                    helper.before
                )),
                Lookup::Absent if helper.before == ABSENT => {}
                Lookup::Absent => self.say(format!(
                    "the helper {name} is absent in the release's tree, and the entry names the digest {}",
                    helper.before
                )),
                Lookup::Failed(error) => {
                    self.say(format!("the helper {name} cannot be read in the release's tree: {error}"));
                }
            }
        }
        for sender in entry.senders {
            for item in sender.evidence.items() {
                if self.class_of(item.krate) != Class::Client {
                    continue;
                }
                let name = format!("{}::{}", item.krate, item.name);
                match release.item(item.krate, item.name) {
                    Lookup::Found(digest) if item.across.iter().any(|(held, _)| *held == digest) => {}
                    Lookup::Found(digest) => self.say(format!(
                        "the item {name} has a text ({digest}) in the release's tree that the entry does not list"
                    )),
                    Lookup::Absent if item.across.iter().any(|(held, _)| *held == ABSENT) => {}
                    Lookup::Absent => self.say(format!(
                        "the item {name} is absent in the release's tree, and the entry lists no absent text"
                    )),
                    Lookup::Failed(error) => {
                        self.say(format!("the item {name} cannot be read in the release's tree: {error}"));
                    }
                }
            }
        }
    }
}

/// Holds what an entry's rule is made of to every release at its level: the root, digested alone,
/// and each helper the entry lists. A release that has another digest of one of them, or none, or
/// cannot be read, is named with its tag, for the root and for each helper apart. The senders, the
/// daemon's items and the accounts are not read here: they change with the code that sends, and a
/// reviewer reads them again.
///
/// No entry and no release give no problem.
pub fn check_held(
    entries: &[Narrower],
    roots: &[Root],
    releases: &[(&str, &dyn Reader)],
) -> Vec<String> {
    let mut out = Vec::new();
    for entry in entries {
        let say = |out: &mut Vec<String>, text: String| {
            out.push(format!("narrower {}: {text}", entry.root));
        };
        let Some(root) = roots.iter().find(|root| root.label == entry.root) else {
            say(
                &mut out,
                "no root has this label, so no release can be held to it".to_owned(),
            );
            continue;
        };
        for (tag, release) in releases {
            match release.root(root) {
                Lookup::Found(digest) if digest == entry.digest => {}
                Lookup::Found(digest) => say(
                    &mut out,
                    format!(
                        "{tag} has the digest {digest} for the root, the entry names {}",
                        entry.digest
                    ),
                ),
                Lookup::Absent => say(&mut out, format!("the root is absent in {tag}")),
                Lookup::Failed(error) => say(
                    &mut out,
                    format!("the root cannot be read in {tag}: {error}"),
                ),
            }
            for helper in entry.helpers {
                let name = format!("{}::{}", helper.krate, helper.name);
                match release.item(helper.krate, helper.name) {
                    Lookup::Found(digest) if digest == helper.now => {}
                    Lookup::Found(digest) => say(
                        &mut out,
                        format!(
                            "{tag} has the digest {digest} for the helper {name}, the entry names {}",
                            helper.now
                        ),
                    ),
                    Lookup::Absent => {
                        say(&mut out, format!("the helper {name} is absent in {tag}"));
                    }
                    Lookup::Failed(error) => say(
                        &mut out,
                        format!("the helper {name} cannot be read in {tag}: {error}"),
                    ),
                }
            }
        }
    }
    out
}
