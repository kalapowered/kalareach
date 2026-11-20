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
        Tree::sightings(self, &|_| true)
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
