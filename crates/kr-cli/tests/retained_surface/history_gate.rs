//! The gate of the historical reader: every release tag read with an entry of its own.
//!
//! The published table holds no entry while no input rule has narrowed, so the reader would read no
//! tag. This case gives it a scratch entry at a level above every release, runs the production
//! extraction, index, scan, source and audit paths over all of them, and holds the result to the
//! gate: every tag read, no scan, lookup or source that failed, a source for every sighting, and the
//! whole run inside an hour.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::history::{
    Report, Snapshot, Tagged, audit_tags, print_report, read_history, version_of_tag,
};
use super::narrower::{
    ABSENT, DAEMON_CRATES, Evidence, Item, Narrower, RECEIVER_CRATES, Range, Sender,
};
use super::walker::Lookup;

/// Whether the crate is read as a sender: the gate holds its own copy of the rule, apart from the
/// reader's and the audit's.
fn client(krate: &str) -> bool {
    !RECEIVER_CRATES.contains(&krate) && !DAEMON_CRATES.contains(&krate)
}

/// The items of the entry's rows in client crates, and the crates its rows say send none, read from
/// the evidence's own variants and not through the audit's helpers or `Evidence::items`.
fn rows_and_silent(entry: &Narrower) -> (Vec<&'static Item>, BTreeSet<&'static str>) {
    let mut rows = Vec::new();
    let mut silent = BTreeSet::new();
    for sender in entry.senders.iter() {
        match &sender.evidence {
            Evidence::Builds { items } | Evidence::Relays { items } => {
                rows.extend(items.iter().filter(|item| client(item.krate)));
            }
            Evidence::SendsNone { crates } => silent.extend(crates.iter().copied()),
        }
    }
    (rows, silent)
}

const CLIENT_ITEMS: &[Item] = &[Item {
    krate: "companion_tauri",
    name: "Link::target",
    now: "scratch",
    across: &[("absent", "x")],
}];
const RELAY_ITEMS: &[Item] = &[Item {
    krate: "kr_cli",
    name: "relay",
    now: "absent",
    across: &[("absent", "x")],
}];
const DAEMON_ITEMS: &[Item] = &[Item {
    krate: "kr_controller",
    name: "relay",
    now: "scratch",
    across: &[],
}];

/// An entry whose digests are not real: its own problems are the ones the gate expects.
const SCRATCH: Narrower = Narrower {
    // Set above the newest release tag when the gate runs: see `level_above`.
    level: "",
    root: "the envelope a worker checks",
    recorded: "scratch",
    digest: "scratch",
    refuses: "x",
    rest: "x",
    registry: "x",
    unreached: "x",
    searched: &["x"],
    range: Range {
        first_tag: "scratch",
        why_first: "x",
        tags: 1,
    },
    helpers: &[],
    senders: &[
        Sender {
            class: "the companion",
            sends: "x",
            evidence: Evidence::Builds {
                items: CLIENT_ITEMS,
            },
        },
        Sender {
            class: "a device's mutation relayed by the daemon",
            sends: "x",
            evidence: Evidence::Relays {
                items: DAEMON_ITEMS,
            },
        },
        Sender {
            class: "kr",
            sends: "x",
            evidence: Evidence::Relays { items: RELAY_ITEMS },
        },
        Sender {
            class: "kr-hook",
            sends: "x",
            evidence: Evidence::SendsNone {
                crates: &["kr_hook"],
            },
        },
    ],
    accounts: &[],
};

/// The release tags as `git for-each-ref` lists them, each peeled to its commit where it is an
/// annotated tag, in the order of releases (version, commit date, tag). This list is made apart
/// from the reader's: it asks git for the tags, the commits and their dates and nothing else.
pub fn listed_releases(repository: &Path) -> Result<Vec<Tagged>, String> {
    let output = Command::new("git")
        .args([
            "for-each-ref",
            "--format=%(refname:strip=2)%09%(objectname)%09%(*objectname)%09%(committerdate:unix)%09%(*committerdate:unix)",
            "refs/tags/packages/v*",
        ])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("git for-each-ref: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git for-each-ref: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut listed = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [tag, object, peeled, date, peeled_date] = fields.as_slice() else {
            return Err(format!(
                "git for-each-ref: a line of {} fields: {line}",
                fields.len()
            ));
        };
        let (commit, date) = if peeled.is_empty() {
            (object, date)
        } else {
            (peeled, peeled_date)
        };
        listed.push(Tagged {
            tag: (*tag).to_owned(),
            commit: (*commit).to_owned(),
            version: version_of_tag(tag).ok_or_else(|| format!("{tag} is no release tag"))?,
            committed: date
                .parse()
                .map_err(|error| format!("the date of {tag}: {error}"))?,
        });
    }
    listed.sort_by(|left, right| left.order().cmp(&right.order()));
    Ok(listed)
}

/// The level above the newest release in `listed`, so that every release is below it.
pub fn level_above(listed: &[Tagged]) -> String {
    let newest = listed
        .iter()
        .map(|tagged| tagged.version)
        .max()
        .expect("a release");
    if newest.major == 0 {
        format!("0.{}", newest.minor + 1)
    } else {
        format!("{}", newest.major + 1)
    }
}

/// Where the snapshots are not the tags and commits `git` lists, in the same order: a snapshot
/// left out, added, repeated or put in place of another.
pub fn release_problems(listed: &[Tagged], snapshots: &[Snapshot]) -> Vec<String> {
    let mut problems = Vec::new();
    let read: Vec<(&str, &str)> = snapshots
        .iter()
        .map(|snapshot| (snapshot.at.tag.as_str(), snapshot.at.commit.as_str()))
        .collect();
    let wanted: Vec<(&str, &str)> = listed
        .iter()
        .map(|tagged| (tagged.tag.as_str(), tagged.commit.as_str()))
        .collect();
    if read.len() != wanted.len() {
        problems.push(format!(
            "{} snapshots for {} release tags",
            read.len(),
            wanted.len()
        ));
    }
    for (at, (found, expected)) in read.iter().zip(&wanted).enumerate() {
        if found != expected {
            problems.push(format!(
                "snapshot {at} is {} at {}, the tags give {} at {}",
                found.0, found.1, expected.0, expected.1
            ));
        }
    }
    let distinct: BTreeSet<&(&str, &str)> = read.iter().collect();
    if distinct.len() != read.len() {
        problems.push("a release is read twice".to_owned());
    }
    problems
}

/// Where a snapshot lacks a lookup the entry needs, holds a lookup that failed, or gives `Absent`
/// where the entry lists no `absent` text; a source that could not be read; a sighting with no
/// source.
pub fn snapshot_problems(entry: &Narrower, snapshots: &[Snapshot]) -> Vec<String> {
    let mut problems = Vec::new();
    let (items, silent) = rows_and_silent(entry);
    let wanted_items: BTreeSet<(String, String)> = items
        .iter()
        .map(|item| (item.krate.to_owned(), item.name.to_owned()))
        .collect();
    let wanted_crates: BTreeSet<String> = items
        .iter()
        .map(|item| item.krate)
        .chain(
            entry
                .accounts
                .iter()
                .map(|account| account.krate)
                .filter(|krate| client(krate)),
        )
        .chain(silent.iter().copied())
        .map(str::to_owned)
        .collect();
    // A crate may be absent from a tag where one of its items is (the crate came later), where an
    // account of it spans only some tags, and where a row that sends none reads it.
    let may_be_absent: BTreeSet<&str> = items
        .iter()
        .filter(|item| item.across.iter().any(|(digest, _)| *digest == ABSENT))
        .map(|item| item.krate)
        .chain(entry.accounts.iter().map(|account| account.krate))
        .chain(silent.iter().copied())
        .collect();
    let absent_text = |item: &Item| item.across.iter().any(|(digest, _)| *digest == ABSENT);
    for snapshot in snapshots {
        let tag = &snapshot.at.tag;
        let keys: BTreeSet<String> = snapshot.krates.keys().cloned().collect();
        for krate in wanted_crates.difference(&keys) {
            problems.push(format!("{tag}: no reading of the crate {krate}"));
        }
        for krate in keys.difference(&wanted_crates) {
            problems.push(format!(
                "{tag}: a reading of the crate {krate}, which no row names"
            ));
        }
        for (krate, lookup) in &snapshot.krates {
            match lookup {
                Lookup::Failed(error) => {
                    problems.push(format!("{tag}: the crate {krate}: {error}"));
                }
                Lookup::Absent if !may_be_absent.contains(krate.as_str()) => {
                    problems.push(format!("{tag}: the crate {krate} is absent"));
                }
                _ => {}
            }
        }
        let keys: BTreeSet<(String, String)> = snapshot.items.keys().cloned().collect();
        for (krate, name) in wanted_items.difference(&keys) {
            problems.push(format!("{tag}: no reading of the item {krate}::{name}"));
        }
        for (krate, name) in keys.difference(&wanted_items) {
            problems.push(format!(
                "{tag}: a reading of the item {krate}::{name}, which no row names"
            ));
        }
        for ((krate, name), lookup) in &snapshot.items {
            match lookup {
                Lookup::Failed(error) => {
                    problems.push(format!("{tag}: the item {krate}::{name}: {error}"));
                }
                Lookup::Absent
                    if !items.iter().any(|item| {
                        item.krate == krate && item.name == name && absent_text(item)
                    }) =>
                {
                    problems.push(format!(
                        "{tag}: the item {krate}::{name} is absent and the entry lists no absent text for it"
                    ));
                }
                _ => {}
            }
        }
        if let Err(error) = &snapshot.names_a_method {
            problems.push(format!("{tag}: method.rs cannot be read: {error}"));
        }
        for (item, error) in &snapshot.source_errors {
            problems.push(format!(
                "{tag}: the source of {item:?} cannot be read: {error}"
            ));
        }
        match &snapshot.sightings {
            Err(error) => problems.push(format!("{tag}: the scan failed: {error}")),
            Ok(sightings) => {
                for sighting in sightings {
                    let key = (sighting.krate.clone(), sighting.name.clone());
                    if !snapshot.records.contains_key(&key) {
                        problems.push(format!("{tag}: no source for {key:?}"));
                    }
                }
            }
        }
    }
    problems
}

/// Where the problems the audit reported are not the ones `expected` lists, as a set of texts.
pub fn audit_differences(report: &Report, expected: &[String]) -> Vec<String> {
    let reported: BTreeSet<&String> = report.problems.iter().collect();
    let wanted: BTreeSet<&String> = expected.iter().collect();
    let mut differences = Vec::new();
    for problem in wanted.difference(&reported) {
        differences.push(format!("expected and not reported: {problem}"));
    }
    for problem in reported.difference(&wanted) {
        differences.push(format!("reported and not expected: {problem}"));
    }
    if report.problems.len() != reported.len() {
        differences.push("a problem is reported twice".to_owned());
    }
    differences
}

/// The problems the audit is to report for `entry` over `listed` and `snapshots`, read here again
/// and apart from the audit: the tags come from the list `git` gave, the item texts and the
/// sightings from the snapshots, and the rows from the entry. It calls none of the audit's
/// functions. It holds the problems that an entry made wrong on purpose has: the range against the
/// tag list (the count, the oldest release, the oldest release whose method.rs names one of the
/// six), each text an item has at a tag that its row does not list, and each sighting in a client
/// crate that no row names as an item and no account covers. A crate that a row says sends none, an
/// unreadable method.rs, a failed lookup and a stale text are the audit's other problems: they are
/// not expected, and each shows as a difference.
pub fn expected_audit_problems(
    entry: &Narrower,
    listed: &[Tagged],
    snapshots: &[Snapshot],
) -> Vec<String> {
    let said = |text: String| format!("history {}: {text}", entry.root);
    let at: BTreeMap<&str, &Snapshot> = snapshots
        .iter()
        .map(|snapshot| (snapshot.at.tag.as_str(), snapshot))
        .collect();
    let mut problems = Vec::new();
    if listed.len() != entry.range.tags as usize {
        problems.push(said(format!(
            "the entry says {} tags and origin lists {} below the level",
            entry.range.tags,
            listed.len()
        )));
    }
    if let Some(oldest) = listed.first()
        && oldest.tag != entry.range.first_tag
    {
        problems.push(said(format!(
            "the oldest release is {}, the entry names {}",
            oldest.tag, entry.range.first_tag
        )));
    }
    let naming = listed.iter().find(|tagged| {
        at.get(tagged.tag.as_str())
            .is_some_and(|snapshot| matches!(snapshot.names_a_method, Ok(true)))
    });
    if let Some(first) = naming
        && first.tag != entry.range.first_tag
    {
        problems.push(said(format!(
            "the oldest release whose method.rs names one of the six is {}, the entry names {}",
            first.tag, entry.range.first_tag
        )));
    }
    let (rows, sends_none) = rows_and_silent(entry);
    for item in &rows {
        let key = (item.krate.to_owned(), item.name.to_owned());
        let mut seen: Vec<String> = Vec::new();
        for tagged in listed {
            let Some(snapshot) = at.get(tagged.tag.as_str()) else {
                continue;
            };
            let digest = match snapshot.items.get(&key) {
                Some(Lookup::Found(digest)) => digest.clone(),
                Some(Lookup::Absent) => ABSENT.to_owned(),
                None => {
                    problems.push(said(format!(
                        "{}: the snapshot has no reading of the item {}::{}",
                        tagged.tag, item.krate, item.name
                    )));
                    continue;
                }
                Some(Lookup::Failed(_)) => continue,
            };
            if seen.contains(&digest) {
                continue;
            }
            if !item.across.iter().any(|(held, _)| *held == digest) {
                problems.push(said(format!(
                    "{}: the item {}::{} has a text ({digest}) that the entry does not list",
                    tagged.tag, item.krate, item.name
                )));
            }
            seen.push(digest);
        }
    }
    for tagged in listed {
        let Some(Ok(sightings)) = at.get(tagged.tag.as_str()).map(|s| &s.sightings) else {
            continue;
        };
        for sighting in sightings {
            let named = rows
                .iter()
                .any(|item| item.krate == sighting.krate && item.name == sighting.name)
                || entry.accounts.iter().any(|account| {
                    account.krate == sighting.krate && account.name == sighting.name
                });
            if client(&sighting.krate) && !sends_none.contains(sighting.krate.as_str()) && !named {
                problems.push(said(format!(
                    "{}: the sighting {}::{} ({:?}) is no item of a row and no account covers it",
                    tagged.tag, sighting.krate, sighting.name, sighting.kinds
                )));
            }
        }
    }
    problems
}

/// The report the gate in `retained_history_gate` reads, tab separated: for each snapshot a
/// `release` line, a `scan` line (`ok` with the number of sightings, or `failed` with the text), a
/// `sighting` line for each sighting and an `extent` line for each range of lines that an item of a
/// sighting covers.
fn render_report(snapshots: &[Snapshot]) -> String {
    let one_line = |text: &str| text.replace(['\t', '\n'], " ");
    let mut out = String::new();
    for snapshot in snapshots {
        let tag = &snapshot.at.tag;
        out.push_str(&format!("release\t{tag}\t{}\n", snapshot.at.commit));
        match &snapshot.sightings {
            Ok(sightings) => {
                out.push_str(&format!("scan\t{tag}\tok\t{}\n", sightings.len()));
                for sighting in sightings {
                    let kinds: Vec<String> = sighting
                        .kinds
                        .iter()
                        .map(|kind| format!("{kind:?}"))
                        .collect();
                    out.push_str(&format!(
                        "sighting\t{tag}\t{}\t{}\t{}\n",
                        sighting.krate,
                        one_line(&sighting.name),
                        kinds.join(",")
                    ));
                }
                for ((krate, name), extents) in &snapshot.extents {
                    for (file, first, last) in extents {
                        out.push_str(&format!(
                            "extent\t{tag}\t{krate}\t{}\t{file}\t{first}\t{last}\n",
                            one_line(name)
                        ));
                    }
                }
            }
            Err(error) => out.push_str(&format!("scan\t{tag}\tfailed\t{}\n", one_line(error))),
        }
    }
    out
}

#[test]
#[ignore = "reads every release tag; run by hand with --show-output"]
fn the_reader_reads_every_release_tag_with_a_scratch_entry() {
    let repository = super::repository();
    let started = Instant::now();
    let listed = listed_releases(&repository).expect("the release tags");
    let entry = Narrower {
        level: Box::leak(level_above(&listed).into_boxed_str()),
        ..SCRATCH
    };
    let (expected, snapshots) = read_history(&repository, &entry)
        .unwrap_or_else(|error| panic!("the history of the scratch entry: {error}"));
    let report = audit_tags(&entry, &expected, &snapshots);
    print_report(&report);
    for problem in &report.problems {
        println!("problem {problem}");
    }
    let took = started.elapsed();
    // The report for the gate in its own target: where `KR_HISTORY_REPORT` names a file it is written.
    if let Some(path) = std::env::var_os("KR_HISTORY_REPORT") {
        let report = render_report(&snapshots);
        assert!(
            !report.contains("\t0\t0\n"),
            "an extent at line 0: the tokens carry no line numbers"
        );
        std::fs::write(&path, report).expect("the report is written");
    }
    println!(
        "read {} releases of {} tags with the scratch entry in {took:?}",
        snapshots.len(),
        listed.len()
    );
    let mut problems = release_problems(&listed, &snapshots);
    problems.extend(snapshot_problems(&entry, &snapshots));
    problems.extend(audit_differences(
        &report,
        &expected_audit_problems(&entry, &listed, &snapshots),
    ));
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        took < Duration::from_secs(3600),
        "{took:?} is over the hour"
    );
}
