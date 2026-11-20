//! The gate of the historical reader: every release tag read with an entry of its own.
//!
//! The published table holds no entry while no input rule has narrowed, so the reader would read no
//! tag. This case gives it a scratch entry at a level above every release, runs the production
//! extraction, index, scan, source and audit paths over all of them, and holds the result to the
//! gate: every tag read, no scan, lookup or source that failed, a source for every sighting, and the
//! whole run inside an hour.

use std::time::{Duration, Instant};

use super::history::{audit_tags, print_report, read_history};
use super::narrower::{Evidence, Item, Narrower, Range, Sender};
use super::walker::Lookup;

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

/// An entry whose digests are not real: its own problems are the ones the case expects.
const SCRATCH: Narrower = Narrower {
    level: "0.79",
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

#[test]
#[ignore = "reads every release tag; run by hand with --show-output"]
fn the_reader_reads_every_release_tag_with_a_scratch_entry() {
    let repository = super::repository();
    let started = Instant::now();
    let tags = std::process::Command::new("git")
        .args(["tag", "-l", "packages/v*"])
        .current_dir(&repository)
        .output()
        .expect("git tag");
    let tags = String::from_utf8_lossy(&tags.stdout).lines().count();
    let (expected, snapshots) = read_history(&repository, &SCRATCH)
        .unwrap_or_else(|error| panic!("the history of the scratch entry: {error}"));
    let report = audit_tags(&SCRATCH, &expected, &snapshots);
    print_report(&report);
    let took = started.elapsed();
    println!(
        "read {} releases of {tags} tags with the scratch entry in {took:?}",
        snapshots.len()
    );
    assert_eq!(snapshots.len(), tags, "a snapshot for every tag");
    for snapshot in &snapshots {
        let tag = &snapshot.at.tag;
        let sightings = snapshot
            .sightings
            .as_ref()
            .unwrap_or_else(|error| panic!("{tag}: the scan failed: {error}"));
        assert!(snapshot.names_a_method.is_ok(), "{tag}");
        assert!(
            snapshot.source_errors.is_empty(),
            "{tag}: {:?}",
            snapshot.source_errors
        );
        for (item, lookup) in &snapshot.items {
            assert!(
                !matches!(lookup, Lookup::Failed(_)),
                "{tag}: {item:?}: {lookup:?}"
            );
        }
        for (krate, lookup) in &snapshot.krates {
            assert!(
                !matches!(lookup, Lookup::Failed(_)),
                "{tag}: {krate}: {lookup:?}"
            );
        }
        for sighting in sightings {
            let key = (sighting.krate.clone(), sighting.name.clone());
            assert!(
                snapshot.records.contains_key(&key),
                "{tag}: no source for {key:?}"
            );
        }
    }
    // The problems are the scratch entry's own: its row, its range and what no row covers.
    for problem in &report.problems {
        let failed = ["the scan failed", "cannot be read", "sightings failed"]
            .iter()
            .any(|words| problem.contains(words));
        assert!(!failed, "{problem}");
    }
    assert!(
        took < Duration::from_secs(3600),
        "{took:?} is over the hour"
    );
}
