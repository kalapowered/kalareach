//! The cases of the historical audit, on a repository a case makes with `git init`: its tags, an
//! origin that is a bare repository, and the production reader of snapshots.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use super::history::{Report, Snapshot, Tagged, audit_tags, expected_below, read_history};
use super::narrower::{Account, Evidence, Item, Narrower, Range, Sender};
use super::narrower_cases::leak;
use super::walker::{Lookup, SightKind, Sighting};

fn git(dir: &Path, args: &[&str], date: Option<i64>) -> String {
    let mut command = Command::new("git");
    command
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1");
    if let Some(date) = date {
        command
            .env("GIT_AUTHOR_DATE", format!("@{date} +0000"))
            .env("GIT_COMMITTER_DATE", format!("@{date} +0000"));
    }
    let output = command.output().expect("git runs");
    assert!(
        output.status.success(),
        "git {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("text")
}

fn write(root: &Path, path: &str, text: &str) {
    let full = root.join(path);
    std::fs::create_dir_all(full.parent().expect("a parent")).expect("a directory");
    std::fs::write(full, text).expect("a file");
}

const MANIFEST: &str = "[package]\nname = \"NAME\"\nversion = \"0.0.0\"\n";

/// The client crate's library at a step: a builder, an old builder, a later one that names a
/// method.
fn client_lib(step: usize) -> Option<String> {
    let target = if step >= 2 { 2 } else { 1 };
    let mut text = format!(
        "struct Link;\nimpl Link {{ fn target(&self) -> ActionTarget {{ ActionTarget {{ instance: {target} }} }} }}\n"
    );
    match step {
        0 => return None,
        1 | 2 => text.push_str("fn old_builder() { let _ = Method::AgentTurnCancel; }\n"),
        _ => text.push_str("fn names_one() { let _ = Method::AgentTurnSteer; }\n"),
    }
    Some(text)
}

/// A repository whose tags are the releases below level 0.11, and an origin that has them.
struct Repo {
    work: tempfile::TempDir,
    origin: tempfile::TempDir,
}

/// The releases: version, commit date, and the step whose content the commit holds. The three
/// releases of 0.4.0 give the order inside one version: a later date, and two of one date.
const RELEASES: [(&str, i64, usize); 8] = [
    ("0.1.0", 100, 0),
    ("0.2.0", 200, 1),
    ("0.3.0", 300, 2),
    ("0.4.0", 450, 3),
    ("0.4.0", 400, 4),
    ("0.4.0", 400, 5),
    ("0.10.0", 500, 6),
    ("0.11.0", 600, 7),
];

fn repo(unreadable_at: Option<usize>) -> Repo {
    let work = tempfile::tempdir().expect("a folder");
    let origin = tempfile::tempdir().expect("a folder");
    git(origin.path(), &["init", "--bare", "-b", "main"], None);
    git(work.path(), &["init", "-b", "main"], None);
    git(
        work.path(),
        &[
            "remote",
            "add",
            "origin",
            origin.path().to_str().expect("a path"),
        ],
        None,
    );
    for (at, (version, date, step)) in RELEASES.iter().enumerate() {
        let root = work.path();
        write(
            root,
            "crates/kr-protocol/Cargo.toml",
            &MANIFEST.replace("NAME", "kr-protocol"),
        );
        write(root, "crates/kr-protocol/src/lib.rs", "pub mod method;\n");
        write(
            root,
            "crates/kr-protocol/src/method.rs",
            "const NAME: &str = \"agent.turn.steer\";\n",
        );
        let client = root.join("crates/kr-client");
        if let Some(lib) = client_lib((*step).min(5)) {
            write(
                root,
                "crates/kr-client/Cargo.toml",
                &MANIFEST.replace("NAME", "kr-client"),
            );
            write(root, "crates/kr-client/src/lib.rs", &lib);
        } else {
            let _ = std::fs::remove_dir_all(client);
        }
        if unreadable_at == Some(at) {
            write(root, "crates/odd/Cargo.toml", "[workspace]\n");
        } else {
            let _ = std::fs::remove_dir_all(root.join("crates/odd"));
        }
        write(root, "notes.txt", &format!("{at}\n"));
        git(root, &["add", "-A"], None);
        git(
            root,
            &["commit", "-m", &format!("release {at}")],
            Some(*date),
        );
        let commit = git(root, &["rev-parse", "HEAD"], None).trim().to_owned();
        git(
            root,
            &["tag", &format!("packages/v{version}+{}", &commit[..12])],
            None,
        );
    }
    git(work.path(), &["push", "origin", "main", "--tags"], None);
    Repo { work, origin }
}

fn leaked(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

/// The entry for the repository: the builder, the old builder that only earlier tags have, an
/// account for the later one, and a crate that sends none.
fn entry(digests: &[String], tags: u32, first_tag: &'static str) -> Narrower {
    let [absent, one, two, old] = [
        "absent".to_owned(),
        digests[0].clone(),
        digests[1].clone(),
        digests[2].clone(),
    ];
    let sentence = "a text";
    let target: &'static [(&'static str, &'static str)] = leak(vec![
        (leaked(absent.clone()), sentence),
        (leaked(one), sentence),
        (leaked(two), sentence),
    ]);
    let old_builder: &'static [(&'static str, &'static str)] =
        leak(vec![(leaked(old), sentence), (leaked(absent), sentence)]);
    Narrower {
        level: "0.11",
        root: "the envelope a worker checks",
        recorded: "r",
        digest: "d",
        refuses: "x",
        rest: "x",
        registry: "x",
        unreached: "x",
        searched: &["x"],
        range: Range {
            first_tag,
            why_first: "x",
            tags,
        },
        helpers: &[],
        senders: leak(vec![
            Sender {
                class: "the companion",
                sends: "x",
                evidence: Evidence::Builds {
                    items: leak(vec![
                        Item {
                            krate: "kr_client",
                            name: "Link::target",
                            now: "n",
                            across: target,
                        },
                        Item {
                            krate: "kr_client",
                            name: "old_builder",
                            now: "absent",
                            across: old_builder,
                        },
                    ]),
                },
            },
            Sender {
                class: "kr-hook",
                sends: "x",
                evidence: Evidence::SendsNone {
                    crates: &["kr_hook"],
                },
            },
        ]),
        accounts: leak(vec![Account {
            krate: "kr_client",
            name: "names_one",
            kinds: &[SightKind::Names],
            now: "n",
            why: "x",
        }]),
    }
}

struct Read {
    expected: Vec<Tagged>,
    snapshots: Vec<Snapshot>,
    entry: Narrower,
}

/// Reads the repository once with an entry that lists no text, takes the digests the snapshots
/// show, and returns the entry that lists them.
fn read(repo: &Repo) -> Read {
    let first = leaked(String::new());
    let probe = entry(&["".into(), "".into(), "".into()], 7, first);
    let (_, snapshots) = read_history(repo.work.path(), &probe).expect("the history");
    let digest = |name: &str, tag_at: usize| match snapshots[tag_at]
        .items
        .get(&("kr_client".to_owned(), name.to_owned()))
    {
        Some(Lookup::Found(digest)) => digest.clone(),
        other => panic!("{name} at {tag_at}: {other:?}"),
    };
    let digests = [
        digest("Link::target", 1),
        digest("Link::target", 2),
        digest("old_builder", 1),
    ];
    let oldest = snapshots
        .iter()
        .min_by(|a, b| a.at.order().cmp(&b.at.order()))
        .expect("a snapshot")
        .at
        .tag
        .clone();
    let entry = entry(&digests, 7, leaked(oldest));
    let (expected, snapshots) = read_history(repo.work.path(), &entry).expect("the history");
    Read {
        expected,
        snapshots,
        entry,
    }
}

fn said(text: &str) -> String {
    format!("history the envelope a worker checks: {text}")
}

fn tag_at(read: &Read, at: usize) -> String {
    let mut ordered: Vec<&Tagged> = read.expected.iter().collect();
    ordered.sort_by(|a, b| a.order().cmp(&b.order()));
    ordered[at].tag.clone()
}

#[test]
fn the_history_of_a_repository_that_fits_its_entry_has_no_problem_and_is_reported_as_data() {
    let read = read(&repo(None));
    let report = audit_tags(&read.entry, &read.expected, &read.snapshots);
    assert_eq!(report.problems, Vec::<String>::new());
    let target: Vec<(String, Vec<String>)> = report
        .groups
        .iter()
        .filter(|group| group.name == "Link::target")
        .map(|group| (group.digest.clone(), group.tags.clone()))
        .collect();
    let all: Vec<String> = (0..7).map(|at| tag_at(&read, at)).collect();
    assert_eq!(target.len(), 3);
    assert_eq!(target[0], ("absent".to_owned(), vec![all[0].clone()]));
    assert_eq!(target[1].1, vec![all[1].clone()]);
    assert_eq!(target[2].1, all[2..].to_vec());
    // The old builder has two groups: its text at the two tags that had it, and absent.
    let old: Vec<(String, Vec<String>)> = report
        .groups
        .iter()
        .filter(|group| group.name == "old_builder")
        .map(|group| (group.digest.clone(), group.tags.clone()))
        .collect();
    assert_eq!(old.len(), 2);
    assert_eq!(old[0].0, "absent");
    assert_eq!(old[0].1.first(), Some(&all[0]));
    assert_eq!(old[1].1, vec![all[1].clone(), all[2].clone()]);
    // Each distinct text once with its tags: the builder has two texts, the later builder one.
    let mut shown: Vec<(&str, usize)> = report
        .texts
        .iter()
        .map(|shown| (shown.name.as_str(), shown.tags.len()))
        .collect();
    shown.sort_unstable();
    assert_eq!(
        shown,
        vec![
            ("Link::target", 1),
            ("Link::target", 5),
            ("names_one", 4),
            ("old_builder", 2),
        ]
    );
    // The account's span is the first and last tag that have it.
    assert_eq!(report.spans.len(), 1);
    assert_eq!(report.spans[0].name, "names_one");
    assert_eq!(report.spans[0].first, all[3]);
    assert_eq!(report.spans[0].last, all[6]);
}

#[test]
fn the_snapshots_must_be_the_releases_origin_lists() {
    let read = read(&repo(None));
    let at = |tag: &str| {
        read.expected
            .iter()
            .find(|t| t.tag == tag)
            .expect("a tag")
            .commit
            .clone()
    };
    // A snapshot left out.
    let mut missing: Vec<Snapshot> = Vec::new();
    for snapshot in &read.snapshots {
        missing.push(clone_snapshot(snapshot));
    }
    let left_out = missing.remove(3);
    let report = audit_tags(&read.entry, &read.expected, &missing);
    assert_eq!(
        report.problems,
        vec![said(&format!(
            "{} at {} is expected and has no snapshot",
            left_out.at.tag,
            at(&left_out.at.tag)
        ))]
    );
    assert!(report.groups.is_empty() && report.texts.is_empty() && report.spans.is_empty());
    // A snapshot that origin does not list, with the one that is left out.
    let mut extra: Vec<Snapshot> = read.snapshots.iter().map(clone_snapshot).collect();
    let mut stranger = clone_snapshot(&extra[0]);
    stranger.at.tag = "packages/v0.0.1+000000000000".to_owned();
    stranger.at.commit = "0".repeat(40);
    extra.push(stranger);
    let report = audit_tags(&read.entry, &read.expected, &extra);
    assert_eq!(
        report.problems,
        vec![said(&format!(
            "packages/v0.0.1+000000000000 at {} has a snapshot and is not expected",
            "0".repeat(40)
        ))]
    );
}

fn clone_snapshot(snapshot: &Snapshot) -> Snapshot {
    Snapshot {
        at: snapshot.at.clone(),
        names_a_method: snapshot.names_a_method.clone(),
        krates: snapshot.krates.clone(),
        items: snapshot.items.clone(),
        sightings: snapshot.sightings.clone(),
        records: snapshot.records.clone(),
    }
}

fn report_with(read: &Read, change: impl FnOnce(&mut Narrower, &mut Vec<Snapshot>)) -> Report {
    let mut entry = read.entry.clone();
    let mut snapshots: Vec<Snapshot> = read.snapshots.iter().map(clone_snapshot).collect();
    change(&mut entry, &mut snapshots);
    audit_tags(&entry, &read.expected, &snapshots)
}

fn snapshot_of<'a>(snapshots: &'a mut [Snapshot], tag: &str) -> &'a mut Snapshot {
    snapshots
        .iter_mut()
        .find(|s| s.at.tag == tag)
        .expect("a snapshot")
}

#[test]
fn the_count_the_oldest_tag_and_the_oldest_naming_release_are_each_held() {
    let read = read(&repo(None));
    let oldest = tag_at(&read, 0);
    let second = tag_at(&read, 1);
    let report = report_with(&read, |entry, _| entry.range.tags = 6);
    assert_eq!(
        report.problems,
        vec![said(
            "the entry says 6 tags and origin lists 7 below the level"
        )]
    );
    let report = report_with(&read, |entry, _| {
        entry.range.first_tag = leaked(second.clone())
    });
    assert_eq!(
        report.problems,
        vec![
            said(&format!(
                "the oldest release is {oldest}, the entry names {second}"
            )),
            said(&format!(
                "the oldest release whose method.rs names one of the six is {oldest}, the entry names {second}"
            )),
        ]
    );
    let report = report_with(&read, |_, snapshots| {
        snapshot_of(snapshots, &oldest).names_a_method = Ok(false);
        snapshot_of(snapshots, &tag_at(&read, 4)).names_a_method = Err("e".to_owned());
    });
    assert_eq!(
        report.problems,
        vec![
            said(&format!(
                "{}: method.rs cannot be read: e",
                tag_at(&read, 4)
            )),
            said(&format!(
                "the oldest release whose method.rs names one of the six is {second}, the entry names {oldest}"
            )),
        ]
    );
}

#[test]
fn a_text_the_entry_does_not_list_a_failed_reading_and_an_unreadable_manifest_name_the_tag() {
    let read = read(&repo(None));
    let third = tag_at(&read, 2);
    let report = report_with(&read, |entry, _| {
        let mut senders = entry.senders.to_vec();
        let Evidence::Builds { items } = &senders[0].evidence else {
            panic!("a row that builds");
        };
        let mut items = items.to_vec();
        items[0].across = &items[0].across[..2];
        senders[0].evidence = Evidence::Builds { items: leak(items) };
        entry.senders = leak(senders);
    });
    assert_eq!(report.problems.len(), 1);
    assert!(
        report.problems[0].starts_with(&said(&format!(
            "{third}: the item kr_client::Link::target has a text ("
        ))),
        "{:?}",
        report.problems
    );
    let report = report_with(&read, |_, snapshots| {
        let snapshot = snapshot_of(snapshots, &third);
        snapshot.items.insert(
            ("kr_client".to_owned(), "Link::target".to_owned()),
            Lookup::Failed("e".to_owned()),
        );
        snapshot.sightings = Err("scan".to_owned());
        snapshot
            .krates
            .insert("kr_hook".to_owned(), Lookup::Failed("k".to_owned()));
    });
    let problems: BTreeSet<String> = report.problems.into_iter().collect();
    assert_eq!(
        problems,
        BTreeSet::from([
            said(&format!(
                "{third}: the item kr_client::Link::target cannot be read: e"
            )),
            said(&format!("{third}: the scan failed: scan")),
            said(&format!("{third}: the crate kr_hook cannot be read: k")),
        ])
    );
    // A manifest that names no package, in a release's tree.
    let odd = repo(Some(2));
    let (_, snapshots) = read_history(odd.work.path(), &read.entry).expect("history");
    let unreadable = snapshots
        .iter()
        .find(|snapshot| snapshot.sightings.is_err())
        .expect("a snapshot whose scan failed");
    assert!(
        matches!(unreadable.krates.get("kr_hook"), Some(Lookup::Failed(_))),
        "a crate that no readable manifest names is unknown"
    );
}

#[test]
fn a_sighting_is_held_to_its_row_its_account_or_its_crate() {
    let read = read(&repo(None));
    let fourth = tag_at(&read, 3);
    let sighting = |krate: &str, name: &str, kinds: &[SightKind]| Sighting {
        krate: krate.to_owned(),
        name: name.to_owned(),
        kinds: kinds.iter().copied().collect(),
    };
    // A3: a sighting in a crate that sends none.
    let report = report_with(&read, |_, snapshots| {
        if let Ok(list) = &mut snapshot_of(snapshots, &fourth).sightings {
            list.push(sighting("kr_hook", "send", &[SightKind::Names]));
        }
    });
    assert_eq!(
        report.problems,
        vec![said(&format!(
            "{fourth}: kr_hook::send is a sighting in a crate that a row says sends none"
        ))]
    );
    // A4: no account, so each tag that has the later builder names it.
    let report = report_with(&read, |entry, _| entry.accounts = &[]);
    assert_eq!(report.problems.len(), 4);
    assert!(report.problems.iter().all(|problem| {
        problem.contains("names_one ({Names}) is no item of a row and no account covers it")
    }));
    // A4: a sighting in a daemon crate at a tag is not read; an account lacking a kind is.
    let report = report_with(&read, |_, snapshots| {
        if let Ok(list) = &mut snapshot_of(snapshots, &fourth).sightings {
            list.push(sighting("kr_controller", "daemon", &[SightKind::Request]));
            list.push(sighting("kr_protocol", "receiver", &[SightKind::Request]));
            list.push(sighting(
                "kr_client",
                "names_one",
                &[SightKind::Names, SightKind::Request],
            ));
        }
    });
    assert_eq!(
        report.problems,
        vec![said(&format!(
            "{fourth}: the account for kr_client::names_one lacks the kind [Request] of its sighting ({{Names, Request}})"
        ))]
    );
}

#[test]
fn an_item_or_account_that_is_gone_now_and_no_tag_has_is_stale() {
    let read = read(&repo(None));
    // An item with now absent that no tag defines.
    let report = report_with(&read, |_, snapshots| {
        for snapshot in snapshots.iter_mut() {
            snapshot.items.insert(
                ("kr_client".to_owned(), "old_builder".to_owned()),
                Lookup::Absent,
            );
        }
    });
    assert!(report.problems.contains(&said(
        "the item kr_client::old_builder is absent now and no release defines it"
    )));
    assert!(
        report
            .problems
            .iter()
            .any(|p| p.contains("is stale: no release has it"))
    );
    // An across digest that no tag has.
    let report = report_with(&read, |entry, _| {
        let mut senders = entry.senders.to_vec();
        let Evidence::Builds { items } = &senders[0].evidence else {
            panic!("a row that builds");
        };
        let mut items = items.to_vec();
        items[0].across = leak(vec![
            ("absent", "a"),
            (items[0].across[1].0, "b"),
            (items[0].across[2].0, "c"),
            ("nowhere", "d"),
        ]);
        senders[0].evidence = Evidence::Builds { items: leak(items) };
        entry.senders = leak(senders);
    });
    assert_eq!(
        report.problems,
        vec![said(
            "the text nowhere of kr_client::Link::target is stale: no release has it"
        )]
    );
    // An account that is gone now and that no tag has, and one with a digest that no tag has.
    let report = report_with(&read, |entry, snapshots| {
        let mut accounts = entry.accounts.to_vec();
        accounts[0].now = "absent";
        entry.accounts = leak(accounts);
        for snapshot in snapshots.iter_mut() {
            snapshot.records.retain(|key, _| key.1 != "names_one");
        }
    });
    assert!(report.problems.contains(&said(
        "the account kr_client::names_one is absent now and no release has it"
    )));
    let report = report_with(&read, |_, snapshots| {
        for snapshot in snapshots.iter_mut() {
            snapshot.records.retain(|key, _| key.1 != "names_one");
            if let Ok(list) = &mut snapshot.sightings {
                list.retain(|sighting| sighting.name != "names_one");
            }
        }
    });
    assert_eq!(
        report.problems,
        Vec::<String>::new(),
        "an account with a digest is not stale for want of a sighting"
    );
}

#[test]
fn a_daemon_item_and_a_daemon_account_cause_no_reading_and_no_text() {
    let repo = repo(None);
    let read = read(&repo);
    let mut entry = read.entry.clone();
    let mut senders = entry.senders.to_vec();
    senders.push(Sender {
        class: "the daemon",
        sends: "x",
        evidence: Evidence::Relays {
            items: leak(vec![Item {
                krate: "kr_controller",
                name: "relay",
                now: "n",
                across: &[],
            }]),
        },
    });
    entry.senders = leak(senders);
    let mut accounts = entry.accounts.to_vec();
    accounts.push(Account {
        krate: "kr_controller",
        name: "other",
        kinds: &[SightKind::Names],
        now: "n",
        why: "x",
    });
    entry.accounts = leak(accounts);
    let (expected, snapshots) = read_history(repo.work.path(), &entry).expect("history");
    assert!(snapshots.iter().all(|snapshot| {
        snapshot.items.keys().all(|key| key.0 != "kr_controller")
            && snapshot.records.keys().all(|key| key.0 != "kr_controller")
            && !snapshot.krates.contains_key("kr_controller")
    }));
    let report = audit_tags(&entry, &expected, &snapshots);
    assert_eq!(report.problems, Vec::<String>::new());
    assert!(
        report
            .spans
            .iter()
            .all(|span| span.krate != "kr_controller")
    );
    assert!(
        report
            .groups
            .iter()
            .all(|group| group.krate != "kr_controller")
    );
}

#[test]
fn the_releases_are_ordered_by_version_then_date_then_tag_and_only_below_the_level_are_read() {
    let repo = repo(None);
    let level = "0.11".parse().expect("a level");
    let expected = expected_below(repo.work.path(), level).expect("the releases");
    assert_eq!(
        expected.len(),
        7,
        "the tag at the level is not in the range"
    );
    let versions: Vec<String> = expected
        .iter()
        .map(|tagged| format!("{}.{}", tagged.version.major, tagged.version.minor))
        .collect();
    assert_eq!(versions, ["0.1", "0.2", "0.3", "0.4", "0.4", "0.4", "0.10"]);
    // 0.10 comes after 0.4, and inside 0.4 the releases are by date, then by tag.
    let dates: Vec<i64> = expected[3..6]
        .iter()
        .map(|tagged| tagged.committed)
        .collect();
    assert_eq!(dates, [400, 400, 450]);
    assert!(expected[3].tag < expected[4].tag);
}

#[test]
fn an_origin_with_a_tag_the_checkout_lacks_is_refused_before_any_snapshot() {
    let repo = repo(None);
    let read = read(&repo);
    let head = git(repo.work.path(), &["rev-parse", "HEAD~1"], None)
        .trim()
        .to_owned();
    git(
        repo.work.path(),
        &[
            "push",
            "origin",
            &format!("{head}:refs/tags/packages/v0.3.5+{}", &head[..12]),
        ],
        None,
    );
    let error = read_history(repo.work.path(), &read.entry)
        .err()
        .expect("an error before any snapshot");
    assert!(error.contains("packages/v0.3.5"), "{error}");
    let _ = &repo.origin;
}
