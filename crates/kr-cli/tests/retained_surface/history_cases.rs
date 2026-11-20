//! The cases of the historical audit, on a repository a case makes with `git init`: its tags, an
//! origin that is a bare repository, and the production reader of snapshots.

use std::path::Path;
use std::process::Command;

use quote::ToTokens as _;

use super::history::{
    Group, Report, Shown, Snapshot, Span, Tagged, audit_tags, expected_below, read_history,
};
use super::history_gate::{
    audit_differences, expected_audit_problems, level_above, listed_releases, release_problems,
    snapshot_problems,
};
use super::narrower::{Account, Evidence, Item, Narrower, Range, Sender};
use super::narrower_cases::leak;
use super::walker::{Lookup, SightKind, Sighting, Source};

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
const APP: &str = "apps/x/src-tauri";

/// The text of each function of the fixture, so that the digests a case expects are made apart
/// from the walker.
fn target_text(instance: u8) -> String {
    format!("fn target(&self) -> ActionTarget {{ ActionTarget {{ instance: {instance} }} }}")
}
const RELAY: &str = "fn relay(value: u8) -> u8 { value }";
const OLD_BUILDER: &str = "fn old_builder() { let _ = Method::AgentTurnCancel; }";
const NAMES_ONE: &str = "fn names_one() { let _ = Method::AgentTurnSteer; }";
const OTHER_ONE: &str = "fn other_one() { let _ = Method::AgentTurnCancel; }";

/// The companion's library at a step: the builder (its target changes at the third release), a
/// relay that builds nothing, an old builder, and a later one that names a method; the later one
/// moves unchanged into its own file at the last release.
fn app_lib(step: usize) -> Option<String> {
    if step == 0 {
        return None;
    }
    let instance = if step >= 2 { 2 } else { 1 };
    let mut text = format!(
        "struct Link;\nimpl Link {{ {} }}\n{RELAY}\n",
        target_text(instance)
    );
    match step {
        1 | 2 => text.push_str(&format!("{OLD_BUILDER}\n")),
        3..=5 => text.push_str(&format!("{NAMES_ONE}\n")),
        _ => text.push_str("mod more;\n"),
    }
    Some(text)
}

/// A repository whose tags are the releases below level 0.11, and an origin that has them.
struct Repo {
    work: tempfile::TempDir,
    origin: tempfile::TempDir,
    /// The tag of each release, in the order of `RELEASES`.
    tags: Vec<String>,
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
    ("0.10.0", 350, 6),
    ("0.11.0", 600, 7),
];

/// `unreadable_at` is the release whose tree holds a manifest that names no package, `broken_at`
/// the one with a file in the account-only crate that does not parse.
fn repo(unreadable_at: Option<usize>, broken_at: Option<usize>) -> Repo {
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
    let root = work.path();
    let mut tags = Vec::new();
    for (at, (version, date, step)) in RELEASES.iter().enumerate() {
        let mut members = vec!["crates/kr-protocol"];
        if app_lib(*step).is_some() {
            members.extend(["crates/kr-other", APP]);
        }
        if unreadable_at == Some(at) {
            members.push("crates/odd");
        }
        write(
            root,
            "Cargo.toml",
            &format!("[workspace]\nmembers = {members:?}\nresolver = \"2\"\n"),
        );
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
        let remove = |path: &str| {
            let _ = std::fs::remove_dir_all(root.join(path));
        };
        match app_lib(*step) {
            Some(lib) => {
                write(
                    root,
                    &format!("{APP}/Cargo.toml"),
                    &MANIFEST.replace("NAME", "companion-tauri"),
                );
                write(root, &format!("{APP}/src/lib.rs"), &lib);
                if *step >= 6 {
                    write(
                        root,
                        &format!("{APP}/src/more.rs"),
                        &format!("{NAMES_ONE}\n"),
                    );
                }
                write(
                    root,
                    "crates/kr-other/Cargo.toml",
                    &MANIFEST.replace("NAME", "kr-other"),
                );
                let declared = if broken_at == Some(at) {
                    "mod broken;\n"
                } else {
                    ""
                };
                write(
                    root,
                    "crates/kr-other/src/lib.rs",
                    &format!("{OTHER_ONE}\n{declared}"),
                );
            }
            None => {
                remove("apps/x");
                remove("crates/kr-other");
            }
        }
        if broken_at == Some(at) {
            write(root, "crates/kr-other/src/broken.rs", "fn (\n");
        } else {
            let _ = std::fs::remove_file(root.join("crates/kr-other/src/broken.rs"));
        }
        if unreadable_at == Some(at) {
            write(root, "crates/odd/Cargo.toml", "[workspace]\n");
        } else {
            remove("crates/odd");
        }
        write(root, "notes.txt", &format!("{at}\n"));
        git(root, &["add", "-A"], None);
        git(
            root,
            &["commit", "-m", &format!("release {at}")],
            Some(*date),
        );
        let commit = git(root, &["rev-parse", "HEAD"], None).trim().to_owned();
        let tag = format!("packages/v{version}+{}", &commit[..12]);
        git(root, &["tag", &tag], None);
        tags.push(tag);
    }
    git(work.path(), &["push", "origin", "main", "--tags"], None);
    Repo { work, origin, tags }
}

fn leaked(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

/// The entry for the repository: the builder and the old builder (that only earlier tags have),
/// a relay that no sighting names, accounts for the later builder and for an account-only crate,
/// and a crate that sends none.
fn entry(digests: &[String; 4], tags: u32, first_tag: &'static str) -> Narrower {
    let sentence = "a text";
    let across = |texts: Vec<&String>| -> &'static [(&'static str, &'static str)] {
        let mut pairs = vec![("absent", sentence)];
        pairs.extend(
            texts
                .into_iter()
                .map(|text| (leaked(text.clone()), sentence)),
        );
        leak(pairs)
    };
    let old_builder: &'static [(&'static str, &'static str)] = leak(vec![
        (leaked(digests[2].clone()), sentence),
        ("absent", sentence),
    ]);
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
                            krate: "companion_tauri",
                            name: "Link::target",
                            now: "n",
                            across: across(vec![&digests[0], &digests[1]]),
                        },
                        Item {
                            krate: "companion_tauri",
                            name: "old_builder",
                            now: "absent",
                            across: old_builder,
                        },
                    ]),
                },
            },
            Sender {
                class: "kr",
                sends: "x",
                evidence: Evidence::Relays {
                    items: leak(vec![Item {
                        krate: "companion_tauri",
                        name: "relay",
                        now: "n",
                        across: across(vec![&digests[3]]),
                    }]),
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
        accounts: leak(vec![
            Account {
                krate: "companion_tauri",
                name: "names_one",
                kinds: &[SightKind::Names],
                now: "n",
                why: "x",
            },
            Account {
                krate: "kr_other",
                name: "other_one",
                kinds: &[SightKind::Names],
                now: "n",
                why: "x",
            },
        ]),
    }
}

struct Read {
    expected: Vec<Tagged>,
    snapshots: Vec<Snapshot>,
    entry: Narrower,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The source of an item as the walker is to give it: made here from the text with `syn`, and the
/// digest of the record the walker documents.
fn source_of(krate: &str, file: &str, label: &str, text: &str) -> Source {
    let text = if label.contains("::") {
        syn::parse_str::<syn::ImplItemFn>(text)
            .expect("a method")
            .to_token_stream()
            .to_string()
    } else {
        syn::parse_str::<syn::ItemFn>(text)
            .expect("a function")
            .to_token_stream()
            .to_string()
    };
    let record = format!("{krate} {file} {label}\n{text}\n");
    Source {
        digest: hex(&kr_cbor::sha256(record.as_bytes())),
        text,
        files: vec![file.to_owned()],
    }
}

fn app_source(label: &str, file: &str, text: &str) -> Source {
    source_of("companion_tauri", &format!("{APP}/src/{file}"), label, text)
}

/// Reads the repository with the entry that lists the digests of the fixture's items, made here
/// from their texts, and the repository's oldest tag.
fn read(repo: &Repo) -> Read {
    let lib = "lib.rs";
    let digests = [
        app_source("Link::target", lib, &target_text(1)).digest,
        app_source("Link::target", lib, &target_text(2)).digest,
        app_source("old_builder", lib, OLD_BUILDER).digest,
        app_source("relay", lib, RELAY).digest,
    ];
    let entry = entry(&digests, 7, leaked(repo.tags[0].clone()));
    let (expected, snapshots) = read_history(repo.work.path(), &entry).expect("the history");
    Read {
        expected,
        snapshots,
        entry,
    }
}

/// The distinct texts of the fixture's items and accounts, each with the tags that have it, in the
/// order of crate, item and digest. `all` is the tags of the snapshots in order: the relay has no
/// sighting, and the account that moved between files has two digests and one text.
fn fixture_texts(all: &[String]) -> Vec<Shown> {
    let lib = "lib.rs";
    let other = source_of(
        "kr_other",
        "crates/kr-other/src/lib.rs",
        "other_one",
        OTHER_ONE,
    );
    let mut texts = vec![
        shown(
            "companion_tauri",
            "Link::target",
            app_source("Link::target", lib, &target_text(1)),
            &all[1..2],
        ),
        shown(
            "companion_tauri",
            "Link::target",
            app_source("Link::target", lib, &target_text(2)),
            &all[2..],
        ),
        shown(
            "companion_tauri",
            "names_one",
            app_source("names_one", lib, NAMES_ONE),
            &all[3..6],
        ),
        shown(
            "companion_tauri",
            "names_one",
            app_source("names_one", "more.rs", NAMES_ONE),
            &all[6..],
        ),
        shown(
            "companion_tauri",
            "old_builder",
            app_source("old_builder", lib, OLD_BUILDER),
            &all[1..3],
        ),
        shown(
            "companion_tauri",
            "relay",
            app_source("relay", lib, RELAY),
            &all[1..],
        ),
        shown("kr_other", "other_one", other, &all[1..]),
    ];
    texts.sort_by(|a, b| {
        (&a.krate, &a.name, &a.source.digest).cmp(&(&b.krate, &b.name, &b.source.digest))
    });
    texts
}

fn said(text: &str) -> String {
    format!("history the envelope a worker checks: {text}")
}

fn tag_at(read: &Read, at: usize) -> String {
    read.snapshots[at].at.tag.clone()
}

fn clone_snapshot(snapshot: &Snapshot) -> Snapshot {
    Snapshot {
        at: snapshot.at.clone(),
        names_a_method: snapshot.names_a_method.clone(),
        krates: snapshot.krates.clone(),
        items: snapshot.items.clone(),
        sightings: snapshot.sightings.clone(),
        records: snapshot.records.clone(),
        source_errors: snapshot.source_errors.clone(),
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

fn group(name: &str, digest: &str, tags: &[String]) -> Group {
    Group {
        krate: "companion_tauri".to_owned(),
        name: name.to_owned(),
        digest: digest.to_owned(),
        tags: tags.to_vec(),
    }
}

fn shown(krate: &str, name: &str, source: Source, tags: &[String]) -> Shown {
    Shown {
        krate: krate.to_owned(),
        name: name.to_owned(),
        source,
        tags: tags.to_vec(),
    }
}

#[test]
fn the_history_of_a_repository_that_fits_its_entry_has_no_problem_and_is_reported_as_data() {
    let read = read(&repo(None, None));
    let report = audit_tags(&read.entry, &read.expected, &read.snapshots);
    assert_eq!(report.problems, Vec::<String>::new());
    let all: Vec<String> = (0..7).map(|at| tag_at(&read, at)).collect();
    let lib = "lib.rs";
    let target_1 = app_source("Link::target", lib, &target_text(1));
    let target_2 = app_source("Link::target", lib, &target_text(2));
    let old = app_source("old_builder", lib, OLD_BUILDER);
    let relay = app_source("relay", lib, RELAY);
    // The groups of each client item, in the order of its first tag.
    let mut absent_old = vec![all[0].clone()];
    absent_old.extend(all[3..].iter().cloned());
    let groups = vec![
        group("Link::target", "absent", &all[..1]),
        group("Link::target", &target_1.digest, &all[1..2]),
        group("Link::target", &target_2.digest, &all[2..]),
        group("old_builder", "absent", &absent_old),
        group("old_builder", &old.digest, &all[1..3]),
        group("relay", "absent", &all[..1]),
        group("relay", &relay.digest, &all[1..]),
    ];
    assert_eq!(report.groups, groups);
    let names_here = app_source("names_one", lib, NAMES_ONE);
    let names_moved = app_source("names_one", "more.rs", NAMES_ONE);
    assert_eq!(names_here.text, names_moved.text);
    assert_ne!(names_here.digest, names_moved.digest);
    // Each distinct text once with its tags: the relay has no sighting, and the account that moved
    // between files has two digests and one text.
    assert_eq!(report.texts, fixture_texts(&all));
    // The account's span is the first and last tag that have it, over both files.
    let span = |krate: &str, name: &str, first: &str, last: &str| Span {
        krate: krate.to_owned(),
        name: name.to_owned(),
        first: first.to_owned(),
        last: last.to_owned(),
    };
    assert_eq!(
        report.spans,
        vec![
            span("companion_tauri", "names_one", &all[3], &all[6]),
            span("kr_other", "other_one", &all[1], &all[6]),
        ]
    );
}

#[test]
fn the_snapshots_must_be_the_releases_origin_lists() {
    let read = read(&repo(None, None));
    let commit = |tag: &str| {
        read.expected
            .iter()
            .find(|t| t.tag == tag)
            .expect("a tag")
            .commit
            .clone()
    };
    let mut missing: Vec<Snapshot> = read.snapshots.iter().map(clone_snapshot).collect();
    let left_out = missing.remove(3);
    let report = audit_tags(&read.entry, &read.expected, &missing);
    assert_eq!(
        report.problems,
        vec![said(&format!(
            "{} at {} is expected and has no snapshot",
            left_out.at.tag,
            commit(&left_out.at.tag)
        ))]
    );
    assert!(report.groups.is_empty() && report.texts.is_empty() && report.spans.is_empty());
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

#[test]
fn the_count_the_oldest_tag_and_the_oldest_naming_release_are_each_held() {
    let read = read(&repo(None, None));
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
    // No release names one of the six.
    let report = report_with(&read, |_, snapshots| {
        for snapshot in snapshots.iter_mut() {
            snapshot.names_a_method = Ok(false);
        }
    });
    assert_eq!(
        report.problems,
        vec![said("no release's method.rs names one of the six")]
    );
}

#[test]
fn a_text_the_entry_does_not_list_or_a_reading_that_is_missing_or_failed_names_the_tag() {
    let read = read(&repo(None, None));
    let third = tag_at(&read, 2);
    let target_2 = app_source("Link::target", "lib.rs", &target_text(2)).digest;
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
    assert_eq!(
        report.problems,
        vec![said(&format!(
            "{third}: the item companion_tauri::Link::target has a text ({target_2}) that the entry does not list"
        ))]
    );
    let report = report_with(&read, |_, snapshots| {
        let snapshot = snapshot_of(snapshots, &third);
        snapshot.items.insert(
            ("companion_tauri".to_owned(), "Link::target".to_owned()),
            Lookup::Failed("e".to_owned()),
        );
        snapshot.sightings = Err("scan".to_owned());
        snapshot
            .krates
            .insert("kr_hook".to_owned(), Lookup::Failed("k".to_owned()));
    });
    assert_eq!(
        report.problems,
        vec![
            said(&format!("{third}: the crate kr_hook cannot be read: k")),
            said(&format!("{third}: the scan failed: scan")),
            said(&format!(
                "{third}: the item companion_tauri::Link::target cannot be read: e"
            )),
        ]
    );
    let report = report_with(&read, |_, snapshots| {
        snapshot_of(snapshots, &third)
            .items
            .remove(&("companion_tauri".to_owned(), "relay".to_owned()));
    });
    assert_eq!(
        report.problems,
        vec![said(&format!(
            "{third}: the snapshot has no reading of the item companion_tauri::relay"
        ))]
    );
    // A tree with a manifest that names no package, read by the production reader and audited.
    let odd = repo(Some(2), None);
    let (expected, snapshots) = read_history(odd.work.path(), &read.entry).expect("history");
    let report = audit_tags(&read.entry, &expected, &snapshots);
    let failed: Vec<&Snapshot> = snapshots
        .iter()
        .filter(|snapshot| snapshot.sightings.is_err())
        .collect();
    assert_eq!(failed.len(), 1, "one snapshot whose scan failed");
    let unreadable = failed[0];
    let (Some(Lookup::Failed(crate_error)), Err(scan_error)) =
        (unreadable.krates.get("kr_hook"), &unreadable.sightings)
    else {
        panic!("a crate and a scan that failed");
    };
    assert_eq!(crate_error, scan_error);
    assert!(
        scan_error.contains(": cargo cannot read the workspace (error: "),
        "{scan_error}"
    );
    // Every crate, the scan and every item of the tag fail with the text, and the tag is named.
    let tag = &unreadable.at.tag;
    let mut expected_problems: Vec<String> = ["companion_tauri", "kr_hook", "kr_other"]
        .iter()
        .map(|krate| {
            said(&format!(
                "{tag}: the crate {krate} cannot be read: {crate_error}"
            ))
        })
        .collect();
    expected_problems.push(said(&format!("{tag}: the scan failed: {scan_error}")));
    for item in ["Link::target", "old_builder", "relay"] {
        expected_problems.push(said(&format!(
            "{tag}: the item companion_tauri::{item} cannot be read: {crate_error}"
        )));
    }
    assert_eq!(report.problems, expected_problems);
}

#[test]
fn a_source_that_cannot_be_read_at_a_tag_is_a_text_of_its_own() {
    // The crate that holds only an account declares a file that does not parse at one release: the
    // scan and the account's text both stop on it, each with a text of its own.
    let broken = repo(None, Some(2));
    let read = read(&repo(None, None));
    let (expected, snapshots) = read_history(broken.work.path(), &read.entry).expect("history");
    let report = audit_tags(&read.entry, &expected, &snapshots);
    let at = &snapshots[2];
    let key = ("kr_other".to_owned(), "other_one".to_owned());
    assert_eq!(
        at.source_errors.keys().cloned().collect::<Vec<_>>(),
        vec![key.clone()],
        "the account's source failed"
    );
    let error = &at.source_errors[&key];
    assert!(error.contains("broken.rs"), "{error}");
    let scan_error = at
        .sightings
        .as_ref()
        .expect_err("the scan stops on the file");
    assert!(scan_error.contains("broken.rs"), "{scan_error}");
    assert_eq!(
        report.problems,
        vec![
            said(&format!("{}: the scan failed: {scan_error}", at.at.tag)),
            said(&format!(
                "{}: the source of kr_other::other_one cannot be read: {error}",
                at.at.tag
            )),
        ]
    );
}

#[test]
fn a_sighting_is_held_to_its_row_its_account_or_its_crate() {
    let read = read(&repo(None, None));
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
    // A4: with no account, each tag names each sighting that only an account covers.
    let report = report_with(&read, |entry, _| entry.accounts = &[]);
    let mut texts = Vec::new();
    for at in 1..7 {
        let tag = tag_at(&read, at);
        if at >= 3 {
            texts.push(said(&format!(
                "{tag}: the sighting companion_tauri::names_one ({{Names}}) is no item of a row and no account covers it"
            )));
        }
        texts.push(said(&format!(
            "{tag}: the sighting kr_other::other_one ({{Names}}) is no item of a row and no account covers it"
        )));
    }
    assert_eq!(report.problems, texts);
    // The texts of the sightings that nothing covers are shown as those of an account are.
    let all: Vec<String> = (0..7).map(|at| tag_at(&read, at)).collect();
    assert_eq!(report.texts, fixture_texts(&all));
    // A4: a sighting in a daemon crate or a receiver crate at a tag is not read; an account that
    // lacks a kind of its sighting is.
    let report = report_with(&read, |_, snapshots| {
        if let Ok(list) = &mut snapshot_of(snapshots, &fourth).sightings {
            list.push(sighting("kr_controller", "daemon", &[SightKind::Request]));
            list.push(sighting("kr_protocol", "receiver", &[SightKind::Request]));
            list.push(sighting(
                "companion_tauri",
                "names_one",
                &[SightKind::Names, SightKind::Request],
            ));
        }
    });
    assert_eq!(
        report.problems,
        vec![said(&format!(
            "{fourth}: the account for companion_tauri::names_one lacks the kind [Request] of its sighting ({{Names, Request}})"
        ))]
    );
}

#[test]
fn an_item_or_account_that_is_gone_now_and_no_tag_has_is_stale() {
    let read = read(&repo(None, None));
    let old = app_source("old_builder", "lib.rs", OLD_BUILDER).digest;
    // An item with now absent that no tag defines.
    let report = report_with(&read, |_, snapshots| {
        for snapshot in snapshots.iter_mut() {
            snapshot.items.insert(
                ("companion_tauri".to_owned(), "old_builder".to_owned()),
                Lookup::Absent,
            );
        }
    });
    assert_eq!(
        report.problems,
        vec![
            said(&format!(
                "the text {old} of companion_tauri::old_builder is stale: no release has it"
            )),
            said("the item companion_tauri::old_builder is absent now and no release defines it"),
        ]
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
            "the text nowhere of companion_tauri::Link::target is stale: no release has it"
        )]
    );
    // An account that is gone now and that no tag has.
    let report = report_with(&read, |entry, snapshots| {
        let mut accounts = entry.accounts.to_vec();
        accounts[0].now = "absent";
        entry.accounts = leak(accounts);
        for snapshot in snapshots.iter_mut() {
            snapshot.records.retain(|key, _| key.1 != "names_one");
        }
    });
    assert_eq!(
        report.problems,
        vec![said(
            "the account companion_tauri::names_one is absent now and no release has it"
        )]
    );
    // An account with a digest that no tag sights is not stale.
    let report = report_with(&read, |_, snapshots| {
        for snapshot in snapshots.iter_mut() {
            snapshot.records.retain(|key, _| key.1 != "names_one");
            if let Ok(list) = &mut snapshot.sightings {
                list.retain(|sighting| sighting.name != "names_one");
            }
        }
    });
    assert_eq!(report.problems, Vec::<String>::new());
}

#[test]
fn a_daemon_item_and_a_daemon_account_cause_no_reading_and_no_text() {
    let repo = repo(None, None);
    let read = read(&repo);
    let baseline = audit_tags(&read.entry, &read.expected, &read.snapshots);
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
        now: "absent",
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
    assert_eq!(report.groups, baseline.groups);
    assert_eq!(report.texts, baseline.texts);
    assert_eq!(report.spans, baseline.spans);
}

#[test]
fn the_releases_are_ordered_by_version_then_date_then_tag_and_only_below_the_level_are_read() {
    let repo = repo(None, None);
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
    let repo = repo(None, None);
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

#[test]
fn the_snapshots_are_read_in_the_order_of_releases_and_hold_the_apps_crate() {
    let read = read(&repo(None, None));
    let order: Vec<_> = read
        .snapshots
        .iter()
        .map(|snapshot| snapshot.at.order())
        .collect();
    assert!(order.windows(2).all(|pair| pair[0] < pair[1]));
    // The crate under `apps/` is read at each tag from the second.
    assert_eq!(
        read.snapshots[0].krates.get("companion_tauri"),
        Some(&Lookup::Absent)
    );
    assert!(
        read.snapshots[1..]
            .iter()
            .all(|snapshot| snapshot.krates.get("companion_tauri")
                == Some(&Lookup::Found(String::new())))
    );
}

/// The tags `git` lists below level 0.11, which the fixture's entry is made for.
fn listed_below_the_level(repo: &Repo) -> Vec<Tagged> {
    listed_releases(repo.work.path())
        .expect("the tags")
        .into_iter()
        .filter(|tagged| tagged.version.minor < 11)
        .collect()
}

#[test]
fn the_gate_lists_the_tags_apart_from_the_reader_and_holds_the_snapshots_to_them() {
    let repo = repo(None, None);
    let read = read(&repo);
    let listed = listed_below_the_level(&repo);
    assert_eq!(listed.len(), 7);
    // The list is the reader's own, made by `git for-each-ref`: its order, its commits, its dates.
    assert_eq!(listed, read.expected);
    assert_eq!(
        release_problems(&listed, &read.snapshots),
        Vec::<String>::new()
    );
    let with = |change: &dyn Fn(&mut Vec<Snapshot>)| {
        let mut snapshots: Vec<Snapshot> = read.snapshots.iter().map(clone_snapshot).collect();
        change(&mut snapshots);
        release_problems(&listed, &snapshots)
    };
    // A snapshot repeated in place of another keeps the count.
    let problems = with(&|snapshots| snapshots[3] = clone_snapshot(&snapshots[2]));
    assert!(
        problems
            .iter()
            .any(|problem| problem.starts_with("snapshot 3 is ")),
        "{problems:?}"
    );
    assert!(
        problems
            .iter()
            .any(|problem| problem == "a release is read twice"),
        "{problems:?}"
    );
    assert!(
        !problems
            .iter()
            .any(|problem| problem.contains("snapshots for")),
        "{problems:?}"
    );
    // A snapshot left out, one added, one swapped with another, and one at another commit.
    let problems = with(&|snapshots| {
        snapshots.remove(1);
    });
    assert!(
        problems
            .iter()
            .any(|problem| problem == "6 snapshots for 7 release tags"),
        "{problems:?}"
    );
    let problems = with(&|snapshots| {
        let extra = clone_snapshot(&snapshots[0]);
        snapshots.push(extra);
    });
    assert!(
        problems
            .iter()
            .any(|problem| problem == "8 snapshots for 7 release tags"),
        "{problems:?}"
    );
    let problems = with(&|snapshots| snapshots.swap(4, 5));
    assert!(
        problems
            .iter()
            .any(|problem| problem.starts_with("snapshot 4 is ")),
        "{problems:?}"
    );
    let problems = with(&|snapshots| snapshots[2].at.commit = "0".repeat(40));
    assert!(
        problems
            .iter()
            .any(|problem| problem.starts_with("snapshot 2 is ")),
        "{problems:?}"
    );
    // An annotated tag is listed at the commit it names, and with that commit's date.
    let work = repo.work.path();
    let commit = git(work, &["rev-parse", "HEAD~2"], None).trim().to_owned();
    let tag = format!("packages/v0.5.0+{}", &commit[..12]);
    git(
        work,
        &["tag", "-a", "-m", "an annotated release", &tag, &commit],
        None,
    );
    let object = git(work, &["rev-parse", &tag], None).trim().to_owned();
    assert_ne!(object, commit, "the tag is an object of its own");
    let date: i64 = git(work, &["log", "-1", "--format=%ct", &commit], None)
        .trim()
        .parse()
        .expect("a date");
    let listed = listed_releases(work);
    let annotated = listed
        .as_ref()
        .ok()
        .and_then(|all| all.iter().find(|tagged| tagged.tag == tag))
        .map(|tagged| (tagged.commit.clone(), tagged.committed));
    assert_eq!(annotated, Some((commit, date)), "{listed:?}");
}

#[test]
fn the_gate_holds_each_lookup_each_absence_and_the_level_to_what_the_entry_needs() {
    let repo = repo(None, None);
    let read = read(&repo);
    assert_eq!(
        snapshot_problems(&read.entry, &read.snapshots),
        Vec::<String>::new()
    );
    let tag = tag_at(&read, 2);
    let with = |entry: &Narrower, change: &dyn Fn(&mut Snapshot)| {
        let mut snapshots: Vec<Snapshot> = read.snapshots.iter().map(clone_snapshot).collect();
        change(snapshot_of(&mut snapshots, &tag));
        snapshot_problems(entry, &snapshots)
    };
    let has = |problems: &[String], text: String| {
        assert!(problems.contains(&text), "{text} is not in {problems:?}");
    };
    let target = || ("companion_tauri".to_owned(), "Link::target".to_owned());
    // A lookup the entry needs and the snapshot lacks, and one that no row names.
    let problems = with(&read.entry, &|snapshot| {
        snapshot.krates.remove("companion_tauri");
        snapshot.items.remove(&target());
    });
    has(
        &problems,
        format!("{tag}: no reading of the crate companion_tauri"),
    );
    has(
        &problems,
        format!("{tag}: no reading of the item companion_tauri::Link::target"),
    );
    let problems = with(&read.entry, &|snapshot| {
        snapshot
            .krates
            .insert("kr_stray".to_owned(), Lookup::Absent);
        snapshot
            .items
            .insert(("kr_stray".to_owned(), "x".to_owned()), Lookup::Absent);
    });
    has(
        &problems,
        format!("{tag}: a reading of the crate kr_stray, which no row names"),
    );
    has(
        &problems,
        format!("{tag}: a reading of the item kr_stray::x, which no row names"),
    );
    // A failed lookup, a failed scan, an unreadable source and a sighting with no source.
    let problems = with(&read.entry, &|snapshot| {
        snapshot
            .items
            .insert(target(), Lookup::Failed("it failed".to_owned()));
        snapshot.sightings = Err("no scan".to_owned());
    });
    has(
        &problems,
        format!("{tag}: the item companion_tauri::Link::target: it failed"),
    );
    has(&problems, format!("{tag}: the scan failed: no scan"));
    let problems = with(&read.entry, &|snapshot| {
        snapshot.krates.insert(
            "companion_tauri".to_owned(),
            Lookup::Failed("no crate".to_owned()),
        );
        snapshot.names_a_method = Err("no method.rs".to_owned());
        snapshot
            .source_errors
            .insert(target(), "no text".to_owned());
    });
    has(
        &problems,
        format!("{tag}: the crate companion_tauri: no crate"),
    );
    has(
        &problems,
        format!("{tag}: method.rs cannot be read: no method.rs"),
    );
    has(
        &problems,
        format!(
            "{tag}: the source of {:?} cannot be read: no text",
            target()
        ),
    );
    let problems = with(&read.entry, &|snapshot| {
        snapshot.records.clear();
    });
    assert!(
        problems
            .iter()
            .any(|problem| problem.starts_with(&format!("{tag}: no source for "))),
        "{problems:?}"
    );
    // `Absent` is read where the entry lists an absent text, and nowhere else: an entry whose item
    // lists none refuses the tag that lacks the item, and its crate.
    let mut strict = read.entry.clone();
    strict.senders = leak(vec![Sender {
        class: "the companion",
        sends: "x",
        evidence: Evidence::Builds {
            items: leak(vec![Item {
                krate: "companion_tauri",
                name: "Link::target",
                now: "n",
                across: leak(vec![("a-digest", "x")]),
            }]),
        },
    }]);
    strict.accounts = &[];
    let first = tag_at(&read, 0);
    let mut snapshots: Vec<Snapshot> = read.snapshots.iter().map(clone_snapshot).collect();
    for snapshot in &mut snapshots {
        snapshot
            .krates
            .retain(|krate, _| krate == "companion_tauri");
        snapshot.items.retain(|(_, name), _| name == "Link::target");
        snapshot.records.clear();
        snapshot.sightings = Ok(Vec::new());
    }
    let problems = snapshot_problems(&strict, &snapshots);
    has(
        &problems,
        format!("{first}: the crate companion_tauri is absent"),
    );
    has(
        &problems,
        format!(
            "{first}: the item companion_tauri::Link::target is absent and the entry lists no absent text for it"
        ),
    );
    assert!(
        snapshot_problems(&read.entry, &read.snapshots).is_empty(),
        "the entry that lists an absent text permits it"
    );
    // The level is above the newest release, whatever it is.
    let listed = listed_below_the_level(&repo);
    assert_eq!(level_above(&listed), "0.11");
    let mut later = listed.clone();
    later.push(Tagged {
        version: kr_protocol::hello::PackageVersion::new(1, 2, 3),
        ..listed[0].clone()
    });
    assert_eq!(level_above(&later), "2");
    for list in [&listed, &later] {
        let level: kr_protocol::update::CompatibilityLevel =
            level_above(list).parse().expect("a level");
        assert!(
            list.iter()
                .all(|tagged| kr_protocol::update::CompatibilityLevel::of(tagged.version) < level)
        );
    }
}

#[test]
fn the_gate_holds_the_audit_to_the_problems_it_expects_and_to_no_others() {
    let read = read(&repo(None, None));
    let clean = audit_tags(&read.entry, &read.expected, &read.snapshots);
    assert_eq!(audit_differences(&clean, &[]), Vec::<String>::new());
    // A problem the audit gives and the list lacks, and one the list has that the audit lacks.
    let report = report_with(&read, |entry, _| entry.range.tags = 5);
    assert_eq!(report.problems.len(), 1, "{:?}", report.problems);
    assert_eq!(
        audit_differences(&report, &[]),
        vec![format!("reported and not expected: {}", report.problems[0])]
    );
    assert_eq!(
        audit_differences(&report, &report.problems),
        Vec::<String>::new()
    );
    assert_eq!(
        audit_differences(&clean, &report.problems),
        vec![format!("expected and not reported: {}", report.problems[0])]
    );
    // A problem told twice.
    let twice = Report {
        problems: vec![report.problems[0].clone(), report.problems[0].clone()],
        ..Report::default()
    };
    assert_eq!(
        audit_differences(&twice, &report.problems),
        vec!["a problem is reported twice".to_owned()]
    );
}

#[test]
fn the_gate_expects_what_the_audit_reports_for_an_entry_that_is_wrong_without_calling_the_audit() {
    let repo = repo(None, None);
    let read = read(&repo);
    let listed = listed_below_the_level(&repo);
    let said = |text: &str| format!("history {}: {text}", read.entry.root);
    // The entry that fits has no problem, and the gate expects none.
    assert_eq!(
        expected_audit_problems(&read.entry, &listed, &read.snapshots),
        Vec::<String>::new()
    );
    // The audit's report for an entry made wrong and what the gate expects of it are the same set,
    // and the expectation holds the line of the kind the change brings.
    let wrong = |change: &dyn Fn(&mut Narrower)| {
        let mut entry = read.entry.clone();
        change(&mut entry);
        let report = audit_tags(&entry, &read.expected, &read.snapshots);
        let expected = expected_audit_problems(&entry, &listed, &read.snapshots);
        assert_eq!(
            audit_differences(&report, &expected),
            Vec::<String>::new(),
            "{expected:?}"
        );
        expected
    };
    // The range says a number of tags that origin does not list.
    let expected = wrong(&|entry| entry.range.tags = 5);
    assert_eq!(
        expected,
        vec![said(
            "the entry says 5 tags and origin lists 7 below the level"
        )]
    );
    // The range starts at a tag that is neither the oldest release nor the oldest that names a method.
    let expected = wrong(&|entry| entry.range.first_tag = "scratch");
    let oldest = &listed[0].tag;
    assert!(
        expected.contains(&said(&format!(
            "the oldest release is {oldest}, the entry names scratch"
        ))),
        "{expected:?}"
    );
    assert!(
        expected.iter().any(|problem| problem
            .contains("the oldest release whose method.rs names one of the six is ")
            && problem.ends_with(", the entry names scratch")),
        "{expected:?}"
    );
    // An item's row lists none of its texts.
    let expected = wrong(&|entry| {
        let mut senders = entry.senders.to_vec();
        senders[0].evidence = Evidence::Builds {
            items: leak(vec![Item {
                krate: "companion_tauri",
                name: "Link::target",
                now: "n",
                across: &[],
            }]),
        };
        entry.senders = leak(senders);
    });
    assert!(
        expected.iter().any(|problem| problem
            .contains("the item companion_tauri::Link::target has a text (")
            && problem.ends_with(") that the entry does not list")),
        "{expected:?}"
    );
    // No account covers a sighting that no row names.
    let expected = wrong(&|entry| entry.accounts = &[]);
    assert!(
        expected.iter().any(|problem| problem.contains(
            "the sighting companion_tauri::names_one ({Names}) is no item of a row and no account covers it"
        )),
        "{expected:?}"
    );
    assert!(
        expected.iter().any(|problem| problem.contains(
            "the sighting kr_other::other_one ({Names}) is no item of a row and no account covers it"
        )),
        "{expected:?}"
    );
    // A row names an item that no snapshot holds a reading of.
    let expected = wrong(&|entry| {
        let mut senders = entry.senders.to_vec();
        senders[0].evidence = Evidence::Builds {
            items: leak(vec![Item {
                krate: "companion_tauri",
                name: "Link::unread",
                now: "n",
                across: &[],
            }]),
        };
        entry.senders = leak(senders);
    });
    assert!(
        expected.iter().any(|problem| problem
            .ends_with(": the snapshot has no reading of the item companion_tauri::Link::unread")),
        "{expected:?}"
    );
}
