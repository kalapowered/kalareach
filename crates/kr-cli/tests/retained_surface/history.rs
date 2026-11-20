//! What each release below an entry's level did with the instance and the revision of a mutation.
//!
//! An entry says who can send to a worker of its level. The senders are code of the release that
//! built them, so the rows are read at every release tag below the level: the tags are the only
//! inventory of what the repository sent. For each tag a [`Snapshot`] is read while its extracted
//! tree exists, then the tree is dropped, and [`audit_tags`] compares the snapshots with the entry
//! and returns a [`Report`], which is data: the problems, the distinct texts each item had, the
//! sightings no row covers, and the span of tags each account covers.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use kr_protocol::hello::PackageVersion;
use kr_protocol::update::CompatibilityLevel;

use super::narrower::{ABSENT, DAEMON_CRATES, Evidence, Item, Narrower, RECEIVER_CRATES};
use super::releases;
use super::walker::{Lookup, SightKind, Sighting, Source, Tree, WIRE_NAMES};

/// A release as its tag names it, with the date of its commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tagged {
    pub tag: String,
    pub commit: String,
    pub version: PackageVersion,
    /// The commit's committer date, in seconds.
    pub committed: i64,
}

impl Tagged {
    /// The order of releases: by version, then by the date of the commit, then by tag. The name of
    /// a tag ends in a commit prefix, so the names alone give no order in time.
    pub fn order(&self) -> (PackageVersion, i64, &str) {
        (self.version, self.committed, &self.tag)
    }
}

/// What was read at one tag, owned: the tree it was read from is gone.
pub struct Snapshot {
    pub at: Tagged,
    /// Whether `crates/kr-protocol/src/method.rs` holds a wire name of the six.
    pub names_a_method: Result<bool, String>,
    /// Every crate the entry names that this audit reads.
    pub krates: BTreeMap<String, Lookup>,
    /// Every client-crate item of the entry.
    pub items: BTreeMap<(String, String), Lookup>,
    /// The sightings of the client crates.
    pub sightings: Result<Vec<Sighting>, String>,
    /// Every client row item, every client-crate account and every sighted item.
    pub records: BTreeMap<(String, String), Source>,
    /// The sources that could not be read, by item: a crate whose files do not all parse reads
    /// no text, and a missing text must not pass for an item that has none.
    pub source_errors: BTreeMap<(String, String), String>,
}

/// One text of an item and the tags that have it, in the order of releases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub krate: String,
    pub name: String,
    /// A digest, or `absent`.
    pub digest: String,
    pub tags: Vec<String>,
}

/// A distinct source text with the tags that have it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shown {
    pub krate: String,
    pub name: String,
    pub source: Source,
    pub tags: Vec<String>,
}

/// The first and last tag that have an account's item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Span {
    pub krate: String,
    pub name: String,
    pub first: String,
    pub last: String,
}

#[derive(Default, Debug)]
pub struct Report {
    pub problems: Vec<String>,
    pub groups: Vec<Group>,
    pub texts: Vec<Shown>,
    pub spans: Vec<Span>,
}

fn is_client(krate: &str) -> bool {
    !RECEIVER_CRATES.contains(&krate) && !DAEMON_CRATES.contains(&krate)
}

fn client_items(entry: &Narrower) -> Vec<&'static Item> {
    entry
        .senders
        .iter()
        .flat_map(|sender| sender.evidence.items())
        .filter(|item| is_client(item.krate))
        .collect()
}

fn none_crates(entry: &Narrower) -> BTreeSet<&'static str> {
    entry
        .senders
        .iter()
        .filter_map(|sender| match &sender.evidence {
            Evidence::SendsNone { crates } => Some(crates.iter().copied()),
            _ => None,
        })
        .flatten()
        .collect()
}

/// The crates the audit reads at a tag: those of client items, of client accounts and of the rows
/// that send none.
fn crates_read(entry: &Narrower) -> BTreeSet<&'static str> {
    let mut crates: BTreeSet<&'static str> =
        client_items(entry).iter().map(|item| item.krate).collect();
    crates.extend(
        entry
            .accounts
            .iter()
            .map(|account| account.krate)
            .filter(|krate| is_client(krate)),
    );
    crates.extend(none_crates(entry));
    crates
}

/// Compares what was read at each tag with the entry.
///
/// `expected` is the list of releases origin has below the entry's level, which comes from a source
/// of its own, so that a snapshot left out or added is found and not counted.
pub fn audit_tags(entry: &Narrower, expected: &[Tagged], snapshots: &[Snapshot]) -> Report {
    let mut report = Report::default();
    let said = |text: String| format!("history {}: {text}", entry.root);
    // A1a: the snapshots are the expected releases, and no check below is read otherwise.
    let wanted: BTreeSet<(&str, &str)> = expected
        .iter()
        .map(|tagged| (tagged.tag.as_str(), tagged.commit.as_str()))
        .collect();
    let read: BTreeSet<(&str, &str)> = snapshots
        .iter()
        .map(|snapshot| (snapshot.at.tag.as_str(), snapshot.at.commit.as_str()))
        .collect();
    for (tag, commit) in wanted.difference(&read) {
        report.problems.push(said(format!(
            "{tag} at {commit} is expected and has no snapshot"
        )));
    }
    for (tag, commit) in read.difference(&wanted) {
        report.problems.push(said(format!(
            "{tag} at {commit} has a snapshot and is not expected"
        )));
    }
    if !report.problems.is_empty() {
        return report;
    }
    let mut ordered: Vec<&Snapshot> = snapshots.iter().collect();
    ordered.sort_by(|left, right| left.at.order().cmp(&right.at.order()));
    // A1b to A1d.
    if expected.len() != entry.range.tags as usize {
        report.problems.push(said(format!(
            "the entry says {} tags and origin lists {} below the level",
            entry.range.tags,
            expected.len()
        )));
    }
    let oldest = expected
        .iter()
        .min_by(|left, right| left.order().cmp(&right.order()));
    if let Some(oldest) = oldest
        && oldest.tag != entry.range.first_tag
    {
        report.problems.push(said(format!(
            "the oldest release is {}, the entry names {}",
            oldest.tag, entry.range.first_tag
        )));
    }
    let mut first_naming = None;
    for snapshot in &ordered {
        match &snapshot.names_a_method {
            Ok(true) if first_naming.is_none() => first_naming = Some(snapshot.at.tag.as_str()),
            Ok(_) => {}
            Err(error) => report.problems.push(said(format!(
                "{}: method.rs cannot be read: {error}",
                snapshot.at.tag
            ))),
        }
    }
    if let Some(first) = first_naming
        && first != entry.range.first_tag
    {
        report.problems.push(said(format!(
            "the oldest release whose method.rs names one of the six is {first}, the entry names {}",
            entry.range.first_tag
        )));
    }
    if first_naming.is_none() && !ordered.is_empty() {
        report.problems.push(said(
            "no release's method.rs names one of the six".to_owned(),
        ));
    }
    let items = client_items(entry);
    let sends_none = none_crates(entry);
    // A2: the texts of each item over the tags are the ones the entry lists.
    for snapshot in &ordered {
        let tag = &snapshot.at.tag;
        for (krate, lookup) in &snapshot.krates {
            if let Lookup::Failed(error) = lookup {
                report.problems.push(said(format!(
                    "{tag}: the crate {krate} cannot be read: {error}"
                )));
            }
        }
        if let Err(error) = &snapshot.sightings {
            report
                .problems
                .push(said(format!("{tag}: the scan failed: {error}")));
        }
        for ((krate, name), error) in &snapshot.source_errors {
            report.problems.push(said(format!(
                "{tag}: the source of {krate}::{name} cannot be read: {error}"
            )));
        }
    }
    for item in &items {
        let key = (item.krate.to_owned(), item.name.to_owned());
        let mut groups: Vec<Group> = Vec::new();
        for snapshot in &ordered {
            let tag = &snapshot.at.tag;
            let digest = match snapshot.items.get(&key) {
                Some(Lookup::Found(digest)) => digest.clone(),
                Some(Lookup::Absent) => ABSENT.to_owned(),
                Some(Lookup::Failed(error)) => {
                    report.problems.push(said(format!(
                        "{tag}: the item {}::{} cannot be read: {error}",
                        item.krate, item.name
                    )));
                    continue;
                }
                None => {
                    report.problems.push(said(format!(
                        "{tag}: the snapshot has no reading of the item {}::{}",
                        item.krate, item.name
                    )));
                    continue;
                }
            };
            match groups.iter_mut().find(|group| group.digest == digest) {
                Some(group) => group.tags.push(tag.clone()),
                None => {
                    if !item.across.iter().any(|(held, _)| *held == digest) {
                        report.problems.push(said(format!(
                            "{tag}: the item {}::{} has a text ({digest}) that the entry does not list",
                            item.krate, item.name
                        )));
                    }
                    groups.push(Group {
                        krate: item.krate.to_owned(),
                        name: item.name.to_owned(),
                        digest,
                        tags: vec![tag.clone()],
                    });
                }
            }
        }
        // A5: a text the entry lists and no tag has, and an item that is gone now and was never there.
        for (held, _) in item.across {
            if !groups.iter().any(|group| group.digest == *held) {
                report.problems.push(said(format!(
                    "the text {held} of {}::{} is stale: no release has it",
                    item.krate, item.name
                )));
            }
        }
        if item.now == ABSENT && !groups.iter().any(|group| group.digest != ABSENT) {
            report.problems.push(said(format!(
                "the item {}::{} is absent now and no release defines it",
                item.krate, item.name
            )));
        }
        report.groups.extend(groups);
    }
    let accounts: Vec<_> = entry
        .accounts
        .iter()
        .filter(|account| is_client(account.krate))
        .collect();
    for account in &accounts {
        let key = (account.krate.to_owned(), account.name.to_owned());
        if account.now == ABSENT
            && !ordered
                .iter()
                .any(|snapshot| snapshot.records.contains_key(&key))
        {
            report.problems.push(said(format!(
                "the account {}::{} is absent now and no release has it",
                account.krate, account.name
            )));
        }
        let tags: Vec<&str> = ordered
            .iter()
            .filter(|snapshot| snapshot.records.contains_key(&key))
            .map(|snapshot| snapshot.at.tag.as_str())
            .collect();
        if let (Some(first), Some(last)) = (tags.first(), tags.last()) {
            report.spans.push(Span {
                krate: account.krate.to_owned(),
                name: account.name.to_owned(),
                first: (*first).to_owned(),
                last: (*last).to_owned(),
            });
        }
    }
    // A3 and A4: at each tag, every sighting of a client crate is a row's item or an account's.
    let mut uncovered: Vec<(String, String, String)> = Vec::new();
    for snapshot in &ordered {
        let tag = &snapshot.at.tag;
        let Ok(sightings) = &snapshot.sightings else {
            continue;
        };
        for sighting in sightings {
            if sends_none.contains(sighting.krate.as_str()) {
                report.problems.push(said(format!(
                    "{tag}: {}::{} is a sighting in a crate that a row says sends none",
                    sighting.krate, sighting.name
                )));
                continue;
            }
            if !is_client(&sighting.krate) {
                continue;
            }
            if items
                .iter()
                .any(|item| item.krate == sighting.krate && item.name == sighting.name)
            {
                continue;
            }
            match accounts
                .iter()
                .find(|account| account.krate == sighting.krate && account.name == sighting.name)
            {
                None => {
                    report.problems.push(said(format!(
                        "{tag}: the sighting {}::{} ({:?}) is no item of a row and no account covers it",
                        sighting.krate, sighting.name, sighting.kinds
                    )));
                    uncovered.push((tag.clone(), sighting.krate.clone(), sighting.name.clone()));
                }
                Some(account) => {
                    let lacking: Vec<&SightKind> = sighting
                        .kinds
                        .iter()
                        .filter(|kind| !account.kinds.contains(kind))
                        .collect();
                    if !lacking.is_empty() {
                        report.problems.push(said(format!(
                            "{tag}: the account for {}::{} lacks the kind {lacking:?} of its sighting ({:?})",
                            sighting.krate, sighting.name, sighting.kinds
                        )));
                    }
                }
            }
        }
    }
    // A6: each distinct text once with its tags.
    let mut shown: BTreeMap<(String, String, String), Shown> = BTreeMap::new();
    for snapshot in &ordered {
        let mut keys: BTreeSet<(String, String)> = items
            .iter()
            .map(|item| (item.krate.to_owned(), item.name.to_owned()))
            .collect();
        keys.extend(
            accounts
                .iter()
                .map(|account| (account.krate.to_owned(), account.name.to_owned())),
        );
        keys.extend(
            uncovered
                .iter()
                .filter(|(tag, _, _)| *tag == snapshot.at.tag)
                .map(|(_, krate, name)| (krate.clone(), name.clone())),
        );
        for key in keys {
            let Some(source) = snapshot.records.get(&key) else {
                continue;
            };
            shown
                .entry((key.0.clone(), key.1.clone(), source.digest.clone()))
                .or_insert_with(|| Shown {
                    krate: key.0.clone(),
                    name: key.1.clone(),
                    source: source.clone(),
                    tags: Vec::new(),
                })
                .tags
                .push(snapshot.at.tag.clone());
        }
    }
    report.texts = shown.into_values().collect();
    report
}

/// The version a release tag names: `packages/v<major>.<minor>.<patch>+<twelve characters>`.
pub fn version_of_tag(tag: &str) -> Option<PackageVersion> {
    let (version, short) = tag.strip_prefix("packages/v")?.split_once('+')?;
    if short.len() != 12 {
        return None;
    }
    let mut parts = version.split('.').map(|part| part.parse::<u16>().ok());
    let version = PackageVersion::new(parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(version)
}

fn committed(repository: &Path, commit: &str) -> Result<i64, String> {
    releases::git_in(repository, &["log", "-1", "--format=%ct", commit])?
        .trim()
        .parse()
        .map_err(|error| format!("the date of {commit}: {error}"))
}

/// The releases origin lists below `level`, in the order of releases.
pub fn expected_below(repository: &Path, level: CompatibilityLevel) -> Result<Vec<Tagged>, String> {
    let mut expected = Vec::new();
    for (tag, commit) in releases::origin_tags(repository)? {
        let version = version_of_tag(&tag)
            .ok_or_else(|| format!("origin lists {tag}, which is no release tag"))?;
        if CompatibilityLevel::of(version) < level {
            let committed = committed(repository, &commit)?;
            expected.push(Tagged {
                tag,
                commit,
                version,
                committed,
            });
        }
    }
    expected.sort_by(|left, right| left.order().cmp(&right.order()));
    Ok(expected)
}

/// Reads the history of an entry: origin's agreement with the local tags first, then the
/// expectation, then one snapshot per local release below the level.
///
/// # Errors
///
/// When origin and the local tags differ, or a tag cannot be read at all.
pub fn read_history(
    repository: &Path,
    entry: &Narrower,
) -> Result<(Vec<Tagged>, Vec<Snapshot>), String> {
    let level: CompatibilityLevel = entry
        .level
        .parse()
        .map_err(|error| format!("the entry's level {}: {error:?}", entry.level))?;
    let inventory = releases::inventory(repository)?;
    let head = releases::git_in(repository, &["rev-parse", "HEAD"])?
        .trim()
        .to_owned();
    releases::agree_with_origin(repository, &inventory, &head)?;
    let expected = expected_below(repository, level)?;
    let mut snapshots = Vec::new();
    for release in inventory.iter().filter(|release| release.level() < level) {
        let tagged = Tagged {
            tag: release.tag.clone(),
            commit: release.commit.clone(),
            version: release.version,
            committed: committed(repository, &release.commit)?,
        };
        snapshots.push(snapshot_at(repository, entry, tagged)?);
    }
    snapshots.sort_by(|left, right| left.at.order().cmp(&right.at.order()));
    Ok((expected, snapshots))
}

/// Extracts the crates of a release into a folder of this function's own, reads the entry's
/// crates, items and sightings, and lets the folder go.
fn snapshot_at(repository: &Path, entry: &Narrower, at: Tagged) -> Result<Snapshot, String> {
    let folder = tempfile::tempdir().map_err(|error| error.to_string())?;
    let mut paths = vec!["crates".to_owned()];
    let applications =
        releases::git_in(repository, &["ls-tree", "--name-only", &at.commit, "apps/"])?;
    for application in applications.lines() {
        let source = format!("{application}/src-tauri");
        let listed =
            releases::git_in(repository, &["ls-tree", "--name-only", &at.commit, &source])?;
        if !listed.trim().is_empty() {
            paths.push(source);
        }
    }
    let mut command = Command::new("git");
    command
        .args(["archive", "--format=tar", &at.commit])
        .args(&paths)
        .current_dir(repository);
    let output = command
        .output()
        .map_err(|error| format!("git archive {}: {error}", at.commit))?;
    if !output.status.success() {
        return Err(format!(
            "git archive {} {}: {}",
            at.commit,
            paths.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    tar::Archive::new(output.stdout.as_slice())
        .unpack(folder.path())
        .map_err(|error| format!("unpacking {}: {error}", at.tag))?;
    let tree = Tree::at(folder.path())?;
    let method = folder.path().join("crates/kr-protocol/src/method.rs");
    let names_a_method = match std::fs::read_to_string(&method) {
        Ok(text) => Ok(WIRE_NAMES
            .iter()
            .any(|name| text.contains(&format!("\"{name}\"")))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    };
    let krates = crates_read(entry)
        .into_iter()
        .map(|krate| (krate.to_owned(), tree.krate(krate)))
        .collect();
    let items: BTreeMap<(String, String), Lookup> = client_items(entry)
        .iter()
        .map(|item| {
            (
                (item.krate.to_owned(), item.name.to_owned()),
                tree.item(item.krate, item.name),
            )
        })
        .collect();
    let scan_started = std::time::Instant::now();
    let sightings = tree.sightings(&|krate| is_client(krate));
    let scan_took = scan_started.elapsed();
    let mut records: BTreeMap<(String, String), Source> = BTreeMap::new();
    let mut source_errors: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut wanted: BTreeSet<(String, String)> = client_items(entry)
        .iter()
        .map(|item| (item.krate.to_owned(), item.name.to_owned()))
        .collect();
    wanted.extend(
        entry
            .accounts
            .iter()
            .filter(|account| is_client(account.krate))
            .map(|account| (account.krate.to_owned(), account.name.to_owned())),
    );
    if let Ok(sightings) = &sightings {
        wanted.extend(
            sightings
                .iter()
                .map(|sighting| (sighting.krate.clone(), sighting.name.clone())),
        );
    }
    for key in wanted {
        match tree.source(&key.0, &key.1) {
            Ok(Some(source)) => {
                records.insert(key, source);
            }
            Ok(None) => {}
            // A row item's failure is its lookup's.
            Err(_) if items.contains_key(&key) => {}
            Err(error) => {
                source_errors.insert(key, error);
            }
        }
    }
    let failed_items: Vec<String> = items
        .iter()
        .filter_map(|((krate, name), lookup)| match lookup {
            Lookup::Failed(error) => Some(format!("{krate}::{name}: {error}")),
            _ => None,
        })
        .collect();
    println!(
        "snapshot {}: sightings {} in {:?}; {} items failed{}",
        at.tag,
        sightings.as_ref().map_or_else(
            |error| format!("failed ({error})"),
            |list| list.len().to_string()
        ),
        scan_took,
        failed_items.len(),
        failed_items
            .first()
            .map_or_else(String::new, |first| format!(" ({first})")),
    );
    Ok(Snapshot {
        at,
        names_a_method,
        krates,
        items,
        sightings,
        records,
        source_errors,
    })
}

/// Prints what the report holds, so that a reader can see each distinct text once.
pub fn print_report(report: &Report) {
    for group in &report.groups {
        println!(
            "group {}::{} {} at {} tags: {}",
            group.krate,
            group.name,
            group.digest,
            group.tags.len(),
            group.tags.join(", ")
        );
    }
    for shown in &report.texts {
        println!(
            "text {}::{} {} at {} tags ({} to {}) in {}:\n{}",
            shown.krate,
            shown.name,
            shown.source.digest,
            shown.tags.len(),
            shown.tags.first().map_or("", String::as_str),
            shown.tags.last().map_or("", String::as_str),
            shown.source.files.join(", "),
            shown.source.text
        );
    }
    for span in &report.spans {
        println!(
            "span {}::{} from {} to {}",
            span.krate, span.name, span.first, span.last
        );
    }
}
