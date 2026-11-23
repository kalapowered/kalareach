//! What the companion's page sends of the resource a plugin action names, at each release.
//!
//! The rule of a worker that checks a resource a plugin action names refuses an action whose
//! `resource_id` the page set wrongly. The page is code of the release that built it, and a device
//! keeps the page it was installed with, so the files that make the call are read at every release
//! tag below this build's level: the tags are the only inventory of what the repository sent.
//!
//! Three files make the call, each found by what it holds and not by where it is:
//!
//! * the bridge maps `pluginActionInvoke` to the command `plugin_action_invoke`;
//! * the caller calls `.pluginActionInvoke(`;
//! * the constructor, a file outside `host/` that names `PluginActionInvokeParams`, sets the
//!   `resource_id` of the parameters.
//!
//! A path that holds `test` or `fake` is never read. The range is every release from the first one
//! whose bridge maps the action. At each tag of the range the audit groups the files of a role by
//! the digest of the whole text; each role's digests are the table's [`PAGE`] and nothing else, and
//! a tag whose constructor has no `resource_id` line fails. The table is outside the `NARROWER`
//! table, so the audit holds with or without an entry.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;
use std::process::Command;

use kr_protocol::update::CompatibilityLevel;

use super::history::{Tagged, in_threads_of_their_own, releases_below};
use super::narrower::ABSENT;
use super::releases;

pub const BRIDGE: &str = "the bridge";
pub const CALLER: &str = "the caller";
pub const CONSTRUCTOR: &str = "the constructor";
/// The roles, in the order a report lists them.
pub const ROLES: [&str; 3] = [BRIDGE, CALLER, CONSTRUCTOR];

/// How many tags are read at once.
const WIDTH: usize = 4;
/// Lines shown on each side of a line that makes a file a role's.
const AROUND: usize = 2;

/// One text of a role: its digest and what it does.
pub struct PageText {
    /// The digest of the whole file text, as `git show <tag>:<path> | shasum -a 256` gives it.
    pub digest: &'static str,
    /// One sentence on what this text does with `resource_id`.
    pub says: &'static str,
}

pub struct PageRole {
    pub role: &'static str,
    /// The texts the role has over the range. The bridge and the caller may list `absent`.
    pub texts: &'static [PageText],
}

pub struct PageTable {
    /// The first tag whose bridge maps the action.
    pub first_tag: &'static str,
    /// How many tags the range holds: that tag and every later one below the level.
    pub tags: u32,
    pub roles: &'static [PageRole],
}

/// A page file at a tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageFile {
    pub path: String,
    pub digest: String,
    pub text: String,
}

/// What was read at one tag, owned: the tree it was read from is gone.
#[derive(Clone, Debug)]
pub struct PageSnapshot {
    pub at: Tagged,
    /// The files of each role, or why the tree could not be read.
    pub roles: Result<BTreeMap<&'static str, Vec<PageFile>>, String>,
}

/// The tags that have one text of a role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageGroup {
    pub role: &'static str,
    /// A digest, or `absent`.
    pub digest: String,
    pub tags: Vec<String>,
}

/// A distinct text of a role, with the lines that make it the role's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageShown {
    pub role: &'static str,
    pub digest: String,
    pub paths: Vec<String>,
    pub tags: Vec<String>,
    pub lines: String,
}

#[derive(Default, Debug)]
pub struct PageReport {
    pub problems: Vec<String>,
    /// The tags of the range, in the order of releases.
    pub range: Vec<String>,
    pub groups: Vec<PageGroup>,
    pub texts: Vec<PageShown>,
}

/// The texts of each role over the range, read at every release tag below level 0.79 by
/// `the_resource_senders_at_each_release`: the table lists each text of a file once, however many
/// tags have it.
pub const PAGE: PageTable = PageTable {
    first_tag: "packages/v0.77.0+495a2f3356cb",
    tags: 52,
    roles: &[
        PageRole {
            role: BRIDGE,
            texts: &[
                PageText {
                    digest: "cb14d3e68369e426e3262864ece57c4bdadef1fc0c95bd63a65e9d29059b03d0",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 265).",
                },
                PageText {
                    digest: "d6cf2a0bcd8955e7c9f4d8b5c9eb1271db64524796dcc2f167559cc1178d9ff0",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 265).",
                },
                PageText {
                    digest: "c1f6f54a767ead4ad20f4c2619f4234822118da956b2504a01fb5ae8589ad195",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 243).",
                },
                PageText {
                    digest: "14d32802924b250eb29cbea177a0522f2c6081d2f4e007bce45b7fad0bb45e14",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 249).",
                },
                PageText {
                    digest: "ee1cf33e22b48099718bc4da8d5612780fa4b96c7d6ce09a47126a16c7e8fa5b",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 249).",
                },
                PageText {
                    digest: "370fb7af39dd7800aacaa1f9d90a1ae7ce56cd8964cac3d49ca3c9f80b903540",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 249).",
                },
                PageText {
                    digest: "ffda682d871e6109fc2989f2ef470b6fb2a75d8bc953a21278a5b40657b0cc2b",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 249).",
                },
                PageText {
                    digest: "3707a2f3400fc0d28111164a30a5dc42e3bcee0b561a809af034ab18f3fb023b",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 249).",
                },
                PageText {
                    digest: "b2d3e4bae12dd168c0c34c3097842b32380a670442be70bc2c827febec5bf87c",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 249).",
                },
                PageText {
                    digest: "27719f8d1fbece599f693e9e428d745aa4da4264117a40d8ff6ac16b50d9ee53",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 327).",
                },
                PageText {
                    digest: "300354691506ac424bc0230d0bd229ec2f75a74e1779c31c2baadda83e071d79",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 327).",
                },
                PageText {
                    digest: "f1105254023dc55f2e1f840c8850b72c94aa6dd44ccf348f9fc910fa1f63cab2",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 329).",
                },
                PageText {
                    digest: "af0d2cef394397ec96659ec8d7a1d3d477e7451ddce143bbfa661baca6b875ac",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 329).",
                },
                PageText {
                    digest: "9b7151d04dc8bdb20618bb9bcc508974898e90b22c56aab18df98a0dca3b991e",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 440).",
                },
                PageText {
                    digest: "2ae8cf584123f98d63cda51cefe89b57952a213c08fbcd80cf6f6db64078a414",
                    says: "Passes the params and the opening to `plugin_action_invoke` as they come (line 445).",
                },
            ],
        },
        PageRole {
            role: CALLER,
            texts: &[
                PageText {
                    digest: "2891b7f07c80d4f7deba365bfec16c570bb049f6403d3a8d6da6b06c80b423ba",
                    says: "Calls the port with `call.params` as the constructor built them (line 702).",
                },
                PageText {
                    digest: "068781ea6bfff4d2bf8002004ddaa443517149072164274ccdd699a07cc1f5d5",
                    says: "Calls the port with `call.params` as the constructor built them (line 697).",
                },
                PageText {
                    digest: "c296dc61aeff48b7a72b194661e82a142dc1db52f03ff2b5b183fbeaa116648c",
                    says: "Calls the port with `call.params` as the constructor built them (line 702).",
                },
                PageText {
                    digest: "bdbbf93a080227507d9befa15359e79441a5cb66f8f311ada0b6687b597d8772",
                    says: "Calls the port with `call.params` as the constructor built them (line 705).",
                },
                PageText {
                    digest: "dc7bf7016e79e1b63d8c03885191a624252de5cdbf3b598734fc9f3231bfc5a9",
                    says: "Calls the port with `call.params` as the constructor built them (line 705).",
                },
                PageText {
                    digest: "1ff0816fcc7cffa6c2f6947f9644a936a7f0d6c2df65e45e4c9e34bfe8410eea",
                    says: "Calls the port with `call.params` as the constructor built them (line 752).",
                },
                PageText {
                    digest: "61bd7702cbe3661670b45cc7a270604b4294795cbff0aee39c4f5bda0e2ea92a",
                    says: "Calls the port with `call.params` as the constructor built them (line 753).",
                },
                PageText {
                    digest: "07609d704076b9a6caf9d9608d140d30b1521f6305df805ce882bfbdd54cc6ba",
                    says: "Calls the port with `call.params` as the constructor built them (line 766).",
                },
                PageText {
                    digest: "4698601c22055bfe295c4f7aaa501269d80899ef25067ab040b9e311ac7666ba",
                    says: "Calls the port with `call.params` as the constructor built them (line 766).",
                },
            ],
        },
        PageRole {
            role: CONSTRUCTOR,
            texts: &[
                PageText {
                    digest: "026f2464bfe1d1b759d3c85e38e35e1db867ee96468501d5864a980a77a665d9",
                    says: "Sets `resource_id: null` in the params of every call of the action (line 167).",
                },
                PageText {
                    digest: "d3d80d9497d37499329c94eabb56b7d66d4bb092bd21dbfefaa66e0395b5e60f",
                    says: "Sets `resource_id: null` in the params of every call of the action (line 180).",
                },
                PageText {
                    digest: "1ab92e1bebe90609814c69d1935074ca3e8c48222d8258a6fbdd70affa15243b",
                    says: "Sets `resource_id: null` in the params of every call of the action (line 180).",
                },
                PageText {
                    digest: "6ca8ba0b7f0d5623aa9228ab2fe1d01f898d1e06e04e25aa85ae304900e69f61",
                    says: "Sets `resource_id: null` in the params of every call of the action (line 181).",
                },
            ],
        },
    ],
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Whether a path is a page file: a TypeScript file under the `src` of an app, and none that a
/// test or a fake owns.
pub fn is_page_file(path: &str) -> bool {
    path.starts_with("apps/")
        && path.contains("/src/")
        && (path.ends_with(".ts") || path.ends_with(".tsx"))
        && !path.contains("test")
        && !path.contains("fake")
}

/// Whether a line makes a file a role's, and so is shown.
fn marks(role: &str, line: &str) -> bool {
    match role {
        BRIDGE => line.contains("plugin_action_invoke"),
        CALLER => line.contains(".pluginActionInvoke("),
        _ => line.contains("resource_id"),
    }
}

/// Whether a file with this text is a role's, by content.
fn is_role(role: &str, path: &str, text: &str) -> bool {
    match role {
        BRIDGE => text.contains("pluginActionInvoke") && text.contains("plugin_action_invoke"),
        CALLER => text.contains(".pluginActionInvoke("),
        _ => !path.contains("/host/") && text.contains("PluginActionInvokeParams"),
    }
}

/// The files of each role among `files` (path and text), by content, test and fake files left out.
pub fn select(
    files: impl IntoIterator<Item = (String, String)>,
) -> BTreeMap<&'static str, Vec<PageFile>> {
    let mut roles: BTreeMap<&'static str, Vec<PageFile>> =
        ROLES.iter().map(|role| (*role, Vec::new())).collect();
    for (path, text) in files {
        if !is_page_file(&path) {
            continue;
        }
        for role in ROLES {
            if is_role(role, &path, &text) {
                roles.entry(role).or_default().push(PageFile {
                    path: path.clone(),
                    digest: hex(&kr_cbor::sha256(text.as_bytes())),
                    text: text.clone(),
                });
            }
        }
    }
    for files in roles.values_mut() {
        files.sort_by(|left, right| left.path.cmp(&right.path));
    }
    roles
}

/// The lines of `text` that make it a role's, with `AROUND` lines on each side, numbered.
fn excerpt(role: &str, text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut keep = BTreeSet::new();
    for (at, line) in lines.iter().enumerate() {
        if marks(role, line) {
            keep.extend(at.saturating_sub(AROUND)..(at + AROUND + 1).min(lines.len()));
        }
    }
    let mut shown = String::new();
    let mut previous: Option<usize> = None;
    for at in keep {
        if previous.is_some_and(|before| before + 1 != at) {
            shown.push_str("   ...\n");
        }
        shown.push_str(&format!("{:>5}: {}\n", at + 1, lines[at]));
        previous = Some(at);
    }
    shown
}

/// The files of a role that count at a tag: a constructor counts when it has a `resource_id` line.
fn counted<'a>(role: &str, files: &'a [PageFile]) -> Vec<&'a PageFile> {
    files
        .iter()
        .filter(|file| role != CONSTRUCTOR || file.text.lines().any(|line| marks(role, line)))
        .collect()
}

/// The shape of the table: each role once, each digest once, a sentence for each, a range, and no
/// `absent` constructor.
pub fn table_problems(table: &PageTable) -> Vec<String> {
    let said = |text: String| format!("page table: {text}");
    let mut problems = Vec::new();
    if table.first_tag.is_empty() {
        problems.push(said("first_tag is empty".to_owned()));
    }
    if table.tags == 0 {
        problems.push(said("tags is zero".to_owned()));
    }
    for role in ROLES {
        let rows = table.roles.iter().filter(|row| row.role == role).count();
        if rows != 1 {
            problems.push(said(format!("{role} has {rows} rows, not one")));
        }
    }
    for row in table.roles {
        if !ROLES.contains(&row.role) {
            problems.push(said(format!("{} is no role of the page", row.role)));
        }
        if row.texts.is_empty() {
            problems.push(said(format!("{} lists no text", row.role)));
        }
        let mut seen = BTreeSet::new();
        for text in row.texts {
            if !seen.insert(text.digest) {
                problems.push(said(format!("{} lists {} twice", row.role, text.digest)));
            }
            if text.says.is_empty() {
                problems.push(said(format!("{} {} says nothing", row.role, text.digest)));
            }
            if text.digest == ABSENT && row.role == CONSTRUCTOR {
                problems.push(said("the constructor is never absent".to_owned()));
            }
        }
    }
    problems
}

/// Compares what was read at each tag with the table.
///
/// `expected` is the list of releases origin has below the level, which comes from a source of its
/// own, so that a snapshot left out or added is found and not counted. The range starts at the
/// first snapshot whose bridge maps the action; a release before it is not read.
pub fn audit_page(
    expected: &[Tagged],
    snapshots: &[PageSnapshot],
    table: &PageTable,
) -> PageReport {
    let mut report = PageReport::default();
    let said = |text: String| format!("page: {text}");
    report.problems.extend(table_problems(table));
    // The snapshots are the expected releases, and nothing below is read otherwise.
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
    if wanted != read {
        return report;
    }
    let mut ordered: Vec<&PageSnapshot> = snapshots.iter().collect();
    ordered.sort_by(|left, right| left.at.order().cmp(&right.at.order()));
    for snapshot in &ordered {
        if let Err(error) = &snapshot.roles {
            report.problems.push(said(format!(
                "{} could not be read ({error})",
                snapshot.at.tag
            )));
        }
    }
    let first = ordered.iter().position(|snapshot| {
        snapshot
            .roles
            .as_ref()
            .is_ok_and(|roles| roles.get(BRIDGE).is_some_and(|files| !files.is_empty()))
    });
    let Some(first) = first else {
        report.problems.push(said(
            "no release below the level has a bridge that maps pluginActionInvoke".to_owned(),
        ));
        return report;
    };
    let range = &ordered[first..];
    report.range = range
        .iter()
        .map(|snapshot| snapshot.at.tag.clone())
        .collect();
    if range.len() != table.tags as usize {
        report.problems.push(said(format!(
            "the table says {} tags and the bridge maps the action at {} of the releases below the level",
            table.tags,
            range.len()
        )));
    }
    if range[0].at.tag != table.first_tag {
        report.problems.push(said(format!(
            "the first release whose bridge maps the action is {}, and the table says {}",
            range[0].at.tag, table.first_tag
        )));
    }
    let mut groups: Vec<PageGroup> = Vec::new();
    let mut shown: Vec<PageShown> = Vec::new();
    for snapshot in range {
        let Ok(roles) = &snapshot.roles else {
            continue;
        };
        for role in ROLES {
            let files = counted(role, roles.get(role).map_or(&[][..], Vec::as_slice));
            if files.is_empty() {
                if role == CONSTRUCTOR {
                    report.problems.push(said(format!(
                        "{}: no file outside host/ that names PluginActionInvokeParams has a resource_id line",
                        snapshot.at.tag
                    )));
                } else {
                    push_tag(&mut groups, role, ABSENT, &snapshot.at.tag);
                }
                continue;
            }
            for file in files {
                push_tag(&mut groups, role, &file.digest, &snapshot.at.tag);
                match shown
                    .iter_mut()
                    .find(|text| text.role == role && text.digest == file.digest)
                {
                    Some(text) => {
                        if !text.paths.contains(&file.path) {
                            text.paths.push(file.path.clone());
                        }
                        if !text.tags.contains(&snapshot.at.tag) {
                            text.tags.push(snapshot.at.tag.clone());
                        }
                    }
                    None => shown.push(PageShown {
                        role,
                        digest: file.digest.clone(),
                        paths: vec![file.path.clone()],
                        tags: vec![snapshot.at.tag.clone()],
                        lines: excerpt(role, &file.text),
                    }),
                }
            }
        }
    }
    for role in ROLES {
        let found: BTreeSet<&str> = groups
            .iter()
            .filter(|group| group.role == role)
            .map(|group| group.digest.as_str())
            .collect();
        let listed: BTreeSet<&str> = table
            .roles
            .iter()
            .filter(|row| row.role == role)
            .flat_map(|row| row.texts.iter().map(|text| text.digest))
            .collect();
        for digest in found.difference(&listed) {
            let at = groups
                .iter()
                .find(|group| group.role == role && group.digest == *digest)
                .map_or_else(String::new, |group| group.tags.join(", "));
            report.problems.push(said(format!(
                "{role} has the text {digest} at {at}, and the table does not list it"
            )));
        }
        for digest in listed.difference(&found) {
            report.problems.push(said(format!(
                "the table lists {digest} for {role}, and no release of the range has it"
            )));
        }
    }
    report.groups = groups;
    report.texts = shown;
    report
}

fn push_tag(groups: &mut Vec<PageGroup>, role: &'static str, digest: &str, tag: &str) {
    match groups
        .iter_mut()
        .find(|group| group.role == role && group.digest == digest)
    {
        Some(group) => group.tags.push(tag.to_owned()),
        None => groups.push(PageGroup {
            role,
            digest: digest.to_owned(),
            tags: vec![tag.to_owned()],
        }),
    }
}

/// The text of the page files at a commit: the `.ts` and `.tsx` files under the `src` of each app.
fn page_files(repository: &Path, commit: &str) -> Result<Vec<(String, String)>, String> {
    // A release before the apps has no page.
    if releases::git_in(
        repository,
        &["ls-tree", "--name-only", commit, "--", "apps"],
    )?
    .trim()
    .is_empty()
    {
        return Ok(Vec::new());
    }
    let output = Command::new("git")
        .args(["archive", "--format=tar", commit, "apps"])
        .current_dir(repository)
        .output()
        .map_err(|error| format!("git archive {commit}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git archive {commit}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut archive = tar::Archive::new(output.stdout.as_slice());
    let mut files = Vec::new();
    for entry in archive
        .entries()
        .map_err(|error| format!("reading the archive of {commit}: {error}"))?
    {
        let mut entry =
            entry.map_err(|error| format!("reading the archive of {commit}: {error}"))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|error| format!("a path in the archive of {commit}: {error}"))?
            .to_string_lossy()
            .into_owned();
        if !is_page_file(&path) {
            continue;
        }
        let mut text = String::new();
        entry
            .read_to_string(&mut text)
            .map_err(|error| format!("{path} at {commit}: {error}"))?;
        files.push((path, text));
    }
    Ok(files)
}

/// Reads the page at every release below `level`: origin's agreement with the local tags first, then
/// the expectation, then one snapshot per local release. `on_read` is given each snapshot as its tag
/// finishes; the snapshots come back in the order of releases.
///
/// # Errors
///
/// When origin and the local tags differ, or a tag cannot be listed.
pub fn read_page_history(
    repository: &Path,
    level: CompatibilityLevel,
    on_read: &(dyn Fn(&PageSnapshot) + Sync),
) -> Result<(Vec<Tagged>, Vec<PageSnapshot>), String> {
    let (expected, tagged) = releases_below(repository, level)?;
    let mut snapshots = in_threads_of_their_own(tagged, WIDTH, |at| {
        let started = std::time::Instant::now();
        let roles = page_files(repository, &at.commit).map(select);
        println!("read {} in {:?}", at.tag, started.elapsed());
        let snapshot = PageSnapshot { at, roles };
        on_read(&snapshot);
        snapshot
    });
    snapshots.sort_by(|left, right| left.at.order().cmp(&right.at.order()));
    Ok((expected, snapshots))
}

/// Prints what the report holds, so that a reader can see each distinct text once.
pub fn print_page_report(report: &PageReport) {
    println!("range: {} tags", report.range.len());
    for group in &report.groups {
        println!(
            "group {} {} at {} tags: {}",
            group.role,
            group.digest,
            group.tags.len(),
            group.tags.join(", ")
        );
    }
    for text in &report.texts {
        println!(
            "text {} {} at {} tags ({} to {}) in {}:\n{}",
            text.role,
            text.digest,
            text.tags.len(),
            text.tags.first().map_or("", String::as_str),
            text.tags.last().map_or("", String::as_str),
            text.paths.join(", "),
            text.lines
        );
    }
}
