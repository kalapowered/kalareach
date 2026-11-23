//! The cases of the page audit of the resource rule, on a repository a case makes with `git init`
//! that holds three releases and an origin that has them.

use kr_protocol::update::CompatibilityLevel;

use super::history::Tagged;
use super::history_cases::{git, write};
use super::narrower::ABSENT;
use super::narrower_cases::leak;
use super::narrower_page::{
    BRIDGE, CALLER, CONSTRUCTOR, PAGE, PageGroup, PageRole, PageSnapshot, PageTable, PageText,
    audit_page, is_page_file, read_page_history, select, table_problems,
};

const OLD_BRIDGE: &str =
    "export const host = { composerSteer: (p) => call('agent_turn_steer', p) }\n";
const BRIDGE_TEXT: &str = "export const host = {\n  composerSteer: (p) => call('agent_turn_steer', p),\n  pluginActionInvoke: (p) => call('plugin_action_invoke', p)\n}\n";
const CALLER_TEXT: &str = "export function invoke(port, call) {\n  port\n    .pluginActionInvoke(call.params)\n    .then(say)\n}\n";
const OLD_CONSTRUCTOR: &str = "import type { PluginActionInvokeParams } from '../host/port'\nexport type Call = { params: PluginActionInvokeParams }\n";
const CONSTRUCTOR_TEXT: &str = "import type { PluginActionInvokeParams } from '../host/port'\nexport const call: PluginActionInvokeParams = {\n  action: 'a',\n  draft_id: null,\n  resource_id: null,\n  parameters: {}\n}\n";
const CONSTRUCTOR_CHANGED: &str = "import type { PluginActionInvokeParams } from '../host/port'\nexport const call: PluginActionInvokeParams = {\n  action: 'a',\n  draft_id: null,\n  resource_id: resourceOf(call),\n  parameters: {}\n}\n";
const PORT: &str = "export interface Port {\n  pluginActionInvoke(params: PluginActionInvokeParams): Promise<void>\n}\n";

const APP: &str = "apps/x/src";

/// What differs from a repository that fits its table.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Fits,
    /// The constructor sets another `resource_id` at the third release.
    ChangedAtThree,
    /// The constructor names the type and sets no `resource_id` at the third release.
    NoLineAtThree,
}

struct Repo {
    work: tempfile::TempDir,
    _origin: tempfile::TempDir,
    tags: Vec<String>,
}

/// The files of release `at` (0, 1 or 2). The first release has no bridge, so the range starts at
/// the second. A fake, a test file and the port of the host carry the words that a role is found
/// by, and change at each release so that a selection of one of them is a text the table lacks.
fn files(at: usize, page: Page) -> Vec<(String, String)> {
    let mut files: Vec<(String, String)> = vec![
        (format!("{APP}/host/port.ts"), PORT.to_owned()),
        (
            format!("{APP}/host/fake.ts"),
            format!(
                "pluginActionInvoke: (p) => call('plugin_action_invoke', p) // {at}\nconst PluginActionInvokeParams = null\nresource_id: 'fake {at}'\n"
            ),
        ),
        (
            format!("{APP}/views/Conversation.test.tsx"),
            format!(
                "port.pluginActionInvoke(call.params)\nconst x: PluginActionInvokeParams = {{ resource_id: 'test {at}' }}\nplugin_action_invoke\n"
            ),
        ),
        (
            "apps/x/src-tauri/src/lib.rs".to_owned(),
            format!("const NAME: &str = \"plugin_action_invoke\"; // {at}\n"),
        ),
    ];
    if at == 0 {
        files.push((format!("{APP}/host/tauri.ts"), OLD_BRIDGE.to_owned()));
        files.push((format!("{APP}/model/agent.ts"), OLD_CONSTRUCTOR.to_owned()));
        return files;
    }
    files.push((format!("{APP}/host/tauri.ts"), BRIDGE_TEXT.to_owned()));
    files.push((
        format!("{APP}/views/Conversation.tsx"),
        CALLER_TEXT.to_owned(),
    ));
    let constructor = match (at, page) {
        (2, Page::ChangedAtThree) => CONSTRUCTOR_CHANGED,
        (2, Page::NoLineAtThree) => OLD_CONSTRUCTOR,
        _ => CONSTRUCTOR_TEXT,
    };
    files.push((format!("{APP}/model/agent.ts"), constructor.to_owned()));
    files
}

fn repo(page: Page) -> Repo {
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
    let mut tags = Vec::new();
    for (at, (version, date)) in [("0.1.0", 100), ("0.2.0", 200), ("0.3.0", 300)]
        .into_iter()
        .enumerate()
    {
        let _ = std::fs::remove_dir_all(work.path().join("apps"));
        for (path, text) in files(at, page) {
            write(work.path(), &path, &text);
        }
        write(work.path(), "notes.txt", &format!("{at}\n"));
        git(work.path(), &["add", "-A"], None);
        git(
            work.path(),
            &["commit", "-m", &format!("release {at}")],
            Some(date),
        );
        let commit = git(work.path(), &["rev-parse", "HEAD"], None)
            .trim()
            .to_owned();
        let tag = format!("packages/v{version}+{}", &commit[..12]);
        git(work.path(), &["tag", &tag], None);
        tags.push(tag);
    }
    git(work.path(), &["push", "origin", "main", "--tags"], None);
    Repo {
        work,
        _origin: origin,
        tags,
    }
}

fn level() -> CompatibilityLevel {
    "0.4".parse().expect("a level")
}

fn read(repo: &Repo) -> (Vec<Tagged>, Vec<PageSnapshot>) {
    read_page_history(repo.work.path(), level(), &|_| {}).expect("the page of each release")
}

fn digest(text: &str) -> String {
    kr_cbor::sha256(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn leaked(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

fn row(role: &'static str, texts: &[&str]) -> PageRole {
    PageRole {
        role,
        texts: leak(
            texts
                .iter()
                .map(|text| PageText {
                    digest: if *text == ABSENT {
                        ABSENT
                    } else {
                        leaked(digest(text))
                    },
                    says: "a text of the fixture",
                })
                .collect(),
        ),
    }
}

/// The table of the repository that fits: the range starts at the second release.
fn table(repo: &Repo) -> PageTable {
    PageTable {
        first_tag: leaked(repo.tags[1].clone()),
        tags: 2,
        roles: leak(vec![
            row(BRIDGE, &[BRIDGE_TEXT]),
            row(CALLER, &[CALLER_TEXT]),
            row(CONSTRUCTOR, &[CONSTRUCTOR_TEXT]),
        ]),
    }
}

fn audit(repo: &Repo, table: &PageTable) -> super::narrower_page::PageReport {
    let (expected, snapshots) = read(repo);
    audit_page(&expected, &snapshots, table)
}

/// R5: the report is data, and a page that fits has no problem.
#[test]
fn a_page_that_fits_its_table_has_no_problem_and_the_report_is_returned_as_data() {
    let repo = repo(Page::Fits);
    let report = audit(&repo, &table(&repo));
    assert_eq!(report.problems, Vec::<String>::new());
    let second_and_third = vec![repo.tags[1].clone(), repo.tags[2].clone()];
    assert_eq!(report.range, second_and_third);
    assert_eq!(
        report.groups,
        vec![
            PageGroup {
                role: BRIDGE,
                digest: digest(BRIDGE_TEXT),
                tags: second_and_third.clone()
            },
            PageGroup {
                role: CALLER,
                digest: digest(CALLER_TEXT),
                tags: second_and_third.clone()
            },
            PageGroup {
                role: CONSTRUCTOR,
                digest: digest(CONSTRUCTOR_TEXT),
                tags: second_and_third.clone()
            },
        ]
    );
    assert_eq!(report.texts.len(), 3);
    let constructor = &report.texts[2];
    assert_eq!(constructor.role, CONSTRUCTOR);
    assert_eq!(constructor.paths, vec!["apps/x/src/model/agent.ts"]);
    assert_eq!(constructor.tags, second_and_third);
    // The line that makes the file the constructor's, numbered, with the lines around it.
    assert!(
        constructor.lines.contains("    5:   resource_id: null,"),
        "{}",
        constructor.lines
    );
    assert!(constructor.lines.contains("    3:   action: 'a',"));
    assert!(report.texts[0].lines.contains("plugin_action_invoke"));
    assert!(
        report.texts[1]
            .lines
            .contains(".pluginActionInvoke(call.params)")
    );
}

/// R1: the constructor's `resource_id` changes at the third release while the bridge stays fixed.
#[test]
fn a_constructor_that_changes_while_the_bridge_stays_fixed_is_a_text_the_table_does_not_list() {
    let repo = repo(Page::ChangedAtThree);
    let report = audit(&repo, &table(&repo));
    let changed = digest(CONSTRUCTOR_CHANGED);
    // The second release still has the table's text, so the only problem is the third release's.
    assert_eq!(
        report.problems,
        vec![format!(
            "page: {CONSTRUCTOR} has the text {changed} at {}, and the table does not list it",
            repo.tags[2]
        )]
    );
    // The bridge and the caller are the same text at the two releases.
    assert_eq!(report.groups.len(), 4);
}

/// R2: a release of the range whose constructor has no `resource_id` line fails and names it.
#[test]
fn a_release_of_the_range_with_no_resource_line_in_its_constructor_fails_naming_the_release() {
    let repo = repo(Page::NoLineAtThree);
    let report = audit(&repo, &table(&repo));
    assert!(
        report.problems.contains(&format!(
            "page: {}: no file outside host/ that names PluginActionInvokeParams has a resource_id line",
            repo.tags[2]
        )),
        "{:?}",
        report.problems
    );
    // The second release still has its text, so the table's text is found and not stale.
    assert!(
        !report
            .problems
            .iter()
            .any(|problem| problem.contains("no release of the range has it")),
        "{:?}",
        report.problems
    );
}

/// R3: a release before the bridge maps the action is not read.
#[test]
fn a_release_before_the_bridge_maps_the_action_is_not_read() {
    let repo = repo(Page::Fits);
    let report = audit(&repo, &table(&repo));
    assert_eq!(report.problems, Vec::<String>::new());
    assert!(!report.range.contains(&repo.tags[0]));
    assert!(
        report
            .groups
            .iter()
            .all(|group| !group.tags.contains(&repo.tags[0]))
    );
    // A table that counts it holds the range to the first release that maps the action.
    let counting_it = PageTable {
        first_tag: leaked(repo.tags[0].clone()),
        tags: 3,
        ..table(&repo)
    };
    let report = audit(&repo, &counting_it);
    assert_eq!(
        report.problems,
        vec![
            "page: the table says 3 tags and the bridge maps the action at 2 of the releases below the level".to_owned(),
            format!(
                "page: the first release whose bridge maps the action is {}, and the table says {}",
                repo.tags[1], repo.tags[0]
            ),
        ]
    );
}

/// R4: a test file and a fake file are not selected, nor is a file that holds one word of a role.
#[test]
fn a_test_file_a_fake_file_and_a_file_that_holds_one_word_of_a_role_are_not_selected() {
    for path in [
        "apps/x/src/host/fake.ts",
        "apps/x/src/views/Conversation.test.tsx",
        "apps/x/src/testing/support.ts",
        "apps/x/test/conversation.test.tsx",
        "apps/x/src-tauri/src/lib.rs",
        "crates/kr-cli/src/lib.ts",
    ] {
        assert!(!is_page_file(path), "{path}");
    }
    assert!(is_page_file("apps/x/src/host/tauri.ts"));
    assert!(is_page_file("apps/x/src/views/Conversation.tsx"));
    let all = [
        "apps/x/src/host/tauri.ts",
        "apps/x/src/views/Conversation.tsx",
        "apps/x/src/model/agent.ts",
        "apps/x/src/host/port.ts",
        "apps/x/src/host/fake.ts",
        "apps/x/src/views/Conversation.test.tsx",
    ];
    let every_word = "pluginActionInvoke plugin_action_invoke .pluginActionInvoke( PluginActionInvokeParams resource_id";
    let selected = select(
        all.iter()
            .map(|path| ((*path).to_owned(), every_word.to_owned())),
    );
    let paths = |role: &str| -> Vec<&str> {
        selected[role]
            .iter()
            .map(|file| file.path.as_str())
            .collect()
    };
    // Outside the test and the fake, a file that holds every word is every role's, except that
    // the constructor is never in `host/`.
    assert_eq!(
        paths(BRIDGE),
        vec![
            "apps/x/src/host/port.ts",
            "apps/x/src/host/tauri.ts",
            "apps/x/src/model/agent.ts",
            "apps/x/src/views/Conversation.tsx",
        ]
    );
    assert_eq!(paths(BRIDGE), paths(CALLER));
    assert_eq!(
        paths(CONSTRUCTOR),
        vec![
            "apps/x/src/model/agent.ts",
            "apps/x/src/views/Conversation.tsx"
        ]
    );
    // The port declares the method and names the type, and is none of the three.
    let selected = select([("apps/x/src/host/port.ts".to_owned(), PORT.to_owned())]);
    assert!(selected.values().all(Vec::is_empty), "{selected:?}");
    // In the repository, the fake and the test file change at each release and the report has no
    // text of theirs.
    let repo = repo(Page::Fits);
    let report = audit(&repo, &table(&repo));
    assert_eq!(report.problems, Vec::<String>::new());
    assert!(
        report
            .texts
            .iter()
            .flat_map(|text| &text.paths)
            .all(|path| !path.contains("fake") && !path.contains("test"))
    );
}

/// A snapshot that is missing, a tag that cannot be read, a range with no bridge, and a table that
/// is malformed are each a text of their own.
#[test]
fn a_missing_snapshot_an_unreadable_tag_and_a_malformed_table_are_texts_of_their_own() {
    let repo = repo(Page::Fits);
    let table = table(&repo);
    let (expected, snapshots) = read(&repo);
    let report = audit_page(&expected, &snapshots[..2], &table);
    assert_eq!(
        report.problems,
        vec![format!(
            "page: {} at {} is expected and has no snapshot",
            expected[2].tag, expected[2].commit
        )]
    );
    let mut unreadable = snapshots.clone();
    unreadable[2].roles = Err("git archive failed".to_owned());
    let report = audit_page(&expected, &unreadable, &table);
    assert!(
        report.problems.contains(&format!(
            "page: {} could not be read (git archive failed)",
            expected[2].tag
        )),
        "{:?}",
        report.problems
    );
    let mut without_bridge = snapshots.clone();
    for snapshot in &mut without_bridge {
        if let Ok(roles) = &mut snapshot.roles {
            roles.insert(BRIDGE, Vec::new());
        }
    }
    let report = audit_page(&expected, &without_bridge, &table);
    assert!(
        report.problems.contains(
            &"page: no release below the level has a bridge that maps pluginActionInvoke"
                .to_owned()
        ),
        "{:?}",
        report.problems
    );
    let malformed = PageTable {
        first_tag: "",
        tags: 0,
        roles: leak(vec![
            row(BRIDGE, &[BRIDGE_TEXT, BRIDGE_TEXT]),
            row(BRIDGE, &[ABSENT]),
            row(CONSTRUCTOR, &[ABSENT]),
        ]),
    };
    let problems = table_problems(&malformed);
    for text in [
        "page table: first_tag is empty",
        "page table: tags is zero",
        "page table: the constructor is never absent",
        "page table: the caller has 0 rows, not one",
        "page table: the bridge has 2 rows, not one",
    ] {
        assert!(
            problems.iter().any(|problem| problem == text),
            "{text}: {problems:?}"
        );
    }
    assert!(problems.iter().any(|problem| problem.contains("twice")));
}

/// The table of the checkout is well formed. What it lists is read at each release by
/// `the_resource_senders_at_each_release`.
#[test]
fn the_page_table_of_this_checkout_is_well_formed() {
    assert_eq!(table_problems(&PAGE), Vec::<String>::new());
}
