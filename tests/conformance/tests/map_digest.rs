//! The key map of this repository, written out whole so two trees of the code can be compared.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kr_conformance::plan::{ApplicationsPlan, Platform};
use kr_conformance::plan_file::Plan;
use kr_conformance::report::{self, Options};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Writes the keys, references, refused mentions, problems and warnings of the map, with every
/// target's tests, once without TypeScript and once with it, to the file named by
/// `KR_KEY_MAP_OUT`. The file lies outside the repository; two files, one from each tree of the code,
/// are equal when the code builds the same map. Source lines are part of each key, so a change
/// to a file between the two trees shows as a difference to read by name.
#[test]
#[ignore = "writes the key map to the file named by KR_KEY_MAP_OUT; run by hand"]
fn the_key_map_is_written_whole_to_the_file_named_by_the_variable() {
    let out = std::env::var_os("KR_KEY_MAP_OUT").expect("KR_KEY_MAP_OUT names the file to write");
    let out = PathBuf::from(out);
    assert!(
        out.is_absolute() && !out.starts_with(repository().canonicalize().expect("the root")),
        "the file lies outside the repository: {}",
        out.display()
    );
    let root = repository();
    let plan = Plan::load(&root, None).expect("the repository's plan file loads");
    let mut text = String::new();
    for (name, typescript) in [("plain", false), ("typescript", true)] {
        let options = Options {
            root: root.clone(),
            evidence: PathBuf::new(),
            selection: Some(Vec::new()),
            all_terminals: false,
            platform: Platform::current(),
            plan: plan.clone(),
            typescript_compiler: None,
            applications: None,
            environment: Vec::new(),
            lister: PathBuf::new(),
            part: None,
            runner_base: PathBuf::new(),
        };
        let map = report::map_declared(&options, typescript);
        writeln!(text, "== {name}").expect("a string");
        writeln!(text, "keys {:#?}", map.keys).expect("a string");
        writeln!(text, "references {:#?}", map.references).expect("a string");
        writeln!(text, "refused {:#?}", map.refused).expect("a string");
        writeln!(text, "problems {:#?}", map.problems).expect("a string");
        writeln!(text, "warnings {:#?}", map.warnings).expect("a string");
        writeln!(text, "rust_tests {:#?}", map.rust_tests).expect("a string");
        writeln!(text, "ignored_tests {:#?}", map.ignored_tests).expect("a string");
        writeln!(text, "lane_classes {:#?}", map.lane_classes).expect("a string");
    }
    std::fs::write(&out, text).expect("the file is written");
}

/// Writes the steps of every platform's plan for every selection of groups, to the file named by
/// `KR_COMMAND_LINES_OUT`: each platform with all the plan's groups and with each group alone, with
/// no applications and with every application run. The file lies outside the repository; two
/// files, one from each tree of the code, are equal when the code selects the same command lines.
#[test]
#[ignore = "writes every selection's command lines to the file named by KR_COMMAND_LINES_OUT; run by hand"]
fn the_command_lines_of_every_selection_are_written_whole_to_the_file_named_by_the_variable() {
    let out = std::env::var_os("KR_COMMAND_LINES_OUT")
        .expect("KR_COMMAND_LINES_OUT names the file to write");
    let out = PathBuf::from(out);
    assert!(
        out.is_absolute() && !out.starts_with(repository().canonicalize().expect("the root")),
        "the file lies outside the repository: {}",
        out.display()
    );
    let plan = Plan::load(&repository(), None).expect("the repository's plan file loads");
    let mut selections: Vec<(String, Vec<String>)> =
        vec![("all groups".to_owned(), plan.all_groups())];
    selections.extend(
        plan.all_groups()
            .into_iter()
            .map(|group| (format!("group {group}"), vec![group])),
    );
    let every_application = ApplicationsPlan {
        left_out: Vec::new(),
    };
    let mut text = String::new();
    for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
        for (name, groups) in &selections {
            for (applications, given) in [("none", None), ("all", Some(&every_application))] {
                writeln!(
                    text,
                    "== {} {name} applications {applications}",
                    platform.name()
                )
                .expect("a string");
                writeln!(
                    text,
                    "{:#?}",
                    plan.steps(platform, groups, "evidence", given)
                )
                .expect("a string");
            }
        }
    }
    std::fs::write(&out, text).expect("the file is written");
}
