//! The key map of this repository, written out whole so two trees of the code can be compared.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use kr_conformance::plan::Platform;
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
            held_to_ignored_runs: true,
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
