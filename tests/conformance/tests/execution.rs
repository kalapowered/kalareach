//! How a step of the plan runs: the directory it runs in, the variables it is given, the file it
//! writes for the report to read, and the scratch directory of the run.
//!
//! Each case copies a tree under `tests/fixtures/` into a directory of its own, makes the copy a Git
//! repository whose index holds every file (the loader reads a plan's scripts through the index),
//! and runs the report over it with a plan the case writes. `setup-step` is a Cargo workspace with
//! two test programs and the scripts the plan runs; `no-root-manifest` has two workspaces, each in a
//! directory of its own.

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_conformance::plan::Platform;
use kr_conformance::plan_file::Plan;
use kr_conformance::report::{self, Document, Options, Stopped, Verdict};

const FIXED: &str = "[ignored_runs]
held = false
[unrun]
bench = 'b'
typescript = 't'
[unrun.rust]
linux = 'l'
macos = 'm'
windows = 'w'
";

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_into(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("the fixture") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_into(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("a file");
        }
    }
}

/// A copy of the fixture `name` in a directory of its own, made a Git repository whose index holds
/// every file the copy has when this returns.
fn copy(name: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path().canonicalize().expect("the copy's root");
    copy_into(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name),
        &root,
    );
    git(&root, &["init", "-q"]);
    git(&root, &["add", "-A"]);
    (directory, root)
}

/// The text of a plan with one group, `rust`, whose workspaces are `manifests`, and `rest`.
fn plan_of(manifests: &[&str], rest: &str) -> String {
    let manifests: Vec<String> = manifests.iter().map(|name| format!("'{name}'")).collect();
    format!(
        "repository = 'execution'\ngroups = ['rust']\n[rust]\nmanifests = [{}]\n{FIXED}{rest}",
        manifests.join(", ")
    )
}

/// What a run left: the result, the evidence directory and the directory the run made its own
/// files in, both still on disk.
struct Ran {
    document: Document,
    evidence: tempfile::TempDir,
    base: tempfile::TempDir,
}

fn options(root: &Path, plan: Plan, evidence: &Path, base: &Path) -> Options {
    Options {
        root: root.to_path_buf(),
        evidence: kr_conformance::evidence::check_directory(evidence)
            .expect("inside the temporary directory"),
        selection: Some(vec!["rust".to_owned()]),
        all_terminals: false,
        platform: Platform::current(),
        plan,
        typescript_compiler: None,
        applications: None,
        environment: vec![(
            "CARGO_TARGET_DIR".to_owned(),
            std::env::temp_dir()
                .join("kr-conformance-fixture-target-execution")
                .to_string_lossy()
                .into_owned(),
        )],
        lister: PathBuf::from(env!("CARGO_BIN_EXE_kr-conformance")),
        part: None,
        runner_base: base.to_path_buf(),
    }
}

/// Loads `text` as the plan of the tree at `root`, after making its files tracked, and runs the
/// report over it.
fn run(root: &Path, text: &str) -> Result<Ran, Stopped> {
    git(root, &["add", "-A"]);
    let plan =
        Plan::parse(text, root).unwrap_or_else(|refusal| panic!("the plan loads: {refusal}"));
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let base = tempfile::tempdir().expect("a directory for the run's own files");
    let options = options(root, plan, evidence.path(), base.path());
    report::run(&options, &mut |_| {}).map(|document| Ran {
        document,
        evidence,
        base,
    })
}

/// KR-REQ-29.01, the part about reproducible commands: a step runs in the directory its plan
/// names, and its build, its listing of the tests and its run all use it. The tree has no manifest
/// at its root, so a build that began in the root would fail.
#[test]
fn a_step_runs_in_its_directory_for_the_build_the_listing_and_the_run() {
    let (_directory, root) = copy("no-root-manifest");
    let text = plan_of(
        &["first/Cargo.toml", "second/Cargo.toml"],
        "[[step]]
id = 'first'
group = 'rust'
what = 'the first workspace'
platforms = ['linux', 'macos', 'windows']
reading = 'cargo'
directory = 'first'
command = ['cargo', 'test', '--locked']
",
    );
    let ran = run(&root, &text).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let step = &ran.document.steps[0];
    assert_eq!(
        (step.exit, step.error.as_deref()),
        (Some(0), None),
        "{step:?}"
    );
    assert_eq!(
        ran.document.identifiers["KR-REQ-03.01"].verdict,
        Verdict::Passed
    );
}

/// KR-REQ-29.01, the part about reproducible commands: the variables of the plan's `[env]` and of a
/// step reach the tests, and the step's value of a name replaces the plan's.
#[test]
fn the_plans_variables_and_the_steps_own_reach_the_tests() {
    let (_directory, root) = copy("setup-step");
    let text = plan_of(
        &["Cargo.toml"],
        "[env]
KR_FROM_PLAN = 'plan'
KR_IN_BOTH = \"the plan's\"
[[step]]
id = 'variables'
group = 'rust'
what = 'the variables'
platforms = ['linux', 'macos', 'windows']
reading = 'cargo'
env = { KR_FROM_STEP = 'step', KR_IN_BOTH = \"the step's\" }
command = ['cargo', 'test', '--locked', '--test', 'plan_env']
",
    );
    let ran = run(&root, &text).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    assert_eq!(
        ran.document.identifiers["KR-REQ-05.01"].verdict,
        Verdict::Passed,
        "{:?}",
        ran.document.steps[0]
    );
}

/// A plan of one `bash` script step that reads nothing, whose command is `words`.
fn script_plan(words: &str, more: &str) -> String {
    plan_of(
        &["Cargo.toml"],
        &format!(
            "[[step]]
id = 'script'
group = 'rust'
what = 'the script'
platforms = ['linux', 'macos', 'windows']
reading = 'build'
{more}
command = [{words}]
"
        ),
    )
}

/// KR-REQ-29.01, the part about reproducible commands: `{scratch}` names a directory the run makes
/// outside the evidence directory, which the step can write in and which is gone when the run ends.
#[cfg(unix)]
#[test]
fn the_scratch_directory_is_outside_the_evidence_and_gone_when_the_run_ends() {
    let (_directory, root) = copy("setup-step");
    let place = tempfile::tempdir().expect("a directory for the step's note");
    let note = place.path().join("scratch.txt");
    let text = script_plan(
        &format!(
            "'bash', 'scripts/scratch.sh', '{{scratch}}', '{}'",
            note.display()
        ),
        "",
    );
    let ran = run(&root, &text).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let step = &ran.document.steps[0];
    assert_eq!(
        (step.exit, step.error.as_deref()),
        (Some(0), None),
        "{step:?}"
    );
    let said = std::fs::read_to_string(&note).expect("the step recorded the directory");
    let scratch = PathBuf::from(said.trim());
    let base = ran.base.path().canonicalize().expect("the base");
    let evidence = ran.evidence.path().canonicalize().expect("the evidence");
    assert!(
        scratch.starts_with(&base),
        "{scratch:?} is not under {base:?}"
    );
    assert!(
        !scratch.starts_with(&evidence),
        "{scratch:?} is inside {evidence:?}"
    );
    assert!(!scratch.exists(), "{scratch:?} is still there");
}

/// KR-REQ-29.01, the part about reproducible commands: the run makes in the evidence directory
/// the directory of the logs, and what the plan's outputs need, and nothing a plan does not name.
#[cfg(unix)]
#[test]
fn a_run_makes_in_the_evidence_only_the_logs_and_the_directories_of_its_outputs() {
    let (_directory, root) = copy("setup-step");
    let text = script_plan(
        "'bash', 'scripts/write.sh', '{output}'",
        "output = '{evidence}/conformance/deep/er/out.txt'",
    );
    let ran = run(&root, &text).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let step = &ran.document.steps[0];
    assert_eq!(
        (step.exit, step.error.as_deref()),
        (Some(0), None),
        "{step:?}"
    );
    let own = ran.evidence.path().join("conformance");
    let mut made: Vec<String> = std::fs::read_dir(&own)
        .expect("the report's directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    made.sort();
    assert_eq!(made, ["deep", "logs"]);
    assert_eq!(
        std::fs::read_to_string(own.join("deep").join("er").join("out.txt")).expect("the output"),
        "written\n"
    );
}

/// KR-REQ-29.01, the part about reproducible commands: a directory a step builds in is a directory
/// the report's own program is not copied into, whether the plan's `[env]` or the step's `env` names
/// it, and a relative one is read from the step's own directory.
#[test]
fn a_runner_base_inside_a_target_directory_a_step_names_is_refused() {
    for (name, plan_env, step_env, directory, target) in [
        (
            "the plan's env",
            "[env]\nCARGO_TARGET_DIR = '{root}/built'\n",
            "",
            "",
            "built",
        ),
        (
            "a step's env",
            "",
            "env = { CARGO_TARGET_DIR = '{root}/built' }\n",
            "",
            "built",
        ),
        (
            "a relative one, read from the step's directory",
            "",
            "env = { CARGO_TARGET_DIR = 'built' }\n",
            "directory = 'first'\n",
            "first/built",
        ),
    ] {
        let (_directory, root) = copy("no-root-manifest");
        let text = plan_of(
            &["first/Cargo.toml", "second/Cargo.toml"],
            &format!(
                "{plan_env}[[step]]
id = 'first'
group = 'rust'
what = 'the first workspace'
platforms = ['linux', 'macos', 'windows']
reading = 'cargo'
{directory}{step_env}command = ['cargo', 'test', '--locked']
"
            ),
        );
        git(&root, &["add", "-A"]);
        let plan = Plan::parse(&text, &root)
            .unwrap_or_else(|refusal| panic!("{name}: the plan loads: {refusal}"));
        let inside = root.join(target).join("work");
        std::fs::create_dir_all(&inside).expect("a directory inside the target directory");
        let evidence = tempfile::Builder::new()
            .prefix("kr-conformance-evidence.")
            .tempdir()
            .expect("an evidence directory");
        let mut options = options(&root, plan, evidence.path(), &inside);
        options.environment.clear();
        match report::run(&options, &mut |_| {}) {
            Err(Stopped::PrivateCopy(problem)) => {
                assert!(problem.contains("where a step builds"), "{name}: {problem}");
            }
            other => panic!("{name}: the run was not stopped by the copy: {other:?}"),
        }
    }
}

/// KR-REQ-29.01, the part about reproducible commands: what a step's output names is what the
/// report reads, so a Vitest step and a lane step each name theirs, and core's plan does so too.
#[test]
fn the_vitest_and_lane_steps_of_cores_plan_each_name_their_output() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("conformance")
            .join("plan.toml"),
    )
    .expect("core's plan file");
    let plan: toml::Table = text.parse().expect("a TOML file");
    let steps = plan["step"].as_array().expect("the steps");
    let mut reading_a_file = 0;
    for step in steps {
        let table = step.as_table().expect("a step");
        let id = table["id"].as_str().expect("an id");
        let reading = table["reading"].as_str().expect("a reading");
        if reading != "vitest" && reading != "lane" {
            continue;
        }
        reading_a_file += 1;
        let output = table
            .get("output")
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("the step `{id}` reads a file and names no output"));
        assert!(
            output.starts_with("{evidence}/conformance/"),
            "{id}: {output}"
        );
        let mentions = |word: &toml::Value| word.as_str().is_some_and(|w| w.contains("{output}"));
        assert!(
            table["command"]
                .as_array()
                .expect("a command")
                .iter()
                .any(mentions),
            "the command of `{id}` does not hold {{output}}"
        );
    }
    assert_eq!(reading_a_file, 5);
}
