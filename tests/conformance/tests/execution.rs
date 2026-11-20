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
#[cfg(unix)]
use std::time::{Duration, Instant};

use kr_conformance::plan::Platform;
use kr_conformance::plan_file::Plan;
#[cfg(unix)]
use kr_conformance::report::Outcome;
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

/// A copy of the fixture `name` at `root`, made a Git repository whose index holds every file the
/// copy has when this returns.
fn copy_to(name: &str, root: &Path) {
    copy_into(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name),
        root,
    );
    git(root, &["init", "-q"]);
    git(root, &["add", "-A"]);
}

/// A copy of the fixture `name` in a directory of its own, made a Git repository whose index holds
/// every file the copy has when this returns.
fn copy(name: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path().canonicalize().expect("the copy's root");
    copy_to(name, &root);
    (directory, root)
}

/// A copy of the fixture `name` as `tree` in a directory of its own, which holds nothing else: the
/// repository has a sibling directory outside it.
fn copy_beside(name: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory
        .path()
        .canonicalize()
        .expect("the case's directory")
        .join("tree");
    copy_to(name, &root);
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

/// What a run left: the result, and on Unix, where the cases that read them are run, the evidence
/// directory and the directory the run made its own files in, both still on disk.
struct Ran {
    document: Document,
    #[cfg(unix)]
    evidence: tempfile::TempDir,
    #[cfg(unix)]
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
        #[cfg(unix)]
        evidence,
        #[cfg(unix)]
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

/// KR-REQ-29.01, the part about reproducible commands: a step's tests are the targets of the map
/// when the root is spelled by a link (or, on Windows, in the `\\?\` form of a canonical path)
/// that the working directory Cargo builds in does not carry. The build's source paths and the
/// map's are two spellings of one file, and the run reads the tests from the build's.
#[cfg(unix)]
#[test]
fn a_step_reads_its_tests_when_the_root_is_spelled_by_a_link() {
    let (_directory, root) = copy("setup-step");
    let links = tempfile::tempdir().expect("a directory");
    let link = links.path().join("checkout");
    std::os::unix::fs::symlink(&root, &link).expect("a link");
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
    let ran = run(&link, &text).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let step = &ran.document.steps[0];
    assert_eq!(
        (step.exit, step.error.as_deref()),
        (Some(0), None),
        "{step:?}"
    );
    assert_eq!(
        ran.document.identifiers["KR-REQ-05.01"].verdict,
        Verdict::Passed
    );
}

/// KR-REQ-29.01, the part about reproducible commands: `{root}` is the absolute root, with forward
/// slashes, so that a step that runs in a directory of the repository reaches the repository
/// through it whatever `--root` the program was started with. Here the program is started in the
/// directory that holds the repository, with the repository's name as its root, and the step's
/// script fails unless the root it is given holds a file of the repository.
#[cfg(unix)]
#[test]
fn the_root_placeholder_is_the_absolute_root_when_the_root_is_given_relative() {
    let (case, root) = copy_beside("no-root-manifest");
    std::fs::write(
        root.join("first").join("check-root.sh"),
        "test -f \"$1/first/check-root.sh\"\n",
    )
    .expect("a script");
    let text = plan_of(
        &["first/Cargo.toml", "second/Cargo.toml"],
        "[[step]]
id = 'check'
group = 'rust'
what = 'the root'
platforms = ['linux', 'macos', 'windows']
reading = 'build'
directory = 'first'
command = ['bash', 'check-root.sh', '{root}']
",
    );
    std::fs::create_dir_all(root.join("conformance")).expect("a directory");
    let plan = root.join("conformance").join("plan.toml");
    std::fs::write(&plan, text).expect("the plan");
    git(&root, &["add", "-A"]);
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir()
        .expect("an evidence directory");
    let output = Command::new(env!("CARGO_BIN_EXE_kr-conformance"))
        .current_dir(case.path())
        .args(["run", "--root", "tree", "--plan"])
        .arg(&plan)
        .arg("--evidence")
        .arg(evidence.path())
        .output()
        .expect("the program runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// KR-REQ-29.01, the part about reproducible commands: two packages whose `tests/shared.rs` are
/// links to one file have a target each, and each test program of the build is the tests of its own
/// package. A match by the file the links lead to, and the name, gives both programs to the first.
#[cfg(unix)]
#[test]
fn two_packages_with_test_files_that_link_to_one_file_each_keep_their_own_target() {
    let (_directory, root) = copy("linked-source");
    for package in ["alpha", "beta"] {
        let tests = root.join(package).join("tests");
        std::fs::create_dir(&tests).expect("a directory");
        std::os::unix::fs::symlink("../../common/shared.rs", tests.join("shared.rs"))
            .expect("a link");
    }
    let text = plan_of(
        &["Cargo.toml"],
        "[[step]]
id = 'both'
group = 'rust'
what = 'the tests of both packages'
platforms = ['linux', 'macos', 'windows']
reading = 'cargo'
command = ['cargo', 'test', '--locked', '--workspace']
",
    );
    let ran = run(&root, &text).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let step = &ran.document.steps[0];
    assert_eq!(
        (step.exit, step.error.as_deref()),
        (Some(0), None),
        "{step:?}"
    );
    let identifier = &ran.document.identifiers["KR-REQ-05.01"];
    let mut tests: Vec<(&str, Vec<(usize, Outcome)>)> = identifier
        .tests
        .iter()
        .map(|test| {
            (
                test.test.as_str(),
                test.runs
                    .iter()
                    .map(|run| (run.step, run.outcome.clone()))
                    .collect(),
            )
        })
        .collect();
    tests.sort_by_key(|(name, _)| *name);
    assert_eq!(
        tests,
        vec![
            (
                "alpha --test shared the_file_both_packages_build",
                vec![(1, Outcome::Passed)]
            ),
            (
                "beta --test shared the_file_both_packages_build",
                vec![(1, Outcome::Passed)]
            ),
        ],
        "{identifier:?}"
    );
}

/// A plan of one `bash` script step that reads nothing, whose command is `words`.
#[cfg(unix)]
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

/// KR-REQ-29.01, the part about reproducible commands: a step whose output is there before it runs
/// is not run, because the plan's checks keep one step's output from another's only where they see
/// it, in `output`, and a command word of an earlier step can name the same place. Here an earlier
/// step writes the later step's output, and the later step would otherwise be read from what the
/// earlier wrote.
#[cfg(unix)]
#[test]
fn a_step_whose_output_exists_before_it_runs_is_not_run() {
    let (_directory, root) = copy("setup-step");
    let text = plan_of(
        &["Cargo.toml"],
        "[[step]]
id = 'writer'
group = 'rust'
what = 'the writer'
platforms = ['linux', 'macos', 'windows']
reading = 'build'
command = ['bash', 'scripts/write.sh', '{evidence}/conformance/x.txt']
[[step]]
id = 'owner'
group = 'rust'
what = 'the owner'
platforms = ['linux', 'macos', 'windows']
reading = 'build'
output = '{evidence}/conformance/x.txt'
command = ['bash', 'scripts/write.sh', '{output}']
",
    );
    let ran = run(&root, &text).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let steps = &ran.document.steps;
    assert_eq!(steps.len(), 2, "{steps:?}");
    assert_eq!((steps[0].exit, steps[0].error.as_deref()), (Some(0), None));
    assert_eq!(
        (steps[1].exit, steps[1].error.as_deref()),
        (
            None,
            Some(
                "the output `conformance/x.txt` of the step was there before the step \
                 ran, so another step or command wrote it"
            )
        )
    );
}

/// KR-REQ-29.01, the part about reproducible commands: a directory a step builds in is a directory
/// the report's own program is not copied into, whichever way the step is given it: by the plan's
/// `[env]`, by the step's `env` or by the options the program was started with, absolute or
/// relative, and a relative one is read from the step's own directory. Each target directory lies
/// outside the repository, so that only the step's variables, and not the repository the guard
/// holds in any case, can name it.
#[test]
fn a_runner_base_inside_a_target_directory_a_step_names_is_refused() {
    let absolute = "'{built}'";
    let relative = "'../../built'";
    for (name, plan_env, step_env, from_options, platform) in [
        (
            "the plan's env, absolute",
            format!("[env]\nCARGO_TARGET_DIR = {absolute}\n"),
            String::new(),
            None,
            Platform::current(),
        ),
        (
            "the plan's env, relative to the step's directory",
            format!("[env]\nCARGO_TARGET_DIR = {relative}\n"),
            String::new(),
            None,
            Platform::current(),
        ),
        (
            "a step's env, absolute",
            String::new(),
            format!("env = {{ CARGO_TARGET_DIR = {absolute} }}\n"),
            None,
            Platform::current(),
        ),
        (
            "a step's env, relative to the step's directory",
            String::new(),
            format!("env = {{ CARGO_TARGET_DIR = {relative} }}\n"),
            None,
            Platform::current(),
        ),
        (
            "a step's env, spelt in lower case, where the platform takes the names as one",
            String::new(),
            format!("env = {{ cargo_target_dir = {absolute} }}\n"),
            None,
            Platform::Windows,
        ),
        (
            "the options' variable, absolute",
            String::new(),
            String::new(),
            Some("{built}"),
            Platform::current(),
        ),
        (
            "the options' variable, relative to the step's directory",
            String::new(),
            String::new(),
            Some("../../built"),
            Platform::current(),
        ),
    ] {
        // The repository is `tree` in a directory of its own, so that `built`, beside it, is
        // outside it, and `../../built` from the step's directory `tree/first` is that directory.
        let (case, root) = copy_beside("no-root-manifest");
        let built = case.path().canonicalize().expect("the case").join("built");
        let inside = built.join("work");
        std::fs::create_dir_all(&inside).expect("a directory inside the target directory");
        let built_text = built.to_string_lossy().replace('\\', "/");
        let text = plan_of(
            &["first/Cargo.toml", "second/Cargo.toml"],
            &format!(
                "{plan_env}[[step]]
id = 'first'
group = 'rust'
what = 'the first workspace'
platforms = ['linux', 'macos', 'windows']
reading = 'cargo'
directory = 'first'
{step_env}command = ['cargo', 'test', '--locked']
"
            )
            .replace("{built}", &built_text),
        );
        git(&root, &["add", "-A"]);
        let plan = Plan::parse(&text, &root)
            .unwrap_or_else(|refusal| panic!("{name}: the plan loads: {refusal}"));
        let evidence = tempfile::Builder::new()
            .prefix("kr-conformance-evidence.")
            .tempdir()
            .expect("an evidence directory");
        let mut options = options(&root, plan, evidence.path(), &inside);
        options.platform = platform;
        options.environment.clear();
        if let Some(value) = from_options {
            options.environment.push((
                "CARGO_TARGET_DIR".to_owned(),
                value.replace("{built}", &built_text),
            ));
        }
        match report::run(&options, &mut |_| {}) {
            Err(Stopped::PrivateCopy(problem)) => {
                assert!(
                    problem.contains("where a step builds")
                        && problem.contains(&built.to_string_lossy().into_owned()),
                    "{name}: {problem}"
                );
            }
            other => panic!("{name}: the run was not stopped by the copy: {other:?}"),
        }
        assert!(
            std::fs::read_dir(&inside)
                .expect("the base")
                .next()
                .is_none(),
            "{name}: the report's program was copied into the base"
        );
    }
}

/// KR-REQ-29.01, the part about reproducible commands: a directory a step builds in is also the one
/// that the report's own environment names. The program is started with `CARGO_TARGET_DIR` in its
/// own environment and a temporary directory inside that directory, which is where it copies its
/// own program to run each test binary, so the run is stopped before a step runs and nothing is
/// copied there.
#[cfg(unix)]
#[test]
fn a_runner_base_inside_the_target_directory_of_the_programs_own_environment_is_refused() {
    let (case, root) = copy_beside("no-root-manifest");
    let built = case.path().canonicalize().expect("the case").join("built");
    let temporary = built.join("work");
    std::fs::create_dir_all(&temporary).expect("a temporary directory inside the target directory");
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
    std::fs::create_dir_all(root.join("conformance")).expect("a directory");
    let plan = root.join("conformance").join("plan.toml");
    std::fs::write(&plan, text).expect("the plan");
    git(&root, &["add", "-A"]);
    let evidence = tempfile::Builder::new()
        .prefix("kr-conformance-evidence.")
        .tempdir_in(&temporary)
        .expect("an evidence directory inside the temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_kr-conformance"))
        .current_dir(case.path())
        .env("CARGO_TARGET_DIR", &built)
        .env("TMPDIR", &temporary)
        .args(["run", "--root"])
        .arg(&root)
        .arg("--plan")
        .arg(&plan)
        .arg("--evidence")
        .arg(evidence.path())
        .output()
        .expect("the program runs");
    let said = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "{said}");
    assert!(
        said.contains("where a step builds")
            && said.contains(&built.to_string_lossy().into_owned()),
        "{said}"
    );
    let entries: Vec<_> = std::fs::read_dir(&temporary)
        .expect("the base")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    assert_eq!(
        entries,
        vec![evidence.path().to_path_buf()],
        "the report's program was copied into the base"
    );
}

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

/// The fixture's own plan, with the exit status the set-up step's script is given replaced.
fn fixture_plan(root: &Path, status: &str) -> String {
    let text = std::fs::read_to_string(root.join("conformance").join("plan.toml"))
        .expect("the fixture's plan");
    let from = "'{scratch}/made.txt', '0']";
    assert!(text.contains(from), "the fixture's set-up step");
    text.replace(from, &format!("'{{scratch}}/made.txt', '{status}']"))
}

/// KR-REQ-29.01, the part about reproducible commands: a set-up step that exits 0 gives a later
/// step what it made, and the test of that step asserts the value it got through its `env`.
#[cfg(unix)]
#[test]
fn a_set_up_step_that_exits_0_gives_a_test_the_value_it_asserts() {
    let (_directory, root) = copy("setup-step");
    let ran = run(&root, &fixture_plan(&root, "0")).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let steps = &ran.document.steps;
    assert_eq!(steps.len(), 3, "{steps:?}");
    for step in steps {
        assert_eq!(
            (step.exit, step.error.as_deref()),
            (Some(0), None),
            "{step:?}"
        );
    }
    assert_eq!(
        ran.document.identifiers["KR-REQ-05.02"].verdict,
        Verdict::Passed
    );
    assert!(ran.document.passed(), "{:?}", ran.document.problems);
}

/// KR-REQ-29.01, the part about reproducible commands: a set-up step that exits 1 fails the run,
/// and the step that names it is not run: it reads not run with the set-up step's number and what
/// became of it, and so does the test that step covers. A step that does not name it still runs.
#[cfg(unix)]
#[test]
fn a_set_up_step_that_fails_leaves_its_dependent_not_run_and_fails_the_run() {
    let (_directory, root) = copy("setup-step");
    let ran = run(&root, &fixture_plan(&root, "1")).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let steps = &ran.document.steps;
    assert_eq!(steps[0].exit, Some(1));
    assert_eq!(
        (steps[1].exit, steps[1].error.as_deref()),
        (Some(0), None),
        "a step that does not name the set-up step runs"
    );
    assert_eq!(steps[2].exit, None);
    assert_eq!(
        steps[2].error.as_deref(),
        Some("not run because its set-up step 1 (the file the tests read) exited with status 1")
    );
    assert!(!ran.document.passed());
    assert_eq!(ran.document.summary.failed_steps, [1, 3]);
    let record = &ran.document.identifiers["KR-REQ-05.02"];
    assert_eq!(record.verdict, Verdict::NotRun);
    let test = &record.tests[0];
    assert_eq!(test.outcome, Outcome::NotRun);
    let reason = test.reason.as_deref().unwrap_or_default();
    assert!(
        reason.contains(
            "was not run because its set-up step 1 (the file the tests read) exited with status 1"
        ),
        "{reason}"
    );
}

/// A plan of the fixture `setup-step` whose steps are two set-up steps, `first` and `second`, which
/// names `first` in `after`, and a test step, `last`, which names `second`. `first_gets` is what the
/// first step is given besides the script.
#[cfg(unix)]
fn chain_of_set_up_steps(first_gets: &str) -> String {
    let set_up = |id: &str, what: &str, after: &str, gets: &str| {
        format!(
            "[[step]]
id = '{id}'
group = 'rust'
what = '{what}'
platforms = ['linux', 'macos', 'windows']
reading = 'exit'
setup = true
{after}{gets}command = ['bash', 'scripts/set-up.sh', '{{scratch}}/{id}.txt', '{}']
",
            if gets.is_empty() { "1" } else { "0" }
        )
    };
    plan_of(
        &["Cargo.toml"],
        &format!(
            "{}{}[[step]]
id = 'last'
group = 'rust'
what = 'the test that reads the file'
platforms = ['linux', 'macos', 'windows']
reading = 'cargo'
after = ['second']
env = {{ KR_MADE_BY_SET_UP = '{{scratch}}/second.txt' }}
command = ['cargo', 'test', '--locked', '--test', 'set_up']
",
            set_up("first", "the first set-up", "", first_gets),
            set_up("second", "the second set-up", "after = ['first']\n", "")
        ),
    )
}

/// KR-REQ-29.01, the part about reproducible commands: a step that names a set-up step that was
/// itself not run, because a set-up step it names failed or could not be run, is not run either,
/// and says so in words that are true of each: the first set-up step's own failure is named once,
/// where it happened, and the steps after it read that it was not run.
#[cfg(unix)]
#[test]
fn a_failed_set_up_step_reaches_a_step_through_another_set_up_step() {
    let (_directory, root) = copy("setup-step");
    // The first set-up step exits 1.
    let ran =
        run(&root, &chain_of_set_up_steps("")).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let steps = &ran.document.steps;
    assert_eq!(steps.len(), 3, "{steps:?}");
    assert_eq!(steps[0].exit, Some(1));
    assert_eq!(
        steps[1].error.as_deref(),
        Some("not run because its set-up step 1 (the first set-up) exited with status 1")
    );
    assert_eq!(
        steps[2].error.as_deref(),
        Some(
            "not run because its set-up step 2 (the second set-up) was not run, because its \
             set-up step 1 did not succeed"
        )
    );
    assert_eq!((steps[1].exit, steps[2].exit), (None, None));
    assert_eq!(ran.document.summary.failed_steps, [1, 2, 3]);
    // The first set-up step reads a variable that nothing sets, so it cannot be run.
    let (_directory, root) = copy("setup-step");
    let ran = run(
        &root,
        &chain_of_set_up_steps("needs = ['KR_THAT_NOTHING_SETS']\n"),
    )
    .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let steps = &ran.document.steps;
    assert_eq!(
        steps[0].error.as_deref(),
        Some("KR_THAT_NOTHING_SETS is not set, and this step reads it")
    );
    assert_eq!(
        steps[1].error.as_deref(),
        Some(
            "not run because its set-up step 1 (the first set-up) could not be run or read: \
             KR_THAT_NOTHING_SETS is not set, and this step reads it"
        )
    );
    assert_eq!(ran.document.summary.failed_steps, [1, 2, 3]);
}

/// KR-REQ-29.01, the part about reproducible commands: a set-up step is not run twice in a run that
/// is one part, and a plan cut into parts gives each part the set-up steps its steps name.
#[test]
fn a_plan_run_in_parts_gives_each_part_the_set_up_step_its_steps_name() {
    let (_directory, root) = copy("setup-step");
    let plan = Plan::parse(&fixture_plan(&root, "0"), &root).expect("the fixture's plan loads");
    let steps = plan.steps(
        Platform::current(),
        &plan.all_groups(),
        &kr_conformance::plan_file::Values::evidence("/tmp/e"),
        None,
    );
    let ids = |part: (usize, usize)| -> Vec<String> {
        kr_conformance::plan::part_of(steps.clone(), part)
            .into_iter()
            .map(|step| step.id)
            .collect()
    };
    assert_eq!(ids((1, 2)), ["variables"]);
    assert_eq!(ids((2, 2)), ["make-the-file", "made"]);
    assert_eq!(ids((1, 1)), ["make-the-file", "variables", "made"]);
}

/// The text of a step of the plan `time-limits` runs on the platforms that can end a step's
/// processes: `limits` are its `timeout` and `budget` lines.
#[cfg(unix)]
fn timed_step(id: &str, reading: &str, command: &str, limits: &str) -> String {
    format!(
        "[[step]]\nid = '{id}'\ngroup = 'rust'\nwhat = 'the {id} step'\nplatforms = ['linux', 'macos']\nreading = '{reading}'\n{limits}\ncommand = [{command}]\n"
    )
}

/// A plan of one group whose `budgets` and `steps` are the text of the tables given.
#[cfg(unix)]
fn timed_plan(budgets: &str, steps: &[String]) -> String {
    plan_of(&["Cargo.toml"], &format!("{budgets}{}", steps.concat()))
}

/// The pids a fixture script recorded in `file`: `count` of them, when the step ran as far as the
/// case needs.
#[cfg(unix)]
fn recorded_pids(file: &Path, count: usize) -> Vec<String> {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    let pids: Vec<String> = text.lines().map(str::to_owned).collect();
    assert_eq!(
        pids.len(),
        count,
        "the step's processes did not all start before its time was spent: {text:?}"
    );
    pids
}

/// Whether the process `pid` exists: a process that has ended and is not reaped yet counts, which
/// its parent or the system's first process ends.
#[cfg(unix)]
fn alive(pid: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("kill -0 {pid} 2>/dev/null")])
        .status()
        .expect("a shell")
        .success()
}

/// The processes of `pids` that still exist `within` a time after the call, looked at every tenth of
/// a second. A case that fails ends them, so that it leaves none.
#[cfg(unix)]
fn left_after(pids: &[String], within: Duration) -> Vec<String> {
    let until = Instant::now() + within;
    loop {
        let left: Vec<String> = pids.iter().filter(|pid| alive(pid)).cloned().collect();
        if left.is_empty() || Instant::now() >= until {
            for pid in &left {
                let _ = Command::new("sh")
                    .args(["-c", &format!("kill -9 {pid} 2>/dev/null")])
                    .status();
            }
            return left;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// What a run of one step with a time limit that its tree outlasts must show: the step is failed
/// with the limit's words, its exit status is none, the run fails, the log says so, and no process
/// of what the step started is left.
#[cfg(unix)]
fn assert_ended_at_its_limit(ran: &Ran, seconds: u64, pids: &[String]) {
    let step = &ran.document.steps[0];
    let said = format!("ran out of its time limit: {seconds} s");
    assert_eq!(
        (step.exit, step.error.as_deref()),
        (None, Some(said.as_str())),
        "{step:?}"
    );
    // An order, with the slack a loaded host needs: the limit and the wait that ends the group, and
    // not the 300 seconds the step's processes wait for.
    assert!(
        step.seconds < seconds + 30,
        "the step ran {} s with a limit of {seconds} s",
        step.seconds
    );
    assert!(!ran.document.passed());
    assert_eq!(ran.document.summary.failed_steps, [1]);
    let log = std::fs::read_to_string(ran.evidence.path().join(&step.log)).expect("the log");
    assert!(log.contains(&format!("== {said}")), "{log}");
    let left = left_after(pids, Duration::from_secs(10));
    assert!(left.is_empty(), "processes of the step were left: {left:?}");
}

/// KR-REQ-29.01, the part about reproducible commands: a step whose time is spent is failed with
/// the limit in its error, and every process it started that is in its group ends, though each
/// ignores the signal that asks it to: the step's own, the child it starts and the child's own.
#[cfg(unix)]
#[test]
fn a_step_whose_processes_ignore_the_first_signal_is_ended_with_every_process_of_its_group() {
    let (_directory, root) = copy("time-limits");
    let place = tempfile::tempdir().expect("a directory for the pids");
    let pids = place.path().join("pids.txt");
    let command = format!("'bash', 'scripts/tree-root.sh', '{}'", pids.display());
    let text = timed_plan("", &[timed_step("tree", "build", &command, "timeout = 3")]);
    let ran = run(&root, &text).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let started = recorded_pids(&pids, 3);
    assert_ended_at_its_limit(&ran, 3, &started);
}

/// KR-REQ-29.01, the part about reproducible commands: the group is ended whether or not its leader
/// has gone: a step whose own process ends when it is asked to, and whose child ignores it, leaves
/// no process either.
#[cfg(unix)]
#[test]
fn a_leader_that_ends_when_asked_does_not_leave_the_process_of_its_group_that_ignored_it() {
    let (_directory, root) = copy("time-limits");
    let place = tempfile::tempdir().expect("a directory for the pids");
    let pids = place.path().join("pids.txt");
    let command = format!("'bash', 'scripts/leader-exits.sh', '{}'", pids.display());
    let text = timed_plan("", &[timed_step("tree", "build", &command, "timeout = 3")]);
    let ran = run(&root, &text).unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let started = recorded_pids(&pids, 3);
    assert_ended_at_its_limit(&ran, 3, &started);
}

/// A plan of one `cargo test` step of the fixture `time-limits`, with `limits`, and `env` as the
/// text of the inside of an inline table that adds to the step's variables. The step builds in
/// `target`, a directory of the case's own: Cargo holds a lock on its target directory while a
/// build waits, so two cases that build in one would wait for each other.
#[cfg(unix)]
fn cargo_plan(target: &Path, limits: &str, env: &str) -> String {
    timed_plan(
        "",
        &[timed_step(
            "cargo",
            "cargo",
            "'cargo', 'test', '--offline'",
            &format!(
                "{limits}\nenv = {{ CARGO_TARGET_DIR = '{}'{env} }}",
                target.display()
            ),
        )],
    )
}

/// KR-REQ-29.01, the part about reproducible commands: the step's time covers its build: a build
/// that does not end is ended at the limit, with the process the build started, and the step has no
/// tests. The fixture is built once without a limit first, so that the time the limit covers is
/// the wait and not the compile.
#[cfg(unix)]
#[test]
fn a_build_that_does_not_end_is_ended_at_the_steps_limit_with_the_process_it_started() {
    let (_directory, root) = copy("time-limits");
    let place = tempfile::tempdir().expect("a directory for the pids");
    let target = tempfile::tempdir().expect("a target directory");
    let pids = place.path().join("pids.txt");
    let warm = run(&root, &cargo_plan(target.path(), "", ""))
        .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    assert!(warm.document.passed(), "{:?}", warm.document.steps);
    let env = format!(", KR_BLOCK = 'build', KR_BLOCK_PIDS = '{}'", pids.display());
    let ran = run(&root, &cargo_plan(target.path(), "timeout = 8", &env))
        .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let started = recorded_pids(&pids, 1);
    assert_ended_at_its_limit(&ran, 8, &started);
}

/// KR-REQ-29.01, the part about reproducible commands: the step's time covers the listing of its
/// tests: a listing that does not end is ended at the limit, with the process it started, though
/// the build before it ended in time.
#[cfg(unix)]
#[test]
fn a_listing_that_does_not_end_is_ended_at_the_steps_limit_with_the_process_it_started() {
    let (_directory, root) = copy("time-limits");
    let place = tempfile::tempdir().expect("a directory for the pids");
    let target = tempfile::tempdir().expect("a target directory");
    let pids = place.path().join("pids.txt");
    let warm = run(&root, &cargo_plan(target.path(), "", ""))
        .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    assert!(warm.document.passed(), "{:?}", warm.document.steps);
    let env = format!(
        ", KR_BLOCK = 'listing', KR_BLOCK_PIDS = '{}'",
        pids.display()
    );
    let ran = run(&root, &cargo_plan(target.path(), "timeout = 8", &env))
        .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let started = recorded_pids(&pids, 1);
    assert_ended_at_its_limit(&ran, 8, &started);
}

/// KR-REQ-29.01, the part about reproducible commands: a step with a limit that ends in time is
/// read as one without: its build, its listing and its run each give what they give.
#[cfg(unix)]
#[test]
fn a_step_that_ends_in_its_time_is_read_as_a_step_without_a_limit() {
    let (_directory, root) = copy("time-limits");
    let target = tempfile::tempdir().expect("a target directory");
    let with = run(&root, &cargo_plan(target.path(), "timeout = 300", ""))
        .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    let without = run(&root, &cargo_plan(target.path(), "", ""))
        .unwrap_or_else(|stopped| panic!("{stopped:?}"));
    for (what, ran) in [("with", &with), ("without", &without)] {
        let step = &ran.document.steps[0];
        assert_eq!(
            (step.exit, step.error.as_deref()),
            (Some(0), None),
            "{what}: {step:?}"
        );
        assert!(ran.document.passed(), "{what}: {:?}", ran.document.problems);
    }
}
