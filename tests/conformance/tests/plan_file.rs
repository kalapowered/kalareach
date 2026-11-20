//! The plan file's loader: each way a file is refused, and what the loader accepts.

use std::path::{Path, PathBuf};

use kr_conformance::plan::Platform;
use kr_conformance::plan_file::Plan;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

const HEAD: &str = "repository = 'planted'
groups = ['rust']
[unrun]
bench = 'b'
typescript = 't'
[unrun.rust]
linux = 'l'
macos = 'm'
windows = 'w'
";

const STEP: &str = "[[step]]
id = 'one'
group = 'rust'
what = 'the first'
platforms = ['linux']
reading = 'cargo'
command = ['cargo', 'test']
";

fn with(extra: &str) -> String {
    format!("{HEAD}{extra}")
}

/// A step that differs from [`STEP`] in the lines `from` names, each replaced by `to`.
fn step_with(from: &str, to: &str) -> String {
    assert!(STEP.contains(from), "{from}");
    with(&STEP.replace(from, to))
}

/// The planted files: a name, the text, and the words the refusal holds, each in the order the
/// loader checks them. `Some(root)` is a root other than the repository.
fn faults() -> Vec<(&'static str, String, &'static str)> {
    vec![
        (
            "an unknown key at the top",
            with("bogus = 1\n"),
            "unknown field `bogus`",
        ),
        (
            "an unknown key in a step",
            format!("{}{STEP}bogus = 1\n", with("")),
            "unknown field `bogus`",
        ),
        (
            "an unknown key in a filter",
            format!(
                "{}{STEP}[step.filter]\nname = 'test'\nreason = 'r'\nbogus = 1\n",
                with("")
            ),
            "unknown field `bogus`",
        ),
        (
            "an unknown key in how an ignored test runs",
            with(
                "[[ignored_run]]\npackage = 'p'\ntarget = '--lib'\n[ignored_run.runs]\nkind = 'by_hand'\nwhy = 'w'\nbogus = 1\n",
            ),
            "unknown field `bogus`",
        ),
        (
            "a duplicate id",
            format!("{}{STEP}{STEP}", with("")),
            "the step id `one` is used twice",
        ),
        (
            "a group outside the plan's",
            step_with("group = 'rust'", "group = 'unit'"),
            "step `one` names the group `unit`, which the plan's groups do not hold",
        ),
        (
            "a platform outside the three",
            step_with("platforms = ['linux']", "platforms = ['solaris']"),
            "unknown variant `solaris`",
        ),
        (
            "a program outside the five",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['sh', '-c', 'true']",
            ),
            "step `one` runs `sh`, which is not one of cargo, pnpm, node, bash, python3",
        ),
        (
            "a script given by an absolute path",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['bash', '/bin/sh']",
            ),
            "step `one` runs the script `/bin/sh`, which is not a relative path",
        ),
        (
            "a script that leaves the repository",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['bash', '../x.sh']",
            ),
            "step `one` runs the script `../x.sh`, which holds `..`",
        ),
        (
            "a script that is not tracked",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['bash', '-e', 'scripts/not-a-script.sh']",
            ),
            "step `one` runs the script `scripts/not-a-script.sh`, which is not a tracked file of the repository",
        ),
        (
            "a placeholder outside the plan's",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['cargo', 'test', '--target-dir={scratch}/t']",
            ),
            "step `one` holds `{scratch}`, which is not a placeholder of the plan (evidence)",
        ),
        (
            "a brace that nothing closes",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['cargo', 'test', '{evidence']",
            ),
            "step `one` holds a `{` that no `}` closes, which is not a placeholder of the plan (evidence)",
        ),
        (
            "skips on a step that does not run cargo",
            format!(
                "{}[[step.skips]]\nname = 'a'\nreason = 'r'\n",
                step_with(
                    "command = ['cargo', 'test']",
                    "command = ['bash', 'scripts/android-unit-tests.sh']"
                )
            ),
            "step `one` has a filter or skips and does not run `cargo`",
        ),
        (
            "a filter on a step that does not run cargo",
            format!(
                "{}[step.filter]\nname = 'a'\nreason = 'r'\n",
                step_with(
                    "command = ['cargo', 'test']",
                    "command = ['bash', 'scripts/android-unit-tests.sh']"
                )
            ),
            "step `one` has a filter or skips and does not run `cargo`",
        ),
        (
            "a filter that is not a word of the command",
            format!(
                "{}{STEP}[step.filter]\nname = 'other'\nreason = 'r'\n",
                with("")
            ),
            "step `one` filters by `other`, which is not a word of its command",
        ),
        (
            "an ignored run missing a field of its kind",
            with(
                "[[ignored_run]]\npackage = 'p'\ntarget = '--lib'\n[ignored_run.runs]\nkind = 'command'\nfile = 'f'\n",
            ),
            "missing field `line`",
        ),
        (
            "a lane that names a group outside the plan's",
            with("[[lane]]\ngroup = 'phones'\nfiles = 'a/**'\nreason = 'r'\n"),
            "the lane `a/**` names the group `phones`, which the plan's groups do not hold",
        ),
        (
            "an absent group outside the plan's",
            with("[[group_absent]]\ngroup = 'phones'\nplatform = 'windows'\nreason = 'r'\n"),
            "a `[[group_absent]]` names the group `phones`, which the plan's groups do not hold",
        ),
        (
            "an absent group on a platform outside the three",
            with("[[group_absent]]\ngroup = 'rust'\nplatform = 'solaris'\nreason = 'r'\n"),
            "unknown variant `solaris`",
        ),
        (
            "an unrun reason that lacks a platform",
            with("").replace("windows = 'w'\n", ""),
            "missing field `windows`",
        ),
        (
            "TypeScript packages that are not a directory",
            with("[typescript]\npackages = ['packages/no-such-package']\n"),
            "`[typescript] packages` names `packages/no-such-package`, which is not a directory of the repository",
        ),
    ]
}

/// Each planted file is refused, with its own reason, and the same file with the fault taken out
/// loads. Run at the repository root, where the tracked-script rule has a Git tree to read.
#[test]
fn a_plan_file_is_refused_for_each_fault_by_its_reason() {
    let root = repository();
    let control = Plan::parse(&format!("{}{STEP}", with("")), &root);
    assert!(control.is_ok(), "the control file loads: {control:?}");
    for (name, text, reason) in faults() {
        let refused = match Plan::parse(&text, &root) {
            Ok(_) => panic!("the loader refused nothing for {name}"),
            Err(refusal) => refusal.to_string(),
        };
        assert!(
            refused.contains(reason),
            "{name}: refused as `{refused}`, which lacks `{reason}`"
        );
    }
}

/// A script that is a link is refused, and so is one that is tracked and is not a link (accepted).
#[test]
fn a_script_that_is_a_link_is_refused_and_a_tracked_one_is_accepted() {
    let directory = tempfile::tempdir().expect("a directory");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/bin/sh", directory.path().join("link.sh")).expect("a link");
        let text = step_with(
            "command = ['cargo', 'test']",
            "command = ['bash', 'link.sh']",
        );
        let refusal = Plan::parse(&text, directory.path()).expect_err("a link is refused");
        assert_eq!(
            refusal.0,
            "step `one` runs the script `link.sh`, which is a link"
        );
    }
    let tracked = step_with(
        "command = ['cargo', 'test']",
        "command = ['bash', 'scripts/android-unit-tests.sh', '--results={evidence}/x']",
    );
    assert!(Plan::parse(&tracked, &repository()).is_ok());
}

/// A plan with a step that reads vitest takes a package, and a lane a `lane`.
#[test]
fn a_reading_takes_the_fields_it_needs_and_no_others() {
    let root = repository();
    let vitest = step_with("reading = 'cargo'", "reading = 'vitest'");
    let refusal = Plan::parse(&vitest, &root).expect_err("a vitest step names a package");
    assert_eq!(
        refusal.0,
        "step `one` reads vitest and takes a `package` and no `lane`"
    );
    let named = step_with("reading = 'cargo'", "reading = 'cargo'\npackage = 'x'");
    let refusal = Plan::parse(&named, &root).expect_err("a cargo step names no package");
    assert_eq!(
        refusal.0,
        "step `one` takes no `package` or `lane`: its reading does not"
    );
}

/// A step is selected by its platform and its group, in the plan's own order.
#[test]
fn the_steps_are_the_plans_in_its_own_order_for_a_platform_and_a_selection() {
    let two = format!(
        "{}{STEP}{}",
        with(""),
        STEP.replace("'one'", "'two'")
            .replace("['linux']", "['linux', 'macos']")
    );
    let plan = Plan::parse(&two, &repository()).expect("a plan of two steps");
    let rust = vec!["rust".to_owned()];
    let linux = plan.steps(Platform::Linux, &rust, "/tmp/e", None);
    assert_eq!(linux.len(), 2);
    assert_eq!(plan.steps(Platform::MacOs, &rust, "/tmp/e", None).len(), 1);
    assert!(
        plan.steps(Platform::Windows, &rust, "/tmp/e", None)
            .is_empty()
    );
    assert!(plan.steps(Platform::Linux, &[], "/tmp/e", None).is_empty());
}

/// Runs the program with `arguments` and returns its exit code and what it wrote to stderr.
fn program(arguments: &[&str]) -> (Option<i32>, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kr-conformance"))
        .args(arguments)
        .output()
        .expect("the program runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// A root with no plan file is refused with exit status 2 and the reason, and nothing is mapped:
/// the program never falls back to another plan.
#[test]
fn a_root_with_no_plan_file_is_refused_with_exit_2() {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path().to_string_lossy().into_owned();
    for command in ["map", "run"] {
        let mut arguments = vec![command, "--root", root.as_str()];
        if command == "run" {
            arguments.extend(["--evidence", "/tmp/kr-no-such-evidence"]);
        }
        let (code, stderr) = program(&arguments);
        assert_eq!(code, Some(2), "{command}: {stderr}");
        assert!(
            stderr.contains("kr-conformance: refused: the plan ")
                && stderr.contains("could not be read")
                && stderr.contains("--plan"),
            "{command}: {stderr}"
        );
    }
    let (code, stderr) = program(&[
        "map",
        "--root",
        root.as_str(),
        "--plan",
        "/no/such/plan.toml",
    ]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("/no/such/plan.toml could not be read"),
        "{stderr}"
    );
}

/// Each planted fault of the table is exit status 2 from the program, before anything runs, with
/// the plan's path and the fault's own reason.
#[test]
fn a_plan_named_by_the_option_is_refused_with_exit_2_for_each_fault() {
    let directory = tempfile::tempdir().expect("a directory");
    let root = repository();
    let root = root.to_string_lossy();
    for (index, (name, text, reason)) in faults().into_iter().enumerate() {
        let file = directory.path().join(format!("plan-{index}.toml"));
        std::fs::write(&file, text).expect("the planted file");
        let file = file.to_string_lossy().into_owned();
        let (code, stderr) = program(&["map", "--root", &root, "--plan", &file]);
        assert_eq!(code, Some(2), "{name}: {stderr}");
        assert!(
            stderr.contains("kr-conformance: refused: the plan ")
                && stderr.contains(&file)
                && stderr.contains(reason),
            "{name}: {stderr}"
        );
    }
}

/// A group the plan does not have is refused after the plan is read, with the groups it has.
#[test]
fn a_group_the_plan_does_not_have_is_refused_with_exit_2() {
    let root = repository();
    let root = root.to_string_lossy();
    let (code, stderr) = program(&[
        "run",
        "--root",
        &root,
        "--evidence",
        "/tmp/kr-no-such-evidence",
        "--group",
        "bogus",
    ]);
    assert_eq!(code, Some(2), "{stderr}");
    assert!(
        stderr.contains("--group bogus is not a group of the plan; it has rust, end-to-end"),
        "{stderr}"
    );
}

/// No constant or static of the plan or the report holds a step, a table row or a reason, and the
/// code names none of the groups that carry behaviour: the plan file is the one place for both.
#[test]
fn the_tables_are_not_in_the_code() {
    // The names of two variables, the schema's version, and the two `const fn` of `Platform`.
    let kept = [
        "SECRET_STORE_VARIABLE",
        "APPLICATIONS_VARIABLE",
        "SCHEMA",
        "current",
        "name",
    ];
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for file in ["plan.rs", "report.rs"] {
        let text = std::fs::read_to_string(source.join(file)).expect("the source");
        for (index, line) in text.lines().enumerate() {
            let words: Vec<&str> = line
                .trim_start()
                .trim_start_matches("pub ")
                .split_whitespace()
                .collect();
            let (Some(&("const" | "static")), rest) = (words.first(), &words[1.min(words.len())..])
            else {
                continue;
            };
            let name = rest
                .iter()
                .find(|word| **word != "fn")
                .and_then(|word| word.split([':', '(', '<']).next())
                .unwrap_or_default();
            if !kept.contains(&name) {
                found.push(format!(
                    "src/{file}:{}: `{name}` is a table in the code",
                    index + 1
                ));
            }
        }
    }
    for entry in std::fs::read_dir(&source).expect("the sources") {
        let path = entry.expect("an entry").path();
        let text = std::fs::read_to_string(&path).expect("the source");
        for (index, line) in text.lines().enumerate() {
            for group in ["TypeScript", "Phones", "EndToEnd", "Performance"] {
                if line.contains(&format!("Group::{group}")) && !line.trim_start().starts_with("//")
                {
                    found.push(format!(
                        "{}:{}: names the group `{group}`",
                        path.display(),
                        index + 1
                    ));
                }
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}
