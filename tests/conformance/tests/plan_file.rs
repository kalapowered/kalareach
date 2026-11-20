//! The plan file's loader: each way a file is refused, and what the loader accepts.

use std::path::{Path, PathBuf};

use kr_conformance::plan::{Platform, Step};
use kr_conformance::plan_file::Plan;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Core's own plan file.
fn core_plan() -> Plan {
    Plan::load(&repository(), None).expect("core's plan file")
}

fn selection(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
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
/// loader checks them.
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
            "a script that is not there",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['bash', '-e', 'scripts/not-a-script.sh']",
            ),
            "step `one` runs the script `scripts/not-a-script.sh`, which does not exist",
        ),
        (
            "a script that is a directory of tracked files",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['bash', 'scripts']",
            ),
            "step `one` runs the script `scripts`, which is not a regular file",
        ),
        (
            "a script that is a wildcard of tracked files",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['bash', 'scripts/*.sh']",
            ),
            "step `one` runs the script `scripts/*.sh`, which does not exist",
        ),
        (
            "a script spelled other than the index holds it",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['bash', './scripts/android-unit-tests.sh']",
            ),
            "step `one` runs the script `./scripts/android-unit-tests.sh`, which is not spelled the way the repository's index holds it (`scripts/android-unit-tests.sh`)",
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
    let mut wrong = Vec::new();
    for (name, text, reason) in faults() {
        match Plan::parse(&text, &root) {
            Ok(_) => wrong.push(format!("{name}: the loader refused nothing")),
            Err(refusal) if refusal.to_string().contains(reason) => {}
            Err(refusal) => wrong.push(format!(
                "{name}: refused as `{refusal}`, which lacks `{reason}`"
            )),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A script that is a link is refused, and so is one that is tracked and is not a link (accepted).
#[test]
fn a_script_that_is_a_link_is_refused_and_a_tracked_one_is_accepted() {
    #[cfg(unix)]
    {
        let directory = tempfile::tempdir().expect("a directory");
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

/// Runs `git` in `root`.
fn git(root: &Path, arguments: &[&str]) {
    let status = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .status()
        .expect("git runs");
    assert!(status.success(), "git {arguments:?}: {status}");
}

/// A repository of its own whose index holds `tracked.sh` and `gone.sh`, with `gone.sh` removed
/// from the tree, `untracked.sh` beside them and, where a name may hold `*`, a file named `*.sh`
/// that the index does not hold.
fn planted_repository() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path();
    for name in ["tracked.sh", "gone.sh", "untracked.sh"] {
        std::fs::write(root.join(name), "").expect("a file");
    }
    git(root, &["init", "-q"]);
    git(root, &["add", "tracked.sh", "gone.sh"]);
    std::fs::remove_file(root.join("gone.sh")).expect("the file is removed from the tree");
    #[cfg(unix)]
    std::fs::write(root.join("*.sh"), "").expect("a file named as a wildcard");
    directory
}

/// A script is a regular file that the index of the repository holds under exactly that name: not
/// a file the index lacks, not one that the tree has lost, and not a name that Git reads as a
/// pattern that matches tracked files. A file that the index holds loads. Each refusal is exit
/// status 2 from the program, with the script's own reason.
#[test]
fn a_script_must_be_a_regular_file_that_the_index_holds_under_that_name() {
    let repository = planted_repository();
    let root = repository.path();
    let scripts = tempfile::tempdir().expect("a directory");
    let mut refusals = vec![
        ("untracked.sh", "is not a tracked file of the repository"),
        ("gone.sh", "does not exist"),
    ];
    if cfg!(unix) {
        refusals.push(("*.sh", "is not a tracked file of the repository"));
    }
    let command = |operand: &str| {
        step_with(
            "command = ['cargo', 'test']",
            &format!("command = ['bash', '{operand}']"),
        )
    };
    let control = Plan::parse(&command("tracked.sh"), root);
    assert!(control.is_ok(), "a tracked file loads: {control:?}");
    let mut wrong = Vec::new();
    for (index, (operand, why)) in refusals.into_iter().enumerate() {
        let expected = format!("step `one` runs the script `{operand}`, which {why}");
        match Plan::parse(&command(operand), root) {
            Ok(_) => wrong.push(format!("{operand}: the loader refused nothing")),
            Err(refusal) if refusal.0 == expected => {}
            Err(refusal) => wrong.push(format!("{operand}: refused as `{refusal}`")),
        }
        let file = scripts.path().join(format!("plan-{index}.toml"));
        std::fs::write(&file, command(operand)).expect("the planted file");
        let (code, stderr) = program(&[
            "map",
            "--root",
            &root.to_string_lossy(),
            "--plan",
            &file.to_string_lossy(),
        ]);
        if code != Some(2) || !stderr.contains(&expected) {
            wrong.push(format!("{operand}: exit {code:?}, stderr `{stderr}`"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A root that Git cannot read is not taken for a root without the script: the loader says that it
/// cannot check the script, with the first line of what Git wrote.
#[test]
fn a_script_is_not_checked_in_a_root_that_git_cannot_read() {
    let directory = tempfile::tempdir().expect("a directory");
    std::fs::write(directory.path().join("x.sh"), "").expect("a file");
    let text = step_with("command = ['cargo', 'test']", "command = ['bash', 'x.sh']");
    let refusal = Plan::parse(&text, directory.path()).expect_err("git cannot read the root");
    assert!(
        refusal.0.starts_with(
            "step `one` runs the script `x.sh`, which cannot be checked: git ended with status 128: fatal: "
        ),
        "{refusal}"
    );
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

/// A plan option with no path is a usage error with exit status 2 and its own reason, before the
/// map is built or anything runs: the program does not take the repository's own plan instead.
#[test]
fn a_plan_option_without_a_path_is_a_usage_error_for_map_and_run() {
    let repository = tempfile::tempdir().expect("a directory");
    let evidence = tempfile::tempdir().expect("a directory");
    std::fs::create_dir(repository.path().join("conformance")).expect("a directory");
    let default_plan = with(
        "[[step]]\nid = 'version'\ngroup = 'rust'\nwhat = 'the version'\n\
         platforms = ['linux', 'macos', 'windows']\nreading = 'build'\ncommand = ['cargo', '--version']\n",
    );
    std::fs::write(
        repository.path().join("conformance/plan.toml"),
        default_plan,
    )
    .expect("the repository's own plan");
    let root = repository.path().to_string_lossy().into_owned();
    let evidence_path = evidence.path().to_string_lossy().into_owned();
    for arguments in [
        vec!["map", "--root", root.as_str(), "--plan"],
        vec![
            "run",
            "--root",
            root.as_str(),
            "--group",
            "rust",
            "--evidence",
            evidence_path.as_str(),
            "--plan",
        ],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_kr-conformance"))
            .args(&arguments)
            .output()
            .expect("the program runs");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}: {stderr}");
        assert!(
            stderr.starts_with("kr-conformance: --plan takes the path of a plan file\n"),
            "{arguments:?}: {stderr}"
        );
        assert!(output.stdout.is_empty(), "{arguments:?}: something ran");
        assert_eq!(
            std::fs::read_dir(evidence.path())
                .expect("the evidence")
                .count(),
            0,
            "{arguments:?}: something was written"
        );
    }
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

/// What each selection of core's groups decides: whether the run reads TypeScript, selects the
/// phone lanes' places, needs the applications, records Node and pnpm, gives the Windows reason for
/// an unrun Rust target, and says why a TypeScript test is not run.
#[test]
fn every_decision_a_group_takes_is_what_core_s_file_says() {
    let plan = core_plan();
    let tests_of_a_phone_lane = "apps/companion/native/ios/Tests/A.swift";
    let every = [
        "rust",
        "end-to-end",
        "performance",
        "typescript",
        "applications",
        "phones",
    ];
    for (names, typescript, phones, applications) in [
        (vec![], false, false, false),
        (vec!["rust"], false, false, false),
        (vec!["end-to-end", "performance"], false, false, false),
        (vec!["typescript"], true, false, false),
        (vec!["phones"], false, true, false),
        (vec!["applications"], false, false, true),
        (vec!["rust", "typescript", "phones"], true, true, false),
        (every.to_vec(), true, true, true),
    ] {
        let groups = selection(&names);
        assert_eq!(plan.reads_typescript(&groups), typescript, "{names:?}");
        assert_eq!(
            plan.selects_lane_file(&groups, tests_of_a_phone_lane),
            phones,
            "{names:?}"
        );
        assert_eq!(
            plan.selects_applications(&groups),
            applications,
            "{names:?}"
        );
        for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
            let unix = platform != Platform::Windows;
            assert_eq!(
                plan.uses_javascript_tools(platform, &groups),
                typescript && unix,
                "{platform:?} {names:?}"
            );
            assert_eq!(
                plan.runs_applications(platform, &groups),
                applications && unix,
                "{platform:?} {names:?}"
            );
        }
    }
    let unix_only = "the end-to-end suites and the measurements drive Unix pseudo-terminals; on Windows the pseudo-console is qualified on the Windows test machine";
    for names in [
        &["end-to-end"][..],
        &["performance"],
        &["end-to-end", "rust"],
    ] {
        let groups = selection(names);
        assert_eq!(
            plan.unrun_rust_reason(Platform::Windows, &groups),
            Some(unix_only),
            "{names:?}"
        );
        assert_eq!(plan.unrun_rust_reason(Platform::Linux, &groups), None);
        assert_eq!(plan.unrun_rust_reason(Platform::MacOs, &groups), None);
    }
    assert_eq!(
        plan.unrun_rust_reason(Platform::Windows, &selection(&["rust", "typescript"])),
        None
    );
    let typescript = selection(&["typescript"]);
    assert_eq!(
        plan.typescript_unrun_reason(Platform::Windows, &typescript),
        "the TypeScript suites are qualified on Linux and macOS"
    );
    assert_eq!(
        plan.typescript_unrun_reason(Platform::Linux, &typescript),
        "no step of this run's selection runs the TypeScript suites"
    );
    // A plan whose groups carry other names reads TypeScript wherever it has a vitest step.
    let planted = r"
repository = 'planted'
groups = ['unit', 'browsers', 'node']
[unrun]
bench = 'b'
typescript = 't'
[unrun.rust]
linux = 'l'
macos = 'm'
windows = 'w'
[[step]]
id = 'unit-tests'
group = 'unit'
what = 'the unit tests'
platforms = ['linux']
reading = 'vitest'
package = '.'
command = ['pnpm', 'run', 'test']
[[step]]
id = 'build'
group = 'node'
what = 'a build'
platforms = ['linux']
reading = 'build'
command = ['cargo', 'build']
";
    let plan = Plan::parse(planted, &repository()).expect("the planted plan loads");
    let unit = selection(&["unit"]);
    let others = selection(&["browsers", "node"]);
    assert!(plan.reads_typescript(&unit));
    assert!(!plan.reads_typescript(&others));
    assert!(plan.uses_javascript_tools(Platform::Linux, &unit));
    assert!(!plan.uses_javascript_tools(Platform::Windows, &unit));
    assert!(!plan.uses_javascript_tools(Platform::Linux, &others));
}

/// The words each way a command is expanded gives: a captured test output, an uncaptured one, a
/// command that already shows its output, the skips of a step, the one raw skip of the Windows
/// startup step, and a build.
#[test]
fn the_one_expansion_rule_gives_the_words_the_steps_are_run_with() {
    let plan = core_plan();
    // Captured: the Linux workspace step. Raw skip: the Windows startup step. Uncaptured: a
    // measurement. Structured skips: the macOS workspace step. Build: the end-to-end build.
    for (platform, group, line) in [
        (
            Platform::Linux,
            "rust",
            "cargo test --locked --workspace --no-fail-fast -- --show-output",
        ),
        (
            Platform::Windows,
            "rust",
            "--test startup_windows -- --ignored --skip a_task_the_task_scheduler_does_not_start --show-output",
        ),
        (
            Platform::Linux,
            "performance",
            "-- --ignored --exact --nocapture attach_to_a_usable_screen",
        ),
        (
            Platform::MacOs,
            "rust",
            "--no-fail-fast -- --show-output --skip the_helper_inside_a_container",
        ),
        (
            Platform::Linux,
            "end-to-end",
            "cargo build --locked -p kr-worker --bin kr-worker",
        ),
    ] {
        let lines: Vec<String> = plan
            .steps(platform, &selection(&[group]), "/tmp/e", None)
            .iter()
            .map(Step::line)
            .collect();
        assert!(
            lines.iter().any(|candidate| candidate.contains(line)),
            "{platform:?} {group}: {line}"
        );
    }
    // A command that already holds `--show-output` or `--nocapture` is left as it is.
    let planted = format!(
        "{HEAD}[[step]]
id = 'shown'
group = 'rust'
what = 'shown already'
platforms = ['linux']
reading = 'cargo'
command = ['cargo', 'test', '--', '--show-output']
[[step]]
id = 'live'
group = 'rust'
what = 'uncaptured'
platforms = ['linux']
reading = 'cargo'
command = ['cargo', 'test', '--', '--nocapture']
[[step]]
id = 'plain'
group = 'rust'
what = 'a plain one'
platforms = ['linux']
reading = 'cargo'
command = ['cargo', 'test']
"
    );
    let plan = Plan::parse(&planted, &repository()).expect("the planted plan loads");
    let lines: Vec<String> = plan
        .steps(Platform::Linux, &selection(&["rust"]), "/tmp/e", None)
        .iter()
        .map(Step::line)
        .collect();
    assert_eq!(
        lines,
        [
            "cargo test -- --show-output",
            "cargo test -- --nocapture",
            "cargo test -- --show-output"
        ]
    );
}
