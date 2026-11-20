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
