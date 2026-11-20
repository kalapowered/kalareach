//! The plan file's loader: each way a file is refused, and what the loader accepts.

use std::path::{Path, PathBuf};

use kr_conformance::plan::{Platform, Step};
use kr_conformance::plan_file::{Plan, Values};

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
[rust]
manifests = ['Cargo.toml']
[ignored_runs]
held = false
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
            format!("bogus = 1\n{}", with("")),
            "unknown field `bogus`",
        ),
        (
            "an unknown key among the unrun reasons",
            with("").replacen("[unrun.rust]", "bogus = 'x'\n[unrun.rust]", 1),
            "unknown field `bogus`",
        ),
        (
            "an unknown key among the unrun reasons of Rust",
            with("bogus = 'x'\n"),
            "unknown field `bogus`",
        ),
        (
            "an unknown key in an excluded package",
            with(
                "[[excluded_package]]\nplatform = 'linux'\npackage = 'p'\nreason = 'r'\nbogus = 1\n",
            ),
            "unknown field `bogus`",
        ),
        (
            "an unknown key in an absent group",
            with(
                "[[group_absent]]\ngroup = 'rust'\nplatform = 'windows'\nreason = 'r'\nbogus = 1\n",
            ),
            "unknown field `bogus`",
        ),
        (
            "an unknown key in a case table",
            with(
                "[[case_table]]\nfiles = 'f'\npackage = 'p'\ntarget = 't'\ntests = ['a']\nbogus = 1\n",
            ),
            "unknown field `bogus`",
        ),
        (
            "an unknown key in an ignored run",
            with(
                "[[ignored_run]]\npackage = 'p'\ntarget = '--lib'\nbogus = 1\n[ignored_run.runs]\nkind = 'by_hand'\nwhy = 'w'\n",
            ),
            "unknown field `bogus`",
        ),
        (
            "an unknown key in a lane",
            with("[[lane]]\nfiles = 'a/**'\nreason = 'r'\nbogus = 1\n"),
            "unknown field `bogus`",
        ),
        (
            "an unknown key among the terminals",
            with("[terminals]\nnames = ['a']\nreason = 'r'\nbogus = 1\n"),
            "unknown field `bogus`",
        ),
        (
            "an unknown key among the TypeScript packages",
            with("[typescript]\npackages = []\nbogus = 1\n"),
            "unknown field `bogus`",
        ),
        (
            "an unknown key among the applications",
            with("[applications]\nlock = 'l'\nbogus = 1\n"),
            "unknown field `bogus`",
        ),
        (
            "a step that names no platform",
            step_with("platforms = ['linux']", "platforms = []"),
            "step `one` names no platform",
        ),
        (
            "a step with an empty command",
            step_with("command = ['cargo', 'test']", "command = []"),
            "step `one` has an empty command",
        ),
        (
            "a lane reading that takes no lane",
            step_with("reading = 'cargo'", "reading = 'lane'"),
            "step `one` reads a lane and takes a `lane` and no `package`",
        ),
        (
            "skips from the applications in a plan that has none",
            step_with(
                "reading = 'cargo'",
                "reading = 'cargo'\nskips_from = 'applications'",
            ),
            "step `one` skips from the applications and the plan has no `[applications]`",
        ),
        (
            "an unrun reason of Rust that says nothing",
            with("").replace("linux = 'l'", "linux = ''"),
            "`[unrun]` has no `rust.linux` reason",
        ),
        (
            "an unrun reason of Rust on macOS that says nothing",
            with("").replace("macos = 'm'", "macos = ''"),
            "`[unrun]` has no `rust.macos` reason",
        ),
        (
            "an unrun reason of Rust on Windows that is blank",
            with("").replace("windows = 'w'", "windows = ' '"),
            "`[unrun]` has no `rust.windows` reason",
        ),
        (
            "an unrun reason of the benchmarks that is blank",
            with("").replace("bench = 'b'", "bench = '  '"),
            "`[unrun]` has no `bench` reason",
        ),
        (
            "an unrun reason of TypeScript that says nothing",
            with("").replace("typescript = 't'", "typescript = ''"),
            "`[unrun]` has no `typescript` reason",
        ),
        (
            "a filter with no reason",
            format!(
                "{}{STEP}[step.filter]\nname = 'test'\nreason = ''\n",
                with("")
            ),
            "step `one` filters with no reason",
        ),
        (
            "a skip with no reason",
            format!(
                "{}{STEP}[[step.skips]]\nname = 'a'\nreason = ' '\n",
                with("")
            ),
            "step `one` skips `a` with no reason",
        ),
        (
            "an excluded package with no reason",
            with("[[excluded_package]]\nplatform = 'linux'\npackage = 'p'\nreason = ''\n"),
            "an `[[excluded_package]]` for `p` has no reason",
        ),
        (
            "an absent group with no reason",
            with("[[group_absent]]\ngroup = 'rust'\nplatform = 'windows'\nreason = ''\n"),
            "a `[[group_absent]]` for the group `rust` has no reason",
        ),
        (
            "a lane with no reason",
            with("[[lane]]\nfiles = 'a/**'\nreason = ' '\n"),
            "the lane `a/**` has no reason",
        ),
        (
            "terminals with no reason",
            with("[terminals]\nnames = ['a']\nreason = ''\n"),
            "`[terminals]` has no reason",
        ),
        (
            "an ignored run by hand that says not why",
            with(
                "[[ignored_run]]\npackage = 'p'\ntarget = '--lib'\n[ignored_run.runs]\nkind = 'by_hand'\nwhy = ''\n",
            ),
            "the `[[ignored_run]]` of `p` `--lib` has no `why`",
        ),
        (
            "an ignored run of nothing that says not why",
            with(
                "[[ignored_run]]\npackage = 'p'\ntarget = '--lib'\n[ignored_run.runs]\nkind = 'nowhere'\nwhy = ''\n",
            ),
            "the `[[ignored_run]]` of `p` `--lib` has no `why`",
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
            "step `one` runs the script `scripts/*.sh`, which holds a pattern character",
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
            "a command that holds the word the loader adds",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['cargo', 'test', '--', '--show-output']",
            ),
            "step `one` holds `--show-output`, which the loader adds and a plan file does not write",
        ),
        (
            "a command that shows its output as it is written and holds the word the loader adds",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['cargo', 'test', '--', '--nocapture', '--show-output']",
            ),
            "step `one` holds `--show-output`, which the loader adds and a plan file does not write",
        ),
        (
            "a placeholder outside the plan's",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['cargo', 'test', '--target-dir={nothing}/t']",
            ),
            "step `one` holds `{nothing}`, which is not a placeholder of the plan (evidence, scratch, root, output)",
        ),
        (
            "a brace that nothing closes",
            step_with(
                "command = ['cargo', 'test']",
                "command = ['cargo', 'test', '{evidence']",
            ),
            "step `one` holds a `{` that no `}` closes, which is not a placeholder of the plan (evidence, scratch, root, output)",
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
            "a plan with no `[rust]` table",
            with("").replace("[rust]\nmanifests = ['Cargo.toml']\n", ""),
            "missing field `rust`",
        ),
        (
            "a `[rust]` table with no manifests",
            with("").replace("manifests = ['Cargo.toml']\n", ""),
            "missing field `manifests`",
        ),
        (
            "a plan with no `[ignored_runs]` table",
            with("").replace("[ignored_runs]\nheld = false\n", ""),
            "missing field `ignored_runs`",
        ),
        (
            "an `[ignored_runs]` table with no `held`",
            with("").replace("held = false\n", ""),
            "missing field `held`",
        ),
        (
            "an unrun reason that lacks a platform",
            with("").replace("windows = 'w'\n", ""),
            "missing field `windows`",
        ),
        (
            "a manifest named twice",
            with("").replace(
                "manifests = ['Cargo.toml']",
                "manifests = ['Cargo.toml', 'Cargo.toml']",
            ),
            "`[rust] manifests` names `Cargo.toml` twice",
        ),
        (
            "a manifest named twice by another spelling",
            with("").replace(
                "manifests = ['Cargo.toml']",
                "manifests = ['Cargo.toml', './Cargo.toml']",
            ),
            "`[rust] manifests` names `./Cargo.toml` twice",
        ),
        (
            "a directory left out that is a path",
            with("[typescript]\npackages = []\nskip_directories = ['web/generated']\n"),
            "`[typescript] skip_directories` names `web/generated`, which is not the name of one directory",
        ),
        (
            "a directory left out that is a path with backslashes",
            with("[typescript]\npackages = []\nskip_directories = ['web\\generated']\n"),
            "`[typescript] skip_directories` names `web\\generated`, which is not the name of one directory",
        ),
        (
            "a directory left out that has no name",
            with("[typescript]\npackages = []\nskip_directories = ['']\n"),
            "`[typescript] skip_directories` names ``, which is not the name of one directory",
        ),
        (
            "a `[typescript]` table with no packages",
            with("[typescript]\ncompiler_from = []\n"),
            "missing field `packages`",
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

/// A plan that names `operand` under `key`, with a step so that its group is used.
fn naming(key: &str, operand: &str) -> String {
    let top = |line: &str| {
        HEAD.replacen(
            "groups = ['rust']\n",
            &format!("groups = ['rust']\n{line}\n"),
            1,
        )
    };
    let text = match key {
        "scripts" | "lane_directories" => top(&format!("{key} = ['{operand}']")),
        "[rust] manifests" => HEAD.replace(
            "manifests = ['Cargo.toml']",
            &format!("manifests = ['{operand}']"),
        ),
        "[terminal_profile] path" => with(&format!("[terminal_profile]\npath = '{operand}'\n")),
        "[typescript] packages" => with(&format!("[typescript]\npackages = ['{operand}']\n")),
        "[typescript] compiler_from" => with(&format!(
            "[typescript]\npackages = []\ncompiler_from = ['{operand}']\n"
        )),
        _ => unreachable!("{key}"),
    };
    // The step runs no `cargo`, so that a manifest the key names is not held to be a root.
    format!(
        "{text}{}",
        STEP.replace("command = ['cargo', 'test']", "command = ['pnpm', 'test']")
    )
}

/// A repository of its own that holds a `Cargo.toml`, `dir/file.txt` and `dir/sub`, and, where a
/// link can be made,
/// `dirlink` (to a directory elsewhere), `insidelink` (to `dir`) and `filelink` (to `dir/file.txt`);
/// and, elsewhere, `sub` and `file.txt`.
fn tree_with_links() -> (tempfile::TempDir, tempfile::TempDir) {
    let repository = tempfile::tempdir().expect("a directory");
    let elsewhere = tempfile::tempdir().expect("a directory");
    std::fs::write(repository.path().join("Cargo.toml"), "").expect("a manifest");
    std::fs::create_dir_all(repository.path().join("dir").join("sub")).expect("a directory");
    std::fs::write(repository.path().join("dir").join("file.txt"), "").expect("a file");
    std::fs::create_dir_all(elsewhere.path().join("sub")).expect("a directory");
    std::fs::write(elsewhere.path().join("file.txt"), "").expect("a file");
    #[cfg(unix)]
    {
        let link = |target: &Path, name: &str| {
            std::os::unix::fs::symlink(target, repository.path().join(name)).expect("a link");
        };
        link(elsewhere.path(), "dirlink");
        link(Path::new("dir"), "insidelink");
        link(Path::new("dir/file.txt"), "filelink");
    }
    (repository, elsewhere)
}

/// Each key of the plan that names a path of the repository is refused with its own reason for each
/// way a path goes wrong: it is absent, it is the other kind of place, it is absolute, it holds
/// `..` or a pattern character, it is a link, or a link on its way leads out of the repository. A
/// path that a link inside the repository reaches inside it is accepted.
#[test]
fn a_key_that_names_a_path_is_refused_with_its_reason_for_each_way_a_path_goes_wrong() {
    let (repository, _elsewhere) = tree_with_links();
    let root = repository.path();
    let directory_keys = [
        "scripts",
        "lane_directories",
        "[typescript] packages",
        "[typescript] compiler_from",
    ];
    let file_keys = ["[rust] manifests", "[terminal_profile] path"];
    let mut wrong = Vec::new();
    let mut check = |key: &str, operand: &str, why: Option<&str>| {
        let outcome = Plan::parse(&naming(key, operand), root);
        let key_name = key.rsplit_once(' ').map_or(key, |(_, name)| name);
        match (why, outcome) {
            (None, Ok(_)) => {}
            (None, Err(refusal)) => {
                wrong.push(format!("{key} `{operand}`: refused as `{refusal}`"));
            }
            (Some(why), Ok(_)) => {
                wrong.push(format!("{key} `{operand}`: nothing refused, wanted {why}"));
            }
            (Some(why), Err(refusal)) => {
                let wanted = format!("names `{operand}`, which {why}");
                if !(refusal.0.contains(&wanted) && refusal.0.contains(key_name)) {
                    wrong.push(format!(
                        "{key} `{operand}`: refused as `{refusal}`, wanted {why}"
                    ));
                }
            }
        }
    };
    // The ways a path goes wrong in the text, and the two that depend on what the key names: a
    // path that is absent, and a path that is the other kind of place.
    let ways = |absent: (&str, &'static str), other_kind: (&str, &'static str)| {
        vec![
            (String::new(), "is empty"),
            (absent.0.to_owned(), absent.1),
            (other_kind.0.to_owned(), other_kind.1),
            ("/dir".to_owned(), "is not a relative path"),
            ("dir\\x".to_owned(), "is not a relative path"),
            ("dir/../dir".to_owned(), "holds `..`"),
            ("d*r".to_owned(), "holds a pattern character"),
            ("d?r".to_owned(), "holds a pattern character"),
            ("[dir".to_owned(), "holds a pattern character"),
            ("dir]".to_owned(), "holds a pattern character"),
        ]
    };
    for key in directory_keys {
        check(key, "dir", None);
        let not_a_directory = "is not a directory of the repository";
        for (operand, why) in ways(
            ("missing", not_a_directory),
            ("dir/file.txt", not_a_directory),
        ) {
            check(key, &operand, Some(why));
        }
        #[cfg(unix)]
        {
            check(key, "dirlink", Some("is a link"));
            check(key, "insidelink", Some("is a link"));
            check(
                key,
                "dirlink/sub",
                Some("leads out of the repository through a link"),
            );
            check(key, "insidelink/sub", None);
        }
    }
    for key in file_keys {
        check(key, "dir/file.txt", None);
        for (operand, why) in ways(
            ("dir/missing.txt", "does not exist"),
            ("dir", "is not a regular file"),
        ) {
            check(key, &operand, Some(why));
        }
        #[cfg(unix)]
        {
            check(key, "filelink", Some("is a link"));
            check(
                key,
                "dirlink/file.txt",
                Some("leads out of the repository through a link"),
            );
            check(key, "insidelink/file.txt", None);
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The values a run gives the placeholders are put in as they are written: a value that holds the
/// text of a placeholder is not expanded again, whatever the order the placeholders come in.
#[test]
fn a_value_that_holds_the_text_of_a_placeholder_is_put_in_as_it_is_written() {
    let text = with(&STEP.replace(
        "command = ['cargo', 'test']",
        "env = { HERE = '{root}|{scratch}|{evidence}' }\ncommand = ['cargo', 'test', '{evidence}']",
    ));
    let plan = Plan::parse(&text, &repository()).expect("the plan loads");
    let values = Values {
        evidence: "/e/{root}",
        root: "/r/{scratch}",
        scratch: "/s/{evidence}",
    };
    let steps = plan.steps(Platform::Linux, &selection(&["rust"]), &values, None);
    assert_eq!(steps[0].command[2], "/e/{root}");
    assert_eq!(
        steps[0].env,
        [(
            "HERE".to_owned(),
            "/r/{scratch}|/s/{evidence}|/e/{root}".to_owned()
        )]
    );
}

/// A step's variable replaces the plan's of the same name, and the same name is what the platform
/// the step is expanded for takes as one: Windows takes names that differ only by case as one
/// variable, so there the step's `PATH` replaces the plan's `Path`; elsewhere they are two.
#[test]
fn a_step_variable_replaces_the_plans_of_the_name_the_platform_takes_as_the_same() {
    let step = STEP
        .replace("platforms = ['linux']", "platforms = ['linux', 'windows']")
        .replace(
            "command = ['cargo', 'test']",
            "env = { PATH = 'step' }\ncommand = ['cargo', 'test']",
        );
    let plan = Plan::parse(
        &with(&format!("[env]\nPath = 'plan'\n{step}")),
        &repository(),
    )
    .expect("the plan loads");
    let rust = selection(&["rust"]);
    let on = |platform| {
        plan.steps(platform, &rust, &Values::evidence("/e"), None)[0]
            .env
            .clone()
    };
    let pair = |name: &str, value: &str| (name.to_owned(), value.to_owned());
    assert_eq!(on(Platform::Windows), [pair("PATH", "step")]);
    assert_eq!(
        on(Platform::Linux),
        [pair("PATH", "step"), pair("Path", "plan")]
    );
}

/// A step that differs from [`STEP`] in the lines `before`, added ahead of its command, and in the
/// command `command`, which replaces its own.
fn step_adding(before: &str, command: &str) -> String {
    with(&STEP.replace(
        "command = ['cargo', 'test']",
        &format!("{before}command = {command}"),
    ))
}

/// The planted files of the execution model: a name, the text, and the words the refusal holds.
fn execution_faults() -> Vec<(&'static str, String, &'static str)> {
    let cargo = "['cargo', 'test']";
    let output = |path: &str| {
        step_adding(
            &format!("output = '{path}'\n"),
            "['cargo', 'test', '{output}']",
        )
    };
    vec![
        (
            "a directory that is absolute",
            step_adding("directory = '/tmp'\n", cargo),
            "step `one` names the `directory` `/tmp`, which is not a relative path",
        ),
        (
            "a directory that holds `..`",
            step_adding("directory = 'crates/..'\n", cargo),
            "which holds `..`",
        ),
        (
            "a directory that is not one",
            step_adding("directory = 'no-such-directory'\n", cargo),
            "which is not a directory of the repository",
        ),
        (
            "a directory that holds a placeholder",
            step_adding("directory = '{root}'\n", cargo),
            "which holds a placeholder",
        ),
        (
            "a cargo step in a directory that is no workspace's root",
            step_adding("directory = 'crates'\n", cargo),
            "which no `[rust] manifests` entry is the workspace root of",
        ),
        (
            "a needed name that is not a variable name",
            step_adding("needs = ['two words']\n", cargo),
            "step `one` needs `two words`, which is not a variable name",
        ),
        (
            "a variable of a step that is not a variable name",
            step_adding("env = { 'two words' = 'x' }\n", cargo),
            "step `one` gives `two words`, which is not a variable name",
        ),
        (
            "a variable of the plan that is not a variable name",
            with("[env]\n'two words' = 'x'\n"),
            "`[env]` gives `two words`, which is not a variable name",
        ),
        (
            "a value of a step that holds a placeholder outside the plan's",
            step_adding("env = { A = '{nothing}' }\n", cargo),
            "step `one` gives `A` a value that holds `{nothing}`",
        ),
        (
            "a value of the plan that holds a placeholder outside the plan's",
            with("[env]\nA = '{nothing}'\n"),
            "`[env]` gives `A` a value that holds `{nothing}`",
        ),
        (
            "a value of the plan that holds the output of a step",
            with("[env]\nA = '{output}'\n"),
            "`[env]` gives `A` a value that holds `{output}`",
        ),
        (
            "a word of a command that holds a placeholder outside the plan's",
            step_adding("", "['cargo', 'test', '{nothing}']"),
            "step `one` holds `{nothing}`, which is not a placeholder of the plan",
        ),
        (
            "an output outside the report's directory",
            output("{evidence}/elsewhere/x"),
            "which is not below `{evidence}/conformance/`",
        ),
        (
            "an output that is an absolute path",
            output("/tmp/x"),
            "which is not below `{evidence}/conformance/`",
        ),
        (
            "an output that climbs out of the report's directory",
            output("{evidence}/conformance/../x"),
            "which holds `..`, `.` or an empty part",
        ),
        (
            "an output that holds a placeholder",
            output("{evidence}/conformance/{scratch}"),
            "which holds a placeholder or a backslash",
        ),
        (
            "an output in the directory of the logs",
            output("{evidence}/conformance/logs/one.json"),
            "which is the report's own",
        ),
        (
            "an output that is the result",
            output("{evidence}/conformance/result.json"),
            "which is the report's own",
        ),
        (
            "two steps with one output",
            format!(
                "{}{}",
                output("{evidence}/conformance/same.json"),
                STEP.replace("'one'", "'two'").replace(
                    "command = ['cargo', 'test']",
                    "output = '{evidence}/conformance/same.json'\ncommand = ['cargo', 'test', '{output}']"
                )
            ),
            "the steps `one` and `two` name outputs that are equal or nested",
        ),
        (
            "an output inside another step's output",
            format!(
                "{}{}",
                output("{evidence}/conformance/outer"),
                STEP.replace("'one'", "'two'").replace(
                    "command = ['cargo', 'test']",
                    "output = '{evidence}/conformance/outer/inner.json'\ncommand = ['cargo', 'test', '{output}']"
                )
            ),
            "the steps `one` and `two` name outputs that are equal or nested",
        ),
        (
            "an output in the directory of the logs spelt with capitals",
            output("{evidence}/conformance/Logs/one.json"),
            "which is the report's own",
        ),
        (
            "an output that is the result spelt with capitals",
            output("{evidence}/conformance/RESULT.json"),
            "which is the report's own",
        ),
        (
            "two steps with outputs that differ only by case",
            format!(
                "{}{}",
                output("{evidence}/conformance/same.json"),
                STEP.replace("'one'", "'two'").replace(
                    "command = ['cargo', 'test']",
                    "output = '{evidence}/conformance/SAME.json'\ncommand = ['cargo', 'test', '{output}']"
                )
            ),
            "the steps `one` and `two` name outputs that are equal or nested",
        ),
        (
            "an output inside another step's output that differs by case",
            format!(
                "{}{}",
                output("{evidence}/conformance/outer"),
                STEP.replace("'one'", "'two'").replace(
                    "command = ['cargo', 'test']",
                    "output = '{evidence}/conformance/OUTER/inner.json'\ncommand = ['cargo', 'test', '{output}']"
                )
            ),
            "the steps `one` and `two` name outputs that are equal or nested",
        ),
        (
            "an output with a part that ends with a dot",
            output("{evidence}/conformance/x."),
            "which holds a part that ends with a dot or a space",
        ),
        (
            "an output with a part that ends with a space",
            output("{evidence}/conformance/dir /x.json"),
            "which holds a part that ends with a dot or a space",
        ),
        (
            "an output that holds a backslash",
            output("{evidence}/conformance/a\\b.json"),
            "which holds a placeholder or a backslash",
        ),
        (
            "an output that holds an empty part",
            output("{evidence}/conformance/a//b.json"),
            "which holds `..`, `.` or an empty part",
        ),
        (
            "an output that holds a non-ASCII letter",
            output("{evidence}/conformance/\u{c4}.json"),
            "step `one` names the `output` `{evidence}/conformance/\u{c4}.json`, whose part `\u{c4}.json` holds a character outside the portable set: letters, digits, `.`, `-` and `_`",
        ),
        (
            "an output nested below a part with a non-ASCII letter",
            output("{evidence}/conformance/\u{e4}/child.json"),
            "step `one` names the `output` `{evidence}/conformance/\u{e4}/child.json`, whose part `\u{e4}` holds a character outside the portable set: letters, digits, `.`, `-` and `_`",
        ),
        (
            "an output whose part holds a long s that a file system takes for an s",
            output("{evidence}/conformance/log\u{17f}/x.json"),
            "whose part `log\u{17f}` holds a character outside the portable set",
        ),
        (
            "an output whose part holds a colon",
            output("{evidence}/conformance/a:b.json"),
            "whose part `a:b.json` holds a character outside the portable set",
        ),
        (
            "an output whose part holds a space inside it",
            output("{evidence}/conformance/a b.json"),
            "whose part `a b.json` holds a character outside the portable set",
        ),
        (
            "an output that is a Windows device name",
            output("{evidence}/conformance/nul"),
            "step `one` names the `output` `{evidence}/conformance/nul`, whose part `nul` is a name that Windows keeps for a device: `con`, `prn`, `aux`, `nul`, `com1` to `com9` and `lpt1` to `lpt9`, with or without an extension",
        ),
        (
            "an output that is a device name in capitals",
            output("{evidence}/conformance/CON"),
            "whose part `CON` is a name that Windows keeps for a device",
        ),
        (
            "an output that is a device name in mixed case",
            output("{evidence}/conformance/Prn"),
            "whose part `Prn` is a name that Windows keeps for a device",
        ),
        (
            "an output that is the device aux",
            output("{evidence}/conformance/aux"),
            "whose part `aux` is a name that Windows keeps for a device",
        ),
        (
            "an output that is a device name with an extension",
            output("{evidence}/conformance/NUL.json"),
            "whose part `NUL.json` is a name that Windows keeps for a device",
        ),
        (
            "an output that is a device name with two extensions",
            output("{evidence}/conformance/aux.tar.gz"),
            "whose part `aux.tar.gz` is a name that Windows keeps for a device",
        ),
        (
            "an output that is the first serial port",
            output("{evidence}/conformance/com1"),
            "whose part `com1` is a name that Windows keeps for a device",
        ),
        (
            "an output that is the last serial port with an extension",
            output("{evidence}/conformance/COM9.log"),
            "whose part `COM9.log` is a name that Windows keeps for a device",
        ),
        (
            "an output that is the first printer port",
            output("{evidence}/conformance/lpt1"),
            "whose part `lpt1` is a name that Windows keeps for a device",
        ),
        (
            "an output that is the last printer port with an extension",
            output("{evidence}/conformance/Lpt9.x"),
            "whose part `Lpt9.x` is a name that Windows keeps for a device",
        ),
        (
            "an output whose directory is a device name",
            output("{evidence}/conformance/prn/x.json"),
            "whose part `prn` is a name that Windows keeps for a device",
        ),
        (
            "an output whose file below a directory is a device name",
            output("{evidence}/conformance/dir/Con.txt"),
            "whose part `Con.txt` is a name that Windows keeps for a device",
        ),
        (
            "a Vitest reading that names no output",
            step_with("reading = 'cargo'", "reading = 'vitest'\npackage = 'p'"),
            "step `one` reads a file and names no `output`",
        ),
        (
            "a lane reading that names no output",
            step_with("reading = 'cargo'", "reading = 'lane'\nlane = 'junit'"),
            "step `one` reads a file and names no `output`",
        ),
        (
            "an output that no command word and no variable holds",
            step_adding("output = '{evidence}/conformance/x.json'\n", cargo),
            "neither its command nor an `env` value holds `{output}`",
        ),
        (
            "a variable that holds the output of a step that names none",
            step_adding("env = { A = '{output}' }\n", cargo),
            "step `one` holds `{output}` and names no `output`",
        ),
        (
            "a command that holds the output of a step that names none",
            step_adding("", "['cargo', 'test', '{output}']"),
            "step `one` holds `{output}` and names no `output`",
        ),
    ]
}

/// The variables the report sets for each step, with the reason the loader gives for refusing each
/// one in a plan's `[env]` or a step's `env`.
const SET_BY_THE_REPORT: [(&str, &str); 6] = [
    (
        "KR_TEST_ARTIFACTS_DIR",
        "the tests write their records and figures there and the report reads them from the evidence directory",
    ),
    (
        "CARGO_TERM_COLOR",
        "the report reads Cargo's output and sets it to `never`",
    ),
    (
        "KR_CONFORMANCE_STEP",
        "the report's own program reads it while it lists and records the tests",
    ),
    (
        "KR_CONFORMANCE_RECORDS",
        "the report's own program reads it while it lists and records the tests",
    ),
    (
        "KR_CONFORMANCE_OWN_HARNESS",
        "the report's own program reads it while it lists and records the tests",
    ),
    (
        "CARGO_TARGET_AARCH64_APPLE_DARWIN_RUNNER",
        "the report sets it to its own program, which runs each test binary",
    ),
];

/// A plan's `[env]` and a step's `env` may not give a variable the report sets for each step: the
/// step would run without what the report gives it, and a known difference a test recorded could
/// be written where the report does not read it. Each name is refused in both places, with its own
/// reason, in the spelling of the report and in lower case, and a name the report does not set
/// loads.
#[test]
fn a_variable_the_report_sets_for_each_step_is_refused_in_the_plan_and_in_a_step() {
    let in_plan = |name: &str| with(&format!("[env]\n{name} = 'x'\n{STEP}"));
    let in_step = |name: &str| {
        with(&STEP.replace(
            "command = ['cargo', 'test']",
            &format!("env = {{ {name} = 'x' }}\ncommand = ['cargo', 'test']"),
        ))
    };
    for name in [
        "KR_FROM_THE_PLAN",
        "CARGO_TARGET_DIR",
        "CARGO_TARGET_X_LINKER",
    ] {
        for text in [in_plan(name), in_step(name)] {
            let loaded = Plan::parse(&text, &repository());
            assert!(loaded.is_ok(), "{name}: {loaded:?}");
        }
    }
    let mut wrong = Vec::new();
    for (name, reason) in SET_BY_THE_REPORT {
        for spelt in [name.to_owned(), name.to_ascii_lowercase()] {
            for (place, text) in [
                ("`[env]`", in_plan(&spelt)),
                ("step `one`", in_step(&spelt)),
            ] {
                let words = format!(
                    "{place} sets `{spelt}`, which the report sets for each step: {reason}"
                );
                match Plan::parse(&text, &repository()) {
                    Ok(_) => wrong.push(format!("{spelt} in {place}: the loader refused nothing")),
                    Err(refusal) if refusal.to_string().contains(&words) => {}
                    Err(refusal) => wrong.push(format!(
                        "{spelt} in {place}: refused as `{refusal}`, which lacks `{words}`"
                    )),
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A plan's `[env]` and a step's `env` each hold one name for one variable: two names of one table
/// that differ only by case are refused on every platform, the pair named in the order the table
/// keeps it. Names that differ by more than case load, and so do a plan's name and a step's that
/// differ only by case: the step's replaces the plan's where the platform takes them as one.
#[test]
fn two_names_of_one_table_that_differ_only_by_case_are_refused_in_the_plan_and_in_a_step() {
    let in_step = |names: &str| {
        with(&STEP.replace(
            "command = ['cargo', 'test']",
            &format!("env = {{ {names} }}\ncommand = ['cargo', 'test']"),
        ))
    };
    for (place, text) in [
        (
            "`[env]`",
            with(&format!("[env]\nLOUD = 'a'\nLoud = 'b'\n{STEP}")),
        ),
        ("step `one`", in_step("LOUD = 'a', Loud = 'b'")),
    ] {
        let words = format!("{place} gives `LOUD` and `Loud`, which differ only by case");
        match Plan::parse(&text, &repository()) {
            Ok(_) => panic!("{place}: the loader refused nothing"),
            Err(refusal) => assert!(
                refusal.to_string().contains(&words),
                "{place}: refused as `{refusal}`, which lacks `{words}`"
            ),
        }
    }
    for (name, text) in [
        (
            "two names of one table that differ by more than case",
            with(&format!("[env]\nLOUD = 'a'\nLOUDER = 'b'\n{STEP}")),
        ),
        (
            "a name of the plan and a name of a step that differ only by case",
            with(&format!(
                "[env]\nLOUD = 'a'\n{}",
                STEP.replace(
                    "command = ['cargo', 'test']",
                    "env = { Loud = 'b' }\ncommand = ['cargo', 'test']"
                )
            )),
        ),
    ] {
        let loaded = Plan::parse(&text, &repository());
        assert!(loaded.is_ok(), "{name}: {loaded:?}");
    }
}

/// A step's `directory` is refused with its own reason for each way a path goes wrong, as the keys
/// that name a path are: it is absent, it is a file, it is absolute or holds `..` or a pattern
/// character, it is a link, or a link on its way leads out of the repository. A directory that a
/// link inside the repository reaches inside it is accepted.
#[test]
fn a_step_directory_is_refused_with_its_reason_for_each_way_a_path_goes_wrong() {
    let (repository, _elsewhere) = tree_with_links();
    let root = repository.path();
    let step =
        |operand: &str| step_adding(&format!("directory = '{operand}'\n"), "['pnpm', 'test']");
    let not_a_directory = "is not a directory of the repository";
    let mut refusals = vec![
        ("missing", not_a_directory),
        ("dir/file.txt", not_a_directory),
        ("/dir", "is not a relative path"),
        ("dir/../dir", "holds `..`"),
        ("d*r", "holds a pattern character"),
    ];
    let mut accepted = vec!["dir", "dir/sub"];
    if cfg!(unix) {
        refusals.push(("dirlink", "is a link"));
        refusals.push(("insidelink", "is a link"));
        refusals.push(("dirlink/sub", "leads out of the repository through a link"));
        accepted.push("insidelink/sub");
    }
    let mut wrong = Vec::new();
    for operand in accepted {
        if let Err(refusal) = Plan::parse(&step(operand), root) {
            wrong.push(format!("{operand}: refused as `{refusal}`"));
        }
    }
    for (operand, why) in refusals {
        let wanted = format!("step `one` names the `directory` `{operand}`, which {why}");
        match Plan::parse(&step(operand), root) {
            Ok(_) => wrong.push(format!("{operand}: the loader refused nothing")),
            Err(refusal) if refusal.0 == wanted => {}
            Err(refusal) => wrong.push(format!("{operand}: refused as `{refusal}`")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A script a step runs is read from the directory the step runs in: the file the step finds there
/// is the one the loader holds to be tracked, and one at the repository's root is not.
#[test]
fn a_script_is_looked_for_in_the_directory_the_step_runs_in() {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path();
    std::fs::write(root.join("Cargo.toml"), "").expect("a manifest");
    std::fs::create_dir(root.join("dir")).expect("a directory");
    std::fs::write(root.join("dir").join("here.sh"), "").expect("a script");
    std::fs::write(root.join("top.sh"), "").expect("a script");
    git(root, &["init", "-q"]);
    git(root, &["add", "dir/here.sh", "top.sh"]);
    let step =
        |directory: &str, script: &str| step_adding(directory, &format!("['bash', '{script}']"));
    let in_dir = "directory = 'dir'\n";
    for (before, script) in [(in_dir, "here.sh"), ("", "top.sh")] {
        let loaded = Plan::parse(&step(before, script), root);
        assert!(loaded.is_ok(), "{before} {script}: {loaded:?}");
    }
    for (before, script) in [(in_dir, "top.sh"), ("", "here.sh")] {
        let refusal =
            Plan::parse(&step(before, script), root).expect_err("the script is not there");
        assert!(
            refusal
                .0
                .contains(&format!("step `one` runs the script `{script}`, which")),
            "{before} {script}: {refusal}"
        );
    }
}

/// `{output}` in a step's variable is the step's output, the one the step names, as it is in a word
/// of its command.
#[test]
fn the_output_placeholder_in_a_step_variable_is_the_steps_output() {
    let text = step_adding(
        "output = '{evidence}/conformance/x.json'\nenv = { WHERE = '{output}' }\n",
        "['cargo', 'test']",
    );
    let plan = Plan::parse(&text, &repository()).expect("a variable can hold the output");
    let steps = plan.steps(
        Platform::Linux,
        &selection(&["rust"]),
        &Values::evidence("/e"),
        None,
    );
    assert_eq!(
        steps[0].env,
        [("WHERE".to_owned(), "/e/conformance/x.json".to_owned())]
    );
}

/// A set-up step, `prep`, on `platforms`, and a step, `one`, that holds `after` and its own
/// `platforms`, in a plan of one group.
fn set_up_and_one(
    prep_reading: &str,
    prep_platforms: &str,
    one_platforms: &str,
    after: &str,
    prep_is_set_up: bool,
) -> String {
    with(&format!(
        "[[step]]
id = 'prep'
group = 'rust'
what = 'the set-up'
platforms = {prep_platforms}
reading = '{prep_reading}'
{}command = ['cargo', 'test']
[[step]]
id = 'one'
group = 'rust'
what = 'the first'
platforms = {one_platforms}
reading = 'cargo'
after = {after}
command = ['cargo', 'test']
",
        if prep_is_set_up { "setup = true\n" } else { "" }
    ))
}

/// The planted files of the set-up steps: a name, the text, and the words the refusal holds.
fn set_up_faults() -> Vec<(&'static str, String, &'static str)> {
    vec![
        (
            "an `after` that names no step",
            set_up_and_one("exit", "['linux']", "['linux']", "['gone']", true),
            "step `one` is `after` `gone`, which names no step of the plan",
        ),
        (
            "an `after` that names a later step",
            with(
                "[[step]]
id = 'one'
group = 'rust'
what = 'the first'
platforms = ['linux']
reading = 'cargo'
after = ['prep']
command = ['cargo', 'test']
[[step]]
id = 'prep'
group = 'rust'
what = 'the set-up'
platforms = ['linux']
reading = 'exit'
setup = true
command = ['cargo', 'test']
",
            ),
            "step `one` is `after` `prep`, which does not come before it in the plan",
        ),
        (
            "an `after` that names its own step",
            step_adding("after = ['one']\n", "['cargo', 'test']"),
            "step `one` is `after` `one`, which does not come before it in the plan",
        ),
        (
            "an `after` that names a step that is not a set-up step",
            set_up_and_one("cargo", "['linux']", "['linux']", "['prep']", false),
            "step `one` is `after` `prep`, which is not a set-up step",
        ),
        (
            "a set-up step that reads more than its exit status",
            set_up_and_one("cargo", "['linux']", "['linux']", "['prep']", true),
            "step `prep` is a set-up step and reads `cargo`: a set-up step reads `exit`",
        ),
        (
            "a step on a platform where its set-up step does not run",
            set_up_and_one(
                "exit",
                "['linux']",
                "['linux', 'windows']",
                "['prep']",
                true,
            ),
            "step `one` runs on windows, where its set-up step `prep` does not run",
        ),
    ]
}

/// Each planted file of the set-up steps is refused with its own reason, and the same plan with the
/// fault taken out loads.
#[test]
fn a_set_up_step_or_an_after_is_refused_for_each_fault_by_its_reason() {
    let root = repository();
    let control = Plan::parse(
        &set_up_and_one(
            "exit",
            "['linux', 'windows']",
            "['linux', 'windows']",
            "['prep']",
            true,
        ),
        &root,
    );
    assert!(control.is_ok(), "the control file loads: {control:?}");
    let mut wrong = Vec::new();
    for (name, text, reason) in set_up_faults() {
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

/// A selection holds, in the plan's order, every set-up step that a step of it names, directly or
/// through another set-up step, whatever the set-up step's group; a set-up step that no selected
/// step names is in the selection only when its own group is.
#[test]
fn a_selection_holds_the_set_up_steps_its_steps_name_from_any_group() {
    let set_up = |id: &str, after: &str| {
        format!(
            "[[step]]
id = '{id}'
group = 'prepare'
what = '{id}'
platforms = ['linux', 'macos']
reading = 'exit'
setup = true
after = [{after}]
command = ['cargo', 'test']
"
        )
    };
    let text = format!(
        "{}{}{}{}[[step]]
id = 'last'
group = 'rust'
what = 'the last'
platforms = ['linux', 'macos']
reading = 'cargo'
after = ['second']
command = ['cargo', 'test']
",
        HEAD.replace("groups = ['rust']", "groups = ['prepare', 'rust']"),
        set_up("first", ""),
        set_up("second", "'first'"),
        set_up("alone", ""),
    );
    let plan = Plan::parse(&text, &repository()).expect("the plan loads");
    let ids = |platform: Platform, groups: &[&str]| -> Vec<String> {
        plan.steps(
            platform,
            &selection(groups),
            &Values::evidence("/tmp/e"),
            None,
        )
        .into_iter()
        .map(|step| step.id)
        .collect()
    };
    assert_eq!(ids(Platform::Linux, &["rust"]), ["first", "second", "last"]);
    assert_eq!(ids(Platform::MacOs, &["rust"]), ["first", "second", "last"]);
    assert_eq!(
        ids(Platform::Linux, &["prepare"]),
        ["first", "second", "alone"]
    );
    assert_eq!(
        ids(Platform::Linux, &["prepare", "rust"]),
        ["first", "second", "alone", "last"]
    );
    assert!(ids(Platform::Windows, &["rust"]).is_empty());
}

/// Each planted file of the execution model is refused with its own reason. A step whose `{output}`
/// is held by a variable and not by a command word is accepted, and so is an output whose parts hold
/// capitals, digits, `.`, `-` and `_`, and one that only looks like a name Windows keeps for a
/// device.
#[test]
fn a_step_of_the_execution_model_is_refused_for_each_fault_by_its_reason() {
    let root = repository();
    let accepted = step_adding(
        "output = '{evidence}/conformance/Out-1_a.2/X.json'\nenv = { WHERE = '{output}', HERE = '{root}', LATER = '{scratch}/y' }\n",
        "['cargo', 'test']",
    );
    let control = Plan::parse(&accepted, &root);
    assert!(control.is_ok(), "the control file loads: {control:?}");
    // Names that only look like a device name: the reserved ones are those up to the first dot, and
    // `com1` to `com9`, `lpt1` to `lpt9` and the four words are all of them.
    let mut wrong = Vec::new();
    for part in [
        "com0",
        "com10.json",
        "lpt0",
        "lpt10",
        "console.json",
        "nulls",
        "auxiliary.log",
        "prnt",
        "a.con",
        "x.nul.json",
        "con-1.json",
        "com_1",
    ] {
        let path = format!("{{evidence}}/conformance/{part}");
        let text = step_adding(
            &format!("output = '{path}'\n"),
            "['cargo', 'test', '{output}']",
        );
        if let Err(refusal) = Plan::parse(&text, &root) {
            wrong.push(format!("{part}: refused as `{refusal}`"));
        }
    }
    for (name, text, reason) in execution_faults() {
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

/// The command of a step that reads the output of `cargo test` is read the way Cargo reads its
/// flags, and one the report cannot read is refused with its own reason. A step that reads no
/// output of `cargo test`, or that runs another program, is not held to it, and each flag that
/// `cargo test --help` lists loads.
#[test]
fn a_cargo_test_step_whose_flags_the_report_cannot_read_is_refused_for_each_fault_by_its_reason() {
    let root = repository();
    let command = |words: &str| step_adding("", &format!("[{words}]"));
    let refused: &[(&str, &str, &str)] = &[
        (
            "a manifest path",
            "'cargo', 'test', '--manifest-path', 'other/Cargo.toml'",
            "step `one` gives `--manifest-path`: the step's directory is its workspace, and `-p` and `--workspace` choose the packages in it",
        ),
        (
            "a manifest path in its short form",
            "'cargo', 'test', '-m', 'other/Cargo.toml'",
            "step `one` gives `--manifest-path`",
        ),
        (
            "an unstable flag",
            "'cargo', 'test', '-Z', 'unstable-options'",
            "step `one` gives `-Z`, an unstable flag that can change which targets Cargo selects and that the report does not read",
        ),
        (
            "an exclusion without the workspace",
            "'cargo', 'test', '--exclude', 'b'",
            "step `one` gives `--exclude` without `--workspace`, which Cargo refuses",
        ),
        (
            "an exclusion beside a package",
            "'cargo', 'test', '-p', 'a', '--exclude', 'b'",
            "step `one` gives `--exclude` without `--workspace`",
        ),
        (
            "a flag that is not one of Cargo's",
            "'cargo', 'test', '--workspace', '--nope'",
            "step `one` gives `--nope`, which is not a flag of `cargo test`: the report reads only the flags it knows",
        ),
        (
            "a package flag with no value",
            "'cargo', 'test', '-p'",
            "step `one` gives `--package` without a value",
        ),
        (
            "a target flag whose value is another flag",
            "'cargo', 'test', '--test', '--lib'",
            "step `one` gives `--test` without a value",
        ),
        (
            "a package with a version",
            "'cargo', 'test', '-p', 'a@0.1.0'",
            "step `one` names the package `a@0.1.0`: give a package by its name, or by a pattern of `*`, `?` and `[...]` that matches names",
        ),
        (
            "a pattern with a class that is never closed",
            "'cargo', 'test', '-p', 'a[b'",
            "step `one` names the pattern `a[b`, which has a `[` that no `]` closes",
        ),
        (
            "the documentation tests beside a library",
            "'cargo', 'test', '--doc', '--lib'",
            "step `one` gives `--doc` with another flag that selects targets, which Cargo refuses",
        ),
        (
            "a command that is not `cargo test`",
            "'cargo', 'build', '-p', 'a'",
            "step `one` reads the output of `cargo test` and its command is not `cargo test`",
        ),
    ];
    let mut wrong = Vec::new();
    for (name, words, reason) in refused {
        match Plan::parse(&command(words), &root) {
            Ok(_) => wrong.push(format!("{name}: the loader refused nothing")),
            Err(refusal) if refusal.to_string().contains(reason) => {}
            Err(refusal) => wrong.push(format!(
                "{name}: refused as `{refusal}`, which lacks `{reason}`"
            )),
        }
    }
    for words in [
        "'cargo', 'test'",
        "'cargo', 'test', '--locked', '-p', 'a', '--features', 'f', '--', '--nocapture'",
        "'cargo', 'test', '--locked', '--workspace', '--exclude', 'b*', '--no-fail-fast'",
        "'cargo', 'test', '--all', '--exclude=b'",
        "'cargo', 'test', '-pa', '-p=b', '--package=c'",
        "'cargo', 'test', '--lib', '--bin=x', '--test', 't', '--bench', 'm', '--example', 'e'",
        "'cargo', 'test', '--bins', '--tests', '--benches', '--examples', '--all-targets'",
        "'cargo', 'test', '--doc', '--no-fail-fast'",
        "'cargo', 'test', '-F', 'f', '--all-features', '--no-default-features', '--release', '--profile', 'ci'",
        "'cargo', 'test', '-qr', '-vv', '-j', '4', '--target', 'x86_64-unknown-linux-gnu', '--timings=html'",
        "'cargo', 'test', '--offline', '--frozen', '--ignore-rust-version', '--color', 'never', 'a_name_filter'",
        "'cargo', 'test', '-p', 'a', '--', '--manifest-path', '--bogus', '-Z'",
    ] {
        let text = command(words);
        if let Err(refusal) = Plan::parse(&text, &root) {
            wrong.push(format!("{words}: refused as `{refusal}`"));
        }
    }
    // A step that reads nothing of `cargo test` is not held to its flags.
    for (reading, words) in [(
        "build",
        "'cargo', 'build', '-Z', 'unstable-options', '--manifest-path', 'x/Cargo.toml'",
    )] {
        let text = step_with(
            "reading = 'cargo'\ncommand = ['cargo', 'test']",
            &format!("reading = '{reading}'\ncommand = [{words}]"),
        );
        if let Err(refusal) = Plan::parse(&text, &root) {
            wrong.push(format!("a {reading} step: refused as `{refusal}`"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A `cargo` step runs in a workspace root that `[rust] manifests` names: the directory the step
/// names or, when it names none, the repository's root. A step of another program is not held to
/// it, and a root named with a `.` in its path is the same root.
#[test]
fn a_cargo_step_runs_only_in_a_workspace_root_the_plan_names_with_or_without_a_directory() {
    let repository = tempfile::tempdir().expect("a directory");
    let root = repository.path();
    for manifest in ["Cargo.toml", "first/Cargo.toml", "second/Cargo.toml"] {
        let path = root.join(manifest);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
        std::fs::write(path, "").expect("a manifest");
    }
    let plan = |manifest: &str, directory: &str, program: &str| {
        let setup = if program == "cargo" {
            ""
        } else {
            "setup = true\n"
        };
        let reading = if program == "cargo" { "cargo" } else { "exit" };
        format!(
            "{}{}",
            HEAD.replace(
                "manifests = ['Cargo.toml']",
                &format!("manifests = ['{manifest}']")
            ),
            STEP.replace("reading = 'cargo'", &format!("reading = '{reading}'"))
                .replace(
                    "command = ['cargo', 'test']",
                    &format!("{setup}{directory}command = ['{program}', 'test']")
                )
        )
    };
    let refused = |manifest: &str, directory: &str| {
        Plan::parse(&plan(manifest, directory, "cargo"), root)
            .expect_err("the step is refused")
            .to_string()
    };
    let why = "which no `[rust] manifests` entry is the workspace root of";
    // No directory: the root, which `first/Cargo.toml` is not the workspace of.
    let text = refused("first/Cargo.toml", "");
    assert!(
        text.contains("step `one` runs `cargo` in the repository's root") && text.contains(why),
        "{text}"
    );
    // A directory that holds a manifest the plan does not name.
    let text = refused("first/Cargo.toml", "directory = 'second'\n");
    assert!(
        text.contains("step `one` runs `cargo` in `second`") && text.contains(why),
        "{text}"
    );
    for (manifest, directory) in [
        ("Cargo.toml", ""),
        ("./Cargo.toml", ""),
        ("Cargo.toml", "directory = '.'\n"),
        ("first/Cargo.toml", "directory = 'first'\n"),
        ("./first/Cargo.toml", "directory = './first'\n"),
    ] {
        let loaded = Plan::parse(&plan(manifest, directory, "cargo"), root);
        assert!(loaded.is_ok(), "{manifest} {directory}: {loaded:?}");
    }
    let loaded = Plan::parse(&plan("first/Cargo.toml", "", "pnpm"), root);
    assert!(loaded.is_ok(), "a step of another program: {loaded:?}");
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

/// A repository of its own that holds a `Cargo.toml`, and whose index holds `tracked.sh` and `gone.sh`, with `gone.sh` removed
/// from the tree, `untracked.sh` beside them and, where a name may hold `*`, a file named `*.sh`
/// that the index does not hold and, where a link can be made, `link.sh`, a link that the index
/// holds.
fn planted_repository() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path();
    std::fs::write(root.join("Cargo.toml"), "").expect("a manifest");
    for name in ["tracked.sh", "gone.sh", "untracked.sh"] {
        std::fs::write(root.join(name), "").expect("a file");
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink("tracked.sh", root.join("link.sh")).expect("a link");
    git(root, &["init", "-q"]);
    git(root, &["add", "tracked.sh", "gone.sh"]);
    #[cfg(unix)]
    git(root, &["add", "link.sh"]);
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
    // The file named `*.sh` exists where a name may hold `*`; the pattern is refused before any
    // file is looked for, so the refusal is the same where it does not.
    refusals.push(("*.sh", "holds a pattern character"));
    if cfg!(unix) {
        refusals.push(("link.sh", "is a link"));
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
/// cannot check the script, with the first line of what Git wrote. The root holds a `.git` file that
/// is not one, so that Git cannot read it whichever work tree holds the temporary folder.
#[test]
fn a_script_is_not_checked_in_a_root_that_git_cannot_read() {
    let directory = tempfile::tempdir().expect("a directory");
    std::fs::write(directory.path().join(".git"), "not a gitfile\n").expect("a file");
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
    let linux = plan.steps(Platform::Linux, &rust, &Values::evidence("/tmp/e"), None);
    assert_eq!(linux.len(), 2);
    assert_eq!(
        plan.steps(Platform::MacOs, &rust, &Values::evidence("/tmp/e"), None)
            .len(),
        1
    );
    assert!(
        plan.steps(Platform::Windows, &rust, &Values::evidence("/tmp/e"), None)
            .is_empty()
    );
    assert!(
        plan.steps(Platform::Linux, &[], &Values::evidence("/tmp/e"), None)
            .is_empty()
    );
}

/// Runs the program with `arguments` and returns its exit code and what it wrote to stderr.
fn program(arguments: &[&str]) -> (Option<i32>, String) {
    let (code, _, stderr) = program_output(arguments);
    (code, stderr)
}

/// Runs the program with `arguments` and returns its exit code, what it wrote to stdout and what it
/// wrote to stderr.
fn program_output(arguments: &[&str]) -> (Option<i32>, String, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_kr-conformance"))
        .args(arguments)
        .output()
        .expect("the program runs");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
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

/// An option with no value is a usage error with exit status 2 and the option's own reason, for
/// `map` and for `run`, before the plan is read, the map is built or anything runs: the option
/// reads as given and without its value, never as absent, and never takes the next option as its
/// value. The `run` selection is the group that needs no applications, so a missing value of
/// `--applications` is not excused by the selection.
#[test]
fn an_option_without_a_value_is_a_usage_error_for_map_and_run() {
    let repository = tempfile::tempdir().expect("a directory");
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
    let options = [
        ("--root", "--root takes the path of the repository"),
        (
            "--evidence",
            "--evidence takes the path of the evidence directory",
        ),
        (
            "--applications",
            "--applications takes the path of the applications cache",
        ),
        ("--plan", "--plan takes the path of a plan file"),
    ];
    let mut failures = Vec::new();
    // At the end of the arguments, and before another option.
    for after in [None, Some("--all-terminals")] {
        for (option, reason) in options {
            for command in ["map", "run"] {
                let evidence = tempfile::tempdir().expect("a directory");
                let evidence_path = evidence.path().to_string_lossy().into_owned();
                let mut arguments = vec![command, "--root", root.as_str()];
                if command == "run" {
                    arguments.extend(["--group", "rust", "--evidence", evidence_path.as_str()]);
                }
                arguments.push(option);
                arguments.extend(after);
                let (code, stdout, stderr) = program_output(&arguments);
                let written = std::fs::read_dir(evidence.path())
                    .expect("the evidence")
                    .count();
                if code != Some(2)
                    || !stderr.starts_with(&format!("kr-conformance: {reason}\n"))
                    || !stdout.is_empty()
                    || written != 0
                {
                    failures.push(format!(
                        "{arguments:?}: exit {code:?}, stdout {} bytes, {written} files of evidence: {stderr}",
                        stdout.len()
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// No constant or static of the harness's sources holds a step, a table row or a reason, no code
/// outside a test builds a step by hand, and the code names none of the groups that carry
/// behaviour: the plan file is the one place for all three.
#[test]
fn the_tables_are_not_in_the_code() {
    // The names of two variables, the schema's version, the two `const fn` of `Platform`, the
    // loader's own constants (the most seconds a time limit may be among them), and the reach and
    // the characters the ignored-test reader holds.
    let kept = [
        "SECRET_STORE_VARIABLE",
        "APPLICATIONS_VARIABLE",
        "SCHEMA",
        "current",
        "name",
        "PLAN_PATH",
        "PROGRAMS",
        "PLACEHOLDERS",
        "HELPER_REACH",
        "UNREAD",
        "MOST_SECONDS",
    ];
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    for file in [
        "plan.rs",
        "report.rs",
        "plan_file.rs",
        "main.rs",
        "ignored.rs",
    ] {
        let text = std::fs::read_to_string(source.join(file)).expect("the source");
        for (index, line) in text.lines().enumerate() {
            let words: Vec<&str> = without_visibility(line).split_whitespace().collect();
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
        // Only a test builds a step by hand: the code takes its steps from the plan file.
        let code = text.split("#[cfg(test)]").next().unwrap_or_default();
        for (index, line) in code.lines().enumerate() {
            if line.contains("Step::cargo(") && !line.trim_start().starts_with("//") {
                found.push(format!(
                    "{}:{}: builds a step outside the plan file",
                    path.display(),
                    index + 1
                ));
            }
        }
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// The line without its visibility: `pub`, `pub(crate)`, `pub(super)` or `pub(in path)`.
fn without_visibility(line: &str) -> &str {
    let line = line.trim_start();
    match line.strip_prefix("pub") {
        Some(rest) if rest.starts_with(char::is_whitespace) => rest.trim_start(),
        Some(rest) if rest.starts_with('(') => rest
            .split_once(')')
            .map_or(line, |(_, after)| after.trim_start()),
        _ => line,
    }
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
        for package in [
            "packages/protocol",
            "packages/plugin-sdk",
            "apps/companion",
            "packages/no-such-package",
        ] {
            assert_eq!(
                plan.selects_package(&groups, package),
                typescript && package != "packages/no-such-package",
                "{package} {names:?}"
            );
        }
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
[rust]
manifests = ['Cargo.toml']
[ignored_runs]
held = false
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
output = '{evidence}/conformance/unit.json'
command = ['pnpm', 'run', 'test', '--outputFile.json={output}']
[[step]]
id = 'build'
group = 'node'
what = 'a build'
platforms = ['linux']
reading = 'build'
command = ['cargo', 'build']
[[step]]
id = 'browser-tests'
group = 'browsers'
what = 'the browser tests'
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

/// Two selected groups that both explain an unrun Rust target on a platform: the plan's first
/// group gives the reason, whatever the order of the selection.
#[test]
fn the_reason_of_an_unrun_target_is_the_plans_first_group_whatever_the_selection_order() {
    let plan = Plan::parse(
        &with(&format!(
            "[[group_absent]]\ngroup = 'rust'\nplatform = 'windows'\nreason = 'first'\nexplains_unrun_rust = true\n\
             [[group_absent]]\ngroup = 'other'\nplatform = 'windows'\nreason = 'second'\nexplains_unrun_rust = true\n\
             {STEP}{}",
            STEP.replace("id = 'one'", "id = 'two'").replace("group = 'rust'", "group = 'other'")
        ))
        .replace("groups = ['rust']", "groups = ['rust', 'other']"),
        &repository(),
    )
    .expect("the planted plan loads");
    for names in [&["rust", "other"][..], &["other", "rust"]] {
        assert_eq!(
            plan.unrun_rust_reason(Platform::Windows, &selection(names)),
            Some("first"),
            "{names:?}"
        );
    }
    assert_eq!(
        plan.unrun_rust_reason(Platform::Windows, &selection(&["other"])),
        Some("second")
    );
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
            .steps(
                platform,
                &selection(&[group]),
                &Values::evidence("/tmp/e"),
                None,
            )
            .iter()
            .map(Step::line)
            .collect();
        assert!(
            lines.iter().any(|candidate| candidate.contains(line)),
            "{platform:?} {group}: {line}"
        );
    }
    // A command that shows its output as it is written, with `--nocapture`, is left as it is.
    let planted = format!(
        "{HEAD}[[step]]
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
        .steps(
            Platform::Linux,
            &selection(&["rust"]),
            &Values::evidence("/tmp/e"),
            None,
        )
        .iter()
        .map(Step::line)
        .collect();
    assert_eq!(
        lines,
        ["cargo test -- --nocapture", "cargo test -- --show-output"]
    );
}

/// A second step of [`STEP`]'s kind, named `two`, with `extra` ahead of its command.
fn second_step(extra: &str) -> String {
    STEP.replace("id = 'one'", "id = 'two'").replace(
        "command = ['cargo', 'test']",
        &format!("{extra}command = ['cargo', 'test']"),
    )
}

/// The planted files of the time limits: a name, the text, and the words the refusal holds.
fn time_faults() -> Vec<(&'static str, String, &'static str)> {
    let limited = |extra: &str| step_adding(extra, "['cargo', 'test']");
    let budgeted = |tables: &str, extra: &str| {
        with(&format!(
            "{tables}{}",
            STEP.replace(
                "command = ['cargo', 'test']",
                &format!("{extra}command = ['cargo', 'test']")
            )
        ))
    };
    let on_windows =
        |text: String| text.replace("platforms = ['linux']", "platforms = ['linux', 'windows']");
    vec![
        (
            "a timeout of zero",
            limited("timeout = 0\n"),
            "step `one` has a `timeout` of 0 seconds: a time is a whole number of seconds from 1 to 86400",
        ),
        (
            "a negative timeout",
            limited("timeout = -5\n"),
            "step `one` has a `timeout` of -5 seconds",
        ),
        (
            "a timeout over a day",
            limited("timeout = 86401\n"),
            "step `one` has a `timeout` of 86401 seconds",
        ),
        (
            "a budget of zero seconds",
            budgeted("[[budget]]\nid = 'b'\nseconds = 0\n", "budget = 'b'\n"),
            "budget `b` has 0 seconds: a time is a whole number of seconds from 1 to 86400",
        ),
        (
            "a budget over a day",
            budgeted("[[budget]]\nid = 'b'\nseconds = 86401\n", "budget = 'b'\n"),
            "budget `b` has 86401 seconds",
        ),
        (
            "a budget id with a space",
            budgeted("[[budget]]\nid = 'a b'\nseconds = 5\n", "budget = 'a b'\n"),
            "a `[[budget]]` has the `id` `a b`, which is not a name",
        ),
        (
            "an empty budget id",
            budgeted("[[budget]]\nid = ''\nseconds = 5\n", "budget = ''\n"),
            "a `[[budget]]` has the `id` ``, which is not a name",
        ),
        (
            "a budget id used twice",
            budgeted(
                "[[budget]]\nid = 'b'\nseconds = 5\n[[budget]]\nid = 'b'\nseconds = 6\n",
                "budget = 'b'\n",
            ),
            "the budget id `b` is used twice",
        ),
        (
            "a budget a step names that the plan does not hold",
            budgeted("", "budget = 'nowhere'\n"),
            "step `one` names the budget `nowhere`, which no `[[budget]]` of the plan is",
        ),
        (
            "a budget that no step names",
            budgeted("[[budget]]\nid = 'idle'\nseconds = 5\n", ""),
            "the budget `idle` is named by no step",
        ),
        (
            "an unknown key of a budget",
            budgeted(
                "[[budget]]\nid = 'b'\nseconds = 5\nminutes = 1\n",
                "budget = 'b'\n",
            ),
            "minutes",
        ),
        (
            "a timeout on a step that runs on windows",
            on_windows(limited("timeout = 5\n")),
            "step `one` has a time limit and runs on `windows`, where the report cannot end the processes of a step",
        ),
        (
            "a budget on a step that runs on windows",
            on_windows(budgeted(
                "[[budget]]\nid = 'b'\nseconds = 5\n",
                "budget = 'b'\n",
            )),
            "step `one` has a time limit and runs on `windows`",
        ),
    ]
}

/// Each fault of a time limit is refused with its own reason, and the file that holds none of
/// them loads: the one control carries a timeout, a budget two steps share, and both on one step.
#[test]
fn a_time_limit_is_refused_for_each_fault_by_its_reason() {
    let root = repository();
    let control = with(&format!(
        "[[budget]]\nid = 'shared-1_a'\nseconds = 7\n{}{}",
        STEP.replace(
            "command = ['cargo', 'test']",
            "timeout = 86400\nbudget = 'shared-1_a'\ncommand = ['cargo', 'test']"
        ),
        second_step("budget = 'shared-1_a'\n"),
    ));
    let loaded = Plan::parse(&control, &root);
    assert!(loaded.is_ok(), "the control file loads: {loaded:?}");
    let mut wrong = Vec::new();
    for (name, text, reason) in time_faults() {
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

/// A step's time limit reaches the step the report runs: its `timeout`, and its budget's id with the
/// budget's seconds; a step without either has none. A step that runs on Windows and holds none
/// loads beside steps that hold them.
#[test]
fn a_steps_time_limit_and_its_budget_reach_the_step_the_report_runs() {
    let text = with(&format!(
        "[[budget]]\nid = 'b'\nseconds = 7\n{}{}{}",
        STEP.replace(
            "command = ['cargo', 'test']",
            "timeout = 5\nbudget = 'b'\ncommand = ['cargo', 'test']"
        ),
        second_step("budget = 'b'\n"),
        STEP.replace("id = 'one'", "id = 'three'")
            .replace("platforms = ['linux']", "platforms = ['linux', 'windows']"),
    ));
    let plan = Plan::parse(&text, &repository()).expect("the plan loads");
    let rust = selection(&["rust"]);
    let linux = plan.steps(Platform::Linux, &rust, &Values::evidence("/e"), None);
    let limits: Vec<_> = linux
        .iter()
        .map(|step| (step.timeout, step.budget.clone()))
        .collect();
    assert_eq!(
        limits,
        [
            (Some(5), Some(("b".to_owned(), 7))),
            (None, Some(("b".to_owned(), 7))),
            (None, None),
        ]
    );
    let windows = plan.steps(Platform::Windows, &rust, &Values::evidence("/e"), None);
    assert_eq!(
        windows
            .iter()
            .map(|step| step.id.as_str())
            .collect::<Vec<_>>(),
        ["three"],
        "the steps that hold a limit are not Windows steps"
    );
}
