//! What the landing workflow keeps of the tests that need a browser, a desktop session or a phone.
//!
//! Section 21 names a tool for each class of test and asks for the tests' screenshots to be kept in
//! `KR_TEST_ARTIFACTS_DIR` and collected into the CI artifact store. A workflow is how that is
//! delivered, so these hold the things a deleted or disabled step or a moved file would lose without
//! any job going red: the check that refuses a run with no screenshot kept, run on real
//! directories; a job for each class of test on the runner the workflow gives it, whose step is not
//! disabled and runs under the condition the workflow gives it, with the matrix leg that condition
//! names still in the matrix; the landing workflow's triggers; the evidence check and the strict
//! uploads, neither disabled, each made by the upload action of the directory the tests write to,
//! after the step that writes last, none of them cut short or kept for less than the repository's
//! default; and the table of those jobs in the conformance document. It reads the workflow as text,
//! line by line, which holds its layout (jobs at two spaces, steps at six, a trigger or a key on a
//! line of its own, no comment after a compared value, though a comment after a job's name is read
//! as that job's header): a reformatting fails it loudly. What it
//! does not read is what a step's command does: a step that swallows its failure (`|| true`),
//! runs no test (`--no-run`), leaves early or changes the shell it runs in is not looked for.

#![cfg(unix)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Runs the evidence check on an evidence directory and a directory to search for strays.
fn check(evidence: &Path, strays: &Path) -> Option<i32> {
    Command::new("bash")
        .arg(repository().join("scripts/check-test-evidence.sh"))
        .arg(evidence)
        .arg("companion-screenshots")
        .arg(strays)
        .output()
        .expect("bash runs")
        .status
        .code()
}

/// KR-REQ-21.02 and KR-REQ-27.03: a run whose browser tests kept their screenshots in the evidence
/// directory passes, and a run that kept none, or left one in the temporary directory where the
/// runner would lose it, fails.
#[test]
fn a_run_that_kept_no_screenshot_in_the_evidence_directory_fails() {
    let evidence = TempDir::new().expect("a directory");
    let strays = TempDir::new().expect("a directory");

    // Nothing was kept: the evidence directory has no pictures, or does not exist.
    assert_eq!(check(evidence.path(), strays.path()), Some(1));
    assert_eq!(
        check(&evidence.path().join("absent"), strays.path()),
        Some(1)
    );

    // A picture in the directory, and none elsewhere.
    let kept = evidence.path().join("companion-screenshots");
    fs::create_dir_all(&kept).expect("a directory");
    fs::write(kept.join("kr-companion-shell-chromium.png"), b"\x89PNG").expect("a picture");
    assert_eq!(check(evidence.path(), strays.path()), Some(0));

    // The same run, with one picture written outside the directory.
    fs::write(
        strays.path().join("kr-companion-settings-webkit.png"),
        b"\x89PNG",
    )
    .expect("a picture");
    assert_eq!(check(evidence.path(), strays.path()), Some(1));
}

/// A line without a comment after its content, and without the space before the comment: the same
/// reading of a trailing ` #` the compared values get.
fn without_comment(line: &str) -> &str {
    line.split(" #").next().unwrap_or_default().trim_end()
}

/// The text of one job of the landing workflow: its header line to the next job's, with the
/// comment lines left out so that a step named only in a comment is not found.
fn job(workflow: &str, name: &str) -> String {
    let lines: Vec<&str> = workflow.lines().collect();
    let header = format!("  {name}:");
    let start = lines
        .iter()
        .position(|line| without_comment(line) == header)
        .unwrap_or_else(|| panic!("the workflow has a {name} job"));
    // A comment line is no job's header, whatever it ends with: a job key below one belongs to the
    // job above it. A header with a comment after its colon is still one, so the job above it ends
    // there.
    let is_job = |line: &str| {
        let line = without_comment(line);
        line.len() > 3
            && line.starts_with("  ")
            && !line.starts_with("   ")
            && !line.trim_start().starts_with('#')
            && line.ends_with(':')
    };
    let end = lines[start + 1..]
        .iter()
        .position(|line| is_job(line))
        .map_or(lines.len(), |offset| start + 1 + offset);
    lines[start..end]
        .iter()
        .filter(|line| !line.trim_start().starts_with('#'))
        .copied()
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether a line of a step starts the command `tool`: the line, less a step's `- ` and a `run:` key
/// and a `bash` that starts a script, begins with it. A step that only prints the tool's name does
/// not. A line that swallows the command's failure (`|| true`) is not looked for.
fn starts(line: &str, tool: &str) -> bool {
    let line = line.trim();
    let line = line.strip_prefix("- ").unwrap_or(line).trim_start();
    let line = line.strip_prefix("run:").unwrap_or(line).trim_start();
    let line = line.strip_prefix("bash ").unwrap_or(line);
    line.starts_with(tool)
}

/// The steps of a job, each from its `- ` line to the next step's, in the order they run.
fn steps_of(job: &str) -> Vec<String> {
    let lines: Vec<&str> = job.lines().collect();
    let starts_of_steps: Vec<usize> = (0..lines.len())
        .filter(|&index| lines[index].starts_with("      - "))
        .collect();
    starts_of_steps
        .iter()
        .enumerate()
        .map(|(position, &start)| {
            let end = starts_of_steps
                .get(position + 1)
                .copied()
                .unwrap_or(lines.len());
            lines[start..end].join("\n")
        })
        .collect()
}

/// The steps of a job that run `tool`. There is at least one.
fn steps_running(job: &str, tool: &str) -> Vec<String> {
    let running: Vec<String> = steps_of(job)
        .into_iter()
        .filter(|text| text.lines().any(|line| starts(line, tool)))
        .collect();
    assert!(!running.is_empty(), "no step of the job runs {tool}");
    running
}

/// The steps of a job that hold `needle` anywhere, as a step's name or its inputs.
fn steps_holding(job: &str, needle: &str) -> Vec<String> {
    let holding: Vec<String> = steps_of(job)
        .into_iter()
        .filter(|text| text.contains(needle))
        .collect();
    assert!(!holding.is_empty(), "no step of the job holds {needle}");
    holding
}

/// Where in the job's steps the step with this exact `id` stands, if one does.
fn position_of_id(job: &str, id: &str) -> Option<usize> {
    steps_of(job).iter().position(|step| {
        step.lines().any(|line| {
            key_value(line).is_some_and(|(indent, key, value)| {
                indent == 8
                    && key == "id"
                    && value.split(" #").next().unwrap_or_default().trim() == id
            })
        })
    })
}

/// Where in the job's steps the first step that runs `tool` stands.
fn position_of_tool(job: &str, tool: &str) -> Option<usize> {
    steps_of(job)
        .iter()
        .position(|step| step.lines().any(|line| starts(line, tool)))
}

/// The value a key has at `indent` in `text`, without the trailing comment, if it has one.
fn value_at(text: &str, indent: usize, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (at, key, value) = key_value(line)?;
        (at == indent && key == name).then(|| {
            value
                .split(" #")
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned()
        })
    })
}

/// The part of a job that is not its steps: its name, runner, condition and limits, wherever the
/// job's own keys stand, before the steps or after them.
fn header(job: &str) -> String {
    let mut before_steps = true;
    job.lines()
        .filter(|line| {
            if *line == "    steps:" {
                before_steps = false;
                return false;
            }
            before_steps || key_value(line).is_some_and(|(indent, ..)| indent == 4)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// A step, or a job's header, that a run skips or lets fail without failing the job: the way a step
/// is kept in the workflow and made to do nothing. A trailing comment, the spaces inside a
/// condition, quotes around the key and spaces before its colon do not hide it, and any
/// `continue-on-error` that is not the plain `false` counts.
fn is_disabled(text: &str) -> bool {
    text.lines().any(|line| {
        let Some((_, key, value)) = key_value(line) else {
            return false;
        };
        let value = compact(value.split(" #").next().unwrap_or_default());
        (key == "if" && (value == "false" || value == "${{false}}"))
            || (key == "continue-on-error" && value != "false")
    })
}

/// A condition without the spaces it is written with, so that how it is spaced does not matter.
/// The spaces inside a quoted string are part of the string, and stay.
fn compact(condition: &str) -> String {
    let mut quoted = false;
    condition
        .chars()
        .filter(|c| {
            if *c == '\'' {
                quoted = !quoted;
                return true;
            }
            quoted || !c.is_whitespace()
        })
        .collect()
}

/// A line of the workflow that reads `key: value`: how far in the key stands, counting the `- ` that
/// starts a step as indentation, the key without its quotes and the spaces before its colon, and
/// the rest of the line.
fn key_value(line: &str) -> Option<(usize, String, &str)> {
    let rest = line.trim_start();
    let indent = line.len() - rest.len();
    let (extra, rest) = match rest.strip_prefix("- ") {
        Some(after) => (
            2 + after.len() - after.trim_start().len(),
            after.trim_start(),
        ),
        None => (0, rest),
    };
    let (key, value) = rest.split_once(':')?;
    let key = key.trim().trim_matches(['\'', '"']);
    Some((indent + extra, key.to_owned(), value))
}

/// The `if` that the keys at `indent` carry in `text`, without the spaces and the trailing comment.
/// A step with none runs whenever its job does.
fn own_condition(text: &str, indent: usize) -> Option<String> {
    text.lines().find_map(|line| {
        let (at, key, value) = key_value(line)?;
        (at == indent && key == "if").then(|| compact(value.split(" #").next().unwrap_or_default()))
    })
}

/// The condition a job gives itself, if it has one.
fn job_condition(job: &str) -> Option<String> {
    own_condition(&header(job), 4)
}

/// The condition a step gives itself, if it has one.
fn step_condition(step: &str) -> Option<String> {
    own_condition(step, 8)
}

/// The steps a condition reads the outcome of (`steps.desktop-build.outcome`).
fn steps_named(condition: &str) -> Vec<String> {
    condition
        .split("steps.")
        .skip(1)
        .map(|after| {
            after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
                .collect()
        })
        .collect()
}

/// The matrix leg a condition names (`matrix.part == 'second'`), if it names one.
fn leg_named(condition: &str) -> Option<String> {
    let after = compact(condition)
        .split_once("matrix.part=='")?
        .1
        .to_owned();
    Some(after.split('\'').next()?.to_owned())
}

/// The `part` of each leg that the job's matrix includes: the line after a `- name:` entry.
fn legs(job: &str) -> Vec<String> {
    let lines: Vec<&str> = job.lines().collect();
    lines
        .windows(2)
        .filter(|pair| pair[0].trim_start().starts_with("- name:"))
        .filter_map(|pair| pair[1].trim().strip_prefix("part:"))
        .map(|part| part.trim().to_owned())
        .collect()
}

/// The lines of a workflow's `on:` block, past blank lines and comments, up to its next top-level
/// key.
fn trigger_lines(workflow: &str) -> Vec<&str> {
    workflow
        .lines()
        .skip_while(|line| *line != "on:")
        .skip(1)
        .take_while(|line| line.is_empty() || line.starts_with([' ', '#']))
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .collect()
}

/// The jobs a table of the conformance document's classes names, in backticks in its second column.
fn documented_jobs(document: &str) -> Vec<String> {
    let table: Vec<&str> = document
        .lines()
        .skip_while(|line| !line.starts_with("| Class | Job |"))
        .take_while(|line| line.starts_with('|'))
        .skip(2)
        .collect();
    assert!(!table.is_empty(), "the document has the table of classes");
    let mut jobs: Vec<String> = table
        .iter()
        .flat_map(|row| {
            row.split('|')
                .nth(2)
                .unwrap_or_default()
                .split('`')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect();
    jobs.sort();
    jobs.dedup();
    jobs
}

/// A class of test section 21 names, and what holds it in the workflow.
struct ClassOfTest {
    class: &'static str,
    job: &'static str,
    /// What the job's runner line holds, or its matrix.
    runner: &'static [&'static str],
    /// The job's `runs-on`, as the workflow writes it.
    runs_on: &'static str,
    /// The condition the job runs under, as the workflow writes it. `None` is a job that always
    /// runs.
    job_when: Option<&'static str>,
    /// What one step of the job runs.
    tool: &'static str,
    /// The condition each step that runs the tool carries, as the workflow writes it. `None` is a
    /// step that runs whenever its job does.
    when: Option<&'static str>,
}

const CLASSES: [ClassOfTest; 10] = [
    ClassOfTest {
        class: "browser behaviour, on both kinds of runner",
        job: "companion",
        runner: &["ubuntu-24.04", "macos-15"],
        runs_on: "${{ matrix.os }}",
        job_when: None,
        tool: "pnpm -C apps/companion e2e",
        when: None,
    },
    ClassOfTest {
        class: "native macOS controls",
        job: "companion",
        runner: &["macos-15"],
        runs_on: "${{ matrix.os }}",
        job_when: None,
        tool: "scripts/desktop-controls-macos.sh",
        when: Some(
            "${{ !cancelled() && runner.os == 'macOS' && steps.desktop-build.outcome == 'success' }}",
        ),
    },
    ClassOfTest {
        class: "the iOS Simulator, with Xcode",
        job: "ios",
        runner: &["runs-on: macos-15"],
        runs_on: "macos-15",
        job_when: Some("github.event_name != 'workflow_dispatch' || inputs.macos || inputs.ios"),
        tool: "scripts/ios-app-launch.sh",
        when: None,
    },
    ClassOfTest {
        class: "an Android emulator",
        job: "android-app",
        runner: &["runs-on: ubuntu-24.04"],
        runs_on: "ubuntu-24.04",
        job_when: None,
        tool: "scripts/android-app-launch.sh",
        when: None,
    },
    ClassOfTest {
        class: "a Windows machine's release build of the desktop application",
        job: "windows",
        runner: &["runs-on: windows-2025"],
        runs_on: "windows-2025",
        job_when: None,
        tool: "cargo build --locked -p companion-tauri --release",
        when: Some("${{ !cancelled() && matrix.part == 'first' }}"),
    },
    ClassOfTest {
        class: "the Tauri desktop application in a real window, on Windows",
        job: "windows",
        runner: &["runs-on: windows-2025"],
        runs_on: "windows-2025",
        job_when: None,
        tool: "cargo test --locked -p companion-tauri --test host_events",
        when: Some("${{ !cancelled() && matrix.part == 'second' }}"),
    },
    ClassOfTest {
        class: "the real-worker host tests, on a native Windows machine",
        job: "windows",
        runner: &["runs-on: windows-2025"],
        runs_on: "windows-2025",
        job_when: None,
        tool: "cargo test --locked -p kr-worker --test host",
        when: Some("${{ !cancelled() && matrix.part == 'second' }}"),
    },
    ClassOfTest {
        class: "the Tauri desktop application's native backend, on both kinds of unix runner",
        job: "companion",
        runner: &["ubuntu-24.04", "macos-15"],
        runs_on: "${{ matrix.os }}",
        job_when: None,
        tool: "cargo test --locked -p companion-tauri -p kr-client",
        when: None,
    },
    ClassOfTest {
        class: "a Linux machine",
        job: "rust",
        runner: &["runs-on: ubuntu-24.04"],
        runs_on: "ubuntu-24.04",
        job_when: None,
        tool: "cargo test --locked --workspace",
        when: None,
    },
    ClassOfTest {
        class: "a macOS machine",
        job: "macos",
        runner: &["runs-on: macos-15"],
        runs_on: "macos-15",
        job_when: Some("github.event_name != 'workflow_dispatch' || inputs.macos"),
        // The whole text of the step's command line, to its end, so that the whole-workspace step
        // holds the class and not a step that starts with the same words.
        tool: "cargo test --locked --workspace --exclude kr-sync-integration --no-fail-fast --",
        when: Some("${{ !cancelled() && matrix.part == 'tests' }}"),
    },
];

/// KR-REQ-21.01 and KR-REQ-27.02, the part a workflow can hold: each class of test section 21
/// names has a job in the landing workflow that runs its tool on a runner that has it, by a step
/// that is not disabled and that runs under the condition the workflow gives it, with the matrix
/// leg that condition names still in the matrix: Playwright for browser behaviour, the operating
/// system's own tooling for native controls and for the iOS Simulator on macOS, an Android
/// emulator for the Android phone, the Tauri desktop application's native backend on Linux and
/// macOS, its release build and its window on Windows, the real-worker host suite on a native
/// Windows machine, and the workspace's tests on a hosted Linux and macOS machine (the macOS step
/// leaves out one package and skips named cases). A step whose condition is never true, or true on
/// one kind of runner when its class names both, or whose leg is gone from the matrix, runs on no
/// runner and fails the case. The Windows job runs many more test steps than the two this case
/// holds. The conformance document's table names the same jobs. Physical devices are the person's
/// own and no workflow starts them.
#[test]
fn each_class_of_test_has_a_job_that_runs_its_tool_on_a_runner_that_has_it() {
    let workflow = fs::read_to_string(repository().join(".github/workflows/core-ci.yml"))
        .expect("the landing workflow");
    for ClassOfTest {
        class,
        job: name,
        runner,
        runs_on,
        job_when,
        tool,
        when,
    } in CLASSES
    {
        let text = job(&workflow, name);
        assert!(
            !is_disabled(&header(&text)),
            "{class}: the {name} job is disabled or lets its failure pass"
        );
        assert_eq!(
            job_condition(&text),
            job_when.map(compact),
            "{class}: the {name} job runs under a condition other than {job_when:?}"
        );
        assert_eq!(
            value_at(&text, 4, "runs-on").map(|runner| compact(&runner)),
            Some(compact(runs_on)),
            "{class}: the {name} job runs on a runner other than {runs_on}"
        );
        assert!(
            text.lines()
                .all(|line| key_value(line).is_none_or(|(_, key, _)| key != "exclude")),
            "{class}: the {name} job's matrix leaves a leg out"
        );
        assert!(
            header(&text)
                .lines()
                .all(|line| key_value(line)
                    .is_none_or(|(indent, key, _)| indent != 4 || key != "needs")),
            "{class}: the {name} job waits for another, which can leave it skipped"
        );
        for expected in runner {
            assert!(
                text.contains(expected),
                "{class}: the {name} job has no {expected}"
            );
        }
        for held in steps_running(&text, tool) {
            assert!(
                !is_disabled(&held),
                "{class}: a step that runs {tool} is disabled"
            );
            assert_eq!(
                step_condition(&held),
                when.map(compact),
                "{class}: a step that runs {tool} runs under a condition other than {when:?}"
            );
            if let Some(leg) = when.and_then(leg_named) {
                assert!(
                    legs(&text).contains(&leg),
                    "{class}: the {name} job's matrix has no {leg} leg, so a step that runs {tool} \
                     never runs"
                );
            }
            // A step the condition reads the outcome of is a step of the job that runs, and runs.
            for id in when.map(steps_named).unwrap_or_default() {
                let Some(at) = position_of_id(&text, &id) else {
                    panic!(
                        "{class}: no step of the {name} job has the id {id}, whose outcome decides \
                         whether the step that runs {tool} runs"
                    );
                };
                let named = &steps_of(&text)[at];
                assert!(
                    !is_disabled(named) && step_condition(named).is_none(),
                    "{class}: the step {id}, whose outcome decides whether the step that runs \
                     {tool} runs, is disabled or does not always run"
                );
                assert!(
                    position_of_tool(&text, tool).is_some_and(|tool_at| at < tool_at),
                    "{class}: the step {id} comes after the step that runs {tool}, which reads \
                     its outcome"
                );
            }
        }
    }

    // The landing workflow runs on every push to main and on every pull request, with no filter
    // that leaves a change out, and by hand: the first four lines of its `on:` block are these
    // exactly, and what follows them is the manual run's inputs.
    let triggers = trigger_lines(&workflow);
    assert_eq!(
        triggers.get(..4),
        Some(
            &[
                "  push:",
                "    branches: [\"main\"]",
                "  pull_request:",
                "  workflow_dispatch:",
            ][..]
        ),
        "the landing workflow does not run on a push to main, a pull request without a filter and \
         by hand, as its first triggers"
    );
    assert!(
        triggers[4..].iter().all(|line| line.starts_with("    ")),
        "the landing workflow has a trigger besides push, pull_request and workflow_dispatch"
    );

    // KR-REQ-27.03: what each of the jobs that drive a device or a browser keeps, and what refuses
    // a run that kept nothing.
    let companion = job(&workflow, "companion");
    assert!(
        !is_disabled(&header(&companion)),
        "the companion job is disabled or lets its failure pass"
    );
    // Both runners on every push and pull request: a manual run started with the macOS jobs turned
    // off may leave the macOS leg out, and nothing else may.
    let runners = value_at(&companion, 8, "os")
        .map(|runners| compact(&runners))
        .expect("the companion job's matrix names its runners");
    assert_eq!(
        runners,
        compact(
            "${{ fromJSON(github.event_name == 'workflow_dispatch' && !inputs.macos && \
             '[\"ubuntu-24.04\"]' || '[\"ubuntu-24.04\", \"macos-15\"]') }}"
        ),
        "the companion job's matrix takes both runners on every run but a manual one without macOS"
    );
    for guard in steps_running(&companion, "scripts/check-test-evidence.sh") {
        assert!(!is_disabled(&guard), "the evidence check is disabled");
        assert_eq!(
            step_condition(&guard),
            None,
            "the evidence check does not run on every runner of the matrix"
        );
    }
    for (job_name, artefact, path, writer) in [
        (
            "companion",
            "companion-evidence-",
            "/tmp/kr-test-artifacts",
            "scripts/desktop-controls-macos.sh",
        ),
        (
            "android-app",
            "test-evidence-android",
            "${{ env.KR_TEST_ARTIFACTS_DIR }}",
            "scripts/android-app-launch.sh",
        ),
        (
            "ios",
            "test-evidence-ios",
            "${{ env.KR_TEST_ARTIFACTS_DIR }}",
            "scripts/ios-app-launch.sh",
        ),
    ] {
        let text = job(&workflow, job_name);
        assert!(
            !is_disabled(&header(&text)),
            "the {job_name} job is disabled or lets its failure pass"
        );
        for upload in steps_holding(&text, &format!("name: {artefact}")) {
            assert_eq!(
                value_at(&upload, 10, "if-no-files-found").as_deref(),
                Some("error"),
                "the {job_name} job's upload of {artefact} does not fail when it kept nothing"
            );
            assert!(
                !is_disabled(&upload),
                "the {job_name} job's upload of {artefact} is disabled or lets its failure pass"
            );
            assert_eq!(
                step_condition(&upload),
                Some(compact("${{ !cancelled() }}")),
                "the {job_name} job's upload of {artefact} does not run on every runner whether \
                 the job passed or failed"
            );
            assert!(
                !upload.contains("retention-days"),
                "the {job_name} job's upload of {artefact} sets a retention of its own, which \
                 can keep the evidence for less than the repository's default"
            );
            // After the step that writes last, or the upload leaves that step's files behind.
            let placed = steps_of(&text)
                .iter()
                .position(|step| step.contains(&format!("name: {artefact}")))
                .expect("the upload is a step of the job");
            assert!(
                position_of_tool(&text, writer).is_some_and(|written| written < placed),
                "the {job_name} job's upload of {artefact} comes before the step that runs \
                 {writer}, which writes after it"
            );
            // The action that uploads, and the directory it uploads: the one the tests write to.
            assert!(
                value_at(&upload, 8, "uses")
                    .is_some_and(|action| action.starts_with("actions/upload-artifact@")),
                "the {job_name} job's upload of {artefact} is not made by the upload action"
            );
            assert_eq!(
                value_at(&upload, 10, "path").map(|found| compact(&found)),
                Some(compact(path)),
                "the {job_name} job's upload of {artefact} keeps a directory other than {path}"
            );
        }
    }

    // The conformance document's table of classes names the jobs the test above holds, and only
    // them.
    let document = fs::read_to_string(repository().join("docs/conformance/README.md"))
        .expect("the conformance document");
    let mut held: Vec<String> = CLASSES.iter().map(|class| class.job.to_owned()).collect();
    held.sort();
    held.dedup();
    assert_eq!(
        documented_jobs(&document),
        held,
        "the conformance document's table of classes names the jobs the workflow's test holds"
    );
}

/// KR-REQ-27.02, the WSL2 run: the release's WSL2 acceptance has a workflow of its own, started by
/// hand and by nothing else, that runs the acceptance script on a hosted Windows machine by a step
/// that is not disabled, because the landing workflow does not carry it. The Linux set that
/// acceptance installs is built by a job of its own on a hosted Linux machine, kept, and fetched
/// by the acceptance, each by a step that is not disabled and runs whenever its job does, and the
/// conformance document says where the workflow is.
#[test]
fn the_wsl2_acceptance_has_a_workflow_that_runs_its_script_on_windows() {
    let workflow = fs::read_to_string(repository().join(".github/workflows/wsl-acceptance.yml"))
        .expect("the WSL2 acceptance workflow");
    let triggers = trigger_lines(&workflow);
    assert_eq!(
        triggers.first().copied(),
        Some("  workflow_dispatch:"),
        "the WSL2 acceptance is started by hand and by nothing else"
    );
    assert!(
        triggers[1..].iter().all(|line| line.starts_with("    ")),
        "the WSL2 acceptance has a trigger besides workflow_dispatch"
    );
    let text = job(&workflow, "acceptance");
    assert!(
        !is_disabled(&header(&text)),
        "the acceptance job is disabled or lets its failure pass"
    );
    assert_eq!(
        job_condition(&text),
        None,
        "the acceptance job runs under a condition"
    );
    assert!(
        text.contains("runs-on: windows-2025"),
        "the acceptance job has no hosted Windows runner"
    );
    for held in steps_running(&text, "scripts/e2e-wsl.sh") {
        assert!(
            !is_disabled(&held),
            "the step that runs the WSL2 acceptance is disabled"
        );
        assert_eq!(
            step_condition(&held),
            None,
            "the step that runs the WSL2 acceptance runs under a condition"
        );
    }

    // The set the acceptance installs in its distribution: built, kept and fetched.
    assert!(
        text.contains("needs: linux-set"),
        "the acceptance does not wait for the Linux set"
    );
    let set = job(&workflow, "linux-set");
    assert!(
        !is_disabled(&header(&set)),
        "the Linux set's job is disabled or lets its failure pass"
    );
    assert_eq!(
        job_condition(&set),
        None,
        "the Linux set's job runs under a condition"
    );
    assert!(
        set.contains("runs-on: ubuntu-24.04"),
        "the Linux set is not built on a hosted Linux machine"
    );
    for built in steps_running(&set, "cargo build --locked -p kr-cli") {
        assert!(
            !is_disabled(&built),
            "the step that builds the set is disabled"
        );
        assert_eq!(
            step_condition(&built),
            None,
            "the step that builds the set runs under a condition"
        );
    }
    for kept in steps_holding(&set, "name: wsl-linux-set") {
        assert!(
            !is_disabled(&kept),
            "the step that keeps the set is disabled"
        );
        assert_eq!(
            step_condition(&kept),
            None,
            "the step that keeps the set runs under a condition"
        );
        assert!(
            value_at(&kept, 8, "uses")
                .is_some_and(|action| action.starts_with("actions/upload-artifact@")),
            "the step that keeps the set is not made by the upload action"
        );
        assert_eq!(
            value_at(&kept, 10, "if-no-files-found").as_deref(),
            Some("error"),
            "the step that keeps the set does not fail when it kept nothing"
        );
    }
    for fetched in steps_holding(&text, "name: wsl-linux-set") {
        assert!(
            !is_disabled(&fetched),
            "the step that fetches the set is disabled"
        );
        assert_eq!(
            step_condition(&fetched),
            None,
            "the step that fetches the set runs under a condition"
        );
        assert!(
            value_at(&fetched, 8, "uses")
                .is_some_and(|action| action.starts_with("actions/download-artifact@")),
            "the step that fetches the set is not made by the download action"
        );
    }

    let document = fs::read_to_string(repository().join("docs/conformance/README.md"))
        .expect("the conformance document");
    assert!(
        document.contains("`wsl-acceptance`, started by hand"),
        "the conformance document does not say where the WSL2 acceptance is"
    );
}

/// The tests that start a daemon through the user's service manager stand down, and pass, on a
/// machine that has none. The Linux runs that report on the workspace's tests set
/// `KR_REQUIRE_SERVICE_MANAGER`, which turns that standing down into a failure, so that a runner
/// without a manager does not report those tests as passed without having run them.
#[test]
fn the_linux_runs_of_the_workspace_tests_require_a_user_service_manager() {
    let variable = "KR_REQUIRE_SERVICE_MANAGER: \"1\"";
    let landing = fs::read_to_string(repository().join(".github/workflows/core-ci.yml"))
        .expect("the landing workflow");
    let tests = steps_running(&job(&landing, "rust"), "cargo test --locked --workspace");
    assert!(
        tests
            .iter()
            .all(|step| step.lines().any(|line| line.trim() == variable)),
        "the step of the landing workflow's rust job that runs the workspace's tests does not \
         require a user service manager"
    );
    let report = fs::read_to_string(repository().join(".github/workflows/conformance.yml"))
        .expect("the conformance workflow");
    // Among the job's own keys, in its environment ahead of its steps, so that every step that runs
    // tests has it.
    assert!(
        header(&job(&report, "linux"))
            .lines()
            .any(|line| line.trim() == variable),
        "the Linux job of the conformance workflow does not require a user service manager in its \
         own environment"
    );
}

/// The names of a workflow's jobs, in file order: the keys at two spaces in the `jobs:` block, which
/// ends at the next line at the left margin. A key there that is not a name and a colon alone (an
/// anchor or a mapping on the same line) is a layout this file's reading does not hold, and fails.
fn jobs_of(workflow: &str) -> Vec<String> {
    workflow
        .lines()
        .skip_while(|line| without_comment(line) != "jobs:")
        .skip(1)
        .take_while(|line| line.is_empty() || line.starts_with([' ', '#']))
        .map(without_comment)
        .filter(|line| {
            line.starts_with("  ") && !line.starts_with("   ") && !line.trim().is_empty()
        })
        .filter(|line| !line.trim_start().starts_with('#'))
        .map(|line| {
            line.strip_prefix("  ")
                .and_then(|key| key.strip_suffix(':'))
                .unwrap_or_else(|| panic!("a job header the case cannot read: {line:?}"))
                .to_owned()
        })
        .collect()
}

/// The report builds every suite's test programs in turn into one directory, with no build cache,
/// and the debug information is the greater part of what that directory holds. A run of the
/// Windows job that built with it filled the drive near the end, and the last two suites failed to
/// build. Each job of the conformance workflow, like the landing workflow, builds without it.
#[test]
fn every_job_of_the_conformance_workflow_builds_without_debug_information() {
    let report = fs::read_to_string(repository().join(".github/workflows/conformance.yml"))
        .expect("the conformance workflow");
    let names = jobs_of(&report);
    assert!(!names.is_empty(), "the conformance workflow has no job");
    for name in &names {
        // Among the job's own keys, in its environment ahead of its steps, so that every step that
        // builds has it.
        let keys = header(&job(&report, name));
        for variable in [
            "CARGO_PROFILE_DEV_DEBUG: \"0\"",
            "CARGO_PROFILE_TEST_DEBUG: \"0\"",
        ] {
            assert!(
                keys.lines().any(|line| line.trim() == variable),
                "the {name} job of the conformance workflow does not set {variable} in its own \
                 environment"
            );
        }
    }
}

/// The variable that names the one directory every test artefact of a run is kept in. Its name is
/// written in two pieces, so that this file's own lines name it only in comments and in the held
/// list, and the case reads this file as it reads every other.
const VARIABLE: &str = concat!("KR_TEST_", "ARTIFACTS_DIR");

/// How a value may begin and still lie in a temporary folder: `/tmp`, or the runner's or the
/// platform's temporary folder, spelled as a shell, PowerShell and the workflow syntax spell it. A
/// shell's `$TMPDIR` alone is not here, since a shell that has none gives `/`: it needs a default,
/// which `lies_in_a_temporary_folder` reads.
const TEMPORARY_FOLDERS: [&str; 7] = [
    "/tmp/",
    "$RUNNER_TEMP",
    "${RUNNER_TEMP}",
    "$env:RUNNER_TEMP",
    "${{ runner.temp }}",
    "$env:TEMP",
    "$env:TMP",
];

/// The tools that take a screenshot, by the name a workflow step runs them under.
const SCREENSHOT_TOOLS: [&str; 12] = [
    "check-test-evidence.sh",
    "desktop-controls-macos.sh",
    "android-app-launch.sh",
    "ios-app-launch.sh",
    "e2e-permissions.sh",
    "e2e-pairing-device.sh",
    "e2e-mobile.sh",
    "e2e-voice-device.sh",
    "e2e-voice-call-device.sh",
    "e2e-push-device.sh",
    "e2e-update.sh",
    "playwright",
];

/// Whether `value` begins with the folder `folder`, as a whole name and not as the start of a longer
/// one (`$env:TEMP` is not `$env:TEMPLATES`).
fn begins_with_folder(value: &str, folder: &str) -> bool {
    value.strip_prefix(folder).is_some_and(|rest| {
        folder.ends_with('/') || rest.is_empty() || rest.starts_with(['/', '\\'])
    })
}

/// The name and the default of a value that begins with `${NAME:-default}`.
fn expansion_default(value: &str) -> Option<(&str, String)> {
    let (name, after) = value.strip_prefix("${")?.split_once(":-")?;
    (!name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then(|| (name, after.chars().take_while(|c| *c != '}').collect()))
}

/// `value` with the quotes around it taken off.
fn unquoted(value: &str) -> &str {
    value.trim().trim_matches(['"', '\''])
}

/// The value at the start of `rest`: a quoted one to its closing quote, an unquoted one to the next
/// space, a command substitution inside either read whole.
fn leading_value(rest: &str) -> String {
    let quoted = rest.starts_with('"');
    let mut value = String::new();
    let mut depth = 0_usize;
    let mut characters = rest.chars().skip(usize::from(quoted)).peekable();
    while let Some(character) = characters.next() {
        match character {
            '$' if characters.peek() == Some(&'(') => {
                depth += 1;
                value.push(character);
                value.extend(characters.next());
            }
            ')' if depth > 0 => {
                depth -= 1;
                value.push(character);
            }
            '"' if depth == 0 => break,
            ' ' | '\t' if depth == 0 && !quoted => break,
            _ => value.push(character),
        }
    }
    value
}

/// The name of the variable a value begins with, in a shell's (`$name`, `${name`) or PowerShell's
/// (`$name`) spelling. `$env:` and `$(` begin no name.
fn leading_variable(value: &str) -> Option<&str> {
    let rest = value
        .strip_prefix("${")
        .or_else(|| value.strip_prefix('$'))?;
    let end = rest
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(rest.len());
    (end > 0).then(|| &rest[..end])
}

/// Every non-empty value `text` gives the variable `name`, in a shell's spelling (`name=value`) or
/// PowerShell's (`$name = value`).
fn values_of(text: &str, name: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            let line = ["local ", "export ", "readonly "]
                .iter()
                .find_map(|word| line.strip_prefix(word))
                .unwrap_or(line);
            let rest = line
                .strip_prefix(&format!("{name}="))
                .or_else(|| line.strip_prefix(&format!("${name} = ")))
                .or_else(|| line.strip_prefix(&format!("${name}=")))?;
            let value = if let Some(command) = rest.strip_prefix("Join-Path ") {
                command
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            } else if let Some(command) = rest.strip_prefix("(Get-Item ") {
                command.split(')').next().unwrap_or_default().to_owned()
            } else {
                leading_value(rest)
            };
            (!value.is_empty()).then_some(value)
        })
        .collect()
}

/// Whether `value` is made from the variable's own value: the variable itself, or the two commands
/// that make its path absolute or a Windows path a POSIX one. The value it is made from is the one
/// the held list shows where it was given.
fn derived_from_itself(value: &str) -> bool {
    [
        format!("${VARIABLE}"),
        format!("${{{VARIABLE}}}"),
        format!("$env:{VARIABLE}"),
        format!("$(cygpath -u \"${VARIABLE}\")"),
        format!("$(cd \"${VARIABLE}\" && pwd)"),
    ]
    .iter()
    .any(|own| own == value)
        || value.starts_with(&format!("${VARIABLE}/"))
        || value.starts_with(&format!("${{{VARIABLE}}}/"))
}

/// Whether `value`, as a script or a workflow writes it, lies in a temporary folder: it begins with
/// one, or with the default that a `${NAME:-default}` falls back on, or with a command that makes a
/// directory in one, or with another variable that `text` gives a value, every one of which does. A
/// value made from the variable's own value is the one checked where that was given. A step up
/// (`..`) is never inside.
fn lies_in_a_temporary_folder(value: &str, text: &str, depth: usize) -> bool {
    let value = unquoted(value);
    if depth == 0 || value.is_empty() || value.split(['/', '\\']).any(|part| part == "..") {
        return false;
    }
    if derived_from_itself(value) {
        return true;
    }
    if let Some((name, default)) = expansion_default(value) {
        // The variable's own default is the one to check; a folder variable's default may be `/tmp`
        // itself, which a path under it then extends; any other name is also read where `text` gives
        // it a value, since that value is what the expansion yields when it is set.
        let in_a_folder = lies_in_a_temporary_folder(&default, text, depth - 1);
        return if name == VARIABLE {
            default.is_empty() || in_a_folder
        } else if ["TMPDIR", "RUNNER_TEMP", "TEMP", "TMP"].contains(&name) {
            default == "/tmp" || in_a_folder
        } else {
            let values = values_of(text, name);
            in_a_folder
                && !values.is_empty()
                && values
                    .iter()
                    .all(|value| lies_in_a_temporary_folder(value, text, depth - 1))
        };
    }
    if TEMPORARY_FOLDERS
        .iter()
        .any(|folder| begins_with_folder(value, folder))
    {
        return true;
    }
    if value.starts_with("$(")
        && let Some(after) = value.split("mktemp").nth(1)
    {
        let mut rest = after.trim_start();
        while rest.starts_with('-') {
            rest = rest
                .split_once(char::is_whitespace)
                .map_or("", |(_, tail)| tail);
            rest = rest.trim_start();
        }
        return lies_in_a_temporary_folder(&leading_value(rest), text, depth - 1);
    }
    leading_variable(value).is_some_and(|name| {
        let values = values_of(text, name);
        !values.is_empty()
            && values
                .iter()
                .all(|value| lies_in_a_temporary_folder(value, text, depth - 1))
    })
}

/// Every file under `directory` whose name ends in one of `endings`.
fn files_ending(directory: &Path, endings: &[&str], found: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("{} is read: {error}", directory.display()))
        .map(|entry| entry.expect("an entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            files_ending(&path, endings, found);
        } else if endings
            .iter()
            .any(|ending| path.to_string_lossy().ends_with(ending))
        {
            found.push(path);
        }
    }
}

/// Whether a step's own `if` is the constant false, so that the step never runs. A step that may
/// fail without stopping the job (`continue-on-error`) still runs.
fn never_runs(step: &str) -> bool {
    step.lines().any(|line| {
        let Some((_, key, value)) = key_value(line) else {
            return false;
        };
        let value = compact(value.split(" #").next().unwrap_or_default());
        key == "if" && (value == "false" || value == "${{false}}")
    })
}

/// The value a line gives the variable in a workflow: an entry of an `env` (`NAME: value`) or an
/// assignment (`NAME=value`, after `export`, in front of a command, or inside the quoted line a
/// PowerShell step writes to the job's environment file). A comment gives none. This is read only
/// to tell whether a step has the variable; the values themselves are the held list's.
fn artifacts_assignment(line: &str) -> Option<String> {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    if let Some(rest) = line.strip_prefix(&format!("{VARIABLE}:")) {
        return Some(unquoted(without_comment(rest)).to_owned());
    }
    let at = line.find(&format!("{VARIABLE}="))?;
    Some(leading_value(&line[at + VARIABLE.len() + 1..]))
}

/// The file that holds the held list: the lines between the two markers below are the list's own
/// text, and they are let through as data.
const THIS_FILE: &str = "tests/conformance/tests/ci_evidence.rs";
const HELD_OPENS: &str = "const HELD: &str = r##\"";
const HELD_CLOSES: &str = "\"##;";

/// What a held entry holds.
#[derive(Clone, Copy, PartialEq)]
enum Kind {
    /// A line that gives the variable a value: the value stands right after the name.
    Write,
    /// A line that hands a value to a program as an argument; the value is a word of the line.
    Argument,
    /// A line that cannot run and that no line rule lets through.
    Comment,
}

/// How an entry shows that its value lies in a temporary folder.
enum Proof {
    /// By the text of the entry's own lines: the value begins with a temporary folder, or with a
    /// variable that one of those lines gives such a value.
    Text,
    /// By a line of the entry that makes a temporary directory, for a value in a language whose
    /// expressions the case does not follow.
    Folder(String),
    /// By a reason, stated in the entry, that it lies elsewhere or comes from outside.
    Reason,
}

/// One entry of the held list: where the lines stand, what they give, and why that is allowed.
struct Held {
    file: String,
    kind: Kind,
    /// Blocks of consecutive lines, in the order they stand in the file; the last line of the last
    /// block is the held line, and the others define what its value names.
    parts: Vec<Vec<String>>,
    value: String,
    proof: Proof,
}

impl Held {
    fn held_line(&self) -> &str {
        self.parts
            .last()
            .and_then(|part| part.last())
            .map_or("", String::as_str)
    }

    /// Every line of the entry but the held one.
    fn definitions(&self) -> Vec<&str> {
        let all: Vec<&str> = self.parts.iter().flatten().map(String::as_str).collect();
        all[..all.len() - 1].to_vec()
    }
}

fn parse_entry(lines: &[&str]) -> Held {
    let (mut file, mut kind, mut value) = (None, Kind::Write, String::new());
    let (mut folder, mut why) = (None, None);
    let mut parts: Vec<Vec<String>> = vec![Vec::new()];
    for line in lines {
        if let Some(rest) = line.strip_prefix("file:") {
            file = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("kind:") {
            kind = match rest.trim() {
                "argument" => Kind::Argument,
                "comment" => Kind::Comment,
                other => panic!("an entry of the held list has the kind {other}"),
            };
        } else if let Some(rest) = line.strip_prefix("value:") {
            value = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("folder:") {
            folder = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("why:") {
            why = Some(rest.trim().to_owned());
        } else if *line == "..." {
            parts.push(Vec::new());
        } else if let Some(rest) = line.strip_prefix("| ") {
            parts
                .last_mut()
                .expect("a part")
                .push(rest.trim().to_owned());
        } else {
            panic!("a line of the held list that is none of its forms: {line}");
        }
    }
    let file = file.unwrap_or_else(|| panic!("an entry of the held list names no file: {lines:?}"));
    assert!(
        parts.iter().all(|part| !part.is_empty()),
        "an entry of the held list for {file} has an empty block"
    );
    assert!(
        kind == Kind::Comment || !value.is_empty(),
        "an entry of the held list for {file} gives no value"
    );
    let proof = match (folder, why) {
        (None, None) => Proof::Text,
        (Some(folder), None) => Proof::Folder(folder),
        (None, Some(why)) if !why.is_empty() => Proof::Reason,
        _ => panic!("an entry of the held list for {file} has no single, non-empty proof"),
    };
    assert!(
        kind != Kind::Comment || matches!(proof, Proof::Reason),
        "a comment entry of the held list for {file} states its reason"
    );
    Held {
        file,
        kind,
        parts,
        value,
        proof,
    }
}

/// The entries of a held list: paragraphs set apart by blank lines.
fn parse_held(text: &str) -> Vec<Held> {
    let mut held = Vec::new();
    let mut paragraph: Vec<&str> = Vec::new();
    for line in text.lines().map(str::trim).chain([""]) {
        if !line.is_empty() {
            paragraph.push(line);
        } else if !paragraph.is_empty() {
            held.push(parse_entry(&paragraph));
            paragraph.clear();
        }
    }
    held
}

/// Where the entry's last line stands in `lines`: every block of the entry stands in exactly one
/// place, after the block before it.
fn locate(entry: &Held, lines: &[&str]) -> Result<Vec<(usize, usize)>, String> {
    let mut next = 0;
    let mut spans = Vec::new();
    for part in &entry.parts {
        let stands: Vec<usize> = if lines.len() < part.len() {
            Vec::new()
        } else {
            (0..=lines.len() - part.len())
                .filter(|start| {
                    part.iter()
                        .enumerate()
                        .all(|(offset, held)| lines[start + offset].trim() == held)
                })
                .collect()
        };
        match stands.as_slice() {
            [] => return Err(format!("no line stands as `{}`", part[0])),
            [only] if *only >= next => {
                spans.push((*only, only + part.len()));
                next = only + part.len();
            }
            [_] => return Err(format!("`{}` stands above a line it must follow", part[0])),
            many => return Err(format!("`{}` stands in {} places", part[0], many.len())),
        }
    }
    Ok(spans)
}

/// What may stand between the name and the value it is given (`=`, `="`, `: `, `:-`, `", `,
/// `'] ?? '`), and what may end the value.
const GAP: [char; 10] = ['"', '\'', '=', ':', '-', ',', ']', '?', ' ', '['];
const VALUE_ENDS: [char; 14] = [
    ' ', '\t', '"', '\'', ')', '}', ';', ',', '&', '|', '\\', '`', '<', '>',
];

fn is_word(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

/// The span of `value` in `line` from `start`, when it is a whole value and not the start of a longer
/// one (`/tmp/a` is not the start of `/tmp/a/../b`).
fn delimited(line: &str, start: usize, value: &str) -> Option<(usize, usize)> {
    let rest = line.get(start..)?.strip_prefix(value)?;
    (rest
        .chars()
        .next()
        .is_none_or(|character| VALUE_ENDS.contains(&character))
        && !rest.split_whitespace().next().unwrap_or("").contains(".."))
    .then_some((start, start + value.len()))
}

/// The span of `value` where the name at `at` is given it: the value stands after nothing but the
/// punctuation of a write.
fn bound_value(line: &str, at: usize, value: &str) -> Option<(usize, usize)> {
    let end = at + VARIABLE.len();
    let after = &line[end..];
    let start = end + after.len() - after.trim_start_matches(GAP).len();
    (start > end)
        .then(|| delimited(line, start, value))
        .flatten()
}

/// The span of `value` where an argument's line holds it as a word of its own.
fn argument_span(line: &str, value: &str) -> Option<(usize, usize)> {
    line.match_indices(value).find_map(|(start, _)| {
        let word_start = line[..start]
            .chars()
            .next_back()
            .is_none_or(|character| !is_word(character));
        word_start.then(|| delimited(line, start, value)).flatten()
    })
}

/// Where the name stands in `line`, in any letter case.
fn occurrences(line: &str) -> Vec<usize> {
    line.to_ascii_lowercase()
        .match_indices(&VARIABLE.to_ascii_lowercase())
        .map(|(at, _)| at)
        .collect()
}

/// Whether the name at `at` is a read, by the closed list of read forms: a whole name that is
///
/// - in a workflow expression, `${{ env.NAME }}`;
/// - in PowerShell, `$env:NAME` not followed by an assignment;
/// - a shell expansion that gives no value: `$NAME`, `${NAME}`, `${NAME:?...}`, `${NAME:+...}` and
///   `${NAME:-}` with an empty default (a default with text gives a value and is a write);
/// - the argument of Rust's `env::var` or `env::var_os`;
/// - alone on an `export` line, which gives the variable no new value.
fn is_a_read(line: &str, at: usize) -> bool {
    let (before, after) = (&line[..at], &line[at + VARIABLE.len()..]);
    if before.chars().next_back().is_some_and(is_word) || after.chars().next().is_some_and(is_word)
    {
        return false;
    }
    let lower = before.to_ascii_lowercase();
    let rest = after.trim_start();
    if lower.ends_with("${{ env.") {
        after.starts_with(" }}")
    } else if lower.ends_with("$env:") {
        // Whatever follows an assignment operator, a default (`??`), a list (`,`) or a line
        // continuation (a backtick) may give the variable a value.
        !["=", "+=", "-=", "*=", "/=", "%=", "??", ",", "`"]
            .iter()
            .any(|start| rest.starts_with(start))
    } else if before.ends_with("${") {
        after.starts_with('}')
            || after.starts_with(":?")
            || after.starts_with(":+")
            || after.starts_with(":-}")
    } else if before.ends_with('$') {
        !rest.starts_with('=')
    } else if before.ends_with("env::var_os(\"") || before.ends_with("env::var(\"") {
        after.starts_with("\")")
    } else {
        before.trim() == "export" && after.trim().is_empty()
    }
}

/// The name of the constant that a line makes of the variable's name (`const NAME: &str = "..."`).
fn alias_of(line: &str) -> Option<String> {
    let mut line = line.trim();
    for word in ["pub(crate) ", "pub "] {
        line = line.strip_prefix(word).unwrap_or(line);
    }
    let rest = line
        .strip_prefix("const ")
        .or_else(|| line.strip_prefix("static "))?;
    let (name, after) = rest.split_once(':')?;
    let literal = after
        .trim()
        .strip_prefix("&str")?
        .trim()
        .strip_prefix('=')?
        .trim()
        .strip_prefix('"')?
        .strip_suffix("\";")?;
    literal
        .eq_ignore_ascii_case(VARIABLE)
        .then(|| name.trim().to_owned())
}

/// Where the constant `name` stands in `line` as a word of its own.
fn word_positions(line: &str, name: &str) -> Vec<usize> {
    line.match_indices(name)
        .map(|(at, _)| at)
        .filter(|at| {
            !line[..*at].chars().next_back().is_some_and(is_word)
                && !line[at + name.len()..].chars().next().is_some_and(is_word)
        })
        .collect()
}

/// Which lines of a file cannot run, by these rules and no others:
///
/// - a line whose first characters are `#`, in `.sh`, `.bash`, `.yml`, `.yaml`, `.py` and `.ps1`
///   files, where a line that starts so is a comment to the end;
/// - a line whose first characters are `//` (so `///` and `//!` too), in `.rs`, `.ts`, `.tsx`,
///   `.js` and `.mjs` files, except the lines of a code block in a doc comment, which the Rust
///   documentation tests compile and run;
/// - a line of a `.md` file outside a fenced code block and not indented as code, which is prose.
///
/// A line that starts a comment and goes on does not start with these characters, and a line that
/// ends a block comment starts with `*` or `*/`: neither is let through.
fn lines_that_cannot_run(path: &str, lines: &[&str]) -> Vec<bool> {
    let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
    let mut fenced = false;
    lines
        .iter()
        .map(|line| {
            let trimmed = line.trim_start();
            match extension {
                "sh" | "bash" | "yml" | "yaml" | "py" | "ps1" => {
                    trimmed.starts_with('#')
                        && !trimmed.starts_with("#>")
                        && !trimmed.starts_with("#!")
                }
                "rs" | "ts" | "tsx" | "js" | "mjs" => {
                    let doc = trimmed
                        .strip_prefix("///")
                        .or_else(|| trimmed.strip_prefix("//!"));
                    if let Some(body) = doc {
                        let marker = body.trim_start();
                        if marker.starts_with("```") || marker.starts_with("~~~") {
                            fenced = !fenced;
                            return true;
                        }
                        return !fenced && !body.starts_with("    ") && !body.starts_with('\t');
                    }
                    trimmed.starts_with("//")
                }
                "md" => {
                    if line.len() - trimmed.len() < 4
                        && (trimmed.starts_with("```") || trimmed.starts_with("~~~"))
                    {
                        fenced = !fenced;
                        return true;
                    }
                    !fenced && !line.starts_with("    ") && !line.starts_with('\t')
                }
                _ => false,
            }
        })
        .collect()
}

/// The lines of this file that are the held list: between the line that opens it and the line that
/// closes it, and equal to the list that the program holds, so that every line let through is data.
fn held_region(lines: &[&str], held_text: &str) -> Result<std::ops::Range<usize>, String> {
    let opens: Vec<usize> = (0..lines.len())
        .filter(|index| lines[*index].trim() == HELD_OPENS)
        .collect();
    let [open] = opens.as_slice() else {
        return Err(format!(
            "{THIS_FILE} has {} lines that open the held list, not one",
            opens.len()
        ));
    };
    let close = lines[open + 1..]
        .iter()
        .position(|line| line.trim() == HELD_CLOSES)
        .map(|offset| open + 1 + offset)
        .ok_or_else(|| format!("{THIS_FILE} does not close the held list"))?;
    let expected: Vec<&str> = held_text.lines().skip(1).collect();
    if lines[open + 1..close] != expected[..] {
        return Err(format!(
            "the lines between the held list's markers in {THIS_FILE} are not the held list"
        ));
    }
    Ok(open + 1..close)
}

/// Whether a file's bytes name the variable in any letter case, or in UTF-16, which PowerShell reads
/// and which has a zero byte beside each letter: with the zero bytes left out the letters stand
/// together.
fn names_the_variable(bytes: &[u8]) -> bool {
    let letters: Vec<u8> = if bytes.contains(&0) {
        bytes.iter().copied().filter(|byte| *byte != 0).collect()
    } else {
        bytes.to_vec()
    };
    String::from_utf8_lossy(&letters.to_ascii_lowercase()).contains(&VARIABLE.to_ascii_lowercase())
}

/// The variable a line gives a value in a shell's spelling (`name=`, after `export`, `local`,
/// `readonly`, `declare` or `typeset`) or PowerShell's (`$name =`).
fn assigned_name(line: &str) -> Option<&str> {
    let mut line = line.trim();
    for word in ["export ", "local ", "readonly ", "declare ", "typeset "] {
        line = line.strip_prefix(word).unwrap_or(line);
    }
    let powershell = line.starts_with('$');
    let line = line.strip_prefix('$').unwrap_or(line);
    let (name, rest) = line.split_at(line.find(|character: char| !is_word(character))?);
    let assigns = rest.starts_with('=') && !rest.starts_with("==")
        || rest.starts_with("+=")
        || powershell && rest.trim_start().starts_with('=');
    (!name.is_empty() && assigns).then_some(name)
}

/// Whether a line gives `name` a value in one of the ordinary shell and PowerShell ways.
fn gives_value_to(line: &str, name: &str) -> bool {
    let line = line.trim();
    assigned_name(line) == Some(name)
        || line.contains(&format!("${{{name}:="))
        || line.contains(&format!("${{{name}="))
        || line.starts_with(&format!("for {name} in "))
        || (line.starts_with("read ") && line.split_whitespace().any(|word| word == name))
        || line.contains(&format!(" -v {name} "))
}

/// The lines that stand between two blocks of an entry and give a variable that an earlier block
/// gives a value another one: the text hold of the blocks would not see them.
fn redefinitions(entry: &Held, lines: &[&str], spans: &[(usize, usize)]) -> Vec<String> {
    let mut problems = Vec::new();
    for (gap, pair) in spans.windows(2).enumerate() {
        let names: Vec<&str> = entry.parts[..=gap]
            .iter()
            .flatten()
            .filter_map(|line| assigned_name(line))
            .collect();
        for (number, line) in lines.iter().enumerate().take(pair[1].0).skip(pair[0].1) {
            for name in &names {
                if gives_value_to(line, name) {
                    problems.push(format!(
                        "{}:{}: a line between the held lines of an entry gives {name} another \
                         value: {}",
                        entry.file,
                        number + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    problems
}

/// What is wrong with an entry's proof that its value lies in a temporary folder.
fn proof_problem(entry: &Held) -> Option<String> {
    let label = format!("held entry for {} ({})", entry.file, entry.held_line());
    match (&entry.kind, &entry.proof) {
        (Kind::Comment, _) | (_, Proof::Reason) => None,
        (_, Proof::Folder(folder)) => {
            let makes_one = ["TempDir::new(", "tempdir(", "env::temp_dir()"]
                .iter()
                .any(|maker| folder.contains(maker));
            (!(makes_one && entry.definitions().contains(&folder.as_str()))).then(|| {
                format!("{label}: the folder line is not a line of the entry that makes a temporary directory")
            })
        }
        (_, Proof::Text) => {
            (!lies_in_a_temporary_folder(&entry.value, &entry.definitions().join("\n"), 6)).then(
                || {
                    format!(
                        "{label}: the value {} does not lie in a temporary folder",
                        entry.value
                    )
                },
            )
        }
    }
}

/// What this case finds wrong in `files` (every tracked file, by path and bytes) when `held_text` is
/// the held list.
fn findings(files: &[(String, Vec<u8>)], held_text: &str) -> Vec<String> {
    let held = parse_held(held_text);
    let mut problems = Vec::new();
    // Each held entry stands once in its file, its value is given by its line, and it shows that the
    // value lies in a temporary folder.
    let mut at_line: HashMap<(&str, usize), Vec<usize>> = HashMap::new();
    let mut covered: HashMap<(&str, usize), Vec<(usize, usize)>> = HashMap::new();
    for (index, entry) in held.iter().enumerate() {
        let Some((_, bytes)) = files.iter().find(|(path, _)| *path == entry.file) else {
            problems.push(format!(
                "held entry for {}: the file is not tracked",
                entry.file
            ));
            continue;
        };
        let Ok(text) = std::str::from_utf8(bytes) else {
            problems.push(format!(
                "held entry for {}: the file is not text",
                entry.file
            ));
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let spans = match locate(entry, &lines) {
            Ok(spans) => spans,
            Err(error) => {
                problems.push(format!("held entry for {}: {error}", entry.file));
                continue;
            }
        };
        let last = spans[spans.len() - 1].1 - 1;
        if matches!(entry.proof, Proof::Text) {
            problems.extend(redefinitions(entry, &lines, &spans));
        }
        at_line
            .entry((entry.file.as_str(), last))
            .or_default()
            .push(index);
        problems.extend(proof_problem(entry));
        let line = lines[last];
        let span = match entry.kind {
            Kind::Write => occurrences(line)
                .into_iter()
                .find_map(|at| bound_value(line, at, &entry.value).map(|span| (at, span))),
            Kind::Argument => argument_span(line, &entry.value).map(|span| (span.0, span)),
            Kind::Comment => continue,
        };
        match span {
            Some((at, (from, to))) => {
                let spans = covered.entry((entry.file.as_str(), last)).or_default();
                if entry.kind == Kind::Write {
                    spans.push((at, at + VARIABLE.len()));
                }
                spans.push((from, to));
            }
            None => problems.push(format!(
                "held entry for {}: its line does not give the variable the value {}: {}",
                entry.file, entry.value, line
            )),
        }
    }

    // Every other line that names the variable is a read, a line that cannot run, or a line of the
    // held list in this file.
    let mut aliases: Vec<(String, String)> = Vec::new();
    for (path, bytes) in files {
        if !names_the_variable(bytes) {
            continue;
        }
        let Some(text) = std::str::from_utf8(bytes)
            .ok()
            .filter(|_| !bytes.contains(&0))
        else {
            problems.push(format!(
                "{path}: a file that is not text names the variable"
            ));
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let mut passes = lines_that_cannot_run(path, &lines);
        if path == THIS_FILE {
            match held_region(&lines, held_text) {
                Ok(region) => passes[region].fill(true),
                Err(error) => problems.push(error),
            }
        }
        for (index, line) in lines.iter().enumerate() {
            let entries = at_line
                .get(&(path.as_str(), index))
                .map_or(&[][..], Vec::as_slice);
            if entries
                .iter()
                .any(|entry| held[*entry].kind == Kind::Comment)
            {
                continue;
            }
            if passes[index] || occurrences(line).is_empty() {
                continue;
            }
            if let Some(name) = alias_of(line) {
                aliases.push((
                    name,
                    path.rsplit_once('.').map_or("", |(_, e)| e).to_owned(),
                ));
                continue;
            }
            let spans = covered
                .get(&(path.as_str(), index))
                .map_or(&[][..], Vec::as_slice);
            let unexplained = occurrences(line).into_iter().any(|at| {
                !spans.iter().any(|(from, to)| (*from..*to).contains(&at)) && !is_a_read(line, at)
            });
            if unexplained {
                problems.push(format!(
                    "{path}:{}: this line names the variable and is neither a known read nor a held \
                     write: {}\n  Show where its value lies (a temporary folder: /tmp, the runner's \
                     or the platform's own, or under the variable's own earlier value) and add \
                     the line to the held list, in the form the list shows.",
                    index + 1,
                    line.trim()
                ));
            }
        }
    }

    // A constant that holds the name is read where it is used: through Rust's environment calls,
    // and nowhere else.
    for (name, extension) in &aliases {
        for (path, bytes) in files
            .iter()
            .filter(|(path, _)| path.ends_with(&format!(".{extension}")))
        {
            let Ok(text) = std::str::from_utf8(bytes) else {
                continue;
            };
            if !text.contains(name.as_str()) {
                continue;
            }
            let lines: Vec<&str> = text.lines().collect();
            let passes = lines_that_cannot_run(path, &lines);
            for (index, line) in lines.iter().enumerate() {
                let uses = word_positions(line, name);
                let read = |at: &usize| {
                    let before = &line[..*at];
                    (before.ends_with("env::var_os(") || before.ends_with("env::var("))
                        && line[at + name.len()..].starts_with(')')
                };
                if !passes[index]
                    && alias_of(line).as_deref() != Some(name)
                    && !uses.iter().all(read)
                {
                    problems.push(format!(
                        "{path}:{}: a use of the constant {name}, which holds the variable's name, \
                         that is not a read: {}",
                        index + 1,
                        line.trim()
                    ));
                }
            }
        }
    }
    problems
}

/// The tracked files of the checkout at `root`, as the checkout's own index lists them, by path and
/// bytes, and what is wrong with the listing: no repository, no `git` program, a listed file that the
/// checkout does not hold. A listed path that is not a regular file (a link, a submodule) holds a
/// path or a commit id and no text of a build, and is not read. A file that is not yet added to the
/// index is not listed.
fn tracked_files(root: &Path) -> (Vec<(String, Vec<u8>)>, Vec<String>) {
    let listing = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "-C"])
        .arg(root)
        .args(["ls-files", "-z", "--cached"])
        .output()
        .unwrap_or_else(|error| panic!("git is needed to list the tracked files: {error}"));
    assert!(
        listing.status.success(),
        "git could not list the tracked files of {}: {}",
        root.display(),
        String::from_utf8_lossy(&listing.stderr)
    );
    let (mut files, mut problems) = (Vec::new(), Vec::new());
    for path in listing
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
    {
        let path = String::from_utf8(path.to_vec()).expect("a tracked path is text");
        match fs::symlink_metadata(root.join(&path)) {
            Err(error) => problems.push(format!(
                "{path} is tracked and the checkout lacks it: {error}"
            )),
            Ok(metadata) if !metadata.is_file() => {}
            Ok(_) => {
                let bytes = fs::read(root.join(&path))
                    .unwrap_or_else(|error| panic!("{path} is read: {error}"));
                files.push((path, bytes));
            }
        }
    }
    (files, problems)
}

/// KR-REQ-27.03, the part about the build's directory: every value that a build gives the variable
/// that names the artefacts directory lies in a temporary folder (`/tmp`, the runner's or the
/// platform's own, or under the variable's own earlier value). The case fails on what it does not
/// know.
///
/// It reads every tracked file of every type: the checkout's own list, from `git ls-files`, and the
/// bytes of each file that the checkout holds (a link or a submodule holds a path or a commit and is
/// not read). The name is searched in any letter case, since Windows takes it in any, and in UTF-16.
/// A file that names the variable and is not text, or holds a zero byte, fails the case. Each line that names the variable is exactly
/// one of these, and a line that is none of them fails the case with the lines to add:
///
/// 1. A held write. The held list holds each line that gives the variable a value (a workflow's
///    `env` entry, an assignment, the default of `${NAME:-default}`, a program's environment call)
///    whole by its text: the file, the line, the value that stands right after the name, and, for
///    each variable that the value names, the line that defines it, in the order they stand. Every
///    block of lines of an entry must stand in exactly one place of its file, so an entry that
///    matches no line, or more than one, fails the case, and so does a value that is only the start
///    of the line's value or a line that gives the variable a second value. The case shows from
///    the entry's own lines that the value lies in a temporary folder. For a value in Rust, whose
///    expressions it does not follow, the entry names its line that makes a temporary directory.
///    A value that lies elsewhere, or is the caller's, carries its reason. A held argument is a
///    line that hands the variable's value to a program, held the same way.
/// 2. A known read, and only these: `${{ env.NAME }}` in a workflow, `$env:NAME` in PowerShell, a
///    shell's `$NAME`, `${NAME}`, `${NAME:?...}`, `${NAME:+...}` and `${NAME:-}` with an empty
///    default, a call of Rust's `env::var` or `env::var_os`, and a bare `export NAME`. A default
///    with text (`${NAME:-default}`) gives a value, and is a held write. A constant that holds the
///    name (`const X: &str = "..."`) is allowed when every use of `X` in a file of its type is
///    such a call.
/// 3. A line that cannot run, by these rules only: a line that starts with `#` in a `.sh`,
///    `.bash`, `.yml`, `.yaml`, `.py` or `.ps1` file, but not one that starts with `#>` (which ends
///    a PowerShell block comment and may go on) or `#!`; a line that starts with `//` (so `///` and
///    `//!`) in a `.rs`, `.ts`, `.tsx`, `.js` or `.mjs` file, except the lines of a code block in a
///    doc comment (fenced with three backticks or `~~~`, or indented), which the Rust
///    documentation tests run; a line of a `.md` file outside a fenced
///    code block and not indented as code; and a line of this file between the two lines that open
///    and close its held list, which equal the list the program holds, so that every line let
///    through is data. A line that has anything before its comment marker, a line that ends a
///    block comment, and a line inside a block comment are not let through: the one such line that
///    names the variable is held as a comment with its reason.
///
/// A text hold detects a change to the lines it holds, and not a wrong change. A line between two
/// blocks of an entry that gives a variable of the earlier block another value fails the case, in
/// the ordinary shell and PowerShell forms of an assignment; any other way to change a variable
/// that a held line names is not read, and nor is what an `env` entry does to `TEMP`. A held Rust
/// value is shown only by a line of the entry that makes a temporary directory, not by following
/// the expressions between that line and the value. A name made at run time (`${!name}`, a
/// joined string, a use of this file's own constant for the name) is out of reach of any case that
/// reads text, and so is a file that is not yet added to the index. A comment marker that stands
/// first on a line inside a string or a template literal is let through as a comment.
///
/// Not shown here: that each run gets a directory of its own (the scripts' fixed default is shared
/// by successive runs on one machine) and that on macOS the default is the OS-resolved `$TMPDIR`
/// rather than `/tmp`; the directory the evidence check accepts is shown by the two cases in the
/// conformance library.
#[test]
fn every_value_a_build_gives_the_artifacts_directory_lies_in_a_temporary_folder() {
    let root = repository();
    let (files, mut problems) = tracked_files(&root);
    problems.extend(findings(&files, HELD));
    assert!(
        problems.is_empty(),
        "the artefacts directory is named or given a value where this case does not know it:\n{}",
        problems.join("\n")
    );

    // The one held write whose value is not in a temporary folder is made by a store build whose
    // release check keeps its screenshots where the check's own default puts them: that has to stay
    // in a temporary folder, or the exception hides a screenshot outside one.
    let check = fs::read_to_string(root.join("scripts/e2e-android-release.sh")).expect("the check");
    let shots = values_of(&check, "shots");
    assert!(
        !shots.is_empty()
            && shots.iter().all(|value| expansion_default(value)
                .is_some_and(|(_, default)| lies_in_a_temporary_folder(&default, &check, 6))),
        "the store build's release check keeps its screenshots outside a temporary folder: {shots:?}"
    );
    let store = fs::read_to_string(root.join("scripts/store-android.sh")).expect("the store build");
    assert!(
        !store.contains("KR_PAIRING_SHOTS"),
        "the store build gives its release check another folder for its screenshots"
    );
}

/// KR-REQ-27.03: a job that runs a screenshot tool has the variable when that step starts: from its
/// workflow, from its own `env`, from a step that wrote it to the job's environment file earlier,
/// or from the step's own `env` or an assignment in the step ahead of the tool.
#[test]
fn a_job_that_runs_a_screenshot_tool_has_the_artifacts_directory_when_the_step_starts() {
    let root = repository();
    let mut workflows = Vec::new();
    files_ending(&root.join(".github"), &[".yml", ".yaml"], &mut workflows);
    let mut steps_with_a_tool = 0_usize;
    for path in &workflows {
        let name = path
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        let text = fs::read_to_string(path).expect("a workflow");
        if !text.lines().any(|line| without_comment(line) == "jobs:") {
            continue;
        }
        let set_for_all = text
            .lines()
            .take_while(|line| without_comment(line) != "jobs:")
            .any(|line| artifacts_assignment(line).is_some());
        for job_name in jobs_of(&text) {
            let body = job(&text, &job_name);
            let mut set = set_for_all
                || body
                    .lines()
                    .take_while(|line| !line.starts_with("    steps:"))
                    .any(|line| artifacts_assignment(line).is_some());
            for step in steps_of(&body) {
                if never_runs(&step) {
                    continue;
                }
                let lines: Vec<&str> = step.lines().collect();
                // The tool is named in a command, not in the step's name; the step's own `env`
                // gives the variable wherever it stands in the step; an assignment in a command
                // counts only ahead of the tool, and a write to the environment file counts for the
                // steps after this one, not for this one.
                let tool = lines.iter().position(|line| {
                    let text = line.trim_start().trim_start_matches("- ");
                    !text.starts_with("name:")
                        && SCREENSHOT_TOOLS.iter().any(|tool| line.contains(tool))
                });
                let in_env = lines
                    .iter()
                    .any(|line| line.trim().starts_with(&format!("{VARIABLE}:")));
                let own = lines.iter().position(|line| {
                    !line.contains("GITHUB_ENV") && artifacts_assignment(line).is_some()
                });
                if let Some(tool) = tool {
                    steps_with_a_tool += 1;
                    assert!(
                        set || in_env || own.is_some_and(|own| own <= tool),
                        "{name}: the job {job_name} runs a screenshot tool in a step that has no \
                         {VARIABLE} yet:\n{step}"
                    );
                }
                if lines
                    .iter()
                    .any(|line| line.contains("GITHUB_ENV") && artifacts_assignment(line).is_some())
                {
                    set = true;
                }
            }
        }
    }
    assert!(
        steps_with_a_tool >= 3,
        "the case found {steps_with_a_tool} steps that run a screenshot tool"
    );
}

/// Writes `@V@` for the variable's name as the files spell it, and `@v@` for it in lower case, so
/// that the lines of a small tree below do not name the variable themselves.
fn named(text: &str) -> String {
    text.replace("@V@", VARIABLE)
        .replace("@v@", &VARIABLE.to_ascii_lowercase())
}

fn tree(files: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
    files
        .iter()
        .map(|(path, text)| ((*path).to_owned(), named(text).into_bytes()))
        .collect()
}

/// This file as a small tree holds it: some code, then the held list between its two markers.
fn this_file(outside: &str, held: &str) -> String {
    format!("{outside}\n{HELD_OPENS}\n{held}\n{HELD_CLOSES}\n")
}

/// The source case fails on a write it has no held entry for, in any spelling and in any file, and
/// on an entry that no longer holds: each tree below has one fault, and the case names it.
#[test]
fn the_source_case_fails_on_what_it_does_not_know() {
    let held_a = "file: scripts/a.sh\n| d=\"${@V@:-/tmp/kr-a}\"\nvalue: /tmp/kr-a";
    let a_sh = "d=\"${@V@:-/tmp/kr-a}\"\necho \"$@V@/x\" \"${@V@:?}\"\n# @V@ is a directory\n";
    let unknown = "neither a known read nor a held write";
    let outside = "does not lie in a temporary folder";
    let value = "does not give the variable the value";
    let this_ok = this_file("fn main() {}", held_a);
    let this_write = this_file(
        "fn f() { std::env::set_var(\"@V@\", \"/home/x\"); }",
        held_a,
    );
    let this_other = this_file(
        "fn main() {}",
        "file: scripts/a.sh\n| d=\"${@V@:-/tmp/kr-other}\"\nvalue: /tmp/kr-other",
    );
    let this_twice = format!("{this_ok}{this_ok}");
    let a = ("scripts/a.sh", a_sh);
    type Case<'a> = (&'a str, Vec<(&'a str, &'a str)>, &'a str, Option<&'a str>);
    let cases: Vec<Case> = vec![
        (
            "a held default, plain reads and a comment pass",
            vec![a],
            held_a,
            None,
        ),
        (
            "a held line that is gone",
            vec![("scripts/a.sh", "d=\"${@V@:-/tmp/kr-b}\"\n")],
            held_a,
            Some("no line stands"),
        ),
        (
            "a held line that stands twice",
            vec![(
                "scripts/a.sh",
                "d=\"${@V@:-/tmp/kr-a}\"\nd=\"${@V@:-/tmp/kr-a}\"\n",
            )],
            held_a,
            Some("stands in 2 places"),
        ),
        (
            "a held entry of a file that is not tracked",
            vec![],
            held_a,
            Some("the file is not tracked"),
        ),
        (
            "an assignment in Python",
            vec![a, ("tools/x.py", "os.environ[\"@V@\"] = \"/home/x\"\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a printf into the environment file",
            vec![
                a,
                (
                    ".github/workflows/w.yml",
                    "run: printf '%s=%s\\n' '@V@' '/home/x' >> \"$GITHUB_ENV\"\n",
                ),
            ],
            held_a,
            Some(unknown),
        ),
        (
            "an assignment in a script outside the script folders",
            vec![a, ("apps/x/y.mjs", "process.env['@V@'] = '/home/x'\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a definition below its use",
            vec![("scripts/b.sh", "export @V@=\"$d/e\"\nd=/tmp/x\n")],
            "file: scripts/b.sh\n| d=/tmp/x\n...\n| export @V@=\"$d/e\"\nvalue: $d/e",
            Some("stands above a line it must follow"),
        ),
        (
            "a value that names a variable that no held line defines",
            vec![("scripts/b.sh", "d=/tmp/x\nexport @V@=\"$d/e\"\n")],
            "file: scripts/b.sh\n| export @V@=\"$d/e\"\nvalue: $d/e",
            Some(outside),
        ),
        (
            "a value that names a variable that a held line defines",
            vec![("scripts/b.sh", "d=/tmp/x\nexport @V@=\"$d/e\"\n")],
            "file: scripts/b.sh\n| d=/tmp/x\n| export @V@=\"$d/e\"\nvalue: $d/e",
            None,
        ),
        (
            "a held value outside the temporary folders",
            vec![("scripts/c.sh", "d=\"${@V@:-/home/x}\"\n")],
            "file: scripts/c.sh\n| d=\"${@V@:-/home/x}\"\nvalue: /home/x",
            Some(outside),
        ),
        (
            "a default that no entry holds",
            vec![a, ("scripts/c.sh", "d=\"${@V@:-/home/x}\"\n")],
            held_a,
            Some(unknown),
        ),
        (
            "an expansion that is no known read",
            vec![a, ("scripts/c.sh", "x=\"${@V@#/tmp}\"\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a bare name",
            vec![a, ("scripts/c.sh", "echo @V@\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a write in lower case",
            vec![a, ("scripts/c.sh", "export @v@=/home/x\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a comment marker inside a string",
            vec![a, ("scripts/c.sh", "x=\"#\"; export @V@=/home/x\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a line that ends a block comment and goes on",
            vec![a, ("apps/x/y.ts", "*/ process.env['@V@'] = '/home/x'\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a line inside a block comment",
            vec![a, ("apps/x/y.ts", " * @V@ names the directory\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a comment line held with its reason",
            vec![a, ("apps/x/y.ts", " * @V@ names the directory\n")],
            "file: scripts/a.sh\n| d=\"${@V@:-/tmp/kr-a}\"\nvalue: /tmp/kr-a\n\n\
             file: apps/x/y.ts\nkind: comment\n| * @V@ names the directory\nwhy: inside a block comment",
            None,
        ),
        (
            "comment lines of a script and of Rust, and prose, pass",
            vec![
                a,
                ("scripts/c.sh", "# export @V@=/home/x\n"),
                ("crates/x/src/lib.rs", "// @V@\n/// @V@ is read\n"),
                ("docs/x.md", "The directory is @V@ here.\n"),
            ],
            held_a,
            None,
        ),
        (
            "a fenced line of a document",
            vec![
                a,
                ("docs/x.md", "text\n```sh\n@V@=/home/x cargo test\n```\n"),
            ],
            held_a,
            Some(unknown),
        ),
        (
            "an indented line of a document",
            vec![a, ("docs/x.md", "    @V@=/home/x cargo test\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a code block of a documentation test",
            vec![
                a,
                (
                    "crates/x/src/lib.rs",
                    "/// ```\n/// std::env::set_var(\"@V@\", \"/home/x\");\n/// ```\n",
                ),
            ],
            held_a,
            Some(unknown),
        ),
        (
            "a held line that gives no value",
            vec![("scripts/a.sh", "echo hi\n")],
            "file: scripts/a.sh\n| echo hi\nvalue: /tmp/a",
            Some(value),
        ),
        (
            "a held value that is the start of a longer one",
            vec![("scripts/c.sh", "d=\"${@V@:-/tmp/a/../../home}\"\n")],
            "file: scripts/c.sh\n| d=\"${@V@:-/tmp/a/../../home}\"\nvalue: /tmp/a",
            Some(value),
        ),
        (
            "a second write on a held line",
            vec![("scripts/c.sh", "@V@=/tmp/a @V@=/home/b cmd\n")],
            "file: scripts/c.sh\n| @V@=/tmp/a @V@=/home/b cmd\nvalue: /tmp/a",
            Some(unknown),
        ),
        (
            "this file with only its held list",
            vec![a, (THIS_FILE, &this_ok)],
            held_a,
            None,
        ),
        (
            "a write in this file outside its held list",
            vec![a, (THIS_FILE, &this_write)],
            held_a,
            Some(unknown),
        ),
        (
            "a held list that is not the lines between the markers",
            vec![a, (THIS_FILE, &this_other)],
            held_a,
            Some("are not the held list"),
        ),
        (
            "two lines that open the held list",
            vec![a, (THIS_FILE, &this_twice)],
            held_a,
            Some("lines that open the held list"),
        ),
        (
            "a constant that holds the name, read through the environment",
            vec![
                a,
                (
                    "crates/x/src/lib.rs",
                    "const ENV: &str = \"@V@\";\nfn f() { std::env::var_os(ENV); }\n",
                ),
            ],
            held_a,
            None,
        ),
        (
            "a write through a constant that holds the name",
            vec![
                a,
                (
                    "crates/x/src/lib.rs",
                    "const ENV: &str = \"@V@\";\nfn f() { cmd.env(ENV, \"/home/x\"); }\n",
                ),
            ],
            held_a,
            Some("a use of the constant"),
        ),
        (
            "an argument whose value lies in a temporary folder",
            vec![("scripts/d.sh", "e=/tmp/x\nrun --evidence \"$e\"\n")],
            "file: scripts/d.sh\nkind: argument\n| e=/tmp/x\n...\n| run --evidence \"$e\"\nvalue: $e",
            None,
        ),
        (
            "an argument whose value lies elsewhere",
            vec![("scripts/d.sh", "e=/home/x\nrun --evidence \"$e\"\n")],
            "file: scripts/d.sh\nkind: argument\n| e=/home/x\n...\n| run --evidence \"$e\"\nvalue: $e",
            Some(outside),
        ),
        (
            "a Rust value shown by the line that makes a temporary directory",
            vec![(
                "crates/x/tests/t.rs",
                "let dir = TempDir::new().unwrap();\ncmd.env(\"@V@\", dir.path());\n",
            )],
            "file: crates/x/tests/t.rs\n| let dir = TempDir::new().unwrap();\n...\n| cmd.env(\"@V@\", dir.path());\n\
             value: dir.path()\nfolder: let dir = TempDir::new().unwrap();",
            None,
        ),
        (
            "a Rust value with a folder line that makes no directory",
            vec![(
                "crates/x/tests/t.rs",
                "let dir = make();\ncmd.env(\"@V@\", dir.path());\n",
            )],
            "file: crates/x/tests/t.rs\n| let dir = make();\n...\n| cmd.env(\"@V@\", dir.path());\n\
             value: dir.path()\nfolder: let dir = make();",
            Some("makes a temporary directory"),
        ),
        (
            "a value that comes with its reason",
            vec![("scripts/e.sh", "@V@=\"$leg/e2e\" cmd\n")],
            "file: scripts/e.sh\n| @V@=\"$leg/e2e\" cmd\nvalue: $leg/e2e\nwhy: the caller's folder",
            None,
        ),
        (
            "a held line that gives no value, as a write",
            vec![("scripts/c.sh", "export @V@\n")],
            "file: scripts/c.sh\n| export @V@\nvalue: /tmp/a",
            Some(value),
        ),
        (
            "a held value with a step up",
            vec![("scripts/c.sh", "d=\"${@V@:-/tmp/a/../b}\"\n")],
            "file: scripts/c.sh\n| d=\"${@V@:-/tmp/a/../b}\"\nvalue: /tmp/a/../b",
            Some(outside),
        ),
        (
            "a plain expansion followed by an assignment",
            vec![a, ("scripts/c.sh", "echo $@V@ = x\n")],
            held_a,
            Some(unknown),
        ),
        (
            "two slashes inside a script line that is not a comment",
            vec![a, ("apps/x/y.mjs", "process.env['@V@'] = 'http://x'\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a held value that stands right against the name",
            vec![("scripts/c.sh", "echo @V@/tmp/a\n")],
            "file: scripts/c.sh\n| echo @V@/tmp/a\nvalue: /tmp/a",
            Some(value),
        ),
        (
            "an argument that is the end of a longer word",
            vec![("scripts/d.sh", "e=/tmp/x\nrun --evidence x$e\n")],
            "file: scripts/d.sh\nkind: argument\n| e=/tmp/x\n...\n| run --evidence x$e\nvalue: $e",
            Some(value),
        ),
        (
            "a PowerShell assignment with an operator",
            vec![a, ("scripts/c.ps1", "$env:@V@ ??= 'C:\\x'\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a PowerShell assignment continued on the next line",
            vec![a, ("scripts/c.ps1", "$env:@V@ `\n    = 'C:\\x'\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a PowerShell line that ends a block comment and goes on",
            vec![a, ("scripts/c.ps1", "#> $env:@V@ = 'C:\\x'\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a shebang that gives the variable a value",
            vec![a, ("scripts/c.sh", "#!/usr/bin/env -S @V@=/home/x bash\n")],
            held_a,
            Some(unknown),
        ),
        (
            "a documentation test in a tilde fence",
            vec![
                a,
                (
                    "crates/x/src/lib.rs",
                    "/// ~~~\n/// cmd.env(\"@V@\", \"/home/x\");\n/// ~~~\n",
                ),
            ],
            held_a,
            Some(unknown),
        ),
        (
            "an indented documentation test",
            vec![
                a,
                (
                    "crates/x/src/lib.rs",
                    "///     cmd.env(\"@V@\", \"/home/x\");\n",
                ),
            ],
            held_a,
            Some(unknown),
        ),
        (
            "a held value followed by a step up after its closing quote",
            vec![("scripts/c.sh", "export @V@=\"/tmp/x\"/../../home\n")],
            "file: scripts/c.sh\n| export @V@=\"/tmp/x\"/../../home\nvalue: /tmp/x",
            Some(value),
        ),
        (
            "a variable given another value between the held lines",
            vec![("scripts/b.sh", "d=/tmp/x\nd=/home/y\nexport @V@=\"$d/e\"\n")],
            "file: scripts/b.sh\n| d=/tmp/x\n...\n| export @V@=\"$d/e\"\nvalue: $d/e",
            Some("another value"),
        ),
        (
            "an unrelated line between the held lines",
            vec![("scripts/b.sh", "d=/tmp/x\necho hi\nexport @V@=\"$d/e\"\n")],
            "file: scripts/b.sh\n| d=/tmp/x\n...\n| export @V@=\"$d/e\"\nvalue: $d/e",
            None,
        ),
    ];
    for (name, files, held, fails_with) in cases {
        let problems = findings(&tree(&files), &format!("\n{}\n", named(held)));
        match fails_with {
            None => assert!(problems.is_empty(), "{name}: {problems:?}"),
            Some(text) => assert!(
                problems.iter().any(|problem| problem.contains(text)),
                "{name}: no finding says {text}: {problems:?}"
            ),
        }
    }

    // A file that is not text, with the name in it.
    let mut files = tree(&[a]);
    let mut binary = VARIABLE.as_bytes().to_vec();
    binary.push(0xff);
    files.push(("data/x.bin".to_owned(), binary));
    let problems = findings(&files, &named(held_a));
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("is not text")),
        "{problems:?}"
    );

    // A file in UTF-16, which PowerShell reads, with a write in it.
    let utf16: Vec<u8> = named("export @V@=/home/x\n")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut files = tree(&[a]);
    files.push(("scripts/u.ps1".to_owned(), utf16));
    let problems = findings(&files, &named(held_a));
    assert!(
        problems
            .iter()
            .any(|problem| problem.contains("is not text")),
        "{problems:?}"
    );
}

/// The held list: one entry for each place that gives the variable a value, set apart by blank
/// lines. `file:` names the file. A line that starts `| ` is a line of the file, compared without
/// its indentation; the lines of a block stand together, a line `...` sets apart blocks that stand
/// further from each other, and the last line is the held one. `value:` is the text that stands
/// right after the name in that line. `folder:` names the line that makes the temporary directory a
/// Rust value lies in, and `why:` gives the reason a value lies elsewhere. `kind:` is `argument`
/// for a line that hands the value to a program, or `comment` for a line that cannot run and that
/// no line rule lets through.
const HELD: &str = r##"
file: .github/workflows/conformance.yml
| # The evidence directory: inside the platform's temporary directory, new for the run.
| KR_TEST_ARTIFACTS_DIR: /tmp/kr-conformance-evidence
value: /tmp/kr-conformance-evidence

file: .github/workflows/conformance.yml
| KR_REQUIRE_PLUGIN_FIXTURES: "1"
| KR_TEST_ARTIFACTS_DIR: /tmp/kr-conformance-evidence
value: /tmp/kr-conformance-evidence

file: .github/workflows/core-ci.yml
| # verdict here before it asserts anything, so a run the target failed on keeps the number.
| KR_TEST_ARTIFACTS_DIR: /tmp/kr-test-artifacts
value: /tmp/kr-test-artifacts

file: .github/workflows/core-ci.yml
| KR_TEST_ARTIFACTS_DIR: /tmp/kr-shell-qualification
value: /tmp/kr-shell-qualification

file: .github/workflows/core-ci.yml
| env:
| KR_TEST_ARTIFACTS_DIR: /tmp/kr-test-artifacts
value: /tmp/kr-test-artifacts

file: scripts/disk-report.sh
| size_of "the test evidence" "${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
value: /tmp/kr-test-artifacts

file: scripts/e2e-android-release.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/release-tls-android"
value: /tmp/kr-test-artifacts

file: scripts/e2e-backup.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
value: /tmp/kr-test-artifacts

file: scripts/e2e-deployment.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
value: /tmp/kr-test-artifacts

file: scripts/e2e-device-records.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/device-records-ios"
value: /tmp/kr-test-artifacts

file: scripts/e2e-fence.sh
| artifacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
value: /tmp/kr-test-artifacts

file: scripts/e2e-m1b.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
value: /tmp/kr-test-artifacts

file: scripts/e2e-mobile.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/companion-mobile"
value: /tmp/kr-test-artifacts

file: scripts/e2e-pairing-device.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/pairing-device-$platform"
value: /tmp/kr-test-artifacts

file: scripts/e2e-permissions.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/permissions"
value: /tmp/kr-test-artifacts

file: scripts/e2e-privacy.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
value: /tmp/kr-test-artifacts

file: scripts/e2e-push-android-receiver.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/push-android-receiver"
value: /tmp/kr-test-artifacts

file: scripts/e2e-push-device.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/push-device-$platform"
value: /tmp/kr-test-artifacts

file: scripts/e2e-voice-call-bridge.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-call-bridge-$platform"
value: /tmp/kr-test-artifacts

file: scripts/e2e-voice-call-device.sh
| artefacts_base="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-call-device-$platform-$mode${KR_RUN_TAG:+-$KR_RUN_TAG}"
value: /tmp/kr-test-artifacts

file: scripts/e2e-voice-device.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-device"
value: /tmp/kr-test-artifacts

file: scripts/e2e-wsl.sh
| artifacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
value: /tmp/kr-test-artifacts

file: scripts/ios-privacy-manifest.sh
| artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/privacy-manifest-ios"
value: /tmp/kr-test-artifacts

file: apps/companion/e2e/evidence.ts
| export const ARTEFACTS: string = env['KR_TEST_ARTIFACTS_DIR'] ?? '/tmp/kr-test-artifacts'
value: /tmp/kr-test-artifacts

file: .github/workflows/conformance.yml
| $temporary = (Get-Item $env:TEMP).FullName
| "KR_TEST_ARTIFACTS_DIR=$temporary\kr-conformance-evidence" >> $env:GITHUB_ENV
value: $temporary\kr-conformance-evidence

file: .github/workflows/core-ci.yml
| $temporary = (Get-Item $env:TEMP).FullName
| "KR_TEST_ARTIFACTS_DIR=$temporary\kr-test-artifacts" >> $env:GITHUB_ENV
value: $temporary\kr-test-artifacts

file: .github/workflows/core-ci.yml
| export KR_TEST_ARTIFACTS_DIR="$RUNNER_TEMP/kr-shell-qualification-second"
value: $RUNNER_TEMP/kr-shell-qualification-second

file: .github/workflows/wsl-acceptance.yml
| $temporary = (Get-Item $env:TEMP).FullName
| $directory = Join-Path $temporary 'kr-test-artifacts'
| New-Item -ItemType Directory -Force $directory | Out-Null
| "KR_TEST_ARTIFACTS_DIR=$directory" >> $env:GITHUB_ENV
value: $directory

file: .github/workflows/wsl-acceptance.yml
| KR_TEST_ARTIFACTS_DIR="$(cygpath -u "$KR_TEST_ARTIFACTS_DIR")"
value: $(cygpath -u "$KR_TEST_ARTIFACTS_DIR")

file: scripts/bench-all.sh
| if [ -z "${KR_TEST_ARTIFACTS_DIR:-}" ]; then
| temporary="${TMPDIR:-/tmp}"
| KR_TEST_ARTIFACTS_DIR="$(mktemp -d "${temporary%/}/kalareach-bench.XXXXXX")" || exit 1
value: $(mktemp -d "${temporary%/}/kalareach-bench.XXXXXX")

file: scripts/bench-all.sh
| evidence="$(cd "$KR_TEST_ARTIFACTS_DIR" && pwd)"
| KR_TEST_ARTIFACTS_DIR="$evidence"
value: $evidence

file: scripts/e2e-fence.sh
| artifacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
...
| if ! KR_TEST_ARTIFACTS_DIR="$artifacts" \
value: $artifacts

file: scripts/e2e-update.sh
| work="$(mktemp -d "${TMPDIR:-/tmp}/kr-e2e-update.XXXXXX")"
...
| KR_E2E_PROGRAMS="$programs" KR_E2E_STATE="$work/state-permissions" KR_TEST_ARTIFACTS_DIR="$work/artifacts" \
value: $work/artifacts

file: scripts/e2e-voice-call-device.sh
| artefacts_base="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-call-device-$platform-$mode${KR_RUN_TAG:+-$KR_RUN_TAG}"
...
| artefacts=""
...
| artefacts="$artefacts_base${leg:+-$leg}"
...
| KR_HARNESS_PLATFORM="$platform" KR_TEST_ARTIFACTS_DIR="$artefacts" \
value: $artefacts

file: scripts/run-conformance.sh
| evidence="${KR_TEST_ARTIFACTS_DIR:-}"
| if [ -z "$evidence" ]; then
| evidence="$(mktemp -d "${TMPDIR:-/tmp}/kr-conformance.XXXXXX")"
| fi
| export KR_TEST_ARTIFACTS_DIR="$evidence"
value: $evidence

file: scripts/store-android.sh
| leg="$device_dir/device"
...
| KR_TEST_ARTIFACTS_DIR="$leg/e2e" KR_RELEASE_APK="$apk" bash "$here/scripts/e2e-android-release.sh" \
value: $leg/e2e
why: the store build keeps the logs of its release check beside the signed bundle, in the leg folder under the directory the caller names ($leg is $device_dir/device), so this value lies where the caller says and not in a temporary folder; the release check keeps its screenshots in the folder its own default names, which the case reads in scripts/e2e-android-release.sh

file: tests/conformance/src/run.rs
| .env("KR_TEST_ARTIFACTS_DIR", self.evidence)
value: self.evidence
why: the directory the run was given by its --evidence argument; the two callers' lines that give it are held below as arguments

file: tests/conformance/tests/device_scripts.rs
| ) -> Run {
| let directory = TempDir::new().expect("a directory");
| let root = directory.path();
...
| .env("KR_TEST_ARTIFACTS_DIR", root.join("artefacts"))
value: root.join("artefacts")
folder: let directory = TempDir::new().expect("a directory");

file: tests/conformance/tests/fetch.rs
| root: TempDir::new().expect("a directory for the case"),
...
| fn path(&self, relative: &str) -> PathBuf {
| self.root.path().join(relative)
...
| .env("KR_TEST_ARTIFACTS_DIR", self.path("evidence"))
value: self.path("evidence")
folder: root: TempDir::new().expect("a directory for the case"),

file: tests/e2e/m1b/tests/origin.rs
| let path = std::env::temp_dir().join(format!("krm-{name}-{}-{nanos}", std::process::id()));
...
| let artefacts = scratch.0.join("artefacts");
...
| .env("KR_TEST_ARTIFACTS_DIR", &artefacts)
value: &artefacts
folder: let path = std::env::temp_dir().join(format!("krm-{name}-{}-{nanos}", std::process::id()));

file: .github/workflows/conformance.yml
kind: argument
| cargo run --locked -p kr-conformance --bin kr-conformance -- run --root $PWD.Path --evidence $env:KR_TEST_ARTIFACTS_DIR @arguments
value: $env:KR_TEST_ARTIFACTS_DIR

file: scripts/run-conformance.sh
kind: argument
| evidence="${KR_TEST_ARTIFACTS_DIR:-}"
| if [ -z "$evidence" ]; then
| evidence="$(mktemp -d "${TMPDIR:-/tmp}/kr-conformance.XXXXXX")"
| fi
...
| arguments=(run --root "$root" --evidence "$evidence")
value: $evidence

file: apps/companion/e2e/evidence.ts
kind: comment
| * Section 27 puts every test artefact in one platform-resolved directory, `KR_TEST_ARTIFACTS_DIR`,
why: a line inside the block comment that opens the module
"##;
