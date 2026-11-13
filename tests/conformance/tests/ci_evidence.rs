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

/// The variable that names the one directory every test artefact of a run is kept in.
const ARTIFACTS_VARIABLE: &str = "KR_TEST_ARTIFACTS_DIR";

/// How a value may begin and still lie in a temporary folder: `/tmp`, or the platform's or the
/// runner's own temporary folder, spelled as each shell and the workflow syntax spell it.
const TEMPORARY_FOLDERS: [&str; 9] = [
    "/tmp/",
    "$RUNNER_TEMP",
    "${RUNNER_TEMP",
    "$env:RUNNER_TEMP",
    "${{ runner.temp }}",
    "$TMPDIR",
    "${TMPDIR",
    "$env:TEMP",
    "$env:TMP",
];

/// The assignments the build's own scripts make that the case cannot follow to a temporary folder,
/// each with the reason it is allowed: the file, the text of the line, and why.
const UNFOLLOWED_ASSIGNMENTS: [(&str, &str, &str); 1] = [(
    "scripts/store-android.sh",
    "KR_TEST_ARTIFACTS_DIR=\"$leg/e2e\"",
    "the store build keeps the logs of its release check beside the signed bundle, in the directory \
     the caller names, and that check takes no screenshot",
)];

/// The tools that take a screenshot, by the name a workflow step runs them under.
const SCREENSHOT_TOOLS: [&str; 11] = [
    "check-test-evidence.sh",
    "desktop-controls-macos.sh",
    "android-app-launch.sh",
    "ios-app-launch.sh",
    "e2e-permissions.sh",
    "e2e-pairing-device.sh",
    "e2e-mobile.sh",
    "e2e-voice-device.sh",
    "e2e-push-device.sh",
    "e2e-update.sh",
    "playwright",
];

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

/// The value a line gives the variable: an entry of a workflow's `env` (`NAME: value`) or an
/// assignment (`NAME=value`, after `export`, in front of a command, or inside the quoted line a
/// PowerShell step writes to the job's environment file). A comment gives none.
fn artifacts_assignment(line: &str) -> Option<String> {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with("//") {
        return None;
    }
    if let Some(rest) = line.strip_prefix(&format!("{ARTIFACTS_VARIABLE}:")) {
        return Some(unquoted(without_comment(rest)).to_owned());
    }
    let at = line.find(&format!("{ARTIFACTS_VARIABLE}="))?;
    Some(leading_value(&line[at + ARTIFACTS_VARIABLE.len() + 1..]))
}

/// What a script falls back on where the variable is unset: the text of each `${NAME:-default}` on
/// a line, less the empty ones, which only pass on what the caller gave.
fn artifacts_defaults(line: &str) -> Vec<String> {
    let opening = format!("${{{ARTIFACTS_VARIABLE}:-");
    line.match_indices(&opening)
        .map(|(at, _)| {
            let mut depth = 0_usize;
            let mut default = String::new();
            for character in line[at + opening.len()..].chars() {
                match character {
                    '{' => depth += 1,
                    '}' if depth == 0 => break,
                    '}' => depth -= 1,
                    _ => {}
                }
                default.push(character);
            }
            default
        })
        .filter(|default| !default.is_empty())
        .collect()
}

/// The name of the variable a value begins with, in a shell's (`$name`, `${name`) or PowerShell's
/// (`$name`) spelling, and nothing for `$env:` and `$(`.
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

/// Whether `value`, as a script or a workflow writes it, lies in a temporary folder: it begins
/// with one, or with the default the variable falls back on, or with a command that makes a
/// directory in one, or with another variable of `text` whose every value does; and a value made
/// from the variable's own value is the one checked where that was set.
fn lies_in_a_temporary_folder(value: &str, text: &str, depth: usize) -> bool {
    let value = unquoted(value);
    if depth == 0 || value.is_empty() {
        return false;
    }
    if let Some(rest) = value.strip_prefix(&format!("${{{ARTIFACTS_VARIABLE}:-")) {
        let default: String = rest
            .chars()
            .take_while(|character| *character != '}')
            .collect();
        return default.is_empty() || lies_in_a_temporary_folder(&default, text, depth - 1);
    }
    if value.contains(ARTIFACTS_VARIABLE) {
        return true;
    }
    if TEMPORARY_FOLDERS
        .iter()
        .any(|folder| value.starts_with(folder))
    {
        return true;
    }
    if value.starts_with("$(") && value.contains("mktemp") {
        let template = value
            .split("mktemp")
            .nth(1)
            .and_then(|after| after.split('"').nth(1));
        return template
            .is_some_and(|template| lies_in_a_temporary_folder(template, text, depth - 1));
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

/// KR-REQ-27.03, the part about the build's directory: every workflow and script of the repository
/// that gives the artefacts directory a value, or a default, puts it in a temporary folder (`/tmp`,
/// or the platform's or the runner's own), and a job that runs a screenshot tool does not leave it
/// unset. The values are read as text, so a value spelled in a way this does not know is one it
/// refuses; the one assignment it cannot follow is named, with its reason.
#[test]
fn every_value_a_build_gives_the_artifacts_directory_lies_in_a_temporary_folder() {
    let root = repository();
    let mut workflows = Vec::new();
    files_ending(&root.join(".github"), &[".yml", ".yaml"], &mut workflows);
    let mut scripts = Vec::new();
    files_ending(
        &root.join("scripts"),
        &[".sh", ".bash", ".py", ".mjs", ".js", ".ps1"],
        &mut scripts,
    );
    let mut outside = Vec::new();
    let mut seen = 0_usize;
    for path in workflows.iter().chain(&scripts) {
        let name = path
            .strip_prefix(&root)
            .expect("under the repository")
            .to_string_lossy()
            .into_owned();
        let text =
            fs::read_to_string(path).unwrap_or_else(|error| panic!("{name} is read: {error}"));
        for (number, line) in text.lines().enumerate() {
            let mut values: Vec<String> = artifacts_assignment(line).into_iter().collect();
            seen += values.len();
            if let Some(excused) = UNFOLLOWED_ASSIGNMENTS
                .iter()
                .find(|(file, needle, _)| *file == name && line.contains(needle))
            {
                assert!(!excused.2.is_empty(), "an exception names its reason");
                values.clear();
            }
            for default in artifacts_defaults(line) {
                seen += 1;
                values.push(default);
            }
            for value in values {
                if !lies_in_a_temporary_folder(&value, &text, 6) {
                    outside.push(format!("{name}:{}: {value}", number + 1));
                }
            }
        }
    }
    assert!(seen >= 30, "the case found only {seen} values to read");
    assert!(
        outside.is_empty(),
        "values outside a temporary folder:\n{}",
        outside.join("\n")
    );

    // The one assignment the case does not follow is made by a store build whose release check
    // takes no screenshot: that has to stay true, or the exception hides one.
    let check = fs::read_to_string(root.join("scripts/e2e-android-release.sh")).expect("the check");
    for word in ["screenshot", ".png", "screencap"] {
        assert!(
            !check.to_lowercase().contains(word),
            "the store build's release check takes a screenshot ({word}), outside a temporary folder"
        );
    }

    // A job that runs a screenshot tool has the variable from its workflow, its job or a step.
    let mut jobs_with_a_tool = 0_usize;
    for path in &workflows {
        let name = path
            .file_name()
            .expect("a name")
            .to_string_lossy()
            .into_owned();
        let text = fs::read_to_string(path).expect("a workflow");
        let before_jobs: Vec<&str> = text
            .lines()
            .take_while(|line| without_comment(line) != "jobs:")
            .collect();
        let set_for_all = before_jobs
            .iter()
            .any(|line| artifacts_assignment(line).is_some());
        if !text.lines().any(|line| without_comment(line) == "jobs:") {
            continue;
        }
        for job_name in jobs_of(&text) {
            let body = job(&text, &job_name);
            if !SCREENSHOT_TOOLS.iter().any(|tool| body.contains(tool)) {
                continue;
            }
            jobs_with_a_tool += 1;
            assert!(
                set_for_all
                    || body
                        .lines()
                        .any(|line| artifacts_assignment(line).is_some()),
                "{name}: the job {job_name} runs a screenshot tool and leaves {ARTIFACTS_VARIABLE} unset"
            );
        }
    }
    assert!(
        jobs_with_a_tool >= 3,
        "the case found {jobs_with_a_tool} jobs that run a screenshot tool"
    );
}
