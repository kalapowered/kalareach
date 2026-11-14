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

/// The reference host's job builds the release profile in hours when its cargo cache is gone, and a
/// run that ends without saving the cache starts cold again. So the save runs after a good build
/// whatever a later step does (a failure, a limit, a cancelled run) and after no build that did not
/// end well: it is the job's one save, its condition reads the outcome of the step that builds and
/// of no other, and it comes after the measurements, because the save takes the workspace's own
/// output out of the build directory and the measurements run that output.
#[test]
fn the_reference_host_job_saves_its_cargo_cache_after_a_good_build_whatever_follows() {
    let workflow = fs::read_to_string(repository().join(".github/workflows/core-ci.yml"))
        .expect("the landing workflow");
    let text = job(&workflow, "macos-reference");
    // Every step that saves a cache, by the shared action or by the cache action itself.
    let saves: Vec<String> = steps_of(&text)
        .into_iter()
        .filter(|step| step.contains("cache-save") || step.contains("cache/save"))
        .collect();
    assert_eq!(saves.len(), 1, "the job does not save a cache once");
    let save = &saves[0];
    assert!(
        save.contains("uses: ./.github/actions/cargo-cache-save"),
        "the job's save is not the shared action's"
    );
    assert!(!is_disabled(save), "the save step is disabled");
    let condition = step_condition(save)
        .expect("the save step has no condition, so a failed step before it ends the job unsaved");
    // `always()` is the one status function: `success()` or `failure()` beside it would end the
    // save after a failed step or after a good one, and `cancelled()` would end it in a cancelled
    // run, which a newer push makes.
    assert!(
        condition.contains("always()")
            && !condition.contains("||")
            && ["success()", "failure()", "cancelled()"]
                .iter()
                .all(|other| !condition.contains(other)),
        "the save step's condition does not hold after a failed or cut step and after nothing else"
    );
    let named = steps_named(&condition);
    assert_eq!(
        named.len(),
        1,
        "the save step's condition does not read the outcome of one step, the build"
    );
    let build_at = position_of_id(&text, &named[0])
        .unwrap_or_else(|| panic!("no step of the job has the id {}", named[0]));
    assert_eq!(
        Some(build_at),
        position_of_tool(&text, "cargo build"),
        "the step whose outcome the save reads is not the step that builds"
    );
    assert!(
        condition.contains(&format!("steps.{}.outcome=='success'", named[0])),
        "the save step does not require the build to have ended well"
    );
    let measure_at = position_of_tool(&text, "scripts/performance.sh")
        .expect("a step of the job runs the measurements");
    let save_at = steps_of(&text)
        .iter()
        .position(|step| step == save)
        .expect("the save is a step of the job");
    assert!(
        build_at < measure_at && measure_at < save_at,
        "the save does not come after the build and the measurements: it would take out the \
         output the measurements run"
    );
}

/// What a cold build of the reference host's job needs: its runner took 120 minutes for the first
/// of the build step's two commands, so the step has at least twice that. Every step has a limit of
/// its own, the limits add up to less than the job's, and the job's is under the 360 minutes at which
/// GitHub ends a hosted job, so that a step is ended by its own limit and the steps after it still
/// report.
#[test]
fn the_reference_host_job_limits_give_a_cold_build_its_time_and_fit_inside_githubs() {
    let workflow = fs::read_to_string(repository().join(".github/workflows/core-ci.yml"))
        .expect("the landing workflow");
    let text = job(&workflow, "macos-reference");
    let minutes = |text: &str, indent: usize| {
        value_at(text, indent, "timeout-minutes").and_then(|value| value.parse::<u32>().ok())
    };
    let job_limit = minutes(&header(&text), 4).expect("the job has no limit of its own");
    let steps = steps_of(&text);
    let mut total = 0;
    for step in &steps {
        total +=
            minutes(step, 8).unwrap_or_else(|| panic!("a step has no limit of its own:\n{step}"));
    }
    let build = &steps_running(&text, "cargo build")[0];
    assert!(
        minutes(build, 8).is_some_and(|limit| limit >= 240),
        "the build step has less than twice what a cold build's first command took on this runner"
    );
    assert!(
        total < job_limit,
        "the steps' limits add up to {total} minutes, which the job's {job_limit} does not exceed"
    );
    assert!(
        job_limit < 360,
        "the job's limit of {job_limit} minutes is not under the 360 GitHub ends a hosted job at"
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
const VARIABLE: &str = "KR_TEST_ARTIFACTS_DIR";

/// Each language's one reader of the variable, where its definition is, and the cases that run the
/// readers with the variable set. They are the files that may read it as they like.
const READERS: [&str; 7] = [
    "tests/support/artifacts/src/lib.rs",
    "scripts/lib/artifacts-dir.sh",
    "scripts/artifacts-dir.ps1",
    "apps/companion/e2e/evidence.ts",
    "tests/conformance/tests/artifacts_readers.rs",
    "apps/companion/test/artefacts-dir.test.ts",
    "tests/conformance/tests/ci_evidence.rs",
];

/// The languages whose files may name the variable, each with how its comments are told.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Language {
    /// Rust: `//` comments and nested `/* */` comments, strings (raw ones too) and characters.
    Rust,
    /// JavaScript and TypeScript: `//` and `/* */` comments, strings, template strings and regular
    /// expressions.
    Script,
    /// Code, a workflow or a manifest with `#` comments.
    Hash,
    /// Prose, where every line is a comment.
    Prose,
}

fn language(path: &str) -> Option<Language> {
    let extension = path.rsplit_once('.')?.1;
    match extension {
        "rs" => Some(Language::Rust),
        // Not `tsx` or `jsx`: the text of JSX looks like code and is none, and the scan cannot tell
        // the two apart, so a file of either that names the variable is one the case does not know.
        "ts" | "js" | "mjs" => Some(Language::Script),
        "sh" | "bash" | "ps1" | "psm1" | "yml" | "yaml" | "toml" => Some(Language::Hash),
        "md" => Some(Language::Prose),
        _ => None,
    }
}

/// The characters of a file with the byte each starts at.
type Chars = [(usize, char)];

/// The character at `at`, or NUL past the end (a file that holds NUL is refused before it is read).
fn char_at(chars: &Chars, at: usize) -> char {
    chars.get(at).map_or('\0', |&(_, c)| c)
}

/// The index of the newline that ends the line `from` is on, or the end.
fn line_end(chars: &Chars, from: usize) -> usize {
    (from..chars.len())
        .find(|&at| chars[at].1 == '\n')
        .unwrap_or(chars.len())
}

/// The index after the string whose opening quote is at `from`. A backslash escapes the next
/// character. A string that is not closed ends at its line's end, unless it may span lines.
fn skip_quoted(chars: &Chars, from: usize, spans_lines: bool) -> usize {
    let quote = chars[from].1;
    let mut at = from + 1;
    while at < chars.len() {
        match chars[at].1 {
            '\\' if char_at(chars, at + 1) == '\r' && char_at(chars, at + 2) == '\n' => at += 3,
            '\\' => at += 2,
            c if c == quote => return at + 1,
            '\n' if !spans_lines => return at,
            _ => at += 1,
        }
    }
    chars.len()
}

/// Where the text of a template string that starts at `from` ends: after its closing backtick, or
/// after a `${` (the second value) that opens code inside it.
fn skip_template(chars: &Chars, from: usize) -> (usize, bool) {
    let mut at = from;
    while at < chars.len() {
        match chars[at].1 {
            '\\' => at += 2,
            '`' => return (at + 1, false),
            '$' if char_at(chars, at + 1) == '{' => return (at + 2, true),
            _ => at += 1,
        }
    }
    (chars.len(), false)
}

/// The index after the regular expression whose opening slash is at `from`, flags included. One
/// that is not closed ends at its line's end.
fn skip_regex(chars: &Chars, from: usize) -> usize {
    let mut at = from + 1;
    let mut class = false;
    while at < chars.len() {
        match chars[at].1 {
            '\\' => at += 2,
            '\n' => return at,
            '[' => {
                class = true;
                at += 1;
            }
            ']' => {
                class = false;
                at += 1;
            }
            '/' if !class => {
                at += 1;
                while char_at(chars, at).is_alphanumeric() {
                    at += 1;
                }
                return at;
            }
            _ => at += 1,
        }
    }
    chars.len()
}

/// The index after the raw string whose `r` is at `from`, or `None` where none starts there.
fn skip_raw_string(chars: &Chars, from: usize) -> Option<usize> {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    if from > 0 {
        let before = chars[from - 1].1;
        let prefix = matches!(before, 'b' | 'c') && (from < 2 || !word(chars[from - 2].1));
        if word(before) && !prefix {
            return None;
        }
    }
    let mut hashes = 0;
    while char_at(chars, from + 1 + hashes) == '#' {
        hashes += 1;
    }
    if char_at(chars, from + 1 + hashes) != '"' {
        return None;
    }
    let mut at = from + 2 + hashes;
    while at < chars.len() {
        if chars[at].1 == '"' && (1..=hashes).all(|n| char_at(chars, at + n) == '#') {
            return Some(at + 1 + hashes);
        }
        at += 1;
    }
    Some(chars.len())
}

/// The index after the character literal that opens at `from`, or after the quote of a lifetime.
fn skip_character(chars: &Chars, from: usize) -> usize {
    if char_at(chars, from + 1) == '\\' {
        let close = (from + 3..chars.len()).find(|&at| matches!(chars[at].1, '\'' | '\n'));
        return close.map_or(chars.len(), |at| at + usize::from(chars[at].1 == '\''));
    }
    if char_at(chars, from + 2) == '\'' {
        from + 3
    } else {
        from + 1
    }
}

/// Calls `comment(from, to)` for each comment of Rust code, as indexes of `chars`.
fn rust_comments(chars: &Chars, comment: &mut impl FnMut(usize, usize)) {
    let mut at = 0;
    while at < chars.len() {
        match chars[at].1 {
            '/' if char_at(chars, at + 1) == '/' => {
                let end = line_end(chars, at);
                comment(at, end);
                at = end;
            }
            '/' if char_at(chars, at + 1) == '*' => {
                // Block comments nest.
                let (mut depth, mut end) = (1, at + 2);
                while end < chars.len() && depth > 0 {
                    match (chars[end].1, char_at(chars, end + 1)) {
                        ('/', '*') => (depth, end) = (depth + 1, end + 2),
                        ('*', '/') => (depth, end) = (depth - 1, end + 2),
                        _ => end += 1,
                    }
                }
                let end = end.min(chars.len());
                comment(at, end);
                at = end;
            }
            '"' => at = skip_quoted(chars, at, true),
            '\'' => at = skip_character(chars, at),
            'r' => at = skip_raw_string(chars, at).unwrap_or(at + 1),
            _ => at += 1,
        }
    }
}

/// Calls `comment(from, to)` for each comment of JavaScript or TypeScript code, as indexes of
/// `chars`.
///
/// This is a scan and no parser. It knows strings (with their escapes), template strings (with the
/// code of their `${}` parts, nested ones too), regular expressions and both kinds of comment. It
/// does not know what a slash means, so after a name, a number, a string or `]` a slash divides,
/// and after anything else, a `)` or `}` included, it opens a regular expression: a division there
/// can hide a comment opener as the end of a regular expression, and then the comment is read as
/// code. A quote that is never closed runs to the end of its line. JSX text is not told from code
/// (the language of a `.tsx` file is not known to this case). Every one of these mistakes reads
/// a comment as code, which is a finding, and none reads code as a comment.
fn script_comments(chars: &Chars, comment: &mut impl FnMut(usize, usize)) {
    // Words after which a slash opens a regular expression.
    const OPERATORS: [&str; 14] = [
        "return",
        "typeof",
        "instanceof",
        "in",
        "of",
        "new",
        "delete",
        "void",
        "throw",
        "case",
        "do",
        "else",
        "yield",
        "await",
    ];
    let is_name = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    // The `{` still open in each code part, the last one's being the `${}` part the scan is in.
    let mut braces = vec![0_usize];
    let mut value = false;
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at].1;
        match c {
            '/' if char_at(chars, at + 1) == '/' => {
                let end = line_end(chars, at);
                comment(at, end);
                at = end;
            }
            '/' if char_at(chars, at + 1) == '*' => {
                let end = (at + 2..chars.len())
                    .find(|&k| chars[k].1 == '*' && char_at(chars, k + 1) == '/')
                    .map_or(chars.len(), |k| k + 2);
                comment(at, end);
                at = end;
            }
            '/' if !value => {
                at = skip_regex(chars, at);
                value = true;
            }
            '\'' | '"' => {
                at = skip_quoted(chars, at, false);
                value = true;
            }
            '`' | '}' if c == '`' || (braces.len() > 1 && braces.last() == Some(&0)) => {
                if c == '}' {
                    braces.pop();
                }
                let (next, code) = skip_template(chars, at + 1);
                at = next;
                if code {
                    braces.push(0);
                } else {
                    value = true;
                }
            }
            '{' | '}' => {
                if let Some(open) = braces.last_mut() {
                    *open = if c == '{' {
                        *open + 1
                    } else {
                        open.saturating_sub(1)
                    };
                }
                value = false;
                at += 1;
            }
            ']' => {
                value = true;
                at += 1;
            }
            c if is_name(c) => {
                let start = at;
                while is_name(char_at(chars, at)) {
                    at += 1;
                }
                let word: String = chars[start..at].iter().map(|&(_, c)| c).collect();
                value = !OPERATORS.contains(&word.as_str());
            }
            c if c.is_whitespace() => at += 1,
            _ => {
                value = false;
                at += 1;
            }
        }
    }
}

/// For each byte of `text`, whether it is inside a comment, the comment's own marks included.
fn comment_bytes(language: Language, text: &str) -> Vec<bool> {
    let mut mask = vec![false; text.len()];
    match language {
        Language::Prose => mask.fill(true),
        Language::Hash => {
            let mut start = 0;
            for line in text.split_inclusive('\n') {
                if line.trim_start().starts_with('#') {
                    mask[start..start + line.len()].fill(true);
                }
                start += line.len();
            }
        }
        Language::Rust | Language::Script => {
            let chars: Vec<(usize, char)> = text.char_indices().collect();
            let mut comment = |from: usize, to: usize| {
                let end = chars.get(to).map_or(text.len(), |&(byte, _)| byte);
                mask[chars[from].0..end].fill(true);
            };
            if language == Language::Rust {
                rust_comments(&chars, &mut comment);
            } else {
                script_comments(&chars, &mut comment);
            }
        }
    }
    mask
}

/// Whether the file names the variable, in any letter case (Windows and a workflow's expressions
/// read a name without regard to case) and in any of the encodings a file may be written in.
fn names_variable(bytes: &[u8]) -> bool {
    let name = VARIABLE.as_bytes();
    let letter = |found: u8, wanted: u8| found.eq_ignore_ascii_case(&wanted);
    bytes.windows(name.len()).any(|w| {
        w.iter()
            .zip(name)
            .all(|(&found, &wanted)| letter(found, wanted))
    }) || bytes.windows(2 * name.len()).any(|w| {
        w.chunks(2)
            .zip(name)
            .all(|(pair, &wanted)| pair[1] == 0 && letter(pair[0], wanted))
    }) || bytes.windows(2 * name.len()).any(|w| {
        w.chunks(2)
            .zip(name)
            .all(|(pair, &wanted)| pair[0] == 0 && letter(pair[1], wanted))
    })
}

/// What a line of a workflow is, as far as the name on it goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Line {
    /// Any other line: a script's text, a key, a value.
    Plain,
    /// The directory handed to the upload of a run's evidence.
    Upload,
    /// The key of an `env:` mapping that names the variable.
    EnvKey,
}

/// One non-blank line of a workflow that is not a comment, with its indentation (a list item's dash
/// counted as part of it, so that a step's keys all stand at one column).
struct Row {
    line: usize,
    indent: usize,
    /// The key of a mapping row (`key: value`, `key:`).
    key: Option<String>,
    /// What follows the key, or the whole row where it has no key, without a comment.
    value: String,
    /// Whether the row opens a list item.
    item: bool,
    /// The row whose value this row is the text of: a block scalar's line or the continuation of a
    /// scalar that spans lines. Such a row is never a key, an item or a step.
    owner: Option<usize>,
}

/// A mapping row's key and the rest of the row after the comment is taken off: `key: value`,
/// `key:`, or a row without a key.
fn key_and_value(content: &str) -> (Option<String>, String) {
    let uncommented = |text: &str| {
        let end = if text.starts_with('#') {
            0
        } else {
            text.find(" #").unwrap_or(text.len())
        };
        text[..end].trim().to_owned()
    };
    let skip = match content.chars().next() {
        Some(quote @ ('"' | '\'')) => content[1..]
            .find(quote)
            .map_or(content.len(), |end| end + 2),
        _ => 0,
    };
    let colon = content[skip..]
        .match_indices(':')
        .map(|(at, _)| skip + at)
        .find(|&at| matches!(content[at + 1..].chars().next(), None | Some(' ' | '\t')));
    match colon {
        Some(at) => (
            Some(content[..at].trim().to_owned()),
            uncommented(&content[at + 1..]),
        ),
        None => (None, uncommented(content)),
    }
}

/// Whether a value is a block scalar's header: `|`, `>`, with a chomping or indentation mark.
fn is_block_scalar(value: &str) -> bool {
    value.starts_with(['|', '>'])
        && value[1..]
            .chars()
            .all(|c| c.is_ascii_digit() || c == '+' || c == '-')
}

/// What each line of a workflow is. The workflow is read by its structure: a row with a value owns
/// every deeper row after it as that value's text (a `run:` script, a quoted string over several
/// lines), so what looks like a step or a key inside it is neither. The upload of a run's evidence
/// is the `path:` of the `with:` of a step that uses `actions/upload-artifact`, as the value of
/// `path:` or as a line of its list: that step reads files and writes none, and the same words
/// anywhere else (a script, another action's input, a condition) are a read. A key of `env:` that
/// names the variable gives it a value.
fn workflow_lines(text: &str) -> Vec<Line> {
    let expression = format!("${{{{ ENV.{VARIABLE} }}}}");
    let mut rows: Vec<Row> = Vec::new();
    // The indentation under which rows are the text of the row that owns them.
    let mut scalar: Option<(usize, usize)> = None;
    for (line, raw) in text.lines().enumerate() {
        let trimmed = raw.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut indent = raw.len() - trimmed.len();
        let (content, item) = match trimmed.strip_prefix("- ") {
            Some(rest) => {
                let rest = rest.trim_start();
                indent += trimmed.len() - rest.len();
                (rest, true)
            }
            None => (trimmed, trimmed == "-"),
        };
        if let Some((limit, owner)) = scalar {
            if indent > limit {
                rows.push(Row {
                    line,
                    indent,
                    key: None,
                    value: trimmed.trim_end().to_owned(),
                    item: false,
                    owner: Some(owner),
                });
                continue;
            }
            scalar = None;
        }
        let (key, value) = if content == "-" {
            (None, String::new())
        } else {
            key_and_value(content.trim_end())
        };
        if !value.is_empty() {
            scalar = Some((indent, rows.len()));
        }
        rows.push(Row {
            line,
            indent,
            key,
            value,
            item,
            owner: None,
        });
    }
    // The mapping each row belongs to (the first row of it) and the row that holds it, by
    // indentation: a list item starts a mapping of its own.
    let mut levels: Vec<(usize, usize, usize)> = Vec::new();
    let mut mapping = vec![0; rows.len()];
    let mut parent: Vec<Option<usize>> = vec![None; rows.len()];
    for at in 0..rows.len() {
        if rows[at].owner.is_some() {
            continue;
        }
        while levels.last().is_some_and(|level| level.0 > rows[at].indent) {
            levels.pop();
        }
        match levels.last_mut() {
            Some(level) if level.0 == rows[at].indent => {
                if rows[at].item {
                    level.1 = at;
                }
                level.2 = at;
                mapping[at] = level.1;
            }
            _ => {
                levels.push((rows[at].indent, at, at));
                mapping[at] = at;
            }
        }
        parent[at] = levels.len().checked_sub(2).map(|above| levels[above].2);
    }
    let holds = |at: usize, key: &str| {
        rows[at].owner.is_none()
            && rows[at].key.as_deref() == Some(key)
            && rows[at].value.is_empty()
    };
    let is_upload_step = |with: usize| {
        rows.iter().enumerate().any(|(other, row)| {
            row.owner.is_none()
                && mapping[other] == mapping[with]
                && row.key.as_deref() == Some("uses")
                && row.value.starts_with("actions/upload-artifact@")
        })
    };
    let under_upload =
        |at: usize| parent[at].is_some_and(|with| holds(with, "with") && is_upload_step(with));
    let mut lines = vec![Line::Plain; text.lines().count()];
    for (at, row) in rows.iter().enumerate() {
        let names_directory = row.value.to_ascii_uppercase() == expression;
        let upload = match row.owner {
            None => row.key.as_deref() == Some("path") && names_directory && under_upload(at),
            Some(owner) => {
                names_directory
                    && rows[owner].key.as_deref() == Some("path")
                    && is_block_scalar(&rows[owner].value)
                    && under_upload(owner)
            }
        };
        let env_key = row.owner.is_none()
            && row
                .key
                .as_deref()
                .is_some_and(|key| key.eq_ignore_ascii_case(VARIABLE))
            && parent[at].is_some_and(|above| holds(above, "env"));
        if upload {
            lines[row.line] = Line::Upload;
        } else if env_key {
            lines[row.line] = Line::EnvKey;
        }
    }
    lines
}

/// Where the name stands in `line` as a whole name, in any letter case.
fn occurrences(line: &str) -> Vec<usize> {
    let word = |character: Option<char>| character.is_some_and(|c| c.is_alphanumeric() || c == '_');
    line.to_ascii_uppercase()
        .match_indices(VARIABLE)
        .map(|(at, _)| at)
        .filter(|&at| {
            !word(line[..at].chars().next_back())
                && !word(line[at + VARIABLE.len()..].chars().next())
        })
        .collect()
}

/// Whether the name at `at` is being given a value, in the one form a write takes in the file's
/// language: in Rust a program's environment (`.env("NAME", value)`); in a shell, PowerShell, a
/// workflow's script or a manifest an assignment (`NAME=value`, also behind `export`, a quote or a
/// PowerShell `$env:`). JavaScript and TypeScript have none: a script's evidence directory is the
/// reader's. A workflow's own `env:` keys are told by its structure. A write needs no proof here:
/// the reader refuses a wrong value where it is used. A name on the right of an assignment, or a
/// second name on the line, is a read.
fn is_write(language: Language, line: &str, at: usize) -> bool {
    let before = &line[..at];
    let after = &line[at + VARIABLE.len()..];
    match language {
        Language::Rust => before.ends_with(".env(\"") && after.starts_with("\","),
        Language::Script | Language::Prose => false,
        Language::Hash => {
            let assigns = after
                .trim_start()
                .strip_prefix('=')
                .is_some_and(|rest| !rest.starts_with(['=', '>']));
            let target = before.is_empty()
                || before.ends_with(char::is_whitespace)
                || before.ends_with(['"', '\'', ';'])
                || before.to_ascii_lowercase().ends_with("$env:");
            assigns && target
        }
    }
}

/// What is wrong with one file's naming of the variable, one finding for each line.
fn findings(path: &str, bytes: &[u8]) -> Vec<String> {
    if READERS.contains(&path) || !names_variable(bytes) {
        return Vec::new();
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) if !text.contains('\0') => text,
        _ => {
            return vec![format!(
                "{path}: names {VARIABLE} and is not text this case can read"
            )];
        }
    };
    let Some(language) = language(path) else {
        return vec![format!(
            "{path}: names {VARIABLE} in a language this case does not know"
        )];
    };
    let comments = comment_bytes(language, text);
    let kinds = if path.ends_with(".yml") || path.ends_with(".yaml") {
        workflow_lines(text)
    } else {
        vec![Line::Plain; text.lines().count()]
    };
    let mut found = Vec::new();
    let mut start = 0;
    for (number, piece) in text.split_inclusive('\n').enumerate() {
        let line = piece.trim_end_matches(['\n', '\r']);
        let reads = occurrences(line).into_iter().any(|at| {
            let key = line[..at].trim().is_empty() && line[at + VARIABLE.len()..].starts_with(':');
            !comments[start + at]
                && match kinds[number] {
                    Line::Upload => false,
                    Line::EnvKey if key => false,
                    _ => !is_write(language, line, at),
                }
        });
        if reads {
            found.push(format!(
                "{path}:{}: reads {VARIABLE} outside its language's reader: {}",
                number + 1,
                line.trim()
            ));
        }
        start += piece.len();
    }
    found
}

/// The files of the checkout, tracked or not yet, as their paths from the repository's root.
fn repository_files(root: &Path) -> Vec<String> {
    let listed = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .expect("git lists the repository's files");
    assert!(listed.status.success(), "git ls-files failed: {listed:?}");
    let mut files: Vec<String> = listed
        .stdout
        .split(|&byte| byte == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8(name.to_vec()).expect("a file name that is text"))
        .collect();
    files.sort();
    files.dedup();
    files
}

/// KR-REQ-27.03, the part about the build's directory: every line of the repository that reads
/// the artefacts variable is the definition of its language's reader or inside a file that tests
/// one. The readers (`kr-test-artifacts` for Rust, `scripts/lib/artifacts-dir.sh`,
/// `scripts/artifacts-dir.ps1`, `apps/companion/e2e/evidence.ts`) refuse a value outside the
/// platform's temporary roots where it is used, so the build fails there whatever way the value
/// took; their own cases run them in `artifacts_readers.rs`, in the reader's crate and in the
/// companion's tests.
///
/// So this case holds only what the readers cannot: that nothing else reads the variable. The name
/// is matched in any letter case. A name passes when it stands in a comment (found by the
/// language's own strings and comments, not by lines: a comment opener inside a string opens
/// none), or is given a value by the one form a write takes in its language (a shell's or a
/// workflow script's `NAME=value` whose value does not read it, a Rust program's
/// `.env("NAME", value)`, a key of a workflow's `env:`), or is the directory handed to the
/// `path:` of a real `actions/upload-artifact` step of a workflow as that run's evidence. Every
/// other occurrence fails with its file and line, so does a file that names it in a language this
/// case does not know or that is not text (UTF-16 included), and JavaScript and TypeScript have no
/// write form at all. Writes are not listed: a wrong write fails at the reader. The readers do not
/// export the name as a constant, which would let a file read the variable without writing the
/// name.
///
/// Not seen: a name put together at run time (or spelled with an escape), and a value that
/// reaches a program in an argument instead of the variable (the conformance runner's
/// `--evidence` passes the same check). The scan of a script is no parser; its limits all read a
/// comment as code, a finding, and each has a sample in the case that reads scripts by their
/// strings and comments.
#[test]
fn nothing_reads_the_artifacts_variable_beside_the_reader_of_its_language() {
    let root = repository();
    let mut found = Vec::new();
    let mut named = 0_usize;
    for path in repository_files(&root) {
        let file = root.join(&path);
        if !fs::symlink_metadata(&file).is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }
        let bytes = fs::read(&file).unwrap_or_else(|error| panic!("{path} is read: {error}"));
        if names_variable(&bytes) {
            named += 1;
        }
        found.extend(findings(&path, &bytes));
    }
    for reader in READERS {
        let text = fs::read_to_string(root.join(reader))
            .unwrap_or_else(|error| panic!("the reader {reader} is read: {error}"));
        assert!(text.contains(VARIABLE), "{reader} does not name {VARIABLE}");
        assert!(
            !(reader.ends_with("lib.rs") || reader.ends_with("evidence.ts"))
                || !(text.contains("pub const VARIABLE") || text.contains("export const VARIABLE")),
            "{reader} exports the variable's name"
        );
    }
    assert!(
        named > READERS.len(),
        "the case found {named} files that name {VARIABLE}"
    );
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// The case fails closed: each shape of a read in each language fails, a file it cannot read or a
/// language it does not know fails, and the shapes of a write and the reader's own file pass.
#[test]
fn the_source_case_fails_on_a_read_in_every_language_and_passes_a_write() {
    let rust = "tests/e2e/x.rs";
    let shell = "scripts/x.sh";
    let power = "scripts/x.ps1";
    let script = "apps/companion/e2e/x.ts";
    let flow = ".github/workflows/x.yml";
    for (path, line) in [
        (
            rust,
            "let dir = std::env::var_os(\"KR_TEST_ARTIFACTS_DIR\");",
        ),
        (
            rust,
            "let dir = std::env::var(NAME).or(std::env::var(\"KR_TEST_ARTIFACTS_DIR\"));",
        ),
        (shell, "artefacts=\"${KR_TEST_ARTIFACTS_DIR:-/tmp/x}\""),
        (shell, "artefacts=\"$KR_TEST_ARTIFACTS_DIR/x\""),
        (
            shell,
            "KR_TEST_ARTIFACTS_DIR=\"${KR_TEST_ARTIFACTS_DIR:-/tmp/x}\"",
        ),
        (
            shell,
            "[ \"$KR_TEST_ARTIFACTS_DIR\" = x ] && echo yes # KR_TEST_ARTIFACTS_DIR",
        ),
        (power, "$evidence = $env:KR_TEST_ARTIFACTS_DIR"),
        (
            power,
            "$env:KR_TEST_ARTIFACTS_DIR = \"$env:KR_TEST_ARTIFACTS_DIR\\x\"",
        ),
        (
            script,
            "const dir = env['KR_TEST_ARTIFACTS_DIR'] ?? '/tmp/x'",
        ),
        (script, "const dir = process.env.KR_TEST_ARTIFACTS_DIR"),
        (script, "const same = KR_TEST_ARTIFACTS_DIR == other"),
        (flow, "        run: ls \"$KR_TEST_ARTIFACTS_DIR\""),
        (
            flow,
            "          path: ${{ env.KR_TEST_ARTIFACTS_DIR }}/more",
        ),
        (
            script,
            "const { KR_TEST_ARTIFACTS_DIR = '/x' } = process.env",
        ),
        (power, "$evidence = $env:kr_test_artifacts_dir"),
        (
            rust,
            "let dir = std::env::var_os(\"kr_test_artifacts_dir\");",
        ),
        (flow, "        run: ls ${{ env.kr_test_artifacts_dir }}"),
        (
            script,
            "/* evidence */ const dir = process.env.KR_TEST_ARTIFACTS_DIR",
        ),
        (
            rust,
            "        .env(\"KR_TEST_ARTIFACTS_DIR\", std::env::var(\"KR_TEST_ARTIFACTS_DIR\").unwrap())",
        ),
        (rust, "        KR_TEST_ARTIFACTS_DIR => 1,"),
    ] {
        assert_eq!(
            findings(path, line.as_bytes()).len(),
            1,
            "{path}: {line} is a read"
        );
    }
    for (path, line) in [
        (
            rust,
            "/// KR_TEST_ARTIFACTS_DIR is where this build keeps its figures.",
        ),
        (rust, "        .env(\"KR_TEST_ARTIFACTS_DIR\", &evidence)"),
        (shell, "# KR_TEST_ARTIFACTS_DIR is not set here."),
        (
            shell,
            "KR_TEST_ARTIFACTS_DIR=\"$leg/e2e\" bash scripts/x.sh",
        ),
        (shell, "export KR_TEST_ARTIFACTS_DIR=\"$RUNNER_TEMP/x\""),
        (
            power,
            "\"KR_TEST_ARTIFACTS_DIR=$temporary\\x\" >> $env:GITHUB_ENV",
        ),
        (power, "$env:KR_TEST_ARTIFACTS_DIR = $directory"),
        (
            flow,
            "  env:\n    KR_TEST_ARTIFACTS_DIR: /tmp/kr-test-artifacts",
        ),
        (
            "docs/x.md",
            "Set `KR_TEST_ARTIFACTS_DIR` to a folder under /tmp.",
        ),
        (
            rust,
            "let other = std::env::var_os(\"MY_KR_TEST_ARTIFACTS_DIR_COPY\");",
        ),
        (
            "tests/support/artifacts/src/lib.rs",
            "std::env::var_os(\"KR_TEST_ARTIFACTS_DIR\")",
        ),
    ] {
        assert!(
            findings(path, line.as_bytes()).is_empty(),
            "{path}: {line} is not a read"
        );
    }
    assert_eq!(
        findings("data/x.json", b"{\"a\": \"KR_TEST_ARTIFACTS_DIR\"}").len(),
        1
    );
    assert_eq!(
        findings("scripts/x", b"echo $KR_TEST_ARTIFACTS_DIR").len(),
        1
    );
    assert_eq!(
        findings("scripts/x.sh", b"\xff KR_TEST_ARTIFACTS_DIR").len(),
        1
    );
    assert!(findings("scripts/x.sh", b"\xff\xfe").is_empty());
}

/// A workflow with one step: `uses` and the lines of its `with:`, then `after` as a later step.
fn step(uses: &str, with: &str) -> String {
    format!(
        "jobs:\n  run:\n    steps:\n      - name: Keep\n        uses: {uses}\n        with:\n          name: kept\n{with}\n      - name: After\n        run: true\n"
    )
}

const UPLOAD: &str = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1";

/// A line that is only the directory's expression is the upload of the run's evidence only in the
/// `with: path:` of an upload step; anywhere else, in any letter case, it is a read. A block
/// comment is a comment up to its end only.
#[test]
fn the_source_case_lets_the_evidence_upload_name_the_directory_and_nothing_else() {
    let flow = ".github/workflows/x.yml";
    let expression = "${{ env.KR_TEST_ARTIFACTS_DIR }}";
    for with in [
        format!("          path: {expression}"),
        format!(
            "          path: |\n            C:\\x.log\n            {expression}\n            !**/y/**"
        ),
        format!("          path: {}", expression.to_lowercase()),
    ] {
        assert!(
            findings(flow, step(UPLOAD, &with).as_bytes()).is_empty(),
            "an upload of the directory is no read: {with}"
        );
    }
    for (uses, with) in [
        ("actions/cache@v4", format!("          path: {expression}")),
        (
            "actions/cache@v4",
            format!("          path: |\n            {expression}"),
        ),
        (UPLOAD, format!("          name: {expression}")),
        (UPLOAD, format!("          path: {expression}/more")),
        (
            UPLOAD,
            format!("          path: x\n          key: {expression}"),
        ),
        (
            UPLOAD,
            format!("          env:\n            path: {expression}"),
        ),
    ] {
        assert_eq!(
            findings(flow, step(uses, &with).as_bytes()).len(),
            1,
            "{uses}: {with} is a read"
        );
    }
    let run = format!(
        "jobs:\n  run:\n    steps:\n      - run: |\n          mkdir -p \\\n            {expression}\n          cd \\\n            {expression}\n          adb pull x \\\n            {expression}\n"
    );
    assert_eq!(
        findings(flow, run.as_bytes()).len(),
        3,
        "a script's own line is a read"
    );
    let script = "apps/companion/e2e/x.ts";
    assert!(
        findings(
            script,
            b"/*\n * KR_TEST_ARTIFACTS_DIR is read by the reader.\n */\nconst a = 1\n"
        )
        .is_empty()
    );
    assert_eq!(
        findings(
            script,
            b"/*\n KR_TEST_ARTIFACTS_DIR\n */ const dir = process.env.KR_TEST_ARTIFACTS_DIR\n"
        )
        .len(),
        1,
        "the line that closes a block comment and goes on with code is code"
    );
}

/// A file that is not UTF-8 text names the variable without a byte string that says so.
#[test]
fn the_source_case_fails_a_file_that_names_the_variable_in_utf_16() {
    // The file ends with the name, so that neither encoding is seen through the other's reading.
    let name = "KR_TEST_ARTIFACTS_DIR";
    let little: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let big: Vec<u8> = name.encode_utf16().flat_map(u16::to_be_bytes).collect();
    for bytes in [little, big] {
        assert_eq!(findings("scripts/x.sh", &bytes).len(), 1);
    }
}

/// Asserts each sample, so that one wrong answer does not hide the others: a file's path, its text
/// and the number of lines of it that the case reports.
fn assert_findings(samples: &[(&str, &str, usize)]) {
    let wrong: Vec<String> = samples
        .iter()
        .filter_map(|&(path, text, wanted)| {
            let found = findings(path, text.as_bytes()).len();
            (found != wanted)
                .then(|| format!("{path}: {found} findings, not {wanted}, for:\n{text}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n---\n"));
}

/// A name inside a string is no comment's, and a comment opener inside a string opens none: JavaScript,
/// TypeScript and Rust files are read by their strings and comments, not by their lines.
#[test]
fn the_source_case_reads_a_script_by_its_strings_and_comments() {
    let script = "apps/companion/e2e/x.ts";
    let module = "apps/companion/e2e/x.mjs";
    let rust = "tests/e2e/x.rs";
    assert_findings(&[
        // A comment opener inside a template string exempts nothing.
        (
            module,
            "import { mkdirSync } from 'node:fs';\n\nconsole.log(`\n/*\n`);\nconst dir = process.env.KR_TEST_ARTIFACTS_DIR;\nmkdirSync(dir);\n",
            1,
        ),
        (
            module,
            "const a = `\n/*\n`;\nconst dir = process.env.KR_TEST_ARTIFACTS_DIR;\nconst b = `\n*/\n`;\n",
            1,
        ),
        (
            script,
            "const marker = '/*'; const dir = process.env.KR_TEST_ARTIFACTS_DIR\n",
            1,
        ),
        (
            script,
            "const url = \"http://x\"; const dir = process.env.KR_TEST_ARTIFACTS_DIR\n",
            1,
        ),
        (
            script,
            "const text = 'it\\'s /*'; const dir = process.env.KR_TEST_ARTIFACTS_DIR\n",
            1,
        ),
        (
            script,
            "const open = /\\/\\*/; const dir = process.env.KR_TEST_ARTIFACTS_DIR\n",
            1,
        ),
        // A regular expression that holds a comment opener hides nothing, also after a word such
        // as `return`.
        (
            script,
            "const open = /\\/\\//; const dir = process.env.KR_TEST_ARTIFACTS_DIR\n",
            1,
        ),
        (
            script,
            "function f() { return /a\\//.test(a) } const dir = process.env.KR_TEST_ARTIFACTS_DIR\n",
            1,
        ),
        // A read inside a template's substitution is a read.
        (
            script,
            "const p = `${process.env.KR_TEST_ARTIFACTS_DIR}/x`\n",
            1,
        ),
        (
            script,
            "const p = `a ${`b ${process.env.KR_TEST_ARTIFACTS_DIR}`}`\n",
            1,
        ),
        // A destructure of the environment over several lines is a read, with a default or a new
        // name, and as the parameter of a function.
        (
            script,
            "const {\n  KR_TEST_ARTIFACTS_DIR = '/tmp/default'\n} = process.env;\n",
            1,
        ),
        (
            script,
            "const {\n  KR_TEST_ARTIFACTS_DIR: evidence,\n} = process.env\n",
            1,
        ),
        (
            script,
            "const dir = (({\n  KR_TEST_ARTIFACTS_DIR: dir,\n}) => dir)(process.env)\n",
            1,
        ),
        // The same in Rust: a string that spans lines or is raw hides no read.
        (
            rust,
            "let text = r#\"a\"b /*\"#;\nlet dir = std::env::var_os(\"KR_TEST_ARTIFACTS_DIR\");\n",
            1,
        ),
        (
            rust,
            "let text = \"\n/*\n\";\nlet dir = std::env::var_os(\"KR_TEST_ARTIFACTS_DIR\");\n",
            1,
        ),
        (
            rust,
            "let text = r#\"\n/*\n\"#;\nlet dir = std::env::var_os(\"KR_TEST_ARTIFACTS_DIR\");\n",
            1,
        ),
        (
            rust,
            "let url = \"http://x\"; let dir = std::env::var_os(\"KR_TEST_ARTIFACTS_DIR\");\n",
            1,
        ),
        // A comment is a comment, after code on its line too, and within a substitution. A quote
        // that is never closed ends with its line.
        (
            script,
            "const s = 'it\n// KR_TEST_ARTIFACTS_DIR is read by the reader\n",
            0,
        ),
        (
            script,
            "const a = 1 // KR_TEST_ARTIFACTS_DIR is read by the reader\n",
            0,
        ),
        (
            script,
            "const note = `see // here`; // KR_TEST_ARTIFACTS_DIR is read by the reader\n",
            0,
        ),
        (script, "const a = `${/* KR_TEST_ARTIFACTS_DIR */ 1}`\n", 0),
        (
            rust,
            "let q = '\"'; let r: &'static str = \"\"; // KR_TEST_ARTIFACTS_DIR is set by the build\n",
            0,
        ),
        (
            rust,
            "/* a /* b */ KR_TEST_ARTIFACTS_DIR */\nfn f() {}\n",
            0,
        ),
        // What the scan does not know fails closed. A slash after `)` may open a regular
        // expression, which would hide a comment opener, so it is taken as one, and a comment after
        // a division is code. A broken quote runs to its line's end. A file of JSX, whose text is
        // not code, is a language the case does not know.
        (
            script,
            "const half = (a + b) / 2 // KR_TEST_ARTIFACTS_DIR is not read here\n",
            1,
        ),
        (
            script,
            "const s = 'it // KR_TEST_ARTIFACTS_DIR is not read here\n",
            1,
        ),
        (
            "apps/companion/src/x.tsx",
            "// KR_TEST_ARTIFACTS_DIR is not read here\n",
            1,
        ),
    ]);
}

/// A workflow is read by its structure: what stands under a `run:` scalar is that script's text,
/// never a step or a mapping of the workflow.
#[test]
fn the_source_case_reads_a_workflow_by_its_structure() {
    let flow = ".github/workflows/x.yml";
    let upload = "actions/upload-artifact@v7";
    assert_findings(&[
        // An upload step spelled inside a script's heredoc is the script's text.
        (
            flow,
            "jobs:\n  a:\n    steps:\n      - run: |\n          dir=\"$(sed -n 's/^ *path: //p' <<'EOF'\n          - uses: actions/upload-artifact@v7\n            with:\n              path: ${{ env.KR_TEST_ARTIFACTS_DIR }}\n          EOF\n          )\"\n          mkdir -p \"$dir\"\n",
            1,
        ),
        (
            flow,
            "jobs:\n  a:\n    steps:\n      - run: |\n          cat <<'EOF'\n          - uses: actions/upload-artifact@v7\n            with:\n              path: |\n                ${{ env.KR_TEST_ARTIFACTS_DIR }}\n          EOF\n",
            1,
        ),
        (
            flow,
            "jobs:\n  a:\n    steps:\n      - run: \"echo\n          uses: actions/upload-artifact@v7\n          with:\n            path: ${{ env.KR_TEST_ARTIFACTS_DIR }}\"\n",
            1,
        ),
        // A step that is not an upload does not become one because an upload step follows.
        (
            flow,
            "jobs:\n  a:\n    steps:\n      - uses: actions/cache@v4\n        with:\n          path: ${{ env.KR_TEST_ARTIFACTS_DIR }}\n      - uses: actions/upload-artifact@v7\n        with:\n          name: x\n",
            1,
        ),
        // Only a block scalar's lines are the lines of the path list.
        (
            flow,
            "jobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@v7\n        with:\n          path: a\n            ${{ env.KR_TEST_ARTIFACTS_DIR }}\n",
            1,
        ),
        // A flow mapping is not a `with:` the scan reads.
        (
            flow,
            "jobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@v7\n        with: { path: ${{ env.KR_TEST_ARTIFACTS_DIR }} }\n",
            1,
        ),
        // The directory is a key of `env:` only, and nothing else of the line reads it.
        (
            flow,
            "jobs:\n  a:\n    steps:\n      - uses: x/y@v1\n        with:\n          KR_TEST_ARTIFACTS_DIR: /tmp/x\n",
            1,
        ),
        (
            flow,
            "jobs:\n  a:\n    env:\n      KR_TEST_ARTIFACTS_DIR: ${{ env.KR_TEST_ARTIFACTS_DIR }}/x\n",
            1,
        ),
        (
            flow,
            "jobs:\n  a:\n    env:\n      KR_TEST_ARTIFACTS_DIR: /tmp/x\n",
            0,
        ),
        // A real upload step after a script is an upload.
        (
            flow,
            &format!(
                "jobs:\n  a:\n    steps:\n      - run: |\n          echo hi\n      - uses: {upload}\n        with:\n          path: ${{{{ env.KR_TEST_ARTIFACTS_DIR }}}}\n"
            ),
            0,
        ),
    ]);
}
