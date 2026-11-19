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
        // The first try and the second one: the form of both is held for every upload by the case
        // below; this one holds what these three jobs' evidence needs of each.
        let uploads = steps_holding(&text, &format!("name: {artefact}"));
        assert_eq!(
            uploads.len(),
            2,
            "the {job_name} job's upload of {artefact} is not a first try and a second one"
        );
        let id = value_at(&uploads[0], 8, "id")
            .unwrap_or_else(|| panic!("the first try of {artefact} has no id"));
        for (upload, second) in uploads.iter().zip([false, true]) {
            assert_eq!(
                value_at(upload, 10, "if-no-files-found").as_deref(),
                Some("error"),
                "the {job_name} job's upload of {artefact} does not fail when it kept nothing"
            );
            // The first try lets its failure pass to the second, and nothing else is disabled.
            assert!(
                if second {
                    !is_disabled(upload)
                } else {
                    value_at(upload, 8, "continue-on-error").as_deref() == Some("true")
                        && !is_disabled(&upload.replace("continue-on-error: true", ""))
                },
                "the {job_name} job's upload of {artefact} is disabled or lets its failure pass"
            );
            assert_eq!(
                step_condition(upload),
                Some(compact(&if second {
                    format!("${{{{ !cancelled() && steps.{id}.outcome == 'failure' }}}}")
                } else {
                    "${{ !cancelled() }}".to_owned()
                })),
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
                value_at(upload, 8, "uses")
                    .is_some_and(|action| action.starts_with("actions/upload-artifact@")),
                "the {job_name} job's upload of {artefact} is not made by the upload action"
            );
            assert_eq!(
                value_at(upload, 10, "path").map(|found| compact(&found)),
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

/// The inputs of a step: its `with:` block, without the blank line that ends the step.
fn inputs_of(step: &str) -> Option<&str> {
    step.split_once("\n        with:\n")
        .map(|(_, inputs)| inputs.trim_end())
}

/// The keys that stand at `indent` in a step, in the order they are written.
fn keys_at(step: &str, indent: usize) -> Vec<String> {
    step.lines()
        .filter_map(key_value)
        .filter(|(at, ..)| *at == indent)
        .map(|(_, key, _)| key)
        .collect()
}

/// The condition each evidence upload's first try runs under, by workflow, job and the first
/// try's id. `None` is a first try with no condition of its own, which runs whenever its job does.
/// A first try that is never true would skip both tries and leave a job's evidence unkept without
/// any step failing, so the value of each one is held here, not only that it has one.
const FIRST_TRIES: &[(&str, &str, &str, Option<&str>)] = &[
    (
        "core-ci.yml",
        "rust",
        "keep-the-deployment-legs-logs",
        Some(
            "${{ always() && ((github.event_name == 'push' && github.ref == 'refs/heads/main') || (github.event_name == 'workflow_dispatch' && inputs.deployment_legs)) }}",
        ),
    ),
    (
        "core-ci.yml",
        "rust",
        "keep-the-performance-evidence",
        Some("${{ !cancelled() }}"),
    ),
    (
        "core-ci.yml",
        "windows",
        "keep-the-test-evidence",
        Some("${{ !cancelled() }}"),
    ),
    (
        "core-ci.yml",
        "shell-packages",
        "publish-the-patch-sets-and-identity-records",
        None,
    ),
    (
        "core-ci.yml",
        "android-app",
        "keep-the-android-evidence",
        Some("${{ !cancelled() }}"),
    ),
    (
        "core-ci.yml",
        "ios",
        "keep-the-ios-evidence",
        Some("${{ !cancelled() }}"),
    ),
    (
        "core-ci.yml",
        "companion",
        "keep-the-end-to-end-evidence",
        Some("${{ !cancelled() }}"),
    ),
    (
        "core-ci.yml",
        "macos",
        "keep-the-test-evidence",
        Some("${{ !cancelled() }}"),
    ),
    (
        "core-ci.yml",
        "macos-reference",
        "keep-the-test-evidence",
        Some("${{ !cancelled() }}"),
    ),
    (
        "conformance.yml",
        "linux",
        "keep-the-result-and-the-evidence",
        Some("${{ !cancelled() }}"),
    ),
    (
        "conformance.yml",
        "macos",
        "keep-the-result-and-the-evidence",
        Some("${{ !cancelled() }}"),
    ),
    (
        "conformance.yml",
        "windows",
        "keep-the-result-and-the-evidence",
        Some("${{ !cancelled() }}"),
    ),
    ("keep-evidence-test.yml", "first-try", "first", None),
    ("keep-evidence-test.yml", "second-try", "first", None),
    ("keep-evidence-test.yml", "both-fail", "first", None),
];

/// The commands of a step's `run: |` block: the lines under the key, as they are written without
/// the indentation of the block, up to the next key or the end of the step. A line before the
/// commands, between them or after them is one of them.
fn commands_of(step: &str) -> Option<Vec<&str>> {
    let (_, block) = step.split_once("\n        run: |\n")?;
    let mut lines: Vec<&str> = block
        .lines()
        .take_while(|line| line.trim().is_empty() || line.starts_with("          "))
        .collect();
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    Some(
        lines
            .into_iter()
            .map(|line| line.strip_prefix("          ").unwrap_or(line))
            .collect(),
    )
}

/// KR-REQ-21.01, the second try of every evidence upload: the landing and conformance workflows
/// keep a job's evidence by the upload action, and a name lookup or a connection that fails for
/// a moment would fail a job whose every other step passed, hours of tests included. Each upload
/// is three steps of the workflow, the upload action named in the workflow so that the runner
/// fetches it when the job is set up: the first try, with its failure let pass; a pause of 60
/// seconds that runs only where the first try failed; and the second try, the same pinned action
/// with the same inputs, that runs only there too and whose failure fails the job. Twelve copies
/// of that cannot drift: this holds the form of every one of them, in the two workflows and in
/// the proof workflow that exercises it: the three steps in that order, the keys each one has and
/// no other (so no `overwrite`, no retention, no second `continue-on-error`), the same full pin
/// and the same inputs in both tries, the condition of the first try as written for its site, the
/// conditions of the pause and the second try that follow from it, the pause's whole command
/// block (the warning and `sleep 60`, with no line before, between or after), and a limit on all
/// three steps or on none, equal on the two tries and long enough on the pause.
#[test]
fn every_evidence_upload_has_a_second_try_after_a_pause_and_fails_the_job_when_both_fail() {
    let mut counted = Vec::new();
    for (file, expected) in [
        ("core-ci.yml", 9),
        ("conformance.yml", 3),
        ("keep-evidence-test.yml", 3),
    ] {
        let workflow = fs::read_to_string(repository().join(".github/workflows").join(file))
            .expect("a workflow");
        let mut sites = 0_usize;
        for name in jobs_of(&workflow) {
            let steps = steps_of(&job(&workflow, &name));
            let uploads: Vec<usize> = (0..steps.len())
                .filter(|&at| {
                    value_at(&steps[at], 8, "uses")
                        .is_some_and(|uses| uses.starts_with("actions/upload-artifact@"))
                })
                .collect();
            assert!(
                uploads.len().is_multiple_of(2),
                "{file}: the {name} job has an upload that is not a first try and a second one"
            );
            let mut ids = Vec::new();
            for pair in uploads.chunks(2) {
                let (at, second_at) = (pair[0], pair[1]);
                let here = format!("{file}: the {name} job's upload at step {at}");
                assert_eq!(
                    second_at,
                    at + 2,
                    "{here} is not followed by the pause and then the second try"
                );
                let (first, pause, second) = (&steps[at], &steps[at + 1], &steps[at + 2]);
                let allowed =
                    |keys: Vec<String>, permitted: &[&str], required: &[&str], what: &str| {
                        assert!(
                            keys.iter().all(|key| permitted.contains(&key.as_str())),
                            "{here}: the {what} has a key beyond {permitted:?}: {keys:?}"
                        );
                        assert!(
                            required
                                .iter()
                                .all(|key| keys.iter().any(|found| found == key)),
                            "{here}: the {what} lacks one of {required:?}: {keys:?}"
                        );
                    };

                // The first try.
                allowed(
                    keys_at(first, 8),
                    &[
                        "name",
                        "id",
                        "if",
                        "continue-on-error",
                        "timeout-minutes",
                        "uses",
                        "with",
                    ],
                    &["name", "id", "continue-on-error", "uses", "with"],
                    "first try",
                );
                assert_eq!(
                    value_at(first, 8, "continue-on-error").as_deref(),
                    Some("true"),
                    "{here}: the first try does not let its failure pass to the second"
                );
                let id = value_at(first, 8, "id").expect("the first try has an id");
                assert!(
                    !ids.contains(&id),
                    "{here}: the id {id} is used twice in the job"
                );
                ids.push(id.clone());
                let written: Vec<_> = FIRST_TRIES
                    .iter()
                    .filter(|site| site.0 == file && site.1 == name && site.2 == id)
                    .collect();
                assert_eq!(
                    written.len(),
                    1,
                    "{here}: no condition is written for the first try {id} of this job"
                );
                assert_eq!(
                    own_condition(first, 8),
                    written[0].3.map(compact),
                    "{here}: the first try's condition is not the one written for its site"
                );
                let uses = value_at(first, 8, "uses").expect("the first try is made by an action");
                let (action, pin) = uses
                    .split_once('@')
                    .expect("an action is named with its pin");
                assert_eq!(action, "actions/upload-artifact", "{here}: another action");
                assert!(
                    pin.len() == 40 && pin.chars().all(|c| c.is_ascii_hexdigit()),
                    "{here}: the upload action is not pinned by its full commit"
                );
                assert_eq!(
                    keys_at(inputs_of(first).expect("a with"), 10),
                    ["name", "path", "if-no-files-found"],
                    "{here}: the first try's inputs are not the name, the path and the rule"
                );

                // The pause and the second try run only where the first try failed, and only
                // while the run is not cancelled where the first try ran under a condition.
                let retry = match own_condition(first, 8) {
                    None => format!("${{{{ steps.{id}.outcome == 'failure' }}}}"),
                    Some(_) => {
                        format!("${{{{ !cancelled() && steps.{id}.outcome == 'failure' }}}}")
                    }
                };

                // The pause.
                allowed(
                    keys_at(pause, 8),
                    &["name", "id", "if", "timeout-minutes", "shell", "run"],
                    &["name", "if", "shell", "run"],
                    "pause",
                );
                assert_eq!(
                    own_condition(pause, 8),
                    Some(compact(&retry)),
                    "{here}: the pause's condition"
                );
                assert_eq!(
                    value_at(pause, 8, "shell").as_deref(),
                    Some("bash"),
                    "{here}: the pause's shell"
                );
                assert_eq!(
                    commands_of(pause),
                    Some(vec![
                        "echo \"::warning title=Evidence not kept::The first try failed. Trying once more in 60 seconds.\"",
                        "sleep 60",
                    ]),
                    "{here}: the pause is not the warning and then sleep 60 and nothing else"
                );

                // The second try: the same action and the same inputs.
                allowed(
                    keys_at(second, 8),
                    &["name", "id", "if", "timeout-minutes", "uses", "with"],
                    &["name", "if", "uses", "with"],
                    "second try",
                );
                assert_eq!(
                    own_condition(second, 8),
                    Some(compact(&retry)),
                    "{here}: the second try's condition"
                );
                assert_eq!(
                    value_at(second, 8, "uses"),
                    Some(uses),
                    "{here}: the second try calls another action or pin"
                );
                assert_eq!(
                    inputs_of(second),
                    inputs_of(first),
                    "{here}: the second try's inputs are not the first try's"
                );

                // Limits: on all three or on none, the same on the two tries, and the pause long
                // enough for its sleep.
                let limit = |step: &str| {
                    value_at(step, 8, "timeout-minutes")
                        .map(|value| value.parse::<u32>().expect("minutes"))
                };
                match (limit(first), limit(pause), limit(second)) {
                    (None, None, None) => {}
                    (Some(tries), Some(waits), Some(again)) => {
                        assert_eq!(tries, again, "{here}: the two tries have different limits");
                        assert!(
                            waits >= 2,
                            "{here}: the pause's limit would cut its sleep of 60 seconds"
                        );
                    }
                    other => panic!(
                        "{here}: a limit on some of the three steps and not on all: {other:?}"
                    ),
                }
                sites += 1;
            }
        }
        counted.push((file, sites, expected));
    }
    assert_eq!(
        FIRST_TRIES.len(),
        counted.iter().map(|(_, sites, _)| sites).sum::<usize>(),
        "the table of first conditions names every evidence upload with a second try and no other"
    );
    for (file, sites, expected) in counted {
        assert_eq!(
            sites, expected,
            "{file}: the number of evidence uploads with a second try"
        );
    }
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

/// The names of the jobs of a workflow, in the order they are written.
fn job_names(workflow: &str) -> Vec<String> {
    let mut in_jobs = false;
    let mut names = Vec::new();
    for line in workflow.lines() {
        if line == "jobs:" {
            in_jobs = true;
        } else if in_jobs
            && line.starts_with("  ")
            && !line.starts_with("   ")
            && !line.trim_start().starts_with('#')
            && without_comment(line).ends_with(':')
        {
            names.push(
                without_comment(line)
                    .trim()
                    .trim_end_matches(':')
                    .to_owned(),
            );
        }
    }
    names
}

/// The tests that start a daemon through the user's service manager load jobs into the account's
/// own launchd on macOS, and stand down, or run detached, in a run that does not set
/// `KR_ALLOW_ACCOUNT_LAUNCHD`, as a person's own Mac does. Every macOS job of the landing workflow
/// that runs the workspace's tests, the end-to-end demonstrations or the performance measurements
/// sets it for the whole job, and so does the macOS job of the conformance workflow, so that those
/// runs happen on the runner whose account is for the run alone and are not reported as passed
/// without having run.
#[test]
fn the_macos_runs_of_the_workspace_tests_ask_for_the_accounts_launchd() {
    let variable = "KR_ALLOW_ACCOUNT_LAUNCHD: \"1\"";
    let landing = fs::read_to_string(repository().join(".github/workflows/core-ci.yml"))
        .expect("the landing workflow");
    let asking: Vec<String> = job_names(&landing)
        .into_iter()
        .filter(|name| {
            let text = job(&landing, name);
            header(&text)
                .lines()
                .any(|line| line.trim().starts_with("runs-on: macos"))
                && steps_of(&text).iter().any(|step| {
                    step.lines().any(|line| {
                        [
                            "cargo test --locked --workspace",
                            "scripts/end-to-end.sh",
                            "scripts/performance.sh",
                        ]
                        .iter()
                        .any(|tool| starts(line, tool))
                    })
                })
        })
        .collect();
    // A selection that finds nothing would pass for every job: the two jobs that exist are named.
    for name in ["macos", "macos-reference"] {
        assert!(
            asking.iter().any(|found| found == name),
            "the {name} job of the landing workflow is no macOS job that runs the workspace's tests, \
             the demonstrations or the measurements; found {asking:?}"
        );
    }
    for name in &asking {
        assert!(
            header(&job(&landing, name))
                .lines()
                .any(|line| line.trim() == variable),
            "the {name} job of the landing workflow runs the workspace's tests, the end-to-end \
             demonstrations or the measurements on macOS and does not ask for the account's own \
             launchd in its own environment"
        );
    }
    let report = fs::read_to_string(repository().join(".github/workflows/conformance.yml"))
        .expect("the conformance workflow");
    // Among the job's own keys, in its environment ahead of its steps, so that every step that runs
    // tests has it.
    assert!(
        header(&job(&report, "macos"))
            .lines()
            .any(|line| line.trim() == variable),
        "the macOS job of the conformance workflow does not ask for the account's own launchd in \
         its own environment"
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

/// A step of the plan builds the report's own package again, and Windows does not let the program
/// that is running be replaced, so the report never runs from the file the build wrote. No job of
/// the conformance workflow starts it with `cargo run`, and the Windows job runs a copy of it.
#[test]
fn no_job_of_the_conformance_workflow_runs_the_report_from_the_file_the_build_wrote() {
    let report = fs::read_to_string(repository().join(".github/workflows/conformance.yml"))
        .expect("the conformance workflow");
    for line in report
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
    {
        assert!(
            !(line.contains("cargo run") && line.contains("kr-conformance")),
            "the conformance workflow starts the report with cargo run: {line}"
        );
    }
    let starting = steps_holding(&job(&report, "windows"), "kr-conformance.exe");
    assert!(
        starting.iter().all(|step| step.contains("Copy-Item")),
        "the Windows job runs the report's program without copying it first"
    );
}

/// A person on Windows is shown the PowerShell commands that start the report twice: in the guide,
/// and in what the script prints where it refuses to run there. They are the same lines.
#[test]
fn the_guides_powershell_block_is_what_the_script_prints_on_windows() {
    let guide = fs::read_to_string(repository().join("docs/conformance/README.md"))
        .expect("the conformance guide");
    let block: Vec<&str> = guide
        .lines()
        .skip_while(|line| *line != "```powershell")
        .skip(1)
        .take_while(|line| *line != "```")
        .collect();
    assert!(!block.is_empty(), "the guide holds no PowerShell block");
    let script = fs::read_to_string(repository().join("scripts/run-conformance.sh"))
        .expect("the conformance script");
    // The lines after the one that says to start the report from PowerShell, up to the script's
    // exit: each is an `echo` of the line, two spaces in, to the error output.
    let printed: Vec<String> = script
        .lines()
        .skip_while(|line| !line.contains("start the report from PowerShell"))
        .skip(1)
        .take_while(|line| line.trim() != "exit 2")
        .map(|line| {
            let echoed = line
                .trim()
                .strip_prefix("echo ")
                .and_then(|rest| rest.strip_suffix(" >&2"))
                .unwrap_or_else(|| panic!("not an echo to the error output: {line}"));
            let quoted = &echoed[1..echoed.len() - 1];
            quoted
                .strip_prefix("  ")
                .unwrap_or_else(|| panic!("not two spaces in: {line}"))
                .to_owned()
        })
        .collect();
    assert_eq!(
        printed, block,
        "the script prints other commands than the guide shows for Windows"
    );
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

/// How a file that holds the name may hold it.
enum Use {
    /// A reader of the variable, or this case with its list and samples: the name may stand
    /// anywhere in the file.
    Reader,
    /// A setter or a mention: only the lines listed, each as its text with the white space at both
    /// ends taken off, with the number of lines that have exactly that text. A line that is not
    /// listed fails, and so does a listed line that is gone or that stands another number of
    /// times.
    Lines(&'static [(&'static str, usize)]),
}

/// A file that may hold the name, and how.
struct Listed {
    path: &'static str,
    uses: Use,
}

const fn reader(path: &'static str) -> Listed {
    Listed {
        path,
        uses: Use::Reader,
    }
}

const fn lines(path: &'static str, lines: &'static [(&'static str, usize)]) -> Listed {
    Listed {
        path,
        uses: Use::Lines(lines),
    }
}

/// Every file of the repository that holds the name, in the order of their paths, with one comment
/// line for each that says why it may. This is the one place that decides it: a new use of the
/// variable anywhere, or a changed line that holds the name, is a change to this list.
const LIST: &[Listed] = &[
    // Sets the folder in each job's `env:` (a Windows step in `GITHUB_ENV`) and uploads it as `path:`.
    lines(
        ".github/workflows/conformance.yml",
        &[
            ("KR_TEST_ARTIFACTS_DIR: /tmp/kr-conformance-evidence", 2),
            ("path: ${{ env.KR_TEST_ARTIFACTS_DIR }}", 6),
            (
                r#""KR_TEST_ARTIFACTS_DIR=$temporary\kr-conformance-evidence" >> $env:GITHUB_ENV"#,
                1,
            ),
        ],
    ),
    // Sets the folder in `env:` (Windows in `GITHUB_ENV`, one shell step by `export`), uploads it as `path:`.
    lines(
        ".github/workflows/core-ci.yml",
        &[
            ("KR_TEST_ARTIFACTS_DIR: /tmp/kr-test-artifacts", 2),
            (
                r#"# `KR_TEST_ARTIFACTS_DIR`, which "Keep the deployment legs' logs" below uploads, with the"#,
                1,
            ),
            (
                r#""KR_TEST_ARTIFACTS_DIR=$temporary\kr-test-artifacts" >> $env:GITHUB_ENV"#,
                1,
            ),
            ("path: ${{ env.KR_TEST_ARTIFACTS_DIR }}", 10),
            ("KR_TEST_ARTIFACTS_DIR: /tmp/kr-shell-qualification", 1),
            (
                r#"export KR_TEST_ARTIFACTS_DIR="$RUNNER_TEMP/kr-shell-qualification-second""#,
                1,
            ),
        ],
    ),
    // Sets the folder in `GITHUB_ENV` for the Windows steps and uploads it with the log.
    lines(
        ".github/workflows/wsl-acceptance.yml",
        &[
            (
                r#""KR_TEST_ARTIFACTS_DIR=$directory" >> $env:GITHUB_ENV"#,
                1,
            ),
            ("${{ env.KR_TEST_ARTIFACTS_DIR }}", 1),
        ],
    ),
    // Reader: the one reader of the variable for TypeScript.
    reader("apps/companion/e2e/evidence.ts"),
    // The TypeScript reader's own cases: they set the variable and match its name in the refusal.
    // A line puts the name into a constant, so each later use of the constant in this file passes
    // unseen: the file is read as a reader's cases.
    lines(
        "apps/companion/test/artefacts-dir.test.ts",
        &[
            (
                "// KR-REQ-27.03: the reader of `KR_TEST_ARTIFACTS_DIR` for TypeScript refuses a value outside this",
                1,
            ),
            ("const VARIABLE = 'KR_TEST_ARTIFACTS_DIR'", 1),
            (
                "expect(() => read(elsewhere)).toThrow(/KR_TEST_ARTIFACTS_DIR.*temporary roots/s)",
                1,
            ),
            (
                "expect(() => read(value)).toThrow(/KR_TEST_ARTIFACTS_DIR.*temporary roots/s)",
                1,
            ),
        ],
    ),
    // A comment that says where the run's figures are kept.
    lines(
        "crates/kr-term/tests/perf.rs",
        &[(
            "/// release run's evidence to be kept. `KR_TEST_ARTIFACTS_DIR` is where this build puts that, and a",
            1,
        )],
    ),
    // A comment that says where the run's figures are kept.
    lines(
        "crates/kr-transport/tests/support/conditions.rs",
        &[(
            "/// release run's evidence to be kept. `KR_TEST_ARTIFACTS_DIR` is where this build puts that, and a",
            1,
        )],
    ),
    // A comment that says where the measurements' record is kept.
    lines(
        "crates/kr-worker/benches/input_latency.rs",
        &[(
            "/// The record these measurements' figures are kept in, under `KR_TEST_ARTIFACTS_DIR`.",
            1,
        )],
    ),
    // A comment that says where the suite's record is kept.
    lines(
        "crates/kr-worker/tests/performance.rs",
        &[(
            "/// The record this suite's figures are kept in, under `KR_TEST_ARTIFACTS_DIR`.",
            1,
        )],
    ),
    // A document that names the variable where the client suites keep their output.
    lines(
        "docs/client/README.md",
        &[(
            "under the directory `KR_TEST_ARTIFACTS_DIR` names, so a leg that failed keeps its whole output and",
            1,
        )],
    ),
    // A document that names the variable where the mobile suites keep their screenshots.
    lines(
        "docs/client/mobile.md",
        &[
            (
                "`companion-screenshots` in the directory `KR_TEST_ARTIFACTS_DIR` names. `scripts/check-test-evidence.sh`",
                1,
            ),
            (
                "the directory `KR_TEST_ARTIFACTS_DIR` names. `KR_IOS_DEVICE` chooses the simulator.",
                1,
            ),
        ],
    ),
    // A document that names the variable as the evidence directory of the report and of the workflow.
    lines(
        "docs/conformance/README.md",
        &[
            (
                "The evidence directory is `KR_TEST_ARTIFACTS_DIR`, or a new directory under the platform's temporary",
                1,
            ),
            (
                "step of the report runs with `KR_TEST_ARTIFACTS_DIR` naming the same directory, so what a test",
                1,
            ),
            (
                "`KR_TEST_ARTIFACTS_DIR` and collected into the CI artifact store. The landing workflow",
                1,
            ),
            (
                "`KR_TEST_ARTIFACTS_DIR` and uploads that directory: `companion-evidence-<runner>` for the browser",
                1,
            ),
            (
                "A performance test that records its figure under `KR_TEST_ARTIFACTS_DIR`, as a Markdown section",
                1,
            ),
        ],
    ),
    // A document that names the variable where the host suite keeps its evidence.
    lines(
        "docs/host/README.md",
        &[(
            "`KR_TEST_ARTIFACTS_DIR`, and it asks for no account of any kind. It needs macOS and a person",
            1,
        )],
    ),
    // A document that names the variable where the performance figures are kept.
    lines(
        "docs/performance/README.md",
        &[
            (
                "`kr-controller-reconnect.md` in the directory `KR_TEST_ARTIFACTS_DIR` names, in the form the records below take: the build, the operating system",
                1,
            ),
            (
                "Every measurement of `scripts/bench-all.sh` writes each figure under `KR_TEST_ARTIFACTS_DIR` as a",
                1,
            ),
        ],
    ),
    // A document that names the variable where the qualification keeps its evidence.
    lines(
        "docs/shell-integration/qualification.md",
        &[
            (
                "every case. Its evidence goes to the directory `KR_TEST_ARTIFACTS_DIR` names, including",
                1,
            ),
            (
                "evidence to `KR_TEST_ARTIFACTS_DIR`, or, where that is unset, to a directory it makes for itself in",
                1,
            ),
        ],
    ),
    // A document that names the variable where each run writes its figures and its verdict.
    lines(
        "docs/terminal/README.md",
        &[(
            "Each run writes its host, its figures and its verdict to the directory `KR_TEST_ARTIFACTS_DIR`",
            1,
        )],
    ),
    // Reader: the one reader of the variable for PowerShell.
    reader("scripts/artifacts-dir.ps1"),
    // Comments that say where every measurement writes its figures.
    lines(
        "scripts/bench-all.sh",
        &[
            (
                "# Every measurement writes its figures under KR_TEST_ARTIFACTS_DIR as Markdown sections headed by",
                1,
            ),
            (
                "# KR_TEST_ARTIFACTS_DIR is not set, the run makes a directory of its own and says where it is.",
                1,
            ),
        ],
    ),
    // A comment that says which directory holds the collected screenshots.
    lines(
        "scripts/check-test-evidence.sh",
        &[(
            "# Section 21 collects the screenshots of the tests into one directory, `KR_TEST_ARTIFACTS_DIR`,",
            1,
        )],
    ),
    // Starts a program with the variable set to the reader's own directory.
    lines(
        "scripts/e2e-fence.sh",
        &[(r#"if ! KR_TEST_ARTIFACTS_DIR="$artifacts" \"#, 1)],
    ),
    // Starts the update suite with the variable set to a folder of its own under its work folder.
    lines(
        "scripts/e2e-update.sh",
        &[(
            r#"KR_E2E_PROGRAMS="$programs" KR_E2E_STATE="$work/state-permissions" KR_TEST_ARTIFACTS_DIR="$work/artifacts" \"#,
            1,
        )],
    ),
    // Starts the device script with the variable set to a folder under the reader's directory.
    lines(
        "scripts/e2e-voice-call-device.sh",
        &[(
            r#"KR_HARNESS_PLATFORM="$platform" KR_TEST_ARTIFACTS_DIR="$artefacts" \"#,
            1,
        )],
    ),
    // A comment that says where every artefact is written.
    lines(
        "scripts/e2e-wsl.sh",
        &[(
            "# Every artefact is written under the directory KR_TEST_ARTIFACTS_DIR names. The Windows",
            1,
        )],
    ),
    // Reader: the one reader of the variable for shell.
    reader("scripts/lib/artifacts-dir.sh"),
    // Starts the release check with the variable set to a temporary folder it made.
    lines(
        "scripts/lib/store-build.sh",
        &[(
            r#"KR_TEST_ARTIFACTS_DIR="$evidence" KR_RELEASE_APK="$package" bash "$repository/scripts/e2e-android-release.sh" \"#,
            1,
        )],
    ),
    // Gives the suites a directory under the run's own temporary folder, for the records that the
    // script then appends to the directory that the caller named.
    lines(
        "scripts/performance.sh",
        &[(r#"export KR_TEST_ARTIFACTS_DIR="$run_evidence""#, 1)],
    ),
    // A comment that says where the evidence directory is.
    lines(
        "scripts/run-conformance.sh",
        &[(
            "# The evidence directory is KR_TEST_ARTIFACTS_DIR, or a new directory under the platform's",
            1,
        )],
    ),
    // Comments on where the performance figures are recorded and the rule that confines the folder.
    lines(
        "tests/conformance/src/evidence.rs",
        &[
            (
                "//! The figures the performance tests record under `KR_TEST_ARTIFACTS_DIR`, and the rule for where",
                1,
            ),
            (
                "/// files. The rule is the one every reader of `KR_TEST_ARTIFACTS_DIR` applies, from",
                1,
            ),
        ],
    ),
    // The report passes the checked evidence directory to each step it starts.
    lines(
        "tests/conformance/src/run.rs",
        &[
            (
                "//! evidence directory, `KR_TEST_ARTIFACTS_DIR` naming that directory, so what a test records beside",
                1,
            ),
            (r#".env("KR_TEST_ARTIFACTS_DIR", self.evidence)"#, 1),
        ],
    ),
    // A comment on where a known difference is recorded.
    lines(
        "tests/conformance/tests/applications/harness.rs",
        &[(
            "/// a section of its own, never as a pass. Where `KR_TEST_ARTIFACTS_DIR` is not set the record is",
            1,
        )],
    ),
    // The shell and PowerShell readers' own cases: they set the variable and read it back from the child.
    // A line puts the name into a constant, so each later use of the constant in this file passes
    // unseen: the file is read as a reader's cases.
    lines(
        "tests/conformance/tests/artifacts_readers.rs",
        &[
            (
                "//! KR-REQ-27.03: the readers of `KR_TEST_ARTIFACTS_DIR` for shell and for PowerShell.",
                1,
            ),
            (r#"const VARIABLE: &str = "KR_TEST_ARTIFACTS_DIR";"#, 1),
            (
                "/// What `KR_TEST_ARTIFACTS_DIR` was once the reader had run.",
                1,
            ),
            (
                r##"printf 'directory=%s\nexported=%s\n' "$kr_artifacts" "$(printenv KR_TEST_ARTIFACTS_DIR)""#,"##,
                1,
            ),
            (
                r##""exported=$([System.Environment]::GetEnvironmentVariable('KR_TEST_ARTIFACTS_DIR'))""#,"##,
                1,
            ),
        ],
    ),
    // Reader: this case: its list and its samples spell the name.
    reader("tests/conformance/tests/ci_evidence.rs"),
    // The case sets the variable for the device scripts it starts, under its own temporary folder.
    lines(
        "tests/conformance/tests/device_scripts.rs",
        &[(
            r#".env("KR_TEST_ARTIFACTS_DIR", root.join("scratch/artefacts"))"#,
            1,
        )],
    ),
    // The case sets the variable for the program it starts, under its own temporary folder.
    lines(
        "tests/conformance/tests/fetch.rs",
        &[(
            r#".env("KR_TEST_ARTIFACTS_DIR", self.path("tmp/evidence"))"#,
            1,
        )],
    ),
    // The case sets the variable for the program it starts, under the temporary folder.
    lines(
        "tests/e2e/m1b/tests/origin.rs",
        &[(r#".env("KR_TEST_ARTIFACTS_DIR", &artefacts)"#, 1)],
    ),
    // A comment on where the measured figures are recorded.
    lines(
        "tests/perf/src/lib.rs",
        &[(
            "//! under `KR_TEST_ARTIFACTS_DIR`, headed by the identifier it measures. [`process`] reads what the",
            1,
        )],
    ),
    // Comments on where the figures are appended and on an unset run.
    lines(
        "tests/perf/src/record.rs",
        &[
            (
                "//! [`report`] prints them and appends them under `KR_TEST_ARTIFACTS_DIR` as one Markdown section",
                1,
            ),
            (
                "/// A run that has not set `KR_TEST_ARTIFACTS_DIR` keeps the section in a directory of its own under",
                1,
            ),
        ],
    ),
    // Runs the performance script with a stand-in measurement, with the variable set to a folder
    // under its temporary folder, or removed; the stand-in for a process that records late reads it.
    lines(
        "tests/perf/tests/evidence.rs",
        &[
            (r#".env_remove("KR_TEST_ARTIFACTS_DIR");"#, 1),
            (r#"command.env("KR_TEST_ARTIFACTS_DIR", evidence);"#, 1),
            (r#"evidence="$KR_TEST_ARTIFACTS_DIR""#, 1),
        ],
    ),
    // Runs the performance script with the evidence variable removed: its temporary folder is the
    // case's own.
    lines(
        "tests/perf/tests/settle.rs",
        &[(r#".env_remove("KR_TEST_ARTIFACTS_DIR")"#, 1)],
    ),
    // A comment on where the stress figures are recorded.
    lines(
        "tests/perf/tests/stress.rs",
        &[(
            "//! Each figure is recorded in `kr-perf-stress.md` under `KR_TEST_ARTIFACTS_DIR`, headed by the",
            1,
        )],
    ),
    // Starts a case of the calling program as a caller does that names an evidence directory under
    // its own temporary folder.
    lines(
        "tests/perf/tests/support/mod.rs",
        &[(
            r#".env("KR_TEST_ARTIFACTS_DIR", physical.join("evidence"))"#,
            1,
        )],
    ),
    // Runs the performance script with the evidence variable removed: its temporary folder is the
    // case's own.
    lines(
        "tests/perf/tests/survivors.rs",
        &[(r#".env_remove("KR_TEST_ARTIFACTS_DIR")"#, 1)],
    ),
    // Reader: the one reader of the variable for Rust.
    reader("tests/support/artifacts/src/lib.rs"),
];

/// The encodings in which `bytes` hold the name, in any ASCII letter case (Windows and a
/// workflow's expressions read a name without regard to case): UTF-8 (which is also every encoding
/// that keeps ASCII as it is), and UTF-16 and UTF-32 in both byte orders. The bytes are searched
/// as they are: nothing of the file's language is read.
fn encodings_naming(bytes: &[u8]) -> Vec<&'static str> {
    let name = VARIABLE.as_bytes();
    // Each encoding, the width of one character in it and the place of the letter in that width.
    [
        ("UTF-8", 1, 0),
        ("UTF-16LE", 2, 0),
        ("UTF-16BE", 2, 1),
        ("UTF-32LE", 4, 0),
        ("UTF-32BE", 4, 3),
    ]
    .into_iter()
    .filter(|&(_, width, letter)| {
        bytes.windows(width * name.len()).any(|window| {
            window.chunks(width).zip(name).all(|(unit, wanted)| {
                unit.iter().enumerate().all(|(place, byte)| {
                    if place == letter {
                        byte.eq_ignore_ascii_case(wanted)
                    } else {
                        *byte == 0
                    }
                })
            })
        })
    })
    .map(|(encoding, ..)| encoding)
    .collect()
}

/// The lines of the file, read as UTF-8, that hold the name: each with its number from 1 and its
/// text with the white space at both ends taken off. A line ends at a line feed and nowhere else,
/// so a line that is cut by another line terminator is one line whose text does not match.
fn lines_naming(bytes: &[u8]) -> Vec<(usize, String)> {
    String::from_utf8_lossy(bytes)
        .split('\n')
        .enumerate()
        .filter(|(_, line)| line.to_ascii_uppercase().contains(VARIABLE))
        .map(|(at, line)| (at + 1, line.trim().to_owned()))
        .collect()
}

/// What is wrong with a file that holds the name and is on no list: one finding for each line, and
/// one for each other encoding that holds it.
fn unlisted(path: &str, bytes: &[u8], encodings: &[&str]) -> Vec<String> {
    let mut found: Vec<String> = lines_naming(bytes)
        .into_iter()
        .map(|(number, text)| {
            format!("{path}:{number}: holds {VARIABLE} and is on no list: {text}")
        })
        .collect();
    for encoding in encodings.iter().filter(|&&encoding| encoding != "UTF-8") {
        found.push(format!(
            "{path}: holds {VARIABLE} in {encoding} and is on no list"
        ));
    }
    found
}

/// What is wrong with a file that holds the name and lists its lines.
fn against(path: &str, bytes: &[u8], encodings: &[&str], listed: &[(&str, usize)]) -> Vec<String> {
    let mut found = Vec::new();
    for encoding in encodings.iter().filter(|&&encoding| encoding != "UTF-8") {
        found.push(format!(
            "{path}: holds {VARIABLE} in {encoding}, which no listed line can be"
        ));
    }
    let held = lines_naming(bytes);
    for (number, text) in &held {
        if !listed.iter().any(|(line, _)| line == text) {
            found.push(format!(
                "{path}:{number}: a line that holds {VARIABLE} and is not on the list: {text}"
            ));
        }
    }
    for (line, wanted) in listed {
        let present = held.iter().filter(|(_, text)| text == line).count();
        if present != *wanted {
            found.push(format!(
                "{path}: the list has {wanted} line(s) `{line}` and the file has {present}"
            ));
        }
    }
    found
}

/// What is wrong with the files' holding of the name, one finding for each file or line: `files`
/// are files of the repository with their bytes, and `list` says which of them may hold the name
/// and how. A listed file that no longer holds it is a finding too, so that the list cannot fall
/// behind.
fn judge(list: &[Listed], files: &[(String, Vec<u8>)]) -> Vec<String> {
    let mut found = Vec::new();
    let mut holding = std::collections::HashSet::new();
    for (path, bytes) in files {
        let encodings = encodings_naming(bytes);
        if encodings.is_empty() {
            continue;
        }
        holding.insert(path.as_str());
        match list.iter().find(|entry| entry.path == path.as_str()) {
            None => found.extend(unlisted(path, bytes, &encodings)),
            Some(Listed {
                uses: Use::Reader, ..
            }) => {}
            Some(Listed {
                uses: Use::Lines(listed),
                ..
            }) => found.extend(against(path, bytes, &encodings, listed)),
        }
    }
    for entry in list {
        if !holding.contains(entry.path) {
            found.push(format!(
                "{}: is on the list and does not hold {VARIABLE}",
                entry.path
            ));
        }
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

/// KR-REQ-27.03, the part about the build's directory: the variable's name stands only in the files
/// of the list above. Every file of the repository is searched for the name as plain bytes (UTF-8,
/// UTF-16 and UTF-32, in any ASCII letter case), whatever its language and whether the name stands
/// in code, a comment, a string or a document: no comment, string, heredoc or workflow structure is
/// read. A file that holds it is a reader, where the name may stand anywhere, or lists each line
/// that holds it as its trimmed text with the number of such lines. A file on no list fails with
/// its path and line; so does a line that is not listed, a listed line that is gone or stands
/// another number of times, and a listed file that no longer holds the name.
///
/// The readers (`kr-test-artifacts` for Rust, `scripts/lib/artifacts-dir.sh`,
/// `scripts/artifacts-dir.ps1`, `apps/companion/e2e/evidence.ts`) refuse a value outside the
/// platform's temporary roots where it is used, so a build fails there whatever way a value took;
/// their own cases run them in `artifacts_readers.rs`, in the reader's crate and in the
/// companion's tests. This case holds what they cannot: that no other file reads the variable.
///
/// Not seen: a name put together at run time or spelled with an escape (no file holds its bytes),
/// and a value that reaches a program in an argument instead of the variable (the conformance
/// runner's `--evidence` passes the same check). A pinned line holds its text and its count, not
/// its place: it can move inside its file (a bare workflow line into the heredoc of a `run:`
/// script) or have a step's `uses:` changed above it, and only the file's diff shows that. A line
/// that puts the name into a constant opens the later uses of that constant in its file, which is
/// why the two files that do so (`artifacts_readers.rs` and `artefacts-dir.test.ts`, each holding
/// the readers' own cases) are said to in their entries.
#[test]
fn the_artifacts_variable_stands_only_in_the_files_the_list_names() {
    let root = repository();
    let mut files = Vec::new();
    for path in repository_files(&root) {
        let file = root.join(&path);
        if !fs::symlink_metadata(&file).is_ok_and(|metadata| metadata.is_file()) {
            continue;
        }
        let bytes = fs::read(&file).unwrap_or_else(|error| panic!("{path} is read: {error}"));
        if !encodings_naming(&bytes).is_empty() {
            files.push((path, bytes));
        }
    }
    let found = judge(LIST, &files);
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// The list is read by people and holds what it says: the paths are in order and each stands once,
/// and every listed line is text with no white space at its ends that holds the name, with a
/// number of lines that is at least one, once in its file's entry.
#[test]
fn the_list_names_each_file_once_and_each_line_as_its_trimmed_text() {
    for pair in LIST.windows(2) {
        assert!(
            pair[0].path < pair[1].path,
            "{} is not before {} in the list",
            pair[0].path,
            pair[1].path
        );
    }
    assert!(!LIST.is_empty());
    for entry in LIST {
        let Use::Lines(listed) = &entry.uses else {
            continue;
        };
        assert!(!listed.is_empty(), "{} lists no line", entry.path);
        for (at, (text, count)) in listed.iter().enumerate() {
            assert_eq!(
                *text,
                text.trim(),
                "{}: `{text}` is not trimmed",
                entry.path
            );
            assert!(
                text.to_ascii_uppercase().contains(VARIABLE) && !text.contains('\n'),
                "{}: `{text}` is not one line that holds {VARIABLE}",
                entry.path
            );
            assert!(*count >= 1, "{}: `{text}` is listed 0 times", entry.path);
            assert!(
                listed[..at].iter().all(|(earlier, _)| earlier != text),
                "{}: `{text}` is listed twice",
                entry.path
            );
        }
    }
}

/// A file as the case reads it: its path and its bytes.
fn file(path: &str, bytes: impl AsRef<[u8]>) -> (String, Vec<u8>) {
    (path.to_owned(), bytes.as_ref().to_vec())
}

/// What the case says of one file that is not on the list: the findings that name its path. No
/// other entry of the list is stale for this one file, so only its own findings are kept.
fn findings_of(path: &str, bytes: impl AsRef<[u8]>) -> Vec<String> {
    assert!(
        LIST.iter().all(|entry| entry.path != path),
        "{path} is on the list, so it is no sample of a file that is not"
    );
    judge(LIST, &[file(path, bytes)])
        .into_iter()
        .filter(|finding| finding.starts_with(&format!("{path}:")))
        .collect()
}

/// Whole file texts that hold the name and are on no list, each spelled the way that once made a
/// scan of the file's language read the name as something else: a comment, a string, a step of a
/// workflow, a write. None has to be read as what it is: each fails because it is on no list.
const SAMPLES: &[(&str, &str, &str)] = &[
    (
        "a read in Rust",
        "tests/e2e/x.rs",
        "let dir = std::env::var_os(\"KR_TEST_ARTIFACTS_DIR\");\n",
    ),
    (
        "a write for a child process in Rust",
        "tests/e2e/x.rs",
        "        .env(\"KR_TEST_ARTIFACTS_DIR\", &evidence)\n",
    ),
    (
        "a default in a shell expansion",
        "scripts/x.sh",
        "artefacts=\"${KR_TEST_ARTIFACTS_DIR:-/tmp/x}\"\n",
    ),
    (
        "a shell assignment whose value reads the variable",
        "scripts/x.sh",
        "KR_TEST_ARTIFACTS_DIR=\"${KR_TEST_ARTIFACTS_DIR:-/tmp/x}\"\n",
    ),
    (
        "a shell assignment",
        "scripts/x.sh",
        "export KR_TEST_ARTIFACTS_DIR=\"$RUNNER_TEMP/x\"\n",
    ),
    (
        "a read of a PowerShell variable",
        "scripts/x.ps1",
        "$evidence = $env:KR_TEST_ARTIFACTS_DIR\n",
    ),
    (
        "a PowerShell assignment whose value becomes an unchecked path",
        "scripts/x.ps1",
        r#"$dir = ($env:KR_TEST_ARTIFACTS_DIR = (Join-Path $env:USERPROFILE 'kr-proof'))
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Set-Content -LiteralPath "$dir/proof.txt" -Value proof
"#,
    ),
    (
        "a PowerShell here-string whose line starts with a number sign",
        "scripts/x.ps1",
        "$dir = @\"\n#$env:KR_TEST_ARTIFACTS_DIR\n\"@\nSet-Content -LiteralPath ($dir.Substring(1) + '/proof.txt') -Value proof\n",
    ),
    (
        "a shell string whose line starts with a number sign",
        "scripts/x.sh",
        "dir=\"\n#$KR_TEST_ARTIFACTS_DIR\n\"\nmkdir -p \"${dir:1}\"\n",
    ),
    (
        "an unquoted heredoc whose line starts with a number sign",
        "scripts/x.sh",
        "dir=\"$(cat <<EOF\n#$KR_TEST_ARTIFACTS_DIR\nEOF\n)\"\n",
    ),
    (
        "a direct read in TypeScript",
        "apps/companion/e2e/x.ts",
        "const dir = process.env.KR_TEST_ARTIFACTS_DIR\n",
    ),
    (
        "a read by a template string whose line holds a comment opener",
        "apps/companion/e2e/x.mjs",
        "import { mkdirSync } from 'node:fs';\n\nconsole.log(`\n/*\n`);\nconst dir = process.env.KR_TEST_ARTIFACTS_DIR;\nmkdirSync(dir);\n",
    ),
    (
        "a destructure of the environment over several lines, with a default",
        "apps/companion/e2e/x.ts",
        "const {\n  KR_TEST_ARTIFACTS_DIR = '/tmp/default'\n} = process.env;\n",
    ),
    (
        "a destructure of the environment over several lines, with a new name",
        "apps/companion/e2e/x.ts",
        "const {\n  KR_TEST_ARTIFACTS_DIR: evidence,\n} = process.env\n",
    ),
    (
        "a destructure of the environment as the parameter of a function",
        "apps/companion/e2e/x.ts",
        "const dir = (({\n  KR_TEST_ARTIFACTS_DIR: dir,\n}) => dir)(process.env)\n",
    ),
    (
        "a read after a division that looks like the start of a regular expression",
        "apps/companion/e2e/x.mjs",
        "import { mkdirSync, writeFileSync } from 'node:fs';\nconst ratio = (1) / \"///\"; const dir = process.env.KR_TEST_ARTIFACTS_DIR;\nmkdirSync(dir, { recursive: true });\nwriteFileSync(`${dir}/proof.txt`, 'proof');\n",
    ),
    (
        "a read inside a raw template after a regular expression",
        "apps/companion/e2e/x.mjs",
        "const dir = String.raw`${/a\\//.test('a/') && process.env.KR_TEST_ARTIFACTS_DIR}`;\n",
    ),
    (
        "a read after a division in a template, then a comment opener in a later string",
        "apps/companion/e2e/x.ts",
        "console.log(`${(bytes * 8) / seconds} bit/s`)\nconst shots = `${root}/*.png`\nconst dir = process.env.KR_TEST_ARTIFACTS_DIR\n/** Lists the shots. */\n",
    ),
    (
        "a read after a division and a line comment that holds a comment opener",
        "apps/companion/e2e/x.ts",
        "const mid = (lo + hi) / 2 // not /* here\nconst dir = process.env.KR_TEST_ARTIFACTS_DIR\n/* done */\n",
    ),
    (
        "a read after a regular expression that holds a slash, behind return",
        "apps/companion/e2e/x.ts",
        "function f() { return /a\\//.test(a) } const dir = process.env.KR_TEST_ARTIFACTS_DIR\n",
    ),
    (
        "a read after a carriage return that ends a line comment",
        "apps/companion/e2e/x.mjs",
        "const n = 0; // note\rconst dir = process.env.KR_TEST_ARTIFACTS_DIR;\n",
    ),
    (
        "a read after a line separator that ends a line comment",
        "apps/companion/e2e/x.mjs",
        "const n = 0; // note\u{2028}const dir = process.env.KR_TEST_ARTIFACTS_DIR;\n",
    ),
    (
        "a read after a paragraph separator that ends a line comment",
        "apps/companion/e2e/x.mjs",
        "const n = 0; // note\u{2029}const dir = process.env.KR_TEST_ARTIFACTS_DIR;\n",
    ),
    (
        "a heredoc whose text looks like an upload step",
        ".github/workflows/x.yml",
        "jobs:\n  a:\n    steps:\n      - run: |\n          dir=\"$(sed -n 's/^ *path: //p' <<'EOF'\n          - uses: actions/upload-artifact@v7\n            with:\n              path: ${{ env.KR_TEST_ARTIFACTS_DIR }}\n          EOF\n          )\"\n          mkdir -p \"$dir\"\n",
    ),
    (
        "a scalar that starts on the line after its key",
        ".github/workflows/x.yml",
        r#"jobs:
  a:
    steps:
      - run:
          |
          dir="$(sed -n 's/^ *path: //p' <<'EOF'
          uses: actions/upload-artifact@v7
          with:
            path: ${{ env.KR_TEST_ARTIFACTS_DIR }}
          EOF
          )"
          mkdir -p "$dir"
          printf proof > "$dir/proof.txt"
"#,
    ),
    (
        "a quoted scalar that starts on the line after its key",
        ".github/workflows/x.yml",
        r#"name: Evidence
on: workflow_dispatch
env:
  KR_TEST_ARTIFACTS_DIR: /home/runner/kr-proof
jobs:
  proof:
    runs-on: ubuntu-latest
    steps:
      - shell: bash
        run:
          "d=$(printf '%s\\n'
          uses: actions/upload-artifact@v7
          with:
            path: ${{ env.KR_TEST_ARTIFACTS_DIR }}
          | tail -n 1); mkdir -p \"$d\"; printf proof > \"$d/proof.txt\""
"#,
    ),
    (
        "a quoted scalar whose lines look like an upload step",
        ".github/workflows/x.yml",
        "jobs:\n  a:\n    steps:\n      - run: \"echo\n          uses: actions/upload-artifact@v7\n          with:\n            path: ${{ env.KR_TEST_ARTIFACTS_DIR }}\"\n",
    ),
    (
        "a script line that starts with a number sign inside a block scalar",
        ".github/workflows/x.yml",
        "jobs:\n  a:\n    steps:\n      - run: |\n          # ${{ env.KR_TEST_ARTIFACTS_DIR }}\n          dir=\"$(sed -n '1s/^# //p' \"$0\")\"\n          mkdir -p \"$dir\"\n",
    ),
    (
        "a script's own line in a workflow",
        ".github/workflows/x.yml",
        "        run: ls \"$KR_TEST_ARTIFACTS_DIR\"\n",
    ),
    (
        "the upload of the directory in a workflow on no list",
        ".github/workflows/x.yml",
        "jobs:\n  a:\n    steps:\n      - uses: actions/upload-artifact@v7\n        with:\n          path: ${{ env.KR_TEST_ARTIFACTS_DIR }}\n",
    ),
    (
        "a key of `env:` in a workflow on no list",
        ".github/workflows/x.yml",
        "env:\n  KR_TEST_ARTIFACTS_DIR: /tmp/kr-test-artifacts\n",
    ),
    (
        "a mention in a document on no list",
        "docs/x.md",
        "Set `KR_TEST_ARTIFACTS_DIR` to a folder under /tmp.\n",
    ),
    (
        "a mention in a comment of a file in a language no table knows",
        "scripts/x.py",
        "# KR_TEST_ARTIFACTS_DIR is read by the reader\n",
    ),
    (
        "a mention in a JSON file",
        "data/x.json",
        "{\"a\": \"KR_TEST_ARTIFACTS_DIR\"}\n",
    ),
    (
        "a read in a file with no extension",
        "scripts/x",
        "echo $KR_TEST_ARTIFACTS_DIR\n",
    ),
    (
        "a mention in a manifest",
        "crates/x/Cargo.toml",
        "# KR_TEST_ARTIFACTS_DIR is read by the reader\n",
    ),
    (
        "a mention in a file of JSX",
        "apps/companion/src/x.tsx",
        "// KR_TEST_ARTIFACTS_DIR is not read here\n",
    ),
    (
        "a read in lower case",
        "scripts/x.ps1",
        "$evidence = $env:kr_test_artifacts_dir\n",
    ),
    (
        "a read in a name that holds the variable's name",
        "tests/e2e/x.rs",
        "let other = std::env::var_os(\"MY_KR_TEST_ARTIFACTS_DIR_COPY\");\n",
    ),
    (
        "a name at the end of a file that has no line feed",
        "scripts/x.sh",
        "echo done; echo $KR_TEST_ARTIFACTS_DIR",
    ),
];

/// A file that holds the name and is on no list fails, whatever its language and wherever the
/// name stands in it: every text that once fooled a scan is a plain failure of the same rule.
#[test]
fn a_file_that_holds_the_name_and_is_on_no_list_fails() {
    let wrong: Vec<String> = SAMPLES
        .iter()
        .filter_map(|&(what, path, text)| {
            let found = findings_of(path, text);
            let holding = text
                .split('\n')
                .filter(|line| line.to_ascii_uppercase().contains(VARIABLE));
            (found.len() != holding.count() || found.is_empty())
                .then(|| format!("{what}: {path} gave {found:?} for:\n{text}"))
        })
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n---\n"));
}

/// The name in a file that is not UTF-8 text is found: in UTF-16 and UTF-32, in both byte orders,
/// also among other bytes, and in either letter case.
#[test]
fn a_file_that_holds_the_name_in_utf_16_or_utf_32_or_in_another_letter_case_fails() {
    let name = VARIABLE;
    let units = |text: &str| -> [(&'static str, Vec<u8>); 5] {
        [
            ("UTF-8", text.as_bytes().to_vec()),
            (
                "UTF-16LE",
                text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            ),
            (
                "UTF-16BE",
                text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
            ),
            (
                "UTF-32LE",
                text.chars()
                    .flat_map(|c| u32::from(c).to_le_bytes())
                    .collect(),
            ),
            (
                "UTF-32BE",
                text.chars()
                    .flat_map(|c| u32::from(c).to_be_bytes())
                    .collect(),
            ),
        ]
    };
    for spelling in [name, "kr_test_artifacts_dir", "Kr_Test_Artifacts_Dir"] {
        for (encoding, bytes) in units(spelling) {
            // The file ends with the name, so that no encoding is seen through another's reading.
            let found = findings_of("scripts/x.sh", &bytes);
            assert!(!found.is_empty(), "{spelling} in {encoding} is not found");
            let mut among = b"\xff\xfe binary \x00\x01".to_vec();
            among.extend_from_slice(&bytes);
            among.extend_from_slice(b"\n\x00\xff");
            assert!(
                !findings_of("data/x.bin", &among).is_empty(),
                "{spelling} in {encoding} among other bytes is not found"
            );
        }
    }
    // A near miss is no name, in UTF-8 or in UTF-16.
    assert!(findings_of("scripts/x.sh", "KR_TEST_ARTIFACTS\n").is_empty());
    assert!(
        findings_of(
            "scripts/x.sh",
            "K\0R\0_\0T\0E\0S\0T\0_\0A\0R\0T\0I\0F\0A\0C\0T\0S\0\0\0"
        )
        .is_empty()
    );
    // A file of the list that holds a line and also holds the name in UTF-16 fails.
    let list = [lines("scripts/y.sh", &[("echo $KR_TEST_ARTIFACTS_DIR", 1)])];
    let mut text = b"echo $KR_TEST_ARTIFACTS_DIR\n".to_vec();
    assert!(judge(&list, &[file("scripts/y.sh", &text)]).is_empty());
    text.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
    assert!(!judge(&list, &[file("scripts/y.sh", &text)]).is_empty());
}

/// The reader of a file is matched by its whole path.
#[test]
fn a_file_that_only_looks_like_a_reader_is_not_one() {
    let list = [reader("scripts/lib/x.sh")];
    let text = "const dir = process.env.KR_TEST_ARTIFACTS_DIR\n";
    assert!(judge(&list, &[file("scripts/lib/x.sh", text)]).is_empty());
    for path in [
        "other/scripts/lib/x.sh",
        "scripts/lib/x.sh.bak",
        "scripts/lib/x.sh/y.sh",
        "scripts/lib",
        "Scripts/lib/x.sh",
        "scripts/lib/X.sh",
        "x.sh",
    ] {
        let found = judge(&list, &[file("scripts/lib/x.sh", text), file(path, text)]);
        assert!(
            found
                .iter()
                .any(|finding| finding.starts_with(&format!("{path}:"))),
            "{path} passed as a reader: {found:?}"
        );
    }
}

/// A file that lists its lines holds those lines, each as often as listed, and no other line that
/// holds the name; and one positive sample of each class passes.
#[test]
fn a_listed_file_holds_exactly_its_listed_lines() {
    let list = [
        reader("scripts/lib/x.sh"),
        lines(
            "scripts/y.sh",
            &[
                ("export KR_TEST_ARTIFACTS_DIR=\"$dir\"", 1),
                ("# KR_TEST_ARTIFACTS_DIR is set above.", 2),
            ],
        ),
    ];
    let reader_text = "echo hi\nconst dir = process.env.KR_TEST_ARTIFACTS_DIR\n";
    let listed = |extra: &str| {
        format!(
            "#!/bin/sh\n  export KR_TEST_ARTIFACTS_DIR=\"$dir\"\r\n# KR_TEST_ARTIFACTS_DIR is set above.\n\t# KR_TEST_ARTIFACTS_DIR is set above.   \n{extra}"
        )
    };
    let run = |text: &str| {
        judge(
            &list,
            &[
                file("scripts/lib/x.sh", reader_text),
                file("scripts/y.sh", text),
            ],
        )
    };
    // The positive sample of each class.
    assert_eq!(run(&listed("")), Vec::<String>::new());
    // A line that holds the name and is not listed fails with its file and line.
    let added = run(&listed("echo $KR_TEST_ARTIFACTS_DIR\n"));
    assert_eq!(added.len(), 1, "{added:?}");
    assert!(added[0].starts_with("scripts/y.sh:5:"), "{added:?}");
    // A listed line that stands once more fails, whether it was listed once or twice.
    for copy in [
        "export KR_TEST_ARTIFACTS_DIR=\"$dir\"",
        "# KR_TEST_ARTIFACTS_DIR is set above.",
    ] {
        assert!(!run(&listed(&format!("{copy}\n"))).is_empty(), "{copy}");
    }
    // A listed line that is gone fails, and so does the last of two of a line that is listed twice.
    let text = listed("");
    for gone in [
        "  export KR_TEST_ARTIFACTS_DIR=\"$dir\"\r\n",
        "\t# KR_TEST_ARTIFACTS_DIR is set above.   \n",
    ] {
        let found = run(&text.replace(gone, ""));
        assert!(!found.is_empty(), "no finding when {gone:?} is gone");
        assert!(
            found.iter().any(|f| f.contains("the list has")),
            "{found:?}"
        );
    }
    // A listed file that no longer holds the name, or is not there, fails.
    let found = run("#!/bin/sh\necho hi\n");
    assert!(
        found
            .iter()
            .any(|f| f.starts_with("scripts/y.sh: is on the list")),
        "{found:?}"
    );
    let found = judge(&list, &[file("scripts/lib/x.sh", reader_text)]);
    assert!(
        found
            .iter()
            .any(|f| f.starts_with("scripts/y.sh: is on the list")),
        "{found:?}"
    );
    // The text of a listed line is matched as a whole line, in its letter case, and a line that
    // another line terminator cuts is one line.
    for other in [
        "export KR_TEST_ARTIFACTS_DIR=\"$dir\"; rm -rf x\n",
        "rm -rf x; export KR_TEST_ARTIFACTS_DIR=\"$dir\"\n",
        "export KR_TEST_ARTIFACTS_DIR=\"$dir\"\u{2028}rm -rf x\n",
        "rm -rf x\u{2028}export KR_TEST_ARTIFACTS_DIR=\"$dir\"\n",
        "rm -rf x\rexport KR_TEST_ARTIFACTS_DIR=\"$dir\"\n",
        "export kr_test_artifacts_dir=\"$dir\"\n",
        "\u{feff}export KR_TEST_ARTIFACTS_DIR=\"$dir\"\n",
    ] {
        assert!(!run(&listed(other)).is_empty(), "{other:?} passed");
    }
    // A file on no list does not pass because its lines are another file's listed lines.
    let elsewhere = judge(
        &list,
        &[
            file("scripts/z.sh", listed("")),
            file("scripts/y.sh", listed("")),
            file("scripts/lib/x.sh", reader_text),
        ],
    );
    assert!(
        elsewhere.iter().any(|f| f.starts_with("scripts/z.sh:")),
        "{elsewhere:?}"
    );
}
