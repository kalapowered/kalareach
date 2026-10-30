//! What the landing workflow keeps of the tests that need a browser, a desktop session or a phone.
//!
//! Section 21 names a tool for each class of test and asks for the tests' screenshots to be kept in
//! `KR_TEST_ARTIFACTS_DIR` and collected into the CI artifact store. A workflow is how that is
//! delivered, so these hold the things a deleted or disabled step or a moved file would lose without
//! any job going red: the check that refuses a run with no screenshot kept, run on real
//! directories; a job for each class of test on a runner that has its tool, whose step is not
//! disabled and runs under the condition the workflow gives it, with the matrix leg that condition
//! names still in the matrix; the evidence check and the strict uploads, neither disabled, none of
//! them cut short or kept for less than the repository's default; and the table of those jobs in
//! the conformance document. It reads the workflow as text, line by line, which holds its layout
//! (jobs at two spaces, steps at six): a reformatting fails it loudly, and a step that swallows
//! its failure in the command (`|| true`) is not looked for.

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

/// The text of one job of the landing workflow: its header line to the next job's, with the
/// comment lines left out so that a step named only in a comment is not found.
fn job(workflow: &str, name: &str) -> String {
    let lines: Vec<&str> = workflow.lines().collect();
    let header = format!("  {name}:");
    let start = lines
        .iter()
        .position(|line| *line == header)
        .unwrap_or_else(|| panic!("the workflow has a {name} job"));
    let is_job = |line: &str| {
        line.len() > 3
            && line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
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

/// The steps of a job that run `tool`, each from its `- ` line to the next step's. There is at
/// least one.
fn steps_running(job: &str, tool: &str) -> Vec<String> {
    let lines: Vec<&str> = job.lines().collect();
    let starts_of_steps: Vec<usize> = (0..lines.len())
        .filter(|&index| lines[index].starts_with("      - "))
        .collect();
    let running: Vec<String> = starts_of_steps
        .iter()
        .enumerate()
        .map(|(position, &start)| {
            let end = starts_of_steps
                .get(position + 1)
                .copied()
                .unwrap_or(lines.len());
            lines[start..end].join("\n")
        })
        .filter(|text| text.lines().any(|line| starts(line, tool)))
        .collect();
    assert!(!running.is_empty(), "no step of the job runs {tool}");
    running
}

/// The steps of a job that hold `needle` anywhere, as a step's name or its inputs.
fn steps_holding(job: &str, needle: &str) -> Vec<String> {
    let lines: Vec<&str> = job.lines().collect();
    let starts_of_steps: Vec<usize> = (0..lines.len())
        .filter(|&index| lines[index].starts_with("      - "))
        .collect();
    let holding: Vec<String> = starts_of_steps
        .iter()
        .enumerate()
        .map(|(position, &start)| {
            let end = starts_of_steps
                .get(position + 1)
                .copied()
                .unwrap_or(lines.len());
            lines[start..end].join("\n")
        })
        .filter(|text| text.contains(needle))
        .collect();
    assert!(!holding.is_empty(), "no step of the job holds {needle}");
    holding
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
/// is kept in the workflow and made to do nothing. A trailing comment and the spaces inside a
/// condition do not hide it, and any `continue-on-error` that is not the plain `false` counts.
fn is_disabled(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.split(" #").next().unwrap_or_default();
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let compact = compact.trim_start_matches('-');
        compact == "if:false"
            || compact == "if:${{false}}"
            || (compact.starts_with("continue-on-error:") && compact != "continue-on-error:false")
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
    /// What the job's runner line holds.
    runner: &'static [&'static str],
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
        job_when: None,
        tool: "pnpm -C apps/companion e2e",
        when: None,
    },
    ClassOfTest {
        class: "native macOS controls",
        job: "companion",
        runner: &["macos-15"],
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
        job_when: Some("github.event_name != 'workflow_dispatch' || inputs.macos || inputs.ios"),
        tool: "scripts/ios-app-launch.sh",
        when: None,
    },
    ClassOfTest {
        class: "an Android emulator",
        job: "android-app",
        runner: &["runs-on: ubuntu-24.04"],
        job_when: None,
        tool: "scripts/android-app-launch.sh",
        when: None,
    },
    ClassOfTest {
        class: "a Windows machine's release build of the desktop application",
        job: "windows",
        runner: &["runs-on: windows-2025"],
        job_when: None,
        tool: "cargo build --locked -p companion-tauri --release",
        when: Some("${{ !cancelled() && matrix.part == 'first' }}"),
    },
    ClassOfTest {
        class: "the Tauri desktop application in a real window, on Windows",
        job: "windows",
        runner: &["runs-on: windows-2025"],
        job_when: None,
        tool: "cargo test --locked -p companion-tauri --test host_events",
        when: Some("${{ !cancelled() && matrix.part == 'second' }}"),
    },
    ClassOfTest {
        class: "the real-worker host tests, on a native Windows machine",
        job: "windows",
        runner: &["runs-on: windows-2025"],
        job_when: None,
        tool: "cargo test --locked -p kr-worker --test host",
        when: Some("${{ !cancelled() && matrix.part == 'second' }}"),
    },
    ClassOfTest {
        class: "the Tauri desktop application's native backend, on both kinds of unix runner",
        job: "companion",
        runner: &["ubuntu-24.04", "macos-15"],
        job_when: None,
        tool: "cargo test --locked -p companion-tauri -p kr-client",
        when: None,
    },
    ClassOfTest {
        class: "a Linux machine",
        job: "rust",
        runner: &["runs-on: ubuntu-24.04"],
        job_when: None,
        tool: "cargo test --locked --workspace",
        when: None,
    },
    ClassOfTest {
        class: "a macOS machine",
        job: "macos",
        runner: &["runs-on: macos-15"],
        job_when: Some("github.event_name != 'workflow_dispatch' || inputs.macos"),
        tool: "cargo test --locked --workspace",
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
        assert!(
            !text
                .lines()
                .any(|line| line.trim_start().starts_with("exclude:")),
            "{class}: the {name} job's matrix leaves a leg out"
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
                for named in steps_holding(&text, &format!("id: {id}")) {
                    assert!(
                        !is_disabled(&named) && step_condition(&named).is_none(),
                        "{class}: the step {id}, whose outcome decides whether the step that runs \
                         {tool} runs, is disabled or does not always run"
                    );
                }
            }
        }
    }

    // KR-REQ-27.03: what each of the jobs that drive a device or a browser keeps, and what refuses
    // a run that kept nothing.
    let companion = job(&workflow, "companion");
    assert!(
        !is_disabled(&header(&companion)),
        "the companion job is disabled or lets its failure pass"
    );
    // Both runners on every push and pull request: a manual run started with the macOS jobs turned
    // off may leave the macOS leg out, and nothing else may.
    let runners = companion
        .lines()
        .find_map(|line| {
            let (indent, key, value) = key_value(line)?;
            (indent == 8 && key == "os").then(|| compact(value))
        })
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
    for (job_name, artefact) in [
        ("companion", "companion-evidence-"),
        ("android-app", "test-evidence-android"),
        ("ios", "test-evidence-ios"),
    ] {
        let text = job(&workflow, job_name);
        assert!(
            !is_disabled(&header(&text)),
            "the {job_name} job is disabled or lets its failure pass"
        );
        for upload in steps_holding(&text, &format!("name: {artefact}")) {
            assert!(
                upload.contains("if-no-files-found: error"),
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
/// by the acceptance, and the conformance document says where the workflow is.
#[test]
fn the_wsl2_acceptance_has_a_workflow_that_runs_its_script_on_windows() {
    let workflow = fs::read_to_string(repository().join(".github/workflows/wsl-acceptance.yml"))
        .expect("the WSL2 acceptance workflow");
    let triggers: Vec<&str> = workflow
        .lines()
        .skip_while(|line| *line != "on:")
        .skip(1)
        .take_while(|line| line.is_empty() || line.starts_with([' ', '#']))
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .collect();
    assert_eq!(
        triggers,
        ["  workflow_dispatch:"],
        "the WSL2 acceptance is started by hand and by nothing else"
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
            kept.contains("if-no-files-found: error"),
            "the step that keeps the set does not fail when it kept nothing"
        );
    }
    for fetched in steps_holding(&text, "name: wsl-linux-set") {
        assert!(
            !is_disabled(&fetched),
            "the step that fetches the set is disabled"
        );
    }

    let document = fs::read_to_string(repository().join("docs/conformance/README.md"))
        .expect("the conformance document");
    assert!(
        document.contains("`wsl-acceptance`, started by hand"),
        "the conformance document does not say where the WSL2 acceptance is"
    );
}
