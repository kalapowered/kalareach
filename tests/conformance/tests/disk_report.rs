//! The disk report's script signals no process whose number it holds: its sampler ends by a stop
//! file that it reads, and the read of the kernel's log carries its own limit.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/disk-report.sh")
}

/// Runs `body` in a shell that has sourced the disk report's functions, with the report's state
/// under `state`, and returns what it printed and whether it exited 0.
fn in_shell(state: &Path, body: &str) -> (String, bool) {
    let file = state.join("case.sh");
    // A case that fails part of the way still ends its sampler and the decoy it started.
    std::fs::write(
        &file,
        format!(
            "source \"$1\" test label\n\
             end_case() {{ stop_sampler > /dev/null 2>&1; [ -z \"${{decoy:-}}\" ] || kill \"$decoy\" 2> /dev/null; }}\n\
             trap end_case EXIT\n{body}\n"
        ),
    )
    .expect("a script");
    let output = Command::new("bash")
        .arg(&file)
        .arg(script())
        .env("RUNNER_TEMP", state)
        .output()
        .expect("bash runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (text, output.status.success())
}

/// A process whose command line carries the sampler's name, as another process does that comes to
/// hold a number the script stored, and a check that it was not signalled.
const DECOY: &str = "bash -c 'sleep 60' kr-disk-sampler > /dev/null 2>&1 &\ndecoy=$!\n";
const DECOY_LIVES: &str = "kill -0 \"$decoy\" || { echo 'the decoy was signalled'; exit 1; }\n\
    kill \"$decoy\"\nwait \"$decoy\" 2> /dev/null\necho done\n";

#[test]
fn the_sampler_ends_by_its_stop_file_and_a_process_that_holds_its_old_number_is_not_signalled() {
    let state = tempfile::tempdir().expect("a state directory");
    let body = format!(
        "mkdir -p \"$state\"\n: > \"$samples\"\ninterval=0.2\nstart_sampler\n{DECOY}\
         echo \"$decoy\" > \"$state/sampler.pid\"\n\
         for _ in $(seq 1 50); do grep -q '^S ' \"$samples\" && break; sleep 0.1; done\n\
         grep -q '^S ' \"$samples\" || {{ echo 'no sample'; exit 1; }}\n\
         stop_sampler\n\
         grep -q \"^E [0-9]* $(cat \"$tokenfile\")\\$\" \"$samples\" || {{ echo 'the sampler did not end'; exit 1; }}\n\
         size=$(wc -c < \"$samples\")\nsleep 1\n\
         [ \"$(wc -c < \"$samples\")\" = \"$size\" ] || {{ echo 'it kept sampling'; exit 1; }}\n\
         {DECOY_LIVES}"
    );
    let (text, ok) = in_shell(state.path(), &body);
    assert!(ok && text.lines().any(|line| line == "done"), "{text}");
}

#[test]
fn a_stop_file_that_holds_another_token_does_not_stop_the_sampler() {
    let state = tempfile::tempdir().expect("a state directory");
    let body = "mkdir -p \"$state\"\n: > \"$samples\"\ninterval=0.2\n\
         echo another-token > \"$stopfile\"\nstart_sampler\nsleep 1.5\n\
         grep -q '^E ' \"$samples\" && { echo 'it ended on another token'; exit 1; }\n\
         stop_sampler\n\
         grep -q \"^E [0-9]* $(cat \"$tokenfile\")\\$\" \"$samples\" || { echo 'it did not end on its own'; exit 1; }\n\
         echo done";
    let (text, ok) = in_shell(state.path(), body);
    assert!(ok && text.lines().any(|line| line == "done"), "{text}");
}

#[test]
fn a_last_line_that_an_earlier_sampler_writes_late_does_not_end_the_wait_for_the_current_one() {
    let state = tempfile::tempdir().expect("a state directory");
    let body = "mkdir -p \"$state\"\n: > \"$samples\"\ninterval=1\nstart_sampler\n\
         printf 'E 1 an-earlier-token\\n' >> \"$samples\"\n\
         stop_sampler\n\
         awk -v t=\"$(cat \"$tokenfile\")\" '$1 == \"E\" && $3 == t { f = 1 } END { exit !f }' \"$samples\" \
         || { echo 'it did not wait for its own sampler'; exit 1; }\n\
         echo done";
    let (text, ok) = in_shell(state.path(), body);
    assert!(ok && text.lines().any(|line| line == "done"), "{text}");
}

#[test]
fn a_case_that_fails_after_it_started_the_sampler_still_ends_it() {
    let state = tempfile::tempdir().expect("a state directory");
    let body = "mkdir -p \"$state\"\n: > \"$samples\"\ninterval=0.2\nstart_sampler\n\
         echo \"$state\" > \"$RUNNER_TEMP/where\"\nexit 1";
    let (_, ok) = in_shell(state.path(), body);
    assert!(!ok, "the case failed on purpose");
    let sampler = std::fs::read_to_string(state.path().join("where")).expect("the state path");
    let sampler = Path::new(sampler.trim());
    // Whatever the outcome, the sampler is told to end by the script's own stop file.
    let token = std::fs::read_to_string(sampler.join("sampler.token")).expect("a token");
    std::fs::write(sampler.join("sampler.stop"), &token).expect("the stop file");
    let samples = std::fs::read_to_string(sampler.join("samples")).expect("the samples");
    assert!(
        samples
            .lines()
            .any(|line| line.starts_with("E ") && line.ends_with(token.trim())),
        "the sampler was left running: {samples}"
    );
}

#[test]
fn a_read_that_ends_at_once_signals_nothing_and_one_that_does_not_end_is_ended_by_its_own_alarm() {
    let state = tempfile::tempdir().expect("a state directory");
    let body = format!(
        "mkdir -p \"$state\"\n{DECOY}out=\"$state/out\"\n\
         alarmed 5 \"$out\" -- echo read\n[ \"$?\" -eq 0 ] || {{ echo 'status'; exit 1; }}\n\
         grep -q read \"$out\" || {{ echo 'no output'; exit 1; }}\n\
         began=$(date +%s)\nalarmed 1 \"$out\" -- sleep 30\nstatus=$?\n\
         [ \"$status\" -eq 142 ] || {{ echo \"status $status\"; exit 1; }}\n\
         [ \"$(( $(date +%s) - began ))\" -lt 10 ] || {{ echo 'it took too long'; exit 1; }}\n\
         {DECOY_LIVES}"
    );
    let (text, ok) = in_shell(state.path(), &body);
    assert!(ok && text.lines().any(|line| line == "done"), "{text}");
}

#[test]
fn the_script_holds_no_command_that_signals_or_looks_up_a_process() {
    let text = std::fs::read_to_string(script()).expect("the script");
    let code: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect();
    for line in code {
        for word in line.split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_') {
            assert!(
                !matches!(word, "kill" | "pkill" | "killall" | "ps" | "pgrep"),
                "{line}"
            );
        }
    }
}
