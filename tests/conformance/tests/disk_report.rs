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
    std::fs::write(&file, format!("source \"$1\" test label\n{body}\n")).expect("a script");
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
const DECOY: &str = "bash -c 'sleep 60' kr-disk-sampler > /dev/null 2>&1 &\ndecoy=$!\n\
    trap 'kill \"$decoy\" 2> /dev/null' EXIT\n";
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
         grep -q '^E ' \"$samples\" || {{ echo 'the sampler did not end'; exit 1; }}\n\
         size=$(wc -c < \"$samples\")\nsleep 1\n\
         [ \"$(wc -c < \"$samples\")\" = \"$size\" ] || {{ echo 'it kept sampling'; exit 1; }}\n\
         {DECOY_LIVES}"
    );
    let (text, ok) = in_shell(state.path(), &body);
    assert!(ok && text.lines().any(|line| line == "done"), "{text}");
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
