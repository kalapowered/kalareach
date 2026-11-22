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

// A scheduling case: it relies on the sampler not waking in the few milliseconds before the
// script reads the samples, and passes with the token rule removed on the rare run that does.
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

// A scheduling case: it holds that a read that does not end is ended by its own alarm well before
// a sleep of thirty seconds would end, and it depends on the machine's timing.
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

/// Writes a program that runs.
fn write_program(path: &Path, text: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::write(path, text).expect("a program");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("the program runs");
}

/// A hosted macOS runner's closing report, with `reader` standing in for `/usr/bin/log` and a
/// program that runs its command in the place of `sudo`, so that no `sudo` runs and none logs the
/// command, which holds the whole predicate: it returns what the report printed and the text of the
/// `disk-faults.txt` it kept.
fn kernel_read_with(reader: &str) -> (String, String) {
    let state = tempfile::tempdir().expect("a state directory");
    let program = state.path().join("log");
    write_program(&program, reader);
    let privilege = state.path().join("privilege");
    write_program(&privilege, "#!/bin/sh\nshift\nexec \"$@\"\n");
    let evidence = state.path().join("evidence");
    let body = format!(
        "mkdir -p \"$state\" '{evidence}'\n\
         echo \"S $(( $(date +%s) - 600 ))\" > \"$samples\"\n\
         export RUNNER_ENVIRONMENT=github-hosted KR_TEST_ARTIFACTS_DIR='{evidence}' \
         KR_DISK_REPORT_LOG='{program}' KR_DISK_REPORT_PRIVILEGE='{privilege}'\n\
         kernel_storage_errors\n\
         echo \"== file\"\ncat '{evidence}/disk-faults.txt'\n",
        evidence = evidence.display(),
        program = program.display(),
        privilege = privilege.display()
    );
    let (text, ok) = in_shell(state.path(), &body);
    assert!(ok, "{text}");
    let (printed, kept) = text.split_once("== file\n").expect("the file is shown");
    (printed.to_owned(), kept.to_owned())
}

#[test]
fn a_kernel_log_that_cannot_be_read_is_said_in_the_file_it_leaves_and_never_leaves_it_empty() {
    if cfg!(not(target_os = "macos")) {
        return;
    }
    let (printed, kept) =
        kernel_read_with("#!/bin/sh\necho 'log: cannot open the log store' >&2\nexit 3\n");
    assert!(
        printed.contains("was not read at all (status 3)") && printed.contains("not ruled out"),
        "{printed}"
    );
    assert!(
        kept.contains("was not read at all (status 3)")
            && kept.contains("the reader said: log: cannot open the log store"),
        "{kept}"
    );
}

#[test]
fn a_kernel_log_read_with_no_fault_says_so_in_the_file_and_a_fault_is_counted() {
    if cfg!(not(target_os = "macos")) {
        return;
    }
    let (printed, kept) =
        kernel_read_with("#!/bin/sh\necho 'Timestamp               Ty Process[PID:TID]'\n");
    assert!(
        printed.contains("holds no line about a storage fault"),
        "{printed}"
    );
    assert!(kept.contains("was read: 0 matching lines"), "{kept}");
    let (printed, kept) = kernel_read_with(
        "#!/bin/sh\n\
         echo '2026-11-21 13:01:52.100 Df kernel[0:1a] (apfs) apfs_vnop_pagein: error 5'\n\
         echo '2026-11-21 13:01:53.200 Df ReportCrash[77:2b] cc exited due to SIGBUS'\n",
    );
    assert!(
        printed.contains("holds 2 lines that match a storage fault")
            && printed.contains("from 2026-11-21 13:01:52 to 2026-11-21 13:01:53"),
        "{printed}"
    );
    assert!(kept.contains("was read: 2 matching lines"), "{kept}");
}

#[test]
fn the_kernel_log_is_asked_for_failed_page_ins_and_a_sigbus_as_well_as_failed_writes() {
    if cfg!(not(target_os = "macos")) {
        return;
    }
    // The reader keeps the predicate it was given, in the evidence directory's file.
    let (_, kept) = kernel_read_with(
        "#!/bin/sh\nfor word in \"$@\"; do echo \"2026-11-21 13:01:52.100 asked: $word\"; done\n",
    );
    for term in [
        "I/O error",
        "cluster_pageout",
        "cluster_push() failed",
        "trim_list failed",
        "pagein",
        "page-in",
        "SIGBUS",
    ] {
        assert!(
            kept.contains(&format!("CONTAINS \"{term}\"")),
            "{term}: {kept}"
        );
    }
}

/// Whether the system's log would return a line of `process` that says `message`, for `predicate`:
/// macOS evaluates the predicate over the line's process and message as `log show` does.
fn predicate_matches(predicate: &str, process: &str, message: &str) -> bool {
    let directory = tempfile::tempdir().expect("a directory");
    let script = directory.path().join("evaluate.js");
    std::fs::write(
        &script,
        "ObjC.import('Foundation');\n\
         function run(argv) {\n\
         \x20 var p = $.NSPredicate.predicateWithFormat(argv[0]);\n\
         \x20 var line = $({process: argv[1], eventMessage: argv[2]});\n\
         \x20 return p.evaluateWithObject(line) ? 'match' : 'no';\n\
         }\n",
    )
    .expect("a script");
    let out = Command::new("/usr/bin/osascript")
        .args(["-l", "JavaScript"])
        .arg(&script)
        .args([predicate, process, message])
        .output()
        .expect("osascript runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim() == "match"
}

#[test]
fn the_line_sudo_logs_for_the_read_holds_the_predicate_and_is_not_counted_as_a_fault() {
    if cfg!(not(target_os = "macos")) {
        return;
    }
    // The reader keeps the predicate it was given, which is its last word.
    let (_, kept) = kernel_read_with(
        "#!/bin/sh\nfor word in \"$@\"; do last=\"$word\"; done\n\
         echo \"2026-11-21 13:01:52.100 predicate: $last\"\n",
    );
    let predicate = kept
        .lines()
        .find_map(|line| line.split_once(" predicate: "))
        .map(|(_, predicate)| predicate.to_owned())
        .expect("the predicate");
    // What sudo logs about a command it runs: the command, whole.
    let sudo_line = format!(
        "user : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=/usr/bin/log show --last 12m --style compact --predicate {predicate}"
    );
    assert!(
        sudo_line.contains("SIGBUS") && sudo_line.contains("page-in"),
        "the line holds the terms: {sudo_line}"
    );
    assert!(
        !predicate_matches(&predicate, "sudo", &sudo_line),
        "sudo's line of the read counts as a storage fault: {predicate}"
    );
    // The lines that are faults still count.
    for (process, message) in [
        ("kernel", "disk0s2: I/O error"),
        ("kernel", "apfs_vnop_pagein: error 5"),
        ("kernel", "cluster_pageout: failed"),
        ("ReportCrash", "cc exited due to SIGBUS"),
        ("launchd", "a service exited due to SIGBUS"),
    ] {
        assert!(
            predicate_matches(&predicate, process, message),
            "{process}: {message}"
        );
    }
    assert!(!predicate_matches(
        &predicate,
        "kernel",
        "a line about nothing"
    ));
}
