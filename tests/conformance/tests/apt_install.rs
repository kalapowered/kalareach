//! The script the hosted Linux jobs install their packages through, run against stand-ins for
//! `apt-get`, `sudo`, `timeout`, `sleep` and `apt-config`: what it calls and in what order, how it
//! reads a failed index, when it stops, and that its bounds stay inside its deadline.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tempfile::TempDir;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// A stand-in for `apt-get`. It records its call, counts the calls of its phase, and does what the
/// rig's plan for that phase says for that call: the plan is one action per line, the last line
/// standing for every later call, and no plan means success. A download that succeeds leaves one
/// archive per package; an install under `--no-download` fails for a package with none, and one
/// without it would fetch, which the rig records as a use of the network.
const APT_GET: &str = r#"#!/bin/bash
rig=$RIG
case "$1" in
  update) phase=update ;;
  install)
    phase=install
    for argument in "$@"; do
      case "$argument" in
        --simulate) phase=simulate ;;
        --download-only) phase=download ;;
        --print-uris) phase=list ;;
      esac
    done
    ;;
  *) phase=other ;;
esac
echo "apt-get $* | frontend=${DEBIAN_FRONTEND-unset}" >> "$rig/calls.log"
echo "$phase" >> "$rig/phases.log"
count=$(( $(cat "$rig/count.$phase" 2>/dev/null || echo 0) + 1 ))
echo "$count" > "$rig/count.$phase"
action=ok
if [ -f "$rig/plan.$phase" ]; then
  action=$(sed -n "${count}p" "$rig/plan.$phase")
  [ -n "$action" ] || action=$(tail -n 1 "$rig/plan.$phase")
fi
packages=()
for argument in "${@:2}"; do
  case "$argument" in -*) ;; *) packages+=("$argument") ;; esac
done
case "$action" in
  ok | drop | consume) ;;
  fail) echo "E: the $phase failed"; exit 100 ;;
  fail-slow) "$REAL_SLEEP" 1; echo "E: the $phase failed"; exit 100 ;;
  spend:*) "$REAL_SLEEP" "${action#spend:}" ;;
  fail-replace) cp "$rig"/replacement/* "$rig/pool/"; echo "E: the $phase failed"; exit 100 ;;
  warn:*)
    n=${action#warn:}
    while [ "$n" -gt 0 ]; do
      echo "W: Failed to fetch http://mirror.test/ubuntu/dists/noble/InRelease  503  Service Unavailable [IP: 192.0.2.1 80]"
      n=$((n - 1))
    done
    ;;
  slow) exec "$REAL_SLEEP" 30 ;;
  ignore-term) exec /bin/bash -c "trap '' TERM; while :; do $REAL_SLEEP 1; done" ;;
  e:*) echo "E: ${action#e:}"; exit 100 ;;
esac
# With a pool the archives are named and hashed as a mirror's are; without one they are empty files.
file_of() {
  if [ -d "$rig/pool" ]; then echo "${1}_1.0_all.deb"; else echo "$1.deb"; fi
}
case "$phase" in
  list)
    for argument in "$@"; do
      case "$argument" in Dir::Cache::Archives=*) ls -A "${argument#Dir::Cache::Archives=}" >> "$rig/listed-dir.log" ;; esac
    done
    for package in "${packages[@]}"; do
      file=$(file_of "$package")
      [ -f "$rig/pool/$file" ] || continue
      size=$(wc -c < "$rig/pool/$file" | tr -d ' ')
      if [ "$(cat "$rig/nohash" 2>/dev/null)" = "$package" ]; then
        echo "'http://mirror.test/pool/$file' $file $size "
      else
        echo "'http://mirror.test/pool/$file' $file $size SHA256:$(sha256sum "$rig/pool/$file" | cut -d' ' -f1)"
      fi
    done
    ;;
  download)
    mkdir -p "$rig/archives"
    for package in "${packages[@]}"; do
      file=$(file_of "$package")
      if [ -d "$rig/pool" ]; then
        # apt keeps an archive of the listed size and fetches the others.
        if [ "$(wc -c < "$rig/archives/$file" 2>/dev/null | tr -d ' ')" != "$(wc -c < "$rig/pool/$file" | tr -d ' ')" ]; then
          cp "$rig/pool/$file" "$rig/archives/$file"
          echo "$file" >> "$rig/fetched.log"
        fi
      else
        : > "$rig/archives/$file"
      fi
    done
    if [ "$action" = drop ]; then rm -f "$rig/archives/$(file_of "${packages[0]}")"; fi
    ;;
  install)
    nodownload=
    for argument in "$@"; do [ "$argument" = --no-download ] && nodownload=1; done
    for package in "${packages[@]}"; do
      if [ ! -f "$rig/archives/$(file_of "$package")" ]; then
        if [ -n "$nodownload" ]; then
          echo "E: Unable to fetch some archives, maybe run apt-get update or try with --fix-missing?"
          exit 100
        fi
        echo "$package" >> "$rig/network-fetch"
      fi
    done
    # An action that stands for apt's deleting an archive once it is installed.
    if [ "$action" = consume ]; then rm -f "$rig/archives/$(file_of "${packages[0]}")"; fi
    ;;
esac
exit 0
"#;

/// `sudo` as the runner has it, passwordless: it records its words and runs them.
const SUDO: &str = r#"#!/bin/bash
echo "sudo $*" >> "$RIG/sudo.log"
exec "$@"
"#;

/// `timeout` as GNU has it, in the part the script uses: `--kill-after=G N COMMAND...` sends TERM
/// to the command's process group after N seconds and KILL G seconds later, and answers 124 when
/// TERM ended it and 137 when KILL did. A bound of less than 1 is refused as 125, and the call is
/// recorded as `<kill-after> <seconds> <command>`, and with the time in the clock log, where the
/// end of the call is logged too. The rig always uses this one, so that a host without GNU `timeout` runs the same cases.
const TIMEOUT: &str = r#"#!/usr/bin/perl
use strict;
use warnings;
use POSIX ();
use Time::HiRes ();
my $grace = 0;
while (@ARGV && $ARGV[0] =~ /^--kill-after=(\d+)$/) { $grace = $1; shift @ARGV; }
my $seconds = shift @ARGV;
open(my $log, '>>', "$ENV{RIG}/timeout.log") or die;
print $log "$grace $seconds @ARGV\n";
close $log;
open(my $clock, '>>', "$ENV{RIG}/clock.log") or die;
printf $clock "bound %.3f %d %s\n", Time::HiRes::time(), $grace, $seconds;
close $clock;
if (!defined $seconds || $seconds !~ /^\d+$/ || $seconds < 1) { print STDERR "timeout: bad bound\n"; exit 125; }
my $pid = fork();
if ($pid == 0) { POSIX::setpgid(0, 0); exec { $ARGV[0] } @ARGV or exit 127; }
my ($status, $stage) = (undef, 0);
$SIG{ALRM} = sub {
  if ($stage == 0) { kill 'TERM', -$pid; $stage = 1; alarm($grace > 0 ? $grace : 1); }
  else { kill 'KILL', -$pid; $stage = 2; }
};
alarm($seconds);
while (1) {
  my $done = waitpid($pid, 0);
  if ($done == $pid) { $status = $?; last; }
}
alarm(0);
kill 'KILL', -$pid;
open(my $ended, '>>', "$ENV{RIG}/clock.log") or die;
printf $ended "ended %.3f\n", Time::HiRes::time();
close $ended;
if ($stage == 1) { exit 124; }
if ($stage == 2) { exit 137; }
exit($status >> 8);
"#;

/// `sleep` for the script's waits: it records the seconds, and the time in the clock log, and does
/// not wait.
const SLEEP: &str = r#"#!/bin/bash
echo "$1" >> "$RIG/sleep.log"
perl -MTime::HiRes=time -e 'printf "wait %.3f %d\n", time, $ARGV[0]' "$1" >> "$RIG/clock.log"
"#;

/// `apt-config`, which a Mac does not have: the settings of a runner image.
const APT_CONFIG: &str = r#"#!/bin/bash
if [ "$1" = shell ]; then
  echo "$2='$RIG/archives/'"
  exit 0
fi
cat <<'LINES'
Acquire::Retries "1";
Acquire::http::Timeout "15";
Acquire::https::Timeout "15";
Acquire::http::Pipeline-Depth "0";
Acquire::http::No-Cache "true";
Acquire::http::BrokenProxy "true";
Acquire::Languages "none";
LINES
"#;

/// `sha256sum` where the host has none: `shasum` prints the same.
const SHA256SUM: &str = r#"#!/bin/bash
exec shasum -a 256 "$@"
"#;

/// `pnpm` for the Playwright package list: it records its arguments and answers with the output
/// and the status the case put in the rig.
const PNPM: &str = r#"#!/bin/bash
echo "pnpm $*" >> "$RIG/pnpm.log"
cat "$RIG/pnpm.out"
exit "$(cat "$RIG/pnpm.status")"
"#;

/// A program that stands for what `--names-from` runs: it prints the number of updates made so far
/// in the name it gives, so that a name shows which indexes it was asked against.
const NAMES: &str = r#"#!/bin/bash
echo "plain-library"
echo "library-after-$(cat "$RIG/count.update" 2>/dev/null || echo 0)-updates"
"#;

struct Rig {
    dir: TempDir,
}

struct Outcome {
    status: i32,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

impl Rig {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("a folder for the rig");
        let bin = dir.path().join("bin");
        fs::create_dir_all(&bin).expect("the stand-ins' folder");
        fs::create_dir_all(dir.path().join("tmp")).expect("the temporary folder");
        fs::create_dir_all(dir.path().join("archives")).expect("apt's archive directory");
        for (name, text) in [
            ("apt-get", APT_GET),
            ("sudo", SUDO),
            ("timeout", TIMEOUT),
            ("sleep", SLEEP),
            ("apt-config", APT_CONFIG),
            ("pnpm", PNPM),
            ("sha256sum", SHA256SUM),
        ] {
            write_program(&bin.join(name), text);
        }
        write_program(&dir.path().join("names.sh"), NAMES);
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// The plan for one phase: `update`, `simulate`, `download` or `install`.
    fn plan(&self, phase: &str, actions: &[&str]) {
        fs::write(
            self.path(&format!("plan.{phase}")),
            actions.join("\n") + "\n",
        )
        .expect("a plan for a phase");
    }

    fn run(&self, arguments: &[&str]) -> Outcome {
        self.run_script("scripts/apt-install.sh", arguments)
    }

    fn run_script(&self, script: &str, arguments: &[&str]) -> Outcome {
        let began = Instant::now();
        let mut command = Command::new("/bin/bash");
        command
            .arg(script)
            .args(arguments)
            .current_dir(repository())
            .env_clear()
            .env(
                "PATH",
                format!(
                    "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                    self.path("bin").display()
                ),
            )
            .env("RIG", self.dir.path())
            .env("TMPDIR", self.path("tmp"))
            .env("REAL_SLEEP", "/bin/sleep")
            .env("GITHUB_OUTPUT", self.path("outputs"))
            .env("GITHUB_RUN_ID", "77")
            .env("GITHUB_RUN_ATTEMPT", "2")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = {
            let _spawning = SPAWNING
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            command.spawn().expect("bash runs the script")
        };
        let output = child.wait_with_output().expect("the script ends");
        Outcome {
            status: output
                .status
                .code()
                .expect("the script ends by its own status"),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            elapsed: began.elapsed(),
        }
    }

    fn lines(&self, name: &str) -> Vec<String> {
        fs::read_to_string(self.path(name))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// The phases of every `apt-get` call, in order.
    fn phases(&self) -> Vec<String> {
        self.lines("phases.log")
    }

    /// The calls of one phase.
    fn calls(&self, phase: &str) -> Vec<String> {
        let phases = self.phases();
        self.lines("calls.log")
            .into_iter()
            .zip(phases)
            .filter(|(_, called)| called == phase)
            .map(|(line, _)| line)
            .collect()
    }

    fn waits(&self) -> Vec<u32> {
        self.lines("sleep.log")
            .iter()
            .map(|line| line.parse().expect("a wait in seconds"))
            .collect()
    }

    /// Every bound, wait and end of a call the stand-ins saw, in order, with the seconds since the
    /// first of them.
    fn events(&self) -> Vec<Event> {
        let lines = self.lines("clock.log");
        let time = |line: &str| {
            line.split(' ')
                .nth(1)
                .expect("a time")
                .parse::<f64>()
                .expect("a time")
        };
        let first = lines.first().map_or(0.0, |line| time(line));
        lines
            .iter()
            .map(|line| {
                let words: Vec<&str> = line.split(' ').collect();
                let at = time(line) - first;
                match words[0] {
                    "bound" => Event::Bound {
                        at,
                        grace: words[2].parse().expect("a grace"),
                        seconds: words[3].parse().expect("a bound"),
                    },
                    "wait" => Event::Wait {
                        at,
                        seconds: words[2].parse().expect("a wait"),
                    },
                    "ended" => Event::Ended { at },
                    other => panic!("an event of kind {other}"),
                }
            })
            .collect()
    }

    /// Holds each bound and each wait to the time left when the script decided it. A bound is at
    /// least 2 s (a grace of at least 1 and a term of at least 1), has a grace of 10 s, or of its
    /// length less 1 s where that is 10 s or less, and is under the time left at the end of the
    /// call before it, and a second over for the script's count of whole seconds; the first call
    /// has the whole deadline. A wait is under the time left at the end of the call or wait before
    /// it. The script starts its count before its first call and decides each call after the one
    /// before it ended, so no stall of the machine moves these limits: they fail a script that
    /// gives a call the time an earlier call spent.
    fn assert_inside_the_time_left(&self, deadline: u32, context: &str) {
        let events = self.events();
        // The seconds, from the first event, at which the call or wait before the one read ended.
        let mut before = 0.0;
        for event in &events {
            match *event {
                Event::Bound { at, grace, seconds } => {
                    let bound = grace + seconds;
                    assert!(
                        grace >= 1 && seconds >= 1,
                        "{context}: a bound of {grace} and {seconds} at {at:.2} s: {events:?}"
                    );
                    let expected = if bound > 10 { 10 } else { bound - 1 };
                    assert_eq!(
                        grace, expected,
                        "{context}: a grace of {grace} for a bound of {bound} at {at:.2} s: {events:?}"
                    );
                    assert!(
                        f64::from(bound) < f64::from(deadline) - before + 1.0,
                        "{context}: a bound of {bound} s at {at:.2} s, with {deadline} s allowed and the call before it ended at {before:.2} s: {events:?}"
                    );
                }
                Event::Wait { at, seconds } => {
                    assert!(
                        seconds >= 1 && f64::from(seconds) < f64::from(deadline) - before,
                        "{context}: a wait of {seconds} s at {at:.2} s, with {deadline} s allowed and the call before it ended at {before:.2} s: {events:?}"
                    );
                    before = at;
                }
                Event::Ended { at } => before = at,
            }
        }
    }

    /// The bounds of the calls, as `(grace, seconds)`.
    fn bounds(&self) -> Vec<(u32, u32)> {
        self.lines("timeout.log")
            .iter()
            .map(|line| {
                let mut words = line.split(' ');
                let grace = words.next().expect("a grace").parse().expect("a number");
                let seconds = words.next().expect("a bound").parse().expect("a number");
                (grace, seconds)
            })
            .collect()
    }
}

/// What a stand-in saw of the clock: a bound that `timeout` was given, the end of that call, or a
/// wait that `sleep` was given, and the seconds since the first thing a stand-in saw when it saw
/// it.
#[derive(Clone, Copy, Debug)]
enum Event {
    Bound { at: f64, grace: u32, seconds: u32 },
    Wait { at: f64, seconds: u32 },
    Ended { at: f64 },
}

/// Held while a stand-in is written and while a script is started, so that no process is forked
/// between the writing of one program and the start of it by another case: a child that inherits
/// the descriptor of a file being written makes that file's start fail as busy.
static SPAWNING: Mutex<()> = Mutex::new(());

fn write_program(path: &Path, text: &str) {
    let _writing = SPAWNING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    fs::write(path, text).expect("a stand-in");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("a mode");
}

fn summary(outcome: &Outcome) -> &str {
    outcome
        .stdout
        .lines()
        .rev()
        .find(|line| line.starts_with("apt-install: packages="))
        .unwrap_or_else(|| panic!("no summary line in: {}", outcome.stdout))
}

/// The first attempt goes through when every call succeeds: the update, the plan of the install,
/// the download and the install, in that order, every call as root with the frontend set, the
/// bounded ones under `timeout` inside `sudo`, and the install with `--no-download`.
#[test]
fn a_first_attempt_that_succeeds_updates_downloads_and_installs_with_no_download() {
    let rig = Rig::new();
    let outcome = rig.run(&["--deadline", "600", "tmux", "fuse3"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(rig.phases(), ["update", "simulate", "download", "install"]);
    let calls = rig.lines("calls.log");
    assert!(
        calls
            .iter()
            .all(|call| call.ends_with("| frontend=noninteractive")),
        "{calls:?}"
    );
    assert_eq!(calls[0], "apt-get update | frontend=noninteractive");
    assert!(calls[1].contains("install --simulate --no-install-recommends tmux fuse3"));
    assert!(calls[2].contains("install --download-only --no-install-recommends --yes tmux fuse3"));
    assert!(calls[3].contains("install --no-install-recommends --no-download --yes tmux fuse3"));
    assert!(summary(&outcome).starts_with("apt-install: packages=2 attempts=1 warnings=0 "));
    assert!(
        outcome.stdout.contains("Acquire::http::BrokenProxy"),
        "the diagnostic keys are printed"
    );
}

/// `timeout` runs inside `sudo`, so that it can signal the root process, and the install is not
/// run under a bound at all.
#[test]
fn the_install_is_never_run_under_a_bound_and_sudo_holds_the_bound() {
    let rig = Rig::new();
    let outcome = rig.run(&["--deadline", "600", "tmux"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    let sudo = rig.lines("sudo.log");
    let bounded: Vec<&String> = sudo
        .iter()
        .filter(|line| line.starts_with("sudo timeout "))
        .collect();
    assert_eq!(
        bounded.len(),
        3,
        "the update, the plan and the download: {sudo:?}"
    );
    for line in &bounded {
        assert!(
            line.contains(" env DEBIAN_FRONTEND=noninteractive apt-get "),
            "{line}"
        );
    }
    let install: Vec<&String> = sudo
        .iter()
        .filter(|line| line.contains("--no-download"))
        .collect();
    assert_eq!(install.len(), 1);
    assert!(
        install[0].starts_with("sudo env DEBIAN_FRONTEND=noninteractive apt-get install "),
        "{}",
        install[0]
    );
    let timeouts = fs::read_to_string(rig.path("timeout.log")).expect("the bounds");
    assert!(
        !timeouts.contains("--no-download"),
        "the install is under a bound: {timeouts}"
    );
}

/// An update that exits 0 and prints `W: Failed to fetch` is what a 503 on an index gives: it is
/// run again, twice at most, after 10 and 20 s, and then the attempt goes on.
#[test]
fn an_update_that_exits_zero_with_failed_fetches_is_run_again_and_the_warnings_are_counted() {
    let rig = Rig::new();
    rig.plan("update", &["warn:2", "ok"]);
    let outcome = rig.run(&["--deadline", "600", "tmux"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(rig.calls("update").len(), 2);
    assert_eq!(rig.waits(), [10]);
    assert!(summary(&outcome).starts_with("apt-install: packages=1 attempts=1 warnings=2 "));

    let rig = Rig::new();
    rig.plan("update", &["warn:1"]);
    rig.plan("simulate", &["fail", "ok"]);
    let outcome = rig.run(&["--deadline", "600", "tmux"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    // Three updates in the first attempt, and the plan, which fails with the indexes as they are;
    // the second attempt updates three times again and goes on.
    assert_eq!(rig.calls("update").len(), 6, "{:?}", rig.phases());
    assert_eq!(rig.waits(), [10, 20, 10, 10, 20]);
    assert!(summary(&outcome).starts_with("apt-install: packages=1 attempts=2 warnings=6 "));
}

/// An update that fails is an attempt that failed: the wait before the next is 10 s times the
/// attempt's number.
#[test]
fn an_update_that_fails_is_retried_with_a_longer_wait_each_time() {
    let rig = Rig::new();
    rig.plan("update", &["fail", "fail", "ok"]);
    let outcome = rig.run(&["--deadline", "600", "tmux"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(rig.calls("update").len(), 3);
    assert_eq!(rig.waits(), [10, 20]);
    assert_eq!(rig.calls("install").len(), 1, "{:?}", rig.phases());
    assert!(
        outcome
            .stdout
            .contains("apt-install: attempt 1 failed, status 100")
    );
    assert!(summary(&outcome).starts_with("apt-install: packages=1 attempts=3 "));
}

/// A mirror that fails five times and then answers inside the deadline is installed from on the
/// sixth attempt: the attempts are not capped at five, and no wait passes 60 s.
#[test]
fn a_mirror_that_fails_five_times_and_recovers_is_installed_from_on_the_sixth_attempt() {
    let rig = Rig::new();
    rig.plan("update", &["fail", "fail", "fail", "fail", "fail", "ok"]);
    let outcome = rig.run(&["--deadline", "1800", "tmux"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(rig.calls("update").len(), 6);
    assert_eq!(rig.waits(), [10, 20, 30, 40, 50]);
    assert_eq!(rig.calls("install").len(), 1, "{:?}", rig.phases());
    assert!(summary(&outcome).starts_with("apt-install: packages=1 attempts=6 "));

    let rig = Rig::new();
    rig.plan(
        "update",
        &[
            "fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "ok",
        ],
    );
    let outcome = rig.run(&["--deadline", "1800", "tmux"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(rig.waits(), [10, 20, 30, 40, 50, 60, 60, 60]);
    assert_eq!(rig.calls("install").len(), 1, "{:?}", rig.phases());
}

/// A download that is still running when the deadline comes is cut by `timeout` inside it, and
/// nothing is installed. An update that is still running is cut at its own bound, which is the
/// time left when that is under 180 s.
#[test]
fn a_download_past_the_deadline_is_cut_and_nothing_is_installed() {
    let rig = Rig::new();
    rig.plan("download", &["slow"]);
    let outcome = rig.run(&["--deadline", "4", "tmux"]);
    assert_eq!(outcome.status, 1, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        outcome.elapsed < Duration::from_secs(4 + 2),
        "{:?}",
        outcome.elapsed
    );
    assert!(
        !rig.phases().contains(&"install".to_owned()),
        "{:?}",
        rig.phases()
    );
    assert!(outcome.stdout.contains("status 124"), "{}", outcome.stdout);
    assert!(
        outcome
            .stderr
            .contains("apt-install: failed: deadline=4s attempts="),
        "{}",
        outcome.stderr
    );

    let rig = Rig::new();
    rig.plan("update", &["slow"]);
    let outcome = rig.run(&["--deadline", "4", "tmux"]);
    assert_eq!(outcome.status, 1, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        outcome.elapsed < Duration::from_secs(4 + 2),
        "{:?}",
        outcome.elapsed
    );
    assert!(
        rig.bounds()
            .iter()
            .all(|(grace, seconds)| grace + seconds <= 4),
        "{:?}",
        rig.bounds()
    );
    let phases = rig.phases();
    assert!(
        !phases.is_empty() && phases.iter().all(|phase| phase == "update"),
        "an update that never ends lets nothing else run: {phases:?}"
    );
}

/// A call that ignores the termination signal is killed after its grace, and the grace and the
/// bound together stay inside the deadline: the grace is 10 s, or less where the time left is not
/// more than 10.
#[test]
fn a_call_that_ignores_the_termination_signal_is_killed_inside_the_deadline() {
    let rig = Rig::new();
    rig.plan("download", &["ignore-term"]);
    let outcome = rig.run(&["--deadline", "4", "tmux"]);
    assert_eq!(outcome.status, 1, "{}{}", outcome.stdout, outcome.stderr);
    // The kill is proved by the record below: a status of 137 and a grace and a bound inside the
    // deadline. The time the run took is a ceiling only, far above the run's own length of about
    // the deadline, so that no stall of the machine reaches it.
    assert!(
        outcome.elapsed < Duration::from_secs(25),
        "{:?}",
        outcome.elapsed
    );
    assert!(outcome.stdout.contains("status 137"), "{}", outcome.stdout);
    let (grace, seconds) = *rig.bounds().last().expect("the download's bound");
    assert!(
        grace >= 1 && seconds >= 1 && grace + seconds <= 4,
        "{grace} {seconds}"
    );
    rig.assert_inside_the_time_left(4, "a call that ignores the termination signal");
    assert!(!rig.phases().contains(&"install".to_owned()));
}

/// No call is bounded by less than 2 s (a bound of 0 is no limit to `timeout`) or by more than the
/// time left, for every deadline the script accepts, and for a run in which an earlier phase has
/// spent time, which leaves the later calls less than the whole deadline.
#[test]
fn no_bound_is_ever_zero_or_longer_than_the_time_left() {
    // A deadline can run out before the script's last call, or before its first, when the machine
    // is slow to run it: the script then stops with its failure status and its expiry message,
    // having run for more than the deadline less 2 s (it stops when under 2 s are left, and counts
    // whole seconds). That is a valid end for every deadline of this sweep, and a stop sooner than
    // that is a script that did not use its time. The bounds a run did make are held to the time
    // left either way.
    for deadline in [2_u32, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12] {
        let rig = Rig::new();
        let outcome = rig.run(&["--deadline", &deadline.to_string(), "tmux"]);
        let said = format!("{deadline}: {}{}", outcome.stdout, outcome.stderr);
        match outcome.status {
            0 => assert_eq!(rig.bounds().len(), 3, "{said}"),
            1 => {
                assert!(
                    outcome.stderr.contains(&format!(
                        "apt-install: failed: deadline={deadline}s attempts="
                    )),
                    "{said}"
                );
                assert!(
                    outcome.elapsed.as_secs_f64() > f64::from(deadline) - 2.0,
                    "{deadline}: the script stopped after {:?}, with time left: {said}",
                    outcome.elapsed
                );
            }
            status => panic!("{deadline}: status {status}: {said}"),
        }
        for (grace, seconds) in rig.bounds() {
            assert!(
                grace + seconds <= deadline,
                "{deadline}: a bound of {grace} and {seconds}"
            );
        }
        rig.assert_inside_the_time_left(deadline, &deadline.to_string());
    }
    // The control: with a long deadline that no stall of a machine uses up, the script makes its
    // three calls and ends with success.
    for deadline in [30_u32, 180, 181, 1800] {
        let rig = Rig::new();
        let outcome = rig.run(&["--deadline", &deadline.to_string(), "tmux"]);
        assert_eq!(
            outcome.status, 0,
            "{deadline}: {}{}",
            outcome.stdout, outcome.stderr
        );
        let bounds = rig.bounds();
        assert_eq!(bounds.len(), 3, "{deadline}: {bounds:?}");
        for (grace, seconds) in &bounds {
            assert!(
                grace + seconds <= deadline,
                "{deadline}: a bound of {grace} and {seconds}"
            );
        }
        rig.assert_inside_the_time_left(deadline, &deadline.to_string());
    }
    let rig = Rig::new();
    rig.run(&["--deadline", "1800", "tmux"]);
    assert_eq!(
        rig.bounds()[0],
        (10, 170),
        "the update's bound is 180 s: 170 and a grace of 10"
    );
    assert_eq!(rig.bounds()[1], (10, 110), "the plan's bound is 120 s");

    // An update that takes 4 s leaves the plan and the download at most the deadline less 4 s,
    // and the download is not given the whole deadline.
    for deadline in [30_u32, 181] {
        let rig = Rig::new();
        rig.plan("update", &["spend:4"]);
        let outcome = rig.run(&["--deadline", &deadline.to_string(), "tmux"]);
        assert_eq!(
            outcome.status, 0,
            "{deadline}: {}{}",
            outcome.stdout, outcome.stderr
        );
        let bounds = rig.bounds();
        assert_eq!(bounds.len(), 3, "{deadline}: {bounds:?}");
        for (grace, seconds) in &bounds[1..] {
            assert!(
                grace + seconds <= deadline - 4,
                "{deadline}: {grace} and {seconds} after an update of 4 s"
            );
        }
        rig.assert_inside_the_time_left(deadline, &format!("{deadline} after an update of 4 s"));
    }

    // A first attempt that fails after a second leaves its retry less than the whole deadline.
    let rig = Rig::new();
    rig.plan("update", &["fail-slow", "ok"]);
    let outcome = rig.run(&["--deadline", "30", "tmux"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    let (grace, seconds) = *rig.bounds().last().expect("the download's bound");
    assert!(grace + seconds <= 29, "{grace} and {seconds}");
    rig.assert_inside_the_time_left(30, "a retry");
}

/// An install that fails is not retried, and the status the script ends with is the install's.
#[test]
fn a_failing_install_is_not_retried_and_its_status_is_the_scripts() {
    let rig = Rig::new();
    rig.plan("install", &["fail"]);
    let outcome = rig.run(&["--deadline", "600", "tmux"]);
    assert_eq!(outcome.status, 100, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(rig.calls("install").len(), 1);
    assert_eq!(rig.calls("download").len(), 1);
    assert!(summary(&outcome).starts_with("apt-install: packages=1 attempts=1 "));
}

/// An archive that goes missing between the download and the install fails the install, and the
/// install does not fetch it.
#[test]
fn an_archive_that_goes_missing_between_the_phases_fails_the_install_and_is_not_fetched() {
    let rig = Rig::new();
    rig.plan("download", &["drop"]);
    let outcome = rig.run(&["--deadline", "600", "tmux", "fuse3"]);
    assert_eq!(outcome.status, 100, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        outcome.stdout.contains("E: Unable to fetch some archives"),
        "{}",
        outcome.stdout
    );
    assert!(
        !rig.path("network-fetch").exists(),
        "the install fetched an archive"
    );
}

/// Every wait is shorter than the deadline, and shorter than the time left.
/// At least one wait is cut below 10 s times its number. At 5 s, every wait is cut.
#[test]
fn the_waits_never_pass_the_deadline() {
    for deadline in [5_u32, 12] {
        let rig = Rig::new();
        rig.plan("update", &["fail-slow"]);
        let outcome = rig.run(&["--deadline", &deadline.to_string(), "tmux"]);
        assert_eq!(
            outcome.status, 1,
            "{deadline}: {}{}",
            outcome.stdout, outcome.stderr
        );
        // The record below proves each wait inside the time left. The time the run took is a
        // ceiling only, far above the run's own length of about the deadline, so that no stall of
        // the machine reaches it.
        assert!(
            outcome.elapsed < Duration::from_secs(25),
            "{deadline}: {:?}",
            outcome.elapsed
        );
        let waits = rig.waits();
        assert!(
            !waits.is_empty() && waits.iter().all(|wait| *wait < deadline),
            "{deadline}: {waits:?}"
        );
        // Wait number N is 10 s times N and at most 60 s unless the time left cuts it.
        assert!(
            waits
                .iter()
                .zip(1_u32..)
                .any(|(wait, attempt)| *wait < (10 * attempt).min(60)),
            "{deadline}: no wait was cut: {waits:?}"
        );
        assert!(rig.calls("update").len() >= 2);
        rig.assert_inside_the_time_left(deadline, &deadline.to_string());
    }
}

/// A program named by `--names-from` is asked after the attempt's last update, so the names it
/// gives are those of the indexes the download and the install use, and they are installed with
/// the named packages.
#[test]
fn a_name_program_is_asked_after_the_update_and_its_names_are_installed() {
    let rig = Rig::new();
    rig.plan("update", &["warn:1", "ok"]);
    let names = rig.path("names.sh");
    let outcome = rig.run(&[
        "--deadline",
        "600",
        "--names-from",
        names.to_str().expect("a path"),
        "tmux",
    ]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(
        rig.phases(),
        ["update", "update", "simulate", "download", "install"]
    );
    let install = &rig.calls("install")[0];
    assert!(
        install.contains("--no-download --yes tmux plain-library library-after-2-updates"),
        "{install}"
    );
    assert!(summary(&outcome).starts_with("apt-install: packages=3 "));

    // The first update and the program succeed and the download fails: the second attempt asks the
    // program again, after its own update, and its plan, download and install use that list and
    // not the first.
    let rig = Rig::new();
    rig.plan("download", &["fail", "ok"]);
    let outcome = rig.run(&[
        "--deadline",
        "600",
        "--names-from",
        names.to_str().expect("a path"),
        "tmux",
    ]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(
        rig.phases(),
        [
            "update", "simulate", "download", "update", "simulate", "download", "install"
        ]
    );
    let first = "library-after-1-updates";
    let second = "library-after-2-updates";
    let simulate = rig.calls("simulate");
    let download = rig.calls("download");
    let install = rig.calls("install");
    assert!(simulate[0].contains(first), "{}", simulate[0]);
    assert!(download[0].contains(first), "{}", download[0]);
    for call in [&simulate[1], &download[1], &install[0]] {
        assert!(call.contains(second) && !call.contains(first), "{call}");
    }
}

/// A name program that fails ends the script, with nothing downloaded or installed.
#[test]
fn a_name_program_that_fails_ends_the_script() {
    let rig = Rig::new();
    let failing = rig.path("failing.sh");
    write_program(
        &failing,
        "#!/bin/bash\necho 'unexpected shape' >&2\nexit 3\n",
    );
    let outcome = rig.run(&[
        "--deadline",
        "600",
        "--names-from",
        failing.to_str().expect("a path"),
        "tmux",
    ]);
    assert_eq!(outcome.status, 1, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        outcome.stderr.contains("unexpected shape"),
        "{}",
        outcome.stderr
    );
    assert_eq!(rig.phases(), ["update"]);
}

/// Where there is nothing to install, the script updates (the names need the indexes) and ends.
#[test]
fn no_package_to_install_runs_no_download_and_no_install() {
    let rig = Rig::new();
    let none = rig.path("none.sh");
    write_program(&none, "#!/bin/bash\nexit 0\n");
    let outcome = rig.run(&[
        "--deadline",
        "600",
        "--names-from",
        none.to_str().expect("a path"),
    ]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(rig.phases(), ["update"]);
    assert!(summary(&outcome).starts_with("apt-install: packages=0 attempts=1 "));
}

/// A plan of the install that fails after an update with no warning is the packages' own fault: the
/// script ends at once with apt's lines and does not wait out its deadline. After an update that
/// printed a warning the indexes may be the cause, and the attempt is tried again.
#[test]
fn a_plan_that_fails_after_a_clean_update_ends_the_script_and_after_a_warning_is_retried() {
    let rig = Rig::new();
    rig.plan("simulate", &["e:Unable to locate package nosuchpackage"]);
    let outcome = rig.run(&["--deadline", "600", "nosuchpackage"]);
    assert_eq!(outcome.status, 1, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        outcome
            .stderr
            .contains("E: Unable to locate package nosuchpackage"),
        "{}",
        outcome.stderr
    );
    assert_eq!(rig.phases(), ["update", "simulate"]);
    assert!(rig.waits().is_empty());

    // Every update prints a warning, so the indexes may be the cause of the failed plan: the
    // attempt is tried again, with three updates of its own, and its plan goes through.
    let rig = Rig::new();
    rig.plan("update", &["warn:1"]);
    rig.plan(
        "simulate",
        &["e:Unable to locate package nosuchpackage", "ok"],
    );
    let outcome = rig.run(&["--deadline", "600", "tmux"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(
        rig.phases(),
        [
            "update", "update", "update", "simulate", "update", "update", "update", "simulate",
            "download", "install"
        ]
    );
    assert!(
        summary(&outcome).starts_with("apt-install: packages=1 attempts=2 warnings=6 "),
        "{}",
        summary(&outcome)
    );
}

/// A command line the script cannot read is refused with status 2 before it calls anything.
#[test]
fn a_bad_command_line_is_refused() {
    for arguments in [
        vec!["--deadline"],
        vec!["--deadline", "soon", "tmux"],
        vec!["--deadline", "1", "tmux"],
        vec!["--deadline", "0", "tmux"],
        vec!["--names-from"],
        vec!["--unknown", "tmux"],
    ] {
        let rig = Rig::new();
        let outcome = rig.run(&arguments);
        assert_eq!(
            outcome.status, 2,
            "{arguments:?}: {}{}",
            outcome.stdout, outcome.stderr
        );
        assert!(rig.phases().is_empty(), "{arguments:?}");
    }
}

/// What Playwright's dry run prints, with the status it exits with, and what the package list
/// script makes of it.
fn playwright_names(printed: &str, status: i32) -> (Outcome, Vec<String>) {
    let rig = Rig::new();
    fs::write(rig.path("pnpm.out"), printed).expect("the dry run's output");
    fs::write(rig.path("pnpm.status"), status.to_string()).expect("the dry run's status");
    let outcome = rig.run_script("scripts/playwright-system-packages.sh", &[]);
    (outcome, rig.lines("pnpm.log"))
}

/// The package list is the names Playwright's dry run prints under its header, one per line, and
/// the dry run is asked for the two browsers the end-to-end run drives.
#[test]
fn the_playwright_package_list_is_the_names_its_dry_run_prints() {
    let (outcome, calls) = playwright_names(
        "Missing system dependencies (3):\n  libasound2t64\n  libgbm1\n  libwoff1\n",
        1,
    );
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(outcome.stdout, "libasound2t64\nlibgbm1\nlibwoff1\n");
    assert_eq!(
        calls,
        ["pnpm --silent -C apps/companion exec playwright install-deps --dry-run chromium webkit"]
    );
}

/// Where Playwright says that every package is installed, the list is empty and the script
/// succeeds.
#[test]
fn the_playwright_package_list_is_empty_when_every_package_is_installed() {
    let (outcome, _) = playwright_names("All system dependencies are installed.\n", 0);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(outcome.stdout, "");
}

/// Any other result stops the step by the script's name, with what Playwright printed: a count
/// that is not the number of names, a list with another line in it, a header with no names, an
/// error with no list, a list with the wrong status, and no output at all.
#[test]
fn the_playwright_package_list_fails_on_any_other_shape() {
    for (printed, status) in [
        (
            "Missing system dependencies (3):\n  libgbm1\n  libwoff1\n",
            1,
        ),
        (
            "Missing system dependencies (1):\n  libgbm1\nWarning: something\n",
            1,
        ),
        ("Missing system dependencies (0):\n", 1),
        (
            "Failed to install browser dependencies\nE: Unable to locate package\n",
            1,
        ),
        ("Missing system dependencies (1):\n  libgbm1\n", 0),
        ("All system dependencies are installed.\n", 1),
        ("Missing system dependencies (1):\n  libgbm1\n", 2),
        ("", 0),
    ] {
        let (outcome, _) = playwright_names(printed, status);
        assert_eq!(
            outcome.status, 1,
            "{printed:?} {status}: {}{}",
            outcome.stdout, outcome.stderr
        );
        assert_eq!(outcome.stdout, "", "{printed:?}");
        assert!(
            outcome.stderr.starts_with("playwright-system-packages: "),
            "{printed:?}: {}",
            outcome.stderr
        );
        assert!(
            outcome.stderr.contains(printed.trim_end()),
            "{printed:?}: {}",
            outcome.stderr
        );
    }
}

// The archive directory: what a cache step restores before the script and saves after it.

/// The archives a mirror would serve: one file per package, named as apt names them.
fn pool(rig: &Rig, packages: &[(&str, &str)]) {
    let pool = rig.path("pool");
    fs::create_dir_all(&pool).expect("a pool");
    for (package, bytes) in packages {
        fs::write(pool.join(format!("{package}_1.0_all.deb")), bytes).expect("an archive");
    }
}

/// A new runner: apt's archive directory and every record of the last run are gone, and the cache
/// directory, the pool and the plans are not.
fn new_runner(rig: &Rig) {
    fs::remove_dir_all(rig.path("archives")).expect("apt's archives");
    fs::create_dir_all(rig.path("archives")).expect("apt's archive directory");
    for name in [
        "calls.log",
        "phases.log",
        "fetched.log",
        "listed-dir.log",
        "sudo.log",
        "sleep.log",
        "timeout.log",
        "clock.log",
        "outputs",
        "count.update",
        "count.list",
        "count.download",
        "count.install",
    ] {
        let _ = fs::remove_file(rig.path(name));
    }
}

fn sha256_hex(path: &Path) -> String {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .expect("shasum runs");
    String::from_utf8(output.stdout)
        .expect("a digest")
        .split(' ')
        .next()
        .expect("a digest")
        .to_owned()
}

fn cache(rig: &Rig) -> PathBuf {
    rig.path("cache/desktop")
}

fn archive_run(rig: &Rig, packages: &[&str]) -> Outcome {
    let directory = cache(rig);
    let directory = directory.to_str().expect("a path");
    let mut arguments = vec!["--deadline", "600", "--archive", directory];
    arguments.extend(packages);
    rig.run(&arguments)
}

/// The last value the run wrote for a step output.
fn output_of(rig: &Rig, name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    rig.lines("outputs")
        .iter()
        .rev()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
}

/// The manifest line of one archive of the pool: its name, size and SHA-256.
fn manifest_line(rig: &Rig, package: &str) -> String {
    let path = rig.path("pool").join(format!("{package}_1.0_all.deb"));
    let size = fs::metadata(&path).expect("an archive").len();
    format!("{package}_1.0_all.deb {size} {}", sha256_hex(&path))
}

fn manifest(rig: &Rig) -> Vec<String> {
    fs::read_to_string(cache(rig).join("MANIFEST"))
        .expect("a manifest")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A run with no archive of its own lists every archive of the plan against an empty archive
/// directory, fetches them, installs, and keeps a new directory of the verified archives with a
/// manifest, which it tells the workflow to save under the manifest's digest.
#[test]
fn a_cold_run_with_an_archive_directory_lists_fetches_and_keeps_a_verified_set() {
    let rig = Rig::new();
    pool(
        &rig,
        &[("tmux", "tmux bytes"), ("fuse3", "fuse3 bytes, longer")],
    );
    let outcome = archive_run(&rig, &["tmux", "fuse3"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(rig.phases(), ["update", "list", "download", "install"]);
    let list = &rig.calls("list")[0];
    assert!(
        list.contains("install --print-uris -qq --no-install-recommends -o Acquire::ForceHash=SHA256 -o Dir::Cache::Archives="),
        "{list}"
    );
    assert!(
        !list.contains(&rig.path("archives").display().to_string()),
        "an empty directory: {list}"
    );
    assert!(
        summary(&outcome).starts_with(
            "apt-install: packages=2 archives=2 seeded=0 fetched=2 dropped=0 attempts=1 "
        ),
        "{}",
        summary(&outcome)
    );
    let mut expected = vec![manifest_line(&rig, "tmux"), manifest_line(&rig, "fuse3")];
    expected.sort();
    assert_eq!(manifest(&rig), expected);
    let digest = sha256_hex(&cache(&rig).join("MANIFEST"));
    assert_eq!(output_of(&rig, "digest"), Some(digest.clone()));
    assert_eq!(output_of(&rig, "save"), Some("true".to_owned()));
    assert_eq!(output_of(&rig, "entry"), Some(digest));
    assert!(
        rig.path("listed-dir.log").is_file() && rig.lines("listed-dir.log").is_empty(),
        "the listing is made against an empty directory: {:?}",
        rig.lines("listed-dir.log")
    );
    for package in ["tmux", "fuse3"] {
        let file = format!("{package}_1.0_all.deb");
        assert_eq!(
            fs::read(cache(&rig).join(&file)).expect("a saved archive"),
            fs::read(rig.path("pool").join(&file)).expect("an archive of the pool"),
            "{file}"
        );
    }
    assert!(!rig.path("cache/desktop.new").exists());
}

/// On a new runner that restores the directory, every archive is seeded and none is fetched, the
/// download phase has nothing to get, and the same set is not saved again.
#[test]
fn a_run_that_restores_a_verified_directory_fetches_nothing_and_saves_nothing() {
    let rig = Rig::new();
    pool(
        &rig,
        &[("tmux", "tmux bytes"), ("fuse3", "fuse3 bytes, longer")],
    );
    assert_eq!(archive_run(&rig, &["tmux", "fuse3"]).status, 0);
    let digest = output_of(&rig, "digest");
    new_runner(&rig);
    let outcome = archive_run(&rig, &["tmux", "fuse3"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        summary(&outcome).starts_with(
            "apt-install: packages=2 archives=2 seeded=2 fetched=0 dropped=0 attempts=1 "
        ),
        "{}",
        summary(&outcome)
    );
    for file in ["tmux_1.0_all.deb", "fuse3_1.0_all.deb"] {
        assert!(
            outcome
                .stdout
                .contains(&format!("apt-install: seeded {file}")),
            "{file}: {}",
            outcome.stdout
        );
    }
    assert!(
        rig.lines("fetched.log").is_empty(),
        "the download fetched: {:?}",
        rig.lines("fetched.log")
    );
    assert_eq!(output_of(&rig, "save"), Some("false".to_owned()));
    assert_eq!(
        sha256_hex(&cache(&rig).join("MANIFEST")),
        digest.expect("a digest")
    );
}

/// An archive that has the right name and size and other bytes is not copied: it is dropped and
/// fetched again, apt installs the fetched bytes, and, though the manifest is the same, the
/// repaired directory is saved under an entry of its own, which a later run restores whole.
#[test]
fn an_archive_with_the_right_size_and_other_bytes_is_dropped_fetched_again_and_saved_as_a_repair() {
    let rig = Rig::new();
    pool(
        &rig,
        &[("tmux", "tmux bytes"), ("fuse3", "fuse3 bytes, longer")],
    );
    assert_eq!(archive_run(&rig, &["tmux", "fuse3"]).status, 0);
    let digest = output_of(&rig, "digest").expect("a digest");
    fs::write(cache(&rig).join("tmux_1.0_all.deb"), "tmux BYTES").expect("a changed archive");
    new_runner(&rig);
    let outcome = archive_run(&rig, &["tmux", "fuse3"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        summary(&outcome).starts_with(
            "apt-install: packages=2 archives=2 seeded=1 fetched=1 dropped=1 attempts=1 "
        ),
        "{}",
        summary(&outcome)
    );
    assert!(
        outcome
            .stdout
            .contains("apt-install: dropped tmux_1.0_all.deb")
    );
    assert_eq!(rig.lines("fetched.log"), ["tmux_1.0_all.deb"]);
    let installed = fs::read(rig.path("archives/tmux_1.0_all.deb")).expect("the archive apt holds");
    assert_eq!(installed, b"tmux bytes");
    assert_eq!(
        output_of(&rig, "digest"),
        Some(digest.clone()),
        "the manifest is the same"
    );
    assert_eq!(output_of(&rig, "save"), Some("true".to_owned()));
    assert_eq!(
        output_of(&rig, "entry"),
        Some(format!("{digest}-repair-77-2"))
    );
    assert_eq!(
        fs::read(cache(&rig).join("tmux_1.0_all.deb")).expect("a repaired archive"),
        b"tmux bytes"
    );

    new_runner(&rig);
    let outcome = archive_run(&rig, &["tmux", "fuse3"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        summary(&outcome).starts_with(
            "apt-install: packages=2 archives=2 seeded=2 fetched=0 dropped=0 attempts=1 "
        ),
        "{}",
        summary(&outcome)
    );
    assert!(
        rig.lines("fetched.log").is_empty(),
        "the download fetched: {:?}",
        rig.lines("fetched.log")
    );
    assert_eq!(output_of(&rig, "save"), Some("false".to_owned()));
}

/// An archive copied from the directory in one attempt is checked against the list of the next. A
/// download that fails, and then an index that lists the same name and size with other bytes, would
/// leave apt holding the old bytes, which it installs as they are: the script removes them and
/// apt fetches the listed ones.
#[test]
fn an_archive_copied_in_one_attempt_is_checked_against_the_list_of_the_next() {
    let rig = Rig::new();
    pool(
        &rig,
        &[("tmux", "tmux bytes"), ("fuse3", "fuse3 bytes, longer")],
    );
    assert_eq!(archive_run(&rig, &["tmux", "fuse3"]).status, 0);
    new_runner(&rig);
    // The first attempt copies both archives and its download fails; the mirror then lists other
    // bytes of the same size under tmux's name.
    fs::create_dir_all(rig.path("replacement")).expect("a folder for the other bytes");
    fs::write(rig.path("replacement/tmux_1.0_all.deb"), "tmux BYTES").expect("other bytes");
    rig.plan("download", &["fail-replace", "ok"]);
    let outcome = archive_run(&rig, &["tmux", "fuse3"]);
    let installed = fs::read(rig.path("archives/tmux_1.0_all.deb")).expect("the archive apt holds");
    assert_eq!(
        String::from_utf8_lossy(&installed),
        "tmux BYTES",
        "apt holds the bytes the second list names: {}{}",
        outcome.stdout,
        outcome.stderr
    );
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(
        rig.phases(),
        [
            "update", "list", "download", "update", "list", "download", "install"
        ]
    );
    assert!(
        outcome
            .stdout
            .contains("apt-install: removed tmux_1.0_all.deb"),
        "{}",
        outcome.stdout
    );
    assert_eq!(rig.lines("fetched.log"), ["tmux_1.0_all.deb"]);
    assert!(
        summary(&outcome).starts_with(
            "apt-install: packages=2 archives=2 seeded=1 fetched=1 dropped=1 attempts=2 "
        ),
        "{}",
        summary(&outcome)
    );
    let mut expected = vec![manifest_line(&rig, "tmux"), manifest_line(&rig, "fuse3")];
    expected.sort();
    assert_eq!(manifest(&rig), expected);
    assert_eq!(
        fs::read(cache(&rig).join("tmux_1.0_all.deb")).expect("a saved archive"),
        b"tmux BYTES"
    );
    assert_eq!(output_of(&rig, "save"), Some("true".to_owned()));
}

/// The new directory is made of the list and not of the old directory: a file that is no longer
/// listed, a directory and a link are not in it or in its manifest. A same-name replacement and a
/// link at a listed name are dropped, and a smaller set has a digest of its own.
#[test]
fn the_saved_directory_is_built_from_the_list_and_keeps_nothing_that_is_not_listed() {
    let rig = Rig::new();
    pool(
        &rig,
        &[("tmux", "tmux bytes"), ("fuse3", "fuse3 bytes, longer")],
    );
    assert_eq!(archive_run(&rig, &["tmux", "fuse3"]).status, 0);
    let first = output_of(&rig, "digest").expect("a digest");

    // A smaller set: fuse3 is no longer listed, and what else the directory holds goes with it.
    fs::write(cache(&rig).join("old_1.0_all.deb"), "an old archive").expect("an old archive");
    fs::create_dir_all(cache(&rig).join("folder")).expect("a folder");
    new_runner(&rig);
    let outcome = archive_run(&rig, &["tmux"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(manifest(&rig), [manifest_line(&rig, "tmux")]);
    let files: Vec<String> = fs::read_dir(cache(&rig))
        .expect("the directory")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert_eq!(files.len(), 2, "{files:?}");
    assert_ne!(output_of(&rig, "digest"), Some(first));
    assert_eq!(output_of(&rig, "save"), Some("true".to_owned()));
    let entry = output_of(&rig, "entry").expect("an entry");
    assert!(!entry.contains("repair"), "{entry}");

    // A replacement under the same name, and a link where an archive is listed.
    pool(
        &rig,
        &[
            ("tmux", "tmux bytes, replaced"),
            ("fuse3", "fuse3 bytes, longer"),
        ],
    );
    std::os::unix::fs::symlink(
        rig.path("pool/fuse3_1.0_all.deb"),
        cache(&rig).join("fuse3_1.0_all.deb"),
    )
    .expect("a link");
    new_runner(&rig);
    let outcome = archive_run(&rig, &["tmux", "fuse3"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        summary(&outcome)
            .starts_with("apt-install: packages=2 archives=2 seeded=0 fetched=2 dropped=2 "),
        "{}",
        summary(&outcome)
    );
    assert_eq!(output_of(&rig, "save"), Some("true".to_owned()));
    assert!(
        output_of(&rig, "entry")
            .expect("an entry")
            .contains("-repair-77-2")
    );
    assert!(!cache(&rig).join("fuse3_1.0_all.deb").is_symlink());

    // A directory where an archive is listed.
    fs::remove_file(cache(&rig).join("tmux_1.0_all.deb")).expect("an archive");
    fs::create_dir(cache(&rig).join("tmux_1.0_all.deb")).expect("a directory");
    new_runner(&rig);
    let outcome = archive_run(&rig, &["tmux", "fuse3"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        summary(&outcome)
            .starts_with("apt-install: packages=2 archives=2 seeded=1 fetched=1 dropped=1 "),
        "{}",
        summary(&outcome)
    );
    assert!(
        outcome
            .stdout
            .contains("apt-install: dropped tmux_1.0_all.deb"),
        "{}",
        outcome.stdout
    );
    assert!(cache(&rig).join("tmux_1.0_all.deb").is_file());
}

/// An archive that apt no longer holds when the install is done (apt may delete it once it is
/// installed) is left out of the saved set and said so, and the install is not failed by it.
#[test]
fn an_archive_that_apt_no_longer_holds_is_left_out_of_the_saved_set() {
    let rig = Rig::new();
    pool(
        &rig,
        &[("tmux", "tmux bytes"), ("fuse3", "fuse3 bytes, longer")],
    );
    rig.plan("install", &["consume"]);
    let outcome = archive_run(&rig, &["tmux", "fuse3"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        outcome
            .stdout
            .contains("apt-install: not saved tmux_1.0_all.deb"),
        "{}",
        outcome.stdout
    );
    assert_eq!(manifest(&rig), [manifest_line(&rig, "fuse3")]);
    assert_eq!(output_of(&rig, "save"), Some("true".to_owned()));
}

/// A list line with no hash is neither seeded nor saved: nothing can be checked against it. The
/// directory holds both archives, and the plan lists tmux with no hash.
#[test]
fn an_archive_with_no_hash_in_the_list_is_neither_seeded_nor_saved() {
    let rig = Rig::new();
    pool(
        &rig,
        &[("tmux", "tmux bytes"), ("fuse3", "fuse3 bytes, longer")],
    );
    assert_eq!(archive_run(&rig, &["tmux", "fuse3"]).status, 0);
    new_runner(&rig);
    fs::write(rig.path("nohash"), "tmux").expect("a marker");
    let outcome = archive_run(&rig, &["tmux", "fuse3"]);
    assert_eq!(outcome.status, 0, "{}{}", outcome.stdout, outcome.stderr);
    assert!(
        summary(&outcome).contains(" archives=1 seeded=1 "),
        "{}",
        summary(&outcome)
    );
    assert!(
        !outcome.stdout.contains("seeded tmux_1.0_all.deb")
            && outcome
                .stdout
                .contains("apt-install: seeded fuse3_1.0_all.deb"),
        "{}",
        outcome.stdout
    );
    assert_eq!(
        rig.lines("fetched.log"),
        ["tmux_1.0_all.deb"],
        "apt fetched the archive the script did not copy"
    );
    assert_eq!(manifest(&rig), [manifest_line(&rig, "fuse3")]);
    assert!(!cache(&rig).join("tmux_1.0_all.deb").exists());
}

/// The names and bytes of the files of the archive directory, in order of name.
fn cache_files(rig: &Rig) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = fs::read_dir(cache(rig))
        .expect("the directory")
        .map(|entry| {
            let entry = entry.expect("an entry");
            (
                entry.file_name().to_string_lossy().into_owned(),
                fs::read(entry.path()).expect("a file"),
            )
        })
        .collect();
    files.sort();
    files
}

/// A failed install saves nothing: a directory that an earlier run saved is left as it was, and
/// with no directory none is made.
#[test]
fn a_failed_install_saves_nothing() {
    let rig = Rig::new();
    pool(&rig, &[("tmux", "tmux bytes")]);
    rig.plan("install", &["fail"]);
    let outcome = archive_run(&rig, &["tmux"]);
    assert_eq!(outcome.status, 100, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(output_of(&rig, "save"), Some("false".to_owned()));
    assert!(!cache(&rig).exists());

    // A directory saved by an earlier run, a changed pool and a runner that fails to install.
    let rig = Rig::new();
    pool(&rig, &[("tmux", "tmux bytes")]);
    assert_eq!(archive_run(&rig, &["tmux"]).status, 0);
    let before = cache_files(&rig);
    assert_eq!(before.len(), 2, "an archive and its manifest");
    pool(&rig, &[("tmux", "tmux BYTES")]);
    new_runner(&rig);
    rig.plan("install", &["fail"]);
    let outcome = archive_run(&rig, &["tmux"]);
    assert_eq!(outcome.status, 100, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(output_of(&rig, "save"), Some("false".to_owned()));
    assert_eq!(cache_files(&rig), before);
    assert!(!rig.path("cache/desktop.new").exists());
}

/// With an archive directory the plan of the install is the listing, and a failure of it after a
/// clean update ends the script as it does without one.
#[test]
fn with_an_archive_directory_a_listing_that_fails_after_a_clean_update_ends_the_script() {
    let rig = Rig::new();
    rig.plan("list", &["e:Unable to locate package nosuchpackage"]);
    let outcome = archive_run(&rig, &["nosuchpackage"]);
    assert_eq!(outcome.status, 1, "{}{}", outcome.stdout, outcome.stderr);
    assert_eq!(rig.phases(), ["update", "list"]);
    assert_eq!(output_of(&rig, "save"), None);
}

/// An archive directory that is not an absolute path of its own is refused before anything is
/// called, since the script replaces the directory as a whole.
#[test]
fn an_archive_directory_that_is_relative_or_the_root_is_refused() {
    for directory in ["cache/desktop", "/", ""] {
        let rig = Rig::new();
        let outcome = rig.run(&["--archive", directory, "tmux"]);
        assert_eq!(
            outcome.status, 2,
            "{directory:?}: {}{}",
            outcome.stdout, outcome.stderr
        );
        assert!(rig.phases().is_empty(), "{directory:?}");
    }
}
