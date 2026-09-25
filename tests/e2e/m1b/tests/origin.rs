//! How the scripts that check a deployment read the origin they are given.
//!
//! `scripts/e2e-deployment.sh` and `scripts/e2e-m1b.sh` sign requests to, reserve invitations at
//! and print whatever origin they are handed. Each must refuse an origin the product's own parsers
//! refuse, with exit status 2, before it prints the value, builds a leg or sends anything, and the
//! refusal must never repeat the value. The rule is the product's: the scripts ask the
//! `kr-e2e-m1b-origin` program this package builds, which reads an origin with the parsers a host
//! reserves its invitations with and a service request is addressed with.
//!
//! The scripts run here as they are, with a stand-in for `cargo` first on their path. It runs the
//! origin checker when a script asks for it, and records and refuses anything else, so a script
//! that would go on to build or run a leg with an origin it should have refused fails here, and
//! nothing is built.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Origins the product refuses, each with the rule it breaks.
const REFUSED: &[(&str, &str)] = &[
    (
        "https://:443",
        "no host, and the port a canonical origin leaves out",
    ),
    ("https://reach.kala.to:https", "a port that is not a number"),
    ("https://reach.kala.to:", "an empty port"),
    ("https://reach.kala.to:443", "the default port written out"),
    ("https://reach.kala.to:0443", "a port with a leading zero"),
    ("https://reach.kala.to:65536", "a port past 65535"),
    (
        "https://[abc]",
        "brackets around something that is not an IPv6 address",
    ),
    (
        "https://[::ffff:192.0.2.1]",
        "an IPv4 address written as a mapped IPv6 one",
    ),
    (
        "https://999.999.999.999",
        "a number that is not an IPv4 address",
    ),
    ("https://Reach.kala.to", "a name in capitals"),
    ("https://reach.kala.to.", "a name with a trailing dot"),
    ("http://reach.kala.to", "plain HTTP"),
];

/// Origins the product accepts.
const ACCEPTED: &[&str] = &[
    "https://reach.kala.to",
    "https://example.invalid:8443",
    "https://127.0.0.1:8443",
    "https://[::1]:8443",
];

/// The scripts that are given an origin.
const SCRIPTS: &[&str] = &["scripts/e2e-deployment.sh", "scripts/e2e-m1b.sh"];

/// The stand-in for `cargo`. It runs the checker `STAND_IN_CHECKER` names when it is asked to run
/// the origin checker, with the arguments after `--`, and for anything else it writes the command's
/// first word to `STAND_IN_RECORD` and fails.
const STAND_IN: &str = r#"#!/bin/sh
if [ "$1" = run ]; then
  for argument in "$@"; do
    if [ "$argument" = kr-e2e-m1b-origin ]; then
      while [ "$#" -gt 0 ] && [ "$1" != -- ]; do shift; done
      [ "$#" -gt 0 ] && shift
      exec "$STAND_IN_CHECKER" "$@"
    fi
  done
fi
printf '%s\n' "$1" >> "$STAND_IN_RECORD"
exit 97
"#;

/// How many of the two tests that start the checker have ended. The companion that starts
/// children beside them runs until both have.
static ENDED: AtomicUsize = AtomicUsize::new(0);

/// Counts its test as ended when it is dropped, whether the test returned or failed.
struct Ending;

impl Drop for Ending {
    fn drop(&mut self) {
        ENDED.fetch_add(1, Ordering::SeqCst);
    }
}

/// A directory of one test's own on the internal disk, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.subsec_nanos());
        let path = std::env::temp_dir().join(format!("krm-{name}-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&path).expect("a scratch directory of this test's own");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The workspace this package belongs to.
fn workspace() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    std::fs::canonicalize(&root).expect("the workspace")
}

/// The origin checker, copied to the internal disk, as everything a test launches runs from there.
fn checker(scratch: &Path) -> PathBuf {
    let copy = scratch.join("kr-e2e-m1b-origin");
    std::fs::copy(env!("CARGO_BIN_EXE_kr-e2e-m1b-origin"), &copy).expect("the checker copies");
    copy
}

/// Whether `said` repeats `origin`, whole or its part after the scheme.
fn repeats(said: &str, origin: &str) -> bool {
    let authority = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    said.contains(origin) || (!authority.is_empty() && said.contains(authority))
}

/// Everything a process wrote, standard output first.
fn everything(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn the_checker_accepts_what_the_product_accepts_and_names_the_rule_a_refusal_breaks() {
    let _ending = Ending;
    let scratch = Scratch::new("origin-checker");
    let checker = checker(&scratch.0);
    let check = |arguments: &[&str]| {
        Command::new(&checker)
            .args(arguments)
            .env_remove("KR_M1B_ORIGIN")
            .output()
            .expect("the checker runs")
    };
    let mut wrong = Vec::new();

    for &origin in ACCEPTED {
        let output = check(&[origin]);
        if output.status.code() != Some(0) || !everything(&output).is_empty() {
            wrong.push(format!(
                "{origin} is an origin the product accepts, and the checker exited {:?} saying {:?}",
                output.status.code(),
                everything(&output)
            ));
        }
    }
    for &(origin, why) in REFUSED {
        let output = check(&[origin]);
        let said = String::from_utf8_lossy(&output.stderr);
        if output.status.code() != Some(2)
            || !output.stdout.is_empty()
            || said.trim().is_empty()
            || repeats(&said, origin)
        {
            wrong.push(format!(
                "{origin} ({why}) is refused by the product, and the checker exited {:?} saying {:?}",
                output.status.code(),
                everything(&output)
            ));
        }
    }
    for arguments in [
        &[][..],
        &["https://reach.kala.to", "https://reach.kala.to"][..],
    ] {
        let output = check(arguments);
        if output.status.code() != Some(2) {
            wrong.push(format!(
                "the checker takes one origin, and given {} it exited {:?}",
                arguments.len(),
                output.status.code()
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
fn each_script_refuses_what_the_product_refuses_before_it_prints_builds_or_sends_it() {
    let _ending = Ending;
    let scratch = Scratch::new("origin-scripts");
    let checker = checker(&scratch.0);
    let bin = scratch.0.join("bin");
    std::fs::create_dir(&bin).expect("a directory for the stand-in");
    let stand_in = bin.join("cargo");
    std::fs::write(&stand_in, STAND_IN).expect("the stand-in is written");
    std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755))
        .expect("the stand-in is executable");
    let record = scratch.0.join("asked");
    let artefacts = scratch.0.join("artefacts");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let workspace = workspace();

    // What a script asked of `cargo` besides the checker, and the evidence directories it made,
    // both cleared for the next run.
    let went_on = || {
        let asked = std::fs::read_to_string(&record).unwrap_or_default();
        let _ = std::fs::remove_file(&record);
        let made = std::fs::read_dir(&artefacts).map_or(0, Iterator::count);
        let _ = std::fs::remove_dir_all(&artefacts);
        (
            asked
                .split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>(),
            made,
        )
    };
    let run = |script: &str, origin: &str| {
        Command::new("bash")
            .arg(workspace.join(script))
            .arg(origin)
            .current_dir(&workspace)
            .env("PATH", &path)
            .env("STAND_IN_CHECKER", &checker)
            .env("STAND_IN_RECORD", &record)
            .env("KR_TEST_ARTIFACTS_DIR", &artefacts)
            .env_remove("KR_DEPLOYED_ORIGIN")
            .env_remove("KR_M1B_ORIGIN")
            .output()
            .expect("bash runs the script")
    };
    let mut wrong = Vec::new();

    for &script in SCRIPTS {
        for &(origin, why) in REFUSED {
            let output = run(script, origin);
            let (asked, made) = went_on();
            let said = everything(&output);
            if output.status.code() != Some(2)
                || repeats(&said, origin)
                || !asked.is_empty()
                || made != 0
            {
                wrong.push(format!(
                    "{script} given {origin} ({why}) exited {:?}, asked cargo for {asked:?} besides \
                     the checker, made {made} evidence directories, and said {said:?}",
                    output.status.code()
                ));
            }
        }

        // An origin the product accepts gets past the check, and the script goes on to build its
        // legs, which the stand-in refuses. So the refusals above are the check's, not the
        // stand-in's.
        let output = run(script, ACCEPTED[1]);
        let (asked, _) = went_on();
        if output.status.code() != Some(1)
            || asked.is_empty()
            || asked.iter().any(|first| first == "run")
        {
            wrong.push(format!(
                "{script} given {} exited {:?} after asking cargo for {asked:?}, where it should \
                 have passed the check and then asked to build: {:?}",
                ACCEPTED[1],
                output.status.code(),
                everything(&output)
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Starts short-lived children, one after another, for as long as the two tests above run.
///
/// A child is handed a copy of every descriptor this process holds at the moment it starts, and
/// keeps the copies until its own program takes over. A program another test of this process has
/// just written can therefore still be held open for writing by a child that test never started,
/// and the system refuses to start a program held open that way. This companion starts children
/// all the time, so that the moment comes often rather than now and then. It is ignored by default
/// and runs with `--include-ignored` and at least three test threads; run without the two tests
/// beside it, it stops after a minute.
#[test]
#[ignore = "a load for the two tests beside it: run it with --include-ignored and three threads"]
fn children_start_beside_the_tests_for_as_long_as_they_run() {
    let bound = Instant::now() + Duration::from_secs(60);
    while ENDED.load(Ordering::SeqCst) < 2 && Instant::now() < bound {
        let status = Command::new("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("a short-lived child starts");
        assert!(status.success(), "a short-lived child ended with {status}");
    }
}
