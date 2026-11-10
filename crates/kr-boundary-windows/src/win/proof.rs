//! The proof that the boundary is in force, and the proof that it has been released.
//!
//! A launch that fails does not show that the policy refused it: a permission, a missing file or
//! another control could fail it the same way. So the proof asks three things of the platform,
//! through the broker, the only holder of the right to make the account's token:
//!
//! 1. an unlisted copy of a system program, made in a directory only administrators can write, is
//!    refused to the account with the policy's own error, and the application-control log names
//!    the account's own deny rule, by its identifier, as the rule that refused it;
//! 2. a program on the account's list runs;
//! 3. the same unlisted copy run under the broker's own token runs, so the refusal was the
//!    policy's and not a defect of the copy.
//!
//! The policy binds a moment after it is written, and how long that takes was not the same twice
//! on the guest it was measured on, so the first question is asked again until the platform
//! answers it. The wait ends on the platform's own answer or on a bound; a bound that runs out is
//! a proof that did not succeed, not a pass.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::frame::Class;
use crate::manifest::{Manifest, ObjectKind};
use crate::policy::{RULE_CHECKOUT, RULE_CONNECT};

use super::acl;
use super::applocker;
use super::launch::{Outcome, REFUSED_BY_POLICY, run_as};
use super::pipe::Stop;
use super::token::{boundary_token, new_invocation_group};

/// The result of a proof.
pub struct Proof {
    /// Whether every question was answered as the boundary requires.
    pub ready: bool,
    /// What the proof saw.
    pub detail: String,
}

fn fail(detail: impl Into<String>) -> Proof {
    Proof {
        ready: false,
        detail: detail.into(),
    }
}

/// The account of a class, from the manifest: its name and its identifier text.
fn account_of(manifest: &Manifest, class: Class) -> Option<(String, String)> {
    let name = match class {
        Class::Checkout => super::install::CHECKOUT,
        Class::Connect => super::install::CONNECT,
    };
    let object = manifest.find(ObjectKind::Account, name)?;
    Some((name.to_owned(), object.detail.clone()?))
}

fn git_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into()))
        .join("Git")
}

fn environment() -> Vec<(&'static str, String)> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    vec![
        ("SystemRoot", root.clone()),
        ("windir", root.clone()),
        ("SystemDrive", "C:".to_owned()),
        (
            "PATH",
            format!(
                "{};{root}\\System32",
                git_dir().join("mingw64").join("bin").display()
            ),
        ),
    ]
}

fn same_path(left: &str, right: &Path) -> bool {
    left.eq_ignore_ascii_case(&right.display().to_string())
}

/// A scratch directory that only administrators can write and every account can read and enter,
/// removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(under: &Path) -> Result<Scratch, String> {
        let dir = under.join(format!("proof-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir)
            .map_err(|error| format!("making {}: {error}", dir.display()))?;
        acl::set_protected(&dir, acl::READABLE_PROTECTED).map_err(|error| error.to_string())?;
        Ok(Scratch(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Proves that the policy refuses an unlisted program to a class's token and runs a listed one.
#[must_use]
pub fn prove(
    manifest: &Manifest,
    class: Class,
    staging: &Path,
    bound: Duration,
    stop: &Stop,
) -> Proof {
    let Some((account, sid)) = account_of(manifest, class) else {
        return fail("the manifest records no account for this class");
    };
    let rule = match class {
        Class::Checkout => RULE_CHECKOUT,
        Class::Connect => RULE_CONNECT,
    };
    let scratch = match Scratch::new(staging) {
        Ok(scratch) => scratch,
        Err(reason) => return fail(reason),
    };
    let system32 =
        PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into()))
            .join("System32");
    let unlisted = scratch.0.join("unlisted.exe");
    if let Err(error) = std::fs::copy(system32.join("hostname.exe"), &unlisted) {
        return fail(format!(
            "copying a system program into the scratch directory: {error}"
        ));
    }
    let token = match boundary_token(&account, &new_invocation_group()) {
        Ok(token) => token,
        Err(error) => return fail(format!("making the token for {account}: {error}")),
    };
    let record = match applocker::newest_record(&scratch.0) {
        Ok(record) => record,
        Err(error) => return fail(error.to_string()),
    };
    let environment = environment();
    let started = Instant::now();
    let mut attempts = 0_u32;
    loop {
        if stop.is_set() {
            return fail("the service is stopping");
        }
        attempts += 1;
        match run_as(
            &token,
            &unlisted,
            "unlisted.exe",
            &scratch.0,
            &environment,
            Duration::from_secs(30),
        ) {
            Ok(Outcome::NotStarted(code)) if code == REFUSED_BY_POLICY => break,
            Ok(Outcome::NotStarted(code)) => {
                return fail(format!(
                    "the unlisted program could not be started for {account}, with error {code} and not the policy's {REFUSED_BY_POLICY}"
                ));
            }
            Ok(Outcome::Ran(_)) => {}
            Ok(Outcome::TimedOut) => return fail("the unlisted program ran for 30 seconds"),
            Err(error) => return fail(error.to_string()),
        }
        if started.elapsed() >= bound {
            return fail(format!(
                "the policy did not refuse the unlisted program to {account} in {} seconds ({attempts} launches)",
                bound.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    // The refusal is the policy's only if the log says which rule made it.
    let named = loop {
        match applocker::blocked_after(record, &scratch.0) {
            Ok(events) => {
                if events.iter().any(|event| {
                    event.rule_id == rule
                        && event.user.eq_ignore_ascii_case(&sid)
                        && same_path(&event.path, &unlisted)
                }) {
                    break true;
                }
            }
            Err(error) => return fail(error.to_string()),
        }
        if started.elapsed() >= bound || stop.is_set() {
            break false;
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    if !named {
        return fail(format!(
            "the unlisted program was refused to {account} but the log does not name the rule {rule}"
        ));
    }
    let git = git_dir().join("mingw64").join("bin").join("git.exe");
    match run_as(
        &token,
        &git,
        "git.exe --version",
        &scratch.0,
        &environment,
        Duration::from_secs(30),
    ) {
        Ok(Outcome::Ran(0)) => {}
        Ok(other) => return fail(format!("Git did not run for {account}: {other:?}")),
        Err(error) => return fail(error.to_string()),
    }
    let control = Command::new(&unlisted)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match control {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return fail(format!(
                "the unlisted program did not run under the broker's own token: {status}"
            ));
        }
        Err(error) => {
            return fail(format!(
                "the unlisted program did not run under the broker's own token: {error}"
            ));
        }
    }
    Proof {
        ready: true,
        detail: format!(
            "{account}: an unlisted program was refused with {REFUSED_BY_POLICY} by rule {rule} after {attempts} launch(es) in {:.1} s, Git ran, and the same program ran under the broker's own token",
            started.elapsed().as_secs_f32()
        ),
    }
}

/// Proves that a program the policy refused runs again for a class's token.
#[must_use]
pub fn release(
    manifest: &Manifest,
    class: Class,
    staging: &Path,
    bound: Duration,
    stop: &Stop,
) -> Proof {
    let Some((account, _)) = account_of(manifest, class) else {
        return fail("the manifest records no account for this class");
    };
    let token = match boundary_token(&account, &new_invocation_group()) {
        Ok(token) => token,
        Err(error) => return fail(format!("making the token for {account}: {error}")),
    };
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_owned());
    let cmd_dir = Path::new(&root).join("System32");
    let cmd = cmd_dir.join("cmd.exe");
    let environment = environment();
    let started = Instant::now();
    let mut attempts = 0_u32;
    loop {
        if stop.is_set() {
            return fail("the service is stopping");
        }
        attempts += 1;
        match run_as(
            &token,
            &cmd,
            "cmd.exe /c exit 0",
            staging,
            &environment,
            Duration::from_secs(30),
        ) {
            Ok(Outcome::Ran(0)) => {
                return Proof {
                    ready: true,
                    detail: format!(
                        "{account}: cmd.exe runs again after {attempts} launch(es) in {:.1} s",
                        started.elapsed().as_secs_f32()
                    ),
                };
            }
            Ok(Outcome::NotStarted(code)) if code == REFUSED_BY_POLICY => {}
            Ok(other) => return fail(format!("cmd.exe for {account}: {other:?}")),
            Err(error) => return fail(error.to_string()),
        }
        if started.elapsed() >= bound {
            return fail(format!(
                "cmd.exe is still refused to {account} after {} seconds ({attempts} launches)",
                bound.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}
