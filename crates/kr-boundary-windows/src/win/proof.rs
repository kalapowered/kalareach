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
use std::time::{Duration, Instant};

use crate::env::{self, EnvBlock, Kind, QualifiedGit, RootPaths};
use crate::frame::Class;
use crate::manifest::{GitSet, Manifest, ObjectKind};
use crate::policy::{RULE_CHECKOUT, RULE_CONNECT};
use crate::quote::quote_command_line;

use super::acl;
use super::applocker;
use super::ffi::{self, Sid};
use super::install::Paths;
use super::launch::{
    Captured, LaunchError, Outcome, REFUSED_BY_POLICY, Run, TokenSpec, VerifiedPath, run_captured,
};
use super::pipe::Stop;
use super::sd::{Principals, SdKind, descriptor};
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

/// The system's own Windows directory, from the platform and not from any environment.
fn system_windows_directory() -> Result<String, String> {
    ffi::system_windows_directory().map_err(|error| error.to_string())
}

/// The environment of a program of the proof, which runs in no repository. The proof's scratch
/// directory stands for the private root.
fn proof_environment(git: &GitSet, scratch: &Path) -> Result<EnvBlock, String> {
    let roots = RootPaths {
        system: system_windows_directory()?,
        boundary: Paths::system().program.display().to_string(),
        private_root: scratch.display().to_string(),
    };
    env::build_env(
        Kind::Proof,
        &roots,
        None,
        &QualifiedGit {
            dir: git.dir.clone(),
        },
    )
    .map_err(|error| error.to_string())
}

/// Starts one program of the proof through the launcher and waits for it.
fn run_program(
    token: TokenSpec<'_>,
    group: Option<&Sid>,
    program: &Path,
    arguments: &[&str],
    cwd: &Path,
    env: &EnvBlock,
    bound: Duration,
) -> Result<Captured, LaunchError> {
    let name = program.display().to_string();
    let mut parts = vec![name.as_str()];
    parts.extend_from_slice(arguments);
    run_captured(
        Run {
            token,
            group,
            program: VerifiedPath::new(program)?,
            command_line: quote_command_line(&parts),
            cwd,
            env,
        },
        bound,
    )
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
        let readable = descriptor(
            SdKind::AdminDir,
            &Principals {
                users_may_read: true,
                ..Principals::default()
            },
        )
        .map_err(|error| error.to_string())?;
        acl::set_protected(&dir, &readable).map_err(|error| error.to_string())?;
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
    let Some(git) = manifest.git.as_ref() else {
        return fail("the manifest records no Git installation");
    };
    let rule = match class {
        Class::Checkout => RULE_CHECKOUT,
        Class::Connect => RULE_CONNECT,
    };
    let scratch = match Scratch::new(staging) {
        Ok(scratch) => scratch,
        Err(reason) => return fail(reason),
    };
    let system = match system_windows_directory() {
        Ok(system) => PathBuf::from(system),
        Err(reason) => return fail(reason),
    };
    let unlisted = scratch.0.join("unlisted.exe");
    if let Err(error) = std::fs::copy(system.join("System32").join("hostname.exe"), &unlisted) {
        return fail(format!(
            "copying a system program into the scratch directory: {error}"
        ));
    }
    let group = new_invocation_group();
    let token = match boundary_token(&account, &group) {
        Ok(token) => token,
        Err(error) => return fail(format!("making the token for {account}: {error}")),
    };
    let environment = match proof_environment(git, &scratch.0) {
        Ok(environment) => environment,
        Err(reason) => return fail(reason),
    };
    let record = match applocker::newest_record(&scratch.0, &environment) {
        Ok(record) => record,
        Err(error) => return fail(error.to_string()),
    };
    let started = Instant::now();
    let mut attempts = 0_u32;
    loop {
        if stop.is_set() {
            return fail("the service is stopping");
        }
        attempts += 1;
        match run_program(
            TokenSpec::Boundary(&token),
            Some(&group),
            &unlisted,
            &[],
            &scratch.0,
            &environment,
            Duration::from_secs(30),
        ) {
            Err(LaunchError::NotStarted(code)) if code == REFUSED_BY_POLICY => break,
            Err(LaunchError::NotStarted(code)) => {
                return fail(format!(
                    "the unlisted program could not be started for {account}, with error {code} and not the policy's {REFUSED_BY_POLICY}"
                ));
            }
            Ok(Captured {
                outcome: Outcome::Ran(_),
                ..
            }) => {}
            Ok(Captured {
                outcome: Outcome::TimedOut,
                ..
            }) => return fail("the unlisted program ran for 30 seconds"),
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
        match applocker::blocked_after(record, &scratch.0, &environment) {
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
    let git_exe = Path::new(&git.dir)
        .join("mingw64")
        .join("bin")
        .join("git.exe");
    match run_program(
        TokenSpec::Boundary(&token),
        Some(&group),
        &git_exe,
        &["--version"],
        &scratch.0,
        &environment,
        Duration::from_secs(30),
    ) {
        Ok(Captured {
            outcome: Outcome::Ran(0),
            ..
        }) => {}
        Ok(other) => {
            return fail(format!(
                "Git did not run for {account}: {:?}",
                other.outcome
            ));
        }
        Err(error) => return fail(error.to_string()),
    }
    match run_program(
        TokenSpec::Own,
        None,
        &unlisted,
        &[],
        &scratch.0,
        &environment,
        Duration::from_secs(30),
    ) {
        Ok(Captured {
            outcome: Outcome::Ran(0),
            ..
        }) => {}
        Ok(other) => {
            return fail(format!(
                "the unlisted program did not run under the broker's own token: {:?}",
                other.outcome
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
    let Some(git) = manifest.git.as_ref() else {
        return fail("the manifest records no Git installation");
    };
    let group = new_invocation_group();
    let token = match boundary_token(&account, &group) {
        Ok(token) => token,
        Err(error) => return fail(format!("making the token for {account}: {error}")),
    };
    let environment = match proof_environment(git, staging) {
        Ok(environment) => environment,
        Err(reason) => return fail(reason),
    };
    let cmd = match system_windows_directory() {
        Ok(system) => Path::new(&system).join("System32").join("cmd.exe"),
        Err(reason) => return fail(reason),
    };
    let started = Instant::now();
    let mut attempts = 0_u32;
    loop {
        if stop.is_set() {
            return fail("the service is stopping");
        }
        attempts += 1;
        match run_program(
            TokenSpec::Boundary(&token),
            Some(&group),
            &cmd,
            &["/c", "exit", "0"],
            staging,
            &environment,
            Duration::from_secs(30),
        ) {
            Ok(Captured {
                outcome: Outcome::Ran(0),
                ..
            }) => {
                return Proof {
                    ready: true,
                    detail: format!(
                        "{account}: cmd.exe runs again after {attempts} launch(es) in {:.1} s",
                        started.elapsed().as_secs_f32()
                    ),
                };
            }
            Err(LaunchError::NotStarted(code)) if code == REFUSED_BY_POLICY => {}
            Ok(other) => return fail(format!("cmd.exe for {account}: {:?}", other.outcome)),
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
