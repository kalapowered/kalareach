//! Starting an enclosed Git child on Unix.
//!
//! One shape serves macOS and Linux, because the sequence is the same on both and only the
//! mechanism differs. The parent builds the child's whole environment and prepares whatever the
//! platform's boundary needs while it is still an ordinary process. The child then, in order:
//! moves into the directory handle the parent opened, applies whatever the platform leaves for it,
//! and executes what the platform named — Git, or the launcher that applies the boundary and then
//! executes Git. Every one of those happens before Git exists, so there is no moment in which Git
//! is running and the boundary is not.
//!
//! The child also leads its own process group, so ending it ends everything it started: a remote
//! helper, an ssh process, a credential helper.

#![expect(
    unsafe_code,
    reason = "a child that must enter a directory handle before it execs has no safe form: std's \
              pre-exec hook is unsafe because only the caller can promise the work it does is what \
              a forked child may do"
)]

use std::process::{Child, Command, Stdio};

use super::{Confinement, Invocation, platform};
use crate::error::{ProjectError, Result};

/// One enclosed Git child.
#[derive(Debug)]
pub struct Spawned {
    child: Child,
}

impl Spawned {
    /// Takes the child's standard output, which is read once.
    pub fn stdout(&mut self) -> Option<std::fs::File> {
        self.child
            .stdout
            .take()
            .map(|pipe| std::fs::File::from(std::os::fd::OwnedFd::from(pipe)))
    }

    /// Takes the child's standard error, which is read once.
    pub fn stderr(&mut self) -> Option<std::fs::File> {
        self.child
            .stderr
            .take()
            .map(|pipe| std::fs::File::from(std::os::fd::OwnedFd::from(pipe)))
    }

    /// Returns the child's exit status when it has one.
    ///
    /// # Errors
    ///
    /// Returns whatever waiting on the child failed with.
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.child.try_wait()
    }

    /// Ends the child and everything it started, and says whether it could confirm that.
    ///
    /// The child leads its own group, so its identifier is the group's and nothing else on this
    /// machine is in it. What is ended is the identity this host recorded rather than a name or a
    /// pattern that could match somebody else's work.
    pub fn end(&mut self) -> bool {
        let Ok(raw) = i32::try_from(self.child.id()) else {
            return false;
        };
        let Some(pid) = rustix::process::Pid::from_raw(raw) else {
            return false;
        };
        let killed =
            rustix::process::kill_process_group(pid, rustix::process::Signal::KILL).is_ok();
        let reaped = self.child.wait().is_ok();
        killed && reaped
    }
}

/// Starts one Git invocation inside its boundary.
///
/// # Errors
///
/// Returns [`ProjectError::GitFailed`] when the boundary cannot be prepared or the child cannot be
/// started. A child whose boundary could not be applied never reaches `exec`: the failure comes
/// back here as a start failure, so there is no case in which Git runs unenclosed.
pub fn start(invocation: &Invocation<'_>, confinement: &Confinement) -> Result<Spawned> {
    // Everything the boundary needs is prepared while this is still an ordinary process: writing a
    // profile, opening the objects the rules are attached to, building a filter program. What is
    // left for the child is the work that can only be done there.
    let mut prepared = platform::prepare(confinement)?;
    let (program, arguments) = prepared.command(invocation);
    // The handle the child moves into, duplicated so the closure owns one. The duplicate is closed
    // when the closure is dropped, which the parent does as soon as the child is started.
    let directory = std::os::fd::AsFd::as_fd(confinement.working.handle().handle())
        .try_clone_to_owned()
        .map_err(|error| ProjectError::GitFailed {
            detail: format!(
                "{} could not be started in the directory this host opened: {error}",
                invocation.described
            )
            .into(),
        })?;
    let mut command = Command::new(&program);
    command.env_clear();
    for (name, value) in invocation.environment {
        command.env(name, value);
    }
    command.args(&arguments);
    // The path is where the child starts; the handle below is where it ends up. Both are set
    // because the first is what two of the three mechanisms write their rules against and the
    // second is the object this host opened, and a substitution between them is exactly what the
    // handle answers.
    command.current_dir(confinement.working.path());
    // A Git subprocess never gets a terminal: it cannot prompt, it cannot page, and a helper that
    // wanted to read from one finds nothing to read.
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
        // SAFETY: the hook runs in the forked child before `exec`. It moves into an already-open
        // directory and applies whatever the platform left for it, and each platform's `apply` is
        // written for that state: no allocation of its own, no lock this process holds, no call
        // back into this crate. On macOS it does nothing at all, because the launcher the child
        // executes applies the boundary itself.
        unsafe {
            command.pre_exec(move || {
                rustix::process::fchdir(&directory)?;
                prepared.apply()
            });
        }
    }
    let child = command.spawn().map_err(|error| ProjectError::GitFailed {
        detail: format!("{} could not start: {error}", invocation.described).into(),
    })?;
    Ok(Spawned { child })
}
