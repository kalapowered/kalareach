//! The host's saved launch commands: `shell.launch.commands.list`, `.save` and `.remove`.
//!
//! The list is read from the store without a lock. A write takes the store's lock first and then
//! asks the registration and the deadline again inside it, as the environment record does: the
//! read of the list, the check of the revision, the change and the publication are one synchronous
//! closure that awaits nothing, so a withdrawal of the caller's authority lands wholly before the
//! check or wholly after the publication.

use std::sync::Arc;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::launch_commands::{
    NamedLaunch, ShellLaunchCommandsListResult, ShellLaunchCommandsRemoveParams,
    ShellLaunchCommandsRemoveResult, ShellLaunchCommandsSaveParams, ShellLaunchCommandsSaveResult,
};
use kr_protocol::method::Method;
use kr_protocol::scalars::U64;

use super::{Controller, encode, parse};
use crate::authority::AdmittedMutation;
use crate::error::{ControllerError, Result};
use crate::launch_commands::{self as store, Outcome};

fn named(stored: &store::Stored) -> Vec<NamedLaunch> {
    stored.commands.iter().map(NamedLaunch::from).collect()
}

impl Controller {
    /// Where this host's own tests stop a change to the saved launch commands once it holds the
    /// store's lock and before it asks the admission again, so that a withdrawal can land in
    /// between. The pause holds the thread, not the task, and the lock with it. Compiled away in
    /// every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_after_the_launch_commands_are_locked(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.after_the_launch_commands_are_locked.arm()
    }

    /// Where this host's own tests stop a change to the saved launch commands inside the commit,
    /// where the registration is held and nothing of the file has been written, so that a
    /// withdrawal that lands now waits for the publication. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn pause_inside_the_launch_commands_commit(
        &self,
    ) -> (
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::SyncSender<()>,
    ) {
        self.inside_the_launch_commands_commit.arm()
    }

    /// How many reads of the saved launch commands this daemon has answered, so that a test can
    /// wait until a client has read the list. Compiled away in every shipped build.
    #[cfg(feature = "testing")]
    pub fn launch_commands_listed(&self) -> u64 {
        self.launch_commands_listed
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Answers `shell.launch.commands.list`: the commands the host holds and the revision of the
    /// list.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the file cannot be read or breaks a rule.
    pub(super) fn launch_commands_list(&self) -> Result<ParamsValue> {
        let stored = store::read(self.paths.state_dir())?;
        #[cfg(feature = "testing")]
        self.launch_commands_listed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        encode(&ShellLaunchCommandsListResult {
            revision: U64::new(stored.revision),
            commands: named(&stored),
        })
    }

    /// Answers `shell.launch.commands.save` and `shell.launch.commands.remove`.
    pub(super) async fn launch_commands_write(
        self: &Arc<Self>,
        mutation: &MutationRequest,
        method: Method,
        carried: AdmittedMutation,
    ) -> Result<ParamsValue> {
        let state_dir = self.paths.state_dir().to_path_buf();
        let controller = Arc::clone(self);
        match method {
            Method::ShellLaunchCommandsSave => {
                let params: ShellLaunchCommandsSaveParams = parse(&mutation.params)?;
                let Outcome {
                    applied,
                    changed,
                    replaced,
                    stored,
                } = self
                    .in_the_store(move || {
                        controller.under_the_store_lock(&carried, || {
                            store::save(&state_dir, params.expected_revision.get(), &params.command)
                        })
                    })
                    .await?;
                encode(&ShellLaunchCommandsSaveResult {
                    applied,
                    changed,
                    replaced,
                    revision: U64::new(stored.revision),
                    commands: named(&stored),
                })
            }
            Method::ShellLaunchCommandsRemove => {
                let params: ShellLaunchCommandsRemoveParams = parse(&mutation.params)?;
                let Outcome {
                    applied,
                    changed,
                    stored,
                    ..
                } = self
                    .in_the_store(move || {
                        controller.under_the_store_lock(&carried, || {
                            store::remove(&state_dir, params.expected_revision.get(), &params.label)
                        })
                    })
                    .await?;
                encode(&ShellLaunchCommandsRemoveResult {
                    applied,
                    removed: changed,
                    revision: U64::new(stored.revision),
                    commands: named(&stored),
                })
            }
            _ => Err(ControllerError::InvalidArgument(format!(
                "{} is not a launch-commands write",
                method.as_str()
            ))),
        }
    }

    /// Runs a blocking step of a write on a thread of its own.
    async fn in_the_store(
        &self,
        step: impl FnOnce() -> Result<Outcome> + Send + 'static,
    ) -> Result<Outcome> {
        tokio::task::spawn_blocking(step)
            .await
            .map_err(|error| ControllerError::supervision(error.to_string()))?
    }

    /// The store's lock first, then the registration and the deadline inside it.
    fn under_the_store_lock(
        &self,
        carried: &AdmittedMutation,
        commit: impl FnOnce() -> Result<Outcome>,
    ) -> Result<Outcome> {
        let _held = store::lock();
        #[cfg(feature = "testing")]
        self.after_the_launch_commands_are_locked.wait();
        self.under_registration(carried, || {
            #[cfg(feature = "testing")]
            self.inside_the_launch_commands_commit.wait();
            commit()
        })?
    }
}
