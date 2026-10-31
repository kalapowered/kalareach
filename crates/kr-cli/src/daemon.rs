//! Asking an environment's control daemon, for the commands that manage what the environment holds:
//! its repositories and workspaces, change sets and diffs, paired devices and plugins.
//!
//! Each of those commands is a client of one method the daemon serves on this user's own socket.
//! They share the same steps, and those steps are here: find the environment the command names,
//! reach its daemon, and ask it. The daemon decides every refusal and says why; a command adds the
//! request's shape and a readable answer, and nothing it prints is decided anywhere else.

use kr_client::retry::UserAction;
use kr_client::shown;
use std::str::FromStr;

use kr_ipc::client::LocalClient;
use kr_ipc::paths::HostPaths;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::method::Method;

use crate::cli::EnvironmentSelector;
use crate::error::{CliError, Result};
use crate::resolve;

/// One environment's control daemon, reached.
pub struct Daemon {
    environment_id: EnvironmentId,
    client: LocalClient,
}

impl Daemon {
    /// Reaches the daemon of the environment `selector` names: the one it names by identifier, or
    /// this installation's own.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Usage`] for a selector that is not an environment identifier, and
    /// [`CliError::HostUnavailable`] when this host has no such environment or its daemon is not
    /// running.
    pub async fn open(paths: &HostPaths, selector: &EnvironmentSelector) -> Result<Self> {
        let environment = resolve::select(paths, selector.environment.as_deref())?;
        let client = resolve::open_controller(&environment.paths, crate::build_id()).await?;
        Ok(Self {
            environment_id: environment.environment_id,
            client,
        })
    }

    /// The environment this daemon serves.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }

    /// Calls a read.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal, or a transport failure.
    pub async fn read<P, T>(&mut self, method: Method, params: &P) -> Result<T>
    where
        P: serde::Serialize + ?Sized,
        T: kr_protocol::wire::WireMessage,
    {
        crate::bind::read(&mut self.client, method, params)
            .await
            .map_err(|error| in_the_hosts_words(method, error))
    }

    /// Calls a mutation on this environment, under an action identity of its own.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal, or a transport failure.
    pub async fn mutate<P, T>(&mut self, method: Method, params: &P) -> Result<T>
    where
        P: serde::Serialize + ?Sized,
        T: kr_protocol::wire::WireMessage,
    {
        let target = ActionTarget::environment(self.environment_id);
        crate::bind::mutate(&mut self.client, method, target, params)
            .await
            .map_err(|error| in_the_hosts_words(method, error))
    }

    /// Calls a mutation on this environment that asks for a lifetime of `ttl`, for a call whose
    /// work can outlast the default one.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal, or a transport failure.
    pub async fn mutate_within<P, T>(
        &mut self,
        method: Method,
        params: &P,
        ttl: kr_protocol::scalars::DurationMs,
    ) -> Result<T>
    where
        P: serde::Serialize + ?Sized,
        T: kr_protocol::wire::WireMessage,
    {
        let target = ActionTarget::environment(self.environment_id);
        crate::bind::mutate_within(&mut self.client, method, target, params, ttl)
            .await
            .map_err(|error| in_the_hosts_words(method, error))
    }
}

/// The methods that run Git on the host.
const RUN_GIT: [Method; 9] = [
    Method::ProjectInit,
    Method::ProjectClone,
    Method::ProjectAdopt,
    Method::WorkspaceCreate,
    Method::WorkspaceRemove,
    Method::ChangesetCapture,
    Method::DiffRead,
    Method::DiffApply,
    Method::DiffRevert,
];

/// Returns a refusal as a person is told it: for a method that runs Git, a host that is not set up
/// for it (no usable Git, or a kernel the boundary cannot be built on) says in its own sentence
/// what a person does, which is to install Git where it names the step or to use a host whose
/// kernel has the interface. The client's one line for that code, which tells a person to change a
/// setting, fits neither, so it is not added. Every other refusal is as it was.
fn in_the_hosts_words(method: Method, error: CliError) -> CliError {
    match error {
        CliError::Refused(refused)
            if refused.code == ErrorCode::HostNotConfigured && RUN_GIT.contains(&method) =>
        {
            CliError::ServiceRefused {
                error: refused,
                action: UserAction::Nothing,
            }
        }
        other => other,
    }
}

/// Reads an identifier from the command line.
///
/// `what` names the kind of thing it identifies, with its article: "a workspace". The text itself
/// is not repeated in the failure: it is whatever was typed.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the text is not such an identifier.
pub fn identifier<T: FromStr>(text: &str, what: &'static str) -> Result<T> {
    text.parse()
        .map_err(|_| CliError::Usage(shown!("the text given is not {} identifier", what)))
}
