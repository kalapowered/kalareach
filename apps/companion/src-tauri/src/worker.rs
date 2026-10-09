//! Reaching one session's worker on this machine.
//!
//! A session's worker publishes a descriptor in the host's runtime directory: the endpoint it
//! listens on and the key it holds. A descriptor is data on disk, so reaching the worker is two
//! steps and never one: connect to the endpoint it names, then have the worker sign a challenge
//! only the descriptor's key could answer. Nothing else crosses the link before that proof, the way
//! `kr attach` reaches a worker. The raw terminal view and the agent calls both reach a worker here.

use kr_ipc::client::LocalClient;
use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::ids::SessionId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::worker::WorkerDescriptor;

use kr_client::shown::Shown;

/// A worker that proved it holds its descriptor's key, and the link to it.
pub struct Reached {
    /// The link, over which nothing but the proof has crossed.
    pub client: LocalClient,
    /// The descriptor the worker proved.
    pub descriptor: WorkerDescriptor,
    /// The build the worker stated in its answer to the hello, when it stated one.
    pub build: Option<kr_protocol::local::LocalBuild>,
}

/// Why a worker was not reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unreached {
    /// No worker for the session has published a descriptor on this machine.
    NotRunning,
    /// A descriptor is there and reaching the worker failed, for this reason.
    Failed(String),
}

impl Unreached {
    /// The reason, in words a person reads.
    #[must_use]
    pub fn words(self) -> String {
        match self {
            Self::NotRunning => "This session is not running on this computer.".to_owned(),
            Self::Failed(reason) => reason,
        }
    }
}

/// The host on this machine, found the way the local connection finds its control daemon.
///
/// Found each time it is asked, because the host can be started after the application.
///
/// # Errors
///
/// Returns why there is no host here.
pub fn this_machine() -> Result<EnvironmentPaths, String> {
    let paths = kr_ipc::paths::HostPaths::discover()
        .map_err(|error| format!("There is no host on this computer: {error}"))?;
    let environment_id = paths
        .open_environment_id()
        .map_err(|error| format!("There is no host on this computer: {error}"))?;
    Ok(paths.environment(environment_id))
}

/// Connects to `session_id`'s worker on the host `paths` names, and has it prove its key.
///
/// # Errors
///
/// Returns [`Unreached::NotRunning`] when the session has no descriptor here, and
/// [`Unreached::Failed`] when the descriptor cannot be read, its endpoint cannot be reached, or the
/// worker behind it cannot prove the descriptor's key.
pub async fn reach(paths: &EnvironmentPaths, session_id: SessionId) -> Result<Reached, Unreached> {
    let descriptor = kr_ipc::descriptor::read(paths, session_id)
        .map_err(|error| {
            Unreached::Failed(format!(
                "This session's details could not be read: {}",
                Shown::ipc(&error)
            ))
        })?
        .ok_or(Unreached::NotRunning)?;
    let unreachable = |error: &kr_ipc::IpcError| {
        Unreached::Failed(format!(
            "This session could not be reached: {}",
            Shown::ipc(error)
        ))
    };
    let endpoint = kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint)
        .map_err(|error| unreachable(&error))?;
    let build_id =
        crate::connection::build_id().map_err(|error| Unreached::Failed(error.message))?;
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build_id)
        .await
        .map_err(|error| unreachable(&error))?;
    client.verify_worker(&descriptor).await.map_err(|error| {
        Unreached::Failed(format!(
            "This session's worker could not prove who it is: {}",
            Shown::ipc(&error)
        ))
    })?;
    let build = client.acknowledgement().build.clone();
    Ok(Reached {
        client,
        descriptor,
        build,
    })
}

/// Whether `session_id` has a worker's descriptor on the host `paths` names: whether its worker is
/// the one that serves it, rather than the host's archive of a session that has ended.
///
/// # Errors
///
/// Returns why the descriptor could not be read.
pub fn publishes(paths: &EnvironmentPaths, session_id: SessionId) -> Result<bool, String> {
    kr_ipc::descriptor::read(paths, session_id)
        .map(|descriptor| descriptor.is_some())
        .map_err(|error| {
            format!(
                "This session's details could not be read: {}",
                Shown::ipc(&error)
            )
        })
}
