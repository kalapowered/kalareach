//! Starting up, reporting in, and serving until told to stop.
//!
//! The order matters and is not an implementation detail:
//!
//! 1. Generate the per-process signing key. It exists only in this process's memory.
//! 2. Bind the owner-only endpoint workers will use. Binding it before reporting in means that a
//!    worker acting on the descriptor the daemon publishes always finds a listener.
//! 3. Present the startup claim on the daemon's rendezvous endpoint, signed with that key.
//! 4. Serve workers until a termination signal arrives.
//!
//! A host that cannot do step 1, 2 or 3 exits without serving. A host that has done all three is
//! the process the descriptor names, and a worker can prove it with a challenge.

use std::sync::Arc;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::HostPaths;
use kr_plugin_runtime::service::host::{HostConfig, PluginHost};
use kr_plugin_runtime::service::launcher::{
    HostIdentity, LaunchError, LaunchResult, host_endpoint,
};
use kr_protocol::frame::StreamKind;

use crate::options::Options;

/// Runs the plugin host until it is told to stop.
///
/// # Errors
///
/// Returns the startup failure. A host that could not report in never served anything, which is
/// what keeps a worker from talking to a process the daemon did not start.
pub async fn run(options: Options) -> LaunchResult<()> {
    let paths = HostPaths::new(&options.runtime_dir, &options.state_dir);
    let environment = paths.environment(options.environment_id());
    environment.create()?;

    let identity = HostIdentity::generate(options.environment_id())?;
    let endpoint = host_endpoint(&environment)?;

    // The endpoint is the host's to own, and a previous incarnation's socket file may still be
    // sitting there. Binding is what proves this process holds it.
    let listener = Listener::bind(&endpoint)?;
    drop(listener);

    let host = Arc::new(PluginHost::new(
        identity,
        HostConfig {
            endpoint: endpoint.clone(),
            packages_root: options.packages_dir.clone(),
            cache_root: environment.state_dir().join(Options::CACHE_DIRECTORY),
        },
    )?);

    report_in(&host, &options, &endpoint.as_text()).await?;

    host.serve(termination()).await
}

/// Presents the startup claim on the control daemon's rendezvous endpoint.
async fn report_in(host: &Arc<PluginHost>, options: &Options, endpoint: &str) -> LaunchResult<()> {
    let rendezvous = kr_ipc::paths::Endpoint::from_path(&options.rendezvous)?;
    let connection = Connection::connect(&rendezvous).await?;
    let (_reader, mut writer) = split(connection, StreamKind::Control);
    let claim = host
        .identity()
        .rendezvous(options.reservation_id(), endpoint)?;
    writer
        .write_message(&claim)
        .await
        .map_err(LaunchError::Endpoint)?;
    Ok(())
}

/// Resolves when the operating system asks this process to stop.
async fn termination() {
    #[cfg(unix)]
    {
        let mut terminate =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                // A host that cannot install a handler still stops when it is killed; it just does not
                // get to close its bindings first.
                Err(_error) => return core::future::pending().await,
            };
        tokio::select! {
            _ = terminate.recv() => {}
            outcome = tokio::signal::ctrl_c() => {
                let _ = outcome;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cache_lives_under_the_state_directory() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let cache = environment.state_dir().join(Options::CACHE_DIRECTORY);
        assert!(cache.starts_with(environment.state_dir()));
        // The runtime directory is for sockets and descriptors; compiled artefacts are state and
        // outlive a boot.
        assert!(!cache.starts_with(environment.runtime_dir()));
    }

    #[tokio::test]
    async fn a_host_with_nowhere_to_report_in_does_not_serve() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let options = Options {
            reservation: kr_protocol::scalars::Uuid::from_bytes([1; 16]),
            environment: host.environment_id().get(),
            rendezvous: environment
                .runtime_dir()
                .join("absent.sock")
                .display()
                .to_string(),
            runtime_dir: environment.runtime_root().to_path_buf(),
            state_dir: environment.state_root().to_path_buf(),
            packages_dir: environment.state_dir().join("packages"),
        };
        let error = run(options)
            .await
            .expect_err("there is nothing to report to");
        // The endpoint was bound and then given up, so nothing is left listening for a worker that
        // read a stale descriptor.
        assert!(matches!(error, LaunchError::Endpoint(_)), "{error}");
    }
}
