//! Starting up, reporting in, and serving until told to stop.
//!
//! The order matters and is not an implementation detail:
//!
//! 1. Connect to the daemon's rendezvous endpoint, and keep the connection. A host that cannot
//!    start has nowhere else to say so: the launcher that started it is waiting on this
//!    connection, and a start that fails before it exists is a start nobody hears about.
//! 2. Generate the per-process signing key. It exists only in this process's memory.
//! 3. Bind the owner-only endpoint workers will use, and hold it. Binding it before reporting in
//!    means a worker acting on the descriptor the daemon publishes always finds a listener; holding
//!    it through the report means there is no moment between claiming the endpoint and answering on
//!    it during which another process could take it. The endpoint of the fourth protocol is bound
//!    beside it, and a host that cannot bind that one serves the third protocol only.
//! 4. Present the startup claim on the connection of step 1, signed with that key, and wait for the
//!    daemon to say it accepted the claim. A host that started serving before that would be
//!    answering workers as a process the daemon might still refuse.
//! 5. Serve workers on the listeners from step 3 until a termination signal arrives.
//!
//! A host that cannot do step 2 or 3 says why on the connection of step 1, waits for the launcher
//! to take it and close, and exits without serving; one that cannot do step 1 or 4 exits without
//! serving. A host that has done all of them is the process the descriptor names, and a worker can
//! prove it with a challenge.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::paths::HostPaths;
use kr_plugin_runtime::service::host::{HostConfig, PluginHost};
use kr_plugin_service::launcher::{HostIdentity, LaunchError, LaunchResult, host_endpoint};
use kr_plugin_service::protocol::{
    HostProtocol, HostStartFailure, RendezvousAccepted, failure_reason_line,
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
    let rendezvous = kr_ipc::paths::Endpoint::from_path(&options.rendezvous)?;
    let connection = Connection::connect(&rendezvous).await?;
    let (mut reader, mut writer) = split(connection, StreamKind::Control);
    let prepared = match prepare(&options) {
        Ok(prepared) => prepared,
        Err(failure) => {
            tell_the_launcher(&mut reader, &mut writer, &options, &failure).await;
            return Err(failure.error);
        }
    };
    report_in(
        &mut reader,
        &mut writer,
        &prepared.host,
        &options,
        &prepared.endpoint,
    )
    .await?;
    // One signal stops both endpoints.
    let (stop, stopped) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        termination().await;
        let _ = stop.send(true);
    });
    let third = Arc::clone(&prepared.host).serve_on(
        prepared.listener,
        HostProtocol::V3,
        stopped_by(stopped.clone()),
    );
    let fourth = async {
        match prepared.listener4 {
            Some(listener) => {
                prepared
                    .host
                    .serve_on(listener, HostProtocol::V4, stopped_by(stopped))
                    .await
            }
            None => Ok(()),
        }
    };
    tokio::try_join!(third, fourth).map(|((), ())| ())
}

/// Resolves when the signal that stops the host has arrived.
async fn stopped_by(mut stopped: tokio::sync::watch::Receiver<bool>) {
    let _ = stopped.wait_for(|stop| *stop).await;
}

/// What a start has made when it is ready to report in.
struct Prepared {
    /// The endpoint workers use, held from the bind until the host serves on it.
    listener: Listener,
    /// The endpoint of the fourth protocol, where it could be bound.
    listener4: Option<Listener>,
    host: Arc<PluginHost>,
    /// The endpoint's text, as the claim names it.
    endpoint: String,
}

/// The step of a start that failed.
#[derive(Clone, Copy, Debug)]
enum Step {
    Paths,
    Environment,
    Identity,
    Endpoint,
    Host,
}

impl Step {
    const fn word(self) -> &'static str {
        match self {
            Self::Paths => "paths",
            Self::Environment => "environment",
            Self::Identity => "identity",
            Self::Endpoint => "endpoint",
            Self::Host => "host",
        }
    }
}

/// A start that failed: the error the process ends with and the one line the launcher is told.
struct StartFailure {
    error: LaunchError,
    reason: String,
}

impl StartFailure {
    /// A failure of `step` other than the bind: only a bind says "listen".
    fn at(step: Step, error: impl Into<LaunchError>) -> Box<Self> {
        let error = error.into();
        let reason = failure_reason_line(&format!(
            "the plugin host could not start: {}: {error}",
            step.word()
        ));
        Box::new(Self { error, reason })
    }

    /// A bind that failed, which says what stands at the endpoint when the refusal is typed.
    fn bind(endpoint: &str, error: kr_ipc::IpcError) -> Box<Self> {
        let reason = match &error {
            kr_ipc::IpcError::Listen { endpoint, refusal } => failure_reason_line(&format!(
                "the plugin host could not listen on {}",
                refusal.said(endpoint)
            )),
            other => failure_reason_line(&format!(
                "the plugin host could not listen on {endpoint}: {other}"
            )),
        };
        Box::new(Self {
            error: error.into(),
            reason,
        })
    }
}

/// Does every step of a start that does not need the daemon: the paths, the environment, the
/// identity, the endpoint, the bind and the service, in that order.
fn prepare(options: &Options) -> Result<Prepared, Box<StartFailure>> {
    // The roots are resolved rather than taken as given: a relative path here would be resolved
    // against whatever directory this process was started in, which is not a directory it has any
    // claim on.
    let paths = HostPaths::new(&options.runtime_dir, &options.state_dir)
        .map_err(|error| StartFailure::at(Step::Paths, error))?;
    let environment = paths.environment(options.environment_id());
    environment
        .create()
        .map_err(|error| StartFailure::at(Step::Environment, error))?;

    let identity = HostIdentity::generate(options.environment_id())
        .map_err(|error| StartFailure::at(Step::Identity, error))?;
    let endpoint = host_endpoint(&environment, &HostProtocol::V3)
        .map_err(|error| StartFailure::at(Step::Endpoint, error))?;

    // The endpoint is the host's to own, and a previous incarnation's socket file may still be
    // sitting there. Binding is what proves this process holds it, and holding the listener from
    // here until `serve_on` is what keeps that proof true: a bind, a release and a second bind
    // would let another launch win the endpoint between them, and the descriptor the daemon
    // published would name the process that lost.
    let listener = Listener::bind(&endpoint)
        .map_err(|error| StartFailure::bind(&endpoint.as_text(), error))?;
    // A host that cannot bind the endpoint of the fourth protocol still serves the third: the
    // daemon publishes a descriptor of the fourth only for a host that answers there.
    let listener4 = host_endpoint(&environment, &HostProtocol::V4)
        .map_err(|error| error.to_string())
        .and_then(|endpoint4| Listener::bind(&endpoint4).map_err(|error| error.to_string()))
        .map_err(|reason| {
            eprintln!(
                "kr-plugin-host: serving protocol 3 only, because the endpoint of protocol 4 could not be bound: {reason}"
            );
        })
        .ok();

    let config = HostConfig {
        endpoint: endpoint.clone(),
        packages_root: options.packages_dir.clone(),
        cache_root: environment.state_dir().join(Options::CACHE_DIRECTORY),
    };
    #[cfg(feature = "testing")]
    let host = if options.hold_epoch {
        PluginHost::new_with_epoch_held(identity, config)
    } else {
        PluginHost::new(identity, config)
    };
    #[cfg(not(feature = "testing"))]
    let host = PluginHost::new(identity, config);
    let host = Arc::new(host.map_err(|error| StartFailure::at(Step::Host, error))?);
    Ok(Prepared {
        listener,
        listener4,
        host,
        endpoint: endpoint.as_text(),
    })
}

/// How long the launcher is given to take a failure and then to close the connection it took it
/// on, the two together.
///
/// A host that exited as soon as it had written would be gone before a launcher that was slow to
/// accept had read, and the launcher would hear nothing; one that waited for ever would hold a
/// process that has nothing to serve.
const FAILURE_HANDOFF: Duration = Duration::from_secs(5);

/// How a failure's handoff ended.
#[derive(Debug, PartialEq, Eq)]
enum Handoff {
    /// The launcher took the failure and closed the connection.
    Closed,
    /// The write or the close did not happen within the bound, or the write failed.
    GaveUp,
}

/// Runs `write` and then `close` inside one bound that starts now: a write that takes part of the
/// bound leaves the close what is left of it, so the two never hold the host for more than `bound`.
async fn hand_off<E>(
    bound: Duration,
    write: impl std::future::Future<Output = Result<(), E>>,
    close: impl std::future::Future,
) -> Handoff {
    let deadline = tokio::time::Instant::now() + bound;
    if !matches!(tokio::time::timeout_at(deadline, write).await, Ok(Ok(()))) {
        return Handoff::GaveUp;
    }
    match tokio::time::timeout_at(deadline, close).await {
        Ok(_) => Handoff::Closed,
        Err(_elapsed) => Handoff::GaveUp,
    }
}

/// Tells the launcher why this host could not start, and waits for it to close the connection.
///
/// A write that does not finish, or a launcher that does not close in time, is given up on: the
/// start has failed either way, and what is left is the launcher's own deadline.
async fn tell_the_launcher(
    reader: &mut FrameReader,
    writer: &mut FrameWriter,
    options: &Options,
    failure: &StartFailure,
) {
    let frame = HostStartFailure {
        reservation_id: options.reservation_id(),
        environment_id: options.environment_id(),
        reason: failure.reason.clone(),
    };
    let _ended = hand_off(
        FAILURE_HANDOFF,
        writer.write_message(&frame),
        reader.read_payload(),
    )
    .await;
}

/// How long the daemon is given to accept this host's claim.
///
/// A daemon that has taken the claim and not answered is a daemon this host cannot serve for, and
/// waiting for ever would leave a process holding an endpoint nobody published.
const ACCEPTANCE_DEADLINE: core::time::Duration = core::time::Duration::from_secs(30);

/// Presents the startup claim on the connection to the daemon's rendezvous endpoint and waits to
/// be accepted.
async fn report_in(
    reader: &mut FrameReader,
    writer: &mut FrameWriter,
    host: &Arc<PluginHost>,
    options: &Options,
    endpoint: &str,
) -> LaunchResult<()> {
    let claim = host
        .identity()
        .rendezvous(options.reservation_id(), endpoint)?;
    writer
        .write_message(&claim)
        .await
        .map_err(LaunchError::Endpoint)?;

    let accepted: RendezvousAccepted =
        match tokio::time::timeout(ACCEPTANCE_DEADLINE, reader.read_message_without_schema()).await
        {
            Ok(message) => message.map_err(LaunchError::Endpoint)?,
            Err(_elapsed) => {
                return Err(LaunchError::NoRendezvous {
                    deadline_ms: u64::try_from(ACCEPTANCE_DEADLINE.as_millis()).unwrap_or(u64::MAX),
                });
            }
        };
    if accepted.reservation_id != options.reservation_id()
        || accepted.environment_id != options.environment_id()
        || accepted.endpoint != endpoint
    {
        return Err(LaunchError::Refused {
            detail: "the daemon accepted a different reservation, environment or endpoint"
                .to_owned(),
        });
    }
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

    /// The host's sentence for every class of refusal, at the longest paths a socket may have on
    /// any platform, is whole and within the bound the launcher holds it to.
    #[test]
    fn every_host_reason_fits_its_bound_at_the_longest_path() {
        use kr_ipc::listen::{ListenRefusal, ListenStep, ObjectKind};
        use kr_plugin_service::protocol::MAX_FAILURE_REASON_BYTES;

        let refusals = [
            ListenRefusal::NotASocket {
                object: ObjectKind::Directory,
            },
            ListenRefusal::Held {
                pid: Some(u32::MAX),
            },
            ListenRefusal::Held { pid: None },
            ListenRefusal::LockHeld,
            ListenRefusal::Unanswered,
            ListenRefusal::NotRemoved { os: i32::MAX },
            ListenRefusal::NameTaken,
            ListenRefusal::Occupied,
            ListenRefusal::Other {
                operation: ListenStep::Permissions,
                os: Some(i32::MAX),
            },
        ];
        for length in [103_usize, 107] {
            let path = format!("/{}", "p".repeat(length - 1));
            for refusal in &refusals {
                let failure = StartFailure::bind(
                    &path,
                    kr_ipc::IpcError::Listen {
                        endpoint: path.clone(),
                        refusal: refusal.clone(),
                    },
                );
                assert_eq!(
                    failure.reason,
                    format!(
                        "the plugin host could not listen on {}",
                        refusal.said(&path)
                    ),
                    "{refusal:?} at {length} bytes is not cut"
                );
                assert!(failure.reason.len() <= MAX_FAILURE_REASON_BYTES);
            }
        }
    }

    /// The write and the close of a failure's hand-over share one bound: a write that takes most
    /// of it leaves the close too little. Each fits the bound alone, and together they do not.
    #[tokio::test]
    async fn the_write_and_the_close_of_a_failure_share_one_bound() {
        let bound = Duration::from_millis(400);
        let after = |wait: u64| tokio::time::sleep(Duration::from_millis(wait));
        let together = hand_off(
            bound,
            async {
                after(250).await;
                Ok::<(), ()>(())
            },
            async { after(250).await },
        )
        .await;
        assert_eq!(
            together,
            Handoff::GaveUp,
            "250 ms and 250 ms are over 400 ms"
        );
        let inside = hand_off(
            bound,
            async {
                after(100).await;
                Ok::<(), ()>(())
            },
            async { after(100).await },
        )
        .await;
        assert_eq!(inside, Handoff::Closed);
        let refused = hand_off(bound, async { Err::<(), ()>(()) }, after(0)).await;
        assert_eq!(
            refused,
            Handoff::GaveUp,
            "a write that failed is not followed by a wait"
        );
    }

    #[tokio::test]
    async fn a_host_with_nowhere_to_report_in_does_not_serve() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let packages = environment.state_dir().join("packages");
        std::fs::create_dir_all(&packages).expect("the packages directory");
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
            packages_dir: packages,
            #[cfg(feature = "testing")]
            hold_epoch: false,
        };
        let error = run(options)
            .await
            .expect_err("there is nothing to report to");
        // The host connects to the rendezvous endpoint before it binds its own, so nothing is
        // left listening for a worker that read a stale descriptor.
        assert!(matches!(error, LaunchError::Endpoint(_)), "{error}");
    }
}
