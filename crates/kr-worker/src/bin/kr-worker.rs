//! The KalaReach session worker process.
//!
//! A worker is started by the platform's own service manager, not by the control daemon, so that a
//! daemon restart never touches a running shell. What the job definition hands it is deliberately
//! thin and entirely non-secret: which reservation it was started for, which session that
//! reservation allocated, and where the host's directories are. Everything else — the shell to
//! launch, the creator's environment, the controller's public key — arrives over the rendezvous
//! channel, after this process has proved with a signature that it is the worker the controller
//! reserved.
//!
//! ```text
//! job definition ──▶ worker ──rendezvous──▶ controller
//!                          ◀──launch spec──
//!                    open pty, launch shell, bind endpoint
//!                          ───worker ready──▶  (controller publishes the descriptor)
//! ```

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use kr_ipc::endpoint::{Connection, Listener};
use kr_ipc::framed::split;
use kr_ipc::paths::{Endpoint, HostPaths};
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::ids::{BuildId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::local::{LocalClientKind, LocalHello};
use kr_protocol::scalars::Uuid;
use kr_protocol::session::{ClosureReason, DisplayNumber, SessionCreateParams, ShellMode};
use kr_protocol::worker::{ReservationId, WorkerLaunchSpec, WorkerReady};
use kr_shell_integration::host::HostError;
use kr_shell_integration::host::endpoint::HostEndpoint;
use kr_shell_integration::host::package::{PackageFault, ShellPackage, StartupMode};
use kr_worker::environment::{ExecutionContext, build as build_environment};
use kr_worker::history::DEFAULT_RESIDENT_BYTES;
use kr_worker::output::DEFAULT_SEND_QUEUE_BYTES;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::{CLOSURE_NOTICE_TIMEOUT, start_or_record};
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::SessionConfig;

/// The release this build reports as its terminal program version.
const RELEASE: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "kr-worker",
    version,
    about = "The KalaReach session worker. Started by the host's service manager, never by hand."
)]
struct Arguments {
    /// The spawn reservation this worker was started for.
    #[arg(long)]
    reservation: Uuid,
    /// The session the reservation allocated.
    #[arg(long)]
    session: Uuid,
    /// The environment the session belongs to.
    #[arg(long)]
    environment: Uuid,
    /// The local alias, which also names this worker's endpoint.
    #[arg(long)]
    display: u64,
    /// The controller's owner-only rendezvous socket.
    #[arg(long)]
    rendezvous: std::path::PathBuf,
    /// The per-user runtime directory.
    #[arg(long)]
    runtime_dir: std::path::PathBuf,
    /// The per-user state directory.
    #[arg(long)]
    state_dir: std::path::PathBuf,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("kr-worker: could not start: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(arguments)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kr-worker: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    // A worker's lifetime must not depend on whatever started it. Becoming a session leader is
    // what detaches it: it leaves the launcher's session and its controlling terminal, so nothing
    // aimed at that terminal or that session reaches this process or the shell it will start.
    // A worker a service manager already placed in its own session is one already, and says so.
    detach_from_the_launcher();
    let session_id = SessionId::new(arguments.session);
    let environment_id = EnvironmentId::new(arguments.environment);
    let paths = HostPaths::new(&arguments.runtime_dir, &arguments.state_dir)?;
    let environment = paths.environment(environment_id);
    environment.create()?;

    let boot_identity = kr_ipc::identity::boot_identity()?;
    let process_identity = kr_ipc::identity::current_process_start_identity()?;
    // The private half of this key never leaves this process: not to disk, not into an argument
    // vector, not into an environment variable. It dies with the worker.
    let identity = Arc::new(WorkerIdentity::generate(
        session_id,
        SessionEpoch::V1,
        boot_identity.clone(),
        process_identity,
        PROTOCOL_VERSION,
    )?);

    let rendezvous = Endpoint::from_path(&arguments.rendezvous)?;
    let connection = Connection::connect(&rendezvous).await?;
    let (mut reader, mut writer) = split(connection, StreamKind::Control);
    writer
        .write_message(&ControlFrame::Hello(LocalHello {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: build_id(),
            client: LocalClientKind::Worker,
            capabilities: kr_protocol::scalars::CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits::default(),
        }))
        .await?;
    let acknowledgement: ControlFrame = reader.read_message().await?;
    if !matches!(acknowledgement, ControlFrame::HelloAck(_)) {
        return Err("the controller did not acknowledge the worker's hello".into());
    }

    let rendezvous_claim = identity.rendezvous(ReservationId::new(arguments.reservation))?;
    writer
        .write_message(&ControlFrame::Rendezvous(rendezvous_claim))
        .await?;
    let specification: ControlFrame = reader.read_message().await?;
    let ControlFrame::LaunchSpec(specification) = specification else {
        return Err("the controller did not send a launch specification".into());
    };
    // The identity this process signed with came from its job definition. A specification that
    // disagrees with it would leave the signature, the descriptor and the running session
    // describing different things.
    if specification.session_id != session_id
        || specification.environment_id != environment_id
        || specification.session_epoch != SessionEpoch::V1
        || specification.display_number.get() != arguments.display
    {
        let error = ProtocolError::new(
            ErrorCode::InvalidArgument,
            "the launch specification does not match the reservation this worker was started for",
        );
        writer
            .write_message(&ControlFrame::WorkerFailed(error))
            .await?;
        return Err("the launch specification does not match the reservation".into());
    }
    // Managed mode launches a KalaReach-qualified package: the exact binary its reader patch was
    // built into, with the flags that package declares. A shell no package qualifies is named
    // rather than silently substituted.
    let package = match managed_package(&specification) {
        Ok(package) => package,
        Err(fault) => {
            writer
                .write_message(&ControlFrame::WorkerFailed(fault.to_protocol_error()))
                .await?;
            return Err(Box::new(fault));
        }
    };

    let display_number = DisplayNumber::new(arguments.display);
    let endpoint = environment.worker_endpoint(display_number)?;
    let listener = Listener::bind(&endpoint)?;

    // The bridge endpoint is bound before the shell starts: its address and one-time secret travel
    // to the shell in its own environment, and a shell that started first would have neither.
    let bridge = match package.as_ref().map(|package| {
        bridge_endpoint(&environment, specification.session_id).map(|endpoint| (package, endpoint))
    }) {
        Some(Ok(bound)) => Some(bound),
        Some(Err(error)) => {
            writer
                .write_message(&ControlFrame::WorkerFailed(error.to_protocol_error()))
                .await?;
            return Err(Box::new(error));
        }
        None => None,
    };

    let config = session_config(
        &specification,
        &environment,
        display_number,
        package.as_ref(),
        bridge.as_ref().map(|(_, endpoint)| endpoint),
        &endpoint,
    );
    // The machine's own continuous clock, which is the clock the daemon expresses a forwarded
    // authority deadline on. Every boundary in this process that decides whether authority has
    // run out reads it.
    let shared_clock: std::sync::Arc<dyn kr_ipc::clock::SharedClock> =
        std::sync::Arc::new(kr_ipc::clock::SystemSharedClock);
    // The palette the create request named, or the profile default when it named none. It is
    // applied before the shell runs, because a session's palette is fixed at creation.
    let palette = kr_worker::snapshot::PaletteChoice::from_request(specification.create.palette.0);
    let runtime = match start_or_record(config, palette, std::sync::Arc::clone(&shared_clock)) {
        Ok(runtime) => runtime,
        Err(failure) => {
            let error = ProtocolError::new(failure.error.code(), failure.error.to_string());
            writer
                .write_message(&ControlFrame::WorkerFailed(error))
                .await?;
            return Err(Box::new(failure.error));
        }
    };

    // The driver and the endpoint go in together, before the ready report: the first thing the
    // reader says about itself must have somewhere to go.
    let bridge_server = bridge.map(|(package, endpoint)| {
        let (expectation, driver) = {
            let session = runtime.session();
            let root_process = session
                .root_identity()
                .expect("a live session has a root process");
            let lease = kr_shell_integration::contract::fence::LeaseView::unheld(
                kr_protocol::ids::InputLeaseEpoch::new(0),
            );
            let driver = kr_worker::fence::FenceDriver::new(
                specification.session_id,
                lease,
                Arc::new(kr_transport::clock::SystemContinuousClock::new()),
            );
            let identity = package.identity();
            let expectation = kr_shell_integration::contract::transport::WorkerExpectation {
                session_id: specification.session_id,
                root_process,
                supported_editor_abis: vec![identity.editor_abi.clone()],
                supported_integration_versions: vec![identity.integration_version.clone()],
                // The whole record this build wrote. A connection that passes every identity check
                // and then describes a different executable, upstream version, patch set or module
                // tree is not the package this session launched.
                launched_package: Some(package.declaration()),
                already_registered: false,
                gesture: kr_shell_integration::contract::events::EofGesture::default(),
            };
            (expectation, driver)
        };
        runtime.session().install_fence(driver);
        let server = kr_worker::fence::bridge::BridgeServer::new(
            Arc::clone(&runtime),
            endpoint,
            expectation,
        );
        tokio::spawn(server.serve())
    });

    // The endpoint serves from here, before anything is waited for. A session that is still being
    // created is reachable on it: section 7 lets a native startup prompt read input in its own
    // non-primary context while the profiles run, and a worker that only began serving afterwards
    // would be the deadlock that paragraph forbids.
    let service = Arc::new(WorkerService::new(
        Arc::clone(&runtime),
        identity,
        endpoint.clone(),
        ServiceBinding {
            environment_id,
            boot_identity,
            controller_public_key: specification.controller_public_key,
            controller_generation: specification.controller_generation,
            build_id: build_id(),
            journal_path: Some(environment.journal_database(specification.session_id)),
        },
    )?);
    // The backends an integrated invocation is given before it runs. The connectors they are
    // established from arrive with the installation's hand-over; until one does, every resolve is
    // answered as a bypass, and the invocation runs as typed.
    let _command_backends =
        service.install_command_backends(kr_worker::broker::commands::CommandBackendsConfig {
            session_id,
            environment_id,
            os_user: kr_worker::desktop::os_user(),
            runtime_dir: environment.runtime_dir().to_path_buf(),
            sources: Arc::new(kr_worker::broker::connectors::ConnectorSources::new()),
            launcher: installed_launcher(),
        });
    let serving = tokio::spawn(Arc::clone(&service).serve(listener));

    // Section 7 paragraph 4: a managed create succeeds only after full post-profile qualification.
    // The shell is running and its startup files are executing; until the integration reports its
    // hooks live, this session is authenticated rather than qualified, and it reports nothing
    // ready. A failure here closes the session that was being created and records why.
    if bridge_server.is_some()
        && let Err(error) = await_qualification(&runtime, QUALIFICATION_DEADLINE).await
    {
        // The failure is reported if it can be, and the session is closed either way: a create that
        // could not deliver the managed contract leaves a closure record rather than a shell nobody
        // is going to use.
        let _ = writer
            .write_message(&ControlFrame::WorkerFailed(error.clone()))
            .await;
        runtime.close(ClosureReason::RootLaunchFailed).1.release();
        let _ = runtime.wait_closed().await;
        finish(&runtime, serving, bridge_server).await;
        return Err(error.message.into());
    }

    let ready = {
        let session = runtime.session();
        WorkerReady {
            session_id,
            endpoint: endpoint.as_text(),
            root_process: session
                .root_identity()
                .ok_or("the root shell has no process identity")?,
            // The executable this session actually launched, which for a managed session is the
            // package's binary rather than whatever the request named.
            shell_path: session.config().shell.program.clone(),
            dimensions: session.geometry().dimensions,
        }
    };
    // A ready report that does not arrive must not end the session. The shell is running, the
    // endpoint is bound, and the controller recovers by verifying this worker with a challenge
    // rather than by starting a second one.
    let ready_reported = writer
        .write_message(&ControlFrame::WorkerReady(ready))
        .await
        .is_ok();
    if !ready_reported {
        eprintln!(
            "kr-worker: the controller did not receive the ready report; the session continues and is recoverable by challenge"
        );
    }
    // The rendezvous is finished. Every later conversation with a controller happens on this
    // worker's own endpoint, where it presents a generation token like any other client.
    drop(writer);
    drop(reader);

    // The worker exists for its session. When the session closes, the last record is written, every
    // attachment is told, and the process ends; nothing here restarts a shell.
    let _record = runtime.wait_closed().await;
    finish(&runtime, serving, bridge_server).await;
    Ok(())
}

/// Ends the work of a worker whose session has closed.
///
/// The root integration's endpoint goes with its shell. Each attachment is sent how the session
/// closed, behind the output it was still owed, and one the session admitted that has not
/// subscribed yet is owed it until it does or leaves. The process ends only once every one has it,
/// or once [`CLOSURE_NOTICE_TIMEOUT`] has passed for a client that has stopped reading. A client
/// that has gone holds nothing up. Ending first would take the connections with it, and every
/// attachment would learn only that its connection had stopped.
///
/// The endpoint goes on answering while this waits, so a client that asks how the session ended is
/// told by the worker that ended it. A connection it accepts cannot attach to a closed session, and
/// every attachment the session had was counted when it closed; the only notice still handed out
/// is one such an attachment asks for again by subscribing, and the wait counts that too. The
/// accept loop stops once nothing is owed, and is awaited, so no connection is taken after that.
async fn finish(
    runtime: &Arc<kr_worker::runtime::SessionRuntime>,
    serving: tokio::task::JoinHandle<kr_worker::Result<()>>,
    bridge_server: Option<tokio::task::JoinHandle<()>>,
) {
    if let Some(server) = bridge_server {
        server.abort();
    }
    if !runtime.closure_delivered(CLOSURE_NOTICE_TIMEOUT).await {
        eprintln!(
            "kr-worker: an attachment had not been sent the closure after {} seconds, and the \
             worker ends without it",
            CLOSURE_NOTICE_TIMEOUT.as_secs()
        );
    }
    serving.abort();
    let _ = serving.await;
}

/// How long a managed session waits for the user's startup files to finish.
///
/// It is a bound rather than a latency: the integration reports its hooks live the moment the
/// startup files are done, and this is only what stops a profile that blocks forever from leaving
/// a create request unanswered.
const QUALIFICATION_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Waits until the root integration has qualified, or says why it did not.
///
/// Waiting is on the phase rather than on a timer: the session is asked what it is, and a session
/// that has closed in the meantime answers immediately rather than holding this for the bound.
async fn await_qualification(
    runtime: &Arc<kr_worker::runtime::SessionRuntime>,
    within: std::time::Duration,
) -> std::result::Result<(), ProtocolError> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        {
            let session = runtime.session();
            if let Some(driver) = session.fence() {
                if driver.phase().reports_ready() {
                    return Ok(());
                }
                if !driver.phase().consumes_eligible_eof() {
                    return Err(ProtocolError::new(
                        ErrorCode::ShellIntegrationUnsupported,
                        "the root shell was replaced by something this build cannot qualify, so \
                         this session claims none of the managed contract",
                    ));
                }
            }
            if session.state() != kr_protocol::session::SessionState::Live {
                return Err(ProtocolError::new(
                    ErrorCode::ShellIntegrationUnsupported,
                    "the session ended before its root integration qualified",
                ));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ProtocolError::new(
                ErrorCode::ShellIntegrationUnsupported,
                format!(
                    "the root integration did not qualify within {} seconds; the session is closed \
                     and an explicit compatibility retry is a new create request",
                    within.as_secs()
                ),
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Resolves the qualified package a managed session launches.
///
/// A `native_compat` session resolves none: it runs the selected stock shell, which cannot claim
/// the managed contract and does not pretend to.
fn managed_package(specification: &WorkerLaunchSpec) -> Result<Option<ShellPackage>, PackageFault> {
    if specification.create.shell_mode != ShellMode::Managed {
        return Ok(None);
    }
    // The controller resolved this create's package against its own configured root, and refused
    // the create where it could not. Reading that exact directory is what makes the session run
    // the package it was admitted against: a worker whose own environment names a different root
    // would otherwise resolve a second time and could launch a different build, or a different
    // shell entirely.
    let directory =
        specification
            .shell_package
            .as_ref()
            .ok_or_else(|| PackageFault::Unreadable {
                path: String::new(),
                detail: "this managed launch names no shell package, so there is nothing to launch"
                    .to_owned(),
            })?;
    ShellPackage::read(std::path::Path::new(directory)).map(Some)
}

/// Returns this installation's launcher, the `kr-hook` beside this executable in every packaged
/// layout, where it is there.
fn installed_launcher() -> Option<std::path::PathBuf> {
    let beside = std::env::current_exe()
        .ok()?
        .parent()?
        .join(if cfg!(windows) {
            "kr-hook.exe"
        } else {
            "kr-hook"
        });
    beside.is_file().then_some(beside)
}

/// Binds this session's root-integration endpoint inside its own owner-only directory.
fn bridge_endpoint(
    environment: &kr_ipc::paths::EnvironmentPaths,
    session_id: SessionId,
) -> Result<HostEndpoint, HostError> {
    // Inside the session's own directory in the environment's runtime tree, which is owner-only
    // and on the internal disk: the socket lives there rather than anywhere a shell chose.
    HostEndpoint::open_for_session(
        environment.runtime_root(),
        environment.runtime_dir(),
        session_id,
    )
}

fn session_config(
    specification: &WorkerLaunchSpec,
    environment: &kr_ipc::paths::EnvironmentPaths,
    display_number: DisplayNumber,
    package: Option<&ShellPackage>,
    bridge: Option<&HostEndpoint>,
    worker_endpoint: &kr_ipc::paths::Endpoint,
) -> SessionConfig {
    let create: &SessionCreateParams = &specification.create;
    // A managed session launches the package's own binary. Everything else launches the shell the
    // request named, or the one this host is configured to use, or the platform's own. Nothing is
    // substituted silently: the session reports the executable it launched.
    let shell_path = package.map_or_else(
        || {
            create
                .shell
                .as_ref()
                .cloned()
                .or_else(configured_shell)
                .unwrap_or_else(default_shell)
        },
        |package| package.executable().display().to_string(),
    );
    // The context a worker of this profile runs in, resolved from the login session the service
    // manager placed it in. A headless worker takes none of it, because it must outlive that
    // login session.
    let context = ExecutionContext::resolve(create.worker_profile);
    let desktop = context
        .desktop
        .clone()
        .unwrap_or_else(kr_protocol::identity::DesktopBinding::none);
    let launch_environment = build_environment(
        &create.environment_snapshot,
        &context,
        &shell_path,
        &specification.release,
        specification.session_id,
    );
    let mut environment_pairs = launch_environment.to_pairs();
    if let Some(bridge) = bridge {
        // The two reserved bootstrap values, and the only two. They come from the worker, they name
        // this session's own endpoint, and the integration removes them from the exported
        // environment as soon as the handshake succeeds, so nothing a child process starts
        // inherits them.
        environment_pairs.extend(
            bridge
                .bootstrap()
                .exported_variables()
                .into_iter()
                .map(|(name, value)| (name.to_owned(), value)),
        );
        environment_pairs.sort();
    }
    let dimensions = create
        .dimensions
        .as_ref()
        .copied()
        .unwrap_or(kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS);
    let cwd = create
        .cwd
        .as_ref()
        .cloned()
        .unwrap_or_else(|| "/".to_owned());
    SessionConfig {
        session_id: specification.session_id,
        session_epoch: specification.session_epoch,
        environment_id: specification.environment_id,
        display_number,
        shell: ShellCommand {
            // A package declares the mechanisms its interactive root shell is launched with; which
            // startup files that shell reads is the session's own decision, so the profile decides
            // it and the package answers for that mode.
            arguments: package.map_or_else(
                || interactive_arguments(&shell_path, startup_mode(&create.launch_profile)),
                |package| package.arguments(startup_mode(&create.launch_profile)),
            ),
            program: shell_path,
            cwd,
            environment: environment_pairs,
        },
        shell_mode: create.shell_mode,
        launch_profile: create.launch_profile.clone(),
        worker_profile: create.worker_profile,
        desktop,
        dimensions,
        journal_path: Some(environment.journal_database(specification.session_id)),
        spool_directory: Some(environment.session_spool(specification.session_id)),
        worker_endpoint: Some(worker_endpoint.as_text()),
        send_queue_bytes: DEFAULT_SEND_QUEUE_BYTES,
        resident_bytes: DEFAULT_RESIDENT_BYTES,
    }
}

/// Returns the startup a session's profile asks a packaged shell for.
///
/// Section 7's defaults are the platform's: login startup on macOS, interactive only elsewhere. A
/// profile that names one overrides that, which is how a Linux session asks for login startup and
/// a macOS session asks not to have it.
const fn startup_mode(profile: &kr_protocol::session::LaunchProfile) -> StartupMode {
    match profile.startup {
        kr_protocol::session::ShellStartup::HostDefault => StartupMode::for_host(),
        kr_protocol::session::ShellStartup::Interactive => StartupMode::Interactive,
        kr_protocol::session::ShellStartup::Login => StartupMode::Login,
    }
}

/// The arguments that make a stock shell an interactive session root shell.
///
/// A `native_compat` session runs the selected stock shell as an interactive shell. It is never a
/// non-interactive script invocation turned interactive, and it is never a silently substituted
/// binary: this is the executable the create request named, run the way an interactive login does.
///
/// The arguments belong to the shell, not to the platform. A PowerShell given `-l -i` would treat
/// them as a script path and a parameter and fail; a Bourne-family shell given `-NoLogo` would do
/// the same in reverse.
fn interactive_arguments(shell_path: &str, mode: StartupMode) -> Vec<String> {
    let name = std::path::Path::new(shell_path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(shell_path)
        .to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    let login = mode == StartupMode::Login;
    match name {
        "fish" => {
            let mut arguments = Vec::new();
            if login {
                arguments.push("--login".to_owned());
            }
            arguments.push("--interactive".to_owned());
            arguments
        }
        // PowerShell reads its profile whichever way it starts, and has no login form to ask for.
        "pwsh" | "powershell" => vec!["-NoLogo".to_owned(), "-NoExit".to_owned()],
        "cmd" => vec!["/K".to_owned()],
        // A login shell reads the profile that sets the user's own path and prompt, which is what
        // makes the first prompt look like the one they get anywhere else. Whether it does is the
        // session's profile to decide, exactly as it is for a packaged shell.
        _ => {
            let mut arguments = Vec::new();
            if login {
                arguments.push("-l".to_owned());
            }
            arguments.push("-i".to_owned());
            arguments
        }
    }
}

/// The shell this host is configured to launch when a request names none.
///
/// The operating system's own record of the user's shell is what a login uses, so it is what a
/// session uses too. A value that names nothing runnable is ignored rather than launched.
fn configured_shell() -> Option<String> {
    let configured = std::env::var("SHELL").ok()?;
    let configured = configured.trim();
    (!configured.is_empty() && std::path::Path::new(configured).is_file())
        .then(|| configured.to_owned())
}

/// The shell a platform falls back to when nothing else names one.
fn default_shell() -> String {
    #[cfg(target_vendor = "apple")]
    {
        "/bin/zsh".to_owned()
    }
    #[cfg(all(unix, not(target_vendor = "apple")))]
    {
        "/bin/bash".to_owned()
    }
    #[cfg(not(unix))]
    {
        // Windows has no `/bin`. PowerShell is the shell a Windows user gets, and `cmd` is the
        // fallback when it is not installed.
        std::env::var("ComSpec").unwrap_or_else(|_| "powershell.exe".to_owned())
    }
}

fn build_id() -> BuildId {
    BuildId::new(format!("kr-worker/{RELEASE}")).expect("the build identifier is well formed")
}

/// Leaves the session and controlling terminal of whatever started this worker.
///
/// `setsid` fails when the caller already leads a process group, which is exactly the case when a
/// service manager has already put this worker in its own session. That failure means the goal is
/// already met, so it is not one.
#[cfg(unix)]
fn detach_from_the_launcher() {
    let _ = rustix::process::setsid();
}

/// Leaves the session of whatever started this worker.
///
/// Windows has no sessions to leave. A worker is kept out of the control daemon's job object by
/// the way the daemon starts it, which is where that decision belongs.
#[cfg(not(unix))]
const fn detach_from_the_launcher() {}

#[cfg(test)]
mod tests {
    use kr_protocol::session::{LaunchProfile, ShellStartup};

    use super::{StartupMode, startup_mode};

    /// KR-REQ-23.38: the profile decides which startup files the root shell reads.
    #[test]
    fn a_profile_that_names_a_startup_overrides_this_platforms_default() {
        let profile = |startup| LaunchProfile {
            startup,
            ..LaunchProfile::default()
        };
        assert_eq!(
            startup_mode(&profile(ShellStartup::HostDefault)),
            StartupMode::for_host(),
            "nothing asked, so section 7's platform default stands"
        );
        assert_eq!(
            startup_mode(&profile(ShellStartup::Interactive)),
            StartupMode::Interactive
        );
        assert_eq!(
            startup_mode(&profile(ShellStartup::Login)),
            StartupMode::Login
        );
    }

    /// KR-REQ-23.38: a stock shell reads the startup files the profile asks for, like a packaged
    /// one.
    #[test]
    fn a_stock_shell_takes_the_profiles_startup_as_well() {
        use super::interactive_arguments;

        assert_eq!(
            interactive_arguments("/bin/zsh", StartupMode::Interactive),
            vec!["-i".to_owned()]
        );
        assert_eq!(
            interactive_arguments("/bin/zsh", StartupMode::Login),
            vec!["-l".to_owned(), "-i".to_owned()]
        );
        assert_eq!(
            interactive_arguments("/usr/local/bin/fish", StartupMode::Interactive),
            vec!["--interactive".to_owned()]
        );
        assert_eq!(
            interactive_arguments("/usr/local/bin/fish", StartupMode::Login),
            vec!["--login".to_owned(), "--interactive".to_owned()]
        );
        // The arguments belong to the shell: PowerShell has no login form to ask for and would
        // read a login flag as a script path.
        assert_eq!(
            interactive_arguments("pwsh.exe", StartupMode::Login),
            vec!["-NoLogo".to_owned(), "-NoExit".to_owned()]
        );
    }
}
