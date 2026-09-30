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
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::local::{LocalClientKind, LocalHello};
use kr_protocol::scalars::Uuid;
use kr_protocol::session::{ClosureReason, DisplayNumber, SessionCreateParams, ShellMode};
use kr_protocol::worker::{ReservationId, WorkerLaunchSpec, WorkerReady};
use kr_shell_integration::host::HostError;
use kr_shell_integration::host::endpoint::HostEndpoint;
use kr_shell_integration::host::package::{PackageFault, ShellPackage, StartupMode};
use kr_worker::action::time::TimeSources;
use kr_worker::environment::{ExecutionContext, build as build_environment};
use kr_worker::history::DEFAULT_RESIDENT_BYTES;
use kr_worker::output::DEFAULT_SEND_QUEUE_BYTES;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::{CLOSURE_NOTICE_TIMEOUT, start_or_record};
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::SessionConfig;

/// What `--version` says: the release, and the protocol package version this build speaks.
///
/// Two builds of one release can speak different protocol versions, and a client refuses a worker
/// of another one, so the answer names both. A worker of an installed release names that release.
static VERSION: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let release = kr_ipc::install::this_process().map_or(env!("CARGO_PKG_VERSION"), |running| {
        running.stated_release(env!("CARGO_PKG_VERSION"))
    });
    format!(
        "{release} (protocol {})",
        kr_protocol::hello::PACKAGE_VERSION
    )
});

#[derive(Debug, Parser)]
#[command(
    name = "kr-worker",
    version = VERSION.as_str(),
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
    // First: a worker of an installed release holds that release for as long as it runs, which is
    // for as long as its session does, and does not start at all once the release is being removed.
    if let Err(error) = kr_ipc::install::this_process() {
        eprintln!("kr-worker: {error}");
        return ExitCode::FAILURE;
    }
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
    // The host's one reading of UTC in this boot, which the control daemon created before it asked
    // for this worker. A worker maps it and never creates or replaces it; one that finds no usable
    // floor maps nothing and serves no copy of authority that carries a UTC deadline.
    let floor = match kr_ipc::floor::SharedFloor::open(
        &environment.utc_floor_file(),
        environment_id,
        kr_ipc::identity::boot_epoch(&boot_identity)?,
    ) {
        Ok(floor) => Some(Arc::new(floor)),
        Err(unusable) => {
            eprintln!(
                "kr-worker: {unusable}; this session serves no copy of authority that carries a UTC \
                 deadline"
            );
            None
        }
    };
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
            build_id: kr_worker::build_id(),
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
    // The first snapshot of plugin admissions follows the specification, in the parts it
    // announced, before anything else does. It is applied before the shell starts: each admitted
    // package is read and checked here, and the connectors among them are what the shell's first
    // command resolves against.
    let first = read_first_admissions(&mut reader, &specification).await?;
    let admissions = Arc::new(kr_worker::broker::catalogue::Admissions::new());
    let sources = Arc::new(kr_worker::broker::connectors::ConnectorSources::new());
    admissions.apply(&first, &sources);
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
        floor,
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
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity,
                controller_public_key: specification.controller_public_key,
                controller_generation: specification.controller_generation,
                build_id: kr_worker::build_id(),
                journal_path: Some(environment.journal_database(specification.session_id)),
            },
        )?
        .with_plugin_admissions(admissions, Arc::clone(&sources)),
    );
    // The backends an integrated invocation is given before it runs, established from the
    // connectors the admissions carry; every later snapshot replaces them, and a resolve that finds
    // none is answered as a bypass, so the invocation runs as typed.
    let _command_backends =
        service.install_command_backends(kr_worker::broker::commands::CommandBackendsConfig {
            session_id,
            environment_id,
            os_user: kr_worker::desktop::os_user(),
            runtime_dir: environment.runtime_dir().to_path_buf(),
            sources,
            launcher: installed_launcher(),
        });
    let serving = tokio::spawn(Arc::clone(&service).serve(listener));

    // Section 7 paragraph 4: a managed create succeeds only after full post-profile qualification.
    // The shell is running and its startup files are executing; until the integration reports its
    // hooks live, this session is authenticated rather than qualified, and it reports nothing
    // ready. A failure here closes the session that was being created and records why.
    if bridge_server.is_some()
        && let Err(error) = runtime.await_qualification(QUALIFICATION_DEADLINE).await
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

    let ready = ready_report(session_id, &endpoint, &runtime.session())?;
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

/// What this worker reports to the daemon that started it once its root shell is running.
///
/// # Errors
///
/// Returns why not when the root shell has no process identity to report.
fn ready_report(
    session_id: SessionId,
    endpoint: &Endpoint,
    session: &kr_worker::session::Session,
) -> Result<WorkerReady, &'static str> {
    Ok(WorkerReady {
        session_id,
        endpoint: endpoint.as_text(),
        root_process: session
            .root_identity()
            .ok_or("the root shell has no process identity")?,
        // The executable this session actually launched, which for a managed session is the
        // package's binary rather than whatever the request named.
        shell_path: session.config().shell.program.clone(),
        dimensions: session.geometry().dimensions,
        session: Box::new(session.summary()),
    })
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

/// Reads the parts of the first snapshot of plugin admissions a specification announced, each of
/// its frame and in its order.
///
/// # Errors
///
/// Returns an error when a frame is not the next part the specification announced.
async fn read_first_admissions(
    reader: &mut kr_ipc::framed::FrameReader,
    specification: &WorkerLaunchSpec,
) -> Result<Vec<kr_protocol::admission::PluginAdmissions>, Box<dyn std::error::Error>> {
    let header = specification.plugins;
    kr_worker::broker::catalogue::check_header(&header, specification.controller_generation)?;
    let mut parts = Vec::new();
    for expected in 1..=header.parts {
        let frame: ControlFrame = reader.read_message().await?;
        let ControlFrame::PluginAdmissions(part) = frame else {
            return Err(
                "the controller did not send the admissions its specification announced".into(),
            );
        };
        if part.frame != header.frame
            || part.part != expected
            || part.parts != header.parts
            || part.environment_id != specification.environment_id
        {
            return Err("the controller sent admissions other than the ones it announced".into());
        }
        parts.push(*part);
    }
    Ok(parts)
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
///
/// This worker's own release's: a session's launches go through the launcher it was started with,
/// whatever release an update has made current since.
fn installed_launcher() -> Option<std::path::PathBuf> {
    let beside = kr_ipc::install::this_process()
        .ok()?
        .own(kr_ipc::install::Program::Hook);
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
    floor: Option<Arc<kr_ipc::floor::SharedFloor>>,
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
    let mut context = ExecutionContext::resolve(create.worker_profile);
    // The database the session's terminal libraries read. A worker that cannot write it says so
    // and the session reads whatever its host has: the terminal still works, and the worker's log
    // line below says that no private database was selected and why.
    #[cfg(unix)]
    match kr_worker::environment::materialise_terminfo(environment.state_dir()) {
        Ok(directory) => context.terminfo = Some(directory),
        Err(error) => context.terminfo_unavailable = Some(error.to_string()),
    }
    #[cfg(not(unix))]
    {
        context.terminfo_unavailable = Some("this platform has no terminfo library".to_owned());
    }
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
    // The worker's own log says which terminfo database the session reads and what it kept of the
    // creator's, next to the other lines it writes about how it started the session.
    eprintln!(
        "kr-worker: session {}: {}",
        specification.session_id,
        launch_environment.sources.terminfo.describe()
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
        time: floor.map_or_else(TimeSources::system, |floor| {
            TimeSources::system().with_floor(floor)
        }),
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

    /// A worker's ready report carries the worker's own description of its session, which is what
    /// the daemon that started it keeps of the session from then on.
    #[test]
    fn the_ready_report_carries_the_sessions_own_description() {
        use kr_cbor::CanonicalValue;
        use kr_protocol::envelope::ParamsValue;
        use kr_protocol::identity::{DesktopBinding, WorkerProfile};
        use kr_protocol::ids::{SessionEpoch, SessionId};
        use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
        use kr_worker::session::{Session, SessionConfig};

        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let mut session = Session::open(SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id: host.environment_id(),
            display_number: DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script("exec cat"),
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(80, 24),
            journal_path: None,
            spool_directory: None,
            worker_endpoint: None,
            send_queue_bytes: 1024 * 1024,
            resident_bytes: 64 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
            launch_profile: LaunchProfile::default(),
        })
        .expect("opens the session");
        session.launch().expect("launches the shell");
        let endpoint = environment
            .worker_endpoint(DisplayNumber::new(1))
            .expect("an endpoint");

        let report = super::ready_report(session_id, &endpoint, &session).expect("a report");
        let CanonicalValue::Map(written) = ParamsValue::from_typed(&report)
            .expect("the report encodes")
            .into_value()
        else {
            panic!("a report is a map of its members");
        };
        let described = ParamsValue::from_typed(&session.summary())
            .expect("the description encodes")
            .into_value();
        assert_eq!(
            written.get("session"),
            Some(&described),
            "the report carries the session as its own worker describes it"
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
