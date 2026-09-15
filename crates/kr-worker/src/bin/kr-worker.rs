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
use kr_protocol::session::{DisplayNumber, Presentation, SessionCreateParams, ShellMode};
use kr_protocol::worker::{ReservationId, WorkerLaunchSpec, WorkerReady};
use kr_worker::environment::{ExecutionContext, build as build_environment};
use kr_worker::history::DEFAULT_RESIDENT_BYTES;
use kr_worker::output::DEFAULT_SEND_QUEUE_BYTES;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::start_or_record;
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
    let paths = HostPaths::new(&arguments.runtime_dir, &arguments.state_dir);
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
    // Managed mode needs a KalaReach-qualified shell package with its reader mailbox and pre-EOF
    // hook. This worker launches the selected stock shell, which cannot claim that contract, so an
    // unsupported mode is named rather than silently substituted.
    if specification.create.shell_mode != ShellMode::NativeCompat {
        let error = ProtocolError::new(
            ErrorCode::ShellIntegrationUnsupported,
            "this host implements the explicitly selected native_compat shell mode; managed mode needs a qualified shell package",
        );
        writer
            .write_message(&ControlFrame::WorkerFailed(error))
            .await?;
        return Err("managed shell mode is not available on this host".into());
    }

    let display_number = DisplayNumber::new(arguments.display);
    let endpoint = environment.worker_endpoint(display_number)?;
    let listener = Listener::bind(&endpoint)?;

    let config = session_config(&specification, &environment, display_number, &endpoint);
    let runtime = match start_or_record(config) {
        Ok(runtime) => runtime,
        Err(failure) => {
            let error = ProtocolError::new(failure.error.code(), failure.error.to_string());
            writer
                .write_message(&ControlFrame::WorkerFailed(error))
                .await?;
            return Err(Box::new(failure.error));
        }
    };

    let ready = {
        let session = runtime.session();
        WorkerReady {
            session_id,
            endpoint: endpoint.as_text(),
            root_process: session
                .root_identity()
                .ok_or("the root shell has no process identity")?,
            shell_path: specification
                .create
                .shell
                .as_ref()
                .cloned()
                .unwrap_or_default(),
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

    let service = Arc::new(WorkerService::new(
        Arc::clone(&runtime),
        identity,
        endpoint,
        ServiceBinding {
            environment_id,
            boot_identity,
            controller_public_key: specification.controller_public_key,
            controller_generation: specification.controller_generation,
            build_id: build_id(),
        },
    )?);
    let serving = tokio::spawn(Arc::clone(&service).serve(listener));
    // The worker exists for its session. When the session closes, the last record is written and
    // the process ends; nothing here restarts a shell.
    let _record = runtime.wait_closed().await;
    serving.abort();
    Ok(())
}

fn session_config(
    specification: &WorkerLaunchSpec,
    environment: &kr_ipc::paths::EnvironmentPaths,
    display_number: DisplayNumber,
    _endpoint: &Endpoint,
) -> SessionConfig {
    let create: &SessionCreateParams = &specification.create;
    // The shell the request named, or the one this host is configured to use, or the platform's
    // own. Nothing is substituted silently: the session reports the executable it launched.
    let shell_path = create
        .shell
        .as_ref()
        .cloned()
        .or_else(configured_shell)
        .unwrap_or_else(default_shell);
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
            arguments: interactive_arguments(&shell_path, create.presentation),
            program: shell_path,
            cwd,
            environment: launch_environment.to_pairs(),
        },
        shell_mode: create.shell_mode,
        worker_profile: create.worker_profile,
        desktop,
        dimensions,
        journal_path: Some(environment.journal_database(specification.session_id)),
        spool_directory: Some(environment.session_spool(specification.session_id)),
        send_queue_bytes: DEFAULT_SEND_QUEUE_BYTES,
        resident_bytes: DEFAULT_RESIDENT_BYTES,
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
fn interactive_arguments(shell_path: &str, _presentation: Presentation) -> Vec<String> {
    let name = std::path::Path::new(shell_path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(shell_path)
        .to_ascii_lowercase();
    let name = name.strip_suffix(".exe").unwrap_or(&name);
    match name {
        "fish" => vec!["--interactive".to_owned()],
        "pwsh" | "powershell" => vec!["-NoLogo".to_owned(), "-NoExit".to_owned()],
        "cmd" => vec!["/K".to_owned()],
        // A login shell reads the profile that sets the user's own path and prompt, which is what
        // makes the first prompt look like the one they get anywhere else.
        _ => vec!["-l".to_owned(), "-i".to_owned()],
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
