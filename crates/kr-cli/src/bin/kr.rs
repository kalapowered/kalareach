//! The `kr` command line.

use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser as _;
use kr_cli::attach::{Attachment, RestorationGuard};
use kr_cli::cli::{Cli, Command};
use kr_cli::error::{CliError, Result};
use kr_cli::resolve::{SessionSelector, find, open_controller, open_worker};
use kr_cli::terminal::ControllingTerminal;
use kr_cli::{build_id, report};
use kr_ipc::paths::HostPaths;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::{HostDoctorResult, HostInfoResult};
use kr_protocol::ids::{ActionId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    Dimensions, SessionCloseParams, SessionCloseResult, SessionCreateParams, SessionCreateResult,
    SessionListParams, SessionListResult, SessionReadParams, SessionReadResult, ShellMode,
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("kr: could not start: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report::failure(&error))
                        .unwrap_or_else(|_| "{}".to_owned())
                );
            } else {
                eprintln!("kr: {error}");
            }
            ExitCode::from(error.exit_code())
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    let paths = HostPaths::discover()?;
    let environment_id = paths.open_environment_id()?;
    let environment = paths.environment(environment_id);
    match cli.command {
        Command::New(arguments) => {
            let presentation = arguments.presentation.resolve(stdio_is_terminal())?;
            if arguments.shell_mode != ShellMode::NativeCompat.as_str() {
                return Err(CliError::ShellIntegrationUnsupported(format!(
                    "this host implements the native_compat shell mode; {} needs a qualified shell package",
                    arguments.shell_mode
                )));
            }
            let dimensions = match presentation {
                kr_protocol::session::Presentation::Attach => {
                    // The creating terminal and its size are registered before the shell starts, so
                    // the first prompt is drawn at the real geometry.
                    ControllingTerminal::open()
                        .ok()
                        .and_then(|terminal| terminal.size().ok())
                        .map(|size| Dimensions::new(u64::from(size.ws_col), u64::from(size.ws_row)))
                }
                _ => None,
            };
            let params = SessionCreateParams {
                environment_id,
                presentation,
                shell: Nullable(arguments.shell),
                shell_mode: ShellMode::NativeCompat,
                cwd: Nullable(arguments.cwd.or_else(|| {
                    std::env::current_dir()
                        .ok()
                        .map(|path| path.display().to_string())
                })),
                dimensions: Nullable(dimensions),
                worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                environment_snapshot: snapshot(),
            };
            let mut client = open_controller(&environment, build_id()).await?;
            let outcome = client
                .mutate(
                    Method::SessionCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    environment_target(environment_id),
                    &params,
                )
                .await?;
            let created: SessionCreateResult = typed(outcome)?;
            if cli.json {
                print_json(&report::session(&created.session));
            } else {
                println!(
                    "created session {} ({})",
                    created.session.display_number, created.session.session_id
                );
                println!(
                    "shell mode {}: Ctrl-D at the prompt follows {}'s own behaviour; kr detach always works",
                    created.session.shell_mode.as_str(),
                    created.session.shell_path
                );
                if let Some(error) = created.presentation_error.as_ref() {
                    eprintln!("kr: the session was created; its terminal was not opened: {error}");
                }
            }
            Ok(())
        }
        Command::Attach(arguments) => {
            let selector = SessionSelector::parse(&arguments.session)?;
            let wanted = parse_environment(arguments.environment.as_deref())?;
            let (_, descriptor) = find(&paths, &selector, wanted)?;
            attach_session(&descriptor, arguments.take_geometry).await
        }
        Command::Detach(arguments) => {
            let attachment = arguments
                .attachment
                .as_deref()
                .ok_or(CliError::NotInSession)?;
            let selector = match arguments.session.as_deref() {
                Some(text) => SessionSelector::parse(text)?,
                None => SessionSelector::Identifier(
                    kr_cli::resolve::current_session().ok_or(CliError::NotInSession)?,
                ),
            };
            let (_, descriptor) = find(&paths, &selector, None)?;
            let attachment_id = attachment
                .parse()
                .map_err(|_| CliError::Usage(format!("{attachment} is not an attachment")))?;
            let mut client = open_worker(&descriptor, build_id()).await?;
            kr_cli::attach::detach(&mut client, &descriptor, attachment_id).await?;
            if cli.json {
                print_json(&serde_json::json!({ "ok": true, "detached": attachment }));
            } else {
                println!("detached {attachment}");
            }
            Ok(())
        }
        Command::Close(arguments) => {
            let selector = session_selector(arguments.session.as_deref())?;
            let wanted = parse_environment(arguments.environment.as_deref())?;
            // Closing goes through the control daemon where one is running, because the daemon
            // owns the registry and writes the closure record. With no daemon the command still
            // works: it closes the worker directly, and the daemon reconciles the record when it
            // comes back.
            let session_id = match find(&paths, &selector, wanted) {
                Ok((_, descriptor)) => Some(descriptor.session_id),
                Err(CliError::UnknownSession(_)) => resolve_identifier(&selector).ok(),
                Err(error) => return Err(error),
            };
            let session_id =
                session_id.ok_or_else(|| CliError::UnknownSession(selector.to_string()))?;
            let closed = match open_controller(&environment, build_id()).await {
                Ok(mut client) => {
                    let outcome = client
                        .mutate(
                            Method::SessionClose,
                            ActionId::new(kr_ipc::new_uuid()),
                            session_target(environment_id, session_id),
                            &SessionCloseParams { session_id },
                        )
                        .await?;
                    typed::<SessionCloseResult>(outcome)?
                }
                Err(_) => {
                    let (_, descriptor) = find(&paths, &selector, wanted)?;
                    let mut client = open_worker(&descriptor, build_id()).await?;
                    let outcome = client
                        .mutate(
                            Method::SessionClose,
                            ActionId::new(kr_ipc::new_uuid()),
                            session_target(descriptor.environment_id, descriptor.session_id),
                            &SessionCloseParams {
                                session_id: descriptor.session_id,
                            },
                        )
                        .await?;
                    typed::<SessionCloseResult>(outcome)?
                }
            };
            if cli.json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "session_id": closed.session_id.to_string(),
                    "state": closed.state.as_str(),
                }));
            } else {
                println!("session {} is {}", closed.session_id, closed.state);
            }
            Ok(())
        }
        Command::List(arguments) => {
            let mut client = open_controller(&environment, build_id()).await?;
            let outcome = client
                .request(
                    Method::SessionList,
                    &SessionListParams {
                        environment_id: Nullable(parse_environment(
                            arguments.environment.as_deref(),
                        )?),
                        include_closed: arguments.include_closed,
                    },
                )
                .await?;
            let listed: SessionListResult = typed(outcome)?;
            if cli.json {
                print_json(&serde_json::json!({
                    "sessions": listed.sessions.iter().map(report::session).collect::<Vec<_>>(),
                }));
            } else if listed.sessions.is_empty() {
                println!("no sessions");
            } else {
                for summary in &listed.sessions {
                    println!("{}", report::session_line(summary));
                }
            }
            Ok(())
        }
        Command::Status(arguments) => {
            let selector = session_selector(arguments.session.as_deref())?;
            let wanted = parse_environment(arguments.environment.as_deref())?;
            let summary = match find(&paths, &selector, wanted) {
                Ok((_, descriptor)) => match read_session(&descriptor).await {
                    Ok(summary) => summary,
                    // A descriptor that no longer answers is a hint that has gone stale. The
                    // daemon reconciles it and returns the closure record.
                    Err(CliError::HostUnavailable(_)) => {
                        let mut client = open_controller(&environment, build_id()).await?;
                        let outcome = client
                            .request(
                                Method::SessionRead,
                                &SessionReadParams {
                                    session_id: descriptor.session_id,
                                },
                            )
                            .await?;
                        typed::<SessionReadResult>(outcome)?.session
                    }
                    Err(error) => return Err(error),
                },
                Err(CliError::UnknownSession(_)) => {
                    let mut client = open_controller(&environment, build_id()).await?;
                    let session_id = resolve_identifier(&selector)?;
                    let outcome = client
                        .request(Method::SessionRead, &SessionReadParams { session_id })
                        .await?;
                    typed::<SessionReadResult>(outcome)?.session
                }
                Err(error) => return Err(error),
            };
            if cli.json {
                print_json(&report::session(&summary));
            } else {
                println!("{}", report::session_line(&summary));
                if let Some(closure) = summary.closure.as_ref() {
                    println!(
                        "closed: {} ({})",
                        closure.reason.as_str(),
                        match closure.durability {
                            kr_protocol::session::Durability::Durable => "recorded",
                            kr_protocol::session::Durability::Volatile => "not recorded durably",
                        }
                    );
                }
            }
            Ok(())
        }
        Command::Doctor(_) => {
            let mut client = open_controller(&environment, build_id()).await?;
            let info: HostInfoResult = typed(client.request(Method::HostInfo, &()).await?)?;
            let checks: HostDoctorResult = typed(client.request(Method::HostDoctor, &()).await?)?;
            if cli.json {
                print_json(&serde_json::json!({
                    "host": report::host(&info),
                    "doctor": report::doctor(&checks),
                }));
            } else {
                println!(
                    "environment {} generation {} ({} of {} sessions)",
                    info.environment_id, info.generation, info.live_sessions, info.session_limit
                );
                print!("{}", report::doctor_lines(&checks));
            }
            if checks.healthy {
                Ok(())
            } else {
                Err(CliError::Other(
                    "one or more diagnostics did not pass".to_owned(),
                ))
            }
        }
    }
}

async fn attach_session(
    descriptor: &kr_protocol::worker::WorkerDescriptor,
    take_geometry: bool,
) -> Result<()> {
    let terminal = ControllingTerminal::open()?;
    let size = terminal.size()?;
    let dimensions = Dimensions::new(u64::from(size.ws_col), u64::from(size.ws_row));
    let mut client = open_worker(descriptor, build_id()).await?;
    let attachment: Attachment =
        kr_cli::attach::attach(&mut client, descriptor, dimensions, take_geometry).await?;
    let epoch = attachment
        .lease
        .as_ref()
        .map_or(kr_protocol::ids::InputLeaseEpoch::new(0), |lease| {
            lease.lease.epoch
        });
    // From the beginning of what is retained, not from the live edge: a terminal that attaches to
    // a running session shows what is on it. The worker clamps the request to the oldest cursor it
    // still holds and names the gap when there is one.
    kr_cli::attach::subscribe(
        &mut client,
        descriptor.session_id,
        attachment.attachment_id,
        Some(0),
    )
    .await?;

    // The guard is armed before the terminal is touched, so there is no window in which the
    // terminal is raw and nothing is holding its previous state.
    let saved = terminal.modes()?;
    let guard = RestorationGuard::arm(&guard_program(), &terminal, &saved)?;
    let saved = terminal.enter_raw_mode()?;

    let handle = Arc::new(
        terminal
            .handle()
            .try_clone()
            .map_err(|error| CliError::Terminal(error.to_string()))?,
    );
    let input_handle = terminal
        .handle()
        .try_clone()
        .map_err(|error| CliError::Terminal(error.to_string()))?;
    let mut input = kr_cli::attach::spawn_input_reader(input_handle);

    let (mut reader, mut writer, acknowledgement) = client.into_halves();
    let output_terminal = Arc::clone(&handle);
    let output = tokio::spawn(async move {
        use std::io::Write as _;

        while let Ok(message) = reader
            .read_message::<kr_protocol::local::ControlMessage>()
            .await
        {
            if let kr_protocol::local::ControlMessage::Notification(notification) = message
                && notification.event_type.as_str() == "session.output"
                && let Ok(event) = notification
                    .payload
                    .to_typed::<kr_protocol::recovery::OutputEvent>()
            {
                let mut handle = output_terminal.as_ref();
                if handle.write_all(event.bytes.as_slice()).is_err() {
                    break;
                }
                let _ = handle.flush();
            }
        }
    });

    let mut sequence = 0_u64;
    let mut request_id = 1_u64;
    while let Some(bytes) = input.recv().await {
        let params = kr_protocol::input::InputWriteParams {
            session_id: descriptor.session_id,
            attachment_id: attachment.attachment_id,
            epoch,
            sequence: kr_protocol::ids::InputSequence::new(sequence),
            bytes: kr_protocol::scalars::Bytes::new(bytes),
        };
        let Ok(params) = kr_protocol::envelope::ParamsValue::from_typed(&params) else {
            break;
        };
        let message = kr_protocol::local::ControlMessage::Request(kr_protocol::envelope::Request {
            request_id: kr_protocol::ids::RequestId::new(request_id),
            method: Method::InputWrite.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            params,
        });
        if writer.write_message(&message).await.is_err() {
            break;
        }
        sequence += 1;
        request_id += 1;
    }
    output.abort();
    let _ = acknowledgement;

    // The terminal comes back here on the ordinary path; the guard is released only once it has.
    terminal.restore(&saved)?;
    guard.release();
    Ok(())
}

async fn read_session(
    descriptor: &kr_protocol::worker::WorkerDescriptor,
) -> Result<kr_protocol::session::SessionSummary> {
    let mut client = open_worker(descriptor, build_id()).await?;
    let outcome = client
        .request(
            Method::SessionRead,
            &SessionReadParams {
                session_id: descriptor.session_id,
            },
        )
        .await?;
    Ok(typed::<SessionReadResult>(outcome)?.session)
}

fn guard_program() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("kr-attach-guard")))
        .unwrap_or_else(|| std::path::PathBuf::from("kr-attach-guard"))
}

fn session_selector(named: Option<&str>) -> Result<SessionSelector> {
    match named {
        Some(text) => SessionSelector::parse(text),
        None => kr_cli::resolve::current_session()
            .map(SessionSelector::Identifier)
            .ok_or(CliError::NotInSession),
    }
}

fn resolve_identifier(selector: &SessionSelector) -> Result<SessionId> {
    match selector {
        SessionSelector::Identifier(session_id) => Ok(*session_id),
        // A closed session has no descriptor to translate a number through. Protocol identity is
        // the UUID, so that is what a closed session is read by.
        SessionSelector::Display(number) => Err(CliError::UnknownSession(format!(
            "{number}: a closed session is read by its identifier"
        ))),
    }
}

fn parse_environment(named: Option<&str>) -> Result<Option<EnvironmentId>> {
    named
        .map(|text| {
            text.parse::<EnvironmentId>()
                .map_err(|_| CliError::Usage(format!("{text} is not an environment identifier")))
        })
        .transpose()
}

fn environment_target(environment_id: EnvironmentId) -> ActionTarget {
    ActionTarget::environment(environment_id)
}

fn session_target(environment_id: EnvironmentId, session_id: SessionId) -> ActionTarget {
    ActionTarget {
        environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

fn snapshot() -> Vec<kr_protocol::session::EnvironmentVariable> {
    std::env::vars()
        .map(|(name, value)| kr_protocol::session::EnvironmentVariable { name, value })
        .collect()
}

fn stdio_is_terminal() -> bool {
    use std::io::IsTerminal as _;

    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn typed<T: serde::de::DeserializeOwned + serde::Serialize>(
    outcome: std::result::Result<
        kr_protocol::envelope::ParamsValue,
        kr_protocol::error::ProtocolError,
    >,
) -> Result<T> {
    outcome
        .map_err(CliError::Refused)?
        .to_typed()
        .map_err(|error| CliError::Other(error.to_string()))
}

fn print_json(value: &serde_json::Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned())
    );
}
