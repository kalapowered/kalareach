//! The `kr` command line.

use std::process::ExitCode;

use clap::Parser as _;
use kr_cli::cli::{Cli, Command, HostCommand, ShellArguments, ShellCommand};
use kr_cli::error::{CliError, Result};
use kr_cli::resolve::{SessionSelector, find, open_controller, open_worker};
use kr_cli::session::AttachOptions;
use kr_cli::terminal::ControllingTerminal;
use kr_cli::{build_id, report};
use kr_ipc::paths::HostPaths;
use kr_protocol::desktop::{SleepInhibitionSetting, setting};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::hostinfo::{HostDoctorResult, HostInfoResult};
use kr_protocol::ids::{ActionId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    Dimensions, Presentation, SessionCloseParams, SessionCloseResult, SessionCreateParams,
    SessionCreateResult, SessionListParams, SessionListResult, SessionReadParams,
    SessionReadResult, ShellMode,
};
use kr_shell_integration::host::startup::HomeLayout;

fn main() -> ExitCode {
    // Whether the caller asked for machine-readable output has to be known before the arguments
    // parse, because a usage mistake is one of the things a script has to be able to read.
    let json = std::env::args().any(|argument| argument == "--json");
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return usage(&error, json),
    };
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
        Ok(Completion::Done) => ExitCode::SUCCESS,
        // The command has already written its own result, which named the failure. Printing a
        // second document here would give a reader two to reconcile.
        Ok(Completion::Reported(error)) => ExitCode::from(error.exit_code()),
        Err(error) => {
            if json {
                print_json(&report::failure(&error));
            } else {
                eprintln!("kr: {error}");
            }
            ExitCode::from(error.exit_code())
        }
    }
}

/// How a command finished.
///
/// A command whose own result describes the failure reports it here rather than returning it, so
/// exactly one result reaches the caller and the exit status still says what happened.
enum Completion {
    /// The command succeeded.
    Done,
    /// The command failed and has already written the result that says so.
    Reported(CliError),
}

/// Reports a usage mistake, in the form the caller asked for.
fn usage(error: &clap::Error, json: bool) -> ExitCode {
    if error.use_stderr() {
        if json {
            let failure = CliError::Usage(error.render().to_string().trim().to_owned());
            print_json(&report::failure(&failure));
            return ExitCode::from(failure.exit_code());
        }
        eprint!("{}", error.render());
        return ExitCode::from(2);
    }
    // `--help` and `--version` are not failures.
    print!("{}", error.render());
    ExitCode::SUCCESS
}

async fn run(cli: Cli) -> Result<Completion> {
    let paths = HostPaths::discover()?;
    match cli.command {
        Command::New(arguments) => {
            let presentation = arguments.presentation.resolve(stdio_is_terminal())?;
            // Both modes are real choices, and neither is a substitute for the other: a managed
            // request the host cannot serve is refused by name rather than created as a stock
            // session, and the daemon decides that before it reserves anything.
            let shell_mode = match arguments.shell_mode.as_str() {
                "managed" => ShellMode::Managed,
                "native_compat" => ShellMode::NativeCompat,
                other => {
                    return Err(CliError::Usage(format!(
                        "{other} is not a shell mode; choose managed or native_compat"
                    )));
                }
            };
            // The environment the session is created in is the one the caller named, resolved
            // before anything connects. A selector that is ignored would create the session
            // somewhere else and say nothing about it.
            let environment = kr_cli::resolve::select(&paths, arguments.environment.as_deref())?;
            // The palette before the geometry, because the probe form asks this terminal a
            // question and a refusal should come before a session exists rather than after.
            let chosen = match arguments.palette.as_deref() {
                Some(value) => Some(kr_cli::create::resolve(
                    kr_cli::create::PaletteChoice::parse(value)?,
                    presentation,
                )?),
                None => None,
            };
            let (palette, typed_while_asking) = match chosen {
                Some(chosen) => (Some(chosen.palette), chosen.typed),
                None => (None, Vec::new()),
            };
            // From here to the attachment, anything the person typed while this terminal was
            // being asked for its colours has nowhere to go but that attachment. It is owed from
            // the moment it was taken, so the guard is taken before anything that can fail:
            // opening the connection and asking this host what it creates by default both can,
            // and a failure there would otherwise lose the count in silence.
            let mut undelivered = kr_cli::session::UndeliveredTyping::new(typed_while_asking.len());
            let mut client = open_controller(&environment.paths, build_id()).await?;
            // The execution context is this host's own unless the command chose one. The
            // presentation is not consulted: an invisible session runs where a visible one would,
            // and it keeps that desktop's access.
            let info: HostInfoResult = typed(client.request(Method::HostInfo, &()).await?)?;
            let profile = arguments
                .execution
                .chosen()
                .unwrap_or(info.default_worker_profile);
            if !cli.json {
                println!(
                    "{}",
                    report::execution_context_line(profile, arguments.execution.chosen().is_some())
                );
            }
            let dimensions = match presentation {
                Presentation::Attach => {
                    // The creating terminal's size is registered before the shell starts, so the
                    // first prompt is drawn at the real geometry rather than redrawn at it.
                    ControllingTerminal::open()
                        .ok()
                        .and_then(|terminal| terminal.size().ok())
                        .map(|size| Dimensions::new(u64::from(size.columns), u64::from(size.rows)))
                }
                Presentation::Terminal | Presentation::Invisible => None,
            };
            let params = SessionCreateParams {
                environment_id: environment.environment_id,
                presentation,
                shell: Nullable(arguments.shell),
                shell_mode,
                cwd: Nullable(arguments.cwd.or_else(|| {
                    std::env::current_dir()
                        .ok()
                        .map(|path| path.display().to_string())
                })),
                dimensions: Nullable(dimensions),
                worker_profile: profile,
                environment_snapshot: snapshot(),
                // Chosen here, before anything connects, because a probe of this terminal is part
                // of choosing it and a session's palette is fixed at creation.
                palette: Nullable(palette),
            };
            let outcome = client
                .mutate(
                    Method::SessionCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget::environment(environment.environment_id),
                    &params,
                )
                .await?;
            let created: SessionCreateResult = typed(outcome)?;
            drop(client);

            // The session exists. Presenting it is a separate step, and a presentation that fails
            // never produces a second session: the failure is reported against the one that was
            // created.
            // The presentation takes responsibility for them, and reports what it could not
            // deliver. Nothing is owed here once it has been handed over.
            undelivered.delivered();
            let presented = present(
                &paths,
                &created,
                presentation,
                kr_cli::session::UndeliveredTyping::new(typed_while_asking.len()),
                typed_while_asking,
            )
            .await;
            if cli.json {
                let mut document = report::session(&created.session);
                if let Some(object) = document.as_object_mut() {
                    object.insert(
                        "presentation".to_owned(),
                        serde_json::json!(presentation.as_str()),
                    );
                    object.insert(
                        "presentation_error".to_owned(),
                        match presented.as_ref() {
                            Ok(()) => serde_json::Value::Null,
                            Err(error) => serde_json::json!(error.to_string()),
                        },
                    );
                    object.insert(
                        "execution_context_chosen".to_owned(),
                        serde_json::json!(arguments.execution.chosen().is_some()),
                    );
                }
                print_json(&document);
            } else {
                println!(
                    "created session {} ({})",
                    created.session.display_number, created.session.session_id
                );
                // The receipt, not the request: what the session was actually created with.
                println!("{}", report::desktop_line(&created.session));
                match created.session.shell_mode {
                    ShellMode::Managed => println!(
                        "shell mode managed: Ctrl-D at an empty root prompt detaches this client, and a launch installs a command in {}'s own editor",
                        created.session.shell_path
                    ),
                    ShellMode::NativeCompat => println!(
                        "shell mode native_compat: Ctrl-D at the prompt follows {}'s own behaviour and can close the session, a launch installs no command, and kr detach always works",
                        created.session.shell_path
                    ),
                }
                if let Err(error) = presented.as_ref() {
                    eprintln!("kr: the session was created; its terminal was not opened: {error}");
                }
            }
            Ok(presented.map_or_else(Completion::Reported, |()| Completion::Done))
        }
        Command::Attach(arguments) => {
            let selector = SessionSelector::parse(&arguments.session)?;
            let wanted = parse_environment(arguments.environment.as_deref())?;
            let (_, descriptor) = find(&paths, &selector, wanted)?;
            let (outcome, session_id) = kr_cli::session::run(
                &descriptor,
                kr_cli::session::UndeliveredTyping::new(0),
                AttachOptions {
                    take_geometry: arguments.take_geometry,
                    no_probe: arguments.no_probe,
                    follow_live: arguments.follow_live,
                    // Attaching asks this terminal nothing before its own handshake, so there is
                    // nothing owed from before it.
                    typed_before: Vec::new(),
                },
            )
            .await?;
            if cli.json {
                print_json(&serde_json::json!({
                    "ok": !outcome.is_failure(),
                    "session_id": session_id.to_string(),
                    "outcome": outcome.detail(),
                }));
            } else {
                println!("{}", outcome.detail());
            }
            Ok(outcome
                .into_error()
                .map_or(Completion::Done, Completion::Reported))
        }
        Command::Detach(arguments) => {
            let selector = session_selector(arguments.session.as_deref())?;
            let (_, descriptor) = find(&paths, &selector, None)?;
            let mut client = open_worker(&descriptor, build_id()).await?;
            let attachment_id = match arguments.attachment.as_deref() {
                Some(text) => text
                    .parse()
                    .map_err(|_| CliError::Usage(format!("{text} is not an attachment")))?,
                // Nothing was named, so the session is asked what is attached. One terminal
                // attachment is unambiguous; more than one is not, and the command says which
                // rather than guessing.
                None => sole_terminal_attachment(&mut client, descriptor.session_id).await?,
            };
            let result =
                kr_cli::attach::detach_attachment(&mut client, &descriptor, attachment_id).await?;
            if cli.json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "session_id": descriptor.session_id.to_string(),
                    "detached": attachment_id.to_string(),
                    "remaining": result.remaining.get(),
                }));
            } else {
                println!(
                    "detached {attachment_id}; {} attachment(s) remain",
                    result.remaining
                );
            }
            Ok(Completion::Done)
        }
        Command::Close(arguments) => {
            let selector = session_selector(arguments.session.as_deref())?;
            let wanted = parse_environment(arguments.environment.as_deref())?;
            let environment = kr_cli::resolve::select(&paths, arguments.environment.as_deref())?;
            // Closing goes through the control daemon where one is running, because the daemon
            // owns the registry and writes the closure record. With no daemon the command still
            // works: it closes the worker directly, and the daemon reconciles the record when it
            // comes back.
            let located = match find(&paths, &selector, wanted) {
                Ok((known, descriptor)) => Some((known, descriptor)),
                Err(CliError::UnknownSession(_)) => None,
                Err(error) => return Err(error),
            };
            let closed = match located {
                Some((known, descriptor)) => {
                    match open_controller(&known.paths, build_id()).await {
                        Ok(mut client) => {
                            let outcome = client
                                .mutate(
                                    Method::SessionClose,
                                    ActionId::new(kr_ipc::new_uuid()),
                                    session_target(known.environment_id, descriptor.session_id),
                                    &SessionCloseParams {
                                        session_id: descriptor.session_id,
                                    },
                                )
                                .await?;
                            typed::<SessionCloseResult>(outcome)?
                        }
                        Err(_) => {
                            let mut client = open_worker(&descriptor, build_id()).await?;
                            let outcome = client
                                .mutate(
                                    Method::SessionClose,
                                    ActionId::new(kr_ipc::new_uuid()),
                                    session_target(
                                        descriptor.environment_id,
                                        descriptor.session_id,
                                    ),
                                    &SessionCloseParams {
                                        session_id: descriptor.session_id,
                                    },
                                )
                                .await?;
                            typed::<SessionCloseResult>(outcome)?
                        }
                    }
                }
                // No descriptor, so the session is closed or was never here. The daemon knows
                // which, and it resolves a display number through the reservations it retains.
                None => {
                    let mut client = open_controller(&environment.paths, build_id()).await?;
                    let session_id = resolve_closed(&mut client, &selector).await?;
                    let outcome = client
                        .mutate(
                            Method::SessionClose,
                            ActionId::new(kr_ipc::new_uuid()),
                            session_target(environment.environment_id, session_id),
                            &SessionCloseParams { session_id },
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
                    "durability": match closed.durability {
                        kr_protocol::session::Durability::Durable => "durable",
                        kr_protocol::session::Durability::Volatile => "volatile",
                    },
                }));
            } else {
                println!("session {} is {}", closed.session_id, closed.state);
                if closed.durability == kr_protocol::session::Durability::Volatile {
                    println!("this closure was not recorded durably");
                }
            }
            Ok(Completion::Done)
        }
        Command::List(arguments) => {
            let environment = kr_cli::resolve::select(&paths, arguments.environment.as_deref())?;
            let mut client = open_controller(&environment.paths, build_id()).await?;
            let outcome = client
                .request(
                    Method::SessionList,
                    &SessionListParams {
                        environment_id: Nullable::some(environment.environment_id),
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
            Ok(Completion::Done)
        }
        Command::Status(arguments) => {
            let selector = session_selector(arguments.session.as_deref())?;
            let wanted = parse_environment(arguments.environment.as_deref())?;
            let environment = kr_cli::resolve::select(&paths, arguments.environment.as_deref())?;
            // The environment the session was found in, which is not always the one this
            // installation opens by default. Reading one environment's session and another's
            // power setting would describe a machine the session is not on.
            let (summary, host) = match find(&paths, &selector, wanted) {
                Ok((known, descriptor)) => {
                    let summary = match read_session(&descriptor).await {
                        Ok(summary) => summary,
                        // A descriptor that no longer answers is a hint that has gone stale. The
                        // daemon reconciles it and returns the closure record.
                        Err(CliError::HostUnavailable(_)) => {
                            let mut client = open_controller(&known.paths, build_id()).await?;
                            read_from_controller(&mut client, descriptor.session_id).await?
                        }
                        Err(error) => return Err(error),
                    };
                    (summary, known.paths)
                }
                Err(CliError::UnknownSession(_)) => {
                    let mut client = open_controller(&environment.paths, build_id()).await?;
                    let session_id = resolve_closed(&mut client, &selector).await?;
                    let summary = read_from_controller(&mut client, session_id).await?;
                    (summary, environment.paths)
                }
                Err(error) => return Err(error),
            };
            // What this host is keeping itself awake for belongs in a status read: a machine
            // that will not sleep is something a person should be able to see the reason for.
            let power = match open_controller(&host, build_id()).await {
                Ok(mut client) => {
                    typed::<HostInfoResult>(client.request(Method::HostInfo, &()).await?)
                        .ok()
                        .map(|info| info.power)
                }
                Err(_) => None,
            };
            if cli.json {
                let mut document = report::session(&summary);
                if let Some(object) = document.as_object_mut() {
                    object.insert(
                        "power".to_owned(),
                        power
                            .as_ref()
                            .map_or(serde_json::Value::Null, report::power),
                    );
                }
                print_json(&document);
            } else {
                println!("{}", report::session_line(&summary));
                println!("{}", report::desktop_line(&summary));
                if let Some(power) = power.as_ref() {
                    println!("{}", power.describe());
                }
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
            Ok(Completion::Done)
        }
        Command::Question(command) => question(&paths, command, cli.json).await,
        Command::Skill(command) => skill(&paths, command, cli.json).await,
        Command::AgentTools(arguments) => {
            if !arguments.stdio {
                return Err(CliError::Usage(
                    "the tool server speaks over standard input and output: pass --stdio"
                        .to_owned(),
                ));
            }
            // Nothing is printed here. Standard output is the protocol's own stream from this
            // point, and one stray line on it would be a frame the client cannot parse.
            kr_cli::contact::run_stdio(build_id()).await?;
            Ok(Completion::Done)
        }
        Command::Doctor(arguments) => {
            let environment = kr_cli::resolve::select(&paths, None)?;
            let mut client = open_controller(&environment.paths, build_id()).await?;
            let info: HostInfoResult = typed(client.request(Method::HostInfo, &()).await?)?;
            let checks: HostDoctorResult = typed(client.request(Method::HostDoctor, &()).await?)?;
            // What this environment can currently do, which is where the desktop, what a logout
            // does to each profile, and the capability evidence come from.
            let capabilities: kr_protocol::desktop::EnvironmentCapabilitiesResult = typed(
                client
                    .request(
                        Method::EnvironmentCapabilities,
                        &kr_protocol::desktop::EnvironmentCapabilitiesParams {
                            environment_id: environment.environment_id,
                        },
                    )
                    .await?,
            )?;
            // One document, whether the diagnostics passed or not. A command that printed a result
            // and then a failure would give a reader two documents to reconcile.
            if cli.json {
                print_json(&serde_json::json!({
                    "ok": checks.healthy,
                    "host": report::host(&info),
                    "doctor": report::doctor(&checks),
                    "environment": report::environment_capabilities(&capabilities),
                }));
            } else {
                println!(
                    "environment {} generation {} ({} of {} sessions)",
                    info.environment_id, info.generation, info.live_sessions, info.session_limit
                );
                println!(
                    "sessions are created in the {} execution context by default",
                    info.default_worker_profile.as_str()
                );
                println!("{}", report::desktop_summary_line(&capabilities.desktop));
                for line in report::capability_lines(&capabilities.desktop) {
                    println!("{line}");
                }
                for line in report::persistence_lines(&capabilities.persistence) {
                    println!("{line}");
                }
                println!("{}", info.power.describe());
                print!("{}", report::doctor_lines(&checks));
                if arguments.verbose {
                    // The detail of every check, including the ones that passed, and the remedy
                    // for any that did not.
                    for check in &checks.checks {
                        println!("  {}: {}", check.id, check.detail);
                        if let Some(remedy) = check.remedy.as_ref() {
                            println!("    {remedy}");
                        }
                    }
                }
            }
            if checks.healthy {
                Ok(Completion::Done)
            } else {
                // The one document above already says which diagnostics failed, so the failure is
                // reported rather than returned and the exit status carries it.
                Ok(Completion::Reported(CliError::Other(
                    "one or more diagnostics did not pass".to_owned(),
                )))
            }
        }
        Command::Host(arguments) => match arguments.command {
            HostCommand::Power(power) => {
                let environment = kr_cli::resolve::select(&paths, None)?;
                // Changing the setting writes this user's own host configuration. Nothing else
                // about the host changes: no service is installed, no privilege is obtained, and
                // the daemon reads the choice the next time it asks itself the question.
                if let Some(chosen) = power.set.as_deref() {
                    let chosen = SleepInhibitionSetting::from_wire(chosen).ok_or_else(|| {
                        CliError::Usage(format!(
                            "{chosen} is not a power setting: choose off, mains_only or \
                             battery_too"
                        ))
                    })?;
                    let file = environment.paths.state_dir().join(setting::FILE_NAME);
                    kr_ipc::paths::write_owner_only_file(
                        &file,
                        setting::document(chosen).as_bytes(),
                    )
                    .map_err(CliError::Ipc)?;
                }
                // The daemon is asked what the setting is now doing, because the setting alone is
                // a choice rather than a state: what is held depends on the work and the power
                // source as well.
                let mut client = open_controller(&environment.paths, build_id()).await?;
                let info: HostInfoResult = typed(client.request(Method::HostInfo, &()).await?)?;
                if cli.json {
                    print_json(&serde_json::json!({
                        "ok": true,
                        "environment_id": environment.environment_id.to_string(),
                        "power": report::power(&info.power),
                    }));
                } else {
                    println!("{}", info.power.describe());
                    if info.power.setting == SleepInhibitionSetting::Off {
                        println!(
                            "kr host power --set mains_only keeps this host awake for work it has \
                             admitted, while it is on mains power"
                        );
                    }
                }
                Ok(Completion::Done)
            }
        },
        Command::Shell(arguments) => {
            // Nothing here reaches the host: setup configures this user's own shell, and the
            // diagnostics read the installed packages and the files those shells actually read.
            let layout = HomeLayout::from_environment();
            let selector = shell_selector(&arguments);
            let reports = match &arguments.command {
                // Removal is the one operation that needs no package: it takes out the marked lines
                // it put in, and an entry whose package was uninstalled is exactly the one somebody
                // is trying to get rid of.
                ShellCommand::Remove(remove) => kr_cli::shell::shells(selector)?
                    .into_iter()
                    .map(|kind| kr_cli::shell::remove(kind, &layout, remove.dry_run))
                    .collect::<Result<Vec<_>>>()?,
                command => {
                    let packages = kr_cli::shell::packages()?;
                    let selected = kr_cli::shell::selected(&packages, selector)?;
                    match command {
                        ShellCommand::Status(_) => selected
                            .iter()
                            .map(|package| kr_cli::shell::report(package, &layout))
                            .collect::<Vec<_>>(),
                        ShellCommand::Install(install) => selected
                            .iter()
                            .map(|package| {
                                kr_cli::shell::install(
                                    package,
                                    &layout,
                                    install.nsh_bypass,
                                    install.dry_run,
                                )
                            })
                            .collect::<Result<Vec<_>>>()?,
                        ShellCommand::Remove(_) => unreachable!("removal is answered above"),
                    }
                }
            };
            if cli.json {
                print_json(&kr_cli::shell::to_json(&reports));
            } else {
                kr_cli::shell::print(&reports);
            }
            Ok(Completion::Done)
        }
    }
}

/// Returns the shell one `kr shell` invocation names, when it names one.
fn shell_selector(arguments: &ShellArguments) -> Option<&str> {
    match &arguments.command {
        ShellCommand::Status(status) => status.shell.as_deref(),
        ShellCommand::Install(install) => install.shell.as_deref(),
        ShellCommand::Remove(remove) => remove.shell.as_deref(),
    }
}

/// Presents a session that has just been created.
///
/// A failure here never creates a second session: the session exists, and what could not be done
/// is opening a window on it.
async fn present(
    paths: &HostPaths,
    created: &SessionCreateResult,
    presentation: Presentation,
    owed: kr_cli::session::UndeliveredTyping,
    typed_before: Vec<u8>,
) -> Result<()> {
    match presentation {
        Presentation::Invisible => Ok(()),
        Presentation::Attach => {
            let selector = SessionSelector::Identifier(created.session.session_id);
            let (_, descriptor) = find(paths, &selector, Some(created.session.environment_id))?;
            let (outcome, _) = kr_cli::session::run(
                &descriptor,
                owed,
                AttachOptions {
                    // A terminal that created the session is the session's terminal: it claims the
                    // geometry, which is what section 8 makes the default for a creating client.
                    take_geometry: true,
                    no_probe: false,
                    // A terminal that has just created a session has nothing above its live page
                    // to look at, so there is nothing to come back from.
                    follow_live: false,
                    // What the person typed while the creation was asking this terminal for its
                    // colours. It is theirs, and this attachment is where it goes.
                    typed_before,
                },
            )
            .await?;
            outcome.into_error().map_or(Ok(()), Err)
        }
        Presentation::Terminal => {
            // Nothing here forwards input, so anything the person typed while the terminal was
            // being asked for its colours has nowhere to go. They are owed the number rather than
            // left to wonder where those keystrokes went, which is what `owed` reports on its way
            // out of scope.
            let _ = typed_before;
            open_terminal_application(created.session.session_id, created.session.environment_id)
        }
    }
}

/// Returns one word quoted for a shell that will re-parse it.
#[cfg(target_vendor = "apple")]
fn shell_quoted(word: &str) -> String {
    // Single quotes, with an embedded single quote closed, escaped and reopened. Nothing inside
    // single quotes is interpreted by the shell, so this is the whole rule.
    format!("'{}'", word.replace('\'', "'\\''"))
}

/// Opens an installed terminal application on a session.
///
/// # Errors
///
/// Returns [`CliError::TerminalUnavailable`] when this host has no launcher. The session is
/// already created, so this is reported against it rather than causing a second one.
#[cfg(target_vendor = "apple")]
fn open_terminal_application(
    session_id: kr_protocol::ids::SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> Result<()> {
    // The session is named by its own identifier and its environment, not by a display number: two
    // environments can each have a session number one, and the terminal that opened would then be
    // attached to whichever the command happened to resolve.
    let program = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "kr".to_owned());
    // `do script` hands its text to a shell, so every word of it is quoted here. The identifiers
    // are the host's own UUIDs and the path is this executable's, but quoting a path that happens
    // to contain a space is not optional and neither is doing it in one place.
    let command = format!(
        "{} attach {} --environment {}",
        shell_quoted(&program),
        shell_quoted(&session_id.to_string()),
        shell_quoted(&environment_id.to_string())
    );
    for application in ["iTerm", "Terminal"] {
        let script = format!(
            "tell application \"{application}\" to activate\n\
             tell application \"{application}\" to do script \"{}\"",
            command.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let started = std::process::Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(&script)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if started.is_ok_and(|status| status.success()) {
            return Ok(());
        }
    }
    Err(CliError::TerminalUnavailable(
        "no terminal application this host can open was found".to_owned(),
    ))
}

/// Returns one launcher's argument vector: its own separator, then the command to run.
#[cfg(not(target_vendor = "apple"))]
fn once(separator: &str, command: &[String]) -> Vec<String> {
    let mut arguments = vec![separator.to_owned()];
    arguments.extend_from_slice(command);
    arguments
}

/// Opens an installed terminal application on a session.
///
/// # Errors
///
/// Returns [`CliError::TerminalUnavailable`] when this host has no launcher.
#[cfg(not(target_vendor = "apple"))]
fn open_terminal_application(
    session_id: kr_protocol::ids::SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> Result<()> {
    let program = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "kr".to_owned());
    // Each candidate is invoked as a vector, never as a command line a shell would re-parse, and
    // the session is named by its own identifier and environment: two environments can each have a
    // session number one, and a terminal opened on the number would attach to whichever the
    // command happened to resolve.
    let attach: Vec<String> = vec![
        program.clone(),
        "attach".to_owned(),
        session_id.to_string(),
        "--environment".to_owned(),
        environment_id.to_string(),
    ];
    let candidates: [(&str, Vec<String>); 4] = [
        ("x-terminal-emulator", once("-e", &attach)),
        ("gnome-terminal", once("--", &attach)),
        ("konsole", once("-e", &attach)),
        ("xterm", once("-e", &attach)),
    ];
    for (launcher, arguments) in candidates {
        let started = std::process::Command::new(launcher)
            .args(&arguments)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if started.is_ok() {
            return Ok(());
        }
    }
    Err(CliError::TerminalUnavailable(
        "no terminal application this host can open was found".to_owned(),
    ))
}

/// Returns the one terminal attachment of a session, or says why there is not one.
async fn sole_terminal_attachment(
    client: &mut kr_ipc::client::LocalClient,
    session_id: SessionId,
) -> Result<kr_protocol::ids::AttachmentId> {
    let outcome = client
        .request(
            Method::EventsSnapshot,
            &kr_protocol::recovery::EventsSnapshotParams { session_id },
        )
        .await?;
    let snapshot: kr_protocol::recovery::EventsSnapshotResult = typed(outcome)?;
    let terminals: Vec<&kr_protocol::attachment::AttachmentSummary> = snapshot
        .attachments
        .iter()
        .filter(|attachment| attachment.mode == kr_protocol::attachment::AttachMode::Terminal)
        .collect();
    match terminals.len() {
        0 => Err(CliError::UnknownSession(format!(
            "session {session_id} has no terminal attachment to detach"
        ))),
        1 => Ok(terminals[0].attachment_id),
        _ => Err(CliError::Usage(format!(
            "session {session_id} has {} terminal attachments; name one with --attachment: {}",
            terminals.len(),
            terminals
                .iter()
                .map(|attachment| attachment.attachment_id.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Resolves a selector that names no live descriptor, through what the daemon retains.
async fn resolve_closed(
    client: &mut kr_ipc::client::LocalClient,
    selector: &SessionSelector,
) -> Result<SessionId> {
    if let SessionSelector::Identifier(session_id) = selector {
        return Ok(*session_id);
    }
    // A display number belongs to the environment for good, so a closed session still answers to
    // the number it was listed under.
    let outcome = client
        .request(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: true,
            },
        )
        .await?;
    let listed: SessionListResult = typed(outcome)?;
    let SessionSelector::Display(number) = selector else {
        unreachable!("an identifier was answered above");
    };
    listed
        .sessions
        .iter()
        .find(|summary| summary.display_number.get() == *number)
        .map(|summary| summary.session_id)
        .ok_or_else(|| CliError::UnknownSession(selector.to_string()))
}

async fn read_from_controller(
    client: &mut kr_ipc::client::LocalClient,
    session_id: SessionId,
) -> Result<kr_protocol::session::SessionSummary> {
    let outcome = client
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await?;
    Ok(typed::<SessionReadResult>(outcome)?.session)
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

fn session_selector(named: Option<&str>) -> Result<SessionSelector> {
    match named {
        Some(text) => SessionSelector::parse(text),
        None => kr_cli::resolve::current_session()
            .map(SessionSelector::Identifier)
            .ok_or(CliError::NotInSession),
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

/// Runs `kr question`.
async fn question(
    paths: &HostPaths,
    command: kr_cli::cli::QuestionCommand,
    json: bool,
) -> Result<Completion> {
    use kr_cli::cli::QuestionCommand;
    use kr_cli::question;

    match command {
        QuestionCommand::List(arguments) => {
            let scope = match arguments.session.as_deref() {
                Some(session) => question::Scope::Session(SessionSelector::parse(session)?),
                None => question::Scope::Everything,
            };
            let found =
                question::list(paths, &scope, arguments.include_resolved, build_id()).await?;
            if json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "questions": found
                        .iter()
                        .map(|(descriptor, item)| question::rendered(descriptor, item))
                        .collect::<Vec<_>>(),
                }));
            } else if found.is_empty() {
                println!("no questions are waiting");
            } else {
                for (descriptor, item) in &found {
                    println!("{}", question::line(descriptor, item));
                }
            }
            Ok(Completion::Done)
        }
        QuestionCommand::Show(arguments) => {
            let question_id = parse_question(&arguments.question)?;
            let (descriptor, item) = question::show(paths, question_id, build_id()).await?;
            if json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "question": question::rendered(&descriptor, &item),
                }));
            } else {
                print!("{}", question::detail(&descriptor, &item));
            }
            Ok(Completion::Done)
        }
        QuestionCommand::Answer(arguments) => {
            let question_id = parse_question(&arguments.question)?;
            let answer = answer_form(&arguments.form)?;
            let item = question::answer(paths, question_id, answer, build_id()).await?;
            if json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "state": item.state.as_str(),
                    "revision": item.revision.get(),
                    "question_id": item.question_id.to_string(),
                }));
            } else {
                println!("{} is {}", item.question_id, item.state.as_str());
            }
            Ok(Completion::Done)
        }
        QuestionCommand::Cancel(arguments) => {
            let question_id = parse_question(&arguments.question)?;
            let item = question::cancel(paths, question_id, build_id()).await?;
            if json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "state": item.state.as_str(),
                    "question_id": item.question_id.to_string(),
                }));
            } else {
                println!("{} is {}", item.question_id, item.state.as_str());
            }
            Ok(Completion::Done)
        }
    }
}

/// Reads the one answer form a command gave.
fn answer_form(form: &kr_cli::cli::AnswerForm) -> Result<kr_protocol::question::QuestionAnswer> {
    use kr_protocol::question::QuestionAnswer;

    // Free text stays free text. `--other` is the answer every select and confirm offers, and it
    // is never folded into a listed choice or into yes.
    if let Some(text) = form.other.as_ref() {
        return Ok(QuestionAnswer::Other { text: text.clone() });
    }
    if let Some(text) = form.text.as_ref() {
        return Ok(QuestionAnswer::Input { text: text.clone() });
    }
    if let Some(choice_id) = form.choice.as_ref() {
        return Ok(QuestionAnswer::Choice {
            choice_id: choice_id.clone(),
        });
    }
    if form.yes {
        return Ok(QuestionAnswer::Decision { decided: true });
    }
    if form.no {
        return Ok(QuestionAnswer::Decision { decided: false });
    }
    Err(CliError::Usage(
        "give one of --text, --choice, --yes, --no or --other".to_owned(),
    ))
}

fn parse_question(text: &str) -> Result<kr_protocol::ids::QuestionId> {
    text.parse()
        .map_err(|_| CliError::Usage(format!("{text} is not a question identifier")))
}

/// Runs `kr skill`.
async fn skill(
    paths: &HostPaths,
    command: kr_cli::cli::SkillCommand,
    json: bool,
) -> Result<Completion> {
    use kr_cli::cli::SkillCommand;
    use kr_cli::skill;

    let arguments = match &command {
        SkillCommand::Install(arguments)
        | SkillCommand::Status(arguments)
        | SkillCommand::Remove(arguments) => arguments,
    };
    let params = skill::parse(
        &arguments.agent,
        &arguments.scope,
        arguments.project_dir.as_deref(),
    )?;
    let environment = kr_cli::resolve::select(paths, None)?;
    let mut client = open_controller(&environment.paths, build_id()).await?;
    match command {
        SkillCommand::Install(_) => {
            let result = skill::install(&mut client, environment.environment_id, &params).await?;
            if json {
                print_json(&serde_json::json!({"ok": true, "install": skill::installed(&result)}));
            } else {
                print!("{}", skill::install_lines(&result));
            }
        }
        SkillCommand::Status(_) => {
            let result = skill::status(&mut client, &params).await?;
            if json {
                print_json(&serde_json::json!({
                    "ok": skill::is_intact(&result),
                    "status": skill::reported(&result),
                }));
            } else {
                print!("{}", skill::status_lines(&result));
            }
        }
        SkillCommand::Remove(_) => {
            let result = skill::remove(&mut client, environment.environment_id, &params).await?;
            if json {
                print_json(&serde_json::json!({"ok": true, "remove": skill::removed(&result)}));
            } else {
                print!("{}", skill::remove_lines(&result));
            }
        }
    }
    Ok(Completion::Done)
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
