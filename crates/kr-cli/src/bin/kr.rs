//! The `kr` command line.

use std::process::ExitCode;

use clap::Parser as _;
use kr_cli::cli::{
    AccountCommand, AccountTokenCommand, Cli, Command, HostCommand, ShellArguments, ShellCommand,
};
use kr_cli::error::{CliError, Result};
use kr_cli::resolve::{SessionSelector, find, open_controller, open_worker};
use kr_cli::session::AttachOptions;
use kr_cli::terminal::ControllingTerminal;
use kr_cli::{build_id, report};
use kr_ipc::paths::HostPaths;
use kr_protocol::desktop::SleepInhibitionSetting;
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
            let launch_profile = arguments.launch_profile()?;
            // What the request asked for, kept for the report below: the profile itself travels
            // into the create.
            let fenced_launch = launch_profile.fenced_launch;
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
                launch_profile,
                terminal: Nullable(arguments.terminal_app.clone()),
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
                        "shell mode managed: Ctrl-D at an empty root prompt detaches this client, \
                         and {}",
                        if fenced_launch {
                            format!(
                                "a launch installs a command in {}'s own editor",
                                created.session.shell_path
                            )
                        } else {
                            "this session's launch profile admits no fenced launch, so a launch \
                             installs no command"
                                .to_owned()
                        }
                    ),
                    ShellMode::NativeCompat => println!(
                        "shell mode native_compat: Ctrl-D at the prompt follows {}'s own behaviour \
                         and can close the session, a launch installs no command, and kr detach \
                         takes --attachment because this session records no originating attachment",
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
                Some(text) => Some(
                    text.parse()
                        .map_err(|_| CliError::Usage(format!("{text} is not an attachment")))?,
                ),
                // Nothing was named, so this command presents the capability the line it runs
                // from was given and the session answers from that. A caller holding none gets
                // `AMBIGUOUS_ATTACHMENT` with the instruction to name the attachment, never a
                // guess made from what this process happens to look like.
                None => None,
            };
            let result =
                kr_cli::attach::detach_attachment(&mut client, &descriptor, attachment_id).await?;
            let detached = result.attachment_id;
            if cli.json {
                print_json(&serde_json::json!({
                    "ok": true,
                    "session_id": descriptor.session_id.to_string(),
                    "detached": detached.to_string(),
                    "remaining": result.remaining.get(),
                }));
            } else {
                println!(
                    "detached {detached}; {} attachment(s) remain",
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
            let (read, host) = match find(&paths, &selector, wanted) {
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
            let summary = &read.session;
            if cli.json {
                let mut document = report::session(summary);
                if let Some(object) = document.as_object_mut() {
                    object.insert(
                        "power".to_owned(),
                        power
                            .as_ref()
                            .map_or(serde_json::Value::Null, report::power),
                    );
                    object.insert(
                        "launch_profile".to_owned(),
                        read.launch_profile
                            .as_ref()
                            .map_or(serde_json::Value::Null, launch_profile_document),
                    );
                }
                print_json(&document);
            } else {
                println!("{}", report::session_line(summary));
                println!("{}", report::desktop_line(summary));
                if let Some(profile) = read.launch_profile.as_ref() {
                    println!("{}", launch_profile_line(profile));
                }
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
            // The diagnostics first, because asking for them is what puts this host's
            // configuration into force: a ceiling somebody edited by hand takes effect here, and
            // a ceiling that withdraws authority also withdraws what this connection was admitted
            // under. Each read is therefore made again on a new connection when that happens, and
            // everything after it is read under the authority now in force rather than beside a
            // number the change has already replaced.
            let checks: HostDoctorResult =
                diagnostic(&mut client, &environment, Method::HostDoctor, &()).await?;
            let info: HostInfoResult =
                diagnostic(&mut client, &environment, Method::HostInfo, &()).await?;
            // What this environment can currently do, which is where the desktop, what a logout
            // does to each profile, and the capability evidence come from.
            let capabilities: kr_protocol::desktop::EnvironmentCapabilitiesResult = diagnostic(
                &mut client,
                &environment,
                Method::EnvironmentCapabilities,
                &kr_protocol::desktop::EnvironmentCapabilitiesParams {
                    environment_id: environment.environment_id,
                },
            )
            .await?;
            let report = kr_cli::doctor::doctor_lines(&checks, arguments.verbose);
            // The bundle is written before anything is printed, so `--json` produces one document
            // and a bundle that could not be written is the command's failure rather than a note
            // after a result that already said everything went well.
            let bundle = match arguments.bundle.as_deref() {
                Some(path) => {
                    let content = if arguments.include_content {
                        let selected =
                            kr_cli::doctor::content_export(&mut client, environment.environment_id)
                                .await?;
                        // On the error stream, because standard output is one document. A person
                        // sees what they selected either way, and a `--json` reader is not handed
                        // two things to parse.
                        eprintln!("--include-content adds the content-bearing diagnostic export:");
                        for entry in &selected {
                            eprintln!("{}", entry.describe());
                        }
                        selected
                    } else {
                        Vec::new()
                    };
                    let bundle = kr_protocol::hostinfo::SupportBundle::new(
                        kr_protocol::scalars::TimestampMs::new(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0)),
                        ),
                        kr_cli::doctor::software(&info),
                        capabilities.desktop.records.clone(),
                        checks.clone(),
                        checks.configuration.clone(),
                        Vec::new(),
                    );
                    kr_cli::doctor::bundle::write(path, &bundle, &content, &report)?;
                    Some((path.display().to_string(), bundle, content.len()))
                }
                None => None,
            };
            // One document, whether the diagnostics passed or not. A command that printed a result
            // and then a failure would give a reader two documents to reconcile.
            if cli.json {
                let mut document = serde_json::json!({
                    "ok": checks.healthy,
                    "host": report::host(&info),
                    "doctor": kr_cli::doctor::doctor(&checks),
                    "configuration": kr_cli::doctor::configuration_report(&checks.configuration),
                    "environment": report::environment_capabilities(&capabilities),
                });
                if let Some((path, written, entries)) = bundle.as_ref() {
                    document["bundle"] = serde_json::json!({
                        "path": path,
                        "software": written.software.len(),
                        "capabilities": written.capabilities.len(),
                        "checks": written.doctor.checks.len(),
                        "content_entries": entries,
                    });
                }
                print_json(&document);
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
                for line in kr_cli::doctor::configurable_lines(&checks.configuration) {
                    println!("{line}");
                }
                print!("{report}");
                if let Some((path, written, entries)) = bundle.as_ref() {
                    println!(
                        "support bundle written to {path} ({} software versions, {} capability \
                         records, {} checks, {entries} content-bearing entries)",
                        written.software.len(),
                        written.capabilities.len(),
                        written.doctor.checks.len()
                    );
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
                // Changing the setting is one validated edit of this user's own host
                // configuration, applied as a new revision of the same document every other
                // preference lives in. Nothing else about the host changes: no service is
                // installed, no privilege is obtained, and the daemon reads the choice the next
                // time it asks itself the question.
                if let Some(chosen) = power.set.as_deref() {
                    let chosen = SleepInhibitionSetting::from_wire(chosen).ok_or_else(|| {
                        CliError::Usage(format!(
                            "{chosen} is not a power setting: choose off, mains_only or \
                             battery_too"
                        ))
                    })?;
                    kr_cli::doctor::configuration::apply(
                        &environment.paths,
                        &kr_protocol::hostinfo::configuration::Change::SleepInhibition(chosen),
                    )?;
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
            HostCommand::Terminal(terminal) => {
                let environment = kr_cli::resolve::select(&paths, None)?;
                let file = environment
                    .paths
                    .state_dir()
                    .join(kr_shell_integration::host::terminal::PREFERENCE_FILE);
                let available = kr_shell_integration::host::terminal::detect();
                if terminal.clear {
                    // Removing the file is the whole of it: with no preference, detection decides.
                    match std::fs::remove_file(&file) {
                        Ok(()) => {}
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(CliError::Other(format!(
                                "could not remove {}: {error}",
                                file.display()
                            )));
                        }
                    }
                } else if let Some(chosen) = terminal.set.as_deref() {
                    if !available.iter().any(|application| application.id == chosen) {
                        return Err(CliError::TerminalUnavailable(format!(
                            "{chosen} is not installed on this host; it has {}",
                            describe_terminals(&available)
                        )));
                    }
                    kr_ipc::paths::write_owner_only_file(
                        &file,
                        kr_shell_integration::host::terminal::preference_document(chosen)
                            .as_bytes(),
                    )
                    .map_err(CliError::Ipc)?;
                }
                let preferred = kr_shell_integration::host::terminal::saved_preference(
                    environment.paths.state_dir(),
                );
                if cli.json {
                    print_json(&serde_json::json!({
                        "ok": true,
                        "environment_id": environment.environment_id.to_string(),
                        "preferred": preferred,
                        "available": available
                            .iter()
                            .map(|application| serde_json::json!({
                                "id": application.id,
                                "name": application.name,
                                "detail": application.detail,
                            }))
                            .collect::<Vec<_>>(),
                    }));
                } else if available.is_empty() {
                    println!("no terminal application this host can open was found");
                } else {
                    println!("available: {}", describe_terminals(&available));
                    match preferred {
                        Some(preferred) => println!("preferred: {preferred}"),
                        None => println!(
                            "preferred: none, so a new window opens in {}",
                            available[0].id
                        ),
                    }
                }
                Ok(Completion::Done)
            }
        },
        Command::Account(arguments) => match arguments.command {
            AccountCommand::Token(token) => match token {
                AccountTokenCommand::Import(import) => {
                    // Nothing here reaches the host or the network. It reads the operator's file
                    // and writes this host's, and what it reports never carries the token.
                    let imported = kr_cli::account::import(&import.path)?;
                    if cli.json {
                        print_json(&serde_json::json!({ "ok": true, "imported": imported }));
                    } else {
                        for line in imported.lines() {
                            println!("{line}");
                        }
                    }
                    Ok(Completion::Done)
                }
                AccountTokenCommand::Show => {
                    let path = kr_cli::account::token_path()?;
                    let stored = kr_client::services::voice::AccountTokenFile::at(path.clone())
                        .stored()
                        .ok();
                    if cli.json {
                        print_json(&serde_json::json!({
                            "ok": true,
                            "path": path.display().to_string(),
                            "imported": stored.is_some(),
                            "origin": stored.as_ref().map(|stored| stored.origin.clone()),
                            "scopes": stored
                                .as_ref()
                                .map(|stored| stored.scopes.clone())
                                .unwrap_or_default(),
                        }));
                    } else {
                        println!("This host reads its account token from {}.", path.display());
                        match stored {
                            // The description is the origin, the scopes and the expiry. The token
                            // itself is never printed by anything.
                            Some(stored) => println!("It holds {}.", stored.description()),
                            None => println!(
                                "No account token has been imported. Write one with `kr account \
                                 token import <path>`."
                            ),
                        }
                    }
                    Ok(Completion::Done)
                }
            },
        },
        Command::Shell(arguments) => {
            // Nothing here reaches the host: setup configures this user's own shell, and the
            // diagnostics read the installed packages and the files those shells actually read.
            //
            // Where this installation has a PowerShell package, that package's own executable is
            // the shell asked where its profile is: two editions keep theirs in different places,
            // and an entry written for one is never read by the other.
            let layout = kr_cli::shell::packages()
                .ok()
                .and_then(|packages| {
                    packages
                        .get(kr_shell_integration::contract::qualification::ShellKind::PowerShell)
                        .map(|package| package.executable())
                })
                .map_or_else(HomeLayout::from_environment, |powershell| {
                    HomeLayout::from_environment().launching(powershell)
                });
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

/// Renders a session's launch profile as a line.
fn launch_profile_line(profile: &kr_protocol::session::LaunchProfile) -> String {
    let integrations: Vec<String> = profile
        .command_integrations
        .iter()
        .filter(|integration| integration.enabled)
        .map(|integration| integration.command.clone())
        .collect();
    let integrated = if integrations.is_empty() {
        "no command integration".to_owned()
    } else {
        format!("command integration for {}", integrations.join(", "))
    };
    format!(
        "launch: {} startup, {}, {integrated}",
        profile.startup.as_str(),
        if profile.fenced_launch {
            "fenced launch"
        } else {
            "no fenced launch"
        }
    )
}

/// Renders a session's launch profile as a document.
fn launch_profile_document(profile: &kr_protocol::session::LaunchProfile) -> serde_json::Value {
    serde_json::json!({
        "startup": profile.startup.as_str(),
        "fenced_launch": profile.fenced_launch,
        "command_integrations": profile
            .command_integrations
            .iter()
            .map(|integration| serde_json::json!({
                "command": integration.command,
                "flags": integration.flags,
                "enabled": integration.enabled,
            }))
            .collect::<Vec<_>>(),
    })
}

/// Names the terminal applications this host has, in the order it would choose them.
fn describe_terminals(
    available: &[kr_shell_integration::host::terminal::TerminalApplication],
) -> String {
    available
        .iter()
        .map(|application| application.id.clone())
        .collect::<Vec<_>>()
        .join(", ")
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
            let _ = paths;
            // The window is the host's to open: a session created on a paired device can ask for a
            // local tab too, and the daemon is the only party on this host that can open one. What
            // this command does with the answer is report it against the session that exists.
            created.presentation_error.as_ref().map_or(Ok(()), |error| {
                Err(CliError::TerminalUnavailable(error.message.clone()))
            })
        }
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
) -> Result<SessionReadResult> {
    let outcome = client
        .request(Method::SessionRead, &SessionReadParams { session_id })
        .await?;
    read_result(outcome)
}

async fn read_session(
    descriptor: &kr_protocol::worker::WorkerDescriptor,
) -> Result<SessionReadResult> {
    let mut client = open_worker(descriptor, build_id()).await?;
    let outcome = client
        .request(
            Method::SessionRead,
            &SessionReadParams {
                session_id: descriptor.session_id,
            },
        )
        .await?;
    read_result(outcome)
}

/// Reads a session read, from a worker of this build or of the one before it.
///
/// A host is upgraded without its workers: the daemon and this command are replaced while every
/// live session's worker goes on running the build that started it. Such a worker answers with the
/// fields its own build has, and the launch profile, the last command block and the outstanding
/// launch count are not among them, so its answer is read with those three absent rather than
/// refused. What this command then prints about that session is what the worker said.
///
/// Remove `Reported` and this fallback once no worker from a build before those fields can still
/// be running, which is when every session that was live across the upgrade has closed.
fn read_result(
    outcome: std::result::Result<
        kr_protocol::envelope::ParamsValue,
        kr_protocol::error::ProtocolError,
    >,
) -> Result<SessionReadResult> {
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reported {
        session: kr_protocol::session::SessionSummary,
        endpoint: Nullable<String>,
    }

    let value = match outcome {
        Ok(value) => value,
        Err(error) => return Err(CliError::Refused(error)),
    };
    match value.to_typed::<SessionReadResult>() {
        Ok(read) => Ok(read),
        Err(error) => match value.to_typed::<Reported>() {
            Ok(reported) => Ok(SessionReadResult {
                session: reported.session,
                endpoint: reported.endpoint,
                launch_profile: Nullable::null(),
                last_command_block: Nullable::null(),
                outstanding_launches: Nullable::null(),
            }),
            Err(_) => Err(CliError::Other(error.to_string())),
        },
    }
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

/// Reads one diagnostic, on a new connection when the authority behind this one was withdrawn.
///
/// Reading the configuration is what puts it into force, so a ceiling edited outside this host
/// takes effect during a `kr doctor` run, and a ceiling that changes what a caller may do
/// deregisters every connection admitted under the authority it replaced - including this
/// command's own. That is the change working, not a failure, so the read is made again under the
/// authority now in force. A second refusal is the answer.
async fn diagnostic<
    T: serde::de::DeserializeOwned + serde::Serialize,
    P: serde::Serialize + ?Sized,
>(
    client: &mut kr_ipc::client::LocalClient,
    environment: &kr_cli::resolve::KnownEnvironment,
    method: Method,
    params: &P,
) -> Result<T> {
    match client.request(method, params).await? {
        Ok(value) => value
            .to_typed()
            .map_err(|error| CliError::Other(error.to_string())),
        Err(refused) if refused.code == kr_protocol::error::ErrorCode::PermissionDenied => {
            *client = open_controller(&environment.paths, build_id()).await?;
            typed(client.request(method, params).await?)
        }
        Err(refused) => Err(CliError::Refused(refused)),
    }
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
