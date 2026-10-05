//! The `kr` command line.

use kr_client::shown;
use kr_client::shown::Shown;
use std::process::ExitCode;

use clap::Parser as _;
use kr_cli::bridge::environments::Selected;
use kr_cli::cli::{
    AccountCommand, AccountTokenCommand, Cli, Command, HostCommand, ShellArguments, ShellCommand,
};
use kr_cli::error::{CliError, Result};
use kr_cli::output::{self, Asked, Document, Request};
use kr_cli::report::Completion;
use kr_cli::resolve::{SessionSelector, find, open_controller, open_worker};
use kr_cli::session::AttachOptions;
use kr_cli::terminal::ControllingTerminal;
use kr_cli::{build_id, report, stdout_line};
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
    // parse, because a usage mistake is one of the things a script has to be able to read. A
    // literal `--` ends the options, so a `--json` after it is an argument and asks for nothing.
    // Read as the operating system gave them: an argument that is not UTF-8 is compared, never
    // decoded, so it cannot end the program with a panic that repeats it.
    let json = std::env::args_os()
        .take_while(|argument| argument != "--")
        .any(|argument| argument == "--json");
    // Before anything a release could matter to: a command of an installed release holds that
    // release for as long as it runs, and does not run at all once the release is being removed.
    if let Err(error) = kr_ipc::install::this_process() {
        let failure = CliError::Other(kr_cli::update::said(error));
        if json {
            output::document(&report::failure(&failure));
        } else {
            report::failed(&failure);
        }
        return ExitCode::from(failure.exit_code());
    }
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
            report::say(&shown!("kr: could not start: {}", Shown::io(&error)));
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
                output::document(&report::failure(&error));
            } else {
                report::failed(&error);
            }
            ExitCode::from(error.exit_code())
        }
    }
}

/// Reports a usage mistake, in the form the caller asked for.
///
/// A mistake is said as the command's own declarations and the kind of mistake say it, never with
/// what was typed: an argument this command does not take can be a secret pasted in the wrong
/// place.
fn usage(error: &clap::Error, json: bool) -> ExitCode {
    // `--help` and `--version` are not failures.
    if !error.use_stderr()
        && let Some(help) = kr_cli::shown::help(error)
    {
        output::say(&help);
        return ExitCode::SUCCESS;
    }
    let failure = CliError::Usage(shown!("{}", kr_cli::shown::usage(error)));
    if json {
        output::document(&report::failure(&failure));
    } else {
        report::say(&shown!("{}", kr_cli::shown::usage(error)));
    }
    ExitCode::from(failure.exit_code())
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
                _ => {
                    return Err(CliError::Usage(Shown::said(
                        "the shell mode is managed or native_compat",
                    )));
                }
            };
            // The environment the session is created in is the one the caller named, resolved
            // before anything connects. A selector that is ignored would create the session
            // somewhere else and say nothing about it.
            //
            // What `--environment` names may also be an enrolled environment of this host, which a
            // process bridge reaches and which has no directory here.
            let environment = match kr_cli::bridge::environments::selected(
                &paths,
                arguments.environment.as_deref(),
            )
            .await?
            {
                Selected::Local(environment) => environment,
                Selected::Enrolled(enrolment) => {
                    return new_in_enrolled(
                        *enrolment,
                        arguments,
                        presentation,
                        shell_mode,
                        cli.json,
                    )
                    .await;
                }
            };
            // The palette before the geometry, because the probe form asks this terminal a
            // question and a refusal should come before a session exists rather than after.
            let (palette, typed_while_asking) =
                choose_palette(arguments.palette.as_deref(), presentation)?;
            // From here to the attachment, anything the person typed while this terminal was
            // being asked for its colours has nowhere to go but that attachment. It is owed from
            // the moment it was taken, so the guard is taken before anything that can fail:
            // opening the connection and asking this host what it creates by default both can,
            // and a failure there would otherwise lose the count in silence.
            let mut undelivered = kr_cli::session::UndeliveredTyping::new(typed_while_asking.len());
            // The creating terminal and its size are registered before the shell starts, so the
            // first prompt is drawn at the real geometry rather than redrawn at it. The exchange
            // comes before anything connects: a terminal that cannot be opened or measured fails
            // it here, no session is asked for, and so no shell starts at a size nobody has.
            let dimensions = match presentation {
                Presentation::Attach => {
                    let size = ControllingTerminal::open()?.size()?;
                    Some(Dimensions::new(
                        u64::from(size.columns),
                        u64::from(size.rows),
                    ))
                }
                Presentation::Terminal | Presentation::Invisible => None,
            };
            // A host set up for the standalone start has its daemon started here when none is
            // running; any other host is told what to set up.
            let (mut client, started) =
                kr_cli::startup::open_or_start(&paths, &environment).await?;
            if let Some(started) = started
                && !cli.json
            {
                report::say(&shown!(
                    "kr: {}",
                    started.describe(environment.environment_id)
                ));
            }
            // The execution context is this host's own unless the command chose one. The
            // presentation is not consulted: an invisible session runs where a visible one would,
            // and it keeps that desktop's access.
            // Asking this host what it creates by default is what puts its configuration into
            // force, so an externally edited ceiling can withdraw the authority this connection
            // was admitted under while the answer is being prepared. The read is made again under
            // the authority now in force rather than failing before a session is created.
            let info: HostInfoResult =
                host_read(&mut client, &environment.paths, Method::HostInfo, &()).await?;
            let profile = arguments
                .execution
                .chosen()
                .unwrap_or(info.default_worker_profile);
            if !cli.json {
                output::say(&report::execution_context_line(
                    profile,
                    arguments.execution.chosen().is_some(),
                ));
            }
            let launch_profile = arguments.launch_profile()?;
            // What the request asked for, kept for the report below: the profile itself travels
            // into the create.
            let fenced_launch = launch_profile.fenced_launch;
            let params = SessionCreateParams {
                environment_id: environment.environment_id,
                presentation,
                shell: Nullable(arguments.shell),
                shell_mode,
                cwd: Nullable(arguments.cwd.or_else(kr_cli::create::process_directory)),
                dimensions: Nullable(dimensions),
                worker_profile: profile,
                environment_snapshot: kr_cli::create::environment_snapshot(
                    presentation,
                    kr_cli::create::process_variables,
                ),
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
            Ok(creation_report(
                &created,
                presentation,
                arguments.execution.chosen().is_some(),
                fenced_launch,
                presented,
                cli.json,
            ))
        }
        Command::Attach(arguments) => {
            let selector = SessionSelector::parse(&arguments.session)?;
            // A name that is one of this host's environments restricts the search to it, as it
            // always did. One that is an enrolled environment is reached through its bridge.
            let wanted = match arguments.environment.as_deref() {
                None => None,
                Some(named) => {
                    match kr_cli::bridge::environments::selected(&paths, Some(named)).await? {
                        Selected::Local(known) => Some(known.environment_id),
                        Selected::Enrolled(enrolment) => {
                            return attach_in_enrolled(&enrolment, &selector, &arguments, cli.json)
                                .await;
                        }
                    }
                }
            };
            let descriptor = match find(&paths, &selector, wanted) {
                Ok((_, descriptor)) => descriptor,
                // No descriptor names it, so it has closed, has not published one yet, or was
                // never here, and the daemon's registry says which. Attaching never starts one.
                Err(CliError::UnknownSession(_)) => {
                    return attach_unpublished(
                        &paths,
                        &selector,
                        arguments.environment.as_deref(),
                        cli.json,
                    )
                    .await;
                }
                Err(error) => return Err(error),
            };
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
            Ok(attach_report(outcome, session_id, cli.json))
        }
        Command::Detach(arguments) => {
            let selector = session_selector(arguments.session.as_deref())?;
            let (_, descriptor) = find(&paths, &selector, None)?;
            let mut client = open_worker(&descriptor, build_id()).await?;
            let attachment_id = match arguments.attachment.as_deref() {
                Some(text) => Some(text.parse().map_err(|_| {
                    CliError::Usage(Shown::said(
                        "the text given is not an attachment identifier",
                    ))
                })?),
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
                output::document(
                    &Document::new()
                        .with("ok", true)
                        .with("session_id", output::said(&descriptor.session_id))
                        .with("detached", output::said(&detached))
                        .with("remaining", result.remaining.get()),
                );
            } else {
                output::say(&shown!(
                    "detached {}; {} attachment(s) remain",
                    detached,
                    result.remaining
                ));
            }
            Ok(Completion::Done)
        }
        Command::Close(arguments) => {
            // A close asked from inside the session it closes is one of the processes that session
            // stops, and the graceful stop begins as soon as the close is accepted: a termination
            // signal to the root shell's process group and a hangup to everything the session
            // owns. Holding both off for the life of this command is what lets it report what it
            // was told; the session's forced stop still ends it if it is somehow still running
            // after the grace.
            #[cfg(unix)]
            let _held = {
                use tokio::signal::unix::{SignalKind, signal};
                (
                    signal(SignalKind::hangup()).ok(),
                    signal(SignalKind::terminate()).ok(),
                )
            };
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
                    let session_id =
                        kr_cli::resolve::retained_session(&mut client, &selector).await?;
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
                output::document(
                    &Document::new()
                        .with("ok", true)
                        .with("session_id", output::said(&closed.session_id))
                        .with("state", closed.state.as_str())
                        .with("durability", report::durability_word(closed.durability)),
                );
            } else {
                output::say(&shown!("session {} is {}", closed.session_id, closed.state));
                if closed.durability == kr_protocol::session::Durability::Volatile {
                    output::say(&Shown::said("this closure was not recorded durably"));
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
                output::document(
                    &Document::new().with(
                        "sessions",
                        listed
                            .sessions
                            .iter()
                            .map(report::session)
                            .collect::<Vec<_>>(),
                    ),
                );
            } else if listed.sessions.is_empty() {
                output::say(&Shown::said("no sessions"));
            } else {
                for summary in &listed.sessions {
                    output::line(&report::session_line(summary));
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
            // The attachments are read only where the session's own worker answered: a session
            // read from the daemon has no live worker to ask.
            let (read, attachments, host) = match find(&paths, &selector, wanted) {
                Ok((known, descriptor)) => match read_session(&descriptor).await {
                    Ok((summary, attachments)) => (summary, Some(attachments), known.paths),
                    // A descriptor that no longer answers is a hint that has gone stale. The
                    // daemon reconciles it and returns the closure record.
                    Err(CliError::HostUnavailable(_)) => {
                        let mut client = open_controller(&known.paths, build_id()).await?;
                        let summary =
                            read_from_controller(&mut client, descriptor.session_id).await?;
                        (summary, None, known.paths)
                    }
                    Err(error) => return Err(error),
                },
                Err(CliError::UnknownSession(_)) => {
                    let mut client = open_controller(&environment.paths, build_id()).await?;
                    let session_id =
                        kr_cli::resolve::retained_session(&mut client, &selector).await?;
                    let summary = read_from_controller(&mut client, session_id).await?;
                    (summary, None, environment.paths)
                }
                Err(error) => return Err(error),
            };
            // What this host is keeping itself awake for belongs in a status read: a machine
            // that will not sleep is something a person should be able to see the reason for.
            let power = match open_controller(&host, build_id()).await {
                Ok(mut client) => {
                    host_read::<HostInfoResult, _>(&mut client, &host, Method::HostInfo, &())
                        .await
                        .ok()
                        .map(|info| info.power)
                }
                Err(_) => None,
            };
            let summary = &read.session;
            if cli.json {
                let mut document = report::session(summary)
                    .with("power", power.as_ref().map(report::power))
                    .with(
                        "launch_profile",
                        read.launch_profile.as_ref().map(launch_profile_document),
                    )
                    .with(
                        "terminal_attachments",
                        match attachments.as_ref() {
                            Some(Ok(attachments)) => {
                                Some(report::terminal_attachments(attachments))
                            }
                            Some(Err(_)) | None => None,
                        },
                    );
                if let Some(Err(why)) = attachments.as_ref() {
                    document.set("terminal_attachments_unread", why.clone());
                }
                output::document(&document);
            } else {
                output::line(&report::session_line(summary));
                output::line(&report::desktop_line(summary));
                if let Some(profile) = read.launch_profile.as_ref() {
                    output::line(&launch_profile_line(profile));
                }
                if let Some(power) = power.as_ref() {
                    output::say(&report::power_line(power));
                }
                match attachments.as_ref() {
                    Some(Ok(attachments)) => {
                        for line in report::terminal_attachment_lines(attachments) {
                            output::say(&line);
                        }
                    }
                    Some(Err(why)) => output::say(&shown!(
                        "terminal attachments: not read from the session's worker: {}",
                        why.clone()
                    )),
                    None => {}
                }
                if let Some(closure) = summary.closure.as_ref() {
                    output::say(&shown!(
                        "closed: {} ({})",
                        closure.reason.as_str(),
                        match closure.durability {
                            kr_protocol::session::Durability::Durable => "recorded",
                            kr_protocol::session::Durability::Volatile => "not recorded durably",
                        }
                    ));
                }
            }
            Ok(Completion::Done)
        }
        Command::Question(command) => question(&paths, command, cli.json).await,
        Command::Pair(command) => {
            kr_cli::pair::run(&paths, command, cli.json).await?;
            Ok(Completion::Done)
        }
        Command::Project(command) => {
            kr_cli::project::run(&paths, command, cli.json).await?;
            Ok(Completion::Done)
        }
        Command::Workspace(command) => {
            kr_cli::workspace::run(&paths, command, cli.json).await?;
            Ok(Completion::Done)
        }
        Command::Changeset(command) => {
            kr_cli::changeset::run(&paths, command, cli.json).await?;
            Ok(Completion::Done)
        }
        Command::Diff(command) => kr_cli::diff::run(&paths, command, cli.json).await,
        Command::Device(command) => kr_cli::device::run(&paths, command, cli.json).await,
        Command::Privacy(command) => kr_cli::privacy::run(&paths, command, cli.json).await,
        Command::Plugin(command) => {
            kr_cli::plugin::run(&paths, command, cli.json).await?;
            Ok(Completion::Done)
        }
        Command::Skill(command) => skill(&paths, command, cli.json).await,
        Command::AgentTools(arguments) => {
            if !arguments.stdio {
                return Err(CliError::Usage(Shown::said(
                    "the tool server speaks over standard input and output: pass --stdio",
                )));
            }
            // Nothing is printed here. Standard output is the protocol's own stream from this
            // point, and one stray line on it would be a frame the client cannot parse.
            kr_cli::contact::run_stdio(build_id()).await?;
            Ok(Completion::Done)
        }
        Command::Export(arguments) => export(&paths, arguments, cli.json).await,
        Command::Doctor(arguments) => {
            // Before any host is asked: what the content export needs of the person is settled
            // first, so a command that could not show them the content never reads it.
            let content_asked = if arguments.include_content {
                Some(content_asked(&arguments)?)
            } else {
                None
            };
            let environment = kr_cli::resolve::select(&paths, None)?;
            let mut client = open_controller(&environment.paths, build_id()).await?;
            // The diagnostics first, because asking for them is what puts this host's
            // configuration into force: a ceiling somebody edited by hand takes effect here, and
            // a ceiling that withdraws authority also withdraws what this connection was admitted
            // under. Each read is therefore made again on a new connection when that happens, and
            // everything after it is read under the authority now in force rather than beside a
            // number the change has already replaced.
            let checks: HostDoctorResult =
                host_read(&mut client, &environment.paths, Method::HostDoctor, &()).await?;
            let checks = kr_cli::doctor::with_startup(checks, &environment.paths);
            let info: HostInfoResult =
                host_read(&mut client, &environment.paths, Method::HostInfo, &()).await?;
            // What this environment can currently do, which is where the desktop, what a logout
            // does to each profile, and the capability evidence come from.
            let capabilities: kr_protocol::desktop::EnvironmentCapabilitiesResult = host_read(
                &mut client,
                &environment.paths,
                Method::EnvironmentCapabilities,
                &kr_protocol::desktop::EnvironmentCapabilitiesParams {
                    environment_id: environment.environment_id,
                },
            )
            .await?;
            // Where each live session's environment came from, which only the sessions' own
            // workers can say.
            let session_environments =
                live_sessions(&environment.paths, environment.environment_id).await;
            // The bundle is written before anything is printed, so `--json` produces one document
            // and a bundle that could not be written is the command's failure rather than a note
            // after a result that already said everything went well.
            let content = match content_asked {
                Some((decision, excluded)) => Some(
                    kr_cli::doctor::content::export(
                        &mut client,
                        environment.environment_id,
                        decision,
                        excluded,
                        &kr_cli::doctor::content::Rules::here(),
                    )
                    .await?,
                ),
                None => None,
            };
            let bundle = match arguments.bundle.as_deref() {
                // A preview writes nothing, and a bundle without content is written as it was.
                Some(path)
                    if content
                        .as_ref()
                        .is_none_or(|exported| exported.approved().is_some()) =>
                {
                    let approved = content.as_ref().and_then(|exported| exported.approved());
                    let bundle = kr_protocol::hostinfo::ComposedBundle::new(
                        kr_protocol::scalars::TimestampMs::new(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0)),
                        ),
                        kr_cli::doctor::software(&info),
                        capabilities.desktop.records.clone(),
                        checks.clone(),
                        Vec::new(),
                    );
                    kr_cli::doctor::bundle::write(path, &bundle, approved)?;
                    Some((path, bundle, usize::from(approved.is_some())))
                }
                _ => None,
            };
            // One document, whether the diagnostics passed or not. A command that printed a result
            // and then a failure would give a reader two documents to reconcile.
            if cli.json {
                let mut document = Document::new()
                    .with("ok", checks.healthy)
                    .with("host", report::host(&info))
                    .with("doctor", kr_cli::doctor::doctor(&checks))
                    .with(
                        "configuration",
                        kr_cli::doctor::configuration_report(&checks.configuration),
                    )
                    .with(
                        "environment",
                        report::environment_capabilities(&capabilities),
                    )
                    .with(
                        "session_environments",
                        report::session_environments(
                            session_environments.as_deref(),
                            info.live_sessions.get(),
                        ),
                    );
                if let Some(exported) = content.as_ref() {
                    // What the content export left out and why, and the digest of what was shown,
                    // so a script can tell a bundle with no sessions in it from a host with none,
                    // and can confirm the content a preview showed.
                    document.set(
                        "content_digest",
                        Shown::compose(
                            "{}",
                            &[&kr_cli::shown::hex_digest(
                                &exported.composed().digest().hex(),
                            )],
                        ),
                    );
                    document.set(
                        "content_left_out",
                        exported
                            .composed()
                            .left_out()
                            .iter()
                            .map(|(why, sessions)| {
                                Document::new()
                                    .with("reason", Shown::said(why.code()))
                                    .with("sessions", *sessions)
                            })
                            .collect::<Vec<_>>(),
                    );
                    document.set("content_written", exported.approved().is_some());
                }
                if let Some((path, written, entries)) = bundle.as_ref() {
                    document.set(
                        "bundle",
                        Document::new()
                            // The destination this person typed, echoed to the terminal they
                            // typed it in. A command that would not say where it had written a file
                            // would be withholding something from the only reader of this line, and
                            // the bundle itself carries none of it.
                            .with("path", shown!("{}", kr_cli::shown::named(path)))
                            .with("software", written.software().len())
                            .with("capabilities", written.capabilities().len())
                            .with("checks", written.doctor().get().checks.len())
                            .with("content_entries", *entries),
                    );
                }
                output::document(&document);
            } else {
                output::say(&shown!(
                    "environment {} generation {} ({} of {} sessions)",
                    info.environment_id,
                    info.generation.get(),
                    info.live_sessions.get(),
                    info.session_limit
                ));
                output::say(&shown!(
                    "sessions are created in the {} execution context by default",
                    info.default_worker_profile.as_str()
                ));
                output::line(&report::desktop_summary_line(&capabilities.desktop));
                output::lines(&report::capability_lines(&capabilities.desktop));
                for line in report::persistence_lines(&capabilities.persistence) {
                    output::say(&line);
                }
                output::say(&report::power_line(&info.power));
                for line in report::session_environment_lines(
                    session_environments.as_deref(),
                    info.live_sessions.get(),
                ) {
                    output::say(&line);
                }
                output::lines(&kr_cli::doctor::configurable_lines(&checks.configuration));
                output::lines(&kr_cli::doctor::doctor_lines(&checks, arguments.verbose));
                if let Some(exported) = content.as_ref()
                    && exported.approved().is_none()
                {
                    output::say(&shown!(
                        "content previewed and nothing written: run the command again with \
                         --confirm-content {} to write it",
                        kr_cli::shown::hex_digest(&exported.composed().digest().hex())
                    ));
                }
                if let Some((path, written, entries)) = bundle.as_ref() {
                    output::say(&shown!(
                        "support bundle written to {} ({} software versions, {} capability \
                         records, {} checks, {} content-bearing entries)",
                        kr_cli::shown::named(path),
                        written.software().len(),
                        written.capabilities().len(),
                        written.doctor().get().checks.len(),
                        *entries
                    ));
                }
            }
            if checks.healthy {
                Ok(Completion::Done)
            } else {
                // The one document above already says which diagnostics failed, so the failure is
                // reported rather than returned and the exit status carries it.
                Ok(Completion::Reported(CliError::Other(Shown::said(
                    "one or more diagnostics did not pass",
                ))))
            }
        }
        Command::Host(arguments) => match arguments.command {
            HostCommand::Descriptions(descriptions) => {
                kr_cli::descriptions::run(&paths, descriptions, cli.json).await
            }
            HostCommand::Power(power) => {
                let environment = kr_cli::resolve::select(&paths, None)?;
                // Changing the setting is one validated edit of this user's own host
                // configuration, applied as a new revision of the same document every other
                // preference lives in. Nothing else about the host changes: no service is
                // installed, no privilege is obtained, and the daemon reads the choice the next
                // time it asks itself the question.
                if let Some(chosen) = power.set.as_deref() {
                    let chosen = SleepInhibitionSetting::from_wire(chosen).ok_or_else(|| {
                        CliError::Usage(Shown::said(
                            "the power setting is off, mains_only or battery_too",
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
                // The setting this command just wrote is put into force by this read, and a
                // grant ceiling edited beside it can withdraw this connection's authority while
                // that happens. Writing the setting and then reporting a failure would leave a
                // person believing the setting did not take.
                let info: HostInfoResult =
                    host_read(&mut client, &environment.paths, Method::HostInfo, &()).await?;
                if cli.json {
                    output::document(
                        &Document::new()
                            .with("ok", true)
                            .with("environment_id", output::said(&environment.environment_id))
                            .with("power", report::power(&info.power)),
                    );
                } else {
                    output::say(&report::power_line(&info.power));
                    if info.power.setting == SleepInhibitionSetting::Off {
                        output::say(&Shown::said(
                            "kr host power --set mains_only keeps this host awake for work it has \
                             admitted, while it is on mains power",
                        ));
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
                            return Err(CliError::Other(shown!(
                                "could not remove {}: {}",
                                Shown::within(
                                    environment.paths.state_dir(),
                                    kr_shell_integration::host::terminal::PREFERENCE_FILE
                                ),
                                Shown::io(&error)
                            )));
                        }
                    }
                } else if let Some(chosen) = terminal.set.as_deref() {
                    if !available.iter().any(|application| application.id == chosen) {
                        return Err(CliError::TerminalUnavailable(shown!(
                            "the terminal given is not installed on this host; it has {}",
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
                    output::document(
                        &Document::new()
                            .with("ok", true)
                            .with("environment_id", output::said(&environment.environment_id))
                            .with(
                                "preferred",
                                preferred
                                    .as_deref()
                                    .map(kr_cli::shown::terminal_application),
                            )
                            .with(
                                "available",
                                available
                                    .iter()
                                    .map(|application| {
                                        Document::new()
                                            .with(
                                                "id",
                                                kr_cli::shown::terminal_application(
                                                    &application.id,
                                                ),
                                            )
                                            .with(
                                                "name",
                                                kr_cli::shown::terminal_application_name(
                                                    &application.id,
                                                ),
                                            )
                                            .with(
                                                "detail",
                                                kr_cli::shown::exported(
                                                    "TerminalApplication",
                                                    "detail",
                                                    &application.detail,
                                                ),
                                            )
                                    })
                                    .collect::<Vec<_>>(),
                            ),
                    );
                } else if available.is_empty() {
                    output::say(&Shown::said(
                        "no terminal application this host can open was found",
                    ));
                } else {
                    output::say(&shown!("available: {}", describe_terminals(&available)));
                    match preferred {
                        Some(preferred) => output::say(&shown!(
                            "preferred: {}",
                            kr_cli::shown::terminal_application(&preferred)
                        )),
                        None => output::say(&shown!(
                            "preferred: none, so a new window opens in {}",
                            kr_cli::shown::terminal_application(&available[0].id)
                        )),
                    }
                }
                Ok(Completion::Done)
            }
            HostCommand::Startup(startup) => {
                kr_cli::startup::run(&paths, &startup, cli.json)?;
                Ok(Completion::Done)
            }
            HostCommand::ImportJournals => kr_cli::import::run(&paths, cli.json),
            HostCommand::Install(install) => {
                let installed =
                    kr_cli::update::install(install.release.as_deref(), install.store.as_deref())
                        .await?;
                if cli.json {
                    output::document(&installed.document());
                } else {
                    for line in installed.lines() {
                        output::say(&line);
                    }
                }
                Ok(Completion::Done)
            }
            HostCommand::Update(update) => {
                let updated =
                    kr_cli::update::update(update.archive.as_deref(), update.check).await?;
                if cli.json {
                    output::document(&updated.document());
                } else {
                    for line in updated.lines() {
                        output::say(&line);
                    }
                }
                Ok(Completion::Done)
            }
            HostCommand::Machine(machine) => kr_cli::machine::run(&paths, machine, cli.json).await,
            HostCommand::Versions => {
                let kept = kr_cli::update::versions()?;
                if cli.json {
                    output::document(
                        &Document::new().with("ok", true).with(
                            "releases",
                            kept.iter()
                                .map(kr_cli::update::Kept::document)
                                .collect::<Vec<_>>(),
                        ),
                    );
                } else {
                    for release in &kept {
                        output::say(&release.said());
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
                        output::document(
                            &Document::new()
                                .with("ok", true)
                                .with("imported", imported.document()),
                        );
                    } else {
                        for line in imported.lines() {
                            output::say(&line);
                        }
                    }
                    Ok(Completion::Done)
                }
                AccountTokenCommand::Show => {
                    let path = kr_cli::account::token_path()?;
                    let stored = kr_client::services::voice::AccountTokenFile::at(path.clone())
                        .stored()
                        .ok();
                    // The origin as a diagnostic names one and the scopes as this build knows
                    // them, for a person and for a script alike. The token itself is never
                    // printed by anything.
                    let held = kr_cli::account::Held::of(&path, stored.as_ref());
                    if cli.json {
                        output::document(&held.document());
                    } else {
                        for line in held.lines() {
                            output::say(&line);
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
            // The record of the files an install wrote an entry to, which removal works from. It is
            // this installation's own, so it lives in its state directory.
            let record = kr_shell_integration::host::startup::EntryRecord::in_state_directory(
                paths.state_root(),
            );
            let reports = match &arguments.command {
                // Removal is the one operation that needs no package: it takes out the marked lines
                // it put in, and an entry whose package was uninstalled is exactly the one somebody
                // is trying to get rid of.
                ShellCommand::Remove(remove) => kr_cli::shell::shells(selector)?
                    .into_iter()
                    .map(|kind| kr_cli::shell::remove(kind, &layout, &record, remove.dry_run))
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
                                    &record,
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
                output::document(&kr_cli::shell::document(&reports));
            } else {
                kr_cli::shell::print(&reports);
            }
            Ok(Completion::Done)
        }
        Command::Bridge(arguments) => match (arguments.stdio, &arguments.command) {
            (true, None) => {
                // Nothing is printed on standard output here: it is the bridge's own stream, and a
                // line of text on it would be read as the front of a frame.
                kr_cli::bridge::helper::run(arguments.environment.as_deref()).await?;
                Ok(Completion::Done)
            }
            (false, Some(command)) => {
                kr_cli::bridge::print(command, cli.json).await?;
                Ok(Completion::Done)
            }
            (true, Some(_)) => Err(CliError::Usage(Shown::said(
                "--stdio serves a bridge; it takes no other operation",
            ))),
            (false, None) => Err(CliError::Usage(Shown::said(
                "kr bridge --stdio serves a bridge; otherwise name list, enrol, forget or refresh",
            ))),
        },
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

/// Renders a session's launch profile as a line: the commands its integrations are for are the
/// session's own, shown to the person who asked about it.
fn launch_profile_line(profile: &kr_protocol::session::LaunchProfile) -> kr_cli::output::Line {
    let integrations: Vec<&str> = profile
        .command_integrations
        .iter()
        .filter(|integration| integration.enabled)
        .map(|integration| integration.command.as_str())
        .collect();
    let fenced = if profile.fenced_launch {
        "fenced launch"
    } else {
        "no fenced launch"
    };
    if integrations.is_empty() {
        stdout_line!(
            "launch: {} startup, {}, no command integration",
            profile.startup.as_str(),
            fenced
        )
    } else {
        stdout_line!(
            "launch: {} startup, {}, command integration for {}",
            profile.startup.as_str(),
            fenced,
            Asked::text(Request::Sessions, &integrations.join(", "))
        )
    }
}

/// Renders a session's launch profile as a document.
fn launch_profile_document(profile: &kr_protocol::session::LaunchProfile) -> Document {
    Document::new()
        .with("startup", profile.startup.as_str())
        .with("fenced_launch", profile.fenced_launch)
        .with(
            "command_integrations",
            profile
                .command_integrations
                .iter()
                .map(|integration| {
                    Document::new()
                        .with(
                            "plugin_id",
                            Asked::text(Request::Sessions, integration.plugin_id.as_str()),
                        )
                        .with(
                            "command",
                            Asked::text(Request::Sessions, &integration.command),
                        )
                        .with(
                            "flags",
                            integration
                                .flags
                                .iter()
                                .map(|flag| Asked::text(Request::Sessions, flag))
                                .collect::<Vec<_>>(),
                        )
                        .with("enabled", integration.enabled)
                })
                .collect::<Vec<_>>(),
        )
}

/// Names the terminal applications this host has, in the order it would choose them.
fn describe_terminals(
    available: &[kr_shell_integration::host::terminal::TerminalApplication],
) -> Shown {
    Shown::joined(
        available
            .iter()
            .map(|application| kr_cli::shown::terminal_application(&application.id)),
        ", ",
    )
}

/// Presents a session that has just been created.
///
/// A failure here never creates a second session: the session exists, and what could not be done
/// is opening a window on it. An attachment that began returns how it ended, which is not a failure
/// to present even when it is a failure of its own.
async fn present(
    paths: &HostPaths,
    created: &SessionCreateResult,
    presentation: Presentation,
    owed: kr_cli::session::UndeliveredTyping,
    typed_before: Vec<u8>,
) -> Result<Option<kr_cli::session::AttachOutcome>> {
    match presentation {
        Presentation::Invisible => Ok(None),
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
            Ok(Some(outcome))
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
            created
                .presentation_error
                .as_ref()
                .map_or(Ok(None), |error| {
                    Err(CliError::TerminalUnavailable(Shown::protocol(error)))
                })
        }
    }
}

/// What `kr new` tells a person about the session it created, and how it ended.
///
/// A presentation that failed never began an attachment. One that began is presented, however the
/// attachment then ended, and how it ended is reported the way `kr attach` reports it.
fn creation_report(
    created: &SessionCreateResult,
    presentation: Presentation,
    execution_chosen: bool,
    fenced_launch: bool,
    presented: Result<Option<kr_cli::session::AttachOutcome>>,
    json: bool,
) -> Completion {
    let (presentation_error, outcome) = match presented {
        Ok(outcome) => (None, outcome),
        Err(error) => (Some(error), None),
    };
    if json {
        let mut document = report::session(&created.session)
            .with("presentation", presentation.as_str())
            .with(
                "presentation_error",
                presentation_error.as_ref().map(|error| output::said(error)),
            )
            .with("execution_context_chosen", execution_chosen)
            .with(
                "outcome",
                outcome.as_ref().map(kr_cli::session::AttachOutcome::detail),
            );
        // An attachment that ended with the session's closure has its record, so the document
        // describes the session as this command leaves it.
        if let Some(record) = outcome
            .as_ref()
            .and_then(kr_cli::session::AttachOutcome::closure)
        {
            document.set("state", kr_protocol::session::SessionState::Closed.as_str());
            document.set("closure", report::closure(record));
        }
        output::document(&document);
    } else {
        output::say(&shown!(
            "created session {} ({})",
            created.session.display_number.get(),
            created.session.session_id
        ));
        // The receipt, not the request: what the session was actually created with.
        output::line(&report::desktop_line(&created.session));
        let shell = Asked::text(Request::Sessions, &created.session.shell_path);
        match created.session.shell_mode {
            ShellMode::Managed if fenced_launch => output::line(&stdout_line!(
                "shell mode managed: Ctrl-D at an empty root prompt detaches this client, \
                 and a launch installs a command in {}'s own editor",
                shell
            )),
            ShellMode::Managed => output::say(&Shown::said(
                "shell mode managed: Ctrl-D at an empty root prompt detaches this client, \
                 and this session's launch profile admits no fenced launch, so a launch \
                 installs no command",
            )),
            ShellMode::NativeCompat => output::line(&stdout_line!(
                "shell mode native_compat: Ctrl-D at the prompt follows {}'s own behaviour \
                 and can close the session, a launch installs no command, and kr detach \
                 takes --attachment because this session records no originating attachment",
                shell
            )),
        }
        if let Some(error) = presentation_error.as_ref() {
            report::say(&shown!(
                "kr: the session was created; its terminal was not opened: {}",
                *error
            ));
        }
        if let Some(outcome) = outcome.as_ref() {
            output::say(&outcome.detail());
        }
    }
    match (presentation_error, outcome) {
        (Some(error), _) => Completion::Reported(error),
        (None, Some(outcome)) => outcome
            .into_error()
            .map_or(Completion::Done, Completion::Reported),
        (None, None) => Completion::Done,
    }
}

/// What `kr attach` tells a person about how an attachment ended.
fn attach_report(
    outcome: kr_cli::session::AttachOutcome,
    session_id: SessionId,
    json: bool,
) -> Completion {
    if json {
        output::document(
            &Document::new()
                .with("ok", !outcome.is_failure())
                .with("session_id", output::said(&session_id))
                .with("outcome", outcome.detail())
                .with("closure", outcome.closure().map(report::closure)),
        );
    } else {
        output::say(&outcome.detail());
    }
    outcome
        .into_error()
        .map_or(Completion::Done, Completion::Reported)
}

/// Refuses an attach to a session that has closed, with how it ended, and starts nothing.
fn closed_refusal(
    session_id: SessionId,
    record: Option<kr_protocol::session::ClosureRecord>,
    json: bool,
) -> Completion {
    let how = record.as_ref().map_or_else(
        || Shown::said("the host did not send its record"),
        kr_cli::session::how_it_closed,
    );
    let error = CliError::Refused(kr_client::error::refusal(
        kr_protocol::error::ErrorCode::SessionClosed,
        shown!(
            "session {} has closed: {}; attaching to it starts nothing",
            session_id,
            how
        ),
    ));
    if json {
        output::document(
            &report::failure(&error)
                .with("session_id", output::said(&session_id))
                .with("closure", record.as_ref().map(report::closure)),
        );
    } else {
        report::failed(&error);
    }
    Completion::Reported(error)
}

/// What `--palette` chose, and what the person typed while this terminal was being asked.
///
/// The palette comes before the geometry, because the probe form asks this terminal a question and
/// a refusal should come before a session exists rather than after.
fn choose_palette(
    value: Option<&str>,
    presentation: Presentation,
) -> Result<(Option<kr_protocol::session::PaletteRequest>, Vec<u8>)> {
    let chosen = match value {
        Some(value) => Some(kr_cli::create::resolve(
            kr_cli::create::PaletteChoice::parse(value)?,
            presentation,
        )?),
        None => None,
    };
    Ok(match chosen {
        Some(chosen) => (Some(chosen.palette), chosen.typed),
        None => (None, Vec::new()),
    })
}

/// Writes a closed session's retained output to the file the person named.
///
/// The name is checked before anything is read, and again where the file is made. The session is
/// read through the control daemon of this host's own environment, or through a bridge to an
/// enrolled one that is already running, which an export never starts.
async fn export(
    paths: &HostPaths,
    arguments: kr_cli::cli::ExportArguments,
    json: bool,
) -> Result<Completion> {
    let selector = SessionSelector::parse(&arguments.session)?;
    kr_cli::export::check_bound(arguments.max_bytes)?;
    kr_cli::export::refuse_existing(&arguments.output)?;
    let exported_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| u64::try_from(since.as_millis()).unwrap_or(0));
    let exported =
        match kr_cli::bridge::environments::selected(paths, arguments.environment.as_deref())
            .await?
        {
            Selected::Local(known) => {
                let mut client = open_controller(&known.paths, build_id()).await?;
                kr_cli::export::read(&mut client, &selector, arguments.max_bytes, exported_at_ms)
                    .await?
            }
            Selected::Enrolled(enrolment) => {
                let mut link = kr_cli::bridge::session::open_running(&enrolment).await?;
                let read =
                    kr_cli::export::read(&mut link, &selector, arguments.max_bytes, exported_at_ms)
                        .await;
                // A failure of the bridge is returned as the export's own, and is not said again.
                link.finish_told().await;
                read?
            }
        };
    kr_cli::export::write(&arguments.output, &exported)?;
    let summary = &exported.summary;
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("session_id", output::said(&summary.session_id))
                .with("display_number", summary.display_number)
                .with(
                    "path",
                    shown!("{}", kr_cli::shown::named(&arguments.output)),
                )
                .with("format", kr_cli::export::FORMAT)
                .with("bytes_read", summary.bytes_read)
                .with("bytes_carried", summary.bytes_carried)
                .with("gaps", summary.gaps)
                .with("truncated", summary.truncated)
                .with("omissions", summary.omissions.clone()),
        );
    } else {
        output::say(&shown!(
            "session {} exported to {}: {} of {} bytes of retained output carried, {} gaps{}; the \
             file declares {} omissions",
            summary.display_number,
            kr_cli::shown::named(&arguments.output),
            summary.bytes_carried,
            summary.bytes_read,
            summary.gaps,
            if summary.truncated {
                ", and the read stopped at the byte bound with output left"
            } else {
                ""
            },
            summary.omissions.len()
        ));
    }
    Ok(Completion::Done)
}

/// Creates a session in an enrolled environment through its bridge, and presents it.
async fn new_in_enrolled(
    enrolment: kr_protocol::identity::EnvironmentEnrolment,
    arguments: kr_cli::cli::NewArguments,
    presentation: Presentation,
    shell_mode: ShellMode,
    json: bool,
) -> Result<Completion> {
    // A terminal application opens where the session runs, and an enrolled environment has no
    // screen of this host's to open one on.
    if presentation == Presentation::Terminal {
        return Err(CliError::Usage(Shown::said(
            "--terminal opens a terminal application on the machine the session runs on, and an \
             enrolled environment has none this host can open; use --attach or --invisible",
        )));
    }
    let (palette, typed_while_asking) = choose_palette(arguments.palette.as_deref(), presentation)?;
    let mut undelivered = kr_cli::session::UndeliveredTyping::new(typed_while_asking.len());
    let dimensions = match presentation {
        Presentation::Attach => {
            let size = ControllingTerminal::open()?.size()?;
            Some(Dimensions::new(
                u64::from(size.columns),
                u64::from(size.rows),
            ))
        }
        Presentation::Terminal | Presentation::Invisible => None,
    };
    let launch_profile = arguments.launch_profile()?;
    let fenced_launch = launch_profile.fenced_launch;
    let chosen_profile = arguments.execution.chosen();
    let created = kr_cli::bridge::session::create(
        &enrolment,
        &kr_cli::bridge::session::NewSession {
            presentation,
            shell: arguments.shell,
            shell_mode,
            cwd: arguments.cwd,
            dimensions,
            profile: chosen_profile,
            palette,
            launch_profile,
        },
    )
    .await?;
    if !json {
        output::say(&report::execution_context_line(
            created.profile,
            chosen_profile.is_some(),
        ));
    }
    // The session exists. Presenting it is a separate step, and a presentation that fails never
    // produces a second session.
    undelivered.delivered();
    let presented = match presentation {
        Presentation::Attach => {
            let session = &created.result.session;
            // The attachment takes responsibility for what was typed, and reports what it could
            // not deliver, as a create on this host does.
            let owed = kr_cli::session::UndeliveredTyping::new(typed_while_asking.len());
            kr_cli::bridge::session::attach(
                &enrolment,
                kr_cli::attach::Attaching {
                    session_id: session.session_id,
                    environment_id: session.environment_id,
                    display_number: session.display_number,
                },
                AttachOptions {
                    take_geometry: true,
                    no_probe: false,
                    follow_live: false,
                    typed_before: typed_while_asking,
                },
                owed,
            )
            .await
            .map(|(outcome, _)| Some(outcome))
        }
        Presentation::Invisible | Presentation::Terminal => Ok(None),
    };
    Ok(creation_report(
        &created.result,
        presentation,
        chosen_profile.is_some(),
        fenced_launch,
        presented,
        json,
    ))
}

/// Attaches to a session in an enrolled environment through its bridge.
async fn attach_in_enrolled(
    enrolment: &kr_protocol::identity::EnvironmentEnrolment,
    selector: &SessionSelector,
    arguments: &kr_cli::cli::AttachArguments,
    json: bool,
) -> Result<Completion> {
    // What the destination retains is read before this terminal is touched, so a closed session is
    // refused with how it ended rather than after a probe of the terminal.
    let attaching = match kr_cli::bridge::session::locate(enrolment, selector).await? {
        kr_cli::bridge::session::Found::Closed { session_id, record } => {
            return Ok(closed_refusal(session_id, record, json));
        }
        kr_cli::bridge::session::Found::Live(attaching) => attaching,
    };
    let (outcome, session_id) = kr_cli::bridge::session::attach(
        enrolment,
        attaching,
        AttachOptions {
            take_geometry: arguments.take_geometry,
            no_probe: arguments.no_probe,
            follow_live: arguments.follow_live,
            typed_before: Vec::new(),
        },
        kr_cli::session::UndeliveredTyping::new(0),
    )
    .await?;
    Ok(attach_report(outcome, session_id, json))
}

/// Answers `kr attach` for a session that no descriptor names, and starts nothing.
///
/// A closed session is refused with `SESSION_CLOSED` and the closure record the daemon keeps, in
/// one document; one the registry never held is `UNKNOWN_SESSION`; and one it holds that has not
/// published a descriptor yet is not attached to, because the descriptor is how the worker is
/// found and proved.
async fn attach_unpublished(
    paths: &HostPaths,
    selector: &SessionSelector,
    environment: Option<&str>,
    json: bool,
) -> Result<Completion> {
    match kr_cli::resolve::registered(paths, selector, environment).await? {
        kr_cli::resolve::Registered::Closed { session_id, record } => {
            Ok(closed_refusal(session_id, record, json))
        }
        kr_cli::resolve::Registered::Unpublished { session_id, state } => {
            Err(CliError::HostUnavailable(shown!(
                "session {} is {} and has not published where to attach to it; \
                 try again once it is live",
                session_id,
                state
            )))
        }
    }
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

/// What `kr status` read of each attachment: the summaries its worker gave, or why they could not
/// be read, which says nothing the worker sent but a refusal's own message.
type AttachmentsRead = std::result::Result<Vec<kr_protocol::attachment::AttachmentSummary>, Shown>;

/// How long `kr status` waits for a worker to answer the question about its attachments, after it
/// has already answered the session read.
const ATTACHMENTS_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Reads a session from its own worker, and each of its attachments with it.
///
/// Each attachment's presentation and the reason for it travel in the worker's snapshot rather
/// than in the session read, so the snapshot is asked on the same connection. It is a second
/// question, asked within [`ATTACHMENTS_BOUND`]: a worker that cannot answer it, or does not answer
/// it in time, leaves the session read standing, and the command says the attachments were not read
/// rather than failing or holding back the whole status.
async fn read_session(
    descriptor: &kr_protocol::worker::WorkerDescriptor,
) -> Result<(SessionReadResult, AttachmentsRead)> {
    let mut client = open_worker(descriptor, build_id()).await?;
    let outcome = client
        .request(
            Method::SessionRead,
            &SessionReadParams {
                session_id: descriptor.session_id,
            },
        )
        .await?;
    let read = read_result(outcome)?;
    let asked = tokio::time::timeout(
        ATTACHMENTS_BOUND,
        client.request(
            Method::EventsSnapshot,
            &kr_protocol::recovery::EventsSnapshotParams {
                session_id: descriptor.session_id,
                agent_resources_from: Nullable::null(),
            },
        ),
    )
    .await;
    let attachments = attachments_read(asked.ok());
    Ok((read, attachments))
}

/// What `kr status` makes of the answer to its question about a session's attachments, or of no
/// answer within [`ATTACHMENTS_BOUND`]: the summaries the worker gave, or why they were not read.
fn attachments_read(
    asked: Option<
        kr_ipc::Result<
            std::result::Result<
                kr_protocol::envelope::ParamsValue,
                kr_protocol::error::ProtocolError,
            >,
        >,
    >,
) -> AttachmentsRead {
    match asked {
        Some(Ok(Ok(value))) => value
            .to_typed::<kr_protocol::recovery::EventsSnapshotResult>()
            .map(|snapshot| snapshot.attachments)
            .map_err(|error| Shown::cbor(&error)),
        Some(Ok(Err(refusal))) => Err(shown!("{}: {}", refusal.code, Shown::protocol(&refusal))),
        Some(Err(error)) => Err(Shown::ipc(&error)),
        None => Err(shown!(
            "the session's worker did not answer within {} seconds",
            ATTACHMENTS_BOUND.as_secs()
        )),
    }
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
    #[derive(serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
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
        // The older shape is checked against its own schema before it is decoded, like any
        // answer: an answer with a field neither shape declares is refused, not read as this.
        Err(error) => match value.to_typed::<Reported>() {
            Ok(reported) => Ok(SessionReadResult {
                session: reported.session,
                endpoint: reported.endpoint,
                launch_profile: Nullable::null(),
                last_command_block: Nullable::null(),
                outstanding_launches: Nullable::null(),
            }),
            Err(_) => Err(CliError::Other(shown!(
                "the host's answer could not be read: {}",
                Shown::cbor(&error)
            ))),
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
            text.parse::<EnvironmentId>().map_err(|_| {
                CliError::Usage(Shown::said(
                    "the text given is not an environment identifier",
                ))
            })
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
                output::document(
                    &Document::new().with("ok", true).with(
                        "questions",
                        found
                            .iter()
                            .map(|(descriptor, item)| question::rendered(descriptor, item))
                            .collect::<Vec<_>>(),
                    ),
                );
            } else if found.is_empty() {
                output::say(&Shown::said("no questions are waiting"));
            } else {
                for (descriptor, item) in &found {
                    output::line(&question::line(descriptor, item));
                }
            }
            Ok(Completion::Done)
        }
        QuestionCommand::Show(arguments) => {
            let question_id = parse_question(&arguments.question)?;
            let (descriptor, item) = question::show(paths, question_id, build_id()).await?;
            if json {
                output::document(
                    &Document::new()
                        .with("ok", true)
                        .with("question", question::rendered(&descriptor, &item)),
                );
            } else {
                output::lines(&question::detail(&descriptor, &item));
            }
            Ok(Completion::Done)
        }
        QuestionCommand::Answer(arguments) => {
            let question_id = parse_question(&arguments.question)?;
            let answer = answer_form(&arguments.form)?;
            let answered = question::answer(paths, question_id, answer, build_id()).await;
            report_answered(question_id, answered, json)
        }
        QuestionCommand::Drafts => {
            let reconciled = question::drafts(paths, build_id()).await?;
            if json {
                output::document(
                    &Document::new().with("ok", true).with(
                        "drafts",
                        reconciled
                            .iter()
                            .map(question::kept_rendered)
                            .collect::<Vec<_>>(),
                    ),
                );
            } else if reconciled.is_empty() {
                output::say(&Shown::said("no answers are kept on this device"));
            } else {
                for item in &reconciled {
                    output::line(&question::kept_line(item));
                }
            }
            Ok(Completion::Done)
        }
        QuestionCommand::Send(arguments) => {
            let question_id = parse_question(&arguments.question)?;
            let sent = question::send(paths, question_id, build_id()).await;
            report_answered(question_id, sent, json)
        }
        QuestionCommand::Cancel(arguments) => {
            let question_id = parse_question(&arguments.question)?;
            let item = question::cancel(paths, question_id, build_id()).await?;
            if json {
                output::document(
                    &Document::new()
                        .with("ok", true)
                        .with("state", item.state.as_str())
                        .with("question_id", output::said(&item.question_id)),
                );
            } else {
                output::say(&shown!("{} is {}", item.question_id, item.state.as_str()));
            }
            Ok(Completion::Done)
        }
    }
}

/// Reports an answer that was sent, or one that was kept on this device instead.
///
/// A kept answer is a failure, because its session's worker did not take it or whether it did is
/// not known, and its document says it was kept, so a script can tell it from an answer that was
/// refused.
fn report_answered(
    question_id: kr_protocol::ids::QuestionId,
    answered: Result<kr_protocol::question::Question>,
    json: bool,
) -> Result<Completion> {
    match answered {
        Ok(item) => {
            if json {
                output::document(
                    &Document::new()
                        .with("ok", true)
                        .with("state", item.state.as_str())
                        .with("revision", item.revision.get())
                        .with("question_id", output::said(&item.question_id)),
                );
            } else {
                output::say(&shown!("{} is {}", item.question_id, item.state.as_str()));
            }
            Ok(Completion::Done)
        }
        Err(error @ CliError::AnswerKept { .. }) => {
            if json {
                output::document(
                    &report::failure(&error)
                        .with("kept", true)
                        .with("question_id", output::said(&question_id)),
                );
            } else {
                report::failed(&error);
            }
            Ok(Completion::Reported(error))
        }
        Err(error) => Err(error),
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
    Err(CliError::Usage(Shown::said(
        "give one of --text, --choice, --yes, --no or --other",
    )))
}

fn parse_question(text: &str) -> Result<kr_protocol::ids::QuestionId> {
    text.parse()
        .map_err(|_| CliError::Usage(Shown::said("the text given is not a question identifier")))
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
                output::document(
                    &Document::new()
                        .with("ok", true)
                        .with("install", skill::installed(&result)),
                );
            } else {
                output::lines(&skill::install_lines(&result));
            }
        }
        SkillCommand::Status(_) => {
            let result = skill::status(&mut client, &params).await?;
            if json {
                output::document(
                    &Document::new()
                        .with("ok", skill::is_intact(&result))
                        .with("status", skill::reported(&result)),
                );
            } else {
                output::lines(&skill::status_lines(&result));
            }
        }
        SkillCommand::Remove(_) => {
            let result = skill::remove(&mut client, environment.environment_id, &params).await?;
            if json {
                output::document(
                    &Document::new()
                        .with("ok", true)
                        .with("remove", skill::removed(&result)),
                );
            } else {
                output::lines(&skill::remove_lines(&result));
            }
        }
    }
    Ok(Completion::Done)
}

fn stdio_is_terminal() -> bool {
    use std::io::IsTerminal as _;

    std::io::stdin().is_terminal() && output::is_terminal()
}

/// What the content export needs of the person, settled before any host is asked: whether it only
/// shows the content, writes it only when it has a digest the person saw, or asks at a terminal,
/// and which sessions they left out.
///
/// # Errors
///
/// Returns a usage failure when the digest or a session identifier is not one, and when there is
/// no terminal to ask at and neither `--preview` nor `--confirm-content` was given.
fn content_asked(
    arguments: &kr_cli::cli::DoctorArguments,
) -> Result<(
    kr_cli::doctor::content::Decision,
    Vec<kr_protocol::ids::SessionId>,
)> {
    use kr_cli::doctor::content::{Decision, Digest};
    use std::io::IsTerminal as _;

    let excluded = arguments
        .exclude_session
        .iter()
        .map(|session| {
            session.parse().map_err(|_| {
                CliError::Usage(Shown::said(
                    "--exclude-session takes a session identifier, as kr list shows it",
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let decision = if arguments.preview {
        Decision::Preview
    } else if let Some(digest) = arguments.confirm_content.as_deref() {
        Decision::Confirmed(Digest::parse(digest).ok_or_else(|| {
            CliError::Usage(Shown::said(
                "--confirm-content takes the digest --preview printed: 64 hexadecimal digits",
            ))
        })?)
    } else if report::is_terminal() && std::io::stdin().is_terminal() {
        Decision::Ask
    } else {
        return Err(CliError::Usage(Shown::said(
            "this command shows the content before it writes it and needs an answer: run it at a \
             terminal, or run it with --preview and then with --confirm-content and the digest it \
             printed",
        )));
    };
    Ok((decision, excluded))
}

/// Reads one host answer, on a new connection when the authority behind this one was withdrawn.
///
/// Reading this host's configuration is what puts it into force, so a ceiling edited outside it
/// takes effect during the read, and a ceiling that changes what a caller may do deregisters every
/// connection admitted under the authority it replaced - including this command's own. That is the
/// change working, not a failure, so the read is made again under the authority now in force, and
/// a second refusal is the answer.
///
/// Every command that reads `host.info` or the diagnostics goes through here. One of them putting
/// a ceiling into force and another failing on the connection that ceiling withdrew would be the
/// same host answering the same edit two different ways.
async fn host_read<T: kr_protocol::wire::WireMessage, P: serde::Serialize + ?Sized>(
    client: &mut kr_ipc::client::LocalClient,
    paths: &kr_ipc::paths::EnvironmentPaths,
    method: Method,
    params: &P,
) -> Result<T> {
    match client.request(method, params).await? {
        Ok(value) => value.to_typed().map_err(|error| {
            CliError::Other(shown!(
                "the host's answer could not be read: {}",
                Shown::cbor(&error)
            ))
        }),
        Err(refused) if refused.code == kr_protocol::error::ErrorCode::PermissionDenied => {
            *client = open_controller(paths, build_id()).await?;
            typed(client.request(method, params).await?)
        }
        Err(refused) => Err(CliError::Refused(refused)),
    }
}

/// How long `kr doctor` waits to read the live sessions: a worker that does not answer holds the
/// host's list of them up for two exchanges of five seconds, and the rest of the diagnostics are
/// worth printing without it.
const SESSIONS_READ_BOUND: std::time::Duration = std::time::Duration::from_secs(15);

/// The live sessions of `environment_id`, or `None` where they were not read within
/// [`SESSIONS_READ_BOUND`].
///
/// Read on a connection of its own: a request given up on leaves an answer nobody reads, and the
/// connection the other diagnostics use is not left holding it.
async fn live_sessions(
    paths: &kr_ipc::paths::EnvironmentPaths,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> Option<Vec<kr_protocol::session::SessionSummary>> {
    let read = async {
        let mut own = open_controller(paths, build_id()).await?;
        host_read::<kr_protocol::session::SessionListResult, _>(
            &mut own,
            paths,
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: kr_protocol::scalars::Nullable::some(environment_id),
                include_closed: false,
            },
        )
        .await
    };
    match tokio::time::timeout(SESSIONS_READ_BOUND, read).await {
        Ok(Ok(listed)) => Some(listed.sessions),
        Ok(Err(_)) | Err(_) => None,
    }
}

fn typed<T: kr_protocol::wire::WireMessage>(
    outcome: std::result::Result<
        kr_protocol::envelope::ParamsValue,
        kr_protocol::error::ProtocolError,
    >,
) -> Result<T> {
    outcome
        .map_err(CliError::Refused)?
        .to_typed()
        .map_err(|error| {
            CliError::Other(shown!(
                "the host's answer could not be read: {}",
                Shown::cbor(&error)
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A snapshot that cannot be read says the rule it broke and where, never a member it named;
    /// a worker's refusal says its code and its message.
    #[test]
    fn an_attachment_read_that_fails_says_nothing_the_worker_sent() {
        const MARKER: &str = "kr-marker-7c1e";

        let named = kr_cbor::CanonicalValue::Map(
            kr_cbor::CanonicalMap::from_entries([(
                MARKER.to_owned(),
                kr_cbor::CanonicalValue::text(MARKER),
            )])
            .expect("one member"),
        );
        let answer = kr_protocol::envelope::ParamsValue::from(named);
        // The negative control: the decoder's failure keeps the member it refused in a field of
        // its own.
        let refused = answer
            .to_typed::<kr_protocol::recovery::EventsSnapshotResult>()
            .map(|_| ())
            .expect_err("not a snapshot");
        assert!(
            matches!(&refused, kr_cbor::CborError::UnknownField { field, .. } if field == MARKER),
            "{refused}"
        );
        let said = attachments_read(Some(Ok(Ok(answer)))).expect_err("not read");
        assert!(!said.as_str().contains(MARKER), "{said}");
        assert!(!format!("{said:?}").contains(MARKER), "{said:?}");

        let refusal = kr_client::error::refusal(
            kr_protocol::error::ErrorCode::UnknownSession,
            Shown::said("no such session"),
        );
        assert_eq!(
            attachments_read(Some(Ok(Err(refusal))))
                .expect_err("refused")
                .as_str(),
            "UNKNOWN_SESSION: no such session"
        );
        assert_eq!(
            attachments_read(None).expect_err("no answer").as_str(),
            "the session's worker did not answer within 10 seconds"
        );
    }
}
