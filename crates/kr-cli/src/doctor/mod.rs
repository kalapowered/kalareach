//! `kr doctor`: what this host is, what it is configured from, and what is wrong with it.
//!
//! The command reads and reports. It repairs nothing, and everything it prints comes from the
//! daemon's own answers rather than from this process looking at the machine a second time.
//!
//! # What it prints
//!
//! The default output is a person glancing at a host: the environment, the execution context, the
//! desktop and its capabilities, the sleep policy, and then each check's verdict, with the
//! evidence under only the checks that did not pass, and each command integration: what a new
//! session gets of it, what it adds, and the executable the daemon's search path resolves its
//! command to, with the version a signed record gives it. `--verbose` prints the evidence under every
//! check, including the ones that passed, which is what a person sending a report needs and what
//! makes each value's source visible beside it.
//!
//! `--bundle <path>` writes a support bundle: software versions, capabilities, the diagnostics and
//! redacted errors, as one archive. `--include-content` adds the content-bearing diagnostic
//! export, which leaves out every private session, and the command prints what that export will
//! contain, and what it left out, before it writes anything.

pub mod bundle;
pub mod configuration;
pub mod content;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::hostinfo::configuration::ValueSource;
use kr_protocol::hostinfo::{
    CommandIntegrationReport, CommandIntegrationUnavailable, DoctorCheck, DoctorStatus,
    EffectiveConfiguration, HostDoctorResult, HostInfoResult,
};

use crate::output::{Asked, Document, Line, Request, configured, configured_field};
use crate::shown::host_text;
use crate::stdout_line;

/// Adds the service start's own check to the daemon's diagnostics, where there is anything of it
/// to report: whether the definition kr wrote is the one `kr new` would have the service manager
/// start the daemon from.
///
/// The daemon does not know how it was started, so this command, which wrote the definition,
/// looks at it. An environment that neither chooses the service start nor has a definition of it
/// installed gets no check.
#[must_use]
pub fn with_startup(
    mut result: HostDoctorResult,
    environment: &kr_ipc::paths::EnvironmentPaths,
) -> HostDoctorResult {
    if let Some(check) = startup_check(environment) {
        result.healthy &= !check.status.is_failure();
        result.checks.push(check);
    }
    result
}

/// The identifier the service start's check is published under.
pub const STARTUP_CHECK: &str = "startup-definition";

/// What the check examines.
#[cfg(unix)]
const STARTUP_TITLE: &str =
    "The service definition kr new has the service manager start the daemon from";

/// The identifier the standalone start's check is published under on Windows.
pub const TASK_CHECK: &str = "startup-task";

/// What the standalone start's check examines on Windows.
#[cfg(any(windows, test))]
const TASK_TITLE: &str = "The scheduled task kr new has start the daemon";

/// The standalone start's check on Windows, when there is anything of it to report.
///
/// An environment that neither chooses the standalone start nor has a task of its own registered
/// gets no check.
#[cfg(windows)]
fn startup_check(environment: &kr_ipc::paths::EnvironmentPaths) -> Option<DoctorCheck> {
    use kr_protocol::hostinfo::configuration::ControllerStartup;

    let chosen = crate::startup::Chosen::read(environment);
    let selected = chosen.controller == Some(ControllerStartup::Standalone);
    let report = crate::startup::task_report(environment, selected)?;
    Some(task_check(&report, selected))
}

/// The standalone start's check from what its scheduled task is: whose it is, whether it is the
/// one this installation registers, and, apart, where a start can use it (the login session this
/// command runs in) and the task's last result, which is one for all of its runs; and that the
/// daemon it starts runs only while the user is signed in.
#[cfg(any(windows, test))]
fn task_check(report: &crate::startup::task::Report, selected: bool) -> DoctorCheck {
    use kr_controller::supervision::windows::{LastResult, Standing};
    use kr_protocol::hostinfo::export::Sentence;

    let task = Sentence::new()
        .stated("the scheduled task of environment ")
        .identifier(&report.environment_id);
    if !selected {
        return DoctorCheck::new(
            TASK_CHECK,
            TASK_TITLE,
            DoctorStatus::Warning,
            task.stated(
                " is still registered, and startup.controller no longer chooses the standalone \
                 start; nothing uses it",
            ),
            Some(
                "run kr host startup --clear to remove it, or kr host startup --set standalone to \
                 use it",
            ),
        );
    }
    let (status, found, remedy) = match &report.standing {
        _ if report.usable() => (
            DoctorStatus::Ok,
            " is this environment's own and the one this installation registers",
            None,
        ),
        Ok(Standing::Owned(differences)) if differences.is_empty() => (
            DoctorStatus::Failed,
            " is this environment's own and runs this installation's kr-controller, which is not \
             there",
            Some("install kr again, then run kr host startup --set standalone"),
        ),
        Ok(Standing::Owned(_)) => (
            DoctorStatus::Failed,
            " is this environment's own and differs from the one this installation registers",
            Some("run kr host startup --set standalone to repair it"),
        ),
        Ok(Standing::Absent) => (
            DoctorStatus::Failed,
            " is not registered",
            Some("run kr host startup --set standalone to register it"),
        ),
        Ok(Standing::Foreign(_)) => (
            DoctorStatus::Failed,
            " is not registered: a task under its name is not this environment's own",
            Some("remove that task, then run kr host startup --set standalone"),
        ),
        Err(_) => (
            DoctorStatus::Failed,
            " cannot be read",
            Some("run kr host startup to see why"),
        ),
    };
    let session = match report.session {
        Some(0) => Sentence::new().stated(
            "; this command runs in no interactive session (login session 0), so whether you \
             are signed in elsewhere is not known here",
        ),
        Some(session) => Sentence::new()
            .stated("; you are signed in to login session ")
            .number(u64::from(session))
            .stated(", where the task can start the daemon"),
        None => Sentence::new().stated("; this command's login session cannot be read"),
    };
    let last = match report.last_result {
        Some(LastResult::NotRun) => {
            Sentence::new().stated("; it has not run since it was registered")
        }
        Some(LastResult::Running) => Sentence::new().stated("; a run of it is under way"),
        Some(LastResult::Ended(0)) => Sentence::new().stated("; its last run succeeded"),
        Some(LastResult::Ended(code)) => Sentence::new()
            .stated("; its last run ended with code ")
            .number(u64::from(code)),
        None => Sentence::new().stated("; its last result cannot be read"),
    };
    DoctorCheck::new(
        TASK_CHECK,
        TASK_TITLE,
        status,
        Sentence::new()
            .stated("startup.controller is ")
            .term("standalone")
            .stated(": ")
            .sentence(&task)
            .stated(found)
            .sentence(&session)
            .sentence(&last)
            .stated(
                ", for all of its runs; the daemon it starts runs only while you are signed in, so \
                 signing out ends it and every session",
            ),
        remedy,
    )
}

/// The service start's check, when there is anything of it to report.
#[cfg(unix)]
fn startup_check(environment: &kr_ipc::paths::EnvironmentPaths) -> Option<DoctorCheck> {
    use kr_protocol::hostinfo::configuration::ControllerStartup;
    use kr_protocol::hostinfo::export::Sentence;

    use crate::service_manager::State;

    let chosen = crate::startup::Chosen::read(environment);
    let selected = chosen.controller == Some(ControllerStartup::Service);
    let inspection = match crate::service_manager::inspect(environment, selected)? {
        Ok(inspection) => inspection,
        Err(_) => {
            return Some(DoctorCheck::new(
                STARTUP_CHECK,
                STARTUP_TITLE,
                DoctorStatus::Failed,
                Sentence::new().stated(
                    "what the service start has for this environment cannot be established",
                ),
                Some(
                    "run kr host startup to see why, then kr host startup --set service or --clear",
                ),
            ));
        }
    };
    let started = Sentence::new()
        .stated(inspection.manager.as_str())
        .stated(" starts the daemon of environment ")
        .identifier(&environment.environment_id());
    if !selected {
        return Some(DoctorCheck::new(
            STARTUP_CHECK,
            STARTUP_TITLE,
            DoctorStatus::Warning,
            started.stated(
                " from a definition kr wrote for the service start, which startup.controller no \
                 longer chooses; nothing uses it",
            ),
            Some(
                "run kr host startup --clear to remove it, or kr host startup --set service to use it",
            ),
        ));
    }
    let (status, found, remedy) = match inspection.state {
        State::Matches => (
            DoctorStatus::Ok,
            " from the definition kr wrote, which matches what kr wrote",
            None,
        ),
        State::Missing => (
            DoctorStatus::Failed,
            ", and the definition kr wrote for it is missing",
            Some("run kr host startup --set service to write it again"),
        ),
        State::Changed => (
            DoctorStatus::Failed,
            ", and the definition kr wrote for it was changed after kr wrote it",
            Some("restore the definition or remove it, then run kr host startup --set service"),
        ),
        State::Foreign => (
            DoctorStatus::Failed,
            ", and a definition kr did not write is where its definition belongs",
            Some("remove that definition, then run kr host startup --set service"),
        ),
        State::Outdated => (
            DoctorStatus::Failed,
            ", from a definition that names another program, other directories or another domain \
             than this installation's",
            Some("run kr host startup --set service to write this installation's"),
        ),
        State::Unrecorded => (
            DoctorStatus::Failed,
            ", from a definition that is what kr writes, and kr has no record of writing it",
            Some("run kr host startup --set service to record it"),
        ),
    };
    Some(DoctorCheck::new(
        STARTUP_CHECK,
        STARTUP_TITLE,
        status,
        Sentence::new()
            .stated("startup.controller is ")
            .term("service")
            .stated(": ")
            .sentence(&started)
            .stated(found),
        remedy,
    ))
}

/// Renders diagnostics.
///
/// A check's words are the host's own export text, said as the host wrote them.
#[must_use]
pub fn doctor(result: &HostDoctorResult) -> Document {
    Document::new()
        .with("healthy", result.healthy)
        .with(
            "checks",
            result
                .checks
                .iter()
                .map(|check| {
                    Document::new()
                        .with("id", host_text(check.stated_id()))
                        .with("title", host_text(check.stated_title()))
                        .with("status", check.status.as_str())
                        .with("detail", host_text(check.stated_detail()))
                        .with("remedy", check.stated_remedy().map(host_text))
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "command_integrations",
            result
                .command_integrations
                .iter()
                .map(integration)
                .collect::<Vec<_>>(),
        )
}

/// One command integration, in the shape the protocol answers it.
///
/// Its package, release, command, flags, variables, resolved executable and that executable's
/// version are what `kr doctor` is asked to show of it (section 7), so they are shown whole; what
/// the host adds about why it is in its state is the host's text, said as its class and its length.
#[must_use]
pub fn integration(report: &CommandIntegrationReport) -> Document {
    let asked = |text: &str| Asked::text(Request::Diagnostics, text);
    Document::new()
        .with("plugin_id", asked(&report.plugin_id))
        .with(
            "version",
            report.version.as_ref().map(|version| asked(version)),
        )
        .with(
            "command",
            report.command.as_ref().map(|command| asked(command)),
        )
        .with(
            "flags",
            report
                .flags
                .iter()
                .map(|flag| asked(flag))
                .collect::<Vec<_>>(),
        )
        .with(
            "variables",
            report
                .variables
                .iter()
                .map(|variable| {
                    Document::new()
                        .with("name", asked(&variable.name))
                        .with("value", asked(&variable.value))
                })
                .collect::<Vec<_>>(),
        )
        .with("state", report.state.as_str())
        .with(
            "unavailable",
            report.unavailable.as_ref().map(|why| why.as_str()),
        )
        .with("mode", report.mode.as_str())
        .with(
            "executable",
            report
                .executable
                .as_ref()
                .map(|executable| Asked::text(Request::Diagnostics, executable)),
        )
        .with(
            "executable_version",
            report
                .executable_version
                .as_ref()
                .map(|version| asked(version)),
        )
        .with(
            "reason",
            report
                .reason
                .as_ref()
                .map(|reason| crate::shown::exported("CommandIntegrationReport", "reason", reason)),
        )
}

/// One command integration as the lines a person reads: what a session created now gets of it and
/// the mode its command runs in, why none could launch through it here where none could, the flags
/// it adds as the elements they are and the variables it sets, and where the daemon's search path
/// resolves its command, with the version a signed record gives that executable. What `kr doctor`
/// is asked to show of it is shown whole; what the host adds about its state is said as its class
/// and its length. `first` goes in front of the first line and `rest` in front of the others.
#[must_use]
pub fn integration_lines(
    report: &CommandIntegrationReport,
    first: &'static str,
    rest: &'static str,
) -> Vec<Line> {
    let asked = |text: &str| Asked::text(Request::Diagnostics, text);
    let quoted = |text: &str| serde_json::to_string(text).unwrap_or_else(|_| format!("{text:?}"));
    let state = report.state.as_str();
    let mode = report.mode.as_str();
    let mut lines = vec![match (report.command.as_ref(), report.version.as_ref()) {
        (Some(command), Some(version)) => stdout_line!(
            "{}{} ({} {}): {}, {}",
            first,
            asked(command),
            asked(&report.plugin_id),
            asked(version),
            state,
            mode
        ),
        (Some(command), None) => stdout_line!(
            "{}{} ({}): {}, {}",
            first,
            asked(command),
            asked(&report.plugin_id),
            state,
            mode
        ),
        (None, Some(version)) => stdout_line!(
            "{}{} {}: {}, {}",
            first,
            asked(&report.plugin_id),
            asked(version),
            state,
            mode
        ),
        (None, None) => stdout_line!("{}{}: {}, {}", first, asked(&report.plugin_id), state, mode),
    }];
    if let Some(why) = report.unavailable.as_ref() {
        lines.push(stdout_line!(
            "{}a new session cannot launch through it here ({}): {}",
            rest,
            why.as_str(),
            match why {
                CommandIntegrationUnavailable::Platform => {
                    "this platform establishes no command backend"
                }
                CommandIntegrationUnavailable::NoLauncher => {
                    "no kr-hook is installed beside this host's worker"
                }
                CommandIntegrationUnavailable::TooLarge => {
                    "the integrations turned on add more flags than one session carries, and this \
                     one's are among the largest"
                }
            }
        ));
    }
    if let Some(command) = report.command.as_ref() {
        let flags: Vec<String> = report.flags.iter().map(|flag| quoted(flag)).collect();
        let variables: Vec<String> = report
            .variables
            .iter()
            .map(|variable| format!("{}={}", variable.name, quoted(&variable.value)))
            .collect();
        lines.push(match (flags.is_empty(), variables.is_empty()) {
            (true, true) => stdout_line!("{}adds no flag; sets no variable", rest),
            (false, true) => {
                stdout_line!("{}adds {}; sets no variable", rest, asked(&flags.join(" ")))
            }
            (true, false) => {
                stdout_line!("{}adds no flag; sets {}", rest, asked(&variables.join(" ")))
            }
            (false, false) => stdout_line!(
                "{}adds {}; sets {}",
                rest,
                asked(&flags.join(" ")),
                asked(&variables.join(" "))
            ),
        });
        lines.push(
            match (
                report.executable.as_ref(),
                report.executable_version.as_ref(),
            ) {
                (Some(executable), Some(version)) => stdout_line!(
                    "{}resolves to {} on the daemon's search path, {} by its signed record",
                    rest,
                    Asked::text(Request::Diagnostics, executable),
                    asked(version)
                ),
                (Some(executable), None) => stdout_line!(
                    "{}resolves to {} on the daemon's search path, a build no signed record \
                     names, so its version is not known",
                    rest,
                    Asked::text(Request::Diagnostics, executable)
                ),
                (None, _) => stdout_line!(
                    "{}{} is not on the daemon's search path; a session looks for it on its own",
                    rest,
                    asked(command)
                ),
            },
        );
    }
    if let Some(reason) = report.reason.as_ref() {
        lines.push(stdout_line!(
            "{}{}",
            rest,
            crate::shown::exported("CommandIntegrationReport", "reason", reason)
        ));
    }
    lines
}

/// One of this host's own locations: its configuration document, its runtime and state directories
/// and a document left at a location it no longer reads. Section 26 has `kr doctor` report them, so
/// each is said whole, as content the person asked the diagnostics for; the host-path rule would
/// replace the names of a document outside this installation's roots, which is where one belongs
/// on Linux.
fn location(path: &str) -> Asked {
    Asked::path(Request::Diagnostics, path)
}

/// One effective value, which section 26 has `kr doctor` show: a value made of names the owner
/// wrote down (the packages whose command integration a new session applies) whole, as content the
/// person asked the diagnostics for, and a value of every other class as [`configured`] says it.
pub(crate) fn value_said(value: &kr_protocol::hostinfo::EffectiveValue) -> Asked {
    match value.class() {
        kr_protocol::hostinfo::export::ContentClass::Name => {
            Asked::text(Request::Diagnostics, value.value())
        }
        class => configured(class, value.value()),
    }
}

/// Where in its rung a value came from: the configuration document's path, said whole as this
/// host's other locations are, or the name of the profile the person selected. Section 26 has
/// `kr doctor` show each value's source.
pub(crate) fn origin_of(source: ValueSource, origin: &str) -> Asked {
    match source {
        ValueSource::HostConfiguration => location(origin),
        _ => Asked::text(Request::Diagnostics, origin),
    }
}

/// Renders this host's effective configuration.
///
/// The host's own sentences are said as it wrote them; this host's own locations, and where each
/// value came from, whole; each other text field, and each value, by the class it is made of
/// ([`configured`]).
#[must_use]
pub fn configuration_report(effective: &EffectiveConfiguration) -> Document {
    Document::new()
        .with(
            "schema_version",
            crate::output::said(&effective.schema_version),
        )
        .with("revision", crate::output::said(&effective.revision))
        .with("document", location(&effective.document))
        .with(
            "status",
            Document::new()
                .with("state", effective.status.state.as_str())
                .with("detail", host_text(&effective.status.detail)),
        )
        // Whether the values below are what this host is acting on, and what its workers still
        // owe a fence one of them raised. A reader that saw only the values would have no way to
        // tell a configuration in force from one that could not be applied.
        .with(
            "not_in_force",
            effective.not_in_force.as_ref().map(host_text),
        )
        .with(
            "fence_outstanding",
            effective.fence_outstanding.as_ref().map(host_text),
        )
        .with("runtime_directory", location(&effective.runtime_directory))
        .with("state_directory", location(&effective.state_directory))
        // Section 26's native OS-appropriate locations: where this host's files are, and the rule
        // this platform followed to put them there. Both, because a rule without the resolved path
        // does not say where anything is, and a path without the rule does not say where the next
        // one would go.
        .with(
            "locations",
            effective
                .locations
                .iter()
                .map(|location| {
                    Document::new()
                        .with(
                            "what",
                            configured_field("ReportedLocation", "what", &location.what),
                        )
                        .with("documented", host_text(&location.documented))
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "precedence",
            effective
                .precedence
                .iter()
                .map(host_text)
                .collect::<Vec<_>>(),
        )
        .with(
            "overrides",
            effective
                .overrides
                .iter()
                .map(|entry| {
                    Document::new()
                        .with(
                            "variable",
                            configured_field("OverrideReport", "variable", &entry.variable),
                        )
                        .with(
                            "preference",
                            configured_field("OverrideReport", "preference", &entry.preference),
                        )
                        .with("position", entry.position.as_str())
                        .with("why", host_text(&entry.why))
                        .with("set", entry.set)
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "values",
            effective
                .values
                .iter()
                .map(|value| {
                    Document::new()
                        .with("key", configured_field("EffectiveValue", "key", &value.key))
                        .with("about", host_text(value.stated_about()))
                        .with("value", value_said(value))
                        // What the value is made of, which is what decides how it leaves this
                        // host. A reader that sees a path and a word in the same shape of row has
                        // no other way to tell them apart.
                        .with("class", value.class().as_str())
                        .with("source", value.source.as_str())
                        .with(
                            "origin",
                            value
                                .origin
                                .as_ref()
                                .map(|named| origin_of(value.source, named)),
                        )
                        .with(
                            "variable",
                            value.variable.as_ref().map(|variable| {
                                configured_field("EffectiveValue", "variable", variable)
                            }),
                        )
                        .with("effect", value.effect.as_str())
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "ceilings",
            effective
                .ceilings
                .iter()
                .map(|ceiling| {
                    Document::new()
                        .with("key", configured_field("CeilingValue", "key", &ceiling.key))
                        .with("configured", ceiling.configured.as_ref().map(host_text))
                        .with("value", host_text(&ceiling.value))
                        .with("source", ceiling.source.as_str())
                        .with(
                            "origin",
                            ceiling
                                .origin
                                .as_ref()
                                .map(|named| origin_of(ceiling.source, named)),
                        )
                        .with("effect", ceiling.effect.as_str())
                        .with("narrowed_by", ceiling.narrowed_by.as_ref().map(host_text))
                        .with("refused", ceiling.refused)
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "secrets",
            effective
                .secrets
                .iter()
                .map(|reference| {
                    Document::new()
                        .with(
                            "name",
                            configured_field("SecretReference", "name", &reference.name),
                        )
                        .with(
                            "store",
                            configured_field("SecretReference", "store", &reference.store),
                        )
                        .with(
                            "item",
                            configured_field("SecretReference", "item", &reference.item),
                        )
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "stale_documents",
            effective
                .stale_documents
                .iter()
                .map(|stale| location(stale))
                .collect::<Vec<_>>(),
        )
}

/// Every check's verdict, and its evidence under it. `verbose` decides how much evidence: with it,
/// every check shows the value, its source and its location; without it, only a check that did not
/// pass does, because a person looking for what is wrong should not have to read past twenty lines
/// that are right.
#[must_use]
pub fn check_lines(result: &HostDoctorResult, verbose: bool) -> Vec<Shown> {
    let mut lines = Vec::new();
    for check in &result.checks {
        let status = check.status.as_str();
        lines.push(shown!(
            "{}{} {}",
            status,
            padding(14, status),
            host_text(check.stated_title())
        ));
        if verbose || check.status != DoctorStatus::Ok {
            lines.push(shown!(
                "               {}",
                host_text(check.stated_detail())
            ));
            if let Some(remedy) = check.stated_remedy() {
                lines.push(shown!("               {}", host_text(remedy)));
            }
        }
    }
    lines
}

/// Renders diagnostics as lines for a person: every check ([`check_lines`]), each command
/// integration ([`integration_lines`]) and the summary.
#[must_use]
pub fn doctor_lines(result: &HostDoctorResult, verbose: bool) -> Vec<Line> {
    let mut lines: Vec<Line> = check_lines(result, verbose)
        .into_iter()
        .map(|line| stdout_line!("{}", line))
        .collect();
    for report in &result.command_integrations {
        lines.extend(integration_lines(
            report,
            "integration    ",
            "               ",
        ));
    }
    lines.push(stdout_line!("{}", summary(result)));
    lines
}

/// The diagnostics as the support bundle's report carries them: every check with its evidence,
/// each command integration by its state, its mode and how many flags and variables it adds, and
/// the summary. The bundle is read by somebody else, so an integration's names and paths, which
/// its exported copy holds only as their class and length, are left out of these lines.
#[must_use]
pub fn report_lines(result: &HostDoctorResult) -> Vec<Shown> {
    let mut lines = check_lines(result, true);
    for report in &result.command_integrations {
        lines.push(shown!(
            "{}{} {}, {}, {} flags, {} variables{}",
            "integration",
            padding(14, "integration"),
            report.state.as_str(),
            report.mode.as_str(),
            report.flags.len(),
            report.variables.len(),
            report.unavailable.as_ref().map_or_else(
                || Shown::said(""),
                |why| shown!(", unavailable: {}", why.as_str())
            )
        ));
    }
    lines.push(summary(result));
    lines
}

/// The spaces that pad `word` to `width` characters.
fn padding(width: usize, word: &str) -> &'static str {
    const SPACES: &str = "                ";
    &SPACES[..width.saturating_sub(word.chars().count()).min(SPACES.len())]
}

/// The last line: how many checks ran and how they came out.
#[must_use]
pub fn summary(result: &HostDoctorResult) -> Shown {
    let mut failed = 0_usize;
    let mut warning = 0_usize;
    let mut not_applicable = 0_usize;
    for check in &result.checks {
        match check.status {
            DoctorStatus::Failed => failed += 1,
            DoctorStatus::Warning => warning += 1,
            DoctorStatus::NotApplicable => not_applicable += 1,
            DoctorStatus::Ok => {}
        }
    }
    shown!(
        "{} checks: {} passed, {} with something worth knowing, {} failed, {} not applicable",
        result.checks.len(),
        result.checks.len() - warning - failed - not_applicable,
        warning,
        failed,
        not_applicable
    )
}

/// The lines that name the engineering defaults this host makes configurable.
///
/// Section 1 says the engineering defaults "are configurable where the product needs a choice", so
/// each one is printed with the value in force and where that value came from rather than as a
/// constant a person has to go and look up.
#[must_use]
pub fn configurable_lines(effective: &EffectiveConfiguration) -> Vec<Line> {
    let mut lines = vec![stdout_line!(
        "configuration {} (schema version {}, revision {}): {}",
        location(&effective.document),
        effective.schema_version,
        effective.revision,
        host_text(&effective.status.detail)
    )];
    lines.push(stdout_line!(
        "  runtime directory {}",
        location(&effective.runtime_directory)
    ));
    lines.push(stdout_line!(
        "  state directory {}",
        location(&effective.state_directory)
    ));
    // Section 26's native OS-appropriate locations: where this platform puts each of them, beside
    // the three paths above that say where this host's own are. The rule is what an owner needs in
    // order to find the next one, or to know that a variable of theirs chose this one instead.
    for location in &effective.locations {
        lines.push(stdout_line!(
            "  {} belongs at {}",
            configured_field("ReportedLocation", "what", &location.what),
            host_text(&location.documented)
        ));
    }
    for value in &effective.values {
        let key = configured_field("EffectiveValue", "key", &value.key);
        let said = value_said(value);
        let effect = value.effect.describe();
        let origin = value
            .variable
            .as_ref()
            .map(|variable| configured_field("EffectiveValue", "variable", variable))
            .or_else(|| {
                value
                    .origin
                    .as_ref()
                    .map(|named| origin_of(value.source, named))
            });
        lines.push(match origin {
            Some(origin) => stdout_line!(
                "  {} = {} from {} ({}), applies {}",
                key,
                said,
                value.source.as_str(),
                origin,
                effect
            ),
            None => stdout_line!(
                "  {} = {} from {}, applies {}",
                key,
                said,
                value.source.as_str(),
                effect
            ),
        });
    }
    for ceiling in &effective.ceilings {
        let refused = if ceiling.refused {
            ", the configured value was more permissive and was refused"
        } else {
            ""
        };
        let key = configured_field("CeilingValue", "key", &ceiling.key);
        let origin = ceiling
            .origin
            .as_ref()
            .map(|named| origin_of(ceiling.source, named));
        let narrowed = ceiling
            .narrowed_by
            .as_ref()
            .map_or_else(|| Shown::said(""), |why| shown!(" ({})", host_text(why)));
        lines.push(match origin {
            Some(origin) => stdout_line!(
                "  {} ceiling {} from {} ({}), applies {}{}{}",
                key,
                host_text(&ceiling.value),
                ceiling.source.as_str(),
                origin,
                ceiling.effect.describe(),
                refused,
                narrowed
            ),
            None => stdout_line!(
                "  {} ceiling {} from {}, applies {}{}{}",
                key,
                host_text(&ceiling.value),
                ceiling.source.as_str(),
                ceiling.effect.describe(),
                refused,
                narrowed
            ),
        });
    }
    lines
}

/// The software versions a support bundle carries.
#[must_use]
pub fn software(info: &HostInfoResult) -> Vec<kr_protocol::hostinfo::SoftwareComponent> {
    use kr_protocol::hostinfo::export::{BuildIdentity, ContentClass, Sentence, Stated};

    let controller = info.build_id.to_string();
    let mut components = vec![
        kr_protocol::hostinfo::SoftwareComponent {
            component: Stated::new("kr"),
            version: Sentence::new().stated(env!("CARGO_PKG_VERSION")),
        },
        kr_protocol::hostinfo::SoftwareComponent {
            component: Stated::new("controller build"),
            // Which build of the daemon is running, which is the first thing somebody reading a
            // bundle needs. It arrives in a reply rather than being this command's own, so the
            // parse is what establishes that it is a build identity; text that is not one leaves
            // as its class and its length.
            version: BuildIdentity::parse(&controller).map_or_else(
                || Sentence::new().withheld(ContentClass::Name, &controller),
                |build| Sentence::new().identifier(&build),
            ),
        },
        kr_protocol::hostinfo::SoftwareComponent {
            component: Stated::new("protocol"),
            version: Sentence::new()
                .number(u64::from(info.protocol_version.major))
                .stated(".")
                .number(u64::from(info.protocol_version.minor)),
        },
        kr_protocol::hostinfo::SoftwareComponent {
            component: Stated::new("platform"),
            version: Sentence::new()
                .stated(std::env::consts::OS)
                .stated(" ")
                .stated(std::env::consts::ARCH),
        },
    ];
    // A kr of an installed release names that release, as each of its programs does in its build.
    if let Some(build) = kr_ipc::install::this_process()
        .ok()
        .filter(|running| running.release().is_some())
        .and_then(|_| BuildIdentity::parse(crate::build_id().as_str()))
    {
        components.push(kr_protocol::hostinfo::SoftwareComponent {
            component: Stated::new("installed release"),
            version: Sentence::new().identifier(&build),
        });
    }
    components
}

#[cfg(test)]
mod tests;
